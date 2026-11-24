"""Self-learning side-tree Engine Lab, blind unseen A/B promotion gate, and atomic rollback (`kintoun engine`).

Enables a decompilation project (and `ENGINE-BUILDER` subagents) to iteratively evolve its own
project-local copy of Kintoun's search, seed-repair, and mutation engine inside `.kintoun/engine_lab/`
without overfitting to a static benchmark:

  1. **Isolated Side Trees & Combined Stack (`.kintoun/engine_lab/`):**
     - `live/src/kintoun`: the project's active engine snapshot (seeded from installed Kintoun).
     - `combined/`: local git repository (`live` branch + `combined` branch stacking discrete
       `[bN] <claim>` commits across 1..N builders via 3-way apply).
     - `builders/<id>/src/kintoun`: isolated per-builder working trees (`b1`, `b2`, `b3`, `b4`, ...).
  2. **Shared Findings Log & In-Flight Lock (`findings.md` + `inflight.json`):**
     - Prevents parallel builders from duplicating the same hypothesis and records append-only
       `dev` outcomes and lessons learned across waves.
  3. **Strict Anti-Overfitting Ledger (`seen_functions.json`):**
     - Every function included in any `dev` set or builder `bench` run is permanently recorded in
       `seen_by_builders`.
     - The promotion gate (`run_unseen_gate`) dynamically samples a wide, size-stratified array of
       plain-C functions that **neither `live` nor `candidate` has ever seen** (`not in seen_by_builders`
       and `not in seen_in_gates`), plus an optional `solved_guard` regression set from matched `src/`.
  4. **Per-Commit Ablation, Strict Dual-Metric Gate, Backup, & 1-Command Rollback:**
     - Ablates multi-commit stacks on `combined`, auto-reverting commits that do not help.
     - Promotes `candidate` into `live/` ONLY when it strictly beats `live` on **both** `% close to
       matched` (`mean_aligned_pct` up, `>=85%` near-miss+match rate non-decreasing) **and**
       `exact matches` (`verified` count strictly up), with **zero lost exact matches** on unseen
       and solved sets, creating a timestamped backup + `PROMOTION_MANIFEST.json` for 1-command rollback.
"""
from __future__ import annotations

from contextlib import contextmanager
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import py_compile
import random
import re
import shutil
import subprocess
import sys
import tempfile
import time
from typing import Any

from kintoun.config import KintounConfig
from kintoun.inspect_fn import check_function, decode_target_features, score_difficulty
from kintoun.similarity import index_matched_c_functions
from kintoun.targets import TargetContext, TargetFunction, load_target_from_config

try:
    import fcntl as _fcntl
except ImportError:  # pragma: no cover - Windows fallback
    _fcntl = None  # type: ignore[assignment]

SIZE_BUCKETS: tuple[tuple[str, int, int, int], ...] = (
    ("<64B", 0, 64, 8),
    ("64-255B", 64, 256, 12),
    ("256-511B", 256, 512, 10),
    ("512-1023B", 512, 1024, 6),
    (">=1024B", 1024, 10**9, 4),
)

_EXCLUDED_GLOBS = (
    "__pycache__",
    "*.pyc",
    "*.pyo",
    "*.bak*",
    "*.orig",
    "*.rej",
    "*.tmp*",
    "*.swp",
    ".pytest_cache",
)

_FINDINGS_MARKER = "\n<!-- entries -->\n"
_FINDINGS_HEADER = (
    "# Engine Builder Findings (append-only, newest first)\n"
    "Read before every cycle (`kintoun engine findings show`); log after every dev bench.\n"
    "Format: - YYYY-MM-DD HH:MMZ | <builder> | <change> | dev <summary> | <verdict> | lesson: <note>\n"
)


def _utc_stamp() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%MZ")


def _norm_slug(raw: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", raw.strip().lower()).strip("-")[:64]


def _atomic_json_write(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    tmp.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    os.replace(tmp, path)


def _read_json(path: Path, default: Any) -> Any:
    if not path.is_file():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default


@contextmanager
def _file_lock(lock_path: Path):
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    lock_path.touch(exist_ok=True)
    with lock_path.open("r+", encoding="utf-8") as fh:
        if _fcntl is not None:
            _fcntl.flock(fh.fileno(), _fcntl.LOCK_EX)
        try:
            yield
        finally:
            if _fcntl is not None:
                _fcntl.flock(fh.fileno(), _fcntl.LOCK_UN)


def installed_kintoun_pkg_dir() -> Path:
    """Return the `src/kintoun` package directory of the running Kintoun installation."""
    import kintoun as _root_pkg

    return Path(_root_pkg.__file__).resolve().parent


def active_overlay_src_dir(project_root: Path) -> Path | None:
    """Return `.kintoun/engine_lab/live/src` if a promoted project-local engine is active."""
    if os.environ.get("KINTOUN_DISABLE_LOCAL_ENGINE") == "1":
        return None
    meta_p = Path(project_root) / ".kintoun" / "engine_lab" / "active_engine.json"
    meta = _read_json(meta_p, {})
    if not meta.get("enabled"):
        return None
    live_src = Path(project_root) / ".kintoun" / "engine_lab" / "live" / "src"
    if (live_src / "kintoun" / "__init__.py").is_file():
        return live_src
    return None


def synthesize_baseline_seed(target_fn: TargetFunction, ctx: TargetContext) -> str:
    """Build a deterministic compilable C89 seed from `target_fn` when no external `m2c` seed exists."""
    dec = decode_target_features(target_fn, ctx)
    lines = [
        "typedef signed char s8;",
        "typedef short s16;",
        "typedef int s32;",
        "typedef unsigned char u8;",
        "typedef unsigned short u16;",
        "typedef unsigned int u32;",
        "typedef float f32;",
        "typedef double f64;",
        "",
    ]
    valid_callees: list[str] = []
    for c in dec["callees"][:12]:
        if re.match(r"^[A-Za-z_]\w*$", c) and c != target_fn.name:
            valid_callees.append(c)
            lines.append(f"s32 {c}(s32 a0, s32 a1);")
    for g in dec["globals"][:12]:
        if re.match(r"^[A-Za-z_]\w*$", g):
            lines.append(f"extern s32 {g};")
    if valid_callees or dec["globals"]:
        lines.append("")

    has_fp = dec["features"].get("float_ops", 0) > 0
    lines.append(f"s32 {target_fn.name}(s32 a0, s32 a1) {{")
    lines.append("    s32 acc;")
    if has_fp:
        lines.append("    f32 ftmp;")
    lines.append("    acc = a0;")
    if has_fp:
        lines.append("    ftmp = (f32)a0;")
        lines.append("    acc += (s32)ftmp;")
    for c in valid_callees[:4]:
        lines.append(f"    acc += {c}(acc, a1);")
    if dec["features"].get("cond_branches", 0) > 0:
        lines.append("    if (acc < a1) {")
        lines.append("        acc = a1;")
        lines.append("    }")
    lines.append("    return acc;")
    lines.append("}")
    return "\n".join(lines) + "\n"


def _copy_kintoun_tree(src_pkg: Path, dst_src_root: Path) -> Path:
    dst_pkg = dst_src_root / "kintoun"
    if dst_pkg.exists():
        shutil.rmtree(dst_pkg)
    dst_src_root.mkdir(parents=True, exist_ok=True)
    shutil.copytree(src_pkg, dst_pkg, ignore=shutil.ignore_patterns(*_EXCLUDED_GLOBS))
    return dst_pkg


def tree_digest(src_root: Path) -> str:
    """Deterministic SHA-256 digest over `.py` files under `<arm>/src/kintoun`."""
    pkg = src_root / "kintoun" if (src_root / "kintoun").is_dir() else src_root
    h = hashlib.sha256()
    for p in sorted(pkg.rglob("*.py")):
        if "__pycache__" in p.parts:
            continue
        h.update(p.relative_to(pkg).as_posix().encode("utf-8"))
        h.update(b"\0")
        h.update(p.read_bytes())
    return h.hexdigest()[:16]


def validate_python_tree(src_root: Path) -> list[str]:
    """Compile-check all `.py` files in `src_root` without writing `.pyc` into the tree."""
    pkg = src_root / "kintoun" if (src_root / "kintoun").is_dir() else src_root
    errors: list[str] = []
    with tempfile.TemporaryDirectory(prefix="kintoun_pyc_") as tmp:
        for idx, p in enumerate(sorted(pkg.rglob("*.py"))):
            if "__pycache__" in p.parts:
                continue
            cfile = Path(tmp) / f"chk_{idx}.pyc"
            try:
                py_compile.compile(str(p), cfile=str(cfile), doraise=True)
            except py_compile.PyCompileError as exc:
                errors.append(f"{p.relative_to(pkg)}: {exc.msg}")
    return errors


class EngineLab:
    """Coordinator for `.kintoun/engine_lab/` side trees, findings, git stack, unseen gate, and rollback."""

    def __init__(self, cfg: KintounConfig, lab_dir: Path | None = None) -> None:
        self.cfg = cfg
        cache_dir = cfg.resolve_path(cfg.search.cache_dir) or (cfg.root / ".kintoun" / "cache")
        self.kintoun_dir = cache_dir.parent
        self.lab_dir = Path(lab_dir) if lab_dir is not None else (self.kintoun_dir / "engine_lab")
        self.live_dir = self.lab_dir / "live"
        self.combined_dir = self.lab_dir / "combined"
        self.builders_dir = self.lab_dir / "builders"
        self.backups_dir = self.lab_dir / "backups"
        self.sandbox_dir = self.lab_dir / "sandbox"
        self.sets_dir = self.lab_dir / "sets"
        self.findings_md = self.lab_dir / "findings.md"
        self.inflight_json = self.lab_dir / "inflight.json"
        self.seen_json = self.lab_dir / "seen_functions.json"
        self.state_json = self.lab_dir / "lab_state.json"
        self.active_json = self.lab_dir / "active_engine.json"
        self.gate_log_jsonl = self.lab_dir / "gate_history.jsonl"
        self._lock_file = self.lab_dir / "lab.lock"

    def _git(self, *args: str, cwd: Path | None = None, check: bool = True, input_text: str | None = None) -> subprocess.CompletedProcess[str]:
        env = {
            **os.environ,
            "GIT_AUTHOR_NAME": "kintoun-engine-lab",
            "GIT_AUTHOR_EMAIL": "engine-lab@localhost",
            "GIT_COMMITTER_NAME": "kintoun-engine-lab",
            "GIT_COMMITTER_EMAIL": "engine-lab@localhost",
            "GIT_TERMINAL_PROMPT": "0",
        }
        proc = subprocess.run(
            ["git", *args],
            cwd=str(cwd or self.combined_dir),
            env=env,
            input=input_text,
            capture_output=True,
            text=True,
        )
        if check and proc.returncode != 0:
            raise RuntimeError(f"git {' '.join(args[:6])} failed: {(proc.stderr or proc.stdout).strip()[:400]}")
        return proc

    def _tree_sha_of_dir(self, src_dir: Path) -> str:
        """Write `src_dir` into `combined`'s git object store using a temporary index and return tree SHA."""
        with tempfile.TemporaryDirectory(prefix="kintoun_idx_") as td:
            idx_env = {
                **os.environ,
                "GIT_INDEX_FILE": str(Path(td) / "index"),
                "GIT_TERMINAL_PROMPT": "0",
            }
            subprocess.run(
                ["git", "--git-dir", str(self.combined_dir / ".git"), "--work-tree", str(src_dir), "add", "-A", "."],
                cwd=str(src_dir),
                env=idx_env,
                check=True,
                capture_output=True,
                text=True,
            )
            res = subprocess.run(
                ["git", "--git-dir", str(self.combined_dir / ".git"), "write-tree"],
                cwd=str(src_dir),
                env=idx_env,
                check=True,
                capture_output=True,
                text=True,
            )
            return res.stdout.strip()

    def init_lab(self, *, builders: int = 4, source_pkg: Path | None = None) -> dict[str, Any]:
        """Initialize `live/`, local git `combined/`, `builders/b1..bN`, `findings.md`, and `seen_functions.json`."""
        src_pkg = Path(source_pkg) if source_pkg is not None else installed_kintoun_pkg_dir()
        n_builders = max(1, min(16, int(builders)))
        with _file_lock(self._lock_file):
            for d in (self.lab_dir, self.builders_dir, self.backups_dir, self.sandbox_dir, self.sets_dir):
                d.mkdir(parents=True, exist_ok=True)

            if not (self.live_dir / "src" / "kintoun" / "__init__.py").is_file():
                _copy_kintoun_tree(src_pkg, self.live_dir / "src")

            if not (self.combined_dir / ".git").exists():
                self.combined_dir.mkdir(parents=True, exist_ok=True)
                self._git("init", "-q", "-b", "live")
                excl = self.combined_dir / ".git" / "info" / "exclude"
                excl.parent.mkdir(parents=True, exist_ok=True)
                excl.write_text("\n".join(_EXCLUDED_GLOBS) + "\n", encoding="utf-8")
                self._git("config", "core.autocrlf", "false")
                self._git("config", "commit.gpgsign", "false")
                _copy_kintoun_tree(self.live_dir / "src" / "kintoun", self.combined_dir / "src")
                self._git("add", "-A", ".")
                self._git("commit", "-q", "-m", f"live: initial engine snapshot ({_utc_stamp()})")
                self._git("branch", "combined", "live")
                self._git("checkout", "-q", "combined")

            comb_head = self._git("rev-parse", "combined").stdout.strip()
            comb_tree = self._git("rev-parse", "combined^{tree}").stdout.strip()
            st = _read_json(self.state_json, {"bases": {}, "events": [], "promotions": 0})

            created_builders: list[str] = []
            for idx in range(1, n_builders + 1):
                bid = f"b{idx}"
                bdir = self.builders_dir / bid
                if not (bdir / "src" / "kintoun" / "__init__.py").is_file():
                    _copy_kintoun_tree(self.combined_dir / "src" / "kintoun", bdir / "src")
                    st.setdefault("bases", {})[bid] = {
                        "commit": comb_head,
                        "tree": comb_tree,
                        "synced_at": _utc_stamp(),
                    }
                    created_builders.append(bid)

            _atomic_json_write(self.state_json, st)
            if not self.findings_md.is_file():
                self.findings_md.write_text(_FINDINGS_HEADER + _FINDINGS_MARKER, encoding="utf-8")
            if not self.inflight_json.is_file():
                _atomic_json_write(self.inflight_json, {})
            if not self.seen_json.is_file():
                _atomic_json_write(
                    self.seen_json,
                    {"seen_by_builders": [], "seen_in_gates": [], "gate_runs": 0},
                )

        return {
            "ok": True,
            "lab_dir": str(self.lab_dir),
            "live_commit": self._git("rev-parse", "live").stdout.strip(),
            "combined_head": comb_head,
            "builders": sorted(p.name for p in self.builders_dir.iterdir() if p.is_dir()),
            "created_builders": created_builders,
        }

    def _ensure_initialized(self) -> None:
        if not (self.combined_dir / ".git").exists():
            self.init_lab()

    def commits_since_live(self) -> list[dict[str, str]]:
        self._ensure_initialized()
        raw = self._git("log", "--reverse", "--format=%H%x09%s", "live..combined").stdout
        out: list[dict[str, str]] = []
        for line in raw.splitlines():
            if "\t" in line:
                sha, subj = line.split("\t", 1)
                out.append({"sha": sha, "subject": subj})
        return out

    def sync_builder(self, builder_id: str, *, force: bool = False) -> dict[str, Any]:
        """Refresh `builders/<builder_id>` to `combined` HEAD (refusing if uncommitted local edits exist unless `force`)."""
        self._ensure_initialized()
        bid = builder_id.strip()
        bdir = self.builders_dir / bid
        with _file_lock(self._lock_file):
            st = _read_json(self.state_json, {"bases": {}, "events": []})
            base_info = (st.get("bases") or {}).get(bid) or {}
            if bdir.is_dir() and not force and base_info.get("tree"):
                cur_tree = self._tree_sha_of_dir(bdir)
                if cur_tree != base_info["tree"]:
                    return {
                        "ok": False,
                        "error": (
                            f"builder '{bid}' has uncommitted changes in {bdir}; "
                            "commit them first or pass --force to discard"
                        ),
                    }
            self._git("checkout", "-q", "combined")
            _copy_kintoun_tree(self.combined_dir / "src" / "kintoun", bdir / "src")
            head = self._git("rev-parse", "combined").stdout.strip()
            tree = self._tree_sha_of_dir(bdir)
            st.setdefault("bases", {})[bid] = {"commit": head, "tree": tree, "synced_at": _utc_stamp()}
            st.setdefault("events", []).insert(0, f"{_utc_stamp()} {bid} synced to {head[:10]}")
            st["events"] = st["events"][:120]
            _atomic_json_write(self.state_json, st)
        return {"ok": True, "builder": bid, "path": str(bdir), "synced_to": head}

    def commit_builder(self, builder_id: str, claim: str) -> dict[str, Any]:
        """Validate `.py` syntax and 3-way apply `builders/<builder_id>`'s diff onto `combined` as one commit."""
        self._ensure_initialized()
        bid = builder_id.strip()
        clean_claim = " ".join(claim.split())[:160]
        if not clean_claim:
            return {"ok": False, "error": "claim must be non-empty (describe what changed and why)"}
        bdir = self.builders_dir / bid
        if not (bdir / "src" / "kintoun").is_dir():
            return {"ok": False, "error": f"unknown builder workdir: {bdir} (run `kintoun engine sync --builder {bid}`)"}

        syntax_errs = validate_python_tree(bdir / "src")
        if syntax_errs:
            return {"ok": False, "error": "syntax error in candidate engine: " + "; ".join(syntax_errs[:3])}

        with _file_lock(self._lock_file):
            st = _read_json(self.state_json, {"bases": {}, "events": []})
            base_tree = ((st.get("bases") or {}).get(bid) or {}).get("tree") or self._git(
                "rev-parse", "live^{tree}"
            ).stdout.strip()
            new_tree = self._tree_sha_of_dir(bdir)
            if new_tree == base_tree:
                return {"ok": False, "error": f"no engine changes in {bdir} since last sync/commit"}

            patch = self._git("diff-tree", "-p", "--binary", "--full-index", base_tree, new_tree).stdout
            files = [
                f.strip()
                for f in self._git("diff-tree", "-r", "--name-only", base_tree, new_tree).stdout.splitlines()
                if f.strip()
            ]
            self._git("checkout", "-q", "-f", "combined")
            app = self._git("apply", "-3", "--index", "-", check=False, input_text=patch)
            if app.returncode != 0:
                self._git("reset", "-q", "--hard", "combined")
                return {
                    "ok": False,
                    "conflict": True,
                    "error": (
                        f"3-way merge conflict with combined HEAD: {(app.stderr or app.stdout).strip()[:240]}. "
                        f"Save your diff, run `kintoun engine sync --builder {bid} --force`, and re-apply."
                    ),
                }
            msg = f"[{bid}] {clean_claim}\n\nBuilder: {bid}\nFiles: {', '.join(files)}\nCommitted: {_utc_stamp()}"
            self._git("commit", "-q", "-m", msg)
            sha = self._git("rev-parse", "combined").stdout.strip()
            # Refresh builder's base tree to current `bdir` tree (or latest combined if fast-forward)
            _copy_kintoun_tree(self.combined_dir / "src" / "kintoun", bdir / "src")
            synced_tree = self._tree_sha_of_dir(bdir)
            st.setdefault("bases", {})[bid] = {"commit": sha, "tree": synced_tree, "synced_at": _utc_stamp()}
            st.setdefault("events", []).insert(0, f"{_utc_stamp()} {bid} committed {sha[:10]}: {clean_claim}")
            st["events"] = st["events"][:120]
            _atomic_json_write(self.state_json, st)
        return {"ok": True, "builder": bid, "sha": sha, "files": files, "claim": clean_claim}

    # -------------------- Shared Findings & In-Flight Lock --------------------

    def findings_start(self, builder_id: str, change: str, what: str = "") -> dict[str, Any]:
        """Claim an in-flight hypothesis slug so two builders never duplicate the same work."""
        self._ensure_initialized()
        bid = builder_id.strip()
        slug = _norm_slug(change)
        if not slug:
            return {"ok": False, "error": "change label must contain alphanumeric characters"}
        with _file_lock(self._lock_file):
            inf = _read_json(self.inflight_json, {})
            for other_b, rec in inf.items():
                if other_b != bid and _norm_slug(str(rec.get("change", ""))) == slug:
                    return {
                        "ok": False,
                        "refused": True,
                        "error": (
                            f"REFUSED: builder '{other_b}' is already working on '{rec.get('change')}' "
                            f"({rec.get('what', '')}). Pick a different hypothesis."
                        ),
                    }
            inf[bid] = {"change": change.strip()[:80], "what": " ".join(what.split())[:200], "started": _utc_stamp()}
            _atomic_json_write(self.inflight_json, inf)
        return {"ok": True, "builder": bid, "change": change.strip(), "inflight": inf}

    def findings_log(
        self,
        builder_id: str,
        change: str,
        *,
        dev_summary: str = "",
        verdict: str = "tested",
        lesson: str = "",
    ) -> dict[str, Any]:
        """Prepend one structured finding line to `findings.md`."""
        self._ensure_initialized()
        clean = lambda s, lim: " ".join(str(s or "").replace("|", "/").split())[:lim]
        entry = (
            f"- {_utc_stamp()} | {clean(builder_id, 20)} | {clean(change, 60)} | "
            f"dev {clean(dev_summary, 60) or 'n/a'} | {clean(verdict, 40)} | lesson: {clean(lesson, 220) or '-'}"
        )
        with _file_lock(self._lock_file):
            txt = self.findings_md.read_text(encoding="utf-8") if self.findings_md.is_file() else (_FINDINGS_HEADER + _FINDINGS_MARKER)
            if _FINDINGS_MARKER not in txt:
                txt = _FINDINGS_HEADER + _FINDINGS_MARKER + txt
            head, _, tail = txt.partition(_FINDINGS_MARKER)
            tmp = self.findings_md.with_suffix(".md.tmp")
            tmp.write_text(head + _FINDINGS_MARKER + entry + "\n" + tail, encoding="utf-8")
            os.replace(tmp, self.findings_md)
        return {"ok": True, "entry": entry}

    def findings_done(self, builder_id: str) -> dict[str, Any]:
        self._ensure_initialized()
        with _file_lock(self._lock_file):
            inf = _read_json(self.inflight_json, {})
            popped = inf.pop(builder_id.strip(), None)
            _atomic_json_write(self.inflight_json, inf)
        return {"ok": True, "builder": builder_id.strip(), "cleared": popped}

    def findings_show(self, limit: int = 15) -> dict[str, Any]:
        self._ensure_initialized()
        inf = _read_json(self.inflight_json, {})
        txt = self.findings_md.read_text(encoding="utf-8") if self.findings_md.is_file() else ""
        lines = [ln for ln in txt.partition(_FINDINGS_MARKER)[2].splitlines() if ln.startswith("- ")][: max(1, limit)]
        return {"inflight": inf, "entries": lines}

    # -------------------- Seen Ledger & Stratified Unseen Sampling --------------------

    def _record_seen(self, names_or_addrs: list[str], *, by_builder: bool) -> None:
        if not names_or_addrs:
            return
        with _file_lock(self._lock_file):
            seen = _read_json(self.seen_json, {"seen_by_builders": [], "seen_in_gates": [], "gate_runs": 0})
            key = "seen_by_builders" if by_builder else "seen_in_gates"
            cur = set(seen.get(key) or [])
            cur.update(str(x) for x in names_or_addrs if x)
            seen[key] = sorted(cur)
            if not by_builder:
                seen["gate_runs"] = int(seen.get("gate_runs", 0)) + 1
            _atomic_json_write(self.seen_json, seen)

    def seen_ledger(self) -> dict[str, Any]:
        self._ensure_initialized()
        return _read_json(self.seen_json, {"seen_by_builders": [], "seen_in_gates": [], "gate_runs": 0})

    def _resolve_seed_code(
        self,
        tf: TargetFunction,
        ctx: TargetContext,
        seeds_dir: Path | None = None,
    ) -> str:
        if seeds_dir is not None and Path(seeds_dir).is_dir():
            for cand_name in (f"{tf.name}.c", f"0x{tf.va:08X}.c"):
                sp = Path(seeds_dir) / cand_name
                if sp.is_file():
                    return sp.read_text(encoding="utf-8")
        hint_c = self.kintoun_dir / "hints" / f"{tf.name}.c"
        if hint_c.is_file():
            return hint_c.read_text(encoding="utf-8")
        return synthesize_baseline_seed(tf, ctx)

    def _sample_stratified_functions(
        self,
        ctx: TargetContext,
        *,
        count: int,
        seed: int,
        exclude_keys: set[str],
        matched_names: set[str],
        seeds_dir: Path | None = None,
    ) -> list[dict[str, Any]]:
        rng = random.Random(seed)
        buckets: dict[str, list[dict[str, Any]]] = {b[0]: [] for b in SIZE_BUCKETS}

        for name, (va, size) in sorted(ctx.funcs.items(), key=lambda kv: kv[1][0]):
            if size <= 0 or name in matched_names:
                continue
            addr_s = f"0x{va:08X}"
            if name in exclude_keys or addr_s in exclude_keys:
                continue
            try:
                tf = ctx.resolve_function(name)
                chk = check_function(tf, ctx)
                if not chk["plain_c"]:
                    continue
                diff = score_difficulty(tf, ctx)
            except Exception:
                continue

            item = {
                "func": name,
                "addr": addr_s,
                "size_bytes": size,
                "tier": diff["tier"],
                "tags": diff["tags"],
                "code": self._resolve_seed_code(tf, ctx, seeds_dir=seeds_dir),
            }
            for label, lo, hi, _q in SIZE_BUCKETS:
                if lo <= size < hi:
                    buckets[label].append(item)
                    break

        total_default_q = sum(b[3] for b in SIZE_BUCKETS)
        picked: list[dict[str, Any]] = []
        leftovers: list[dict[str, Any]] = []
        for label, _lo, _hi, default_q in SIZE_BUCKETS:
            pool = buckets[label]
            rng.shuffle(pool)
            scaled_q = max(1, round(count * (default_q / total_default_q)))
            picked.extend(pool[:scaled_q])
            leftovers.extend(pool[scaled_q:])

        if len(picked) < count and leftovers:
            rng.shuffle(leftovers)
            picked.extend(leftovers[: count - len(picked)])
        return picked[:count]

    def make_dev_set(
        self,
        ctx: TargetContext,
        *,
        out_path: Path | None = None,
        count: int = 24,
        seed: int = 1,
        src_dir: Path | None = None,
        seeds_dir: Path | None = None,
    ) -> dict[str, Any]:
        """Build a stratified `dev` benchmark manifest and permanently mark its functions `seen_by_builders`."""
        self._ensure_initialized()
        eff_src = src_dir if src_dir is not None else (self.cfg.root / "src")
        matched = set(index_matched_c_functions(eff_src).keys())
        ledger = self.seen_ledger()
        # Exclude functions already used in unseen gates so dev & gate never cross-pollinate
        exclude = set(ledger.get("seen_in_gates") or [])
        rows = self._sample_stratified_functions(
            ctx,
            count=max(1, count),
            seed=seed,
            exclude_keys=exclude,
            matched_names=matched,
            seeds_dir=seeds_dir,
        )
        tainted = [r["func"] for r in rows] + [r["addr"] for r in rows]
        self._record_seen(tainted, by_builder=True)

        dest = Path(out_path) if out_path is not None else (self.sets_dir / f"dev_s{seed}.json")
        doc = {
            "set_id": f"dev-s{seed}",
            "kind": "dev",
            "created": _utc_stamp(),
            "seed": seed,
            "functions": rows,
        }
        _atomic_json_write(dest, doc)
        return {"ok": True, "manifest": str(dest), "count": len(rows), "set_id": doc["set_id"]}

    def sample_unseen_gate_set(
        self,
        ctx: TargetContext | None,
        *,
        count: int = 40,
        seed: int | None = None,
        src_dir: Path | None = None,
        seeds_dir: Path | None = None,
        pool_manifest: Path | None = None,
    ) -> dict[str, Any]:
        """Draw a fresh unseen promotion-gate manifest strictly excluding all `seen_by_builders` functions."""
        self._ensure_initialized()
        ledger = self.seen_ledger()
        builder_tainted = set(ledger.get("seen_by_builders") or [])
        prior_gates = set(ledger.get("seen_in_gates") or [])
        eff_seed = seed if seed is not None else int(time.time() * 1000) & 0x7FFFFFFF

        if pool_manifest is not None:
            raw = _read_json(Path(pool_manifest), [])
            items = raw.get("functions", []) if isinstance(raw, dict) else raw
            fresh_pool = [
                it
                for it in items
                if str(it.get("func") or it.get("name") or "") not in builder_tainted
                and str(it.get("addr") or "") not in builder_tainted
                and str(it.get("func") or it.get("name") or "") not in prior_gates
            ]
            # If every unseen pool item was already used in earlier gates (small personal project),
            # recycle prior-gate items ONLY - NEVER `builder_tainted` items!
            if len(fresh_pool) < min(count, 4):
                fresh_pool = [
                    it
                    for it in items
                    if str(it.get("func") or it.get("name") or "") not in builder_tainted
                    and str(it.get("addr") or "") not in builder_tainted
                ]
            rng = random.Random(eff_seed)
            shuffled = list(fresh_pool)
            rng.shuffle(shuffled)
            rows = shuffled[:count]
        else:
            if ctx is None:
                raise ValueError("TargetContext or --pool-manifest is required to sample unseen gate functions")
            eff_src = src_dir if src_dir is not None else (self.cfg.root / "src")
            matched = set(index_matched_c_functions(eff_src).keys())
            rows = self._sample_stratified_functions(
                ctx,
                count=count,
                seed=eff_seed,
                exclude_keys=builder_tainted | prior_gates,
                matched_names=matched,
                seeds_dir=seeds_dir,
            )
            if len(rows) < min(count, 6):
                # Recycle prior gate functions if binary is small, while STILL strictly excluding `builder_tainted`!
                rows = self._sample_stratified_functions(
                    ctx,
                    count=count,
                    seed=eff_seed,
                    exclude_keys=builder_tainted,
                    matched_names=matched,
                    seeds_dir=seeds_dir,
                )

        seen_keys = [str(r.get("func") or r.get("name") or "") for r in rows] + [
            str(r.get("addr") or "") for r in rows if r.get("addr")
        ]
        self._record_seen(seen_keys, by_builder=False)
        rows_sig = hashlib.sha256(
            json.dumps([r.get("func") or r.get("name") for r in rows]).encode("utf-8")
        ).hexdigest()[:16]
        return {
            "set_id": f"unseen-gate-{eff_seed}",
            "seed": eff_seed,
            "rows_hash": rows_sig,
            "functions": rows,
        }

    # -------------------- Isolated Headless Arm Execution --------------------

    def resolve_arm_src(self, arm: str) -> tuple[str, Path]:
        """Resolve `'live'`, `'combined'`, `'b1'..'bN'`, or an explicit directory to its `src` folder."""
        self._ensure_initialized()
        key = arm.strip()
        if key == "live":
            return "live", self.live_dir / "src"
        if key == "combined":
            self._git("checkout", "-q", "-f", "combined")
            return "combined", self.combined_dir / "src"
        if (self.builders_dir / key / "src" / "kintoun").is_dir():
            return key, self.builders_dir / key / "src"
        p = Path(key).resolve()
        if (p / "src" / "kintoun").is_dir():
            return p.name, p / "src"
        if (p / "kintoun").is_dir():
            return p.parent.name, p
        raise ValueError(f"unknown engine arm '{arm}' (expected live, combined, b1..bN, or path containing src/kintoun)")

    def run_isolated_arm(
        self,
        arm: str,
        manifest_doc: dict[str, Any] | Path,
        *,
        budget_s: float = 15.0,
        max_candidates: int = 200,
        workers: int = 1,
        mark_builder_seen: bool = False,
        close_threshold_pct: float = 85.0,
    ) -> dict[str, Any]:
        """Execute `run_benchmark` inside a clean subprocess using `arm`'s `PYTHONPATH` and an ephemeral cache."""
        label, arm_src = self.resolve_arm_src(arm)
        if isinstance(manifest_doc, Path):
            mdoc = _read_json(manifest_doc, {})
            items = mdoc.get("functions") or mdoc.get("items") or (mdoc if isinstance(mdoc, list) else [])
        else:
            mdoc = manifest_doc
            items = mdoc.get("functions") or []

        if mark_builder_seen:
            tainted = [str(it.get("func") or it.get("name") or "") for it in items] + [
                str(it.get("addr") or "") for it in items if it.get("addr")
            ]
            self._record_seen(tainted, by_builder=True)

        rows_hash = hashlib.sha256(
            json.dumps([it.get("func") or it.get("name") for it in items]).encode("utf-8")
        ).hexdigest()[:16]

        with tempfile.TemporaryDirectory(prefix=f"arm_{label}_", dir=str(self.sandbox_dir)) as run_tmp:
            tmp_p = Path(run_tmp)
            man_p = tmp_p / "manifest.json"
            out_p = tmp_p / "report.json"
            iso_cache = tmp_p / "cache"
            iso_cache.mkdir(parents=True, exist_ok=True)
            _atomic_json_write(man_p, {"functions": items})

            driver = (
                "import json, pathlib, sys\n"
                "sys.dont_write_bytecode = True\n"
                "from kintoun.config import load_config\n"
                "from kintoun.lab import run_benchmark\n"
                "cfg_arg, root_arg, man_arg, out_arg, cache_arg, b_s, max_c, w_n = sys.argv[1:9]\n"
                "cfg = load_config(pathlib.Path(cfg_arg) if cfg_arg else None)\n"
                "cfg.root = pathlib.Path(root_arg)\n"
                "cfg.search.cache_dir = cache_arg\n"
                "rep = run_benchmark(cfg, pathlib.Path(man_arg), budget_s=float(b_s), max_candidates=int(max_c), workers=int(w_n))\n"
                "pathlib.Path(out_arg).write_text(json.dumps(rep), encoding='utf-8')\n"
            )
            cfg_file = self.cfg.root / "kintoun.toml"
            existing_pp = os.environ.get("PYTHONPATH", "")
            pp = f"{arm_src}{os.pathsep}{existing_pp}" if existing_pp else str(arm_src)
            env = {
                **os.environ,
                "PYTHONPATH": pp,
                "PYTHONDONTWRITEBYTECODE": "1",
                "KINTOUN_DISABLE_LOCAL_ENGINE": "1",
            }
            proc = subprocess.run(
                [
                    sys.executable,
                    "-B",
                    "-c",
                    driver,
                    str(cfg_file) if cfg_file.is_file() else "",
                    str(self.cfg.root),
                    str(man_p),
                    str(out_p),
                    str(iso_cache),
                    str(budget_s),
                    str(max_candidates),
                    str(max(1, workers)),
                ],
                cwd=str(self.cfg.root),
                env=env,
                capture_output=True,
                text=True,
                timeout=max(60.0, budget_s * max(1, len(items)) * 2.5 + 60.0),
            )
            if proc.returncode != 0 or not out_p.is_file():
                return {
                    "ok": False,
                    "arm": label,
                    "tree_hash": tree_digest(arm_src),
                    "rows_hash": rows_hash,
                    "error": (proc.stderr or proc.stdout or "isolated benchmark failed").strip()[-500:],
                }
            rep = json.loads(out_p.read_text(encoding="utf-8"))

        res_rows = rep.get("results") or []
        n = max(1, len(res_rows))
        exact_names = sorted(r["name"] for r in res_rows if r.get("verified"))
        close_count = sum(1 for r in res_rows if r.get("verified") or float(r.get("aligned_pct", 0.0)) >= close_threshold_pct)
        return {
            "ok": True,
            "arm": label,
            "tree_hash": tree_digest(arm_src),
            "rows_hash": rows_hash,
            "functions": len(res_rows),
            "verified": len(exact_names),
            "verified_pct": round(100.0 * len(exact_names) / n, 2) if res_rows else 0.0,
            "exact_names": exact_names,
            "mean_aligned_pct": float(rep.get("mean_aligned_pct", 0.0)),
            "close_count": close_count,
            "close_pct": round(100.0 * close_count / n, 2) if res_rows else 0.0,
            "elapsed_s": rep.get("elapsed_s", 0.0),
            "results": res_rows,
        }

    # -------------------- Strict Dual-Metric Unseen Gate, Ablation & Promotion --------------------

    @staticmethod
    def judge_ab_gate(
        live_rep: dict[str, Any],
        cand_rep: dict[str, Any],
        *,
        solved_live: dict[str, Any] | None = None,
        solved_cand: dict[str, Any] | None = None,
        min_functions: int = 4,
        min_exact_delta: int = 1,
        min_align_delta: float = 0.01,
    ) -> dict[str, Any]:
        """Evaluate whether `cand_rep` provably beats `live_rep` on BOTH closeness % and exact matches."""
        reasons: list[str] = []
        if not live_rep.get("ok") or not cand_rep.get("ok"):
            reasons.append(f"arm error: live={live_rep.get('error', 'ok')}, cand={cand_rep.get('error', 'ok')}")
            return {"win": False, "reasons": reasons}

        if live_rep.get("rows_hash") != cand_rep.get("rows_hash"):
            reasons.append("rows_hash mismatch between live and candidate arms")

        n = int(cand_rep.get("functions", 0))
        if n < min_functions:
            reasons.append(f"unseen sample size {n} < required min_functions ({min_functions})")

        lost_unseen = sorted(set(live_rep.get("exact_names") or []) - set(cand_rep.get("exact_names") or []))
        if lost_unseen:
            reasons.append(f"lost exact match(es) on unseen set: {lost_unseen}")

        if solved_live and solved_cand:
            lost_solved = sorted(set(solved_live.get("exact_names") or []) - set(solved_cand.get("exact_names") or []))
            if lost_solved:
                reasons.append(f"lost exact match(es) on already-solved guard set: {lost_solved}")

        exact_delta = int(cand_rep["verified"]) - int(live_rep["verified"])
        align_delta = round(float(cand_rep["mean_aligned_pct"]) - float(live_rep["mean_aligned_pct"]), 2)
        close_delta = round(float(cand_rep["close_pct"]) - float(live_rep["close_pct"]), 2)

        if exact_delta < min_exact_delta:
            reasons.append(
                f"exact matches delta {exact_delta:+d} < +{min_exact_delta} "
                f"({live_rep['verified']} -> {cand_rep['verified']})"
            )
        if align_delta < min_align_delta:
            reasons.append(
                f"mean aligned % delta {align_delta:+.2f}% < +{min_align_delta:.2f}% "
                f"({live_rep['mean_aligned_pct']:.2f}% -> {cand_rep['mean_aligned_pct']:.2f}%)"
            )
        if close_delta < 0.0:
            reasons.append(
                f"close-to-matched (>=85%) rate regressed ({live_rep['close_pct']:.2f}% -> {cand_rep['close_pct']:.2f}%)"
            )

        return {
            "win": len(reasons) == 0,
            "reasons": reasons,
            "functions": n,
            "exact_delta": exact_delta,
            "mean_aligned_delta": align_delta,
            "close_pct_delta": close_delta,
            "gained_exact": sorted(set(cand_rep.get("exact_names") or []) - set(live_rep.get("exact_names") or [])),
            "lost_exact": lost_unseen,
        }

    def ablate_combined_commits(
        self,
        gate_manifest: dict[str, Any],
        *,
        head_rep: dict[str, Any],
        budget_s: float,
        max_candidates: int,
        workers: int,
    ) -> list[dict[str, Any]]:
        """Test `combined` minus each commit when `>= 2` commits exist; revert non-contributing commits."""
        commits = self.commits_since_live()
        if len(commits) <= 1 or not head_rep.get("ok"):
            return []

        ablation_log: list[dict[str, Any]] = []
        for c in commits[:6]:
            sha = c["sha"]
            wt = Path(tempfile.mkdtemp(prefix="ablate_", dir=str(self.sandbox_dir)))
            shutil.rmtree(wt)
            try:
                self._git("worktree", "add", "-q", "--detach", str(wt), "combined")
                rev = self._git("revert", "--no-edit", sha, cwd=wt, check=False)
                if rev.returncode != 0:
                    ablation_log.append({"sha": sha[:10], "subject": c["subject"], "action": "kept (non-trivial revert)"})
                    continue
                minus_rep = self.run_isolated_arm(
                    str(wt / "src"),
                    gate_manifest,
                    budget_s=budget_s,
                    max_candidates=max_candidates,
                    workers=workers,
                )
                if not minus_rep.get("ok"):
                    continue
                d_exact = int(head_rep["verified"]) - int(minus_rep["verified"])
                d_align = round(float(head_rep["mean_aligned_pct"]) - float(minus_rep["mean_aligned_pct"]), 2)
                helps = d_exact > 0 or (d_exact == 0 and d_align >= 0.25)
                if helps:
                    ablation_log.append(
                        {
                            "sha": sha[:10],
                            "subject": c["subject"],
                            "exact_contrib": d_exact,
                            "align_contrib": d_align,
                            "action": "kept",
                        }
                    )
                else:
                    with _file_lock(self._lock_file):
                        self._git("checkout", "-q", "-f", "combined")
                        r_main = self._git("revert", "--no-edit", sha, check=False)
                        if r_main.returncode == 0:
                            ablation_log.append(
                                {
                                    "sha": sha[:10],
                                    "subject": c["subject"],
                                    "exact_contrib": d_exact,
                                    "align_contrib": d_align,
                                    "action": "reverted (no positive contribution)",
                                }
                            )
                        else:
                            self._git("revert", "--abort", check=False)
            finally:
                self._git("worktree", "remove", "--force", str(wt), check=False)
                self._git("worktree", "prune", check=False)
        return ablation_log

    def promote_arm(self, arm: str, gate_summary: dict[str, Any]) -> dict[str, Any]:
        """Back up `live/` with `PROMOTION_MANIFEST.json`, promote `arm` into `live/`, and enable project overlay."""
        label, cand_src = self.resolve_arm_src(arm)
        cand_pkg = cand_src / "kintoun"
        live_pkg = self.live_dir / "src" / "kintoun"

        errs = validate_python_tree(cand_src)
        if errs:
            return {"ok": False, "error": "refusing promotion; py_compile failed: " + "; ".join(errs[:3])}

        with _file_lock(self._lock_file):
            stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%d-%H%M%S")
            bdir = self.backups_dir / f"engine-{stamp}"
            _copy_kintoun_tree(live_pkg, bdir / "src")

            live_files = {
                p.relative_to(live_pkg).as_posix(): p.read_bytes()
                for p in sorted(live_pkg.rglob("*"))
                if p.is_file() and "__pycache__" not in p.parts and not p.name.endswith(".pyc")
            }
            cand_files = {
                p.relative_to(cand_pkg).as_posix(): p.read_bytes()
                for p in sorted(cand_pkg.rglob("*"))
                if p.is_file() and "__pycache__" not in p.parts and not p.name.endswith(".pyc")
            }

            changed = sorted(k for k in (live_files.keys() & cand_files.keys()) if live_files[k] != cand_files[k])
            added = sorted(cand_files.keys() - live_files.keys())
            deleted = sorted(live_files.keys() - cand_files.keys())

            manifest = {
                "stamp": stamp,
                "promoted_at": _utc_stamp(),
                "from_arm": label,
                "old_tree_hash": tree_digest(self.live_dir / "src"),
                "new_tree_hash": tree_digest(cand_src),
                "changed": changed,
                "added": added,
                "deleted": deleted,
                "gate_summary": gate_summary,
            }
            _atomic_json_write(bdir / "PROMOTION_MANIFEST.json", manifest)
            _atomic_json_write(self.backups_dir / "LATEST.json", {"backup_dir": str(bdir), "stamp": stamp})

            # Atomic file replacement into `live/src/kintoun`
            for rel in changed + added:
                dst = live_pkg / rel
                dst.parent.mkdir(parents=True, exist_ok=True)
                tmp = dst.with_name(f".{dst.name}.promote-tmp")
                shutil.copy2(cand_pkg / rel, tmp)
                os.replace(tmp, dst)
            for rel in deleted:
                (live_pkg / rel).unlink(missing_ok=True)

            # Sync local git `live` branch to match promoted `live/`
            _copy_kintoun_tree(live_pkg, self.combined_dir / "src")
            self._git("checkout", "-q", "-f", "live")
            _copy_kintoun_tree(live_pkg, self.combined_dir / "src")
            self._git("add", "-A", ".")
            if self._git("status", "--porcelain").stdout.strip():
                self._git("commit", "-q", "-m", f"promote({label}): {stamp}")
            live_sha = self._git("rev-parse", "live").stdout.strip()
            if label == "combined":
                self._git("checkout", "-q", "-B", "combined", live_sha)
            else:
                self._git("checkout", "-q", "combined")

            _atomic_json_write(
                self.active_json,
                {
                    "enabled": True,
                    "live_src": str(self.live_dir / "src"),
                    "tree_hash": tree_digest(self.live_dir / "src"),
                    "promoted_at": _utc_stamp(),
                    "backup_dir": str(bdir),
                },
            )
            st = _read_json(self.state_json, {"bases": {}, "events": [], "promotions": 0})
            st["promotions"] = int(st.get("promotions", 0)) + 1
            st.setdefault("events", []).insert(0, f"{_utc_stamp()} PROMOTED {label} -> live (backup {bdir.name})")
            _atomic_json_write(self.state_json, st)

        return {
            "ok": True,
            "promoted": True,
            "from_arm": label,
            "live_commit": live_sha,
            "backup_dir": str(bdir),
            "changed_files": len(changed) + len(added) + len(deleted),
            "manifest": manifest,
        }

    def rollback(self, backup_dir: Path | None = None, *, disable_overlay: bool = False) -> dict[str, Any]:
        """Atomically restore `live/` from `PROMOTION_MANIFEST.json` (or disable overlay back to stock Kintoun)."""
        self._ensure_initialized()
        with _file_lock(self._lock_file):
            if disable_overlay:
                _atomic_json_write(self.active_json, {"enabled": False, "updated_at": _utc_stamp()})
                return {"ok": True, "overlay_enabled": False}

            if backup_dir is None:
                latest = _read_json(self.backups_dir / "LATEST.json", {})
                if not latest.get("backup_dir"):
                    return {"ok": False, "error": "no backup found in .kintoun/engine_lab/backups/LATEST.json"}
                bdir = Path(latest["backup_dir"])
            else:
                bdir = Path(backup_dir)

            man_p = bdir / "PROMOTION_MANIFEST.json"
            if not man_p.is_file():
                return {"ok": False, "error": f"missing PROMOTION_MANIFEST.json in {bdir}"}
            man = _read_json(man_p, {})
            src_pkg = bdir / "src" / "kintoun"
            live_pkg = self.live_dir / "src" / "kintoun"

            restored = 0
            for rel in man.get("changed", []) + man.get("deleted", []):
                dst = live_pkg / rel
                dst.parent.mkdir(parents=True, exist_ok=True)
                tmp = dst.with_name(f".{dst.name}.rollback-tmp")
                shutil.copy2(src_pkg / rel, tmp)
                os.replace(tmp, dst)
                restored += 1
            for rel in man.get("added", []):
                if (live_pkg / rel).is_file():
                    (live_pkg / rel).unlink()
                    restored += 1

            # Verify byte-identical restoration
            for rel in man.get("changed", []) + man.get("deleted", []):
                if (src_pkg / rel).read_bytes() != (live_pkg / rel).read_bytes():
                    raise RuntimeError(f"rollback byte check failed on {rel}")

            _atomic_json_write(
                self.active_json,
                {
                    "enabled": True,
                    "live_src": str(self.live_dir / "src"),
                    "tree_hash": tree_digest(self.live_dir / "src"),
                    "rolled_back_at": _utc_stamp(),
                    "restored_from": str(bdir),
                },
            )
            st = _read_json(self.state_json, {"bases": {}, "events": []})
            st.setdefault("events", []).insert(0, f"{_utc_stamp()} ROLLED BACK live from {bdir.name}")
            _atomic_json_write(self.state_json, st)

        return {"ok": True, "restored_files": restored, "from_backup": str(bdir)}

    def run_unseen_gate(
        self,
        *,
        candidate_arm: str = "combined",
        ctx: TargetContext | None = None,
        count: int = 40,
        budget_s: float = 20.0,
        max_candidates: int = 250,
        workers: int = 1,
        min_functions: int = 4,
        min_exact_delta: int = 1,
        min_align_delta: float = 0.01,
        confirm_runs: int = 1,
        ablate: bool = True,
        promote: bool = False,
        seeds_dir: Path | None = None,
        pool_manifest: Path | None = None,
    ) -> dict[str, Any]:
        """Run `live` vs `candidate_arm` on a fresh unseen function array, ablate commits, and optionally promote."""
        self._ensure_initialized()
        eff_ctx = ctx
        if eff_ctx is None and pool_manifest is None and (self.cfg.target.dol or self.cfg.target.binary):
            eff_ctx = load_target_from_config(self.cfg)

        rounds_out: list[dict[str, Any]] = []
        ablation_out: list[dict[str, Any]] = []
        overall_win = True

        n_rounds = max(1, min(3, int(confirm_runs)))
        for round_idx in range(n_rounds):
            gate_set = self.sample_unseen_gate_set(
                eff_ctx,
                count=count,
                src_dir=self.cfg.root / "src",
                seeds_dir=seeds_dir,
                pool_manifest=pool_manifest,
            )
            eff_min_fns = min(min_functions, len(gate_set["functions"])) if len(gate_set["functions"]) >= 2 else min_functions
            live_rep = self.run_isolated_arm(
                "live",
                gate_set,
                budget_s=budget_s,
                max_candidates=max_candidates,
                workers=workers,
            )
            cand_rep = self.run_isolated_arm(
                candidate_arm,
                gate_set,
                budget_s=budget_s,
                max_candidates=max_candidates,
                workers=workers,
            )

            if round_idx == 0 and ablate and candidate_arm == "combined":
                ablation_out = self.ablate_combined_commits(
                    gate_set,
                    head_rep=cand_rep,
                    budget_s=budget_s,
                    max_candidates=max_candidates,
                    workers=workers,
                )
                if any(a.get("action", "").startswith("reverted") for a in ablation_out):
                    # Re-evaluate pruned `combined` HEAD cleanly on the same unseen gate set
                    cand_rep = self.run_isolated_arm(
                        "combined",
                        gate_set,
                        budget_s=budget_s,
                        max_candidates=max_candidates,
                        workers=workers,
                    )

            verdict = self.judge_ab_gate(
                live_rep,
                cand_rep,
                min_functions=eff_min_fns,
                min_exact_delta=min_exact_delta,
                min_align_delta=min_align_delta,
            )
            rounds_out.append(
                {
                    "round": round_idx + 1,
                    "set_id": gate_set["set_id"],
                    "rows_hash": gate_set["rows_hash"],
                    "live": {k: v for k, v in live_rep.items() if k != "results"},
                    "candidate": {k: v for k, v in cand_rep.items() if k != "results"},
                    "verdict": verdict,
                }
            )
            if not verdict["win"]:
                overall_win = False
                break

        promo_res: dict[str, Any] | None = None
        if overall_win and promote:
            promo_res = self.promote_arm(candidate_arm, {"rounds": rounds_out, "ablations": ablation_out})

        record = {
            "ts": _utc_stamp(),
            "candidate_arm": candidate_arm,
            "win": overall_win,
            "promoted": bool(promo_res and promo_res.get("promoted")),
            "ablations": ablation_out,
            "rounds": rounds_out,
            "promotion": promo_res,
        }
        with self.gate_log_jsonl.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record) + "\n")
        return record

    def status(self) -> dict[str, Any]:
        self._ensure_initialized()
        st = _read_json(self.state_json, {"bases": {}, "events": [], "promotions": 0})
        active = _read_json(self.active_json, {"enabled": False})
        ledger = self.seen_ledger()
        inf = _read_json(self.inflight_json, {})
        return {
            "lab_dir": str(self.lab_dir),
            "overlay_enabled": bool(active.get("enabled")),
            "live_commit": self._git("rev-parse", "live").stdout.strip(),
            "live_tree_hash": tree_digest(self.live_dir / "src"),
            "combined_head": self._git("rev-parse", "combined").stdout.strip(),
            "commits_above_live": self.commits_since_live(),
            "builders": st.get("bases", {}),
            "inflight": inf,
            "seen_counts": {
                "seen_by_builders": len(ledger.get("seen_by_builders") or []),
                "seen_in_gates": len(ledger.get("seen_in_gates") or []),
                "gate_runs": int(ledger.get("gate_runs", 0)),
            },
            "promotions": int(st.get("promotions", 0)),
            "recent_events": (st.get("events") or [])[:8],
        }
