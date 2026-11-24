"""Stratified 60-function zero-prior-context AI agent benchmark harness (`kintoun agent-bench`).

Provides a clean, reproducible, open-source benchmark protocol for evaluating AI coding agents
paired with Kintoun on any PowerPC, MIPS, or ARM/Thumb binary:
  1. `select_agent_benchmark`: deterministically selects a stratified set of plain-C functions
     (default 60: 12 per byte-size tier across 5 size tiers, balanced across 6 structural families
     with `shape_hash` deduplication).
  2. `run_agent_benchmark`: runs an external CLI agent (`agy`, `claude`, `codex`, or custom command)
     with **strict zero prior context** (one fresh isolated temporary workspace per function, hex-only
     anonymous symbols, no cross-function project history, hard per-function wall-clock limit
     defaulting to 30 minutes / 1800s), optional headless `kintoun permute` baseline, and independent
     ground-truth `verify_source(..., forbid_asm=True)` auditing (including recovery of the highest-ranked
     valid real-C candidate from `.kintoun/cache/candidates.sqlite3` if the timer expires mid-edit).
  3. `render_agent_bench_markdown`: emits publication-ready GitHub Markdown summary tables broken down
     by byte-size tier and structural family with zero copyrighted C source or local paths.
"""
from __future__ import annotations

from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import os
from pathlib import Path
import random
import re
import shlex
import shutil
import signal
import sqlite3
import statistics
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any

from kintoun.compiler import make_compiler
from kintoun.config import KintounConfig
from kintoun.inspect_fn import check_function, score_difficulty
from kintoun.search.runner import rank_result, run_search
from kintoun.targets import TargetContext, TargetFunction, load_target_from_config, load_target_from_object
from kintoun.verify import real_c_violation, verify_source

SIZE_TIERS: tuple[tuple[str, int, int], ...] = (
    ("tiny_24_64B", 24, 64),
    ("small_68_136B", 68, 136),
    ("medium_140_260B", 140, 260),
    ("large_264_480B", 264, 480),
    ("xlarge_484_960B", 484, 960),
)

FAMILIES: tuple[str, ...] = (
    "leaf_int",
    "branch_guard",
    "loop",
    "float_fpu",
    "call_chain",
    "vtable_dispatch",
)

_HEX_SYM_RE = re.compile(r"^(?:fn|func|sub|lbl|D|jpt)_[0-9A-Fa-f]{6,8}$")


def size_tier_for(size_bytes: int) -> str | None:
    """Return the canonical byte-size tier name for `size_bytes`, or `None` if outside `[24, 960]`."""
    for name, lo, hi in SIZE_TIERS:
        if lo <= size_bytes <= hi:
            return name
    return None


def classify_structural_family(chk: dict[str, Any]) -> str | None:
    """Classify a `check_function` report into one of the 6 structural benchmark families."""
    if not chk.get("plain_c"):
        return None
    feats = chk.get("features") or {}
    calls = int(feats.get("calls", 0))
    icalls = int(feats.get("indirect_calls", 0))
    loops = int(feats.get("loops", 0))
    conds = int(feats.get("cond_branches", 0))
    floats = int(feats.get("float_ops", 0))
    int_fp = int(feats.get("int_float_conv", 0))

    if icalls > 0:
        return "vtable_dispatch"
    if floats >= 2 or int_fp > 0:
        return "float_fpu"
    if loops > 0:
        return "loop"
    if calls == 0 and conds == 0:
        return "leaf_int"
    if calls == 0 and conds > 0:
        return "branch_guard"
    return "call_chain"


def select_agent_benchmark(
    ctx: TargetContext,
    *,
    count: int = 60,
    seed: int = 20261124,
    configured_preset: str = "",
    va_min: int = 0,
    va_max: int = 0xFFFFFFFF,
    exclude_switches: bool = True,
    candidate_names: list[str] | None = None,
) -> dict[str, Any]:
    """Select `count` plain-C functions stratified across 5 byte-size tiers and 6 structural families."""
    rng = random.Random(seed)
    names = list(candidate_names) if candidate_names is not None else sorted(ctx.funcs, key=lambda n: ctx.funcs[n][0])

    by_cell: dict[tuple[str, str], list[dict[str, Any]]] = {}
    seen_shapes: set[str] = set()
    scanned = 0

    for fname in names:
        if fname not in ctx.funcs:
            continue
        va, sz = ctx.funcs[fname]
        if va < va_min or va >= va_max:
            continue
        tier = size_tier_for(sz)
        if tier is None:
            continue
        try:
            tf = ctx.resolve_function(fname)
        except Exception:
            continue
        scanned += 1
        chk = check_function(tf, ctx, configured_preset=configured_preset)
        if not chk.get("plain_c"):
            continue
        feats = chk.get("features") or {}
        if exclude_switches and int(feats.get("switches", 0)) > 0:
            continue
        fam = classify_structural_family(chk)
        if fam is None:
            continue
        sh = str(chk.get("shape_hash") or "")
        if sh and sh in seen_shapes:
            continue
        if sh:
            seen_shapes.add(sh)
        diff = score_difficulty(tf, ctx)
        rec = {
            "func": tf.name,
            "addr": f"0x{tf.va:08X}",
            "size_bytes": tf.size,
            "size_tier": tier,
            "family": fam,
            "difficulty_score": diff["score"],
            "difficulty_tier": diff["tier"],
            "shape_hash": sh,
            "features": feats,
        }
        by_cell.setdefault((tier, fam), []).append(rec)

    for cell_list in by_cell.values():
        rng.shuffle(cell_list)

    tier_names = [t[0] for t in SIZE_TIERS]
    base_per_tier = count // len(tier_names)
    rem_tiers = count % len(tier_names)
    tier_targets = {
        t: base_per_tier + (1 if idx < rem_tiers else 0)
        for idx, t in enumerate(tier_names)
    }
    fam_target = max(1, count // len(FAMILIES))

    selected: list[dict[str, Any]] = []
    tier_counts: Counter[str] = Counter()
    fam_counts: Counter[str] = Counter()

    # Pass 1: greedily fill rarest-available families first inside each size tier up to `fam_target`.
    avail_by_fam = {
        f: sum(len(by_cell.get((t, f), [])) for t in tier_names)
        for f in FAMILIES
    }
    ordered_fams = sorted(FAMILIES, key=lambda f: (avail_by_fam[f], FAMILIES.index(f)))

    made_progress = True
    while len(selected) < count and made_progress:
        made_progress = False
        for fam in sorted(ordered_fams, key=lambda f: (fam_counts[f], avail_by_fam[f], FAMILIES.index(f))):
            if fam_counts[fam] >= fam_target:
                continue
            # Pick a tier that still needs functions and has candidates for `fam`
            cand_tiers = [
                t for t in tier_names
                if tier_counts[t] < tier_targets[t] and by_cell.get((t, fam))
            ]
            if not cand_tiers:
                continue
            cand_tiers.sort(key=lambda t: (tier_counts[t] - tier_targets[t], -len(by_cell[(t, fam)])))
            chosen_t = cand_tiers[0]
            item = by_cell[(chosen_t, fam)].pop()
            selected.append(item)
            tier_counts[chosen_t] += 1
            fam_counts[fam] += 1
            made_progress = True
            if len(selected) >= count:
                break

    # Pass 2: top up any size tier still short of `tier_targets[t]` preferring lowest-count families.
    for t in tier_names:
        while tier_counts[t] < tier_targets[t] and len(selected) < count:
            fams_with_items = [f for f in FAMILIES if by_cell.get((t, f))]
            if not fams_with_items:
                break
            fams_with_items.sort(key=lambda f: (fam_counts[f], FAMILIES.index(f)))
            chosen_f = fams_with_items[0]
            item = by_cell[(t, chosen_f)].pop()
            selected.append(item)
            tier_counts[t] += 1
            fam_counts[chosen_f] += 1

    # Pass 3: if any tier exhausted early, top up from remaining pool up to `count`.
    while len(selected) < count:
        remaining_cells = [(t, f) for (t, f), lst in by_cell.items() if lst]
        if not remaining_cells:
            break
        remaining_cells.sort(key=lambda tf_pair: (fam_counts[tf_pair[1]], tier_counts[tf_pair[0]]))
        t, f = remaining_cells[0]
        item = by_cell[(t, f)].pop()
        selected.append(item)
        tier_counts[t] += 1
        fam_counts[f] += 1

    selected.sort(key=lambda r: (tier_names.index(r["size_tier"]), FAMILIES.index(r["family"]), int(r["addr"], 16)))
    return {
        "protocol": "kintoun-agent-bench-v1",
        "seed": seed,
        "scanned_candidates": scanned,
        "requested_count": count,
        "selected_count": len(selected),
        "by_size_tier": {t: int(tier_counts[t]) for t in tier_names},
        "by_family": {f: int(fam_counts[f]) for f in FAMILIES},
        "functions": selected,
    }


def _anonymize_symbols_text(ctx: TargetContext) -> tuple[str, dict[str, str]]:
    """Render an anonymous hex-only `symbols.txt` (`fn_XXXXXXXX` / `D_XXXXXXXX`) with zero semantic leaks.

    Returns `(symbols_txt, orig_to_anon_map)`.
    """
    lines: list[str] = []
    orig_to_anon: dict[str, str] = {}
    for fname, (va, sz) in sorted(ctx.funcs.items(), key=lambda kv: kv[1][0]):
        anon = fname if _HEX_SYM_RE.match(fname) else f"fn_{va:08X}"
        orig_to_anon[fname] = anon
        if ctx.arch in ("ppc", "ppc_elf"):
            lines.append(f"{anon} = .text:0x{va:08X}; // type:function size:0x{sz:X}")
        else:
            th = " type:thumb" if (ctx.thumb or va in ctx.thumb_addrs) else ""
            lines.append(f"{anon} = 0x{va:08X}; // type:func size:0x{sz:X}{th}")
    for ova, (oname, osz) in sorted(ctx.objs.items()):
        anon_o = oname if _HEX_SYM_RE.match(oname) else f"D_{ova:08X}"
        orig_to_anon[oname] = anon_o
        sz_part = f" size:0x{osz:X}" if osz > 0 else ""
        if ctx.arch in ("ppc", "ppc_elf"):
            lines.append(f"{anon_o} = .data:0x{ova:08X}; // type:object{sz_part}")
        else:
            lines.append(f"{anon_o} = 0x{ova:08X}; // type:data{sz_part}")
    return "\n".join(lines) + ("\n" if lines else ""), orig_to_anon


def _rewrite_identifiers(source: str, mapping: dict[str, str]) -> str:
    out = source
    for old_name, new_name in mapping.items():
        if old_name != new_name and old_name in out:
            out = re.sub(r"\b" + re.escape(old_name) + r"\b", new_name, out)
    return out


def _write_isolated_toml(
    ws: Path,
    cfg: KintounConfig,
    *,
    rel_binary: str,
    rel_symbols: str,
) -> None:
    """Write a clean, anonymous `kintoun.toml` into `ws` with absolute compiler paths and zero project leaks."""
    comp = cfg.compiler
    tgt = cfg.target
    comp_dir = str(cfg.resolve_path(comp.compiler_dir) or comp.compiler_dir or "")
    flags_json = json.dumps(list(comp.flags))
    cmd_line = f"command = {json.dumps(list(comp.command))}\n" if comp.command else ""
    wine_line = f'wine = {json.dumps(comp.wine)}\n' if comp.wine else ""

    if tgt.arch in ("ppc", "ppc_elf"):
        target_block = (
            f'[target]\n'
            f'arch = "ppc_elf"\n'
            f'dol = {json.dumps(rel_binary)}\n'
            f'symbols = {json.dumps(rel_symbols)}\n'
            f'sda_r13 = "0x{tgt.sda_r13:08X}"\n'
            f'sda_r2 = "0x{tgt.sda_r2:08X}"\n'
        )
    elif tgt.arch in ("arm", "arm_elf"):
        target_block = (
            f'[target]\n'
            f'arch = "arm_elf"\n'
            f'binary = {json.dumps(rel_binary)}\n'
            f'symbols = {json.dumps(rel_symbols)}\n'
            f'base_addr = "0x{tgt.base_addr:08X}"\n'
            f'thumb = {"true" if tgt.thumb else "false"}\n'
        )
    else:
        target_block = (
            f'[target]\n'
            f'arch = "mips_elf"\n'
            f'binary = {json.dumps(rel_binary)}\n'
            f'symbols = {json.dumps(rel_symbols)}\n'
            f'gp = "0x{tgt.gp:08X}"\n'
        )

    toml_text = (
        f'[project]\n'
        f'name = "zero-context-bench"\n\n'
        f'[compiler]\n'
        f'preset = {json.dumps(comp.preset)}\n'
        f'compiler_dir = {json.dumps(comp_dir)}\n'
        f'{wine_line}'
        f'{cmd_line}'
        f'flags = {flags_json}\n'
        f'timeout_s = {float(comp.timeout_s)}\n\n'
        f'{target_block}\n'
        f'[search]\n'
        f'budget_s = 180.0\n'
        f'max_candidates = 2500\n'
        f'mode = "standard"\n'
        f'workers = 2\n'
        f'shared_governor = true\n'
        f'cache_dir = ".kintoun/cache"\n'
        f'forbid_asm = true\n'
    )
    (ws / "kintoun.toml").write_text(toml_text, encoding="utf-8")


def build_zero_context_prompt(
    func_name: str,
    addr: str,
    size_bytes: int,
    arch: str,
    preset: str,
    timeout_s: float,
    kintoun_cmd: str = "kintoun",
) -> str:
    """Construct the self-contained zero-prior-context matching brief for one function."""
    isa_ref = (
        "skills/kintoun-match/references/mips.md"
        if "mips" in arch
        else "skills/kintoun-match/references/arm.md"
        if "arm" in arch
        else "skills/kintoun-match/references/powerpc.md"
    )
    mins = max(1, int(round(timeout_s / 60.0)))
    return (
        f"You are matching a single standalone C function `{func_name}` at `{addr}` ({size_bytes} bytes, "
        f"arch `{arch}`, compiler preset `{preset}`) to a 100% relocation-verified byte-exact match (`VERIFIED`, "
        f"`different_bytes == 0`).\n\n"
        f"Workspace files:\n"
        f"- `cand.c`: starting raw decompiler seed for `{func_name}` (keep your best compiling C saved in `cand.c` at all times!).\n"
        f"- `kintoun.toml`: preconfigured compiler and target settings.\n"
        f"- `skills/kintoun-match/SKILL.md` and `{isa_ref}`: assembly-diff-to-C lookup reference.\n\n"
        f"Strict rules:\n"
        f"1. REAL C ONLY: Never emit `asm`, `__asm__`, `GLOBAL_ASM`, register pins, `.word`/`.byte`/`.long`, or naked functions.\n"
        f"2. Zero external snooping: Work strictly inside this workspace using `{kintoun_cmd}` CLI commands and `cand.c`.\n"
        f"3. Time budget: You have up to {mins} minutes ({int(timeout_s)}s). Take as long as needed to reach `VERIFIED` "
        f"(`different_bytes == 0`), and stop immediately once `{kintoun_cmd} verify cand.c --func {func_name}` reports `VERIFIED`.\n"
        f"4. Always write improvements back to `cand.c` so `cand.c` always holds your highest-aligned compiling C.\n\n"
        f"Recommended workflow:\n"
        f"1. Read `{isa_ref}` and run `{kintoun_cmd} context --func {func_name}` to inspect the exact target disassembly, callees, and globals.\n"
        f"2. Run `{kintoun_cmd} permute cand.c --func {func_name} --quick --governed --write --write-best` to repair raw syntax and get a baseline diff.\n"
        f"3. Hand-edit `cand.c` to match the target control flow, types, struct offsets, casts, and expressions; check every edit with "
        f"`{kintoun_cmd} verify cand.c --func {func_name}`.\n"
        f"4. Use `{kintoun_cmd} permute cand.c --func {func_name} --governed --write --write-best` (optionally with `KINTOUN_ALT` / "
        f"`KINTOUN_LINESWAP` macros) and `{kintoun_cmd} close cand.c --func {func_name} --write --write-best` on near-misses until `VERIFIED`.\n"
    )


def build_agent_command(
    runner: str,
    *,
    prompt: str,
    model: str = "gemini-4-neon-high",
    effort: str = "high",
    timeout_s: float = 1800.0,
    agent_bin: str = "",
    custom_template: str = "",
    func_name: str = "",
    addr: str = "",
    workspace: Path | None = None,
) -> list[str]:
    """Build the subprocess argv for the selected CLI agent runner (`agy`, `claude`, `codex`, `custom`)."""
    if runner == "custom" or custom_template:
        if not custom_template:
            raise ValueError("--agent-cmd template is required when --runner=custom")
        parts = shlex.split(custom_template)
        mapping = {
            "prompt": prompt,
            "model": model,
            "effort": effort,
            "timeout_s": str(int(timeout_s)),
            "func": func_name,
            "addr": addr,
            "workspace": str(workspace or ""),
        }
        return [p.format(**mapping) for p in parts]

    if runner == "agy":
        exe = agent_bin or shutil.which("agy") or str(Path.home() / ".local" / "bin" / "agy")
        cmd = [
            exe,
            "-p",
            prompt,
            "--model",
            model,
            "--effort",
            effort,
            "--dangerously-skip-permissions",
            "--disable-slash-commands",
            "--new-project",
            "--print-timeout",
            f"{max(1, int(timeout_s))}s",
        ]
        return cmd

    if runner == "claude":
        exe = agent_bin or shutil.which("claude") or "claude"
        return [exe, "-p", prompt, "--model", model, "--dangerously-skip-permissions"]

    if runner == "codex":
        exe = agent_bin or shutil.which("codex") or "codex"
        return [
            exe,
            "exec",
            "--model",
            model,
            "--dangerously-bypass-approvals-and-sandbox",
            "--skip-git-repo-check",
            prompt,
        ]

    raise ValueError(f"unsupported runner '{runner}'; expected agy, claude, codex, or custom")


def _recover_best_cached_source(ws: Path, func_name: str) -> list[str]:
    """Extract up to 8 candidate C sources recorded in SQLite or `trajectories.jsonl` during the agent turn."""
    seen: set[str] = set()
    out: list[tuple[tuple[Any, ...], str]] = []

    traj_path = ws / ".kintoun" / "cache" / "trajectories.jsonl"
    if traj_path.is_file():
        for line in traj_path.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                trec = json.loads(line)
            except ValueError:
                continue
            fcode = trec.get("final_code")
            if isinstance(fcode, str) and fcode not in seen and not real_c_violation(fcode):
                seen.add(fcode)
                fake_res = {
                    "verified": bool(trec.get("verified")),
                    "status": "verified" if trec.get("verified") else "mismatch",
                    "different_bytes": 0 if trec.get("verified") else 100,
                    "search": {"aligned_pct": float(trec.get("final_pct") or 0.0), "total": 100},
                }
                out.append((rank_result(fake_res), fcode))

    db_path = ws / ".kintoun" / "cache" / "candidates.sqlite3"
    if db_path.is_file():
        try:
            conn = sqlite3.connect(db_path, timeout=5.0)
            try:
                rows = conn.execute(
                    "SELECT source, result_json FROM candidates WHERE func_name = ? ORDER BY created DESC LIMIT 200",
                    (func_name,),
                ).fetchall()
                if not rows:
                    rows = conn.execute(
                        "SELECT source, result_json FROM candidates ORDER BY created DESC LIMIT 200"
                    ).fetchall()
            finally:
                conn.close()
        except Exception:
            rows = []

        for src, rjson in rows:
            if not isinstance(src, str) or src in seen or real_c_violation(src):
                continue
            seen.add(src)
            try:
                res = json.loads(rjson)
            except Exception:
                continue
            out.append((rank_result(res), src))

    out.sort(key=lambda pair: pair[0])
    return [src for _rk, src in out[:8]]


def _run_subprocess_bounded(cmd: list[str], cwd: Path, env: dict[str, str], timeout_s: float) -> tuple[int, str, bool, float]:
    """Run `cmd` in its own process group with a hard wall-clock timeout and clean group termination."""
    t0 = time.monotonic()
    timed_out = False
    proc = subprocess.Popen(
        cmd,
        cwd=str(cwd),
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        errors="replace",
        start_new_session=True,
    )
    try:
        out, _ = proc.communicate(timeout=timeout_s)
        rc = int(proc.returncode or 0)
    except subprocess.TimeoutExpired:
        timed_out = True
        try:
            os.killpg(proc.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            out, _ = proc.communicate(timeout=3.0)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            out, _ = proc.communicate()
        rc = 124
    elapsed = round(time.monotonic() - t0, 3)
    return rc, out or "", timed_out, elapsed


def run_agent_benchmark(
    cfg: KintounConfig,
    manifest_path: Path,
    out_dir: Path,
    *,
    runner: str = "agy",
    model: str = "gemini-4-neon-high",
    effort: str = "high",
    agent_bin: str = "",
    custom_template: str = "",
    per_func_timeout_s: float = 1800.0,
    concurrency: int = 1,
    with_headless_baseline: bool = True,
    headless_budget_s: float = 30.0,
    headless_max_candidates: int = 300,
    limit: int = 0,
    only_funcs: set[str] | None = None,
    resume: bool = True,
    kintoun_cmd: str = "",
) -> dict[str, Any]:
    """Execute the zero-prior-context per-function agent benchmark and write `results.jsonl` + `summary.json`."""
    manifest_doc = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
    entries = manifest_doc.get("functions") if isinstance(manifest_doc, dict) else manifest_doc
    if not isinstance(entries, list):
        raise ValueError("manifest must contain a list of functions")

    if only_funcs:
        entries = [e for e in entries if str(e.get("func") or e.get("name")) in only_funcs]
    if limit > 0:
        entries = entries[:limit]

    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    best_dir = out_dir / "best"
    logs_dir = out_dir / "logs"
    best_dir.mkdir(parents=True, exist_ok=True)
    logs_dir.mkdir(parents=True, exist_ok=True)
    results_jsonl = out_dir / "results.jsonl"

    completed: dict[str, dict[str, Any]] = {}
    if resume and results_jsonl.is_file():
        for line in results_jsonl.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
                fn_k = str(rec.get("func") or "")
                if fn_k:
                    completed[fn_k] = rec
            except ValueError:
                continue

    repo_skills = Path(__file__).resolve().parent.parent.parent / "skills" / "kintoun-match"
    src_pkg_dir = Path(__file__).resolve().parent.parent
    eff_kintoun_cmd = kintoun_cmd or "kintoun"

    # Preload shared target context and anonymous symbol table when using config-backed binary mode
    has_cfg_binary = bool(cfg.target.binary or cfg.target.dol)
    shared_ctx = load_target_from_config(cfg) if has_cfg_binary else None
    anon_syms_text, orig_to_anon = _anonymize_symbols_text(shared_ctx) if shared_ctx is not None else ("", {})
    anon_to_orig = {v: k for k, v in orig_to_anon.items()}

    cfg_bin_path = cfg.resolve_path(cfg.target.binary or cfg.target.dol) if has_cfg_binary else None
    write_lock = threading.Lock()

    def _eval_one(item: dict[str, Any]) -> dict[str, Any]:
        orig_name = str(item.get("func") or item.get("name") or "")
        if resume and orig_name in completed:
            return completed[orig_name]

        # Load seed C
        seed_src = item.get("code")
        if seed_src is None and item.get("source"):
            sp = Path(item["source"])
            if not sp.is_absolute():
                sp = Path(manifest_path).resolve().parent / sp
                if not sp.is_file():
                    sp = cfg.root / item["source"]
            seed_src = sp.read_text(encoding="utf-8")
        if not seed_src:
            seed_src = f"int {orig_name}(void) {{\n    return 0;\n}}\n"

        if item.get("target"):
            tp = Path(item["target"])
            if not tp.is_absolute():
                tp = (Path(manifest_path).resolve().parent / tp)
                if not tp.is_file():
                    tp = cfg.root / item["target"]
            ctx, tf = load_target_from_object(tp, orig_name or None)
            item_orig_to_anon = {tf.name: f"fn_{tf.va:08X}" if not _HEX_SYM_RE.match(tf.name) else tf.name}
            item_anon_to_orig = {v: k for k, v in item_orig_to_anon.items()}
            standalone_obj_path: Path | None = tp
        else:
            assert shared_ctx is not None
            ctx = shared_ctx
            tf = ctx.resolve_function(orig_name)
            item_orig_to_anon = orig_to_anon
            item_anon_to_orig = anon_to_orig
            standalone_obj_path = None

        anon_func = item_orig_to_anon.get(tf.name, f"fn_{tf.va:08X}")
        anon_seed = _rewrite_identifiers(seed_src, item_orig_to_anon)
        compiler = make_compiler(cfg, va=tf.va)

        # 1. Ground-truth score of raw starting seed
        seed_res = verify_source(seed_src, tf, ctx, compiler, lines=0, forbid_asm=True)
        seed_compiled = seed_res.get("status") in ("verified", "mismatch", "unresolved")
        seed_aligned = float((seed_res.get("search") or {}).get("aligned_pct") or 0.0) if seed_compiled else 0.0

        # 2. Optional deterministic headless `kintoun permute` baseline (zero LLM)
        headless_info: dict[str, Any] | None = None
        if with_headless_baseline:
            with tempfile.TemporaryDirectory(prefix="kintoun_hl_") as hl_tmp:
                hl_res = run_search(
                    source=seed_src,
                    target_fn=tf,
                    ctx=ctx,
                    compiler=compiler,
                    budget_s=headless_budget_s,
                    max_candidates=headless_max_candidates,
                    workers=1,
                    cache_dir=Path(hl_tmp) / "cache",
                    forbid_asm=True,
                    seed=0,
                    governed=True,
                )
            hl_best = hl_res.get("best") or {}
            hl_comp = hl_best.get("status") in ("verified", "mismatch", "unresolved")
            headless_info = {
                "compiled": hl_comp,
                "verified": bool(hl_res.get("verified")),
                "status": hl_best.get("status", "error"),
                "aligned_pct": round(float((hl_best.get("search") or {}).get("aligned_pct") or 0.0), 2) if hl_comp else 0.0,
                "different_bytes": hl_best.get("different_bytes"),
                "evaluated": hl_res.get("evaluated", 0),
                "elapsed_s": hl_res.get("elapsed_s", 0.0),
            }

        # 3. Fresh isolated zero-prior-context agent workspace
        with tempfile.TemporaryDirectory(prefix="kintoun_zc_") as tmp_ws:
            ws = Path(tmp_ws)
            orig_sub = ws / "orig"
            orig_sub.mkdir(parents=True, exist_ok=True)
            if repo_skills.is_dir():
                shutil.copytree(repo_skills, ws / "skills" / "kintoun-match")

            if standalone_obj_path is not None:
                ext = standalone_obj_path.suffix or ".o"
                shutil.copy2(standalone_obj_path, orig_sub / f"target{ext}")
                _write_isolated_toml(ws, cfg, rel_binary="", rel_symbols="")
                prompt_func = tf.name
                target_flag = f" --target orig/target{ext}"
            else:
                assert cfg_bin_path is not None and cfg_bin_path.is_file()
                bin_ext = cfg_bin_path.suffix or ".bin"
                rel_bin = f"orig/target{bin_ext}"
                try:
                    os.symlink(cfg_bin_path.resolve(), ws / rel_bin)
                except OSError:
                    shutil.copy2(cfg_bin_path, ws / rel_bin)
                (orig_sub / "symbols.txt").write_text(anon_syms_text, encoding="utf-8")
                _write_isolated_toml(ws, cfg, rel_binary=rel_bin, rel_symbols="orig/symbols.txt")
                prompt_func = anon_func
                target_flag = ""

            cand_file = ws / "cand.c"
            cand_file.write_text(anon_seed if standalone_obj_path is None else seed_src, encoding="utf-8")

            prompt = build_zero_context_prompt(
                func_name=prompt_func,
                addr=f"0x{tf.va:08X}",
                size_bytes=tf.size,
                arch=ctx.arch,
                preset=cfg.compiler.preset,
                timeout_s=per_func_timeout_s,
                kintoun_cmd=eff_kintoun_cmd,
            )
            if target_flag:
                prompt += f"\nNote: pass `{target_flag.strip()}` to `{eff_kintoun_cmd}` commands.\n"

            cmd = build_agent_command(
                runner,
                prompt=prompt,
                model=model,
                effort=effort,
                timeout_s=per_func_timeout_s,
                agent_bin=agent_bin,
                custom_template=custom_template,
                func_name=prompt_func,
                addr=f"0x{tf.va:08X}",
                workspace=ws,
            )
            env = dict(os.environ)
            existing_pp = env.get("PYTHONPATH", "")
            env["PYTHONPATH"] = f"{src_pkg_dir}{os.pathsep}{existing_pp}" if existing_pp else str(src_pkg_dir)
            shim_dir = ws / ".kintoun_bin"
            shim_dir.mkdir(parents=True, exist_ok=True)
            shim_bin = shim_dir / "kintoun"
            shim_bin.write_text(
                f"#!/bin/sh\nPYTHONPATH={shlex.quote(env['PYTHONPATH'])} exec {shlex.quote(sys.executable)} -m kintoun.cli \"$@\"\n",
                encoding="utf-8",
            )
            shim_bin.chmod(0o755)
            env["PATH"] = f"{shim_dir}{os.pathsep}{env.get('PATH', '')}"
            # Enforce hard timeout (`per_func_timeout_s + 15s` grace over CLI's internal `--print-timeout`)
            rc, agent_log, timed_out, agent_elapsed_s = _run_subprocess_bounded(
                cmd,
                cwd=ws,
                env=env,
                timeout_s=per_func_timeout_s + 15.0,
            )

            # Collect candidate sources (`cand.c` + top valid real-C entries from per-function cache + starting seed)
            candidate_sources: list[str] = []
            if cand_file.is_file():
                candidate_sources.append(cand_file.read_text(encoding="utf-8", errors="replace"))
            candidate_sources.extend(_recover_best_cached_source(ws, prompt_func))
            candidate_sources.append(anon_seed if standalone_obj_path is None else seed_src)

        # 4. Independent ground-truth external verification (`forbid_asm=True`)
        best_res: dict[str, Any] | None = None
        best_src = seed_src
        for raw_cand in candidate_sources:
            deanon_cand = _rewrite_identifiers(raw_cand, item_anon_to_orig) if standalone_obj_path is None else raw_cand
            vres = verify_source(deanon_cand, tf, ctx, compiler, lines=24, forbid_asm=True)
            if best_res is None or rank_result(vres) < rank_result(best_res):
                best_res = vres
                best_src = deanon_cand
                if vres.get("verified"):
                    break

        if best_res is None:
            best_res = seed_res
            best_src = seed_src

        (logs_dir / f"{tf.name}.log").write_text(agent_log, encoding="utf-8")
        (best_dir / f"{tf.name}.c").write_text(best_src, encoding="utf-8")

        ag_comp = best_res.get("status") in ("verified", "mismatch", "unresolved")
        ag_aligned = round(float((best_res.get("search") or {}).get("aligned_pct") or 0.0), 2) if ag_comp else 0.0
        size_tier = str(item.get("size_tier") or size_tier_for(tf.size) or "other")
        family = str(item.get("family") or classify_structural_family(check_function(tf, ctx)) or "other")

        rec = {
            "func": tf.name,
            "anon_func": anon_func,
            "addr": f"0x{tf.va:08X}",
            "size_bytes": tf.size,
            "size_tier": size_tier,
            "family": family,
            "runner": runner,
            "model": model,
            "effort": effort,
            "time_limit_s": per_func_timeout_s,
            "seed": {
                "compiled": seed_compiled,
                "verified": bool(seed_res.get("verified")),
                "aligned_pct": round(seed_aligned, 2),
            },
            "headless": headless_info,
            "agent": {
                "compiled": ag_comp,
                "verified": bool(best_res.get("verified")),
                "status": best_res.get("status", "error"),
                "aligned_pct": ag_aligned,
                "different_bytes": best_res.get("different_bytes"),
                "elapsed_s": min(agent_elapsed_s, per_func_timeout_s) if timed_out else agent_elapsed_s,
                "wall_elapsed_s": agent_elapsed_s,
                "timed_out": timed_out,
                "exit_code": rc,
            },
        }
        with write_lock:
            with results_jsonl.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(rec) + "\n")
        return rec

    t_start = time.monotonic()
    ordered_results: list[dict[str, Any]] = []
    workers = max(1, int(concurrency))
    if workers == 1:
        for item in entries:
            ordered_results.append(_eval_one(item))
    else:
        by_func: dict[str, dict[str, Any]] = {}
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futs = {pool.submit(_eval_one, item): str(item.get("func") or item.get("name") or "") for item in entries}
            for fut in as_completed(futs):
                r = fut.result()
                by_func[r["func"]] = r
        for item in entries:
            fk = str(item.get("func") or item.get("name") or "")
            if fk in by_func:
                ordered_results.append(by_func[fk])

    summary = summarize_agent_benchmark(
        ordered_results,
        runner=runner,
        model=model,
        effort=effort,
        per_func_timeout_s=per_func_timeout_s,
        wall_elapsed_s=round(time.monotonic() - t_start, 3),
    )
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return summary


def _agg_arm(rows: list[dict[str, Any]], key: str) -> dict[str, Any]:
    sub = [r.get(key) for r in rows if isinstance(r.get(key), dict)]
    if not sub:
        return {
            "functions": 0,
            "compiles": 0,
            "verified": 0,
            "verified_pct": 0.0,
            "mean_aligned_pct": 0.0,
            "median_aligned_pct": 0.0,
            "ge_80": 0,
            "ge_95": 0,
            "mean_elapsed_s": 0.0,
            "median_elapsed_s": 0.0,
        }
    n = len(sub)
    aligned_vals = [float(s.get("aligned_pct") or 0.0) for s in sub]
    elapsed_vals = [float(s.get("elapsed_s") or 0.0) for s in sub if "elapsed_s" in s]
    ver = sum(1 for s in sub if s.get("verified"))
    comp = sum(1 for s in sub if s.get("compiled"))
    return {
        "functions": n,
        "compiles": comp,
        "verified": ver,
        "verified_pct": round(100.0 * ver / n, 1),
        "mean_aligned_pct": round(sum(aligned_vals) / n, 1),
        "median_aligned_pct": round(float(statistics.median(aligned_vals)), 1),
        "ge_80": sum(1 for a in aligned_vals if a >= 80.0),
        "ge_95": sum(1 for a in aligned_vals if a >= 95.0),
        "mean_elapsed_s": round(sum(elapsed_vals) / len(elapsed_vals), 1) if elapsed_vals else 0.0,
        "median_elapsed_s": round(float(statistics.median(elapsed_vals)), 1) if elapsed_vals else 0.0,
    }


def summarize_agent_benchmark(
    results: list[dict[str, Any]],
    *,
    runner: str = "",
    model: str = "",
    effort: str = "",
    per_func_timeout_s: float = 1800.0,
    wall_elapsed_s: float = 0.0,
) -> dict[str, Any]:
    """Aggregate overall, byte-size-tier, and structural-family statistics from `results`."""
    tier_order = [t[0] for t in SIZE_TIERS]
    by_tier: dict[str, Any] = {}
    for t in tier_order:
        t_rows = [r for r in results if r.get("size_tier") == t]
        if t_rows:
            by_tier[t] = {
                "seed": _agg_arm(t_rows, "seed"),
                "headless": _agg_arm(t_rows, "headless") if any(r.get("headless") for r in t_rows) else None,
                "agent": _agg_arm(t_rows, "agent"),
            }
    other_t = [r for r in results if r.get("size_tier") not in tier_order]
    if other_t:
        by_tier["other"] = {
            "seed": _agg_arm(other_t, "seed"),
            "headless": _agg_arm(other_t, "headless") if any(r.get("headless") for r in other_t) else None,
            "agent": _agg_arm(other_t, "agent"),
        }

    by_family: dict[str, Any] = {}
    for f in FAMILIES:
        f_rows = [r for r in results if r.get("family") == f]
        if f_rows:
            by_family[f] = {
                "seed": _agg_arm(f_rows, "seed"),
                "headless": _agg_arm(f_rows, "headless") if any(r.get("headless") for r in f_rows) else None,
                "agent": _agg_arm(f_rows, "agent"),
            }
    other_f = [r for r in results if r.get("family") not in FAMILIES]
    if other_f:
        by_family["other"] = {
            "seed": _agg_arm(other_f, "seed"),
            "headless": _agg_arm(other_f, "headless") if any(r.get("headless") for r in other_f) else None,
            "agent": _agg_arm(other_f, "agent"),
        }

    has_hl = any(r.get("headless") for r in results)
    return {
        "protocol": "kintoun-agent-bench-v1",
        "functions": len(results),
        "runner": runner or (results[0].get("runner", "") if results else ""),
        "model": model or (results[0].get("model", "") if results else ""),
        "effort": effort or (results[0].get("effort", "") if results else ""),
        "per_func_timeout_s": per_func_timeout_s,
        "wall_elapsed_s": wall_elapsed_s,
        "overall": {
            "seed": _agg_arm(results, "seed"),
            "headless": _agg_arm(results, "headless") if has_hl else None,
            "agent": _agg_arm(results, "agent"),
        },
        "by_size_tier": by_tier,
        "by_family": by_family,
        "results": [
            {
                "addr": r["addr"],
                "size_bytes": r["size_bytes"],
                "size_tier": r["size_tier"],
                "family": r["family"],
                "seed_aligned_pct": r["seed"]["aligned_pct"],
                "headless_aligned_pct": (r["headless"]["aligned_pct"] if r.get("headless") else None),
                "headless_verified": (r["headless"]["verified"] if r.get("headless") else None),
                "agent_aligned_pct": r["agent"]["aligned_pct"],
                "agent_verified": r["agent"]["verified"],
                "agent_different_bytes": r["agent"]["different_bytes"],
                "agent_elapsed_s": r["agent"]["elapsed_s"],
                "agent_timed_out": r["agent"]["timed_out"],
            }
            for r in results
        ],
    }


def render_agent_bench_markdown(summary: dict[str, Any], *, title: str = "Zero-Context Agent Benchmark") -> str:
    """Render clean public GitHub Markdown tables (zero source code, zero local paths)."""
    ov = summary.get("overall") or {}
    s_ov = ov.get("seed") or {}
    h_ov = ov.get("headless")
    a_ov = ov.get("agent") or {}
    n = int(summary.get("functions") or 0)
    model = summary.get("model") or "agent"
    effort = summary.get("effort") or ""
    limit_m = int(round(float(summary.get("per_func_timeout_s") or 1800.0) / 60.0))
    model_lbl = f"`{model}` ({effort}, <= {limit_m}m/fn)" if effort else f"`{model}` (<= {limit_m}m/fn)"

    lines: list[str] = [
        f"## {title}",
        "",
        f"* **Functions:** {n} unseen plain-C functions stratified across 5 byte-size tiers and 6 structural families.",
        f"* **Isolation:** fresh temporary workspace per function, anonymous hex symbols (`fn_XXXXXXXX` / `D_XXXXXXXX`), zero prior conversation or project context, Real C Only (`forbid_asm = true`).",
        f"* **Agent budget:** {model_lbl}, independent external relocation verification.",
        "",
        "### Overall progression",
        "",
        "| Stage | Functions | Compiles | Exact (`VERIFIED`) | Exact % | Mean aligned | Median aligned | >= 80% | >= 95% | Median time |",
        "|---|---|---|---|---|---|---|---|---|---|",
        f"| Raw `m2c` seed | {s_ov.get('functions', 0)} | {s_ov.get('compiles', 0)} | {s_ov.get('verified', 0)} | {s_ov.get('verified_pct', 0.0)}% | {s_ov.get('mean_aligned_pct', 0.0)}% | {s_ov.get('median_aligned_pct', 0.0)}% | {s_ov.get('ge_80', 0)} | {s_ov.get('ge_95', 0)} | - |",
    ]
    if h_ov:
        lines.append(
            f"| Headless `kintoun permute` (30s) | {h_ov['functions']} | {h_ov['compiles']} | {h_ov['verified']} | {h_ov['verified_pct']}% | {h_ov['mean_aligned_pct']}% | {h_ov['median_aligned_pct']}% | {h_ov['ge_80']} | {h_ov['ge_95']} | {h_ov['median_elapsed_s']}s |"
        )
    lines.append(
        f"| **Zero-context {model_lbl} + Kintoun** | **{a_ov.get('functions', 0)}** | **{a_ov.get('compiles', 0)}** | **{a_ov.get('verified', 0)}** | **{a_ov.get('verified_pct', 0.0)}%** | **{a_ov.get('mean_aligned_pct', 0.0)}%** | **{a_ov.get('median_aligned_pct', 0.0)}%** | **{a_ov.get('ge_80', 0)}** | **{a_ov.get('ge_95', 0)}** | **{a_ov.get('median_elapsed_s', 0.0)}s** |"
    )

    lines.extend(
        [
            "",
            "### Results by byte-size tier",
            "",
            "| Size tier | Functions | Headless mean | Headless exact | Agent compiles | Agent exact | Agent exact % | Agent mean aligned | Agent median aligned | Median time |",
            "|---|---|---|---|---|---|---|---|---|---|",
        ]
    )
    for t_key, t_val in (summary.get("by_size_tier") or {}).items():
        ag = t_val["agent"]
        hl = t_val.get("headless")
        hl_mean = f"{hl['mean_aligned_pct']}%" if hl else "-"
        hl_ex = str(hl["verified"]) if hl else "-"
        lines.append(
            f"| `{t_key}` | {ag['functions']} | {hl_mean} | {hl_ex} | {ag['compiles']} | {ag['verified']} | {ag['verified_pct']}% | {ag['mean_aligned_pct']}% | {ag['median_aligned_pct']}% | {ag['median_elapsed_s']}s |"
        )

    lines.extend(
        [
            "",
            "### Results by structural family",
            "",
            "| Family | Functions | Headless mean | Headless exact | Agent compiles | Agent exact | Agent exact % | Agent mean aligned | Agent median aligned | Median time |",
            "|---|---|---|---|---|---|---|---|---|---|",
        ]
    )
    for f_key, f_val in (summary.get("by_family") or {}).items():
        ag = f_val["agent"]
        hl = f_val.get("headless")
        hl_mean = f"{hl['mean_aligned_pct']}%" if hl else "-"
        hl_ex = str(hl["verified"]) if hl else "-"
        lines.append(
            f"| `{f_key}` | {ag['functions']} | {hl_mean} | {hl_ex} | {ag['compiles']} | {ag['verified']} | {ag['verified_pct']}% | {ag['mean_aligned_pct']}% | {ag['median_aligned_pct']}% | {ag['median_elapsed_s']}s |"
        )

    return "\n".join(lines) + "\n"


def load_results_jsonl(results_path: Path) -> list[dict[str, Any]]:
    """Load deduplicated per-function benchmark records from `results.jsonl`."""
    by_fn: dict[str, dict[str, Any]] = {}
    for line in Path(results_path).read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        rec = json.loads(line)
        fk = str(rec.get("func") or rec.get("addr") or len(by_fn))
        by_fn[fk] = rec
    return list(by_fn.values())
