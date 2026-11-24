"""Single-machine brute-force resource governor, pressure auto-tuner, and persistent Wine warmer.

Coordinates concurrent compiles across processes on one machine using short file-locked
leases (`governor_state.json`) across three priority tiers:
  1. `interactive` - fast single compiles (`verify`, `revise_candidate`) with reserved slots.
  2. `search`      - parallel `permute` / agent searches sharing spare CPU cores fairly.
  3. `background`  - lowest-priority `close` / `overseer` sweeps (`<= 2` slots, yields whenever
                     any `interactive` or `search` caller is waiting).

Also provides:
  - `AutoTuner`: zram- and cgroup-aware duty-cycle controller using active working set
    (`memory.current - inactive_file`), Linux memory PSI, and real swap-in rate (`pswpin`).
  - `CompileDeduper`: 64-stripe file lock preventing duplicate concurrent compiles of the
    same candidate key across processes.
  - `ensure_warm_wine` / `stop_warm_wine` / `wine_status`: persistent `wineserver -p` helper
    for Win32 console compilers (`prodg-wine`, `mwcc-wine`).
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import time
from typing import Any, Iterator

try:
    import fcntl as _fcntl
except ImportError:  # pragma: no cover - Windows fallback
    _fcntl = None  # type: ignore[assignment]

GIB = 1 << 30

DUTY_LEVELS: dict[int, dict[str, int]] = {
    0: {"budget_s": 0, "max_candidates": 0, "rest_s": 15},
    1: {"budget_s": 30, "max_candidates": 60, "rest_s": 15},
    2: {"budget_s": 60, "max_candidates": 160, "rest_s": 5},
    3: {"budget_s": 90, "max_candidates": 320, "rest_s": 0},
}


@contextmanager
def _file_lock(lock_path: Path) -> Iterator[None]:
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    if _fcntl is None:
        yield
        return
    with lock_path.open("a+", encoding="utf-8") as handle:
        _fcntl.flock(handle.fileno(), _fcntl.LOCK_EX)
        try:
            yield
        finally:
            _fcntl.flock(handle.fileno(), _fcntl.LOCK_UN)


def _read_text(path: str | Path) -> str:
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return ""


def effective_cpus() -> int:
    """Return effective CPU count, respecting Linux cgroup v2 `cpuset.cpus.effective` when present."""
    spec = _read_text("/sys/fs/cgroup/cpuset.cpus.effective") or _read_text("/sys/fs/cgroup/cpuset.cpus")
    if spec:
        count = 0
        for part in spec.split(","):
            part = part.strip()
            if "-" in part:
                lo, hi = part.split("-", 1)
                if lo.isdigit() and hi.isdigit():
                    count += int(hi) - int(lo) + 1
            elif part.isdigit():
                count += 1
        if count > 0:
            return count
    return max(1, os.cpu_count() or 2)


def sample_machine_pressure() -> dict[str, Any]:
    """Read live Linux cgroup/host memory working set, PSI, and swap-in counter (graceful on macOS/BSD/Win)."""
    cpus = effective_cpus()
    mem_avail: int | None = None
    swap_used: int = 0
    for line in _read_text("/proc/meminfo").splitlines():
        key, _, rest = line.partition(":")
        toks = rest.split()
        if not toks or not toks[0].isdigit():
            continue
        val = int(toks[0]) * 1024
        if key == "MemAvailable":
            mem_avail = val
        elif key == "SwapTotal":
            swap_used += val
        elif key == "SwapFree":
            swap_used -= val

    pswpin: int | None = None
    for line in _read_text("/proc/vmstat").splitlines():
        k, _, v = line.partition(" ")
        if k == "pswpin" and v.strip().isdigit():
            pswpin = int(v.strip())
            break

    psi_avg10: float | None = None
    for line in _read_text("/proc/pressure/memory").splitlines():
        if line.startswith("some "):
            for tok in line.split():
                if tok.startswith("avg10="):
                    try:
                        psi_avg10 = float(tok.split("=", 1)[1])
                    except ValueError:
                        pass
            break

    cgroup_raw: int | None = None
    cgroup_ws: int | None = None
    cgroup_limit: int | None = None
    raw_txt = _read_text("/sys/fs/cgroup/memory.current")
    if raw_txt.isdigit():
        cgroup_raw = int(raw_txt)
        inactive_file = 0
        for line in _read_text("/sys/fs/cgroup/memory.stat").splitlines():
            if line.startswith("inactive_file "):
                parts = line.split()
                if len(parts) >= 2 and parts[1].isdigit():
                    inactive_file = int(parts[1])
                break
        cgroup_ws = max(0, cgroup_raw - inactive_file)
    max_txt = _read_text("/sys/fs/cgroup/memory.max")
    if max_txt.isdigit():
        lim = int(max_txt)
        if lim < (1 << 50):
            cgroup_limit = lim

    return {
        "ts": time.time(),
        "cpus": cpus,
        "mem_available_bytes": mem_avail,
        "swap_used_bytes": max(0, swap_used),
        "pswpin": pswpin,
        "psi_some_avg10": psi_avg10,
        "cgroup_raw_bytes": cgroup_raw,
        "cgroup_working_set_bytes": cgroup_ws,
        "cgroup_limit_bytes": cgroup_limit,
    }


class AutoTuner:
    """Zram- and cgroup-aware duty-cycle auto-tuner with upward hysteresis."""

    def __init__(
        self,
        state_dir: Path,
        min_free_gib: float = 1.0,
        psi_pause: float = 20.0,
        swapin_pause_ps: float = 1000.0,
        up_hold_s: float = 60.0,
    ) -> None:
        self.state_path = Path(state_dir) / "autotune.json"
        self.min_free_bytes = int(min_free_gib * GIB)
        self.psi_pause = psi_pause
        self.swapin_pause_ps = swapin_pause_ps
        self.up_hold_s = up_hold_s

    def _load(self) -> dict[str, Any]:
        try:
            return json.loads(self.state_path.read_text(encoding="utf-8"))
        except Exception:
            return {"level": 3, "samples": [], "up_since": None}

    def _save(self, data: dict[str, Any]) -> None:
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.state_path.with_suffix(f".{os.getpid()}.tmp")
        tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
        os.replace(tmp, self.state_path)

    def evaluate(self) -> dict[str, Any]:
        snap = sample_machine_pressure()
        st = self._load()
        now = snap["ts"]
        samples: list[list[float]] = [
            s for s in st.get("samples", []) if isinstance(s, list) and len(s) == 2 and now - s[0] < 600
        ]
        if snap["pswpin"] is not None and (not samples or now - samples[-1][0] >= 5.0):
            samples.append([now, float(snap["pswpin"])])
        samples = samples[-60:]

        swapin_ps = 0.0
        older = [s for s in samples if now - s[0] >= 15.0]
        if older and snap["pswpin"] is not None and snap["pswpin"] >= older[-1][1]:
            swapin_ps = (snap["pswpin"] - older[-1][1]) / max(1.0, now - older[-1][0])

        cap = 3
        reasons: list[str] = []

        avail = snap["mem_available_bytes"]
        if avail is not None:
            if avail < self.min_free_bytes:
                cap = 0
                reasons.append(f"MemAvailable {avail / GIB:.2f} GiB < {self.min_free_bytes / GIB:.2f} GiB")
            elif avail < int(self.min_free_bytes * 1.75):
                cap = min(cap, 1)
                reasons.append(f"MemAvailable {avail / GIB:.2f} GiB low")

        ws = snap["cgroup_working_set_bytes"]
        lim = snap["cgroup_limit_bytes"]
        if ws is not None and lim is not None:
            headroom = lim - ws
            if headroom < self.min_free_bytes:
                cap = 0
                reasons.append(f"cgroup headroom {headroom / GIB:.2f} GiB < {self.min_free_bytes / GIB:.2f} GiB")
            elif headroom < int(self.min_free_bytes * 2.0):
                cap = min(cap, 1)
                reasons.append(f"cgroup headroom {headroom / GIB:.2f} GiB tight")

        psi = snap["psi_some_avg10"]
        if psi is not None:
            if psi >= self.psi_pause:
                cap = 0
                reasons.append(f"memory PSI {psi:.1f}% >= {self.psi_pause:.0f}%")
            elif psi >= self.psi_pause * 0.5:
                cap = min(cap, 1)
                reasons.append(f"memory PSI {psi:.1f}%")

        if swapin_ps >= self.swapin_pause_ps:
            cap = 0
            reasons.append(f"swap-in {swapin_ps:.0f} pages/s")
        elif swapin_ps >= self.swapin_pause_ps * 0.2:
            cap = min(cap, 1)
            reasons.append(f"swap-in {swapin_ps:.0f} pages/s")
        elif swapin_ps >= self.swapin_pause_ps * 0.05:
            cap = min(cap, 2)

        level = int(st.get("level", 3))
        up_since = st.get("up_since")
        if cap < level:
            level = 0 if cap == 0 else level - 1
            up_since = None
        elif cap > level:
            if up_since is None:
                up_since = now
            elif now - float(up_since) >= self.up_hold_s:
                level += 1
                up_since = now if level < cap else None
        else:
            up_since = None

        out = {
            "level": level,
            "params": DUTY_LEVELS[level],
            "cap": cap,
            "reasons": reasons,
            "swapin_pages_s": round(swapin_ps, 1),
            "readings": snap,
            "samples": samples,
            "up_since": up_since,
        }
        self._save(out)
        return out


@dataclass
class CompileGovernor:
    """3-tier cross-process compile admission gate (`interactive`, `search`, `background`)."""

    state_dir: Path
    caller_id: str = "default"
    lease_ttl_s: float = 90.0

    def __post_init__(self) -> None:
        self.state_dir = Path(self.state_dir)
        self.state_file = self.state_dir / "governor_state.json"
        self.lock_file = self.state_dir / "governor.lock"
        self.tuner = AutoTuner(self.state_dir)

    def _slot_caps(self) -> tuple[int, int, int]:
        cpus = effective_cpus()
        total = max(2, int(round(cpus * 0.85)))
        reserved_interactive = min(4, max(1, total // 4))
        search_cap = max(1, total - reserved_interactive)
        bg_cap = min(2, search_cap)
        return total, search_cap, bg_cap

    def _clean_state(self, raw: dict[str, Any], now: float) -> dict[str, Any]:
        leases = {
            lid: info
            for lid, info in (raw.get("leases") or {}).items()
            if isinstance(info, dict) and now - float(info.get("ts", 0)) < self.lease_ttl_s
        }
        waiters = {
            wid: info
            for wid, info in (raw.get("waiters") or {}).items()
            if isinstance(info, dict) and now - float(info.get("ts", 0)) < 20.0
        }
        return {"leases": leases, "waiters": waiters}

    def status(self) -> dict[str, Any]:
        now = time.time()
        total, search_cap, bg_cap = self._slot_caps()
        with _file_lock(self.lock_file):
            try:
                raw = json.loads(self.state_file.read_text(encoding="utf-8"))
            except Exception:
                raw = {}
            st = self._clean_state(raw, now)
        by_tier: dict[str, int] = {"interactive": 0, "search": 0, "background": 0}
        for info in st["leases"].values():
            t = str(info.get("tier", "search"))
            by_tier[t] = by_tier.get(t, 0) + 1
        return {
            "total_slots": total,
            "search_cap": search_cap,
            "background_cap": bg_cap,
            "active_leases": by_tier,
            "waiting": len(st["waiters"]),
            "autotune": self.tuner.evaluate(),
        }

    @contextmanager
    def acquire(self, tier: str = "search", timeout_s: float = 30.0) -> Iterator[bool]:
        """Acquire one compile slot lease for `tier`. Yields `True` if admitted, `False` on timeout/pressure."""
        tier = tier if tier in ("interactive", "search", "background") else "search"
        lease_id = f"{os.getpid()}:{time.monotonic_ns()}"
        deadline = time.monotonic() + max(0.1, timeout_s)
        admitted = False

        while time.monotonic() < deadline:
            now = time.time()
            total, search_cap, bg_cap = self._slot_caps()
            if tier == "background":
                tune = self.tuner.evaluate()
                if tune["level"] == 0:
                    break

            with _file_lock(self.lock_file):
                try:
                    raw = json.loads(self.state_file.read_text(encoding="utf-8"))
                except Exception:
                    raw = {}
                st = self._clean_state(raw, now)
                leases = st["leases"]
                waiters = st["waiters"]

                n_total = len(leases)
                n_non_int = sum(1 for v in leases.values() if v.get("tier") != "interactive")
                n_bg = sum(1 for v in leases.values() if v.get("tier") == "background")
                higher_waiting = any(
                    v.get("tier") in ("interactive", "search") and v.get("caller") != self.caller_id
                    for v in waiters.values()
                )

                ok = False
                if tier == "interactive":
                    ok = n_total < total
                elif tier == "search":
                    # Fair share across active search callers when contended
                    active_callers = {
                        str(v.get("caller")) for v in leases.values() if v.get("tier") == "search"
                    } | {self.caller_id}
                    fair_share = max(1, (search_cap + len(active_callers) - 1) // len(active_callers))
                    my_leases = sum(
                        1 for v in leases.values() if v.get("tier") == "search" and v.get("caller") == self.caller_id
                    )
                    waiting_search = any(
                        v.get("tier") == "search" and v.get("caller") != self.caller_id for v in waiters.values()
                    )
                    ok = n_total < total and n_non_int < search_cap and (not waiting_search or my_leases < fair_share)
                else:  # background
                    ok = n_total < total and n_non_int < search_cap and n_bg < bg_cap and not higher_waiting

                if ok:
                    waiters.pop(lease_id, None)
                    leases[lease_id] = {"tier": tier, "caller": self.caller_id, "pid": os.getpid(), "ts": now}
                    admitted = True
                else:
                    waiters[lease_id] = {"tier": tier, "caller": self.caller_id, "ts": now}

                tmp = self.state_file.with_suffix(f".{os.getpid()}.tmp")
                tmp.write_text(json.dumps(st), encoding="utf-8")
                os.replace(tmp, self.state_file)

            if admitted:
                break
            time.sleep(0.05)

        try:
            yield admitted
        finally:
            with _file_lock(self.lock_file):
                try:
                    raw = json.loads(self.state_file.read_text(encoding="utf-8"))
                except Exception:
                    raw = {}
                st = self._clean_state(raw, time.time())
                st["leases"].pop(lease_id, None)
                st["waiters"].pop(lease_id, None)
                tmp = self.state_file.with_suffix(f".{os.getpid()}.tmp")
                tmp.write_text(json.dumps(st), encoding="utf-8")
                os.replace(tmp, self.state_file)


class CompileDeduper:
    """64-stripe cross-process file lock so concurrent agents do not compile identical source twice."""

    def __init__(self, cache_dir: Path, stripes: int = 64) -> None:
        self.lock_dir = Path(cache_dir) / "stripes"
        self.stripes = max(8, stripes)

    @contextmanager
    def lock_key(self, key: str) -> Iterator[None]:
        idx = int(hashlib.sha256(key.encode("utf-8")).hexdigest()[:8], 16) % self.stripes
        with _file_lock(self.lock_dir / f"stripe_{idx:02d}.lock"):
            yield


def _resolve_wineserver(wine_bin: str = "wine") -> str | None:
    cand = shutil.which("wineserver")
    if cand:
        return cand
    wp = shutil.which(wine_bin)
    if wp:
        sibling = Path(wp).with_name("wineserver")
        if sibling.is_file():
            return str(sibling)
    return None


def ensure_warm_wine(wineprefix: Path | None = None, persist_s: int = 900, wine_bin: str = "wine") -> dict[str, Any]:
    """Start a persistent `wineserver -p<seconds>` so Win32 compilers skip Wine cold-start latency."""
    ws = _resolve_wineserver(wine_bin)
    if not ws:
        return {"ok": False, "error": "wineserver not found in PATH"}
    prefix = (wineprefix or (Path.cwd() / ".kintoun" / "wineprefix")).resolve()
    prefix.mkdir(parents=True, exist_ok=True)
    temp_dir = prefix / "drive_c" / "temp"
    temp_dir.mkdir(parents=True, exist_ok=True)
    env = dict(
        os.environ,
        WINEPREFIX=str(prefix),
        WINEDEBUG="-all",
        WINEDLLOVERRIDES="mscoree,mshtml=",
    )
    proc = subprocess.run(
        [ws, f"-p{max(60, int(persist_s))}"],
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=15,
    )
    return {
        "ok": proc.returncode == 0,
        "wineserver": ws,
        "wineprefix": str(prefix),
        "persist_s": persist_s,
        "returncode": proc.returncode,
        "stderr": (proc.stderr or "").strip()[:300],
    }


def stop_warm_wine(wineprefix: Path | None = None, wine_bin: str = "wine") -> dict[str, Any]:
    """Stop persistent `wineserver` for `wineprefix`."""
    ws = _resolve_wineserver(wine_bin)
    if not ws:
        return {"ok": False, "error": "wineserver not found in PATH"}
    prefix = (wineprefix or (Path.cwd() / ".kintoun" / "wineprefix")).resolve()
    env = dict(os.environ, WINEPREFIX=str(prefix), WINEDEBUG="-all")
    proc = subprocess.run(
        [ws, "-k"],
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=15,
    )
    return {"ok": proc.returncode in (0, 1), "wineprefix": str(prefix), "returncode": proc.returncode}
