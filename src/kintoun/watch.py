"""Live file-save watch mode for interactive C matching (`kintoun watch`).

Monitors a `.c` file as a developer saves edits in VS Code, Neovim, or CLion, re-scoring through
Kintoun's shared cache and governor, reporting alignment and byte-diff deltas against the previous
save, and optionally triggering a quick targeted `close` pass when alignment crosses a threshold.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import sys
import time
from typing import Any

from kintoun.candidates import CandidateStore
from kintoun.closer import close_near_miss
from kintoun.compiler import CompilerBackend
from kintoun.targets import TargetContext, TargetFunction


@dataclass
class WatchSession:
    """Stateful tracker across consecutive file saves during `kintoun watch`."""

    source_path: Path
    target_fn: TargetFunction
    ctx: TargetContext
    compiler: CompilerBackend
    cache_dir: Path
    forbid_asm: bool = True
    auto_close_pct: float = 0.0
    write_on_match: bool = False
    save_count: int = 0
    prev_aligned_pct: float | None = None
    prev_diff_bytes: int | None = None
    best_aligned_pct: float = 0.0
    best_code: str = ""
    _store: CandidateStore = field(init=False)

    def __post_init__(self) -> None:
        self._store = CandidateStore(self.cache_dir)

    def evaluate_current(self) -> dict[str, Any]:
        """Score current `source_path` contents and compute deltas vs previous save and session best."""
        code = self.source_path.read_text(encoding="utf-8")
        res = self._store.score_one(
            code,
            self.target_fn,
            self.ctx,
            self.compiler,
            lines=20,
            forbid_asm=self.forbid_asm,
            strategy="watch",
        )
        self.save_count += 1
        sc = res.get("search") or {}
        aligned = float(sc.get("aligned_pct", 0.0)) if res.get("status") != "compile_error" else 0.0
        diff_b = res.get("different_bytes")

        delta_pct = round(aligned - self.prev_aligned_pct, 2) if self.prev_aligned_pct is not None else 0.0
        delta_bytes = (
            int(diff_b) - int(self.prev_diff_bytes)
            if isinstance(diff_b, int) and isinstance(self.prev_diff_bytes, int)
            else None
        )

        if res.get("status") != "compile_error":
            self.prev_aligned_pct = aligned
            if isinstance(diff_b, int):
                self.prev_diff_bytes = diff_b
            if aligned >= self.best_aligned_pct:
                self.best_aligned_pct = aligned
                self.best_code = code

        auto_close_result: dict[str, Any] | None = None
        if (
            not res.get("verified")
            and self.auto_close_pct > 0.0
            and aligned >= self.auto_close_pct
            and res.get("status") == "mismatch"
        ):
            closed = close_near_miss(
                code,
                self.target_fn,
                self.ctx,
                self.compiler,
                budget_s=15.0,
                max_candidates=60,
                workers=2,
                cache_dir=self.cache_dir,
                forbid_asm=self.forbid_asm,
            )
            auto_close_result = {
                "verified": bool(closed.get("verified")),
                "primary_class": (closed.get("classification") or {}).get("primary_class", ""),
                "best_aligned_pct": float(((closed.get("best") or {}).get("search") or {}).get("aligned_pct", aligned)),
            }
            if closed.get("verified") and (closed.get("best") or {}).get("code"):
                win_code = closed["best"]["code"]
                self.best_aligned_pct = 100.0
                self.best_code = win_code
                if self.write_on_match:
                    self.source_path.write_text(win_code, encoding="utf-8")
                res["verified"] = True
                res["status"] = "verified"
                res["different_bytes"] = 0

        return {
            "save_number": self.save_count,
            "name": self.target_fn.name,
            "addr": f"0x{self.target_fn.va:08X}",
            "status": res.get("status"),
            "verified": bool(res.get("verified")),
            "aligned_pct": aligned,
            "delta_aligned_pct": delta_pct,
            "best_aligned_pct": self.best_aligned_pct,
            "different_bytes": diff_b,
            "delta_different_bytes": delta_bytes,
            "hints": (sc.get("hints") or [])[:4],
            "diff": sc.get("diff", ""),
            "error": res.get("error", ""),
            "auto_close": auto_close_result,
        }


def format_watch_panel(ev: dict[str, Any]) -> str:
    """Format a compact single-screen text update for a watch cycle."""
    status = str(ev["status"] or "unknown").upper()
    dp = ev["delta_aligned_pct"]
    sign = "+" if dp > 0 else ""
    header = (
        f"[#{ev['save_number']} {status}] {ev['name']} ({ev['addr']})  "
        f"aligned={ev['aligned_pct']:.2f}% ({sign}{dp:.2f}%, best={ev['best_aligned_pct']:.2f}%)"
    )
    lines = [header]
    if ev.get("different_bytes") is not None:
        db_s = ""
        if ev.get("delta_different_bytes") is not None:
            db = ev["delta_different_bytes"]
            db_s = f" ({'+' if db > 0 else ''}{db}B)"
        lines.append(f"  different_bytes={ev['different_bytes']}{db_s}")
    if ev.get("error"):
        lines.append(f"  compile_error: {ev['error'].splitlines()[0][:140]}")
    for h in ev.get("hints") or []:
        lines.append(f"  hint: {h}")
    if ev.get("auto_close"):
        ac = ev["auto_close"]
        ac_msg = "VERIFIED 100%!" if ac["verified"] else f"best {ac['best_aligned_pct']:.2f}%"
        lines.append(f"  auto-close ({ac['primary_class']}): {ac_msg}")
    if ev.get("diff") and not ev.get("verified"):
        lines.append(ev["diff"])
    return "\n".join(lines)


def run_watch_loop(
    session: WatchSession,
    *,
    interval_s: float = 0.25,
    stop_on_verified: bool = True,
    max_events: int = 0,
    stream: Any = None,
) -> list[dict[str, Any]]:
    """Poll `session.source_path` mtime and re-evaluate whenever saved (`Ctrl+C` or `stop_on_verified` exits)."""
    out = stream if stream is not None else sys.stdout
    events: list[dict[str, Any]] = []
    last_mtime: int | None = None
    try:
        while True:
            try:
                cur_ns = session.source_path.stat().st_mtime_ns
            except OSError:
                cur_ns = -1
            if cur_ns != -1 and cur_ns != last_mtime:
                last_mtime = cur_ns
                ev = session.evaluate_current()
                events.append(ev)
                print(format_watch_panel(ev), file=out, flush=True)
                if (stop_on_verified and ev["verified"]) or (max_events > 0 and len(events) >= max_events):
                    break
            time.sleep(max(0.05, interval_s))
    except KeyboardInterrupt:
        pass
    return events
