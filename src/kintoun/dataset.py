"""Verifiable SFT and DPO/RL fine-tuning dataset recorder & exporter (`kintoun export-dataset`).

Captures ground-truth verified decompilation trajectories (`disassembly -> verified C` and
`near-miss C + aligned diff -> verified/improved C`) from Kintoun's `CandidateStore`, `runner.py`
search milestones, and matched `src/` files so teams can fine-tune small local matching models.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sqlite3
import time
from typing import Any

from kintoun.inspect_fn import decode_target_features
from kintoun.similarity import index_matched_c_functions
from kintoun.targets import TargetContext
from kintoun.verify import real_c_violation


def record_search_trajectory(
    cache_dir: Path | None,
    *,
    func_name: str,
    func_addr: int,
    arch: str,
    seed_code: str,
    near_miss_code: str,
    near_miss_pct: float,
    near_miss_diff: str,
    final_code: str,
    final_pct: float,
    verified: bool,
    strategy: str,
) -> None:
    """Append a compact trajectory milestone to `<cache_dir>/trajectories.jsonl` when search improves/matches."""
    if cache_dir is None:
        return
    if not verified and (final_pct - near_miss_pct) < 3.0:
        return
    try:
        out_p = Path(cache_dir) / "trajectories.jsonl"
        out_p.parent.mkdir(parents=True, exist_ok=True)
        row = {
            "ts": round(time.time(), 2),
            "func": func_name,
            "addr": f"0x{func_addr:08X}",
            "arch": arch,
            "verified": bool(verified),
            "strategy": strategy,
            "seed_code": seed_code[:6000],
            "near_miss_code": near_miss_code[:6000],
            "near_miss_pct": round(near_miss_pct, 2),
            "near_miss_diff": near_miss_diff[:2400],
            "final_code": final_code[:6000],
            "final_pct": round(final_pct, 2),
        }
        with out_p.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(row) + "\n")
    except OSError:
        pass


def export_dataset(
    cache_dir: Path,
    ctx: TargetContext | None,
    *,
    src_dir: Path | None = None,
    out_path: Path,
    kinds: tuple[str, ...] = ("sft_decomp", "sft_repair", "dpo_pair"),
) -> dict[str, Any]:
    """Export deduplicated verifiable SFT & DPO training rows to `out_path` (`.jsonl`)."""
    cdir = Path(cache_dir)
    records: list[dict[str, Any]] = []
    seen_hashes: set[str] = set()
    counts = {"sft_decomp": 0, "sft_repair": 0, "dpo_pair": 0}

    def _emit(rec: dict[str, Any]) -> None:
        k = rec["kind"]
        if k not in kinds:
            return
        # Never export snippets containing inline asm violations
        for field_name in ("completion", "chosen"):
            if field_name in rec and real_c_violation(str(rec[field_name])):
                return
        sig = hashlib.sha256(json.dumps(rec, sort_keys=True).encode("utf-8")).hexdigest()[:16]
        if sig not in seen_hashes:
            seen_hashes.add(sig)
            records.append(rec)
            counts[k] = counts.get(k, 0) + 1

    def _disasm_for(fname: str) -> str:
        if ctx is None or fname not in ctx.funcs:
            return ""
        try:
            tf = ctx.resolve_function(fname)
            return decode_target_features(tf, ctx)["disasm"]
        except Exception:
            return ""

    arch_name = ctx.arch if ctx is not None else "ppc_elf"

    # 1. Ground-truth SFT pairs from matched `src/` functions paired with binary disassembly
    if ctx is not None and src_dir is not None and Path(src_dir).is_dir():
        for fname, (_file, c_def) in index_matched_c_functions(src_dir).items():
            if fname in ctx.funcs:
                dis = _disasm_for(fname)
                if dis:
                    _emit(
                        {
                            "kind": "sft_decomp",
                            "func": fname,
                            "arch": arch_name,
                            "prompt": f"/* Target {arch_name} disassembly for {fname}: */\n{dis}",
                            "completion": c_def,
                        }
                    )

    # 2. Search milestone trajectories (`trajectories.jsonl`)
    traj_p = cdir / "trajectories.jsonl"
    if traj_p.is_file():
        for line in traj_p.read_text(encoding="utf-8", errors="replace").splitlines():
            if not line.strip():
                continue
            try:
                tr = json.loads(line)
            except Exception:
                continue
            fn = str(tr.get("func", ""))
            t_arch = str(tr.get("arch", arch_name))
            dis = _disasm_for(fn)
            nm_code = str(tr.get("near_miss_code") or tr.get("seed_code") or "")
            nm_diff = str(tr.get("near_miss_diff") or "")
            fin_code = str(tr.get("final_code") or "")
            if not fin_code:
                continue
            if tr.get("verified"):
                if dis:
                    _emit(
                        {
                            "kind": "sft_decomp",
                            "func": fn,
                            "arch": t_arch,
                            "prompt": f"/* Target {t_arch} disassembly for {fn}: */\n{dis}",
                            "completion": fin_code,
                        }
                    )
                if nm_code and nm_code != fin_code:
                    _emit(
                        {
                            "kind": "sft_repair",
                            "func": fn,
                            "arch": t_arch,
                            "near_miss_code": nm_code,
                            "aligned_diff": nm_diff,
                            "prompt": f"/* Near-miss C ({tr.get('near_miss_pct')}%): */\n{nm_code}\n/* Diff: */\n{nm_diff}",
                            "completion": fin_code,
                        }
                    )
            if nm_code and nm_code != fin_code and float(tr.get("final_pct", 0)) > float(tr.get("near_miss_pct", 0)):
                _emit(
                    {
                        "kind": "dpo_pair",
                        "func": fn,
                        "arch": t_arch,
                        "prompt": f"/* Match {fn} ({t_arch}): */\n{dis or nm_diff}",
                        "chosen": fin_code,
                        "rejected": nm_code,
                    }
                )

    # 3. `CandidateStore` (`candidates.sqlite3`) verified vs mismatch pairs per function
    cand_db = cdir / "candidates.sqlite3"
    if cand_db.is_file():
        conn = sqlite3.connect(cand_db, timeout=10.0)
        try:
            rows = conn.execute(
                "SELECT func_name, source, result_json FROM candidates ORDER BY created ASC"
            ).fetchall()
        finally:
            conn.close()
        by_fn: dict[str, list[tuple[float, bool, str, str]]] = {}
        for fname, src_code, rjson in rows:
            try:
                robj = json.loads(rjson)
            except Exception:
                continue
            if robj.get("status") not in ("mismatch", "verified"):
                continue
            pct = 100.0 if robj.get("verified") else float((robj.get("search") or {}).get("aligned_pct", 0.0))
            diff_txt = str((robj.get("search") or {}).get("diff", ""))
            by_fn.setdefault(fname, []).append((pct, bool(robj.get("verified")), src_code, diff_txt))

        for fname, items in by_fn.items():
            dis = _disasm_for(fname)
            verified_items = [it for it in items if it[1]]
            mismatch_items = [it for it in items if not it[1] and it[0] >= 50.0]
            if verified_items:
                win_code = verified_items[-1][2]
                if dis:
                    _emit(
                        {
                            "kind": "sft_decomp",
                            "func": fname,
                            "arch": arch_name,
                            "prompt": f"/* Target {arch_name} disassembly for {fname}: */\n{dis}",
                            "completion": win_code,
                        }
                    )
                if mismatch_items:
                    best_mm = sorted(mismatch_items, key=lambda x: x[0])[-1]
                    _emit(
                        {
                            "kind": "sft_repair",
                            "func": fname,
                            "arch": arch_name,
                            "near_miss_code": best_mm[2],
                            "aligned_diff": best_mm[3],
                            "prompt": f"/* Near-miss C ({best_mm[0]:.1f}%): */\n{best_mm[2]}\n/* Diff: */\n{best_mm[3]}",
                            "completion": win_code,
                        }
                    )
                    _emit(
                        {
                            "kind": "dpo_pair",
                            "func": fname,
                            "arch": arch_name,
                            "prompt": f"/* Match {fname} ({arch_name}): */\n{dis or best_mm[3]}",
                            "chosen": win_code,
                            "rejected": best_mm[2],
                        }
                    )

    out_p = Path(out_path)
    out_p.parent.mkdir(parents=True, exist_ok=True)
    with out_p.open("w", encoding="utf-8") as handle:
        for r in records:
            handle.write(json.dumps(r) + "\n")

    return {
        "output_path": str(out_p),
        "total_records": len(records),
        "counts": counts,
    }
