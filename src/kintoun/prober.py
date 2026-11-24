"""Per-file compiler flag prober (`kintoun probe-flags`).

Compiles a rough or starting C draft across a curated matrix of compiler flags for the
configured preset (`prodg-wine`, `mwcc-wine`, `ee-gcc`, `mwccps2`, `psp-gcc`, `mwccpsp`,
`pspsnc`, `mips-gcc`, `agbcc`, `arm-none-eabi-gcc`, `mwccarm`, `armcc`, `gcc`, `custom`)
in parallel and ranks flag combinations by strict alignment %, identifying per-file
optimization/inlining/small-data/float-mode overrides in seconds.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import time
from typing import Any

from kintoun.compiler import make_compiler
from kintoun.config import KintounConfig
from kintoun.search.runner import rank_result
from kintoun.targets import TargetContext, TargetFunction
from kintoun.verify import verify_source

PRESET_FLAG_MATRICES: dict[str, list[list[str]]] = {
    "prodg-wine": [
        ["-O2", "-c"],
        ["-O1", "-c"],
        ["-O3", "-c"],
        ["-O2", "-fno-inline", "-c"],
        ["-O2", "-fomit-frame-pointer", "-c"],
        ["-O2", "-fsigned-char", "-c"],
        ["-O2", "-funsigned-char", "-c"],
        ["-O0", "-c"],
    ],
    "mwcc-wine": [
        ["-O4,p", "-nodefaults", "-proc", "gekko", "-fp", "hardware", "-c"],
        ["-O4,s", "-nodefaults", "-proc", "gekko", "-fp", "hardware", "-c"],
        ["-O4,p", "-nodefaults", "-proc", "gekko", "-fp", "fmadd", "-c"],
        ["-O4,p", "-inline", "auto", "-nodefaults", "-proc", "gekko", "-fp", "hardware", "-c"],
        ["-O4,p", "-inline", "deferred", "-nodefaults", "-proc", "gekko", "-fp", "hardware", "-c"],
        ["-O4,p", "-inline", "off", "-nodefaults", "-proc", "gekko", "-fp", "hardware", "-c"],
        ["-O4,p", "-rostr", "-nodefaults", "-proc", "gekko", "-fp", "hardware", "-c"],
        ["-O3,p", "-nodefaults", "-proc", "gekko", "-fp", "hardware", "-c"],
        ["-O2", "-nodefaults", "-proc", "gekko", "-fp", "hardware", "-c"],
    ],
    "ee-gcc": [
        ["-O2", "-mno-abicalls", "-fno-pic", "-G8", "-c"],
        ["-O2", "-mno-abicalls", "-fno-pic", "-G0", "-c"],
        ["-O2", "-mno-abicalls", "-fno-pic", "-G4", "-c"],
        ["-O1", "-mno-abicalls", "-fno-pic", "-G8", "-c"],
        ["-O3", "-mno-abicalls", "-fno-pic", "-G8", "-c"],
        ["-O2", "-fomit-frame-pointer", "-mno-abicalls", "-fno-pic", "-G8", "-c"],
        ["-Os", "-mno-abicalls", "-fno-pic", "-G8", "-c"],
    ],
    "psp-gcc": [
        ["-O2", "-mno-abicalls", "-fno-pic", "-G8", "-c"],
        ["-O2", "-mno-abicalls", "-fno-pic", "-G0", "-c"],
        ["-Os", "-mno-abicalls", "-fno-pic", "-G8", "-c"],
        ["-O3", "-mno-abicalls", "-fno-pic", "-G8", "-c"],
        ["-O1", "-mno-abicalls", "-fno-pic", "-G8", "-c"],
        ["-O2", "-ffast-math", "-mno-abicalls", "-fno-pic", "-G8", "-c"],
    ],
    "mips-gcc": [
        ["-O2", "-mno-abicalls", "-fno-pic", "-c"],
        ["-O1", "-mno-abicalls", "-fno-pic", "-c"],
        ["-O3", "-mno-abicalls", "-fno-pic", "-c"],
        ["-Os", "-mno-abicalls", "-fno-pic", "-c"],
        ["-O2", "-G8", "-mno-abicalls", "-fno-pic", "-c"],
        ["-O2", "-G0", "-mno-abicalls", "-fno-pic", "-c"],
    ],
    "mwccps2": [
        ["-O4,p", "-nodefaults", "-c"],
        ["-O4,s", "-nodefaults", "-c"],
        ["-O3,p", "-nodefaults", "-c"],
        ["-O2", "-nodefaults", "-c"],
        ["-O4,p", "-sdata", "8", "-nodefaults", "-c"],
        ["-O4,p", "-sdata", "0", "-nodefaults", "-c"],
    ],
    "mwccpsp": [
        ["-O4,p", "-nodefaults", "-c"],
        ["-O4,s", "-nodefaults", "-c"],
        ["-O3,p", "-nodefaults", "-c"],
        ["-O2", "-nodefaults", "-c"],
    ],
    "pspsnc": [
        ["-O2", "-c"],
        ["-O1", "-c"],
        ["-O3", "-c"],
        ["-Os", "-c"],
    ],
    "agbcc": [
        ["-O2"],
        ["-O1"],
        ["-O0"],
        ["-O2", "-fhex-asm"],
        ["-O2", "-fno-inline"],
    ],
    "arm-none-eabi-gcc": [
        ["-O2", "-mcpu=arm7tdmi", "-mthumb", "-c"],
        ["-Os", "-mcpu=arm7tdmi", "-mthumb", "-c"],
        ["-O1", "-mcpu=arm7tdmi", "-mthumb", "-c"],
        ["-O3", "-mcpu=arm7tdmi", "-mthumb", "-c"],
        ["-O2", "-mcpu=arm7tdmi", "-marm", "-c"],
        ["-O2", "-mcpu=arm946e-s", "-marm", "-c"],
        ["-O2", "-mcpu=arm946e-s", "-mthumb", "-c"],
    ],
    "mwccarm": [
        ["-O4,p", "-proc", "arm946e", "-c"],
        ["-O4,s", "-proc", "arm946e", "-c"],
        ["-O4,p", "-thumb", "-proc", "arm946e", "-c"],
        ["-O3,p", "-proc", "arm946e", "-c"],
        ["-O2", "-proc", "arm946e", "-c"],
    ],
    "armcc": [
        ["--thumb", "-O2", "-c"],
        ["--thumb", "-O3", "-Otime", "-c"],
        ["--thumb", "-O3", "-Ospace", "-c"],
        ["--arm", "-O2", "-c"],
        ["--thumb", "-O1", "-c"],
    ],
}


def candidate_flag_sets(cfg: KintounConfig, va: int | None = None) -> list[list[str]]:
    """Build deduplicated candidate flag lists starting with the active config flags."""
    active_cc = cfg.compiler_for(va)
    preset = active_cc.preset.strip().lower()
    seen: list[list[str]] = []
    if active_cc.flags:
        seen.append(list(active_cc.flags))
    matrix = PRESET_FLAG_MATRICES.get(preset) or [
        ["-O2", "-c"],
        ["-O1", "-c"],
        ["-O3", "-c"],
        ["-Os", "-c"],
        ["-O0", "-c"],
    ]
    for flags in matrix:
        if flags not in seen:
            seen.append(list(flags))
    return seen


def probe_compiler_flags(
    source: str,
    target_fn: TargetFunction,
    ctx: TargetContext,
    cfg: KintounConfig,
    *,
    extra_flag_sets: list[list[str]] | None = None,
    workers: int = 4,
) -> dict[str, Any]:
    """Compile `source` across candidate flag sets in parallel and rank by strict alignment."""
    t0 = time.monotonic()
    flag_sets = candidate_flag_sets(cfg, va=target_fn.va)
    for extra in extra_flag_sets or []:
        if extra not in flag_sets:
            flag_sets.append(list(extra))

    base_cc = cfg.compiler_for(target_fn.va)

    def _eval_one(flags: list[str]) -> dict[str, Any]:
        sub_cc = replace(base_cc, flags=list(flags))
        sub_cfg = replace(cfg, compiler=sub_cc, compiler_bands=[])
        compiler = make_compiler(sub_cfg)
        res = verify_source(
            source,
            target_fn,
            ctx,
            compiler,
            lines=12,
            forbid_asm=cfg.search.forbid_asm,
        )
        res["_source"] = source
        res["_flags"] = flags
        return res

    max_w = max(1, min(workers, len(flag_sets), 8))
    with ThreadPoolExecutor(max_workers=max_w) as pool:
        raw_results = list(pool.map(_eval_one, flag_sets))

    ranked = sorted(raw_results, key=rank_result)
    rows: list[dict[str, Any]] = []
    for r in ranked:
        sc = r.get("search") or {}
        rows.append(
            {
                "flags": r["_flags"],
                "verified": bool(r.get("verified")),
                "status": r.get("status", "error"),
                "aligned_pct": round(float(sc.get("aligned_pct") or 0.0), 2),
                "normalized_pct": round(float(sc.get("normalized_pct") or 0.0), 2),
                "different_bytes": r.get("different_bytes"),
                "ours_bytes": r.get("ours_bytes"),
                "score_total": sc.get("total"),
            }
        )

    best = rows[0] if rows else None
    return {
        "name": target_fn.name,
        "addr": f"0x{target_fn.va:08X}",
        "preset": cfg.compiler.preset,
        "tested_flag_sets": len(rows),
        "best": best,
        "toml_snippet": f"flags = {best['flags']!r}" if best else "",
        "results": rows,
        "elapsed_s": round(time.monotonic() - t0, 3),
    }
