"""Zero-LLM near-miss diff classifier and targeted 1-to-2-pass closer (`$0` API).

Classifies strict assembly mismatches across PowerPC (`ppc_elf`), MIPS (`mips_elf`), and
ARM/Thumb (`arm_elf`) into seven actionable categories:
  - `register_allocation`
  - `instruction_order`
  - `missing_cast`
  - `stack_layout`
  - `constant_literal`
  - `branch_shape`
  - `float_shape`

Then runs a bounded targeted search using only the matching Kintoun strategy families under
the `background` governor tier, running a deeper second pass ONLY if pass 1 strictly reduced
`different_bytes` or raised `aligned_pct`, and saving `.kintoun/hints/<func>.{json,c}` when
improved but not yet verified.
"""
from __future__ import annotations

import json
from pathlib import Path
import re
import time
from typing import Any

from kintoun.compiler import CompilerBackend
from kintoun.governor import CompileGovernor
from kintoun.search.runner import rank_result, run_search
from kintoun.targets import TargetContext, TargetFunction
from kintoun.verify import real_c_violation, verify_source

MISMATCH_CLASSES: tuple[str, ...] = (
    "register_allocation",
    "instruction_order",
    "missing_cast",
    "stack_layout",
    "constant_literal",
    "branch_shape",
    "float_shape",
    "unknown",
)

CLASS_STRATEGIES: dict[str, list[str]] = {
    "register_allocation": ["register_focus", "regalloc", "temps"],
    "instruction_order": ["statement", "temps", "regalloc"],
    "missing_cast": ["types", "regalloc"],
    "stack_layout": ["temps", "types", "regalloc"],
    "constant_literal": ["types", "systematic"],
    "branch_shape": ["control", "types"],
    "float_shape": ["types", "temps", "regalloc"],
    "unknown": ["systematic", "register_focus"],
}

_REG_NORM_RE = re.compile(
    r"\b(?:r\d{1,2}|f\d{1,2}|\$(?:v[01]|a[0-3]|t[0-9]|s[0-7]|f\d{1,2}))\b"
)


def classify_mismatch(result: dict[str, Any], arch: str = "ppc_elf") -> dict[str, Any]:
    """Classify a strict verification mismatch into a primary class and strategy plan."""
    sc = result.get("search") or {}
    hints: list[str] = [str(h) for h in (sc.get("hints") or [])]
    repairs: list[dict[str, Any]] = [r for r in (result.get("repairs") or []) if isinstance(r, dict)]
    diff_text = str(sc.get("diff") or "")

    votes: dict[str, float] = {c: 0.0 for c in MISMATCH_CLASSES}

    # 1. Architecture-specific assembly diff line voting
    for raw_line in diff_text.splitlines():
        line = raw_line.strip()
        if not line or not line.startswith(("!", "+", "-")):
            continue
        marker = line[0]
        body = line[1:].lower()
        if marker == "!":
            votes["register_allocation"] += 1.5

        if arch in ("mips", "mips_elf"):
            if re.search(r"\b(?:andi.*0xffff|andi.*0xff|sll\b.*sra\b|slt\b|sltu\b|sltiu?\b|seb\b|seh\b)\b", body):
                votes["missing_cast"] += 1.5
            elif re.search(r"\b\$sp\b", body):
                votes["stack_layout"] += 1.5
            elif re.search(r"\b(?:lui|ori|addiu)\b.*0x", body):
                votes["constant_literal"] += 1.0
            elif re.search(r"\b(?:beq|bne|blez|bgtz|bltz|bgez|beql|bnel|bc1[ft])\b", body):
                votes["branch_shape"] += 1.2
            elif re.search(r"\b(?:add\.s|sub\.s|mul\.s|div\.s|cvt\.|madd\.s|lwc1|swc1|mov\.s)\b", body):
                votes["float_shape"] += 1.5
            else:
                votes["instruction_order"] += 0.5
        elif arch in ("arm", "arm_elf"):
            if re.search(r"\b(?:lsls?.*#16|lsls?.*#24|asrs?.*#16|lsrs?.*#16|uxth|sxth|uxtb|sxtb)\b", body):
                votes["missing_cast"] += 1.5
            elif re.search(r"\b(?:sp|push|pop)\b", body):
                votes["stack_layout"] += 1.5
            elif re.search(r"\.(?:word|4byte|short)\b|\[pc,", body):
                votes["constant_literal"] += 1.2
            elif re.search(r"\bb(?:eq|ne|cs|cc|mi|pl|hi|ls|ge|lt|gt|le)\b", body):
                votes["branch_shape"] += 1.2
            elif re.search(r"__aeabi_[fd]|mulsf3|addsf3|subsf3|divsf3", body):
                votes["float_shape"] += 1.5
            else:
                votes["instruction_order"] += 0.5
        else:  # PowerPC (`ppc_elf`)
            if re.search(r"\b(?:exts[bh]|clrlwi|rlwinm|cmplwi?|srawi|srwi)\b", body):
                votes["missing_cast"] += 1.5
            elif re.search(r"\b(?:stwu|stmw|lmw)\b|\(\s*r1\s*\)", body):
                votes["stack_layout"] += 1.5
            elif re.search(r"\b(?:lis|ori|addis|li)\b", body):
                votes["constant_literal"] += 1.0
            elif re.search(r"\b(?:beq|bne|blt|bgt|ble|bge|bc|cror)\b", body):
                votes["branch_shape"] += 1.2
            elif re.search(r"\b(?:lfs|lfd|stfs|stfd|fadds?|fsubs?|fmuls?|fdivs?|fmadds?|frsp|fcmp[ou])\b", body):
                votes["float_shape"] += 1.5
            else:
                votes["instruction_order"] += 0.5

    # 2. Scorer hints and instruction-backed repair hypotheses
    blob = (
        " ".join(hints).lower()
        + " "
        + " ".join(f"{r.get('category', '')} {r.get('action', '')}" for r in repairs).lower()
    )
    if re.search(r"register|regalloc|callee-saved|live-range", blob):
        votes["register_allocation"] += 2.5
    if re.search(r"order|schedul|delay|swap", blob):
        votes["instruction_order"] += 2.0
    if re.search(r"sign|unsigned|width|cast|zero-ext|narrow", blob):
        votes["missing_cast"] += 2.5
    if re.search(r"stack|frame|spill|sp\b", blob):
        votes["stack_layout"] += 2.5
    if re.search(r"literal|constant|immediate|pool|global", blob):
        votes["constant_literal"] += 2.0
    if re.search(r"branch|polarity|condition|loop", blob):
        votes["branch_shape"] += 2.0
    if re.search(r"float|double|single|fma|frsp", blob):
        votes["float_shape"] += 2.0

    # Strip `unknown` unless every concrete class scored 0
    best_cls = max((c for c in MISMATCH_CLASSES if c != "unknown"), key=lambda c: votes[c])
    if votes[best_cls] <= 0.0:
        best_cls = "unknown"
    ranked = sorted(((k, round(v, 2)) for k, v in votes.items() if v > 0), key=lambda kv: -kv[1])
    return {
        "primary_class": best_cls,
        "strategies": list(CLASS_STRATEGIES[best_cls]),
        "votes": dict(ranked[:4]),
        "summary": ", ".join(f"{k}={v:g}" for k, v in ranked[:3]) or "no signal",
    }


def save_near_miss_hint(
    kintoun_dir: Path,
    target_fn: TargetFunction,
    code: str,
    result: dict[str, Any],
    classification: dict[str, Any],
) -> Path:
    """Persist the best near-miss C and diff classification to `.kintoun/hints/<func>.{json,c}`."""
    hints_dir = Path(kintoun_dir) / "hints"
    hints_dir.mkdir(parents=True, exist_ok=True)
    c_path = hints_dir / f"{target_fn.name}.c"
    j_path = hints_dir / f"{target_fn.name}.json"
    c_path.write_text(code, encoding="utf-8")
    sc = result.get("search") or {}
    payload = {
        "name": target_fn.name,
        "addr": f"0x{target_fn.va:08X}",
        "updated_ts": time.time(),
        "aligned_pct": sc.get("aligned_pct"),
        "normalized_pct": sc.get("normalized_pct"),
        "different_bytes": result.get("different_bytes"),
        "classification": classification,
        "hints": (sc.get("hints") or [])[:6],
        "source_file": str(c_path),
    }
    tmp = j_path.with_suffix(".tmp")
    tmp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    tmp.replace(j_path)
    return j_path


def close_near_miss(
    seeds: str | list[str],
    target_fn: TargetFunction,
    ctx: TargetContext,
    compiler: CompilerBackend,
    *,
    budget_s: float = 60.0,
    max_candidates: int = 160,
    second_pass: bool = True,
    second_budget_s: float = 45.0,
    workers: int = 2,
    cache_dir: Path | None = None,
    priors_path: Path | None = None,
    forbid_asm: bool = True,
    governor_check: bool = True,
) -> dict[str, Any]:
    """Run targeted zero-LLM near-miss closing across 1..4 seed drafts with optional 2nd pass."""
    seed_list = [seeds] if isinstance(seeds, str) else list(seeds)
    clean_seeds = [s for s in seed_list if s and s.strip() and (not forbid_asm or not real_c_violation(s))][:4]
    if not clean_seeds:
        return {
            "name": target_fn.name,
            "addr": f"0x{target_fn.va:08X}",
            "verified": False,
            "error": "no valid plain-C seeds provided",
        }

    eff_cache = Path(cache_dir) if cache_dir else None
    if governor_check and eff_cache is not None:
        gov = CompileGovernor(eff_cache, caller_id="closer")
        with gov.acquire(tier="background", timeout_s=2.0) as admitted:
            if not admitted:
                return {
                    "name": target_fn.name,
                    "addr": f"0x{target_fn.va:08X}",
                    "verified": False,
                    "skipped": True,
                    "reason": "governor deferred background closer (higher-priority work or memory pressure)",
                }

    started = time.monotonic()
    # Score all seeds first to pick the strongest starting point and classify its asm diff
    best_seed_src = clean_seeds[0]
    best_seed_res = verify_source(best_seed_src, target_fn, ctx, compiler, lines=32, forbid_asm=forbid_asm)
    best_seed_res["_source"] = best_seed_src
    if best_seed_res.get("verified"):
        clean = {k: v for k, v in best_seed_res.items() if not k.startswith("_")}
        clean["code"] = best_seed_src
        return {
            "name": target_fn.name,
            "addr": f"0x{target_fn.va:08X}",
            "verified": True,
            "passes": 0,
            "evaluated": 1,
            "compiled": 1,
            "classification": {"primary_class": "already_verified", "strategies": []},
            "best": clean,
            "elapsed_s": round(time.monotonic() - started, 3),
        }

    for extra_src in clean_seeds[1:]:
        r = verify_source(extra_src, target_fn, ctx, compiler, lines=32, forbid_asm=forbid_asm)
        r["_source"] = extra_src
        if r.get("verified"):
            clean = {k: v for k, v in r.items() if not k.startswith("_")}
            clean["code"] = extra_src
            return {
                "name": target_fn.name,
                "addr": f"0x{target_fn.va:08X}",
                "verified": True,
                "passes": 0,
                "evaluated": 2,
                "compiled": 2,
                "classification": {"primary_class": "already_verified", "strategies": []},
                "best": clean,
                "elapsed_s": round(time.monotonic() - started, 3),
            }
        if rank_result(r) < rank_result(best_seed_res):
            best_seed_res = r
            best_seed_src = extra_src

    cls_info = classify_mismatch(best_seed_res, arch=ctx.arch)
    pass1 = run_search(
        source=best_seed_src,
        target_fn=target_fn,
        ctx=ctx,
        compiler=compiler,
        budget_s=max(1.0, budget_s),
        max_candidates=max(8, max_candidates),
        strategies=cls_info["strategies"],
        workers=max(1, min(workers, 4)),
        cache_dir=eff_cache,
        priors_path=priors_path,
        forbid_asm=forbid_asm,
        seed=0,
    )

    total_eval = int(pass1.get("evaluated") or 0)
    total_comp = int(pass1.get("compiled") or 0)
    passes = 1
    best_out = pass1.get("best") or {}
    verified = bool(pass1.get("verified"))

    # Pass 2 runs ONLY if Pass 1 strictly improved over the starting seed without verifying
    start_rank = rank_result(best_seed_res)
    pass1_rank = rank_result({**best_out, "_source": best_out.get("code", best_seed_src)}) if best_out else start_rank
    strictly_improved = pass1_rank < start_rank

    if second_pass and not verified and strictly_improved and best_out.get("code"):
        passes = 2
        cls_info_2 = classify_mismatch(best_out, arch=ctx.arch)
        pass2 = run_search(
            source=best_out["code"],
            target_fn=target_fn,
            ctx=ctx,
            compiler=compiler,
            budget_s=max(1.0, second_budget_s),
            max_candidates=max(8, max_candidates),
            strategies=list(dict.fromkeys(cls_info_2["strategies"] + ["systematic"])),
            workers=max(1, min(workers, 4)),
            cache_dir=eff_cache,
            priors_path=priors_path,
            forbid_asm=forbid_asm,
            seed=1,
        )
        total_eval += int(pass2.get("evaluated") or 0)
        total_comp += int(pass2.get("compiled") or 0)
        p2_best = pass2.get("best") or {}
        if pass2.get("verified") or (
            p2_best
            and rank_result({**p2_best, "_source": p2_best.get("code", "")})
            < rank_result({**best_out, "_source": best_out.get("code", "")})
        ):
            best_out = p2_best
            verified = bool(pass2.get("verified"))
            cls_info = cls_info_2

    hint_file: str | None = None
    if not verified and best_out.get("code") and eff_cache is not None and strictly_improved:
        saved = save_near_miss_hint(eff_cache.parent, target_fn, best_out["code"], best_out, cls_info)
        hint_file = str(saved)

    return {
        "name": target_fn.name,
        "addr": f"0x{target_fn.va:08X}",
        "verified": verified,
        "improved": strictly_improved or verified,
        "passes": passes,
        "evaluated": total_eval,
        "compiled": total_comp,
        "classification": cls_info,
        "best": best_out,
        "hint_file": hint_file,
        "elapsed_s": round(time.monotonic() - started, 3),
    }
