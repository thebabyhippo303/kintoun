"""Standalone parallel C mutation & register-permutation search runner."""
from __future__ import annotations

from collections import deque
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
import hashlib
import os
from pathlib import Path
import random
import time
from typing import Any

from kintoun.cache import ResultCache, source_key
from kintoun.compiler import CompilerBackend
from kintoun.search import base_mutations, guidance, mutations, permuter
from kintoun.targets import TargetContext, TargetFunction
from kintoun.verify import real_c_violation, verify_source

GROUPS = {
    "statement": {"swap_stmts", "ordered_stores", "decl_order"},
    "types": {"local_type", "param_type", "field_type", "cast_strip", "callee_proto", "float_expr"},
    "temps": {"inline_temp", "hoist_cse", "split_load", "var_split", "temp_merge", "var_merge", "bool_phi"},
    "control": {"if_invert", "cond_rewrite", "loop_shape", "return_style", "bool_assign"},
    "regalloc": {"register", "alias_make", "commute", "arith", "cr_flag", "alias_fold", "struct_copy"},
}
STRATEGIES = (
    "systematic",
    "random",
    "statement",
    "types",
    "temps",
    "control",
    "regalloc",
    "register_focus",
)


def generate_proposals(
    source: str,
    strategies: list[str] | tuple[str, ...],
    rng: random.Random,
    max_items: int = 800,
    result: dict[str, Any] | None = None,
    priors_path: Path | None = None,
) -> list[tuple[str, str]]:
    """Generate one-step real-C variants ordered by strict mismatch hints and priors."""
    if max_items <= 0:
        return []
    chosen = set(strategies)
    families = set().union(*(GROUPS[key] for key in GROUPS if key in chosen))
    if "systematic" in chosen or "random" in chosen:
        families = {fn.__name__.removeprefix("m_") for fn in base_mutations.FAMILIES}

    outputs: list[tuple[str, str]] = []
    seen = {source}
    preferred = guidance.priorities(result)

    for family, text in guidance.repair_proposals(source, result):
        if text not in seen:
            seen.add(text)
            outputs.append((family, text))
            if len(outputs) >= max_items:
                return outputs

    if ("register_focus" in chosen or "regalloc" in chosen) and guidance.near_miss(result):
        for family, text in permuter.variants(
            source, base_mutations, limit=min(24, max(4, max_items // 8))
        ):
            if text not in seen:
                seen.add(text)
                outputs.append((family, text))
                if len(outputs) >= max_items:
                    return outputs

    priors = guidance.load_priors(priors_path=priors_path)

    def _order(fn: Any) -> tuple[int, float, int]:
        family = fn.__name__.removeprefix("m_")
        return (
            0 if family in preferred else 1,
            -priors.get(family, 1.0),
            preferred.index(family) if family in preferred else 0,
        )

    ordered = sorted(
        (fn for fn in base_mutations.FAMILIES if fn.__name__.removeprefix("m_") in families),
        key=_order,
    )
    family_iters = [iter(base_mutations.mutations(source, [fn])) for fn in ordered]

    if preferred:
        while family_iters and len(outputs) < max_items:
            remaining = []
            for it in family_iters:
                try:
                    family, text = next(it)
                except StopIteration:
                    continue
                remaining.append(it)
                if text not in seen:
                    seen.add(text)
                    outputs.append((family, text))
                    if len(outputs) >= max_items:
                        break
            family_iters = remaining
    else:
        for it in family_iters:
            for family, text in it:
                if text in seen:
                    continue
                seen.add(text)
                outputs.append((family, text))
                if len(outputs) >= max_items:
                    return outputs

    extras = (
        mutations.m_index_address,
        mutations.m_narrow_return,
        mutations.m_extern_const,
        mutations.m_fp_prototype,
    )
    for fn in sorted(
        extras,
        key=lambda f: preferred.index(f.__name__.removeprefix("m_"))
        if f.__name__.removeprefix("m_") in preferred
        else len(preferred),
    ):
        if len(outputs) >= max_items or ("systematic" not in chosen and "random" not in chosen):
            break
        for family, text in fn(source):
            if text in seen:
                continue
            seen.add(text)
            outputs.append((family, text))
            if len(outputs) >= max_items:
                break

    if "random" in chosen and outputs:
        if not preferred:
            rng.shuffle(outputs)
        for _, first in outputs[: min(32, len(outputs))]:
            if len(outputs) >= max_items:
                break
            next_variants = list(base_mutations.mutations(first))
            if next_variants:
                family, text = rng.choice(next_variants)
                if text not in seen:
                    seen.add(text)
                    outputs.append(("random+" + family, text))

    return outputs


def rank_result(result: dict[str, Any]) -> tuple[int, int, int, int]:
    """Strict ranking tuple (lower is better; (0,0,0,0) is byte-exact match)."""
    if result.get("verified"):
        return (0, 0, 0, 0)
    if result.get("status") == "mismatch":
        return (
            1,
            int(result.get("different_bytes", 10**9)),
            int(result.get("instruction_mismatches", 10**9)),
            int(result.get("search", {}).get("total", 10**9)),
        )
    if result.get("status") == "unresolved":
        return (2, int(result.get("search", {}).get("total", 10**9)), 0, 0)
    return (3, 10**9, 10**9, 10**9)


def run_search(
    *,
    source: str,
    target_fn: TargetFunction,
    ctx: TargetContext,
    compiler: CompilerBackend,
    budget_s: float = 60.0,
    max_candidates: int = 600,
    strategies: list[str] | tuple[str, ...] = ("systematic", "register_focus", "random"),
    workers: int = 0,
    cache_dir: Path | None = None,
    priors_path: Path | None = None,
    forbid_asm: bool = True,
    seed: int = 0,
) -> dict[str, Any]:
    """Run a bounded parallel real-C mutation & register-permutation search."""
    if not 1 <= budget_s <= 3600:
        raise ValueError("budget_s must be between 1 and 3600 seconds")
    if not 1 <= max_candidates <= 10000:
        raise ValueError("max_candidates must be between 1 and 10000")
    unknown = set(strategies) - set(STRATEGIES)
    if unknown:
        raise ValueError("unknown strategies: " + ", ".join(sorted(unknown)))
    if forbid_asm and real_c_violation(source):
        raise ValueError(f"REAL C ONLY: input contains '{real_c_violation(source)}'")

    cache = ResultCache(cache_dir) if cache_dir else None
    max_workers = workers if workers > 0 else max(1, min((os.cpu_count() or 2) // 2, 8))
    max_workers = min(max_workers, max_candidates)
    target_id = f"{target_fn.name}@0x{target_fn.va:08X}:{hashlib.sha256(target_fn.data).hexdigest()[:16]}"

    started = time.monotonic()
    deadline = started + budget_s
    stats: dict[str, Any] = {
        "evaluated": 0,
        "compiled": 0,
        "useful_candidates": 0,
        "cache_hits": 0,
        "compile_errors": 0,
        "improvements": 0,
        "stopped": None,
        "workers": max_workers,
    }
    pending: deque[tuple[str, str]] = deque([("input", source)])
    seen = {hashlib.sha256(source.encode("utf-8")).digest()}
    rng = random.Random(seed)
    best: dict[str, Any] | None = None
    input_result: dict[str, Any] | None = None
    active: dict[Any, str] = {}
    family_attempts: dict[str, int] = {}
    family_errors: dict[str, int] = {}
    failed_families: set[str] = set()
    no_improvement = 0
    placement_cache: dict[Any, Any] = {}

    def stop() -> bool:
        return time.monotonic() >= deadline

    def prepend(items: list[tuple[str, str]]) -> None:
        fresh = []
        for family, text in items:
            digest = hashlib.sha256(text.encode("utf-8")).digest()
            if digest not in seen and (not forbid_asm or not real_c_violation(text)):
                seen.add(digest)
                fresh.append((family, text))
                if len(fresh) + len(pending) >= max_candidates * 2:
                    break
        pending.extendleft(reversed(fresh))

    def evaluate(family: str, text: str) -> dict[str, Any] | None:
        if stop():
            return None
        key = source_key(text, target_id, compiler.flags, compiler.compiler_id)
        if cache is not None:
            cached = cache.get(key)
            if cached is not None:
                cached["cache_hit"] = True
                cached["_compiled"] = False
                cached["_family"] = family
                cached["_source"] = text
                return cached
        res = verify_source(
            text,
            target_fn,
            ctx,
            compiler,
            lines=12,
            forbid_asm=forbid_asm,
            partial_link=False,
            placement_cache=placement_cache,
        )
        res["cache_hit"] = False
        res["_compiled"] = True
        if cache is not None:
            cache.put(key, res)
        res["_family"] = family
        res["_source"] = text
        return res

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        while pending or active:
            while pending and len(active) < max_workers and stats["evaluated"] + len(active) < max_candidates:
                if stop():
                    stats["stopped"] = "budget expired"
                    break
                family, text = pending.popleft()
                if family in failed_families:
                    continue
                active[pool.submit(evaluate, family, text)] = family
            if not active:
                break
            done, _ = wait(active, timeout=0.1, return_when=FIRST_COMPLETED)
            for future in done:
                active.pop(future)
                result = future.result()
                if result is None:
                    continue
                stats["evaluated"] += 1
                stats["compiled"] += int(bool(result.get("_compiled")))
                stats["cache_hits"] += int(bool(result.get("cache_hit")))
                stats["compile_errors"] += int(result.get("status") == "compile_error")
                stats["useful_candidates"] += int(
                    bool(result.get("_compiled")) and result.get("status") in ("mismatch", "verified")
                )
                family = result["_family"]
                if family != "input":
                    family_attempts[family] = family_attempts.get(family, 0) + 1
                    family_errors[family] = family_errors.get(family, 0) + int(
                        result.get("status") == "compile_error"
                    )
                    if family_attempts[family] >= 8 and family_errors[family] / family_attempts[family] >= 0.75:
                        failed_families.add(family)
                if family == "input":
                    input_result = result
                    if result.get("status") == "mismatch":
                        prepend(
                            generate_proposals(
                                source,
                                strategies,
                                rng,
                                min(800, max_candidates * 2),
                                result=result,
                                priors_path=priors_path,
                            )
                        )
                    elif result.get("status") == "compile_error":
                        prepend(list(guidance.recovery_proposals(source)))
                if best is None or rank_result(result) < rank_result(best):
                    if best is not None:
                        stats["improvements"] += 1
                    best = result
                    no_improvement = 0
                    if result.get("verified"):
                        stats["stopped"] = "verified match"
                        pending.clear()
                    elif (
                        family != "input"
                        and result.get("status") == "mismatch"
                        and not stop()
                        and len(seen) < max_candidates * 8
                    ):
                        prepend(
                            generate_proposals(
                                result["_source"],
                                strategies,
                                rng,
                                160,
                                result=result,
                                priors_path=priors_path,
                            )
                        )
                else:
                    no_improvement += 1
                if guidance.near_miss(best) and no_improvement >= 64:
                    stats["stopped"] = "near-miss plateau (64 candidates without improvement)"
                    pending.clear()
            if stop():
                stats["stopped"] = "budget expired"
                pending.clear()

    elapsed_s = round(time.monotonic() - started, 3)
    if best is None:
        return {"name": target_fn.name, "elapsed_s": elapsed_s, **stats, "error": stats["stopped"] or "no result"}

    clean_best = {k: v for k, v in best.items() if not k.startswith("_")}
    clean_best["code"] = best["_source"]
    clean_best["strategy"] = best["_family"]
    clean_input = {k: v for k, v in (input_result or {}).items() if not k.startswith("_")}
    return {
        "name": target_fn.name,
        "addr": f"0x{target_fn.va:08X}",
        "verified": bool(best.get("verified")),
        "best": clean_best,
        "input": clean_input,
        "elapsed_s": elapsed_s,
        **stats,
    }
