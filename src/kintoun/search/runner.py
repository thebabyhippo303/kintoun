"""Standalone parallel C mutation & register-permutation beam search runner."""
from __future__ import annotations

from collections import deque
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
import hashlib
import os
from pathlib import Path
import random
import re
import time
from typing import Any

from kintoun.cache import ResultCache, source_key
from kintoun.compiler import CompilerBackend
from kintoun.search import base_mutations, guidance, mutations, permuter
from kintoun.search import score as ppc_score_mod
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

# Pure C-to-C scheduling, memory, switch, and recovery transforms from `mutations_*.py`
# usable across PowerPC, MIPS, and ARM/Thumb.
_TEXT_C_SHAPE_FAMILIES = (
    mutations.m_index_address,
    mutations.m_narrow_return,
    mutations.m_extern_const,
    mutations.m_fp_prototype,
    mutations.m_init_order,
    mutations.m_constarg_hoist,
    mutations.m_mixed_order,
    mutations.m_plainload_order,
    mutations.m_addr_order,
    mutations.m_samecopy_order,
    mutations.m_member_order,
    mutations.m_callmove_order,
    mutations.m_cho_midfirst,
    mutations.m_disjoint_order,
    mutations.m_spillsched_order,
    mutations.m_calladdr_order,
    mutations.m_callpure_order,
    mutations.m_cholit_order,
    mutations.m_samemem_order,
    mutations.m_sameload_order,
    mutations.m_bytesview_order,
    mutations.m_caseswap_order,
    mutations.m_loadhoist_order,
    mutations.m_alias_sink,
    mutations.m_case_order,
    mutations.m_switch_lower,
    mutations.m_fmem_order,
    mutations.m_fmem_hop,
)

_FLOAT_C_SHAPE_FAMILIES = (
    mutations.m_fma_negate,
    mutations.m_fneg_intro,
    mutations.m_fneg_zero,
    mutations.m_fneg_distsum,
    mutations.m_ftwice_add,
    mutations.m_fconv_narrow,
    mutations.m_fconv_widen,
    mutations.m_fconv_pun,
    mutations.m_fcmp_negate,
    mutations.m_fcmp_swap,
    mutations.m_fcmp_eqswap,
)


class _PpcScoreProxy:
    """Adapter exposing `.ours`, `.target`, `.ops`, and `.unresolved` to `mutations.directed`."""

    def __init__(
        self,
        ours: list[int],
        target: list[int],
        ops: list[Any] | None = None,
        unresolved: dict[Any, Any] | None = None,
    ) -> None:
        self.ours = ours
        self.target = target
        self.ops = ops if ops is not None else ppc_score_mod.score(ours, target, with_hints=False).ops
        self.unresolved = unresolved or {}


class _PpcBookProxy:
    """Symbol-book adapter exposing `.functions`, `.objects`, and `.address(name)` to `mutations.directed`."""

    def __init__(self, ctx: TargetContext) -> None:
        self._ctx = ctx
        self.functions = {va: (n, sz) for n, (va, sz) in ctx.funcs.items()}
        self.objects = ctx.objs

    def address(self, name: str) -> int:
        if name in self._ctx.external:
            return self._ctx.external[name]
        m = re.fullmatch(r"(?:lbl|fn|func|D)_([0-9A-Fa-f]{8})", name)
        if m:
            return int(m.group(1), 16)
        raise ValueError(name)


def _iter_c_shape_families(source: str, hoist_c89: bool = False):
    """Yield cross-architecture C-to-C scheduling, switch, memory, and FP variants."""
    from kintoun.search import mips_seeds

    has_fp = bool(re.search(r"\b(?:f32|f64|float|double)\b", source))
    fams = _TEXT_C_SHAPE_FAMILIES + (_FLOAT_C_SHAPE_FAMILIES if has_fp else ())
    for fn in fams:
        try:
            for family, text in fn(source):
                if hoist_c89:
                    text = mips_seeds.hoist_c89_declarations(text)
                yield family, text
        except Exception:
            continue


def generate_proposals(
    source: str,
    strategies: list[str] | tuple[str, ...],
    rng: random.Random,
    max_items: int = 800,
    result: dict[str, Any] | None = None,
    priors_path: Path | None = None,
    arch: str = "ppc_elf",
    ctx: TargetContext | None = None,
    target_fn: TargetFunction | None = None,
) -> list[tuple[str, str]]:
    """Generate one-step real-C variants ordered by strict mismatch hints, target instructions, and priors."""
    if arch in ("mips", "mips_elf", "arm", "arm_elf"):
        return _generate_arch_proposals(
            source, strategies, rng, max_items, result, priors_path, arch, ctx=ctx, target_fn=target_fn
        )
    if max_items <= 0:
        return []
    chosen = set(strategies)
    families = set().union(*(GROUPS[key] for key in GROUPS if key in chosen))
    if "systematic" in chosen or "random" in chosen:
        families = {fn.__name__.removeprefix("m_") for fn in base_mutations.FAMILIES}

    outputs: list[tuple[str, str]] = []
    seen = {source}
    preferred = guidance.priorities(result)

    # 1. Exact one-site repair hypotheses
    for family, text in guidance.repair_proposals(source, result):
        if text not in seen:
            seen.add(text)
            outputs.append((family, text))
            if len(outputs) >= max_items:
                return outputs

    # 2. Target-instruction-directed PowerPC moves (`mutations.directed`, `frame_unions`, `ppc_seeds`)
    if target_fn is not None and target_fn.data and ctx is not None:
        from kintoun.search import mips_seeds, ppc_seeds

        target_words = ppc_score_mod.words_be(target_fn.data)
        ours_words = (result or {}).get("_ours_words")
        if ours_words:
            sc_proxy = _PpcScoreProxy(
                ours=list(ours_words),
                target=target_words,
                ops=(result or {}).get("_ops"),
            )
            book_proxy = _PpcBookProxy(ctx)
            cfg_dict = {"sda_r13": ctx.sda_r13, "sda_r2": ctx.sda_r2}
            try:
                for family, cand in mutations.directed(source, sc_proxy, book_proxy, target_fn.va, cfg_dict):
                    c89 = mips_seeds.hoist_c89_declarations(cand)
                    if c89 not in seen:
                        seen.add(c89)
                        outputs.append((family, c89))
                        if len(outputs) >= max_items:
                            return outputs
            except Exception:
                pass
            try:
                for family, cand in mutations.frame_unions(source, sc_proxy):
                    if cand not in seen:
                        seen.add(cand)
                        outputs.append((family, cand))
                        if len(outputs) >= max_items:
                            return outputs
            except Exception:
                pass

        if "systematic" in chosen or "random" in chosen:
            from kintoun.constants import constant_repair_variants

            for family, cand in constant_repair_variants(source, target_fn, ctx):
                if cand not in seen:
                    seen.add(cand)
                    outputs.append((family, cand))
                    if len(outputs) >= max_items:
                        return outputs
            for family, cand in ppc_seeds.ppc_seed_variants(source, target_fn, ctx):
                if cand not in seen:
                    seen.add(cand)
                    outputs.append((family, cand))
                    if len(outputs) >= max_items:
                        return outputs

    directed_count = len(outputs)

    # 3. Live-range register permuter
    if ("register_focus" in chosen or "regalloc" in chosen) and (
        guidance.near_miss(result) or "register" in preferred
    ):
        for family, text in permuter.variants(
            source, base_mutations, limit=min(28, max(6, max_items // 6))
        ):
            if text not in seen:
                seen.add(text)
                outputs.append((family, text))
                if len(outputs) >= max_items:
                    return outputs

    # 4. Prior-weighted base C mutation families
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

    # 5. Full extended C-shape & floating-point mutation families
    if "systematic" in chosen or "random" in chosen:
        for family, text in _iter_c_shape_families(source, hoist_c89=True):
            if text in seen:
                continue
            seen.add(text)
            outputs.append((family, text))
            if len(outputs) >= max_items:
                break

    if "random" in chosen and outputs:
        if not preferred and len(outputs) > directed_count:
            tail = outputs[directed_count:]
            rng.shuffle(tail)
            outputs[directed_count:] = tail
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


def _arch_recovery_proposals(
    source: str,
    arch: str,
    target_fn: TargetFunction | None,
    ctx: TargetContext | None = None,
) -> list[tuple[str, str]]:
    """Compile-error recovery proposals for PowerPC, MIPS, and ARM (`m2c` seed repair + target rebase + load recovery)."""
    out: list[tuple[str, str]] = []
    seen = {source}
    fname = target_fn.name if target_fn is not None else "func"
    fva = target_fn.va if target_fn is not None else 0

    if arch in ("mips", "mips_elf"):
        from kintoun.search import mips_score, mips_seeds

        gp = ctx.gp if ctx else 0
        repaired = mips_seeds.repair_mips_seed(source, fname, fva, gp=gp)
        cands: list[tuple[str, str]] = [
            ("mips_seed_repair", repaired),
            ("mips_c89_hoist", mips_seeds.hoist_c89_declarations(mips_seeds.ensure_mips_prelude(source, use_c89_bitwise=True))),
        ]
        if target_fn is not None and target_fn.data:
            endian = (ctx.endian if ctx and ctx.endian else "little")
            t_words = mips_score.words_mips(target_fn.data, endian)
            rebased = mips_seeds.mips_raw_addr_rebase(repaired, t_words, gp=gp)
            if rebased:
                cands.insert(0, ("mips_seed_rebase", rebased))
        for tag, cand in cands:
            if cand not in seen:
                seen.add(cand)
                out.append((tag, cand))
    elif arch in ("arm", "arm_elf"):
        from kintoun.search import arm_score, arm_seeds, mips_seeds

        repaired = arm_seeds.repair_arm_seed(source, fname, fva)
        cands = [
            ("arm_seed_repair", repaired),
            ("arm_c89_hoist", mips_seeds.hoist_c89_declarations(arm_seeds.ensure_arm_prelude(source))),
        ]
        if target_fn is not None and target_fn.data:
            endian = (ctx.endian if ctx and ctx.endian else "little")
            t_items = arm_score.tokenize_arm(
                target_fn.data,
                intervals=list(target_fn.intervals) if target_fn.intervals else None,
                default_thumb=target_fn.is_thumb or bool(ctx and ctx.thumb),
                data_endian=endian,
                insn_endian="little" if endian == "little" else endian,
            )
            rebased = arm_seeds.arm_raw_pool_rebase(repaired, t_items)
            if rebased:
                cands.insert(0, ("arm_seed_rebase", rebased))
        for tag, cand in cands:
            if cand not in seen:
                seen.add(cand)
                out.append((tag, cand))
    else:
        from kintoun.search import mips_seeds, ppc_seeds

        r13 = ctx.sda_r13 if ctx else 0
        r2 = ctx.sda_r2 if ctx else 0
        repaired = ppc_seeds.repair_ppc_seed(source, fname, fva, sda_r13=r13, sda_r2=r2)
        cands = [
            ("ppc_seed_repair", repaired),
            ("ppc_c89_hoist", mips_seeds.hoist_c89_declarations(mips_seeds.ensure_mips_prelude(source, use_c89_bitwise=True))),
        ]
        if target_fn is not None and target_fn.data:
            t_words = ppc_score_mod.words_be(target_fn.data)
            rebased = ppc_seeds.ppc_raw_addr_rebase(repaired, t_words, sda_r13=r13, sda_r2=r2)
            if rebased:
                cands.insert(0, ("ppc_seed_rebase", rebased))
        for tag, cand in cands:
            if cand not in seen:
                seen.add(cand)
                out.append((tag, cand))

    for tag, cand in guidance.recovery_proposals(source):
        if cand not in seen:
            seen.add(cand)
            out.append((tag, cand))
    return out


def _generate_arch_proposals(
    source: str,
    strategies: list[str] | tuple[str, ...],
    rng: random.Random,
    max_items: int,
    result: dict[str, Any] | None,
    priors_path: Path | None,
    arch: str,
    ctx: TargetContext | None = None,
    target_fn: TargetFunction | None = None,
) -> list[tuple[str, str]]:
    """Dedicated score- & target-instruction-directed proposal routing for `mips` and `arm`."""
    if max_items <= 0:
        return []
    is_mips = arch in ("mips", "mips_elf")
    if is_mips:
        from kintoun.search import mips_guidance as arch_guidance
        from kintoun.search import mips_mutations as arch_mutations
        from kintoun.search import mips_permuter as arch_permuter
        from kintoun.search import mips_score
        from kintoun.search import mips_seeds

        endian = (ctx.endian if ctx and ctx.endian else "little")
        target_words = (
            mips_score.words_mips(target_fn.data, endian)
            if target_fn is not None and target_fn.data
            else (result or {}).get("_target_words")
        )
        ours_words = (result or {}).get("_ours_words")
        directed_iter = arch_mutations.directed_mips(
            source, result, target_words=target_words, ours_words=ours_words, ctx=ctx
        )
    else:
        from kintoun.search import arm_guidance as arch_guidance
        from kintoun.search import arm_mutations as arch_mutations
        from kintoun.search import arm_permuter as arch_permuter
        from kintoun.search import arm_score
        from kintoun.search import mips_seeds

        endian = (ctx.endian if ctx and ctx.endian else "little")
        target_items = (
            arm_score.tokenize_arm(
                target_fn.data,
                intervals=list(target_fn.intervals) if target_fn.intervals else None,
                default_thumb=target_fn.is_thumb or bool(ctx and ctx.thumb),
                data_endian=endian,
                insn_endian="little" if endian == "little" else endian,
            )
            if target_fn is not None and target_fn.data
            else (result or {}).get("_target_items")
        )
        ours_items = (result or {}).get("_ours_items")
        if ours_items is None and result and isinstance(result.get("_linked_hex"), str):
            raw_ivs = result.get("_ours_intervals")
            ivs = [tuple(x) for x in raw_ivs] if raw_ivs else None
            ours_items = arm_score.tokenize_arm(
                bytes.fromhex(result["_linked_hex"]),
                intervals=ivs,
                default_thumb=bool(result.get("_cand_thumb", target_fn.is_thumb if target_fn else False)),
                data_endian=endian,
                insn_endian="little" if endian == "little" else endian,
            )
        directed_iter = arch_mutations.directed_arm(
            source, result, target_items=target_items, ours_items=ours_items, ctx=ctx
        )

    chosen = set(strategies)
    families = set().union(*(GROUPS[key] for key in GROUPS if key in chosen))
    if "systematic" in chosen or "random" in chosen:
        families = {fn.__name__.removeprefix("m_") for fn in base_mutations.FAMILIES}

    outputs: list[tuple[str, str]] = []
    seen = {source}
    preferred = arch_guidance.priorities(result)

    # 1. Directed target-evidenced repairs, store/load/pool/delay-slot/regcopy moves, & seed idioms
    for family, text in directed_iter:
        if text not in seen:
            seen.add(text)
            outputs.append((family, text))
            if len(outputs) >= max_items:
                return outputs
    directed_count = len(outputs)

    # 2. Register-class-aware live-range permuter (`$v/$a/$t/$s/$f/HI-LO` or `r0-r7`/`r8-r12`)
    if ("register_focus" in chosen or "regalloc" in chosen) and (
        arch_guidance.near_miss(result) or "register" in preferred
    ):
        perm_limit = min(28, max(6, max_items // 6))
        if is_mips:
            perm_iter = arch_permuter.variants(
                source,
                base_mutations,
                limit=perm_limit,
                ours_words=ours_words,
                target_words=target_words,
            )
        else:
            perm_iter = arch_permuter.variants(
                source,
                base_mutations,
                limit=perm_limit,
                ours_items=ours_items,
                target_items=target_items,
            )
        for family, text in perm_iter:
            c89_text = mips_seeds.hoist_c89_declarations(text)
            if c89_text not in seen:
                seen.add(c89_text)
                outputs.append((family, c89_text))
                if len(outputs) >= max_items:
                    return outputs

    # 3. Prior-weighted base C mutation families
    priors = arch_guidance.load_priors(priors_path=priors_path)

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
                text = mips_seeds.hoist_c89_declarations(text)
                if text not in seen:
                    seen.add(text)
                    outputs.append((family, text))
                    if len(outputs) >= max_items:
                        break
            family_iters = remaining
    else:
        for it in family_iters:
            for family, text in it:
                text = mips_seeds.hoist_c89_declarations(text)
                if text in seen:
                    continue
                seen.add(text)
                outputs.append((family, text))
                if len(outputs) >= max_items:
                    return outputs

    # 4. Full cross-architecture C-shape & floating-point mutations
    if "systematic" in chosen or "random" in chosen:
        if target_fn is not None and ctx is not None:
            from kintoun.constants import constant_repair_variants

            for family, text in constant_repair_variants(source, target_fn, ctx):
                if text not in seen:
                    seen.add(text)
                    outputs.append((family, text))
        for family, text in _iter_c_shape_families(source, hoist_c89=True):
            if text in seen:
                continue
            seen.add(text)
            outputs.append((family, text))
            if len(outputs) >= max_items:
                break

    if "random" in chosen and outputs:
        if not preferred and len(outputs) > directed_count:
            tail = outputs[directed_count:]
            rng.shuffle(tail)
            outputs[directed_count:] = tail
        for _, first in outputs[: min(32, len(outputs))]:
            if len(outputs) >= max_items:
                break
            next_variants = list(base_mutations.mutations(first))
            if next_variants:
                family, text = rng.choice(next_variants)
                text = mips_seeds.hoist_c89_declarations(text)
                if text not in seen:
                    seen.add(text)
                    outputs.append(("random+" + family, text))

    return outputs


def rank_result(result: dict[str, Any]) -> tuple[int, int, int, int, int]:
    """Strict monotonic ranking tuple (lower is better; (0,0,0,0,0) is byte-exact match).

    Ranks compiled mismatches by:
      1. Higher `aligned_pct` (`-round(aligned_pct * 100)`), preventing regressions below the seed;
      2. Lower structural `search.total`;
      3. Lower `different_bytes` (so constant/offset repairs with equal normalized shape win immediately);
      4. Lower `instruction_mismatches`.
    """
    if result.get("verified"):
        return (0, 0, 0, 0, 0)
    sc = result.get("search") or {}
    if result.get("status") == "mismatch":
        return (
            1,
            -round(float(sc.get("aligned_pct", 0.0)) * 100),
            int(sc.get("total", 10**9)),
            int(result.get("different_bytes", 10**9)),
            int(result.get("instruction_mismatches", 10**9)),
        )
    if result.get("status") == "unresolved":
        return (
            2,
            -round(float(sc.get("aligned_pct", 0.0)) * 100),
            int(sc.get("total", 10**9)),
            10**9,
            10**9,
        )
    return (3, 10**9, 10**9, 10**9, 10**9)


def _beam_total_rank(result: dict[str, Any]) -> tuple[int, int, int, int]:
    """Secondary beam rank favoring lower structural `search.total` stepping stones."""
    if result.get("verified"):
        return (0, 0, 0, 0)
    sc = result.get("search") or {}
    if result.get("status") in ("mismatch", "unresolved"):
        return (
            1 if result.get("status") == "mismatch" else 2,
            int(sc.get("total", 10**9)),
            -round(float(sc.get("aligned_pct", 0.0)) * 100),
            int(result.get("different_bytes", 10**9)),
        )
    return (3, 10**9, 10**9, 10**9)


def _generate_multistep_batch(
    beam: list[dict[str, Any]],
    rng: random.Random,
    seen: set[bytes],
    forbid_asm: bool,
    batch_size: int = 48,
) -> list[tuple[str, str]]:
    """Generate 2-step and 3-step chained C mutations from top beam parents so deep budgets keep exploring."""
    from kintoun.search import mips_seeds

    if not beam:
        return []
    all_fams = list(base_mutations.FAMILIES) + list(_TEXT_C_SHAPE_FAMILIES)
    out: list[tuple[str, str]] = []
    attempts = 0
    max_attempts = batch_size * 4
    while len(out) < batch_size and attempts < max_attempts:
        attempts += 1
        parent = beam[0] if (len(beam) == 1 or rng.random() < 0.35) else rng.choice(beam)
        cur_src = parent["_source"]
        steps = 2 if rng.random() < 0.7 else 3
        tags: list[str] = []
        ok = True
        for _ in range(steps):
            chosen_fams = rng.sample(all_fams, k=min(4, len(all_fams)))
            cands: list[tuple[str, str]] = []
            for fn in chosen_fams:
                try:
                    for fam, txt in fn(cur_src):
                        cands.append((fam, txt))
                        if len(cands) >= 12:
                            break
                except Exception:
                    continue
                if len(cands) >= 12:
                    break
            if not cands:
                ok = False
                break
            fam, nxt = rng.choice(cands)
            cur_src = mips_seeds.hoist_c89_declarations(nxt)
            tags.append(fam)
        if not ok or not tags:
            continue
        digest = hashlib.sha256(cur_src.encode("utf-8")).digest()
        if digest in seen:
            continue
        if forbid_asm and real_c_violation(cur_src):
            continue
        seen.add(digest)
        out.append(("chain+" + "+".join(tags), cur_src))
    return out


def run_search(
    *,
    source: str,
    target_fn: TargetFunction,
    ctx: TargetContext,
    compiler: CompilerBackend,
    budget_s: float = 180.0,
    max_candidates: int = 2500,
    strategies: list[str] | tuple[str, ...] = ("systematic", "register_focus", "random"),
    workers: int = 0,
    cache_dir: Path | None = None,
    priors_path: Path | None = None,
    forbid_asm: bool = True,
    seed: int = 0,
    plateau: int = 0,
    governed: bool = False,
) -> dict[str, Any]:
    """Run a bounded parallel real-C mutation, seed-recovery, & register-permutation beam search."""
    if not 0.1 <= budget_s <= 86400:
        raise ValueError("budget_s must be between 0.1 and 86400 seconds")
    if not 1 <= max_candidates <= 1000000:
        raise ValueError("max_candidates must be between 1 and 1000000")
    unknown = set(strategies) - set(STRATEGIES)
    if unknown:
        raise ValueError("unknown strategies: " + ", ".join(sorted(unknown)))
    if forbid_asm and real_c_violation(source):
        raise ValueError(f"REAL C ONLY: input contains '{real_c_violation(source)}'")

    cache = ResultCache(cache_dir) if cache_dir else None
    gov = None
    deduper = None
    if governed and cache_dir is not None:
        from kintoun.governor import CompileDeduper, CompileGovernor

        gov = CompileGovernor(cache_dir, caller_id=f"search-{os.getpid()}")
        deduper = CompileDeduper(cache_dir)
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

    beam: list[dict[str, Any]] = []
    beam_digests: set[bytes] = set()
    expanded_beam: set[bytes] = set()
    empty_refills = 0

    def stop() -> bool:
        return time.monotonic() >= deadline

    def _offer_beam(res: dict[str, Any]) -> None:
        if res.get("status") not in ("mismatch", "unresolved"):
            return
        d = hashlib.sha256(res["_source"].encode("utf-8")).digest()
        if d in beam_digests:
            return
        beam_digests.add(d)
        beam.append(res)
        if len(beam) > 16:
            by_align = sorted(beam, key=rank_result)[:10]
            by_total = sorted(beam, key=_beam_total_rank)[:6]
            kept: list[dict[str, Any]] = []
            kept_d: set[bytes] = set()
            for item in by_align + by_total:
                kd = hashlib.sha256(item["_source"].encode("utf-8")).digest()
                if kd not in kept_d:
                    kept_d.add(kd)
                    kept.append(item)
            beam[:] = kept[:12]
            beam_digests.clear()
            beam_digests.update(kept_d)

    def prepend(items: list[tuple[str, str]]) -> int:
        fresh = []
        cap = max(max_candidates * 2, 512)
        for family, text in items:
            digest = hashlib.sha256(text.encode("utf-8")).digest()
            if digest not in seen and (not forbid_asm or not real_c_violation(text)):
                seen.add(digest)
                fresh.append((family, text))
                if len(fresh) + len(pending) >= cap:
                    break
        pending.extendleft(reversed(fresh))
        return len(fresh)

    def append_items(items: list[tuple[str, str]]) -> int:
        added = 0
        cap = max(max_candidates * 2, 512)
        for family, text in items:
            if len(pending) >= cap:
                break
            digest = hashlib.sha256(text.encode("utf-8")).digest()
            if digest not in seen and (not forbid_asm or not real_c_violation(text)):
                seen.add(digest)
                pending.append((family, text))
                added += 1
        return added

    def _refill_pending() -> None:
        nonlocal empty_refills
        if stop() or stats["evaluated"] + len(active) >= max_candidates:
            return
        # 1. Expand any unexplored parent in the beam first
        for cand_res in sorted(beam, key=_beam_total_rank):
            d = hashlib.sha256(cand_res["_source"].encode("utf-8")).digest()
            if d not in expanded_beam:
                expanded_beam.add(d)
                props = generate_proposals(
                    cand_res["_source"],
                    strategies,
                    rng,
                    min(400, max(160, max_candidates)),
                    result=cand_res,
                    priors_path=priors_path,
                    arch=ctx.arch,
                    ctx=ctx,
                    target_fn=target_fn,
                )
                if append_items(props) > 0:
                    empty_refills = 0
                    return
        # 2. Multi-step (2-3 step) chained exploration across top beam states
        if beam and empty_refills < 4:
            chained = _generate_multistep_batch(
                sorted(beam, key=rank_result)[:8],
                rng=rng,
                seen=seen,
                forbid_asm=forbid_asm,
                batch_size=min(64, max(16, max_workers * 8)),
            )
            if chained:
                pending.extend(chained)
                empty_refills = 0
                return
            empty_refills += 1

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
        extra_kw: dict[str, Any] = {}
        if ctx.arch not in ("mips", "mips_elf", "arm", "arm_elf"):
            extra_kw["_include_words"] = True
        if deduper is not None and gov is not None and cache is not None:
            with deduper.lock_key(key):
                cached2 = cache.get(key)
                if cached2 is not None:
                    cached2["cache_hit"] = True
                    cached2["_compiled"] = False
                    cached2["_family"] = family
                    cached2["_source"] = text
                    return cached2
                rem = max(0.2, deadline - time.monotonic())
                with gov.acquire(tier="search", timeout_s=min(30.0, rem)) as admitted:
                    if not admitted:
                        return None
                    res = verify_source(
                        text,
                        target_fn,
                        ctx,
                        compiler,
                        lines=12,
                        forbid_asm=forbid_asm,
                        partial_link=False,
                        placement_cache=placement_cache,
                        **extra_kw,
                    )
                res["cache_hit"] = False
                res["_compiled"] = True
                to_cache = {k: v for k, v in res.items() if not k.startswith("_")}
                cache.put(key, to_cache)
                res["_family"] = family
                res["_source"] = text
                return res
        res = verify_source(
            text,
            target_fn,
            ctx,
            compiler,
            lines=12,
            forbid_asm=forbid_asm,
            partial_link=False,
            placement_cache=placement_cache,
            **extra_kw,
        )
        res["cache_hit"] = False
        res["_compiled"] = True
        if cache is not None:
            # Strip internal `_` keys before caching to SQLite JSON
            to_cache = {k: v for k, v in res.items() if not k.startswith("_")}
            cache.put(key, to_cache)
        res["_family"] = family
        res["_source"] = text
        return res

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        while pending or active:
            if len(pending) < max(8, max_workers * 3) and best is not None and not best.get("verified"):
                _refill_pending()
            while pending and len(active) < max_workers and stats["evaluated"] + len(active) < max_candidates:
                if stop():
                    stats["stopped"] = "budget expired"
                    break
                family, text = pending.popleft()
                if family in failed_families:
                    continue
                active[pool.submit(evaluate, family, text)] = family
            if not active:
                if len(pending) == 0 and best is not None and not best.get("verified") and not stop() and stats["evaluated"] < max_candidates:
                    _refill_pending()
                    if pending:
                        continue
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
                    if family_attempts[family] >= 12 and family_errors[family] / family_attempts[family] >= 0.85:
                        failed_families.add(family)
                if family == "input":
                    input_result = result
                    if result.get("status") in ("mismatch", "unresolved"):
                        src_d = hashlib.sha256(source.encode("utf-8")).digest()
                        expanded_beam.add(src_d)
                        prepend(
                            generate_proposals(
                                source,
                                strategies,
                                rng,
                                min(800, max(200, max_candidates * 2)),
                                result=result,
                                priors_path=priors_path,
                                arch=ctx.arch,
                                ctx=ctx,
                                target_fn=target_fn,
                            )
                        )
                    elif result.get("status") == "compile_error":
                        prepend(_arch_recovery_proposals(source, ctx.arch, target_fn, ctx=ctx))

                _offer_beam(result)

                if best is None or rank_result(result) < rank_result(best):
                    was_uncompiled = best is not None and best.get("status") == "compile_error"
                    if best is not None:
                        stats["improvements"] += 1
                    best = result
                    no_improvement = 0
                    if result.get("verified"):
                        stats["stopped"] = "verified match"
                        pending.clear()
                    elif (
                        family != "input"
                        and result.get("status") in ("mismatch", "unresolved")
                        and not stop()
                    ):
                        src_d = hashlib.sha256(result["_source"].encode("utf-8")).digest()
                        expanded_beam.add(src_d)
                        prop_cap = min(800, max(240, max_candidates * 2)) if was_uncompiled else 240
                        prepend(
                            generate_proposals(
                                result["_source"],
                                strategies,
                                rng,
                                prop_cap,
                                result=result,
                                priors_path=priors_path,
                                arch=ctx.arch,
                                ctx=ctx,
                                target_fn=target_fn,
                            )
                        )
                else:
                    no_improvement += 1
                if plateau > 0 and guidance.near_miss(best) and no_improvement >= plateau:
                    stats["stopped"] = f"near-miss plateau ({plateau} candidates without improvement)"
                    pending.clear()
            if stop():
                stats["stopped"] = "budget expired"
                pending.clear()

    if stats["stopped"] is None:
        if stats["evaluated"] >= max_candidates:
            stats["stopped"] = f"max_candidates ({max_candidates}) reached"
        elif empty_refills >= 4:
            stats["stopped"] = "search space exhausted"

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
