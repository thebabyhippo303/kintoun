"""ARM/Thumb score-guided search priorities and one-site C repair proposals."""
from __future__ import annotations

from pathlib import Path
from typing import Any, Iterator

from kintoun.search import guidance as ppc_guidance
from kintoun.search.mips_guidance import _struct_field_offset_edits

REGISTER = (
    "register", "decl_order", "temp_merge", "inline_temp", "var_split",
    "split_load", "hoist_cse", "swap_stmts", "alias_make", "commute",
)
BRANCH = ("if_invert", "cond_rewrite", "loop_shape", "return_style", "bool_phi", "bool_assign")
TYPES = (
    "local_type", "param_type", "field_type", "cast_strip", "callee_proto",
    "float_expr", "extern_const", "narrow_return",
)
ORDER = ("swap_stmts", "ordered_stores", "decl_order", "inline_temp", "split_load", "commute")


def near_miss(result: dict[str, Any] | None) -> bool:
    return ppc_guidance.near_miss(result)


def load_priors(priors_path: Path | None = None, metrics_path: Path | None = None) -> dict[str, float]:
    return ppc_guidance.load_priors(priors_path=priors_path, metrics_path=metrics_path)


def priorities(result: dict[str, Any] | None) -> tuple[str, ...]:
    """Map ARM/Thumb score hints and repair categories to C mutation family priorities."""
    hints = " ".join((result or {}).get("search", {}).get("hints", [])).lower()
    rep_cats = {r.get("category") for r in (result or {}).get("repairs", [])}
    preferred: list[str] = []

    if (
        "register allocation" in hints
        or "saved regs" in hints
        or "high-register" in hints
        or "thumb_width" in rep_cats
    ):
        preferred.extend(REGISTER)
    if "branch polarity" in hints:
        preferred.extend(BRANCH)
    if "evaluation order" in hints or "stack frame" in hints or "literal pool" in hints:
        preferred.extend(ORDER)
    if any(
        w in hints
        for w in (
            "signedness",
            "field width",
            "narrows via",
            "interworking",
        )
    ) or "interworking" in rep_cats:
        preferred.extend(TYPES + ("arith",))
    if near_miss(result) and not preferred:
        preferred.extend(REGISTER + ORDER + BRANCH)
    return tuple(dict.fromkeys(preferred))


def repair_proposals(source: str, result: dict[str, Any] | None) -> Iterator[tuple[str, str]]:
    """Yield targeted one-site C edits from ARM/Thumb repair hypotheses (including literal pools)."""
    seen: set[str] = {source}
    for repair in (result or {}).get("repairs", [])[:16]:
        category = repair.get("category", "repair")
        edit = repair.get("suggested_edit") or {}
        old, new = edit.get("old"), edit.get("new")
        if isinstance(old, str) and old and isinstance(new, str) and old != new and source.count(old) == 1:
            cand = source.replace(old, new, 1)
            if cand not in seen:
                seen.add(cand)
                yield "target_" + category, cand
        if category in ("field_offset", "offset"):
            try:
                before = int(str(repair["ours"]), 0)
                after = int(str(repair["target"]), 0)
            except (KeyError, TypeError, ValueError):
                continue
            for cand in _struct_field_offset_edits(source, before, after):
                if cand not in seen:
                    seen.add(cand)
                    yield "target_offset", cand
