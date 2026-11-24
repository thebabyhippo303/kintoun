"""MIPS score-guided search priorities and one-site C repair proposals."""
from __future__ import annotations

from pathlib import Path
import re
from typing import Any, Iterator

from kintoun.search import guidance as ppc_guidance

REGISTER = (
    "register", "decl_order", "temp_merge", "inline_temp", "var_split",
    "split_load", "hoist_cse", "swap_stmts", "alias_make", "commute",
)
DELAY_AND_BRANCH = (
    "if_invert", "cond_rewrite", "swap_stmts", "return_style", "loop_shape", "bool_phi", "bool_assign",
)
TYPES = (
    "local_type", "param_type", "field_type", "cast_strip", "callee_proto",
    "float_expr", "fp_prototype", "extern_const", "narrow_return",
)
ORDER = ("swap_stmts", "ordered_stores", "decl_order", "inline_temp", "split_load", "commute")

_PTR_ELEM_SIZE = {
    "s8": 1, "u8": 1, "char": 1, "unsigned char": 1, "signed char": 1,
    "s16": 2, "u16": 2, "short": 2, "unsigned short": 2,
    "s32": 4, "u32": 4, "int": 4, "unsigned int": 4, "long": 4, "float": 4, "f32": 4,
    "s64": 8, "u64": 8, "long long": 8, "double": 8, "f64": 8,
}


def near_miss(result: dict[str, Any] | None) -> bool:
    return ppc_guidance.near_miss(result)


def load_priors(priors_path: Path | None = None, metrics_path: Path | None = None) -> dict[str, float]:
    return ppc_guidance.load_priors(priors_path=priors_path, metrics_path=metrics_path)


def priorities(result: dict[str, Any] | None) -> tuple[str, ...]:
    """Map MIPS score hints and repair categories to C mutation family priorities."""
    hints = " ".join((result or {}).get("search", {}).get("hints", [])).lower()
    rep_cats = {r.get("category") for r in (result or {}).get("repairs", [])}
    preferred: list[str] = []

    if "delay-slot" in hints or "branch polarity" in hints or "delay_slot" in rep_cats:
        preferred.extend(DELAY_AND_BRANCH)
    if "register allocation" in hints or "callee-saved" in hints or "extra `move`" in hints:
        preferred.extend(REGISTER)
    if "evaluation order" in hints or "stack layout" in hints:
        preferred.extend(ORDER)
    if any(
        w in hints
        for w in (
            "signedness",
            "field width",
            "float vs double",
            "sign-extends",
            "zero-extends",
            "promotes float",
            "multiply vs shift",
        )
    ):
        preferred.extend(TYPES + ("arith",))
    if "global addressing" in hints or "gp_small_data" in rep_cats:
        preferred.extend(("global_section", "extern_const", "field_type", "cast_strip"))
    if "conditional move" in hints:
        preferred.extend(("bool_phi", "bool_assign", "if_invert", "return_style"))
    if near_miss(result) and not preferred:
        preferred.extend(REGISTER + ORDER + DELAY_AND_BRANCH)
    return tuple(dict.fromkeys(preferred))


def _pointer_elem_sizes(source: str) -> dict[str, int]:
    """Extract pointer parameter/local variable element sizes in bytes."""
    sizes: dict[str, int] = {}
    for m in re.finditer(
        r"\b((?:unsigned\s+|signed\s+)?(?:char|short|int|long(?:\s+long)?|float|double|[us](?:8|16|32|64)|f32|f64))\s*\*\s*(\w+)\b",
        source,
    ):
        tname = re.sub(r"\s+", " ", m.group(1).strip())
        if tname in _PTR_ELEM_SIZE:
            sizes[m.group(2)] = _PTR_ELEM_SIZE[tname]
    return sizes


def _struct_field_offset_edits(source: str, before: int, after: int) -> Iterator[str]:
    """Propose field/offset edits across `M2C_FIELD`, byte-offset casts, array indices, and struct members."""
    # 1. M2C_FIELD(base, type, off)
    for match in re.finditer(r"M2C_FIELD\([^,\n]+,\s*[^,\n]+,\s*(0x[\da-fA-F]+|-?\d+)\s*\)", source):
        off_m = re.search(r"(0x[\da-fA-F]+|-?\d+)\s*\)$", match.group(0))
        if not off_m:
            continue
        tok = off_m.group(1)
        if int(tok, 0) != before:
            continue
        s = match.start() + off_m.start(1)
        e = match.start() + off_m.end(1)
        yield source[:s] + (hex(after) if tok.lower().startswith("0x") and after >= 0 else str(after)) + source[e:]

    # 2. Byte-pointer offset casts: `*(T *)((u8 *)p + 0x10)` or `((char *)p + 16)`
    for match in re.finditer(
        r"(\(\s*(?:const\s+)?(?:u8|s8|unsigned\s+char|char)\s*\*\s*\)\s*\w+\s*\+\s*)(0x[\da-fA-F]+|\d+)\b",
        source,
    ):
        tok = match.group(2)
        if int(tok, 0) != before or after < 0:
            continue
        repl = hex(after) if tok.lower().startswith("0x") else str(after)
        yield source[: match.start(2)] + repl + source[match.end(2) :]

    # 3. Typed pointer indexing: `p[idx]` where `idx * elem_size == before` and `after % elem_size == 0`
    ptr_sizes = _pointer_elem_sizes(source)
    for pname, esz in ptr_sizes.items():
        if before < 0 or after < 0 or before % esz != 0 or after % esz != 0:
            continue
        old_idx, new_idx = before // esz, after // esz
        for match in re.finditer(r"\b" + re.escape(pname) + r"\s*\[\s*(0x[\da-fA-F]+|\d+)\s*\]", source):
            tok = match.group(1)
            if int(tok, 0) != old_idx:
                continue
            repl = hex(new_idx) if tok.lower().startswith("0x") else str(new_idx)
            yield source[: match.start(1)] + repl + source[match.end(1) :]

    # 4. Struct definition member swap/select when a `struct { ... }` is defined in `source` and `p->member` is used
    for sm in re.finditer(r"struct\s+\w*\s*\{([^{}]+)\}", source):
        body = sm.group(1)
        cur_off = 0
        offset_to_field: dict[int, str] = {}
        ok = True
        for fm in re.finditer(r"([A-Za-z_][\w\s]*?)\s+(\w+)\s*(?:\[(\d+)\])?\s*;", body):
            ft = re.sub(r"\s+", " ", fm.group(1).strip())
            fname = fm.group(2)
            arr_n = int(fm.group(3)) if fm.group(3) else 1
            esz = _PTR_ELEM_SIZE.get(ft)
            if esz is None:
                ok = False
                break
            if cur_off % esz:
                cur_off += esz - (cur_off % esz)
            offset_to_field[cur_off] = fname
            cur_off += esz * arr_n
        if ok and before in offset_to_field and after in offset_to_field:
            old_f, new_f = offset_to_field[before], offset_to_field[after]
            for um in re.finditer(r"(->|\.)\s*\b" + re.escape(old_f) + r"\b", source):
                s = um.end(1)
                # Replace just the field identifier after `->` or `.`
                id_m = re.search(r"\b" + re.escape(old_f) + r"\b", source[s:])
                if id_m:
                    yield source[: s + id_m.start()] + new_f + source[s + id_m.end() :]


def repair_proposals(source: str, result: dict[str, Any] | None) -> Iterator[tuple[str, str]]:
    """Yield targeted one-site C edits from MIPS repair hypotheses."""
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
