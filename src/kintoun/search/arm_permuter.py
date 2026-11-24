"""Register-class-aware ARM/Thumb live-range permuter (`r0-r12` and Thumb low registers `r0-r7`)."""
from __future__ import annotations

from itertools import islice
from pathlib import Path
import re
from typing import Any, Iterator

from kintoun.search import permuter as ppc_permuter
from kintoun.search.arm_score import ArmItem

ARM_FAMILIES: tuple[str, ...] = (
    "m_register",
    "m_decl_order",
    "m_var_split",
    "m_temp_merge",
    "m_inline_temp",
    "m_split_load",
    "m_alias_make",
    "m_commute",
    "m_hoist_cse",
    "m_if_invert",
    "m_loop_shape",
    "m_return_style",
    "m_cast_strip",
)

_DECL_RE = re.compile(
    r"^([ \t]{2,8})(register\s+)?((?:unsigned\s+|signed\s+)?(?:s32|u32|s16|u16|s8|u8|int|short|char|long|float|double|f32|f64|bool|\w+\s*\*+))\s*(\w+);$"
)
_FUNC_HEAD_RE = re.compile(r"^([^\n;#=]*?\b(\w+)\s*\(([^()]*)\)\s*\{)\s*$", re.M)


def classify_arm_reg_diffs(ours: list[ArmItem], target: list[ArmItem]) -> set[str]:
    """Identify whether aligned differences involve Thumb low regs (`r0-r7`), high regs (`r8-r12`), or A32 regs."""
    classes: set[str] = set()
    for ia, ib in zip(ours, target):
        if ia.mode != ib.mode or ia.raw != ib.raw or ia.hw2 != ib.hw2:
            if ia.mode == "t16" or ib.mode == "t16":
                classes.add("thumb_lo")
                if ia.mode == "t16" and ((ia.raw >> 10) == 0b010001):
                    classes.add("thumb_hi")
                if ib.mode == "t16" and ((ib.raw >> 10) == 0b010001):
                    classes.add("thumb_hi")
            elif ia.mode == "t32" or ib.mode == "t32":
                classes.add("thumb_lo")
                classes.add("thumb_hi")
            elif ia.mode == "a" or ib.mode == "a":
                classes.add("a32")
    return classes or {"thumb_lo", "a32"}


def _thumb_register_keyword_variants(source: str, limit: int = 8) -> Iterator[tuple[str, str]]:
    """Toggle `register` on individual and paired locals (controls `r4-r7` assignment in `agbcc`/Thumb GCC)."""
    lines = source.split("\n")
    start = next((i + 1 for i, line in enumerate(lines) if line.rstrip().endswith("{") and "(" in line), 0)
    decls: list[tuple[int, re.Match[str]]] = []
    for i in range(start, min(len(lines), start + 48)):
        m = _DECL_RE.match(lines[i])
        if m:
            decls.append((i, m))
    if not decls:
        return

    emitted = 0
    # 1. Single-variable `register` toggle
    for idx, m in decls:
        if emitted >= limit:
            return
        indent, reg_kw, typ, name = m.groups()
        sep = "" if typ.endswith("*") else " "
        toggled = f"{indent}{'' if reg_kw else 'register '}{typ}{sep}{name};"
        out = list(lines)
        out[idx] = toggled
        yield "arm_reg_kw", "\n".join(out)
        emitted += 1

    # 2. Mark first two locals `register` + swap their order (`r4` <-> `r5` in `agbcc`)
    if len(decls) >= 2 and emitted < limit:
        (i1, m1), (i2, m2) = decls[0], decls[1]
        ind1, _, t1, n1 = m1.groups()
        ind2, _, t2, n2 = m2.groups()
        s1 = "" if t1.endswith("*") else " "
        s2 = "" if t2.endswith("*") else " "
        out = list(lines)
        out[i1] = f"{ind1}register {t2}{s2}{n2};"
        out[i2] = f"{ind2}register {t1}{s1}{n1};"
        cand = "\n".join(out)
        if cand != source:
            yield "arm_reg_pair_swap", cand


def _decl_permutations_arm(source: str, limit: int = 6) -> Iterator[tuple[str, str]]:
    """Adjacent declaration swaps and cyclic rotations for `r4-r7` / `r4-r11` allocation."""
    lines = source.split("\n")
    start = next((i + 1 for i, line in enumerate(lines) if line.rstrip().endswith("{") and "(" in line), 0)
    idx = [i for i in range(start, min(len(lines), start + 48)) if _DECL_RE.match(lines[i])]
    if len(idx) < 2:
        return
    emitted = 0
    for k in range(len(idx) - 1):
        if emitted >= limit:
            return
        out = list(lines)
        out[idx[k]], out[idx[k + 1]] = out[idx[k + 1]], out[idx[k]]
        cand = "\n".join(out)
        if cand != source:
            emitted += 1
            yield "arm_decl_swap", cand
    for shift in range(1, min(len(idx), 4)):
        if emitted >= limit:
            return
        out = list(lines)
        vals = [lines[i] for i in idx]
        rotated = vals[shift:] + vals[:shift]
        for pos, val in zip(idx, rotated):
            out[pos] = val
        cand = "\n".join(out)
        if cand != source:
            emitted += 1
            yield "arm_decl_rot", cand


def _param_lowreg_copy(source: str, limit: int = 3) -> Iterator[tuple[str, str]]:
    """Copy an incoming `r0-r3` parameter into a local variable to shift `r0-r3` vs `r4-r7` liveness."""
    m = _FUNC_HEAD_RE.search(source)
    if not m:
        return
    params_raw = [p.strip() for p in m.group(3).split(",") if p.strip() and p.strip() != "void"]
    body_start = m.end()
    body = source[body_start:]
    emitted = 0
    for p in params_raw[:4]:
        pm = re.match(r"^(.+?[\s*])([A-Za-z_]\w*)$", p)
        if not pm:
            continue
        ptype, pname = pm.group(1).strip(), pm.group(2)
        if len(re.findall(r"\b" + re.escape(pname) + r"\b", body)) < 2:
            continue
        alias = f"{pname}_r"
        if alias in source:
            continue
        new_body = re.sub(r"\b" + re.escape(pname) + r"\b", alias, body)
        sep = "" if ptype.endswith("*") else " "
        yield "arm_param_copy", source[:body_start] + f"\n    {ptype}{sep}{alias} = {pname};" + new_body
        emitted += 1
        if emitted >= limit:
            return


def variants(
    source: str,
    mut_mod: Any,
    limit: int = 24,
    ours_items: list[ArmItem] | None = None,
    target_items: list[ArmItem] | None = None,
    metrics_path: Path | None = None,
) -> Iterator[tuple[str, str]]:
    """Yield up to `limit` ARM/Thumb register-class-aware real-C live-range variants."""
    if limit <= 0:
        return
    seen = {source}
    emitted = 0
    classes = classify_arm_reg_diffs(ours_items, target_items) if (ours_items and target_items) else {"thumb_lo", "a32"}

    # Thumb low-register (`r0-r7`) declaration order & `register` keyword permutations first
    if "thumb_lo" in classes or "thumb_hi" in classes:
        for fam, text in _decl_permutations_arm(source, limit=min(5, limit - emitted)):
            if text not in seen:
                seen.add(text)
                emitted += 1
                yield fam, text
                if emitted >= limit:
                    return
        for fam, text in _thumb_register_keyword_variants(source, limit=min(5, limit - emitted)):
            if text not in seen:
                seen.add(text)
                emitted += 1
                yield fam, text
                if emitted >= limit:
                    return
    else:
        for fam, text in _decl_permutations_arm(source, limit=min(4, limit - emitted)):
            if text not in seen:
                seen.add(text)
                emitted += 1
                yield fam, text
                if emitted >= limit:
                    return

    for fam, text in _param_lowreg_copy(source, limit=min(2, limit - emitted)):
        if text not in seen:
            seen.add(text)
            emitted += 1
            yield fam, text
            if emitted >= limit:
                return

    # Prioritize temp-merging/inlining when Thumb high registers (`r8-r12`) are spilling
    ordered_fams = list(ARM_FAMILIES)
    if "thumb_hi" in classes:
        ordered_fams = ["m_temp_merge", "m_inline_temp", "m_register", "m_decl_order"] + [
            f for f in ARM_FAMILIES if f not in ("m_temp_merge", "m_inline_temp", "m_register", "m_decl_order")
        ]

    first_pass: dict[str, list[str]] = {}
    for name in ordered_fams:
        fn = getattr(mut_mod, name, None)
        if fn is None:
            continue
        tag = "arm_reg_" + name.removeprefix("m_")
        bucket: list[str] = []
        for _, text in islice(fn(source), 5):
            if text not in seen:
                seen.add(text)
                bucket.append(text)
                emitted += 1
                yield tag, text
                if emitted >= limit:
                    return
        if bucket:
            first_pass[name] = bucket

    for first_name, second_name in ppc_permuter.COMPOSE:
        second_fn = getattr(mut_mod, second_name, None)
        if second_fn is None or first_name not in first_pass:
            continue
        tag = f"arm_reg_{first_name.removeprefix('m_')}+{second_name.removeprefix('m_')}"
        for base_text in first_pass[first_name][:2]:
            for _, text in islice(second_fn(base_text), 2):
                if text not in seen:
                    seen.add(text)
                    emitted += 1
                    yield tag, text
                    if emitted >= limit:
                        return
