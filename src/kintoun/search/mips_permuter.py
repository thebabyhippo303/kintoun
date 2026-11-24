"""Register-class-aware MIPS live-range permuter ($v, $a, $t, $s, $f, and HI/LO)."""
from __future__ import annotations

from itertools import islice
from pathlib import Path
import re
from typing import Any, Iterator

from kintoun.search import permuter as ppc_permuter

# MIPS register classes by GPR number (0..31)
_CLASS_V = {2, 3}                       # $v0-$v1: return & expression evaluation
_CLASS_A = {4, 5, 6, 7}                 # $a0-$a3: incoming / outgoing arguments
_CLASS_T = {8, 9, 10, 11, 12, 13, 14, 15, 24, 25}  # $t0-$t9: caller-saved temporaries
_CLASS_S = {16, 17, 18, 19, 20, 21, 22, 23, 30}    # $s0-$s7, $fp($s8): callee-saved

MIPS_FAMILIES: tuple[str, ...] = (
    "m_decl_order",
    "m_register",
    "m_var_split",
    "m_temp_merge",
    "m_inline_temp",
    "m_split_load",
    "m_hoist_cse",
    "m_alias_make",
    "m_commute",
    "m_return_style",
    "m_if_invert",
    "m_loop_shape",
    "m_cast_strip",
)

_DECL_RE = re.compile(
    r"^([ \t]{2,8})((?:register\s+)?(?:unsigned\s+|signed\s+)?(?:s32|u32|s16|u16|s8|u8|s64|u64|int|short|char|long|float|double|f32|f64|\w+\s*\*+))\s*(\w+);$"
)
_FUNC_HEAD_RE = re.compile(r"^([^\n;#=]*?\b(\w+)\s*\(([^()]*)\)\s*\{)\s*$", re.M)
_DIVMOD_PAIR_RE = re.compile(
    r"^([ \t]+)(\w+)\s*=\s*([^;/%\n]+?)\s*([/%])\s*([^;/%\n]+?);\n"
    r"\1(\w+)\s*=\s*\3\s*([/%])\s*\5;",
    re.M,
)


def classify_mips_reg_diffs(ours_words: list[int], target_words: list[int]) -> set[str]:
    """Identify which MIPS register classes ($v, $a, $t, $s, $f, hi_lo) differ across aligned words."""
    classes: set[str] = set()
    for wa, wb in zip(ours_words, target_words):
        if wa == wb:
            continue
        op_a, op_b = (wa >> 26) & 0x3F, (wb >> 26) & 0x3F
        if op_a != op_b:
            if op_a == 0 and (wa & 0x3F) in (16, 18, 24, 25, 26, 27) or op_b == 0 and (wb & 0x3F) in (16, 18, 24, 25, 26, 27):
                classes.add("hi_lo")
            continue
        if op_a == 17 or op_a in (49, 53, 57, 61):
            classes.add("f")
            continue
        if op_a == 0 and ((wa & 0x3F) in (16, 17, 18, 19, 24, 25, 26, 27)):
            classes.add("hi_lo")
        regs_changed: set[int] = set()
        for shift in (21, 16, 11):
            if shift == 11 and op_a != 0 and op_a != 28:
                continue
            ra, rb = (wa >> shift) & 0x1F, (wb >> shift) & 0x1F
            if ra != rb:
                regs_changed.update((ra, rb))
        if regs_changed & _CLASS_V:
            classes.add("v")
        if regs_changed & _CLASS_A:
            classes.add("a")
        if regs_changed & _CLASS_T:
            classes.add("t")
        if regs_changed & _CLASS_S:
            classes.add("s")
    return classes


def _arg_local_copies(source: str, limit: int = 4) -> Iterator[tuple[str, str]]:
    """Copy an incoming `$a0-$a3` parameter to a local variable to change `$a` vs `$s`/`$t` allocation."""
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
        alias = f"{pname}_loc"
        if alias in source:
            continue
        new_body = re.sub(r"\b" + re.escape(pname) + r"\b", alias, body)
        decl_sep = "" if ptype.endswith("*") else " "
        injected = f"\n    {ptype}{decl_sep}{alias} = {pname};" + new_body
        yield "mips_arg_copy", source[:body_start] + injected
        emitted += 1
        if emitted >= limit:
            return


def _hilo_divmod_variants(source: str) -> Iterator[tuple[str, str]]:
    """Swap adjacent `/` and `%` assignments on the same operands to flip `mflo`/`mfhi` order."""
    for m in _DIVMOD_PAIR_RE.finditer(source):
        op1, op2 = m.group(4), m.group(7)
        if {op1, op2} != {"/", "%"}:
            continue
        indent, lhs1, a, b, lhs2 = m.group(1), m.group(2), m.group(3), m.group(5), m.group(6)
        if lhs1 == lhs2 or re.search(r"\b" + re.escape(lhs1) + r"\b", f"{a} {b}"):
            continue
        swapped = f"{indent}{lhs2} = {a} {op2} {b};\n{indent}{lhs1} = {a} {op1} {b};"
        yield "mips_hilo_order", source[: m.start()] + swapped + source[m.end() :]


def _decl_rotations_mips(source: str, limit: int = 6) -> Iterator[tuple[str, str]]:
    lines = source.split("\n")
    start = next((i + 1 for i, line in enumerate(lines) if line.rstrip().endswith("{") and "(" in line), 0)
    idx = [i for i in range(start, min(len(lines), start + 48)) if _DECL_RE.match(lines[i])]
    if len(idx) < 2:
        return
    emitted = 0
    # Adjacent swaps first (surgical $t/$s pair flips in GCC), then rotations
    for k in range(len(idx) - 1):
        if emitted >= limit:
            return
        out = list(lines)
        out[idx[k]], out[idx[k + 1]] = out[idx[k + 1]], out[idx[k]]
        cand = "\n".join(out)
        if cand != source:
            emitted += 1
            yield "mips_decl_swap", cand
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
            yield "mips_decl_rot", cand


def variants(
    source: str,
    mut_mod: Any,
    limit: int = 24,
    ours_words: list[int] | None = None,
    target_words: list[int] | None = None,
    metrics_path: Path | None = None,
) -> Iterator[tuple[str, str]]:
    """Yield up to `limit` MIPS register-class-aware real-C live-range variants."""
    if limit <= 0:
        return
    seen = {source}
    emitted = 0
    classes = (
        classify_mips_reg_diffs(ours_words, target_words)
        if ours_words and target_words
        else {"v", "a", "t", "s"}
    )

    if "hi_lo" in classes or "/" in source or "%" in source:
        for fam, text in _hilo_divmod_variants(source):
            if text not in seen:
                seen.add(text)
                emitted += 1
                yield fam, text
                if emitted >= limit:
                    return

    if "a" in classes or "s" in classes:
        for fam, text in _arg_local_copies(source, limit=min(3, limit - emitted)):
            if text not in seen:
                seen.add(text)
                emitted += 1
                yield fam, text
                if emitted >= limit:
                    return

    for fam, text in _decl_rotations_mips(source, limit=min(6, limit - emitted)):
        if text not in seen:
            seen.add(text)
            emitted += 1
            yield fam, text
            if emitted >= limit:
                return

    # Order mutation families according to active MIPS register-class diffs
    priority_fams: list[str] = []
    if "v" in classes:
        priority_fams.extend(("m_return_style", "m_inline_temp", "m_var_split"))
    if "s" in classes:
        priority_fams.extend(("m_hoist_cse", "m_temp_merge", "m_split_load", "m_register"))
    if "t" in classes:
        priority_fams.extend(("m_var_split", "m_temp_merge", "m_commute", "m_alias_make"))
    if "f" in classes:
        priority_fams.extend(("m_float_expr", "m_var_split", "m_inline_temp"))
    for f in MIPS_FAMILIES:
        if f not in priority_fams:
            priority_fams.append(f)

    first_pass: dict[str, list[str]] = {}
    for name in priority_fams:
        fn = getattr(mut_mod, name, None)
        if fn is None:
            continue
        tag = "mips_reg_" + name.removeprefix("m_")
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
        tag = f"mips_reg_{first_name.removeprefix('m_')}+{second_name.removeprefix('m_')}"
        for base_text in first_pass[first_name][:2]:
            for _, text in islice(second_fn(base_text), 2):
                if text not in seen:
                    seen.add(text)
                    emitted += 1
                    yield tag, text
                    if emitted >= limit:
                        return
