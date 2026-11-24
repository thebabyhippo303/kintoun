"""Dedicated MIPS target-instruction-guided C mutations and score-directed search orchestrator.

Decodes relocated MIPS instruction words (`ee-gcc`, `mwccps2`, `psp-gcc`, `mwccpsp`, `pspsnc`, `mips-gcc`)
to drive high-precision C rewrites on both `m2c` (`M2C_FIELD`) and standard human C (`p->field`, `arr[i]`):
- `m_mips_store_tgtorder` / `m_mips_load_tgtorder`: target memory-offset inversion swaps;
- `m_mips_regcopy` / `m_mips_fregcopy`: GPR `move` and COP1 `mov.s`/`mov.d` count-guided temp copy insertion/removal;
- `m_mips_globalcache`: `$gp` and `lui` reload count-guided global caching;
- `m_mips_ptrstep_rescale`: `addiu`/`daddiu` immediate-guided pointer stride rescaling;
- `m_mips_delayslot_sched`: branch/jump delay-slot scheduling, tail-hoist/sink, return-style, and loop increment moves;
- `m_mips_lit_order`: `li` (`addiu`/`ori $zero`) vs `lui` constant materialization ordering;
- `m_mips_r5900_madd_fma`: R5900/Allegrex 3-op `mult`/`madd`, COP1 `madd.s`/`msub.s`/`neg.s`, and `max`/`min` shapes;
- `m_mips_frame_pad`: `$sp` prologue frame-delta stack padding/resizing;
- Universal standard-C struct/array/cast/commute/control mutations (`m_c_*`) + `directed_mips()` orchestrator.
"""
from __future__ import annotations

import re
from typing import Any, Iterator

from kintoun.search import mips_guidance, mips_seeds
from kintoun.search.mutations_mem import m_alias_sink, m_fmem_hop, m_fmem_order, m_loadhoist_order
from kintoun.search.mutations_order_reg import (
    m_cho_midfirst,
    m_constarg_hoist,
    m_disjoint_order,
    m_init_order,
    m_spillsched_order,
)
from kintoun.search.mutations_order_stmt import (
    m_addr_order,
    m_calladdr_order,
    m_callmove_order,
    m_callpure_order,
    m_cholit_order,
    m_decl_order,
    m_member_order,
    m_mixed_order,
    m_plainload_order,
    m_samecopy_order,
    m_sameload_order,
    m_samemem_order,
)
from kintoun.search.mutations_switch import m_case_order, m_caseswap_order, m_switch_lower

_MIPS_LOAD_OPS = frozenset((30, 32, 33, 34, 35, 36, 37, 38, 39, 48, 49, 53, 55))
_MIPS_STORE_OPS = frozenset((31, 40, 41, 42, 43, 44, 45, 46, 56, 57, 61, 63))

_IDENT_RE = re.compile(r"[A-Za-z_]\w*")
_CALL_RE = re.compile(r"\b(?!(?:if|for|while|switch|return|sizeof|__typeof__|typeof|M2C_FIELD|M2C_BITWISE)\b)[A-Za-z_]\w*\s*\(")
_C_KEYWORDS = frozenset(
    "if else for while do switch case default break continue return goto sizeof typeof __typeof__ "
    "volatile const static extern register auto typedef struct union enum "
    "void char short int long float double signed unsigned s8 u8 s16 u16 s32 u32 s64 u64 f32 f64 M2C_UNK".split()
)
_ELEM_SIZES = {
    "char": 1, "signed char": 1, "unsigned char": 1, "s8": 1, "u8": 1, "int8_t": 1, "uint8_t": 1,
    "short": 2, "signed short": 2, "unsigned short": 2, "s16": 2, "u16": 2, "int16_t": 2, "uint16_t": 2,
    "int": 4, "signed int": 4, "unsigned int": 4, "unsigned": 4, "long": 4, "unsigned long": 4,
    "s32": 4, "u32": 4, "int32_t": 4, "uint32_t": 4, "float": 4, "f32": 4, "M2C_UNK": 4,
    "long long": 8, "unsigned long long": 8, "s64": 8, "u64": 8, "double": 8, "f64": 8,
}


def _s16(v: int) -> int:
    v &= 0xFFFF
    return v - 0x10000 if (v & 0x8000) else v


def _idents(s: str) -> set[str]:
    return {w for w in _IDENT_RE.findall(s) if w not in _C_KEYWORDS and w != "M2C_FIELD"}


def parse_struct_field_offsets(text: str) -> dict[str, int]:
    """Parse `struct` definitions in `text` into `member_name -> byte_offset` when unambiguous."""
    field_offs: dict[str, int] = {}
    ambiguous: set[str] = set()
    for sm in re.finditer(r"\bstruct\s+\w*\s*\{([^{}]+)\}", text):
        cur = 0
        for fm in re.finditer(r"([A-Za-z_][\w\s]*?)\s*(\**)\s*(\w+)\s*(?:\[(\d+)\])?\s*;", sm.group(1)):
            tname = re.sub(r"\s+", " ", fm.group(1).strip())
            stars = fm.group(2).strip()
            fname = fm.group(3)
            arr = int(fm.group(4)) if fm.group(4) else 1
            esz = 4 if stars else _ELEM_SIZES.get(tname)
            if esz is None:
                break
            align = min(esz, 8)
            if cur % align:
                cur += align - (cur % align)
            if fname in field_offs and field_offs[fname] != cur:
                ambiguous.add(fname)
            else:
                field_offs[fname] = cur
            cur += esz * arr
    for k in ambiguous:
        field_offs.pop(k, None)
    return field_offs


def parse_pointer_elem_sizes(text: str) -> dict[str, int]:
    """Map pointer identifiers `p` in `text` to pointee byte size."""
    out: dict[str, int] = {}
    for m in re.finditer(
        r"\b((?:unsigned\s+|signed\s+)?(?:char|short|int|long(?:\s+long)?|float|double|[us](?:8|16|32|64)|u?int(?:8|16|32|64)_t|f32|f64|M2C_UNK))\s*(\*+)\s*(\w+)\b",
        text,
    ):
        tname = re.sub(r"\s+", " ", m.group(1).strip())
        stars = m.group(2)
        out[m.group(3)] = 4 if len(stars) > 1 else _ELEM_SIZES.get(tname, 4)
    return out


def _extract_mem_access(
    expr: str,
    struct_offs: dict[str, int],
    ptr_sizes: dict[str, int],
) -> tuple[str, int] | None:
    """Extract `(base_ident, byte_offset)` from `M2C_FIELD`, `p->member`, `p[k]`, or `*(T *)((u8 *)p + off)`."""
    s = expr.strip()
    m = re.fullmatch(r"M2C_FIELD\(\s*(\w+)\s*,\s*[^,]+\s*,\s*(-?(?:0x[0-9A-Fa-f]+|\d+))\s*\)", s)
    if m:
        return m.group(1), int(m.group(2), 0)
    m = re.fullmatch(r"(\w+)->(\w+)", s)
    if m and m.group(2) in struct_offs:
        return m.group(1), struct_offs[m.group(2)]
    m = re.fullmatch(r"(\w+)\[\s*(0x[0-9A-Fa-f]+|\d+)\s*\]", s)
    if m:
        esz = ptr_sizes.get(m.group(1), 4)
        return m.group(1), int(m.group(2), 0) * esz
    m = re.fullmatch(r"\*\(\s*[^()]+\*\s*\)\s*\(\s*\(\s*(?:u8|s8|unsigned\s+char|char)\s*\*\s*\)\s*(\w+)\s*\+\s*(0x[0-9A-Fa-f]+|\d+)\s*\)", s)
    if m:
        return m.group(1), int(m.group(2), 0)
    return None


def _mips_offset_seq(words: list[int], ops_set: frozenset[int]) -> dict[int, list[int]]:
    """Observed immediate byte-offset sequence per non-stack/non-GP base register."""
    seq: dict[int, list[int]] = {}
    for w in words or []:
        op = (w >> 26) & 0x3F
        if op not in ops_set:
            continue
        base = (w >> 21) & 0x1F
        if base in (0, 28, 29):
            continue
        seq.setdefault(base, []).append(_s16(w & 0xFFFF))
    return seq


def m_mips_store_tgtorder(
    text: str,
    target_words: list[int] | None,
    ours_words: list[int] | None = None,
    cap: int = 4,
) -> Iterator[tuple[str, str]]:
    """Swap adjacent C stores when target MIPS store offsets appear in the opposite order."""
    seq = _mips_offset_seq(target_words or [], _MIPS_STORE_OPS)
    if not seq:
        return
    inv: set[tuple[int, int]] = set()
    for offs in seq.values():
        for x in range(len(offs)):
            for y in range(x + 1, len(offs)):
                if offs[x] != offs[y]:
                    inv.add((offs[y], offs[x]))
    if not inv:
        return

    struct_offs = parse_struct_field_offsets(text)
    ptr_sizes = parse_pointer_elem_sizes(text)
    lines = text.split("\n")
    seen = {text}
    made = 0
    stmt_re = re.compile(r"^([ \t]+)(.+?)\s*=\s*(?!=)(.+);\s*$")

    for i in range(len(lines) - 1):
        if made >= cap:
            return
        if "volatile" in lines[i] or "volatile" in lines[i + 1]:
            continue
        if _CALL_RE.search(lines[i]) or _CALL_RE.search(lines[i + 1]):
            continue
        m1, m2 = stmt_re.match(lines[i]), stmt_re.match(lines[i + 1])
        if not (m1 and m2) or m1.group(1) != m2.group(1):
            continue
        a1 = _extract_mem_access(m1.group(2), struct_offs, ptr_sizes)
        a2 = _extract_mem_access(m2.group(2), struct_offs, ptr_sizes)
        if not (a1 and a2) or a1[0] != a2[0] or a1[1] == a2[1]:
            continue
        if (a1[1], a2[1]) not in inv:
            continue
        r1_ids, r2_ids = _idents(m1.group(3)), _idents(m2.group(3))
        if a1[0] in r2_ids or a2[0] in r1_ids:
            # Check if RHS reads the exact struct base; pure scalar/const RHS is always safe
            if m1.group(2).strip() in m2.group(3) or m2.group(2).strip() in m1.group(3):
                continue
        out = lines[:]
        out[i], out[i + 1] = out[i + 1], out[i]
        cand = "\n".join(out)
        if cand not in seen:
            seen.add(cand)
            made += 1
            yield "mips_store_tgtorder", cand


def m_mips_load_tgtorder(
    text: str,
    target_words: list[int] | None,
    ours_words: list[int] | None = None,
    cap: int = 4,
) -> Iterator[tuple[str, str]]:
    """Swap adjacent C load assignments when target MIPS load offsets appear in the opposite order."""
    seq = _mips_offset_seq(target_words or [], _MIPS_LOAD_OPS)
    if not seq:
        return
    inv: set[tuple[int, int]] = set()
    for offs in seq.values():
        for x in range(len(offs)):
            for y in range(x + 1, len(offs)):
                if offs[x] != offs[y]:
                    inv.add((offs[y], offs[x]))
    if not inv:
        return

    struct_offs = parse_struct_field_offsets(text)
    ptr_sizes = parse_pointer_elem_sizes(text)
    lines = text.split("\n")
    seen = {text}
    made = 0
    stmt_re = re.compile(r"^([ \t]+)([A-Za-z_]\w*)\s*=\s*(?!=)(.+);\s*$")
    mem_tok_re = re.compile(
        r"M2C_FIELD\([^()]+\)|\b\w+->\w+\b|\b\w+\[\s*(?:0x[0-9A-Fa-f]+|\d+)\s*\]|\*\([^()]+\*\)\(\([u8schar\s*]+\)\w+\s*\+\s*(?:0x[0-9A-Fa-f]+|\d+)\)"
    )

    for i in range(len(lines) - 1):
        if made >= cap:
            return
        if "volatile" in lines[i] or "volatile" in lines[i + 1]:
            continue
        if _CALL_RE.search(lines[i]) or _CALL_RE.search(lines[i + 1]):
            continue
        m1, m2 = stmt_re.match(lines[i]), stmt_re.match(lines[i + 1])
        if not (m1 and m2) or m1.group(1) != m2.group(1):
            continue
        lhs1, rhs1 = m1.group(2), m1.group(3)
        lhs2, rhs2 = m2.group(2), m2.group(3)
        if lhs1 == lhs2 or lhs1 in _idents(rhs2) or lhs2 in _idents(rhs1):
            continue
        f1 = mem_tok_re.findall(rhs1)
        f2 = mem_tok_re.findall(rhs2)
        if len(f1) != 1 or len(f2) != 1:
            continue
        a1 = _extract_mem_access(f1[0], struct_offs, ptr_sizes)
        a2 = _extract_mem_access(f2[0], struct_offs, ptr_sizes)
        if not (a1 and a2) or a1[0] != a2[0] or (a1[1], a2[1]) not in inv:
            continue
        out = lines[:]
        out[i], out[i + 1] = out[i + 1], out[i]
        cand = "\n".join(out)
        if cand not in seen:
            seen.add(cand)
            made += 1
            yield "mips_load_tgtorder", cand


def _mips_gpr_move_count(words: list[int]) -> int:
    """Count MIPS GPR `move` instructions (`addu`/`daddu`/`or rd, rs, $zero` with `rd != 0, rs != 0`)."""
    n = 0
    for w in words or []:
        if ((w >> 26) & 0x3F) != 0:
            continue
        fn = w & 0x3F
        if fn not in (33, 37, 45):  # addu, or, daddu
            continue
        rs, rt, rd = (w >> 21) & 0x1F, (w >> 16) & 0x1F, (w >> 11) & 0x1F
        if rd != 0 and ((rt == 0 and rs != 0) or (rs == 0 and rt != 0)):
            n += 1
    return n


def _mips_fpr_move_count(words: list[int]) -> int:
    """Count COP1 `mov.s` / `mov.d` instructions (`op==17, fmt in (16,17), fn==6`)."""
    return sum(
        1
        for w in (words or [])
        if ((w >> 26) & 0x3F) == 17 and ((w >> 21) & 0x1F) in (16, 17) and (w & 0x3F) == 6
    )


def _infer_var_types(text: str) -> dict[str, str]:
    types: dict[str, str] = {}
    for m in re.finditer(
        r"\b((?:unsigned\s+|signed\s+)?(?:char|short|int|long(?:\s+long)?|float|double|[us](?:8|16|32|64)|u?int(?:8|16|32|64)_t|f32|f64|void)\s*\*+|\b(?:unsigned\s+|signed\s+)?(?:char|short|int|long(?:\s+long)?|float|double|[us](?:8|16|32|64)|u?int(?:8|16|32|64)_t|f32|f64|M2C_UNK))\s*([A-Za-z_]\w*)\b",
        text,
    ):
        types.setdefault(m.group(2), re.sub(r"\s+", " ", m.group(1).strip()))
    return types


def m_mips_regcopy(
    text: str,
    target_words: list[int] | None,
    ours_words: list[int] | None,
    cap: int = 3,
) -> Iterator[tuple[str, str]]:
    """Introduce or eliminate C integer/pointer copy temps to match target MIPS `move` count (C89-safe)."""
    if not target_words or not ours_words:
        return
    want = _mips_gpr_move_count(target_words) - _mips_gpr_move_count(ours_words)
    if want == 0:
        return
    lines = text.split("\n")
    sig_idx = next(
        (i for i, l in enumerate(lines) if l.rstrip().endswith("{") and "(" in l and not l.startswith((" ", "\t"))),
        None,
    )
    if sig_idx is None:
        return
    vtypes = _infer_var_types(text)
    seen = {text}
    made = 0

    if want > 0:
        assign_re = re.compile(r"^([ \t]+)([A-Za-z_]\w*)\s*=\s*(?!=)(.+);\s*$")
        for i in range(sig_idx + 1, len(lines)):
            if made >= cap:
                return
            line = lines[i]
            if "volatile" in line or _CALL_RE.search(line):
                continue
            m = assign_re.match(line)
            if not m:
                continue
            ind, lhs, rhs = m.groups()
            for u in sorted(_idents(rhs) - {lhs}):
                utype = vtypes.get(u)
                if not utype or utype in ("float", "double", "f32", "f64"):
                    continue
                if re.search(r"(?:\.|->)\s*" + re.escape(u) + r"\b", rhs):
                    continue
                tname = f"mc_rc{made}"
                while re.search(r"\b" + tname + r"\b", text):
                    tname += "_"
                sep = "" if utype.endswith("*") else " "
                new_rhs = re.sub(r"\b" + re.escape(u) + r"\b", tname, rhs, count=1)
                out = lines[:]
                out[i] = f"{ind}{lhs} = {new_rhs};"
                out.insert(i, f"{ind}{tname} = {u};")
                out.insert(sig_idx + 1, f"    {utype}{sep}{tname};")
                cand = "\n".join(out)
                if cand not in seen:
                    seen.add(cand)
                    made += 1
                    yield "mips_regcopy", cand
                    break
    else:
        copy_re = re.compile(r"^([ \t]+)([A-Za-z_]\w*)\s*=\s*([A-Za-z_]\w*)\s*;\s*$")
        for i in range(sig_idx + 1, len(lines)):
            if made >= cap:
                return
            m = copy_re.match(lines[i])
            if not m:
                continue
            t, u = m.group(2), m.group(3)
            if t == u or vtypes.get(t) in ("float", "double", "f32", "f64"):
                continue
            if sum(1 for ln in lines if re.search(r"\b" + re.escape(t) + r"\s*=(?!=)", ln)) != 1:
                continue
            if sum(1 for ln in lines[i + 1 :] if re.search(r"\b" + re.escape(u) + r"\s*(?:[+\-*/%&|^]?=|\+\+|--)", ln)):
                continue
            out = lines[:i] + lines[i + 1 :]
            bare = re.compile(r"(?<![\w.])(?<!->)" + re.escape(t) + r"\b")
            for j in range(i, len(out)):
                out[j] = bare.sub(u, out[j])
            # Drop unused local declaration of `t`
            out = [
                ln
                for k, ln in enumerate(out)
                if not (
                    k > sig_idx
                    and re.match(r"^[ \t]+[^;=\n]+\b" + re.escape(t) + r"\s*;\s*$", ln)
                    and not any(bare.search(other) for m_idx, other in enumerate(out) if m_idx != k)
                )
            ]
            cand = "\n".join(out)
            if cand not in seen:
                seen.add(cand)
                made += 1
                yield "mips_regcopy", cand


def m_mips_fregcopy(
    text: str,
    target_words: list[int] | None,
    ours_words: list[int] | None,
    cap: int = 2,
) -> Iterator[tuple[str, str]]:
    """Introduce or eliminate C float copy temps to match target COP1 `mov.s`/`mov.d` count."""
    if not target_words or not ours_words:
        return
    want = _mips_fpr_move_count(target_words) - _mips_fpr_move_count(ours_words)
    if want == 0:
        return
    lines = text.split("\n")
    sig_idx = next(
        (i for i, l in enumerate(lines) if l.rstrip().endswith("{") and "(" in l and not l.startswith((" ", "\t"))),
        None,
    )
    if sig_idx is None:
        return
    vtypes = _infer_var_types(text)
    seen = {text}
    made = 0

    if want > 0:
        assign_re = re.compile(r"^([ \t]+)([A-Za-z_]\w*)\s*=\s*(?!=)(.+);\s*$")
        for i in range(sig_idx + 1, len(lines)):
            if made >= cap:
                return
            m = assign_re.match(lines[i])
            if not m or _CALL_RE.search(lines[i]):
                continue
            ind, lhs, rhs = m.groups()
            for u in sorted(_idents(rhs) - {lhs}):
                utype = vtypes.get(u)
                if utype not in ("float", "double", "f32", "f64"):
                    continue
                tname = f"mc_fc{made}"
                new_rhs = re.sub(r"\b" + re.escape(u) + r"\b", tname, rhs, count=1)
                out = lines[:]
                out[i] = f"{ind}{lhs} = {new_rhs};"
                out.insert(i, f"{ind}{tname} = {u};")
                out.insert(sig_idx + 1, f"    {utype} {tname};")
                cand = "\n".join(out)
                if cand not in seen:
                    seen.add(cand)
                    made += 1
                    yield "mips_fregcopy", cand
                    break
    else:
        copy_re = re.compile(r"^([ \t]+)([A-Za-z_]\w*)\s*=\s*([A-Za-z_]\w*)\s*;\s*$")
        for i in range(sig_idx + 1, len(lines)):
            if made >= cap:
                return
            m = copy_re.match(lines[i])
            if not m:
                continue
            t, u = m.group(2), m.group(3)
            if vtypes.get(t) not in ("float", "double", "f32", "f64"):
                continue
            if sum(1 for ln in lines if re.search(r"\b" + re.escape(t) + r"\s*=(?!=)", ln)) != 1:
                continue
            out = lines[:i] + lines[i + 1 :]
            bare = re.compile(r"(?<![\w.])(?<!->)" + re.escape(t) + r"\b")
            for j in range(i, len(out)):
                out[j] = bare.sub(u, out[j])
            out = [
                ln
                for k, ln in enumerate(out)
                if not (k > sig_idx and re.match(r"^[ \t]+(?:float|double|f32|f64)\s+" + re.escape(t) + r"\s*;$", ln))
            ]
            cand = "\n".join(out)
            if cand not in seen:
                seen.add(cand)
                made += 1
                yield "mips_fregcopy", cand


def m_mips_globalcache(
    text: str,
    target_words: list[int] | None,
    ours_words: list[int] | None,
    cap: int = 2,
) -> Iterator[tuple[str, str]]:
    """Cache a repeatedly-read `$gp` or `lui` global in a local temp when `ours` reloads globals more than `target`."""
    if not target_words or not ours_words:
        return
    gp_loads_o = sum(1 for w in ours_words if ((w >> 26) & 0x3F) in _MIPS_LOAD_OPS and ((w >> 21) & 0x1F) == 28)
    gp_loads_t = sum(1 for w in target_words if ((w >> 26) & 0x3F) in _MIPS_LOAD_OPS and ((w >> 21) & 0x1F) == 28)
    lui_o = sum(1 for w in ours_words if ((w >> 26) & 0x3F) == 15)
    lui_t = sum(1 for w in target_words if ((w >> 26) & 0x3F) == 15)
    if (gp_loads_o - gp_loads_t) <= 0 and (lui_o - lui_t) <= 0:
        return

    lines = text.split("\n")
    sig_idx = next(
        (i for i, l in enumerate(lines) if l.rstrip().endswith("{") and "(" in l and not l.startswith((" ", "\t"))),
        None,
    )
    if sig_idx is None:
        return
    ext_scalars: dict[str, str] = {}
    for m in re.finditer(
        r"^extern\s+((?:const\s+)?(?:s32|u32|s16|u16|s8|u8|int|unsigned(?:\s+int)?|short|char|f32|float|(?:void|M2C_UNK|s32|u32|u8)\s*\*+))\s*([A-Za-z_]\w*)\b(?![\s*]*\[)",
        text,
        re.M,
    ):
        ext_scalars[m.group(2)] = m.group(1).replace("const ", "").strip()
    if not ext_scalars:
        return

    seen = {text}
    made = 0
    for gsym, gtype in ext_scalars.items():
        if made >= cap:
            return
        pat = re.compile(r"(?<![\w.&])(?<!->)\b" + re.escape(gsym) + r"\b")
        read_lines: list[int] = []
        dirty = False
        for i in range(sig_idx + 1, len(lines)):
            ln = lines[i]
            if not pat.search(ln):
                continue
            if re.search(r"\b" + re.escape(gsym) + r"\s*(?:[+\-*/%&|^]?=|\+\+|--)", ln) or _CALL_RE.search(ln):
                if read_lines:
                    dirty = True
                    break
                continue
            read_lines.append(i)
        if dirty or len(read_lines) < 2:
            continue
        first, last = read_lines[0], read_lines[-1]
        if any(_CALL_RE.search(lines[k]) for k in range(first, last + 1)):
            continue
        tname = f"mc_gc{made}"
        ind = re.match(r"[ \t]*", lines[first]).group(0)
        out = lines[:]
        for j in read_lines:
            out[j] = pat.sub(tname, out[j])
        out.insert(first, f"{ind}{tname} = {gsym};")
        out.insert(sig_idx + 1, f"    {gtype} {tname};")
        cand = "\n".join(out)
        if cand not in seen:
            seen.add(cand)
            made += 1
            yield "mips_globalcache", cand


def m_mips_ptrstep_rescale(
    text: str,
    target_words: list[int] | None,
    cap: int = 2,
) -> Iterator[tuple[str, str]]:
    """Rescale typed-pointer steps (`p += K` / `p -= K`) when target `addiu`/`daddiu` byte displacements evidence it."""
    imms = {
        abs(_s16(w & 0xFFFF))
        for w in (target_words or [])
        if ((w >> 26) & 0x3F) in (8, 9, 24, 25) and ((w >> 21) & 0x1F) not in (0, 28, 29) and 0 < abs(_s16(w & 0xFFFF)) <= 0x4000
    }
    if not imms:
        return
    ptr_sizes = {k: v for k, v in parse_pointer_elem_sizes(text).items() if v > 1}
    if not ptr_sizes:
        return
    lines = text.split("\n")
    adj_re = re.compile(r"^([ \t]*)(\w+)\s*([+-])=\s*(0x[0-9A-Fa-f]+|\d+)[uUlL]*\s*;\s*$")
    seen = {text}
    made = 0
    for i, ln in enumerate(lines):
        if made >= cap:
            return
        m = adj_re.match(ln)
        if not m:
            continue
        ind, vname, op, step_s = m.groups()
        esz = ptr_sizes.get(vname)
        if not esz:
            continue
        step = int(step_s, 0)
        if step == 0:
            continue
        for new_step in ((step // esz,) if step % esz == 0 else ()) + (step * esz,):
            if new_step != step and new_step * esz in imms:
                out = lines[:]
                out[i] = f"{ind}{vname} {op}= {new_step};"
                cand = "\n".join(out)
                if cand not in seen:
                    seen.add(cand)
                    made += 1
                    yield "mips_ptrstep", cand
                    if made >= cap:
                        return


def m_mips_delayslot_sched(
    text: str,
    delay_swaps: list[dict[str, Any]] | None = None,
    cap: int = 6,
) -> Iterator[tuple[str, str]]:
    """Schedule C statements around branches, returns, and loop back-edges to fill/reorder MIPS delay slots."""
    lines = text.split("\n")
    sig_idx = next(
        (i for i, l in enumerate(lines) if l.rstrip().endswith("{") and "(" in l and not l.startswith((" ", "\t"))),
        None,
    )
    if sig_idx is None:
        return
    seen = {text}
    made = 0

    def _emit(cand: str) -> Iterator[tuple[str, str]]:
        nonlocal made
        if cand not in seen and made < cap:
            seen.add(cand)
            made += 1
            yield "mips_delayslot", cand

    # 1. Pull common tail statement out of both arms of `if (c) { ...; S; } else { ...; S; }` (or push S into both!)
    i = sig_idx + 1
    while i < len(lines) and made < cap:
        m_if = re.match(r"^([ \t]+)if\s*\((.+)\)\s*\{\s*$", lines[i])
        if not m_if:
            i += 1
            continue
        ind = m_if.group(1)
        else_idx = next((j for j in range(i + 1, len(lines)) if lines[j] == f"{ind}}} else {{"), None)
        end_idx = (
            next((j for j in range(else_idx + 1, len(lines)) if lines[j] == f"{ind}}}"), None)
            if else_idx is not None
            else None
        )
        if else_idx is not None and end_idx is not None:
            then_body = lines[i + 1 : else_idx]
            else_body = lines[else_idx + 1 : end_idx]
            if then_body and else_body and then_body[-1].strip() == else_body[-1].strip():
                tail = then_body[-1].strip()
                if tail.endswith(";") and not tail.startswith(("return", "break", "continue", "goto")):
                    pulled = (
                        lines[: i + 1]
                        + then_body[:-1]
                        + [lines[else_idx]]
                        + else_body[:-1]
                        + [lines[end_idx], f"{ind}{tail}"]
                        + lines[end_idx + 1 :]
                    )
                    yield from _emit("\n".join(pulled))
            # Conversely, push a pure assignment immediately following `if/else` into the end of both arms
            if end_idx + 1 < len(lines):
                after = lines[end_idx + 1]
                if (
                    after.startswith(ind)
                    and not after[len(ind) :].startswith(" ")
                    and after.strip().endswith(";")
                    and "=" in after
                    and not _CALL_RE.search(after)
                    and not (then_body and then_body[-1].strip().startswith(("return", "goto", "break", "continue")))
                    and not (else_body and else_body[-1].strip().startswith(("return", "goto", "break", "continue")))
                ):
                    pushed = (
                        lines[:else_idx]
                        + [f"    {after}"]
                        + lines[else_idx:end_idx]
                        + [f"    {after}", lines[end_idx]]
                        + lines[end_idx + 2 :]
                    )
                    yield from _emit("\n".join(pushed))
        i += 1

    # 2. Loop increment `i++` <-> `++i` <-> `i += 1` (changes `bne` delay-slot fill in `ee-gcc` / `psp-gcc`!)
    for idx in range(sig_idx + 1, len(lines)):
        if made >= cap:
            return
        ln = lines[idx]
        if "for (" in ln or "for(" in ln:
            m_post = re.search(r"\b(\w+)\+\+\s*\)", ln)
            if m_post:
                out = lines[:]
                out[idx] = ln[: m_post.start()] + f"++{m_post.group(1)})" + ln[m_post.end() :]
                yield from _emit("\n".join(out))
            m_pre = re.search(r"\+\+(\w+)\s*\)", ln)
            if m_pre:
                out = lines[:]
                out[idx] = ln[: m_pre.start()] + f"{m_pre.group(1)}++)" + ln[m_pre.end() :]
                yield from _emit("\n".join(out))

    # 3. `if (c) return A; return B;` <-> `return (c) ? A : B;` (controls `jr $ra` delay-slot `li`/`move`)
    ret_pair_re = re.compile(
        r"^([ \t]+)if\s*\(([^;\n{}]+)\)\s*\{\n\1    return\s+([^;\n{}]+);\n\1\}\n\1return\s+([^;\n{}]+);",
        re.M,
    )
    m_rp = ret_pair_re.search(text)
    if m_rp and made < cap:
        ind, cond, ra, rb = m_rp.groups()
        if not _CALL_RE.search(ra) and not _CALL_RE.search(rb):
            yield from _emit(text[: m_rp.start()] + f"{ind}return ({cond}) ? ({ra}) : ({rb});" + text[m_rp.end() :])


def m_mips_lit_order(text: str, target_words: list[int] | None, cap: int = 3) -> Iterator[tuple[str, str]]:
    """Swap adjacent `li` (`simm16`/`uimm16`) and `lui` (`>= 0x10000` / `&sym`) initializations."""
    if not target_words:
        return
    has_li = any(((w >> 26) & 0x3F) in (9, 13, 25) and ((w >> 21) & 0x1F) == 0 for w in target_words)
    has_lui = any(((w >> 26) & 0x3F) == 15 for w in target_words)
    if not (has_li and has_lui):
        return
    lines = text.split("\n")
    assign_re = re.compile(r"^([ \t]+)([A-Za-z_]\w*)\s*=\s*(?!=)(.+);\s*$")

    def _lit_class(rhs: str) -> str | None:
        r = rhs.strip()
        if re.fullmatch(r"-?(?:0x[0-9A-Fa-f]+|\d+)[uUlL]*", r):
            val = int(r.rstrip("uUlL"), 0)
            return "li" if -0x8000 <= val <= 0xFFFF else "lui"
        if re.fullmatch(r"(?:\([^()]+\)\s*)?&[A-Za-z_]\w*", r):
            return "lui"
        return None

    seen = {text}
    made = 0
    for i in range(len(lines) - 1):
        if made >= cap:
            return
        m1, m2 = assign_re.match(lines[i]), assign_re.match(lines[i + 1])
        if not (m1 and m2) or m1.group(1) != m2.group(1) or m1.group(2) == m2.group(2):
            continue
        k1, k2 = _lit_class(m1.group(3)), _lit_class(m2.group(3))
        if {k1, k2} != {"li", "lui"}:
            continue
        out = lines[:]
        out[i], out[i + 1] = out[i + 1], out[i]
        cand = "\n".join(out)
        if cand not in seen:
            seen.add(cand)
            made += 1
            yield "mips_lit_order", cand


def m_mips_r5900_madd_fma(text: str, target_words: list[int] | None, cap: int = 4) -> Iterator[tuple[str, str]]:
    """Target R5900 `madd`/`madd.s`/`msub.s` and Allegrex `max`/`min` idioms."""
    if not target_words:
        return
    has_madd_int = any(((w >> 26) & 0x3F) == 28 and (w & 0x3F) in (0, 1, 32, 33) for w in target_words)
    has_madd_fp = any(
        ((w >> 26) & 0x3F) == 17 and ((w >> 21) & 0x1F) == 16 and (w & 0x3F) in (24, 25, 28, 29)
        for w in target_words
    )
    has_minmax = any(((w >> 26) & 0x3F) == 0 and (w & 0x3F) in (44, 45) for w in target_words)
    seen = {text}
    made = 0

    if has_madd_int or has_madd_fp:
        # Fuse adjacent `t = a * b; acc += t;` -> `acc += a * b;` or split `acc + a * b`
        pat = re.compile(
            r"^([ \t]+)(\w+)\s*=\s*([^;=\n]+?\*[^;=\n]+?);\n\1(\w+)\s*([+-])=\s*\2;",
            re.M,
        )
        for m in pat.finditer(text):
            if made >= cap:
                return
            ind, tmp, prod, acc, op = m.groups()
            if len(re.findall(r"\b" + re.escape(tmp) + r"\b", text)) <= 3:
                cand = text[: m.start()] + f"{ind}{acc} {op}= ({prod});" + text[m.end() :]
                if cand not in seen:
                    seen.add(cand)
                    made += 1
                    yield "mips_madd_fuse", cand

    if has_minmax and made < cap:
        # Toggle `<` <-> `<=` and `>` <-> `>=` in clamping ternaries `(a < b) ? a : b`
        for m in re.finditer(r"\(\s*(\w+)\s*([<>]=?)\s*([^()?:;]+?)\s*\)\s*\?\s*\1\s*:\s*\3", text):
            op = m.group(2)
            flipped = {"<": "<=", "<=": "<", ">": ">=", ">=": ">"}[op]
            cand = text[: m.start(2)] + flipped + text[m.end(2) :]
            if cand not in seen:
                seen.add(cand)
                made += 1
                yield "mips_minmax", cand
                if made >= cap:
                    return


def _mips_frame_size(words: list[int]) -> int | None:
    for w in (words or [])[:8]:
        op = (w >> 26) & 0x3F
        if op in (9, 25) and ((w >> 21) & 0x1F) == 29 and ((w >> 16) & 0x1F) == 29:
            simm = _s16(w & 0xFFFF)
            if simm < 0:
                return -simm
    return None


def m_mips_frame_pad(
    text: str,
    target_words: list[int] | None,
    ours_words: list[int] | None,
) -> Iterator[tuple[str, str]]:
    """Resize stack arrays/unions or add a stack pad to match target MIPS `$sp` frame allocation."""
    cur = _mips_frame_size(ours_words or [])
    want = _mips_frame_size(target_words or [])
    if cur is None or want is None or cur == want:
        return
    delta = want - cur
    arr_re = re.compile(r"^([ \t]+(?:unsigned\s+char|u8|s8|char|s32|u32|int)\s+\w+\[)(\d+)(\];)", re.M)
    m = arr_re.search(text)
    if m:
        esz = 4 if any(t in m.group(1) for t in ("s32", "u32", "int")) else 1
        if delta % esz == 0:
            new_n = int(m.group(2)) + (delta // esz)
            if 1 <= new_n <= 16384:
                yield "mips_frame", text[: m.start(2)] + str(new_n) + text[m.end(2) :]
                return
    if delta > 0 and delta % 4 == 0 and "mc_sp_pad[" not in text:
        sig = re.search(r"^[^\n;#]*\b\w+\s*\([^{};]*\)\s*\{", text, re.M)
        if sig:
            yield "mips_frame", text[: sig.end()] + f"\n    volatile int mc_sp_pad[{delta // 4}];" + text[sig.end() :]


# ---------- Universal Standard-C Mutations (for non-M2C_FIELD human C & decomp C) ----------

def m_c_commute_general(text: str, cap: int = 6) -> Iterator[tuple[str, str]]:
    """Commute `+`, `*`, `&`, `|`, `^`, `==`, `!=` and relational `<`/`>` operands on standard C."""
    lines = text.split("\n")
    sig_idx = next(
        (i for i, l in enumerate(lines) if l.rstrip().endswith("{") and "(" in l and not l.startswith((" ", "\t"))),
        0,
    )
    made = 0
    seen = {text}
    bin_re = re.compile(r"(?<![\w.>])([A-Za-z_]\w*(?:->\w+|\.\w+|\[\w+\])?)\s*(\+|\*|&|\||\^|==|!=)\s*([A-Za-z_]\w*(?:->\w+|\.\w+|\[\w+\])?|-?(?:0x[0-9A-Fa-f]+|\d+))(?![\w.(])")
    rel_re = re.compile(r"\(\s*([A-Za-z_]\w*|-?\d+|0x[0-9A-Fa-f]+)\s*(<=|>=|<|>)\s*([A-Za-z_]\w*|-?\d+|0x[0-9A-Fa-f]+)\s*\)")
    rel_flip = {"<": ">", ">": "<", "<=": ">=", ">=": "<="}

    for i in range(sig_idx + 1, len(lines)):
        ln = lines[i]
        for m in bin_re.finditer(ln):
            if made >= cap:
                return
            a, op, b = m.groups()
            if a == b or a in _C_KEYWORDS or b in _C_KEYWORDS:
                continue
            out = lines[:]
            out[i] = ln[: m.start()] + f"{b} {op} {a}" + ln[m.end() :]
            cand = "\n".join(out)
            if cand not in seen:
                seen.add(cand)
                made += 1
                yield "c_commute", cand
        for m in rel_re.finditer(ln):
            if made >= cap:
                return
            a, op, b = m.groups()
            if a == b:
                continue
            out = lines[:]
            out[i] = ln[: m.start()] + f"({b} {rel_flip[op]} {a})" + ln[m.end() :]
            cand = "\n".join(out)
            if cand not in seen:
                seen.add(cand)
                made += 1
                yield "c_rel_commute", cand


def m_c_narrow_local(text: str, cap: int = 6) -> Iterator[tuple[str, str]]:
    """Flip local integer declarations between `int`/`s32`/`u32` and narrow `s16`/`u16`/`s8`/`u8` (and signedness)."""
    lines = text.split("\n")
    sig_idx = next(
        (i for i, l in enumerate(lines) if l.rstrip().endswith("{") and "(" in l and not l.startswith((" ", "\t"))),
        None,
    )
    if sig_idx is None:
        return
    decl_re = re.compile(
        r"^([ \t]{2,8})(register\s+)?(int|unsigned\s+int|unsigned|short|unsigned\s+short|signed\s+char|unsigned\s+char|char|s32|u32|s16|u16|s8|u8|int32_t|uint32_t|int16_t|uint16_t|int8_t|uint8_t)\s+([A-Za-z_]\w*)(\s*(?:=[^;]+)?;\s*)$"
    )
    alts_map = {
        "int": ("unsigned int", "short", "signed char"),
        "unsigned int": ("int", "unsigned short", "unsigned char"),
        "unsigned": ("int", "unsigned short", "unsigned char"),
        "s32": ("u32", "s16", "s8"),
        "u32": ("s32", "u16", "u8"),
        "int32_t": ("uint32_t", "int16_t", "int8_t"),
        "uint32_t": ("int32_t", "uint16_t", "uint8_t"),
        "short": ("int", "unsigned short"),
        "unsigned short": ("unsigned int", "short"),
        "s16": ("s32", "u16"),
        "u16": ("u32", "s16"),
        "int16_t": ("int32_t", "uint16_t"),
        "uint16_t": ("uint32_t", "int16_t"),
        "s8": ("s32", "u8"),
        "u8": ("u32", "s8"),
        "char": ("int", "unsigned char", "signed char"),
        "signed char": ("int", "unsigned char"),
        "unsigned char": ("unsigned int", "signed char", "int"),
    }
    made = 0
    seen = {text}
    for i in range(sig_idx + 1, min(len(lines), sig_idx + 40)):
        m = decl_re.match(lines[i])
        if not m:
            continue
        ind, reg_kw, t_raw, vname, tail = m.groups()
        t_key = re.sub(r"\s+", " ", t_raw.strip())
        for alt in alts_map.get(t_key, ()):
            if made >= cap:
                return
            out = lines[:]
            out[i] = f"{ind}{reg_kw or ''}{alt} {vname}{tail}"
            cand = "\n".join(out)
            if cand not in seen:
                seen.add(cand)
                made += 1
                yield "c_local_width", cand


def m_c_struct_store_swap(text: str, cap: int = 4) -> Iterator[tuple[str, str]]:
    """Swap adjacent independent standard-C struct/array stores (`p->a = ...; p->b = ...;` or `p[0] = ...; p[1] = ...;`)."""
    lines = text.split("\n")
    stmt_re = re.compile(r"^([ \t]+)(\w+(?:->\w+|\.\w+|\[\s*(?:0x[0-9A-Fa-f]+|\d+)\s*\]))\s*=\s*(?!=)(.+);\s*$")
    made = 0
    seen = {text}
    for i in range(len(lines) - 1):
        if made >= cap:
            return
        if "volatile" in lines[i] or "volatile" in lines[i + 1]:
            continue
        if _CALL_RE.search(lines[i]) or _CALL_RE.search(lines[i + 1]):
            continue
        m1, m2 = stmt_re.match(lines[i]), stmt_re.match(lines[i + 1])
        if not (m1 and m2) or m1.group(1) != m2.group(1) or m1.group(2) == m2.group(2):
            continue
        if m1.group(2) in m2.group(3) or m2.group(2) in m1.group(3):
            continue
        out = lines[:]
        out[i], out[i + 1] = out[i + 1], out[i]
        cand = "\n".join(out)
        if cand not in seen:
            seen.add(cand)
            made += 1
            yield "c_store_swap", cand


def m_c_for_while_do(text: str, cap: int = 3) -> Iterator[tuple[str, str]]:
    """Convert standard `for (i = 0; cond; step) { ... }` into `i = 0; while (cond) { ...; step; }` and guarded `do-while`."""
    lines = text.split("\n")
    for_re = re.compile(r"^([ \t]+)for\s*\(\s*([^;{}]+);\s*([^;{}]+);\s*([^;{}]+)\)\s*\{\s*$")
    seen = {text}
    made = 0
    for i, ln in enumerate(lines):
        if made >= cap:
            return
        m = for_re.match(ln)
        if not m:
            continue
        ind, init_s, cond_s, step_s = m.groups()
        depth = 1
        close = None
        for j in range(i + 1, len(lines)):
            depth += lines[j].count("{") - lines[j].count("}")
            if depth == 0:
                close = j
                break
        if close is None or any("continue;" in lines[k] for k in range(i + 1, close)):
            continue
        body = lines[i + 1 : close]
        while_cand = "\n".join(
            lines[:i]
            + [f"{ind}{init_s.strip()};", f"{ind}while ({cond_s.strip()}) {{"]
            + body
            + [f"{ind}    {step_s.strip()};", f"{ind}}}"]
            + lines[close + 1 :]
        )
        if while_cand not in seen:
            seen.add(while_cand)
            made += 1
            yield "c_for_to_while", while_cand
        if made < cap:
            do_cand = "\n".join(
                lines[:i]
                + [
                    f"{ind}{init_s.strip()};",
                    f"{ind}if ({cond_s.strip()}) {{",
                    f"{ind}    do {{",
                ]
                + [f"        {b}" if b.strip() else b for b in body]
                + [
                    f"{ind}        {step_s.strip()};",
                    f"{ind}    }} while ({cond_s.strip()});",
                    f"{ind}}}",
                ]
                + lines[close + 1 :]
            )
            if do_cand not in seen:
                seen.add(do_cand)
                made += 1
                yield "c_for_to_guarded_do", do_cand


def _apply_callee_and_global_repairs(
    source: str,
    repairs: list[dict[str, Any]],
    external: dict[str, int] | None,
) -> Iterator[tuple[str, str]]:
    """Rewrite wrong `callee` or `global` identifiers in C using the target symbol map (parity with PPC `directed`)."""
    ext = external or {}
    for rep in repairs:
        cat = rep.get("category")
        if cat == "callee":
            ours_sym = str(rep.get("ours", ""))
            targ_sym = str(rep.get("target", ""))
            if not re.fullmatch(r"[A-Za-z_]\w*", targ_sym):
                continue
            # Match by direct symbol name or shared address in `external`
            candidates_to_replace = {ours_sym}
            if ours_sym in ext:
                want_addr = ext[ours_sym]
                candidates_to_replace |= {k for k, v in ext.items() if (v & ~1) == (want_addr & ~1)}
            elif ours_sym.startswith("0x"):
                try:
                    want_addr = int(ours_sym, 16)
                    candidates_to_replace |= {k for k, v in ext.items() if (v & ~1) == (want_addr & ~1)}
                except ValueError:
                    pass
            for old_fn in sorted(candidates_to_replace):
                if re.fullmatch(r"[A-Za-z_]\w*", old_fn) and old_fn != targ_sym and re.search(r"\b" + re.escape(old_fn) + r"\s*\(", source):
                    cand = re.sub(r"\b" + re.escape(old_fn) + r"\b", targ_sym, source)
                    if not re.search(r"\b" + re.escape(targ_sym) + r"\s*\([^;{}]*\)\s*;", cand):
                        cand = f"int {targ_sym}();\n" + cand
                    yield "target_callee", cand
        elif cat == "global":
            targ_sym = str(rep.get("target_symbol", "")).split("+")[0]
            ours_sym = str(rep.get("ours_symbol", "")).split("+")[0]
            if not re.fullmatch(r"[A-Za-z_]\w*", targ_sym):
                continue
            candidates_to_replace = {ours_sym}
            try:
                ours_addr = int(str(rep.get("ours", "")), 16)
                candidates_to_replace |= {k for k, v in ext.items() if v == ours_addr}
            except ValueError:
                pass
            for old_g in sorted(candidates_to_replace):
                if re.fullmatch(r"[A-Za-z_]\w*", old_g) and old_g != targ_sym and re.search(r"\b" + re.escape(old_g) + r"\b", source):
                    cand = re.sub(r"\b" + re.escape(old_g) + r"\b", targ_sym, source)
                    yield "target_global", cand


def directed_mips(
    text: str,
    result: dict[str, Any] | None,
    target_words: list[int] | None = None,
    ours_words: list[int] | None = None,
    ctx: Any = None,
) -> Iterator[tuple[str, str]]:
    """Full score- and target-instruction-directed MIPS proposal generator."""
    seen: set[str] = {text}
    repairs = (result or {}).get("repairs") or []
    unresolved = (result or {}).get("_unresolved") or {}
    delay_swaps = (result or {}).get("_delay_swaps") or []
    gp = getattr(ctx, "gp", 0) if ctx is not None else 0
    ext = getattr(ctx, "external", None) if ctx is not None else None
    objs = getattr(ctx, "objs", None) if ctx is not None else None
    funcs = getattr(ctx, "by_addr", None) if ctx is not None else None
    read_mem = getattr(ctx, "read", None) if ctx is not None else None
    endian = (getattr(ctx, "endian", "") if ctx is not None else "") or "little"

    def _dedup(it: Iterator[tuple[str, str]]) -> Iterator[tuple[str, str]]:
        for fam, cand in it:
            if cand and cand not in seen:
                seen.add(cand)
                yield fam, cand

    # 1. Unresolved relocation / `.rodata` / `$gp` range repairs first!
    if unresolved:
        yield from _dedup(mips_seeds.mips_extern_relocs(text, unresolved, target_words, gp=gp, read_mem=read_mem, endian=endian))

    # 2. Direct instruction-backed one-site & batch repairs (literal, field_offset, callee, global)
    yield from _dedup(mips_guidance.repair_proposals(text, result))
    yield from _dedup(_apply_callee_and_global_repairs(text, repairs, ext))

    # Batch multi-offset remap when >= 2 field offsets differ simultaneously
    off_pairs = {
        int(str(r["ours"]), 0): int(str(r["target"]), 0)
        for r in repairs
        if r.get("category") in ("field_offset", "offset")
        and isinstance(r.get("ours"), int)
        and isinstance(r.get("target"), int)
    }
    if len(off_pairs) >= 2:
        from kintoun.search.mutations_directed import _remap_offsets

        remapped = _remap_offsets(text, off_pairs)
        if remapped and remapped not in seen:
            seen.add(remapped)
            yield "target_offset_batch", remapped

    # 3. Target-instruction-guided MIPS mutations (no blind compiling!)
    yield from _dedup(m_mips_store_tgtorder(text, target_words, ours_words))
    yield from _dedup(m_mips_load_tgtorder(text, target_words, ours_words))
    yield from _dedup(m_mips_regcopy(text, target_words, ours_words))
    yield from _dedup(m_mips_fregcopy(text, target_words, ours_words))
    yield from _dedup(m_mips_globalcache(text, target_words, ours_words))
    yield from _dedup(m_mips_ptrstep_rescale(text, target_words))
    yield from _dedup(m_mips_lit_order(text, target_words))
    yield from _dedup(m_mips_r5900_madd_fma(text, target_words))
    yield from _dedup(m_mips_frame_pad(text, target_words, ours_words))
    yield from _dedup(m_mips_delayslot_sched(text, delay_swaps))

    # 4. Target-backed MIPS seed transforms (`single_float`, `lit16_sign`, `raw_addr_rebase`, `gp`, etc.)
    yield from _dedup(
        mips_seeds.mips_seed_variants(
            text,
            target_words=target_words,
            objects=objs,
            functions=funcs,
            gp=gp,
            external=ext,
        )
    )

    # 5. Near-miss statement-scheduling & switch-case permutations (reusing proven pure-C families!)
    if mips_guidance.near_miss(result) or delay_swaps:
        for order_fn in (
            m_init_order,
            m_constarg_hoist,
            m_mixed_order,
            m_plainload_order,
            m_addr_order,
            m_samecopy_order,
            m_member_order,
            m_decl_order,
            m_callmove_order,
            m_cho_midfirst,
            m_disjoint_order,
            m_spillsched_order,
            m_calladdr_order,
            m_callpure_order,
            m_cholit_order,
            m_samemem_order,
            m_sameload_order,
            m_loadhoist_order,
            m_alias_sink,
        ):
            try:
                yield from _dedup(order_fn(text))
            except Exception:
                continue

    if "switch (" in text or "switch(" in text:
        yield from _dedup(m_case_order(text))
        yield from _dedup(m_caseswap_order(text))
        yield from _dedup(m_switch_lower(text))
    if ".v" in text or "M2C_FIELD" in text:
        yield from _dedup(m_fmem_order(text))
        yield from _dedup(m_fmem_hop(text))

    # 6. Universal standard-C struct/narrow/commute/loop rewrites
    yield from _dedup(m_c_struct_store_swap(text))
    yield from _dedup(m_c_narrow_local(text))
    yield from _dedup(m_c_commute_general(text))
    yield from _dedup(m_c_for_while_do(text))
