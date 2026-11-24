"""Dedicated ARM/Thumb target-instruction-guided C mutations and score-directed search orchestrator.

Decodes relocated `ArmItem` streams (`agbcc`, `arm-none-eabi-gcc`, `mwccarm`, `armcc`) across
A32, Thumb-16, Thumb-32, and inline `$d` literal pools:
- `m_arm_pool_order`: reorders C global/constant evaluations to match target `$d` literal-pool `.word` emission order;
- `m_arm_store_tgtorder` / `m_arm_load_tgtorder`: target `[rB, #off]` load/store offset inversion swaps;
- `m_arm_regcopy`: C89-safe register-move (`mov`/`adds #0`) count-guided copy temp introduction/elimination;
- `m_arm_thumb_hireg_spill`: Thumb high-register (`r8-r11`) spill relief (rematerialize/scope) & CSE hoisting;
- `m_arm_ptrstep_rescale`: A32/Thumb `add`/`sub`/`adds`/`subs` immediate-guided pointer step rescaling;
- `m_arm_bic_and_shift`: ARM/Thumb `bic` (`& ~mask`) and A32/Thumb-2 barrel-shifter `x * 3/5/9` <-> `x + (x << k)`;
- `m_arm_agbcc_comma_pin`: `agbcc` `(0, expr)` / local-temp Thumb low-register allocation nudges;
- `m_arm_frame_pad`: `sub sp, #N` frame-size adjustment;
- `directed_arm()` full score-directed ARM/Thumb orchestrator.
"""
from __future__ import annotations

import re
from typing import Any, Iterator

from kintoun.search import arm_guidance, arm_seeds, mips_mutations
from kintoun.search.arm_repairs import _alu_immediate_arm, _mem_offset_arm
from kintoun.search.arm_score import ArmItem, disasm_arm_item
from kintoun.search.mips_mutations import (
    _CALL_RE,
    _C_KEYWORDS,
    _apply_callee_and_global_repairs,
    _extract_mem_access,
    _idents,
    _infer_var_types,
    m_c_commute_general,
    m_c_for_while_do,
    m_c_narrow_local,
    m_c_struct_store_swap,
    parse_pointer_elem_sizes,
    parse_struct_field_offsets,
)
from kintoun.search.mutations_mem import m_alias_sink, m_loadhoist_order
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

_ARM_STORE_MNS = frozenset(("str", "strh", "strb", "strd", "str.w", "strh.w", "strb.w"))
_ARM_LOAD_MNS = frozenset(("ldr", "ldrh", "ldrb", "ldrsb", "ldrsh", "ldrd", "ldr.w", "ldrh.w", "ldrb.w", "ldrsb.w", "ldrsh.w"))


def _arm_pool_words(items: list[ArmItem] | None) -> list[int]:
    return [it.raw for it in (items or []) if it.mode == "d" and it.size == 4]


def _pool_val_matches_line(val: int, line: str, external: dict[str, int] | None) -> bool:
    """True if `line` references constant `val` (hex/dec/signed) or symbol at `val` (`&sym` / `sym`)."""
    sval = val - 0x100000000 if (val & 0x80000000) else val
    for tok in (f"0x{val:X}", f"0x{val:x}", f"0x{val:08X}", f"0x{val:08x}", str(val), str(sval)):
        if re.search(r"(?<![\w.])" + re.escape(tok) + r"[uUlL]*(?![\w.])", line):
            return True
    if external:
        even = val & ~1
        for sym, addr in external.items():
            if addr == val or (addr & ~1) == even or (0 <= val - addr <= 0xFF and sym.startswith(("lbl_", "g_"))):
                if re.search(r"\b" + re.escape(sym) + r"\b", line):
                    return True
    return False


def m_arm_pool_order(
    text: str,
    target_items: list[ArmItem] | None,
    ours_items: list[ArmItem] | None,
    external: dict[str, int] | None = None,
    cap: int = 4,
) -> Iterator[tuple[str, str]]:
    """Reorder C constant/global evaluations so inline `$d` literal-pool `.word` emission matches `target_items`!

    `agbcc`, `arm-none-eabi-gcc`, and `mwccarm` emit inline `$d` literal-pool entries in exact
    first-reference order. When `ours` and `target` share two pool words `(v1, v2)` in opposite
    pool order, swapping the independent C statements (or commutative operands) that first
    reference `v1` and `v2` flips the emitted `$d` pool words into exact alignment!
    """
    t_pool = _arm_pool_words(target_items)
    o_pool = _arm_pool_words(ours_items)
    if len(t_pool) < 2 or len(o_pool) < 2 or t_pool == o_pool:
        return

    # Find pairs `(u, v)` where `u` precedes `v` in `o_pool` while `v` precedes `u` in `t_pool`
    inversions: list[tuple[int, int]] = []
    t_pos = {w: idx for idx, w in enumerate(t_pool)}
    for idx_a, u in enumerate(o_pool):
        if u not in t_pos:
            continue
        for v in o_pool[idx_a + 1 :]:
            if v != u and v in t_pos and t_pos[v] < t_pos[u]:
                inversions.append((u, v))
    if not inversions:
        return

    lines = text.split("\n")
    sig_idx = next(
        (i for i, l in enumerate(lines) if l.rstrip().endswith("{") and "(" in l and not l.startswith((" ", "\t"))),
        0,
    )
    seen = {text}
    made = 0

    for u, v in inversions:
        if made >= cap:
            return
        u_lines = [i for i in range(sig_idx + 1, len(lines)) if _pool_val_matches_line(u, lines[i], external)]
        v_lines = [i for i in range(sig_idx + 1, len(lines)) if _pool_val_matches_line(v, lines[i], external)]
        if not u_lines or not v_lines:
            continue
        iu, iv = u_lines[0], v_lines[0]
        if iu < iv and iv - iu <= 3:
            # Check independence across lines[iu..iv]
            block = lines[iu : iv + 1]
            if all(
                ln.strip().endswith(";")
                and not ln.lstrip().startswith(("return", "if", "for", "while", "switch", "case", "goto", "break"))
                and "volatile" not in ln
                and not _CALL_RE.search(ln)
                for ln in block
            ):
                lhs_u = block[0].split("=", 1)[0] if "=" in block[0] else ""
                lhs_v = block[-1].split("=", 1)[0] if "=" in block[-1] else ""
                w_u = _idents(lhs_u)
                w_v = _idents(lhs_v)
                if not (w_u & _idents(" ".join(block[1:]))) and not (w_v & _idents(" ".join(block[:-1]))):
                    out = lines[:]
                    out[iu], out[iv] = out[iv], out[iu]
                    cand = "\n".join(out)
                    if cand not in seen:
                        seen.add(cand)
                        made += 1
                        yield "arm_pool_order", cand
                        continue
        # Same-line commutative binary expression `expr_u + expr_v` -> `expr_v + expr_u`
        if iu == iv:
            ln = lines[iu]
            for op in (" + ", " | ", " ^ ", " & ", " * "):
                if op in ln and "=" in ln:
                    lhs_p, rhs_p = ln.split("=", 1)
                    rhs_core = rhs_p.rsplit(";", 1)[0]
                    parts = rhs_core.split(op)
                    if len(parts) == 2 and _pool_val_matches_line(u, parts[0], external) and _pool_val_matches_line(v, parts[1], external):
                        out = lines[:]
                        out[iu] = f"{lhs_p}= {parts[1].strip()}{op}{parts[0].strip()};"
                        cand = "\n".join(out)
                        if cand not in seen:
                            seen.add(cand)
                            made += 1
                            yield "arm_pool_order", cand
                            break


def _arm_offset_seq(items: list[ArmItem] | None, want_mns: frozenset[str]) -> dict[int, list[int]]:
    seq: dict[int, list[int]] = {}
    for it in items or []:
        if it.mode == "d" or it.pool_target_off is not None:
            continue
        mn = disasm_arm_item(it)[0]
        if mn not in want_mns:
            continue
        mo = _mem_offset_arm(it)
        if mo is not None:
            base_reg, off = mo
            seq.setdefault(base_reg, []).append(off)
    return seq


def m_arm_store_tgtorder(
    text: str,
    target_items: list[ArmItem] | None,
    ours_items: list[ArmItem] | None = None,
    cap: int = 4,
) -> Iterator[tuple[str, str]]:
    """Swap adjacent C stores when target ARM/Thumb `[rB, #off]` store offsets show the opposite order."""
    seq = _arm_offset_seq(target_items, _ARM_STORE_MNS)
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
    stmt_re = re.compile(r"^([ \t]+)(.+?)\s*=\s*(?!=)(.+);\s*$")
    seen = {text}
    made = 0

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
        if not (a1 and a2) or a1[0] != a2[0] or (a1[1], a2[1]) not in inv:
            continue
        if m1.group(2).strip() in m2.group(3) or m2.group(2).strip() in m1.group(3):
            continue
        out = lines[:]
        out[i], out[i + 1] = out[i + 1], out[i]
        cand = "\n".join(out)
        if cand not in seen:
            seen.add(cand)
            made += 1
            yield "arm_store_tgtorder", cand


def m_arm_load_tgtorder(
    text: str,
    target_items: list[ArmItem] | None,
    ours_items: list[ArmItem] | None = None,
    cap: int = 4,
) -> Iterator[tuple[str, str]]:
    """Swap adjacent C loads when target ARM/Thumb `[rB, #off]` load offsets show the opposite order."""
    seq = _arm_offset_seq(target_items, _ARM_LOAD_MNS)
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
    stmt_re = re.compile(r"^([ \t]+)([A-Za-z_]\w*)\s*=\s*(?!=)(.+);\s*$")
    mem_tok_re = re.compile(
        r"M2C_FIELD\([^()]+\)|\b\w+->\w+\b|\b\w+\[\s*(?:0x[0-9A-Fa-f]+|\d+)\s*\]"
    )
    seen = {text}
    made = 0

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
        f1, f2 = mem_tok_re.findall(rhs1), mem_tok_re.findall(rhs2)
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
            yield "arm_load_tgtorder", cand


def _arm_reg_move_count(items: list[ArmItem] | None) -> int:
    """Count register-to-register `mov` / `movs` / Thumb `adds Rd, Rs, #0` copies."""
    n = 0
    for it in items or []:
        if it.mode == "t16":
            # `adds Rd, Rs, #0` (`0x1C00..0x1C3F`) or `mov Rd, Rm` (`0x4600..0x46FF`, excluding nop `mov r8, r8`)
            if (it.raw & 0xFFC0) == 0x1C00 or ((it.raw & 0xFF00) == 0x4600 and it.raw != 0x46C0):
                n += 1
        elif it.mode == "a":
            # A32 `MOV Rd, Rm` (top3==0, opc==13, shift==0, Rd != PC, Rm != PC)
            if ((it.raw >> 28) & 0xF) != 0xF and (it.raw & 0x0FEF0FF0) == 0x01A00000:
                rd, rm = (it.raw >> 12) & 0xF, it.raw & 0xF
                if rd != 15 and rm != 15 and rd != rm:
                    n += 1
    return n


def m_arm_regcopy(
    text: str,
    target_items: list[ArmItem] | None,
    ours_items: list[ArmItem] | None,
    cap: int = 3,
) -> Iterator[tuple[str, str]]:
    """C89-safe ARM/Thumb register-copy temp introduction or elimination (`agbcc`-compatible!)."""
    if not target_items or not ours_items:
        return
    want = _arm_reg_move_count(target_items) - _arm_reg_move_count(ours_items)
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
            ln = lines[i]
            if "volatile" in ln or _CALL_RE.search(ln):
                continue
            m = assign_re.match(ln)
            if not m:
                continue
            ind, lhs, rhs = m.groups()
            for u in sorted(_idents(rhs) - {lhs}):
                utype = vtypes.get(u)
                if not utype:
                    continue
                if re.search(r"(?:\.|->)\s*" + re.escape(u) + r"\b", rhs):
                    continue
                tname = f"ac_rc{made}"
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
                    yield "arm_regcopy", cand
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
            if t == u or sum(1 for ln in lines if re.search(r"\b" + re.escape(t) + r"\s*=(?!=)", ln)) != 1:
                continue
            if sum(1 for ln in lines[i + 1 :] if re.search(r"\b" + re.escape(u) + r"\s*(?:[+\-*/%&|^]?=|\+\+|--)", ln)):
                continue
            out = lines[:i] + lines[i + 1 :]
            bare = re.compile(r"(?<![\w.])(?<!->)" + re.escape(t) + r"\b")
            for j in range(i, len(out)):
                out[j] = bare.sub(u, out[j])
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
                yield "arm_regcopy", cand


def _thumb_hireg_spills(items: list[ArmItem] | None) -> int:
    """Count Thumb-1 high-register (`r8-r11`, `ip`) spill `mov` instructions."""
    n = 0
    for it in items or []:
        if it.mode == "t16" and (it.raw & 0xFF00) == 0x4600 and it.raw != 0x46C0:
            rd = ((it.raw >> 4) & 8) | (it.raw & 7)
            rm = (it.raw >> 3) & 0xF
            if rd in (8, 9, 10, 11, 12) or rm in (8, 9, 10, 11, 12):
                n += 1
    return n


def _thumb_callee_saved_count(items: list[ArmItem] | None) -> int:
    """Count `r4-r7` callee-saved registers in Thumb `push {...}` prologue (`0xB400..0xB5FF`)."""
    for it in (items or [])[:3]:
        if it.mode == "t16" and (it.raw & 0xFE00) == 0xB400:
            return (it.raw & 0xF0).bit_count()
    return 0


def m_arm_thumb_hireg_spill(
    text: str,
    target_items: list[ArmItem] | None,
    ours_items: list[ArmItem] | None,
    cap: int = 3,
) -> Iterator[tuple[str, str]]:
    """Adjust Thumb low-register (`r0-r7`) pressure when `r8-r12` spill or `push {r4-r7}` counts differ."""
    if not target_items or not ours_items:
        return
    o_hi = _thumb_hireg_spills(ours_items)
    t_hi = _thumb_hireg_spills(target_items)
    o_cs = _thumb_callee_saved_count(ours_items)
    t_cs = _thumb_callee_saved_count(target_items)
    if o_hi == t_hi and o_cs == t_cs:
        return
    seen = {text}
    made = 0

    if o_hi > t_hi or (o_hi == t_hi and o_cs > t_cs):
        # Ours spills to r8-r12 or uses more r4-r7 than target: sink address aliases!
        for _, cand in m_alias_sink(text):
            if cand not in seen:
                seen.add(cand)
                made += 1
                yield "arm_hireg_sink", cand
                if made >= cap:
                    return
    else:
        # Target spills to r8-r12 or allocates an extra `r4-r7` (`agbcc -O2` classic!):
        lines = text.split("\n")
        sig_idx = next(
            (i for i, l in enumerate(lines) if l.rstrip().endswith("{") and "(" in l and not l.startswith((" ", "\t"))),
            None,
        )
        if sig_idx is not None:
            idx_m = re.search(r"(\b\w+)\[\s*(\w+->\w+|M2C_FIELD\([^()]+\))\s*\]", text)
            if idx_m and made < cap:
                arr_n, idx_e = idx_m.group(1), idx_m.group(2)
                ln_idx = next((k for k in range(sig_idx + 1, len(lines)) if idx_m.group(0) in lines[k]), None)
                if ln_idx is not None:
                    ind = re.match(r"[ \t]*", lines[ln_idx]).group(0)
                    out = lines[:]
                    out[ln_idx] = lines[ln_idx].replace(idx_m.group(0), f"{arr_n}[ac_r4]", 1)
                    out.insert(ln_idx, f"{ind}ac_r4 = {idx_e};")
                    out.insert(sig_idx + 1, "    register s32 ac_r4;")
                    cand_h = "\n".join(out)
                    if cand_h not in seen:
                        seen.add(cand_h)
                        made += 1
                        yield "arm_hireg_hoist_idx", cand_h
            for m in re.finditer(r"^([ \t]{2,8})((?:s32|u32|int|unsigned|u8\s*\*|s32\s*\*|void\s*\*|[A-Za-z_]\w*\s*\*))\s*(\w+)\s*;$", text, re.M):
                if made >= cap:
                    return
                cand = text[: m.start()] + f"{m.group(1)}register {m.group(2)} {m.group(3)};" + text[m.end() :]
                if cand not in seen:
                    seen.add(cand)
                    made += 1
                    yield "arm_hireg_pin", cand


def m_arm_ptrstep_rescale(text: str, target_items: list[ArmItem] | None, cap: int = 2) -> Iterator[tuple[str, str]]:
    """Rescale `p += K` / `p -= K` pointer steps using target ARM/Thumb `add`/`sub`/`adds`/`subs` immediates."""
    imms: set[int] = set()
    for it in target_items or []:
        mn = disasm_arm_item(it)[0].removesuffix(".w")
        if mn in ("add", "adds", "sub", "subs"):
            imm = _alu_immediate_arm(it)
            if imm is not None and 0 < abs(imm) <= 0x4000:
                imms.add(abs(imm))
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
                    yield "arm_ptrstep", cand
                    if made >= cap:
                        return


def m_arm_bic_and_shift(text: str, target_items: list[ArmItem] | None, cap: int = 4) -> Iterator[tuple[str, str]]:
    """Target ARM/Thumb `bic`/`bics` (`x & ~m`) and barrel-shifter multiply-by-3/5/9 (`x + (x << k)`)."""
    seen = {text}
    made = 0
    has_bic = any(disasm_arm_item(it)[0].startswith("bic") for it in (target_items or []))
    if has_bic:
        # `x &= 0xFFFE` / `x & 0xFFFFFFFE` -> `x &= ~1` / `x & ~1`
        for m in re.finditer(r"(&=?\s*)0x([Ff]{2,7}[0-9A-Fa-f]{1,2})\b", text):
            if made >= cap:
                return
            op_s, hex_s = m.groups()
            nbits = len(hex_s) * 4
            inv = ((1 << nbits) - 1) ^ int(hex_s, 16)
            if 0 < inv <= 0xFF:
                cand = text[: m.start()] + f"{op_s}~0x{inv:X}" + text[m.end() :]
                if cand not in seen:
                    seen.add(cand)
                    made += 1
                    yield "arm_bic_mask", cand

    # Barrel-shifter constant multiply <-> shift-add (`x * 3` <-> `x + (x << 1)`, `x * 5` <-> `x + (x << 2)`)
    shift_map = {3: 1, 5: 2, 9: 3}
    for m in re.finditer(r"\b([A-Za-z_]\w*)\s*\*\s*([359])\b", text):
        if made >= cap:
            return
        var, mult_s = m.group(1), int(m.group(2))
        if var in _C_KEYWORDS:
            continue
        sh = shift_map[mult_s]
        cand = text[: m.start()] + f"({var} + ({var} << {sh}))" + text[m.end() :]
        if cand not in seen:
            seen.add(cand)
            made += 1
            yield "arm_shift_add", cand


def _thumb_narrow_shift_pairs(items: list[ArmItem] | None) -> int:
    """Count Thumb-1 `lsls Rd, Rs, #16/#24` followed by `lsrs`/`asrs Rd, Rd, #16/#24` truncation pairs."""
    if not items:
        return 0
    n = 0
    for k in range(len(items) - 1):
        a, b = items[k], items[k + 1]
        if a.mode == "t16" and b.mode == "t16":
            # lsls #24 (`0x0600`) or #16 (`0x0400`) + lsrs/asrs #24/#16 (`0x0E00`/`0x1600`/`0x0C00`/`0x1400`)
            if (a.raw & 0xFFC0) in (0x0600, 0x0400) and (b.raw & 0xFFC0) in (0x0E00, 0x1600, 0x0C00, 0x1400):
                n += 1
    return n


def m_arm_widen_thumb_narrow(
    text: str,
    target_items: list[ArmItem] | None,
    ours_items: list[ArmItem] | None,
) -> Iterator[tuple[str, str]]:
    """Eliminate spurious `agbcc` Thumb `lsls #16/#24; lsrs/asrs #16/#24` truncations on params, locals, & prototypes!"""
    if ours_items is not None and target_items is not None:
        o_pairs = _thumb_narrow_shift_pairs(ours_items)
        t_pairs = _thumb_narrow_shift_pairs(target_items)
        o_prolog_shift = any(
            it.mode == "t16" and (it.raw & 0xFFC0) in (0x0600, 0x0400) for it in ours_items[:4]
        )
        t_prolog_shift = any(
            it.mode == "t16" and (it.raw & 0xFFC0) in (0x0600, 0x0400) for it in target_items[:4]
        )
        if o_pairs == t_pairs and o_prolog_shift == t_prolog_shift:
            return
    seen = {text}
    sig = re.search(r"^([^\n;#]*\b\w+\s*\()([^{};]*)(\)\s*\{)", text, re.M)
    if not sig:
        return
    head = text[: sig.start()]
    sig_prefix, sig_params, sig_suffix = sig.groups()
    body_after_sig = text[sig.end() :]

    # 1. Widen narrow parameters of the target function itself (`void fn(u16 arg0)` -> `void fn(s32 arg0)`)
    for wide_p_type in ("s32", "u32"):
        new_params = re.sub(r"\b(?:u8|s8|u16|s16)(\s+\w+)\b", rf"{wide_p_type}\1", sig_params)
        if new_params != sig_params:
            cand_p = head + sig_prefix + new_params + sig_suffix + body_after_sig
            if cand_p not in seen:
                seen.add(cand_p)
                yield "arm_widen_param", cand_p

    # 2. Widen narrow `temp_r*` and `var_r*` locals (`u8 var_r3;` -> `s32 var_r3;`)
    wide_locals_body = re.sub(
        r"^([ \t]+)(?:u8|s8|u16|s16)(\s+(?:temp|var)_r\w*\s*;)",
        r"\1s32\2",
        body_after_sig,
        flags=re.M,
    )
    if wide_locals_body != body_after_sig:
        cand_loc = head + sig.group(0) + wide_locals_body
        if cand_loc not in seen:
            seen.add(cand_loc)
            yield "arm_widen_locals", cand_loc

    # 3. Widen narrow `(u8, s8, u16, s16)` in extern prototypes AND `temp_r*`/`var_r*` locals
    wide_head = head
    prev_h = None
    while prev_h != wide_head:
        prev_h = wide_head
        wide_head = re.sub(
            r"(\bfn_[0-9A-Fa-f]+\s*\([^;{}]*)\b(?:u8|s8|u16|s16)\b",
            r"\1s32",
            wide_head,
        )
    cand_all = wide_head + sig_prefix + re.sub(r"\b(?:u8|s8|u16|s16)(\s+\w+)\b", r"s32\1", sig_params) + sig_suffix + wide_locals_body
    if cand_all not in seen:
        seen.add(cand_all)
        yield "arm_widen_narrow", cand_all
    cand_proto_loc = wide_head + sig.group(0) + wide_locals_body
    if cand_proto_loc not in seen:
        seen.add(cand_proto_loc)
        yield "arm_widen_narrow", cand_proto_loc

    # 4. Strip redundant outer `(u8)`/`(u16)` cast on narrow `M2C_FIELD(..., u8 *, ...) = (u8)(...)`
    stripped = re.sub(
        r"(M2C_FIELD\([^;\n]+,\s*(?:u8|s8|u16|s16)\s*\*\s*,\s*[^)]+\)\s*=\s*)\(\s*(?:u8|s8|u16|s16)\s*\)\s*",
        r"\1",
        text,
    )
    if stripped not in seen:
        seen.add(stripped)
        yield "arm_strip_narrow_store_cast", stripped


def m_arm_agbcc_comma_pin(text: str, cap: int = 3) -> Iterator[tuple[str, str]]:
    """Classic GBA `agbcc` `(0, expr)` comma-expression nudge that swaps `r0-r3` scratch register order in GCC 2.95."""
    lines = text.split("\n")
    sig_idx = next(
        (i for i, l in enumerate(lines) if l.rstrip().endswith("{") and "(" in l and not l.startswith((" ", "\t"))),
        0,
    )
    bin_assign = re.compile(r"^([ \t]+\w+\s*=\s*)([A-Za-z_]\w*)\s*(\+|\||&|\^)\s*([A-Za-z_]\w*)\s*;\s*$")
    seen = {text}
    made = 0
    for i in range(sig_idx + 1, len(lines)):
        if made >= cap:
            return
        m = bin_assign.match(lines[i])
        if not m:
            continue
        lhs_eq, a, op, b = m.groups()
        out = lines[:]
        out[i] = f"{lhs_eq}(0, {a}) {op} {b};"
        cand = "\n".join(out)
        if cand not in seen:
            seen.add(cand)
            made += 1
            yield "arm_agbcc_comma", cand


def _arm_sp_sub(items: list[ArmItem] | None) -> int | None:
    for it in (items or [])[:6]:
        if it.mode == "t16" and (it.raw & 0xFF80) == 0xB080:
            return (it.raw & 0x7F) * 4
        if it.mode == "a" and (it.raw & 0x0FFF0000) == 0x024DD000:
            from kintoun.arch.arm_disasm import _ror32

            return _ror32(it.raw & 0xFF, ((it.raw >> 8) & 0xF) * 2)
    return None


def m_arm_frame_pad(
    text: str,
    target_items: list[ArmItem] | None,
    ours_items: list[ArmItem] | None,
) -> Iterator[tuple[str, str]]:
    """Resize stack arrays or add a volatile stack pad to match target `sub sp, #N`."""
    cur = _arm_sp_sub(ours_items)
    want = _arm_sp_sub(target_items)
    if cur is None and want is None:
        return
    cur_v = cur or 0
    want_v = want or 0
    if cur_v == want_v:
        return
    delta = want_v - cur_v
    arr_re = re.compile(r"^([ \t]+(?:unsigned\s+char|u8|s8|char|s32|u32|int)\s+\w+\[)(\d+)(\];)", re.M)
    m = arr_re.search(text)
    if m:
        esz = 4 if any(t in m.group(1) for t in ("s32", "u32", "int")) else 1
        if delta % esz == 0:
            new_n = int(m.group(2)) + (delta // esz)
            if 1 <= new_n <= 4096:
                yield "arm_frame", text[: m.start(2)] + str(new_n) + text[m.end(2) :]
                return
    if delta > 0 and delta % 4 == 0 and "ac_sp_pad[" not in text:
        sig = re.search(r"^[^\n;#]*\b\w+\s*\([^{};]*\)\s*\{", text, re.M)
        if sig:
            yield "arm_frame", text[: sig.end()] + f"\n    volatile int ac_sp_pad[{delta // 4}];" + text[sig.end() :]


def directed_arm(
    text: str,
    result: dict[str, Any] | None,
    target_items: list[ArmItem] | None = None,
    ours_items: list[ArmItem] | None = None,
    ctx: Any = None,
) -> Iterator[tuple[str, str]]:
    """Full score- and target-instruction-directed ARM/Thumb proposal generator."""
    seen: set[str] = {text}
    repairs = (result or {}).get("repairs") or []
    unresolved = (result or {}).get("_unresolved") or {}
    ext = getattr(ctx, "external", None) if ctx is not None else None
    objs = getattr(ctx, "objs", None) if ctx is not None else None
    funcs = getattr(ctx, "by_addr", None) if ctx is not None else None
    read_mem = getattr(ctx, "read", None) if ctx is not None else None

    def _dedup(it: Iterator[tuple[str, str]]) -> Iterator[tuple[str, str]]:
        for fam, cand in it:
            if cand and cand not in seen:
                seen.add(cand)
                yield fam, cand

    # 1. Unresolved relocation / `.rodata` pool repairs first!
    if unresolved:
        yield from _dedup(arm_seeds.arm_extern_relocs(text, unresolved, target_items, read_mem=read_mem))

    # 2. Direct instruction-backed repairs (literal, pool, field_offset, callee, global)
    yield from _dedup(arm_guidance.repair_proposals(text, result))
    yield from _dedup(_apply_callee_and_global_repairs(text, repairs, ext))

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

    # 3. Target-instruction-guided ARM/Thumb mutations (pool order, load/store order, regcopy, Thumb spill, etc.)
    yield from _dedup(m_arm_pool_order(text, target_items, ours_items, external=ext))
    yield from _dedup(m_arm_widen_thumb_narrow(text, target_items, ours_items))
    yield from _dedup(m_arm_store_tgtorder(text, target_items, ours_items))
    yield from _dedup(m_arm_load_tgtorder(text, target_items, ours_items))
    yield from _dedup(m_arm_regcopy(text, target_items, ours_items))
    yield from _dedup(m_arm_thumb_hireg_spill(text, target_items, ours_items))
    yield from _dedup(m_arm_ptrstep_rescale(text, target_items))
    yield from _dedup(m_arm_bic_and_shift(text, target_items))
    yield from _dedup(m_arm_frame_pad(text, target_items, ours_items))

    # 4. Target-backed ARM/Thumb seed transforms (`raw_pool_rebase`, `or_merge`, `dma_flush`, `shift_cast`)
    yield from _dedup(
        arm_seeds.arm_seed_variants(
            text,
            target_items=target_items,
            objects=objs,
            functions=funcs,
        )
    )

    # 5. Near-miss statement-scheduling & switch-case permutations (filtered through C89 declaration hoist!)
    if arm_guidance.near_miss(result):
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
                for fam, cand in order_fn(text):
                    # `__typeof__` hoists in `m_constarg_hoist`/`m_cholit_order` are GCC-valid even in `agbcc`!
                    from kintoun.search.mips_seeds import hoist_c89_declarations

                    c89_cand = hoist_c89_declarations(cand)
                    if c89_cand not in seen:
                        seen.add(c89_cand)
                        yield fam, c89_cand
            except Exception:
                continue
        yield from _dedup(m_arm_agbcc_comma_pin(text))

    if "switch (" in text or "switch(" in text:
        yield from _dedup(m_case_order(text))
        yield from _dedup(m_caseswap_order(text))
        yield from _dedup(m_switch_lower(text))

    # 6. Universal standard-C struct/narrow/commute/loop rewrites
    yield from _dedup(m_c_struct_store_swap(text))
    yield from _dedup(m_c_narrow_local(text))
    yield from _dedup(m_c_commute_general(text))
    yield from _dedup(m_c_for_while_do(text))
