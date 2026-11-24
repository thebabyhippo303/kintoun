"""ARM/Thumb instruction-backed C repair hypotheses.

Covers `callee` (`BL`/`BLX`), `global` (literal-pool symbol pointers and `MOVW`+`MOVT`),
`literal` (shifted immediates, Thumb `movs`/`adds`/`cmp`, `MOVW`/`MOVT`, and `$d`
literal-pool `.word` constants), `field_offset`, `frame`/`push`-`pop`,
`thumb_width`, and `interworking` (`BL` vs `BLX`).
"""
from __future__ import annotations

from typing import Any

from kintoun.arch.arm_disasm import ARM_REGS, _ror32, disasm_a32, disasm_thumb16, disasm_thumb32
from kintoun.arch.arm_elf import _sext, symbol_name_arm
from kintoun.search.arm_score import ArmItem, disasm_arm_item
from kintoun.search.mips_repairs import _signed_immediate_edit
from kintoun.search.repairs import signed


def _call_target_arm(item: ArmItem, base_va: int, fn_end_va: int = 0) -> tuple[int, str] | None:
    """Return `(target_even_va, 'bl'|'blx'|'b')` if `item` is a direct A32/Thumb call or external tail-call."""
    pc = (base_va & ~1) + item.offset
    even_base = base_va & ~1
    if item.mode == "a":
        w = item.raw
        if ((w >> 28) & 0xF) == 0xF and (w & 0xFE000000) == 0xFA000000:
            h = (w >> 24) & 1
            off = _sext(((w & 0x00FFFFFF) << 2) | (h << 1), 26)
            return ((pc + 8 + off) & 0xFFFFFFFF) & ~1, "blx"
        if ((w >> 28) & 0xF) != 0xF and ((w >> 25) & 7) == 5:
            is_bl = bool((w >> 24) & 1)
            off = _sext((w & 0x00FFFFFF) << 2, 26)
            dest = ((pc + 8 + off) & 0xFFFFFFFF) & ~1
            if is_bl:
                return dest, "bl"
            if fn_end_va and not (even_base <= dest < fn_end_va):
                return dest, "b"
    elif item.mode == "t32":
        h1, h2 = item.raw, item.hw2
        if (h1 & 0xF800) == 0xF000 and (h2 & 0x8000) == 0x8000:
            op2 = (h2 >> 12) & 7
            if op2 in (4, 5, 6, 7):
                s = (h1 >> 10) & 1
                j1, j2 = (h2 >> 13) & 1, (h2 >> 11) & 1
                i1, i2 = (~(j1 ^ s)) & 1, (~(j2 ^ s)) & 1
                is_bl = bool((h2 >> 12) & 1)
                imm11 = (h2 & 0x7FF) if is_bl else (h2 & 0x7FE)
                off = _sext((s << 24) | (i1 << 23) | (i2 << 22) | ((h1 & 0x3FF) << 12) | (imm11 << 1), 25)
                base = (pc + 4) if is_bl else ((pc + 4) & ~3)
                return ((base + off) & 0xFFFFFFFF) & ~1, ("bl" if is_bl else "blx")
            if op2 in (1, 3):  # B.W unconditional tail-call
                s = (h1 >> 10) & 1
                j1, j2 = (h2 >> 13) & 1, (h2 >> 11) & 1
                i1, i2 = (~(j1 ^ s)) & 1, (~(j2 ^ s)) & 1
                off = _sext((s << 24) | (i1 << 23) | (i2 << 22) | ((h1 & 0x3FF) << 12) | ((h2 & 0x7FF) << 1), 25)
                dest = ((pc + 4 + off) & 0xFFFFFFFF) & ~1
                if fn_end_va and not (even_base <= dest < fn_end_va):
                    return dest, "b.w"
    return None


def _movw_movt_pairs(items: list[ArmItem]) -> dict[int, tuple[int, int]]:
    """Map index of `MOVT` to `(movw_idx, full_u32)` for adjacent/paired `MOVW`+`MOVT` on the same Rd."""
    active: dict[int, tuple[int, int]] = {}
    out: dict[int, tuple[int, int]] = {}
    for k, it in enumerate(items):
        if it.mode == "a" and (it.raw & 0x0FB00000) == 0x03000000:
            is_movt = (it.raw >> 22) & 1
            rd = (it.raw >> 12) & 0xF
            imm16 = ((it.raw >> 4) & 0xF000) | (it.raw & 0xFFF)
            if not is_movt:
                active[rd] = (k, imm16)
            elif rd in active:
                w_idx, lo16 = active.pop(rd)
                out[k] = (w_idx, ((imm16 << 16) | lo16) & 0xFFFFFFFF)
        elif it.mode == "t32" and (it.raw & 0xFB70) == 0xF240 and (it.hw2 & 0x8000) == 0:
            is_movt = (it.raw >> 7) & 1
            rd = (it.hw2 >> 8) & 0xF
            imm16 = ((it.raw & 0xF) << 12) | (((it.raw >> 10) & 1) << 11) | (((it.hw2 >> 12) & 7) << 8) | (it.hw2 & 0xFF)
            if not is_movt:
                active[rd] = (k, imm16)
            elif rd in active:
                w_idx, lo16 = active.pop(rd)
                out[k] = (w_idx, ((imm16 << 16) | lo16) & 0xFFFFFFFF)
    return out


def _mem_offset_arm(item: ArmItem) -> tuple[int, int] | None:
    """Return `(base_reg, byte_offset)` if `item` is an immediate-offset memory load/store on a general register."""
    if item.mode == "a":
        w = item.raw
        if ((w >> 28) & 0xF) == 0xF:
            return None
        top3 = (w >> 25) & 7
        if top3 == 2 and ((w >> 24) & 1):  # pre-indexed LDR/STR/LDRB/STRB imm12
            rn = (w >> 16) & 0xF
            if rn in (13, 15):
                return None
            u = (w >> 23) & 1
            off = (w & 0xFFF) if u else -(w & 0xFFF)
            return rn, off
        if top3 == 0 and (w & 0x90) == 0x90 and (w & 0x60) != 0 and ((w >> 22) & 1) and ((w >> 24) & 1):
            rn = (w >> 16) & 0xF
            if rn in (13, 15):
                return None
            u = (w >> 23) & 1
            off = (((w >> 8) & 0xF) << 4) | (w & 0xF)
            return rn, (off if u else -off)
    elif item.mode == "t16":
        h = item.raw
        top5 = (h >> 11) & 0x1F
        if top5 in (12, 13, 14, 15):  # LDR/STR/LDRB/STRB [rb, #imm5]
            rb = (h >> 3) & 7
            scale = 1 if top5 in (14, 15) else 4
            return rb, ((h >> 6) & 0x1F) * scale
        if top5 in (16, 17):  # LDRH/STRH [rb, #imm5*2]
            rb = (h >> 3) & 7
            return rb, ((h >> 6) & 0x1F) * 2
    elif item.mode == "t32":
        h1, h2 = item.raw, item.hw2
        if (h1 & 0xFE00) == 0xF800:
            rn = h1 & 0xF
            if rn in (13, 15):
                return None
            if (h1 >> 7) & 1:
                return rn, h2 & 0xFFF
            if (h2 & 0x0C00) == 0x0C00:  # immediate pre-indexed +-imm8
                u = (h2 >> 9) & 1
                return rn, (h2 & 0xFF) if u else -(h2 & 0xFF)
    return None


def _alu_immediate_arm(item: ArmItem) -> int | None:
    """Extract constant immediate from A32 / Thumb-16 / Thumb-32 `mov`/`mvn`/`add`/`sub`/`cmp`."""
    if item.mode == "a":
        w = item.raw
        if ((w >> 28) & 0xF) != 0xF and ((w >> 25) & 7) == 1:
            opc = (w >> 21) & 0xF
            val = _ror32(w & 0xFF, ((w >> 8) & 0xF) * 2)
            if opc == 15:  # MVN
                return signed((~val) & 0xFFFFFFFF, 32)
            if opc in (2, 4, 10, 11, 13):  # SUB, ADD, CMP, CMN, MOV
                return val
        if (w & 0x0FF00000) == 0x03000000:  # MOVW standalone
            return ((w >> 4) & 0xF000) | (w & 0xFFF)
    elif item.mode == "t16":
        h = item.raw
        top5 = (h >> 11) & 0x1F
        if top5 in (4, 5, 6, 7):  # movs / cmp / adds / subs Rd, #imm8
            return h & 0xFF
        if top5 == 3 and (h & 0x0400):  # adds/subs Rd, Rs, #imm3
            return (h >> 6) & 7
    elif item.mode == "t32":
        h1, h2 = item.raw, item.hw2
        if (h1 & 0xFBF0) == 0xF240 and (h2 & 0x8000) == 0:  # MOVW standalone
            return ((h1 & 0xF) << 12) | (((h1 >> 10) & 1) << 11) | (((h2 >> 12) & 7) << 8) | (h2 & 0xFF)
    return None


def _frame_info_arm(item: ArmItem) -> tuple[str, Any] | None:
    """Return `('push_pop', reglist_str)` or `('sp_sub', bytes)` for prologue/epilogue stack instructions."""
    mn, op_s = disasm_arm_item(item)
    if mn in ("push", "push.w", "pop", "pop.w"):
        return ("push_pop", f"{mn} {op_s}")
    if item.mode == "t16" and (item.raw & 0xFF80) == 0xB080:  # sub sp, #imm7*4
        return ("sp_sub", (item.raw & 0x7F) * 4)
    if item.mode == "a" and (item.raw & 0x0FFF0000) == 0x024DD000:  # sub sp, sp, #imm
        return ("sp_sub", _ror32(item.raw & 0xFF, ((item.raw >> 8) & 0xF) * 2))
    return None


def hypotheses(
    ours: list[ArmItem],
    target: list[ArmItem],
    source: str,
    va: int,
    symbols: dict[int, str],
    objects: dict[int, tuple[str, int]],
    ops: list[tuple[str, int, int, int, int]] | None = None,
    limit: int = 8,
) -> list[dict[str, Any]]:
    """Build prioritized, instruction-backed ARM/Thumb repair hypotheses from relocated `ArmItem` streams."""
    pairs: list[tuple[int, int]] = []
    if ops:
        for tag, i1, i2, j1, j2 in ops:
            if tag not in ("equal", "replace"):
                continue
            pairs.extend((i1 + k, j1 + k) for k in range(min(i2 - i1, j2 - j1)))
    else:
        pairs = list(zip(range(len(ours)), range(len(target))))

    ours_pool_by_off = {it.offset: it.raw for it in ours if it.mode == "d" and it.size == 4}
    targ_pool_by_off = {it.offset: it.raw for it in target if it.mode == "d" and it.size == 4}
    ours_movt = _movw_movt_pairs(ours)
    targ_movt = _movw_movt_pairs(target)
    consumed_movw_o = {v[0] for v in ours_movt.values()}
    consumed_movw_t = {v[0] for v in targ_movt.values()}
    handled_pool_pairs: set[tuple[int, int]] = set()

    out: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()

    def _emit(rep: dict[str, Any]) -> None:
        key = (rep["category"], str(rep.get("ours")), str(rep.get("target")))
        if key not in seen:
            seen.add(key)
            out.append(rep)

    def _classify_word32_diff(
        val_a: int,
        val_b: int,
        off_o: int,
        off_t: int,
        note: str,
        feeds_call_branch: bool = False,
    ) -> None:
        if val_a == val_b:
            return
        even_a, even_b = val_a & ~1, val_b & ~1
        if feeds_call_branch and (even_a in symbols or even_b in symbols):
            sym_a = symbols.get(even_a, f"0x{even_a:08X}")
            sym_b = symbols.get(even_b, f"0x{even_b:08X}")
            _emit(
                {
                    "ours_offset": off_o,
                    "target_offset": off_t,
                    "confidence": "hypothesis",
                    "category": "callee",
                    "ours": sym_a,
                    "target": sym_b,
                    "action": "Check the called function and its declaration (`ldr`+`bx`/`blx` pool call); do not permute registers around a wrong callee.",
                }
            )
            return
        is_global = (
            val_a in objects or val_b in objects
            or even_a in symbols or even_b in symbols
        )
        base_rep: dict[str, Any] = {
            "ours_offset": off_o,
            "target_offset": off_t,
            "confidence": "hypothesis",
        }
        if is_global:
            sym_a = symbols.get(even_a) or symbol_name_arm(objects, val_a)
            sym_b = symbols.get(even_b) or symbol_name_arm(objects, val_b)
            base_rep.update(
                category="global",
                ours=f"0x{val_a:08X}",
                target=f"0x{val_b:08X}",
                ours_symbol=sym_a,
                target_symbol=sym_b,
                action=f"Use target global `{sym_b}` (0x{val_b:08X}); ours refers to `{sym_a}` (0x{val_a:08X}) via {note}.",
            )
            _emit(base_rep)
        else:
            sa, sb = signed(val_a, 32), signed(val_b, 32)
            locs, edit = _signed_immediate_edit(source, val_a, val_b)
            use_a, use_b = val_a, val_b
            if not edit and sa < 0:
                locs2, edit2 = _signed_immediate_edit(source, sa, sb)
                if edit2 or locs2:
                    locs, edit = locs2, edit2
                    use_a, use_b = sa, sb
            base_rep.update(
                category="literal",
                ours=use_a,
                target=use_b,
                action=f"Test the target 32-bit constant in C ({note}).",
                source_locations=locs,
            )
            if edit:
                base_rep["suggested_edit"] = edit
            _emit(base_rep)

    def _ldr_feeds_bx(stream: list[ArmItem], idx: int) -> bool:
        it = stream[idx]
        if it.mode == "t16" and (it.raw >> 11) == 9:
            rd = (it.raw >> 8) & 7
            for nxt in stream[idx + 1 : idx + 5]:
                if nxt.mode == "t16" and (nxt.raw & 0xFF00) == 0x4700 and ((nxt.raw >> 3) & 0xF) == rd:
                    return True
        return False

    for i, j in pairs:
        ia, ib = ours[i], target[j]
        if ia.mode == ib.mode and ia.raw == ib.raw and ia.hw2 == ib.hw2:
            # Even if the PC-load instruction encoded identical offset, its literal pool word may differ!
            if (
                ia.pool_target_off is not None
                and ib.pool_target_off is not None
                and ia.pool_target_off in ours_pool_by_off
                and ib.pool_target_off in targ_pool_by_off
            ):
                pa, pb = ours_pool_by_off[ia.pool_target_off], targ_pool_by_off[ib.pool_target_off]
                if pa != pb:
                    handled_pool_pairs.add((ia.pool_target_off, ib.pool_target_off))
                    _classify_word32_diff(
                        pa,
                        pb,
                        ia.offset,
                        ib.offset,
                        "PC-relative literal pool",
                        feeds_call_branch=(_ldr_feeds_bx(ours, i) or _ldr_feeds_bx(target, j)),
                    )
            continue

        base_rep: dict[str, Any] = {
            "ours_offset": ia.offset,
            "target_offset": ib.offset,
            "confidence": "hypothesis",
        }

        # 1. Callee & Interworking (`BL` vs `BLX` & external tail-call `B`/`B.W`)
        fn_end = (va & ~1) + max((it.offset + it.size for it in target), default=0)
        ca, cb = _call_target_arm(ia, va, fn_end), _call_target_arm(ib, va, fn_end)
        if ca and cb:
            addr_a, kind_a = ca
            addr_b, kind_b = cb
            if addr_a != addr_b:
                rep = dict(base_rep)
                rep.update(
                    category="callee",
                    ours=symbols.get(addr_a, f"0x{addr_a:08X}"),
                    target=symbols.get(addr_b, f"0x{addr_b:08X}"),
                    action="Check the called function and its declaration; do not permute registers around a wrong callee.",
                )
                _emit(rep)
            elif kind_a != kind_b:
                rep = dict(base_rep)
                rep.update(
                    category="interworking",
                    ours=kind_a,
                    target=kind_b,
                    action=(
                        f"Target uses `{kind_b}` while ours uses `{kind_a}` for `{symbols.get(addr_b, hex(addr_b))}`. "
                        "Check ARM vs Thumb callee state and `-mthumb-interwork`."
                    ),
                )
                _emit(rep)
            continue

        # 2. PC-relative literal pool load (`ldr Rd, [pc, #imm]`): compare resolved pool values!
        if (
            ia.pool_target_off is not None
            and ib.pool_target_off is not None
            and ia.pool_target_off in ours_pool_by_off
            and ib.pool_target_off in targ_pool_by_off
        ):
            pa, pb = ours_pool_by_off[ia.pool_target_off], targ_pool_by_off[ib.pool_target_off]
            handled_pool_pairs.add((ia.pool_target_off, ib.pool_target_off))
            _classify_word32_diff(
                pa,
                pb,
                ia.offset,
                ib.offset,
                "PC-relative literal pool",
                feeds_call_branch=(_ldr_feeds_bx(ours, i) or _ldr_feeds_bx(target, j)),
            )
            continue

        # 3. Direct `$d` literal pool `.word` comparison (if not already reported at its `ldr` site)
        if ia.mode == "d" and ib.mode == "d" and ia.size == 4 and ib.size == 4:
            if (ia.offset, ib.offset) not in handled_pool_pairs:
                _classify_word32_diff(ia.raw, ib.raw, ia.offset, ib.offset, "inline `$d` literal pool")
            continue

        # 4. Paired `MOVW` + `MOVT` 32-bit constant / global
        if i in ours_movt and j in targ_movt:
            _classify_word32_diff(ours_movt[i][1], targ_movt[j][1], ia.offset, ib.offset, "`movw`+`movt` pair")
            continue
        if i in consumed_movw_o or j in consumed_movw_t:
            continue

        # 5. Thumb 16-bit vs 32-bit `.w` instruction width mismatch
        if {ia.mode, ib.mode} == {"t16", "t32"}:
            mna = disasm_arm_item(ia)[0].removesuffix(".w").removesuffix("s")
            mnb = disasm_arm_item(ib)[0].removesuffix(".w").removesuffix("s")
            if mna == mnb:
                rep = dict(base_rep)
                rep.update(
                    category="thumb_width",
                    ours=f"{ia.size * 8}-bit ({disasm_arm_item(ia)[0]})",
                    target=f"{ib.size * 8}-bit ({disasm_arm_item(ib)[0]})",
                    action=(
                        "Thumb 16-bit vs 32-bit `.w` encoding differs for the same operation. "
                        "Check `-march` (`armv4t`/`armv5te` vs Thumb-2) or reduce high-register (`r8-r12`) pressure."
                    ),
                )
                _emit(rep)
                continue

        # 6. Frame / `push`-`pop` mismatch
        fa, fb = _frame_info_arm(ia), _frame_info_arm(ib)
        if fa and fb and fa[0] == fb[0] and fa[1] != fb[1]:
            rep = dict(base_rep)
            rep.update(
                category="frame",
                ours=fa[1],
                target=fb[1],
                action=(
                    "Prologue/epilogue stack frame or `push`/`pop` register mask differs; "
                    "check live values across calls, address-taken locals, and `register` declarations."
                ),
            )
            _emit(rep)
            continue

        # 7. Struct field / array immediate offset on loads/stores
        ma, mb = _mem_offset_arm(ia), _mem_offset_arm(ib)
        if ma and mb and ma[1] != mb[1]:
            mna = disasm_arm_item(ia)[0].removesuffix(".w")
            mnb = disasm_arm_item(ib)[0].removesuffix(".w")
            if mna == mnb:
                rep = dict(base_rep)
                rep.update(
                    category="field_offset",
                    ours=ma[1],
                    target=mb[1],
                    action=(
                        f"Test struct/member byte offset {mb[1]:#x} instead of {ma[1]:#x} "
                        f"on `{ARM_REGS[mb[0]]}`; confirm the base pointer agrees."
                    ),
                )
                _emit(rep)
                continue

        # 8. Immediate ALU / `movs` / `cmp` / `movw` literal mismatch
        la, lb = _alu_immediate_arm(ia), _alu_immediate_arm(ib)
        if la is not None and lb is not None and la != lb:
            mna = disasm_arm_item(ia)[0].removesuffix(".w").removesuffix("s")
            mnb = disasm_arm_item(ib)[0].removesuffix(".w").removesuffix("s")
            if mna == mnb or {mna, mnb} <= {"mov", "mvn", "movw"}:
                rep = dict(base_rep)
                rep.update(
                    category="literal",
                    ours=la,
                    target=lb,
                    action="Test the target integer immediate constant in C.",
                )
                locs, edit = _signed_immediate_edit(source, la, lb)
                rep["source_locations"] = locs
                if edit:
                    rep["suggested_edit"] = edit
                _emit(rep)

    priority = {
        "callee": 0,
        "interworking": 1,
        "global": 2,
        "literal": 3,
        "field_offset": 4,
        "thumb_width": 5,
        "frame": 6,
    }
    return sorted(out, key=lambda item: priority.get(item["category"], 9))[:limit]
