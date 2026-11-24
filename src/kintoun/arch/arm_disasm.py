"""Pure-stdlib disassembler for A32, Thumb-16 (ARMv4T/v5TE), Thumb-2 (32-bit), and `$d` literal pools."""
from __future__ import annotations

ARM_REGS: tuple[str, ...] = (
    "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7",
    "r8", "r9", "r10", "r11", "r12", "sp", "lr", "pc",
)

COND_NAMES: tuple[str, ...] = (
    "eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc",
    "hi", "ls", "ge", "lt", "gt", "le", "", "nv",
)

_DP_OPS: tuple[str, ...] = (
    "and", "eor", "sub", "rsb", "add", "adc", "sbc", "rsc",
    "tst", "teq", "cmp", "cmn", "orr", "mov", "bic", "mvn",
)
_THUMB_ALU_OPS: tuple[str, ...] = (
    "ands", "eors", "lsls", "lsrs", "asrs", "adcs", "sbcs", "rors",
    "tst", "negs", "cmp", "cmn", "orrs", "muls", "bics", "mvns",
)
_SHIFT_TYPES: tuple[str, ...] = ("lsl", "lsr", "asr", "ror")


def _sext(val: int, bits: int) -> int:
    mask = (1 << bits) - 1
    val &= mask
    return val - (1 << bits) if val & (1 << (bits - 1)) else val


def _ror32(val: int, rot: int) -> int:
    val &= 0xFFFFFFFF
    rot &= 31
    return ((val >> rot) | ((val << (32 - rot)) & 0xFFFFFFFF)) if rot else val


def _fmt_reglist(mask: int) -> str:
    names: list[str] = []
    i = 0
    while i < 16:
        if not (mask & (1 << i)):
            i += 1
            continue
        j = i
        while j + 1 < 16 and (mask & (1 << (j + 1))):
            j += 1
        if j - i >= 2 and j < 13:
            names.append(f"{ARM_REGS[i]}-{ARM_REGS[j]}")
        else:
            for k in range(i, j + 1):
                names.append(ARM_REGS[k])
        i = j + 1
    return "{" + ", ".join(names) + "}"


def _fmt_imm(val: int) -> str:
    if -9 <= val <= 9:
        return f"#{val}"
    return f"#-0x{-val:x}" if val < 0 else f"#0x{val:x}"


def is_thumb32_hw1(hw1: int) -> bool:
    """Return True if 16-bit Thumb halfword `hw1` starts a 32-bit Thumb/Thumb-2 instruction."""
    return (hw1 & 0xF800) in (0xE800, 0xF000, 0xF800)


def disasm_a32(word: int, pc: int = 0) -> tuple[str, str]:
    """Disassemble a 32-bit A32 instruction word into `(mnemonic, op_str)`."""
    w = word & 0xFFFFFFFF
    cond = (w >> 28) & 0xF
    c = COND_NAMES[cond]

    if w == 0xE1A00000 or w == 0xE320F000:
        return ("nop", "")

    # Unconditional space (cond == 0xF)
    if cond == 0xF:
        if (w & 0xFE000000) == 0xFA000000:
            h = (w >> 24) & 1
            off = _sext(((w & 0x00FFFFFF) << 2) | (h << 1), 26)
            target = (pc + 8 + off) & 0xFFFFFFFF
            return ("blx", f"0x{target:x}")
        return (".word", f"0x{w:08x}")

    top3 = (w >> 25) & 0x7

    # BX / BLX Rm / CLZ
    if (w & 0x0FFFFFF0) == 0x012FFF10:
        return (f"bx{c}", ARM_REGS[w & 0xF])
    if (w & 0x0FFFFFF0) == 0x012FFF30:
        return (f"blx{c}", ARM_REGS[w & 0xF])
    if (w & 0x0FFF0FF0) == 0x016F0F10:
        rd, rm = (w >> 12) & 0xF, w & 0xF
        return (f"clz{c}", f"{ARM_REGS[rd]}, {ARM_REGS[rm]}")

    # MOVW / MOVT (ARMv6T2+)
    if (w & 0x0FB00000) == 0x03000000:
        is_movt = (w >> 22) & 1
        rd = (w >> 12) & 0xF
        imm16 = ((w >> 4) & 0xF000) | (w & 0xFFF)
        return (f"{'movt' if is_movt else 'movw'}{c}", f"{ARM_REGS[rd]}, #0x{imm16:x}")

    # UXTB / SXTB / UXTH / SXTH / REV
    if (w & 0x0FFF0FF0) == 0x06BF0F30:
        return (f"rev{c}", f"{ARM_REGS[(w >> 12) & 0xF]}, {ARM_REGS[w & 0xF]}")
    if (w & 0x0FBF03F0) in (0x06AF0070, 0x06BF0070):
        op_ext = {
            (0, 0): "sxtb",
            (0, 1): "sxth",
            (1, 0): "uxtb",
            (1, 1): "uxth",
        }.get((((w >> 22) & 1), ((w >> 20) & 1)))
        if op_ext:
            rd, rm = (w >> 12) & 0xF, w & 0xF
            rot = ((w >> 10) & 3) * 8
            rot_s = f", ror #{rot}" if rot else ""
            return (f"{op_ext}{c}", f"{ARM_REGS[rd]}, {ARM_REGS[rm]}{rot_s}")

    # Multiply / MLA / Long Multiply
    if (w & 0x0FC000F0) == 0x00000090:
        acc = (w >> 21) & 1
        s_s = "s" if ((w >> 20) & 1) else ""
        rd, rn, rs, rm = (w >> 16) & 0xF, (w >> 12) & 0xF, (w >> 8) & 0xF, w & 0xF
        if acc:
            return (f"mla{c}{s_s}", f"{ARM_REGS[rd]}, {ARM_REGS[rm]}, {ARM_REGS[rs]}, {ARM_REGS[rn]}")
        return (f"mul{c}{s_s}", f"{ARM_REGS[rd]}, {ARM_REGS[rm]}, {ARM_REGS[rs]}")

    if (w & 0x0F8000F0) == 0x00800090:
        u_s = "s" if ((w >> 22) & 1) else "u"
        acc = "mlal" if ((w >> 21) & 1) else "mull"
        s_s = "s" if ((w >> 20) & 1) else ""
        rdhi, rdlo, rs, rm = (w >> 16) & 0xF, (w >> 12) & 0xF, (w >> 8) & 0xF, w & 0xF
        return (f"{u_s}{acc}{c}{s_s}", f"{ARM_REGS[rdlo]}, {ARM_REGS[rdhi]}, {ARM_REGS[rm]}, {ARM_REGS[rs]}")

    # Halfword / signed byte / doubleword load/store (extra load/store space: top3==0, bit7==1, bit4==1)
    if top3 == 0 and (w & 0x90) == 0x90 and (w & 0x60) != 0:
        p = (w >> 24) & 1
        u = (w >> 23) & 1
        imm_flag = (w >> 22) & 1
        wb = (w >> 21) & 1
        ld = (w >> 20) & 1
        rn, rd = (w >> 16) & 0xF, (w >> 12) & 0xF
        sh = (w >> 5) & 3
        mn_map = {
            (1, 1): "ldrh",
            (0, 1): "strh",
            (1, 2): "ldrsb",
            (1, 3): "ldrsh",
            (0, 2): "ldrd",
            (0, 3): "strd",
        }
        mn = mn_map.get((ld, sh), "ldrh")
        if imm_flag:
            off = (((w >> 8) & 0xF) << 4) | (w & 0xF)
            signed_off = off if u else -off
            off_s = f", {_fmt_imm(signed_off)}" if signed_off else ""
        else:
            sign = "" if u else "-"
            off_s = f", {sign}{ARM_REGS[w & 0xF]}"
        if p:
            addr_s = f"[{ARM_REGS[rn]}{off_s}]{'!' if wb else ''}"
        else:
            addr_s = f"[{ARM_REGS[rn]}]{off_s}"
        return (f"{mn}{c}", f"{ARM_REGS[rd]}, {addr_s}")

    # Data processing (top3 in 0, 1)
    if top3 in (0, 1):
        is_imm = top3 == 1
        opc = (w >> 21) & 0xF
        s_bit = (w >> 20) & 1
        rn, rd = (w >> 16) & 0xF, (w >> 12) & 0xF
        base_mn = _DP_OPS[opc]
        s_s = "s" if (s_bit and opc not in (8, 9, 10, 11)) else ""

        if is_imm:
            imm_val = _ror32(w & 0xFF, ((w >> 8) & 0xF) * 2)
            op2_s = _fmt_imm(imm_val)
        else:
            rm = w & 0xF
            stype = _SHIFT_TYPES[(w >> 5) & 3]
            if (w >> 4) & 1:
                rs = (w >> 8) & 0xF
                op2_s = f"{ARM_REGS[rm]}, {stype} {ARM_REGS[rs]}"
            else:
                sh_amt = (w >> 7) & 0x1F
                if sh_amt == 0 and stype == "lsl":
                    op2_s = ARM_REGS[rm]
                elif opc == 13:  # Shifted MOV -> LSL/LSR/ASR/ROR alias
                    if sh_amt == 0 and stype == "ror":
                        return (f"rrx{c}{s_s}", f"{ARM_REGS[rd]}, {ARM_REGS[rm]}")
                    amt = 32 if (sh_amt == 0 and stype in ("lsr", "asr")) else sh_amt
                    return (f"{stype}{c}{s_s}", f"{ARM_REGS[rd]}, {ARM_REGS[rm]}, #{amt}")
                else:
                    amt = 32 if (sh_amt == 0 and stype in ("lsr", "asr")) else sh_amt
                    op2_s = f"{ARM_REGS[rm]}, {stype} #{amt}"

        if opc in (13, 15):  # mov / mvn
            return (f"{base_mn}{c}{s_s}", f"{ARM_REGS[rd]}, {op2_s}")
        if opc in (8, 9, 10, 11):  # tst / teq / cmp / cmn
            return (f"{base_mn}{c}", f"{ARM_REGS[rn]}, {op2_s}")
        return (f"{base_mn}{c}{s_s}", f"{ARM_REGS[rd]}, {ARM_REGS[rn]}, {op2_s}")

    # Single data transfer LDR / STR / LDRB / STRB (top3 in 2, 3)
    if top3 in (2, 3):
        is_reg = top3 == 3
        if is_reg and (w & 0x10):
            return (".word", f"0x{w:08x}")
        p = (w >> 24) & 1
        u = (w >> 23) & 1
        b_bit = (w >> 22) & 1
        wb = (w >> 21) & 1
        ld = (w >> 20) & 1
        rn, rd = (w >> 16) & 0xF, (w >> 12) & 0xF
        mn = ("ldr" if ld else "str") + ("b" if b_bit else "") + c

        # PUSH / POP single-register aliases (`str rd, [sp, #-4]!` / `ldr rd, [sp], #4`)
        if not b_bit and rn == 13 and not is_reg and (w & 0xFFF) == 4:
            if not ld and p and not u and wb:
                return (f"push{c}", "{" + ARM_REGS[rd] + "}")
            if ld and not p and u and not wb:
                return (f"pop{c}", "{" + ARM_REGS[rd] + "}")

        if not is_reg:
            imm12 = w & 0xFFF
            signed_off = imm12 if u else -imm12
            off_s = f", {_fmt_imm(signed_off)}" if signed_off else ""
        else:
            rm = w & 0xF
            sign = "" if u else "-"
            sh_amt = (w >> 7) & 0x1F
            stype = _SHIFT_TYPES[(w >> 5) & 3]
            sh_s = f", {stype} #{sh_amt}" if sh_amt else ""
            off_s = f", {sign}{ARM_REGS[rm]}{sh_s}"
        addr_s = f"[{ARM_REGS[rn]}{off_s}]{'!' if wb else ''}" if p else f"[{ARM_REGS[rn]}]{off_s}"
        return (mn, f"{ARM_REGS[rd]}, {addr_s}")

    # Block data transfer LDM / STM / PUSH / POP (top3 == 4)
    if top3 == 4:
        p = (w >> 24) & 1
        u = (w >> 23) & 1
        wb = (w >> 21) & 1
        ld = (w >> 20) & 1
        rn = (w >> 16) & 0xF
        reglist = _fmt_reglist(w & 0xFFFF)
        if rn == 13 and wb and not ld and p and not u:
            return (f"push{c}", reglist)
        if rn == 13 and wb and ld and not p and u:
            return (f"pop{c}", reglist)
        mode_sfx = {(0, 0): "da", (0, 1): "ia", (1, 0): "db", (1, 1): "ib"}[(p, u)]
        return (f"{'ldm' if ld else 'stm'}{mode_sfx}{c}", f"{ARM_REGS[rn]}{'!' if wb else ''}, {reglist}")

    # Branch B / BL (top3 == 5)
    if top3 == 5:
        link = (w >> 24) & 1
        off = _sext((w & 0x00FFFFFF) << 2, 26)
        target = (pc + 8 + off) & 0xFFFFFFFF
        return (f"{'bl' if link else 'b'}{c}", f"0x{target:x}")

    return (".word", f"0x{w:08x}")


def disasm_thumb16(hw: int, pc: int = 0) -> tuple[str, str]:
    """Disassemble a 16-bit Thumb instruction into `(mnemonic, op_str)`."""
    h = hw & 0xFFFF
    if h == 0xBF00 or h == 0x46C0:
        return ("nop", "")

    top5 = (h >> 11) & 0x1F

    # Format 1 & 2: shift by imm / add-sub 3-operand (`000xx`)
    if top5 in (0, 1, 2):
        rd, rs = h & 7, (h >> 3) & 7
        imm5 = (h >> 6) & 0x1F
        op_sh = ("lsls", "lsrs", "asrs")[top5]
        if top5 == 0 and imm5 == 0:
            return ("movs", f"{ARM_REGS[rd]}, {ARM_REGS[rs]}")
        amt = 32 if (imm5 == 0 and top5 in (1, 2)) else imm5
        return (op_sh, f"{ARM_REGS[rd]}, {ARM_REGS[rs]}, #{amt}")

    if top5 == 3:
        rd, rs, rn_imm = h & 7, (h >> 3) & 7, (h >> 6) & 7
        op_as = "subs" if ((h >> 9) & 1) else "adds"
        if (h >> 10) & 1:
            return (op_as, f"{ARM_REGS[rd]}, {ARM_REGS[rs]}, #{rn_imm}")
        return (op_as, f"{ARM_REGS[rd]}, {ARM_REGS[rs]}, {ARM_REGS[rn_imm]}")

    # Format 3: movs / cmp / adds / subs immediate (`001xx`)
    if top5 in (4, 5, 6, 7):
        rd = (h >> 8) & 7
        imm8 = h & 0xFF
        mn = ("movs", "cmp", "adds", "subs")[top5 - 4]
        return (mn, f"{ARM_REGS[rd]}, {_fmt_imm(imm8)}")

    # Format 4 & 5: ALU ops (`010000`) & Hi-register ops / BX / BLX (`010001`)
    if (h >> 10) == 0b010000:
        op_alu = (h >> 6) & 0xF
        rs, rd = (h >> 3) & 7, h & 7
        mn = _THUMB_ALU_OPS[op_alu]
        if op_alu == 9:  # negs rd, rs
            return ("negs", f"{ARM_REGS[rd]}, {ARM_REGS[rs]}")
        return (mn, f"{ARM_REGS[rd]}, {ARM_REGS[rs]}")

    if (h >> 10) == 0b010001:
        op_hi = (h >> 8) & 3
        rm = (h >> 3) & 0xF
        rd = ((h >> 4) & 8) | (h & 7)
        if op_hi == 3:
            return ("blx" if (h & 0x80) else "bx", ARM_REGS[rm])
        mn = ("add", "cmp", "mov")[op_hi]
        return (mn, f"{ARM_REGS[rd]}, {ARM_REGS[rm]}")

    # Format 6: PC-relative literal pool load `ldr Rd, [pc, #imm8*4]` (`01001`)
    if top5 == 9:
        rd = (h >> 8) & 7
        off = (h & 0xFF) * 4
        pool_va = ((pc + 4) & ~3) + off
        return ("ldr", f"{ARM_REGS[rd]}, [pc, #{off}] ; @0x{pool_va:x}")

    # Format 7 & 8: register-offset load/store (`0101x`)
    if top5 in (10, 11):
        ro, rb, rd = (h >> 6) & 7, (h >> 3) & 7, h & 7
        subop = (h >> 9) & 7
        mn = ("str", "strh", "strb", "ldrsb", "ldr", "ldrh", "ldrb", "ldrsh")[subop]
        return (mn, f"{ARM_REGS[rd]}, [{ARM_REGS[rb]}, {ARM_REGS[ro]}]")

    # Format 9: word/byte immediate offset load/store (`011xx`)
    if top5 in (12, 13, 14, 15):
        rd, rb = h & 7, (h >> 3) & 7
        imm5 = (h >> 6) & 0x1F
        is_byte = top5 in (14, 15)
        is_load = top5 in (13, 15)
        off = imm5 if is_byte else imm5 * 4
        mn = ("ldr" if is_load else "str") + ("b" if is_byte else "")
        return (mn, f"{ARM_REGS[rd]}, [{ARM_REGS[rb]}, #{off}]")

    # Format 10: halfword immediate offset load/store (`1000x`)
    if top5 in (16, 17):
        rd, rb = h & 7, (h >> 3) & 7
        off = ((h >> 6) & 0x1F) * 2
        return ("ldrh" if top5 == 17 else "strh", f"{ARM_REGS[rd]}, [{ARM_REGS[rb]}, #{off}]")

    # Format 11: SP-relative load/store (`1001x`)
    if top5 in (18, 19):
        rd = (h >> 8) & 7
        off = (h & 0xFF) * 4
        return ("ldr" if top5 == 19 else "str", f"{ARM_REGS[rd]}, [sp, #{off}]")

    # Format 12: ADR / ADD Rd, sp, #imm (`1010x`)
    if top5 in (20, 21):
        rd = (h >> 8) & 7
        off = (h & 0xFF) * 4
        base = "sp" if top5 == 21 else "pc"
        return ("add", f"{ARM_REGS[rd]}, {base}, #{off}")

    # Miscellaneous 16-bit (`1011xxxx`)
    if top5 in (22, 23):
        sub8 = (h >> 8) & 0xF
        if sub8 == 0:  # add/sub sp, #imm7*4
            off = (h & 0x7F) * 4
            return ("sub" if (h & 0x80) else "add", f"sp, sp, #{off}")
        if sub8 in (1, 3, 9, 11):  # CBZ / CBNZ (Thumb-2)
            rn = h & 7
            off = (((h >> 9) & 1) << 6) | (((h >> 3) & 0x1F) << 1)
            target = (pc + 4 + off) & 0xFFFFFFFF
            return ("cbnz" if (h & 0x0800) else "cbz", f"{ARM_REGS[rn]}, 0x{target:x}")
        if sub8 == 2:  # SXTH / SXTB / UXTH / UXTB
            rd, rm = h & 7, (h >> 3) & 7
            mn = ("sxth", "sxtb", "uxth", "uxtb")[(h >> 6) & 3]
            return (mn, f"{ARM_REGS[rd]}, {ARM_REGS[rm]}")
        if sub8 in (4, 5):  # PUSH {reglist [, lr]}
            mask = (h & 0xFF) | (0x4000 if (h & 0x0100) else 0)
            return ("push", _fmt_reglist(mask))
        if sub8 == 10:  # REV / REV16 / REVSH
            rd, rm = h & 7, (h >> 3) & 7
            op_rev = (h >> 6) & 3
            if op_rev in (0, 1, 3):
                mn = {0: "rev", 1: "rev16", 3: "revsh"}[op_rev]
                return (mn, f"{ARM_REGS[rd]}, {ARM_REGS[rm]}")
        if sub8 in (12, 13):  # POP {reglist [, pc]}
            mask = (h & 0xFF) | (0x8000 if (h & 0x0100) else 0)
            return ("pop", _fmt_reglist(mask))
        if sub8 == 14:
            return ("bkpt", f"#0x{h & 0xFF:x}")
        if sub8 == 15 and (h & 0xF) != 0:  # IT block
            cond_first = (h >> 4) & 0xF
            return ("it", COND_NAMES[cond_first])

    # Format 15: STMIA / LDMIA (`1100x`)
    if top5 in (24, 25):
        rb = (h >> 8) & 7
        reglist = _fmt_reglist(h & 0xFF)
        return ("ldmia" if top5 == 25 else "stmia", f"{ARM_REGS[rb]}!, {reglist}")

    # Format 16 & 17: Conditional branch `B<cond>` / `SVC` (`1101x`)
    if top5 in (26, 27):
        cond = (h >> 8) & 0xF
        if cond == 15:
            return ("svc", f"#0x{h & 0xFF:x}")
        if cond < 14:
            off = _sext((h & 0xFF) << 1, 9)
            target = (pc + 4 + off) & 0xFFFFFFFF
            return (f"b{COND_NAMES[cond]}", f"0x{target:x}")

    # Format 18: Unconditional branch `B` (`11100`)
    if top5 == 28:
        off = _sext((h & 0x7FF) << 1, 12)
        target = (pc + 4 + off) & 0xFFFFFFFF
        return ("b", f"0x{target:x}")

    return (".short", f"0x{h:04x}")


def disasm_thumb32(hw1: int, hw2: int, pc: int = 0) -> tuple[str, str]:
    """Disassemble a 32-bit Thumb / Thumb-2 instruction `(hw1, hw2)` into `(mnemonic, op_str)`."""
    h1, h2 = hw1 & 0xFFFF, hw2 & 0xFFFF

    # BL / BLX / B.W / B<cond>.W (`11110...` + `10...`/`11...`)
    if (h1 & 0xF800) == 0xF000 and (h2 & 0x8000) == 0x8000:
        op2 = (h2 >> 12) & 0x7
        if op2 in (5, 7):  # BL (`11x1`)
            s = (h1 >> 10) & 1
            j1, j2 = (h2 >> 13) & 1, (h2 >> 11) & 1
            i1, i2 = (~(j1 ^ s)) & 1, (~(j2 ^ s)) & 1
            off = _sext((s << 24) | (i1 << 23) | (i2 << 22) | ((h1 & 0x3FF) << 12) | ((h2 & 0x7FF) << 1), 25)
            return ("bl", f"0x{(pc + 4 + off) & 0xFFFFFFFF:x}")
        if op2 in (4, 6):  # BLX (`11x0`)
            s = (h1 >> 10) & 1
            j1, j2 = (h2 >> 13) & 1, (h2 >> 11) & 1
            i1, i2 = (~(j1 ^ s)) & 1, (~(j2 ^ s)) & 1
            off = _sext((s << 24) | (i1 << 23) | (i2 << 22) | ((h1 & 0x3FF) << 12) | ((h2 & 0x7FE) << 1), 25)
            target = (((pc + 4) & ~3) + off) & 0xFFFFFFFF
            return ("blx", f"0x{target:x}")
        if op2 in (1, 3):  # B.W unconditional (`10x1`)
            s = (h1 >> 10) & 1
            j1, j2 = (h2 >> 13) & 1, (h2 >> 11) & 1
            i1, i2 = (~(j1 ^ s)) & 1, (~(j2 ^ s)) & 1
            off = _sext((s << 24) | (i1 << 23) | (i2 << 22) | ((h1 & 0x3FF) << 12) | ((h2 & 0x7FF) << 1), 25)
            return ("b.w", f"0x{(pc + 4 + off) & 0xFFFFFFFF:x}")
        if op2 in (0, 2) and ((h1 >> 6) & 0xF) < 14:  # B<cond>.W (`10x0`)
            cond = (h1 >> 6) & 0xF
            s = (h1 >> 10) & 1
            j1, j2 = (h2 >> 13) & 1, (h2 >> 11) & 1
            off = _sext((s << 20) | (j2 << 19) | (j1 << 18) | ((h1 & 0x3F) << 12) | ((h2 & 0x7FF) << 1), 21)
            return (f"b{COND_NAMES[cond]}.w", f"0x{(pc + 4 + off) & 0xFFFFFFFF:x}")

    # MOVW / MOVT (`11110 i 100100 imm4` / `11110 i 101100 imm4`, `0 imm3 Rd imm8`)
    if (h1 & 0xFB70) == 0xF240 and (h2 & 0x8000) == 0:
        is_movt = (h1 >> 7) & 1
        rd = (h2 >> 8) & 0xF
        imm16 = ((h1 & 0xF) << 12) | (((h1 >> 10) & 1) << 11) | (((h2 >> 12) & 7) << 8) | (h2 & 0xFF)
        return ("movt" if is_movt else "movw", f"{ARM_REGS[rd]}, #0x{imm16:x}")

    # ADDW / SUBW (`11110 i 100000 Rn` / `11110 i 101010 Rn`)
    if (h1 & 0xFB50) == 0xF200 and (h2 & 0x8000) == 0:
        is_sub = (h1 >> 7) & 1
        rn, rd = h1 & 0xF, (h2 >> 8) & 0xF
        imm12 = (((h1 >> 10) & 1) << 11) | (((h2 >> 12) & 7) << 8) | (h2 & 0xFF)
        return ("subw" if is_sub else "addw", f"{ARM_REGS[rd]}, {ARM_REGS[rn]}, {_fmt_imm(imm12)}")

    # PUSH.W / POP.W / LDM.W / STM.W (`1110100 xx0 W L Rn`)
    if (h1 & 0xFE40) == 0xE800:
        op_m = (h1 >> 7) & 3
        wb = (h1 >> 5) & 1
        ld = (h1 >> 4) & 1
        rn = h1 & 0xF
        reglist = _fmt_reglist(h2)
        if rn == 13 and wb and not ld and op_m == 2:
            return ("push.w", reglist)
        if rn == 13 and wb and ld and op_m == 1:
            return ("pop.w", reglist)
        sfx = "db.w" if op_m == 2 else "ia.w"
        return (f"{'ldm' if ld else 'stm'}{sfx}", f"{ARM_REGS[rn]}{'!' if wb else ''}, {reglist}")

    # LDRD / STRD (`1110100 P U 1 W L Rn`, `Rt Rt2 imm8`)
    if (h1 & 0xFE40) == 0xE840:
        p = (h1 >> 8) & 1
        u = (h1 >> 7) & 1
        wb = (h1 >> 5) & 1
        ld = (h1 >> 4) & 1
        rn = h1 & 0xF
        rt, rt2 = (h2 >> 12) & 0xF, (h2 >> 8) & 0xF
        off = (h2 & 0xFF) * 4
        signed_off = off if u else -off
        addr_s = f"[{ARM_REGS[rn]}, {_fmt_imm(signed_off)}]{'!' if wb else ''}" if p else f"[{ARM_REGS[rn]}], {_fmt_imm(signed_off)}"
        return ("ldrd" if ld else "strd", f"{ARM_REGS[rt]}, {ARM_REGS[rt2]}, {addr_s}")

    # Thumb-2 Single Data Load/Store (`1111100 0 U sz L Rn`, `Rt imm12` or shifted/neg)
    if (h1 & 0xFE00) == 0xF800:
        sign_ext = (h1 >> 8) & 1
        u_imm12 = (h1 >> 7) & 1
        sz = (h1 >> 5) & 3
        ld = (h1 >> 4) & 1
        rn = h1 & 0xF
        rt = (h2 >> 12) & 0xF
        base_mn = {
            (1, 0, 0): "ldrb.w",
            (1, 1, 0): "ldrsb.w",
            (1, 0, 1): "ldrh.w",
            (1, 1, 1): "ldrsh.w",
            (1, 0, 2): "ldr.w",
            (0, 0, 0): "strb.w",
            (0, 0, 1): "strh.w",
            (0, 0, 2): "str.w",
        }.get((ld, sign_ext, sz))
        if base_mn:
            if rn == 15:
                off = (h2 & 0xFFF) if u_imm12 else -(h2 & 0xFFF)
                return (base_mn, f"{ARM_REGS[rt]}, [pc, {_fmt_imm(off)}]")
            if u_imm12:
                return (base_mn, f"{ARM_REGS[rt]}, [{ARM_REGS[rn]}, #{h2 & 0xFFF}]")
            if (h2 & 0x0800) == 0x0800:
                p = (h2 >> 10) & 1
                u = (h2 >> 9) & 1
                wb = (h2 >> 8) & 1
                off = (h2 & 0xFF) if u else -(h2 & 0xFF)
                addr = f"[{ARM_REGS[rn]}, {_fmt_imm(off)}]{'!' if wb else ''}" if p else f"[{ARM_REGS[rn]}], {_fmt_imm(off)}"
                return (base_mn, f"{ARM_REGS[rt]}, {addr}")
            rm = h2 & 0xF
            lsl = (h2 >> 4) & 3
            sh = f", lsl #{lsl}" if lsl else ""
            return (base_mn, f"{ARM_REGS[rt]}, [{ARM_REGS[rn]}, {ARM_REGS[rm]}{sh}]")

    # Thumb-2 Modified immediate data processing (`11110 i 0 op S Rn`, `0 imm3 Rd imm8`)
    if (h1 & 0xFA00) == 0xF000 and (h2 & 0x8000) == 0:
        op_t2 = (h1 >> 5) & 0xF
        s_bit = (h1 >> 4) & 1
        rn, rd = h1 & 0xF, (h2 >> 8) & 0xF
        imm12 = (((h1 >> 10) & 1) << 11) | (((h2 >> 12) & 7) << 8) | (h2 & 0xFF)
        val = _thumb_expand_imm(imm12)
        t2_map = {
            0: "and", 1: "bic", 2: "orr", 3: "orn", 4: "eor",
            8: "add", 10: "adc", 11: "sbc", 13: "sub", 14: "rsb",
        }
        if op_t2 == 2 and rn == 15:
            return (f"mov{'s' if s_bit else ''}.w", f"{ARM_REGS[rd]}, {_fmt_imm(val)}")
        if op_t2 == 3 and rn == 15:
            return (f"mvn{'s' if s_bit else ''}.w", f"{ARM_REGS[rd]}, {_fmt_imm(val)}")
        if op_t2 == 13 and rd == 15 and s_bit:
            return ("cmp.w", f"{ARM_REGS[rn]}, {_fmt_imm(val)}")
        if op_t2 == 8 and rd == 15 and s_bit:
            return ("cmn.w", f"{ARM_REGS[rn]}, {_fmt_imm(val)}")
        if op_t2 in t2_map:
            return (f"{t2_map[op_t2]}{'s' if s_bit else ''}.w", f"{ARM_REGS[rd]}, {ARM_REGS[rn]}, {_fmt_imm(val)}")

    # Thumb-2 Shifted register / MUL / MLA / SDIV / UDIV (`1110101...` / `1111101...`)
    if (h1 & 0xFE00) == 0xEA00 and (h2 & 0x8000) == 0:
        op_t2 = (h1 >> 5) & 0xF
        s_bit = (h1 >> 4) & 1
        rn, rd, rm = h1 & 0xF, (h2 >> 8) & 0xF, h2 & 0xF
        sh_amt = (((h2 >> 12) & 7) << 2) | ((h2 >> 6) & 3)
        stype = _SHIFT_TYPES[(h2 >> 4) & 3]
        sh_s = f", {stype} #{sh_amt}" if sh_amt else ""
        t2_map = {
            0: "and", 1: "bic", 2: "orr", 3: "orn", 4: "eor",
            8: "add", 10: "adc", 11: "sbc", 13: "sub", 14: "rsb",
        }
        if op_t2 == 2 and rn == 15:
            if sh_amt or stype != "lsl":
                return (f"{stype}{'s' if s_bit else ''}.w", f"{ARM_REGS[rd]}, {ARM_REGS[rm]}, #{sh_amt or 32}")
            return (f"mov{'s' if s_bit else ''}.w", f"{ARM_REGS[rd]}, {ARM_REGS[rm]}")
        if op_t2 in t2_map:
            return (f"{t2_map[op_t2]}{'s' if s_bit else ''}.w", f"{ARM_REGS[rd]}, {ARM_REGS[rn]}, {ARM_REGS[rm]}{sh_s}")

    if (h1 & 0xFF80) == 0xFB00:
        op1, op2 = (h1 >> 4) & 7, (h2 >> 4) & 0xF
        rn, rd, rm, ra = h1 & 0xF, (h2 >> 8) & 0xF, h2 & 0xF, (h2 >> 12) & 0xF
        if op1 == 0 and op2 == 0:
            if ra == 15:
                return ("mul", f"{ARM_REGS[rd]}, {ARM_REGS[rn]}, {ARM_REGS[rm]}")
            return ("mla", f"{ARM_REGS[rd]}, {ARM_REGS[rn]}, {ARM_REGS[rm]}, {ARM_REGS[ra]}")
        if op1 == 0 and op2 == 1:
            return ("mls", f"{ARM_REGS[rd]}, {ARM_REGS[rn]}, {ARM_REGS[rm]}, {ARM_REGS[ra]}")

    if (h1 & 0xFF80) == 0xFB80:
        op1 = (h1 >> 4) & 7
        rn, rm = h1 & 0xF, h2 & 0xF
        rdlo, rdhi = (h2 >> 12) & 0xF, (h2 >> 8) & 0xF
        if op1 in (1, 3) and (h2 & 0x00F0) == 0x00F0:
            return ("sdiv" if op1 == 1 else "udiv", f"{ARM_REGS[rdhi]}, {ARM_REGS[rn]}, {ARM_REGS[rm]}")
        if op1 in (0, 2) and (h2 & 0x00F0) == 0x0000:
            return ("smull" if op1 == 0 else "umull", f"{ARM_REGS[rdlo]}, {ARM_REGS[rdhi]}, {ARM_REGS[rn]}, {ARM_REGS[rm]}")

    return (".inst.w", f"0x{h1:04x}{h2:04x}")


def _thumb_expand_imm(imm12: int) -> int:
    if (imm12 >> 10) == 0:
        sub = (imm12 >> 8) & 3
        b = imm12 & 0xFF
        if sub == 0:
            return b
        if sub == 1:
            return (b << 16) | b
        if sub == 2:
            return (b << 24) | (b << 8)
        return (b << 24) | (b << 16) | (b << 8) | b
    unrotated = 0x80 | (imm12 & 0x7F)
    rot = (imm12 >> 7) & 0x1F
    return _ror32(unrotated, rot)
