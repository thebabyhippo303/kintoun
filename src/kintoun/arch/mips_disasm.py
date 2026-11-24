"""Pure-stdlib MIPS disassembler (MIPS I-IV, MIPS32, PS2 R5900 EE, PSP Allegrex, COP1 FP)."""
from __future__ import annotations

GPR_NAMES: tuple[str, ...] = (
    "$zero", "$at", "$v0", "$v1", "$a0", "$a1", "$a2", "$a3",
    "$t0", "$t1", "$t2", "$t3", "$t4", "$t5", "$t6", "$t7",
    "$s0", "$s1", "$s2", "$s3", "$s4", "$s5", "$s6", "$s7",
    "$t8", "$t9", "$k0", "$k1", "$gp", "$sp", "$fp", "$ra",
)
FPR_NAMES: tuple[str, ...] = tuple(f"$f{i}" for i in range(32))

_COP1_COND: tuple[str, ...] = (
    "f", "un", "eq", "ueq", "olt", "ult", "ole", "ule",
    "sf", "ngle", "seq", "ngl", "lt", "nge", "le", "ngt",
)

_DISASM_CACHE: dict[tuple[int, int, str], tuple[str, str]] = {}


def _s16(val: int) -> int:
    val &= 0xFFFF
    return val - 0x10000 if val & 0x8000 else val


def _fmt_simm(val: int) -> str:
    s = _s16(val)
    if -9 <= s <= 9:
        return str(s)
    return f"-0x{-s:x}" if s < 0 else f"0x{s:x}"


def disasm_mips_word(word: int, pc: int = 0, mach: str = "") -> tuple[str, str]:
    """Disassemble one 32-bit MIPS instruction word into `(mnemonic, op_str)`."""
    key = (word, pc, mach)
    if key in _DISASM_CACHE:
        return _DISASM_CACHE[key]
    res = _decode_mips(word & 0xFFFFFFFF, pc, mach)
    if len(_DISASM_CACHE) < 65536:
        _DISASM_CACHE[key] = res
    return res


def _decode_mips(w: int, pc: int, mach: str = "") -> tuple[str, str]:
    if w == 0:
        return ("nop", "")

    op = (w >> 26) & 0x3F
    rs = (w >> 21) & 0x1F
    rt = (w >> 16) & 0x1F
    rd = (w >> 11) & 0x1F
    sa = (w >> 6) & 0x1F
    fn = w & 0x3F
    uimm = w & 0xFFFF
    simm = _s16(uimm)
    rs_n, rt_n, rd_n = GPR_NAMES[rs], GPR_NAMES[rt], GPR_NAMES[rd]

    if op == 0:
        if fn == 0:
            return ("sll", f"{rd_n}, {rt_n}, {sa}")
        if fn == 2:
            if rs == 1:
                return ("rotr", f"{rd_n}, {rt_n}, {sa}")
            return ("srl", f"{rd_n}, {rt_n}, {sa}")
        if fn == 3:
            return ("sra", f"{rd_n}, {rt_n}, {sa}")
        if fn == 4:
            return ("sllv", f"{rd_n}, {rt_n}, {rs_n}")
        if fn == 6:
            if sa == 1:
                return ("rotrv", f"{rd_n}, {rt_n}, {rs_n}")
            return ("srlv", f"{rd_n}, {rt_n}, {rs_n}")
        if fn == 7:
            return ("srav", f"{rd_n}, {rt_n}, {rs_n}")
        if fn == 8:
            return ("jr", rs_n)
        if fn == 9:
            return ("jalr", rs_n if rd == 31 else f"{rd_n}, {rs_n}")
        if fn == 10:
            return ("movz", f"{rd_n}, {rs_n}, {rt_n}")
        if fn == 11:
            return ("movn", f"{rd_n}, {rs_n}, {rt_n}")
        if fn == 12:
            return ("syscall", f"0x{(w >> 6) & 0xFFFFF:x}" if (w >> 6) & 0xFFFFF else "")
        if fn == 13:
            return ("break", f"0x{(w >> 6) & 0xFFFFF:x}" if (w >> 6) & 0xFFFFF else "")
        if fn == 15:
            return ("sync", f"{sa}" if sa else "")
        if fn == 16:
            return ("mfhi", rd_n)
        if fn == 17:
            return ("mthi", rs_n)
        if fn == 18:
            return ("mflo", rd_n)
        if fn == 19:
            return ("mtlo", rs_n)
        if fn == 20:
            return ("dsllv", f"{rd_n}, {rt_n}, {rs_n}")
        if fn == 22:
            return ("dsrlv", f"{rd_n}, {rt_n}, {rs_n}")
        if fn == 23:
            return ("dsrav", f"{rd_n}, {rt_n}, {rs_n}")
        if fn == 24:
            if rd != 0:  # R5900 EE 3-operand mult rd, rs, rt
                return ("mult", f"{rd_n}, {rs_n}, {rt_n}")
            return ("mult", f"{rs_n}, {rt_n}")
        if fn == 25:
            if rd != 0:
                return ("multu", f"{rd_n}, {rs_n}, {rt_n}")
            return ("multu", f"{rs_n}, {rt_n}")
        if fn == 26:
            return ("div", f"$zero, {rs_n}, {rt_n}")
        if fn == 27:
            return ("divu", f"$zero, {rs_n}, {rt_n}")
        if fn == 28:
            return ("dmult", f"{rs_n}, {rt_n}")
        if fn == 29:
            return ("dmultu", f"{rs_n}, {rt_n}")
        if fn == 30:
            return ("ddiv", f"$zero, {rs_n}, {rt_n}")
        if fn == 31:
            return ("ddivu", f"$zero, {rs_n}, {rt_n}")
        if fn == 32:
            return ("add", f"{rd_n}, {rs_n}, {rt_n}")
        if fn == 33:
            if rt == 0:
                return ("move", f"{rd_n}, {rs_n}")
            if rs == 0:
                return ("move", f"{rd_n}, {rt_n}")
            return ("addu", f"{rd_n}, {rs_n}, {rt_n}")
        if fn == 34:
            return ("sub", f"{rd_n}, {rs_n}, {rt_n}")
        if fn == 35:
            return ("subu", f"{rd_n}, {rs_n}, {rt_n}" if rs != 0 else f"{rd_n}, $zero, {rt_n}")
        if fn == 36:
            return ("and", f"{rd_n}, {rs_n}, {rt_n}")
        if fn == 37:
            if rt == 0:
                return ("move", f"{rd_n}, {rs_n}")
            return ("or", f"{rd_n}, {rs_n}, {rt_n}")
        if fn == 38:
            return ("xor", f"{rd_n}, {rs_n}, {rt_n}")
        if fn == 39:
            return ("nor", f"{rd_n}, {rs_n}, {rt_n}")
        if fn == 40:
            return ("mfsa", rd_n)
        if fn == 41:
            return ("mtsa", rs_n)
        if fn == 42:
            return ("slt", f"{rd_n}, {rs_n}, {rt_n}")
        if fn == 43:
            return ("sltu", f"{rd_n}, {rs_n}, {rt_n}")
        if fn == 44:
            # Allegrex `max` uses sa==0 on 32-bit targets; R5900/MIPS64 `dadd` also uses fn==44
            return ("dadd" if sa else "max", f"{rd_n}, {rs_n}, {rt_n}")
        if fn == 45:
            if rt == 0:
                return ("move", f"{rd_n}, {rs_n}")
            return ("daddu", f"{rd_n}, {rs_n}, {rt_n}")
        if fn == 46:
            return ("dsub", f"{rd_n}, {rs_n}, {rt_n}")
        if fn == 47:
            return ("dsubu", f"{rd_n}, {rs_n}, {rt_n}")
        if fn == 56:
            return ("dsll", f"{rd_n}, {rt_n}, {sa}")
        if fn == 58:
            return ("dsrl", f"{rd_n}, {rt_n}, {sa}")
        if fn == 59:
            return ("dsra", f"{rd_n}, {rt_n}, {sa}")
        if fn == 60:
            return ("dsll32", f"{rd_n}, {rt_n}, {sa}")
        if fn == 62:
            return ("dsrl32", f"{rd_n}, {rt_n}, {sa}")
        if fn == 63:
            return ("dsra32", f"{rd_n}, {rt_n}, {sa}")

    if op == 1:
        btarget = (pc + 4 + (simm << 2)) & 0xFFFFFFFF
        regimm_mn = {
            0: "bltz",
            1: "bgez",
            2: "bltzl",
            3: "bgezl",
            16: "bltzal",
            17: "bgezal",
            18: "bltzall",
            19: "bgezall",
        }.get(rt)
        if regimm_mn:
            if rt == 1 and rs == 0:
                return ("b", f"0x{btarget:x}")
            if rt == 17 and rs == 0:
                return ("bal", f"0x{btarget:x}")
            return (regimm_mn, f"{rs_n}, 0x{btarget:x}")
        if rt == 24:
            return ("mtsab", f"{rs_n}, {_fmt_simm(uimm)}")
        if rt == 25:
            return ("mtsah", f"{rs_n}, {_fmt_simm(uimm)}")

    if op in (2, 3):
        jtarget = ((pc + 4) & 0xF0000000) | ((w & 0x03FFFFFF) << 2)
        return ("j" if op == 2 else "jal", f"0x{jtarget:x}")

    if op in (4, 5, 6, 7, 20, 21, 22, 23):
        btarget = (pc + 4 + (simm << 2)) & 0xFFFFFFFF
        if op == 4:
            if rs == 0 and rt == 0:
                return ("b", f"0x{btarget:x}")
            if rt == 0:
                return ("beqz", f"{rs_n}, 0x{btarget:x}")
            return ("beq", f"{rs_n}, {rt_n}, 0x{btarget:x}")
        if op == 5:
            if rt == 0:
                return ("bnez", f"{rs_n}, 0x{btarget:x}")
            return ("bne", f"{rs_n}, {rt_n}, 0x{btarget:x}")
        if op in (6, 7, 22, 23):
            mn = {6: "blez", 7: "bgtz", 22: "blezl", 23: "bgtzl"}[op]
            return (mn, f"{rs_n}, 0x{btarget:x}")
        mn = "beql" if op == 20 else "bnel"
        return (mn, f"{rs_n}, {rt_n}, 0x{btarget:x}")

    if op == 8:
        return ("addi", f"{rt_n}, {rs_n}, {_fmt_simm(uimm)}")
    if op == 9:
        if rs == 0:
            return ("li", f"{rt_n}, {_fmt_simm(uimm)}")
        return ("addiu", f"{rt_n}, {rs_n}, {_fmt_simm(uimm)}")
    if op == 10:
        return ("slti", f"{rt_n}, {rs_n}, {_fmt_simm(uimm)}")
    if op == 11:
        return ("sltiu", f"{rt_n}, {rs_n}, {_fmt_simm(uimm)}")
    if op == 12:
        return ("andi", f"{rt_n}, {rs_n}, 0x{uimm:x}")
    if op == 13:
        if rs == 0:
            return ("li", f"{rt_n}, 0x{uimm:x}")
        return ("ori", f"{rt_n}, {rs_n}, 0x{uimm:x}")
    if op == 14:
        return ("xori", f"{rt_n}, {rs_n}, 0x{uimm:x}")
    if op == 15:
        return ("lui", f"{rt_n}, 0x{uimm:x}")

    if op == 17:  # COP1 (FPU)
        fs, ft, fd = rd, rt, sa
        fs_n, ft_n, fd_n = FPR_NAMES[fs], FPR_NAMES[ft], FPR_NAMES[fd]
        if rs == 0:
            return ("mfc1", f"{rt_n}, {fs_n}")
        if rs == 2:
            return ("cfc1", f"{rt_n}, ${fs}")
        if rs == 4:
            return ("mtc1", f"{rt_n}, {fs_n}")
        if rs == 6:
            return ("ctc1", f"{rt_n}, ${fs}")
        if rs == 8:
            btarget = (pc + 4 + (simm << 2)) & 0xFFFFFFFF
            cc = (rt >> 2) & 7
            nd_tf = rt & 3
            mn = ("bc1f", "bc1t", "bc1fl", "bc1tl")[nd_tf]
            return (mn, f"0x{btarget:x}" if cc == 0 else f"$fcc{cc}, 0x{btarget:x}")
        if rs in (16, 17, 20):
            sfx = {16: "s", 17: "d", 20: "w"}[rs]
            two_op = {
                4: "sqrt",
                5: "abs",
                6: "mov",
                7: "neg",
                12: "round.w",
                13: "trunc.w",
                14: "ceil.w",
                15: "floor.w",
                22: "rsqrt",
                32: "cvt.s",
                33: "cvt.d",
                36: "cvt.w",
            }
            three_op = {
                0: "add",
                1: "sub",
                2: "mul",
                3: "div",
                28: "madd",
                29: "msub",
                40: "max",
                41: "min",
            }
            if fn in three_op:
                return (f"{three_op[fn]}.{sfx}", f"{fd_n}, {fs_n}, {ft_n}")
            if fn in two_op:
                return (f"{two_op[fn]}.{sfx}", f"{fd_n}, {fs_n}")
            if fn in (24, 25, 26):
                acc_mn = {24: "adda", 25: "suba", 26: "mula"}[fn]
                return (f"{acc_mn}.{sfx}", f"{fs_n}, {ft_n}")
            if 48 <= fn <= 63:
                cc = (w >> 8) & 7
                cond = _COP1_COND[fn - 48]
                ops = f"{fs_n}, {ft_n}" if cc == 0 else f"$fcc{cc}, {fs_n}, {ft_n}"
                return (f"c.{cond}.{sfx}", ops)

    if op == 24:
        return ("daddi", f"{rt_n}, {rs_n}, {_fmt_simm(uimm)}")
    if op == 25:
        return ("daddiu", f"{rt_n}, {rs_n}, {_fmt_simm(uimm)}")

    if op == 28:  # SPECIAL2 (MIPS32 / R5900 EE)
        if fn == 0:
            return ("madd", f"{rs_n}, {rt_n}" if rd == 0 else f"{rd_n}, {rs_n}, {rt_n}")
        if fn == 1:
            return ("maddu", f"{rs_n}, {rt_n}" if rd == 0 else f"{rd_n}, {rs_n}, {rt_n}")
        if fn == 2:
            return ("mul", f"{rd_n}, {rs_n}, {rt_n}")
        if fn == 4:
            return ("msub" if rt != 0 else "plzcw", f"{rs_n}, {rt_n}" if rt != 0 else f"{rd_n}, {rs_n}")
        if fn == 5:
            return ("msubu", f"{rs_n}, {rt_n}")
        if fn == 16:
            return ("mfhi1", rd_n)
        if fn == 17:
            return ("mthi1", rs_n)
        if fn == 18:
            return ("mflo1", rd_n)
        if fn == 19:
            return ("mtlo1", rs_n)
        if fn == 24:
            return ("mult1", f"{rd_n}, {rs_n}, {rt_n}" if rd != 0 else f"{rs_n}, {rt_n}")
        if fn == 25:
            return ("multu1", f"{rd_n}, {rs_n}, {rt_n}" if rd != 0 else f"{rs_n}, {rt_n}")
        if fn == 26:
            return ("div1", f"$zero, {rs_n}, {rt_n}")
        if fn == 27:
            return ("divu1", f"$zero, {rs_n}, {rt_n}")
        if fn == 32:
            return ("clz", f"{rd_n}, {rs_n}")
        if fn == 33:
            return ("clo", f"{rd_n}, {rs_n}")

    if op == 30:  # R5900 EE lq
        return ("lq", f"{rt_n}, {_fmt_simm(uimm)}({rs_n})")
    if op == 31:  # SPECIAL3 (MIPS32r2 / Allegrex) or R5900 EE sq
        if mach != "r5900":
            # Distinguish MIPS32r2/Allegrex `ext` (`fn==0`) from R5900 `sq` (`uimm==0` or `$sp`/`$ra` save)
            if fn == 0 and rs != 29 and rt != 31 and not (rd == 0 and sa == 0):
                return ("ext", f"{rt_n}, {rs_n}, {sa}, {rd + 1}")
            if fn == 4 and rd >= sa and rs != 29 and rt != 31:
                size = rd - sa + 1
                return ("ins", f"{rt_n}, {rs_n}, {sa}, {size}")
            if fn == 32 and rs == 0:
                bshfl = {2: "wsbh", 16: "seb", 20: "bitrev", 24: "seh"}.get(sa)
                if bshfl:
                    return (bshfl, f"{rd_n}, {rt_n}")
        return ("sq", f"{rt_n}, {_fmt_simm(uimm)}({rs_n})")

    mem_mn = {
        32: "lb",
        33: "lh",
        34: "lwl",
        35: "lw",
        36: "lbu",
        37: "lhu",
        38: "lwr",
        39: "lwu",
        40: "sb",
        41: "sh",
        42: "swl",
        43: "sw",
        44: "sdl",
        45: "sdr",
        46: "swr",
        48: "ll",
        55: "ld",
        56: "sc",
        63: "sd",
    }.get(op)
    if mem_mn:
        return (mem_mn, f"{rt_n}, {_fmt_simm(uimm)}({rs_n})")

    fp_mem_mn = {49: "lwc1", 53: "ldc1", 57: "swc1", 61: "sdc1"}.get(op)
    if fp_mem_mn:
        return (fp_mem_mn, f"{FPR_NAMES[rt]}, {_fmt_simm(uimm)}({rs_n})")

    return (".word", f"0x{w:08x}")
