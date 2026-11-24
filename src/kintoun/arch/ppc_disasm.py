"""Pure-stdlib PowerPC 32-bit / Gekko disassembler for context packs and diff classifiers."""
from __future__ import annotations

_GPR = tuple(f"r{i}" for i in range(32))
_FPR = tuple(f"f{i}" for i in range(32))

_COND_BR = {
    (4, 0): "bge",
    (4, 1): "ble",
    (4, 2): "bne",
    (12, 0): "blt",
    (12, 1): "bgt",
    (12, 2): "beq",
}

_X31_2OP = {
    26: "cntlzw",
    124: "nor",
    266: "add",
    40: "subf",
    104: "neg",
    136: "subfe",
    138: "adde",
    200: "subfze",
    202: "addze",
    235: "mullw",
    75: "mulhw",
    11: "mulhwu",
    491: "divw",
    459: "divwu",
    28: "and",
    60: "andc",
    444: "or",
    412: "orc",
    316: "xor",
    284: "eqv",
    476: "nand",
    24: "slw",
    536: "srw",
    792: "sraw",
    922: "extsh",
    954: "extsb",
}

_LDST_D = {
    32: "lwz",
    33: "lwzu",
    34: "lbz",
    35: "lbzu",
    36: "stw",
    37: "stwu",
    38: "stb",
    39: "stbu",
    40: "lhz",
    41: "lhzu",
    42: "lha",
    43: "lhau",
    44: "sth",
    45: "sthu",
    46: "lmw",
    47: "stmw",
    48: "lfs",
    49: "lfsu",
    50: "lfd",
    51: "lfdu",
    52: "stfs",
    53: "stfsu",
    54: "stfd",
    55: "stfdu",
}

_FP59 = {18: "fdivs", 20: "fsubs", 21: "fadds", 24: "fres", 25: "fmuls", 28: "fmsubs", 29: "fmadds", 30: "fnmsubs", 31: "fnmadds"}
_FP63_A = {18: "fdiv", 20: "fsub", 21: "fadd", 25: "fmul", 26: "frsqrte", 28: "fmsub", 29: "fmadd", 30: "fnmsub", 31: "fnmadd"}
_FP63_X = {12: "frsp", 14: "fctiw", 15: "fctiwz", 32: "fcmpo", 0: "fcmpu", 40: "fneg", 72: "fmr", 136: "fnabs", 264: "fabs"}


def _s16(val: int) -> int:
    val &= 0xFFFF
    return val - 0x10000 if val & 0x8000 else val


def _fmt_simm(val: int) -> str:
    s = _s16(val)
    if -9 <= s <= 9:
        return str(s)
    return f"-0x{-s:x}" if s < 0 else f"0x{s:x}"


def disasm_ppc_word(word: int, pc: int = 0) -> tuple[str, str]:
    """Disassemble one big-endian 32-bit PowerPC/Gekko instruction into `(mnemonic, operands)`."""
    w = word & 0xFFFFFFFF
    if w == 0x60000000:
        return ("nop", "")
    if w == 0x4E800020:
        return ("blr", "")
    if w == 0x4E800420:
        return ("bctr", "")
    if w == 0x4E800421:
        return ("bctrl", "")
    if w == 0x4E800021:
        return ("blrl", "")

    op = (w >> 26) & 0x3F
    rd = (w >> 21) & 0x1F
    ra = (w >> 16) & 0x1F
    rb = (w >> 11) & 0x1F
    rc_dot = "." if (w & 1) else ""
    uimm = w & 0xFFFF
    simm = _s16(uimm)

    if op == 18:
        li = w & 0x03FFFFFC
        if li & 0x02000000:
            li -= 0x04000000
        aa = bool(w & 2)
        lk = bool(w & 1)
        tgt = (li if aa else (pc + li)) & 0xFFFFFFFF
        mn = ("bl" if lk else "b") + ("a" if aa else "")
        return (mn, f"0x{tgt:08x}")

    if op == 16:
        bd = w & 0xFFFC
        if bd & 0x8000:
            bd -= 0x10000
        bo = rd
        bi = ra
        lk = "l" if (w & 1) else ""
        tgt = ((bd if (w & 2) else (pc + bd)) & 0xFFFFFFFF)
        cr = bi // 4
        cc = bi % 4
        base = _COND_BR.get((bo & 0x1E, cc))
        cr_pfx = f"cr{cr}, " if cr else ""
        if base:
            return (base + lk, f"{cr_pfx}0x{tgt:08x}")
        return ("bc" + lk, f"{bo}, {bi}, 0x{tgt:08x}")

    if op == 14:
        if ra == 0:
            return ("li", f"{_GPR[rd]}, {_fmt_simm(uimm)}")
        return ("addi", f"{_GPR[rd]}, {_GPR[ra]}, {_fmt_simm(uimm)}")
    if op == 15:
        if ra == 0:
            return ("lis", f"{_GPR[rd]}, {_fmt_simm(uimm)}")
        return ("addis", f"{_GPR[rd]}, {_GPR[ra]}, {_fmt_simm(uimm)}")
    if op == 7:
        return ("mulli", f"{_GPR[rd]}, {_GPR[ra]}, {_fmt_simm(uimm)}")
    if op == 8:
        return ("subfic", f"{_GPR[rd]}, {_GPR[ra]}, {_fmt_simm(uimm)}")
    if op == 12:
        return ("addic", f"{_GPR[rd]}, {_GPR[ra]}, {_fmt_simm(uimm)}")
    if op == 13:
        return ("addic.", f"{_GPR[rd]}, {_GPR[ra]}, {_fmt_simm(uimm)}")
    if op == 11:
        cr = rd >> 2
        pfx = f"cr{cr}, " if cr else ""
        return ("cmpwi", f"{pfx}{_GPR[ra]}, {_fmt_simm(uimm)}")
    if op == 10:
        cr = rd >> 2
        pfx = f"cr{cr}, " if cr else ""
        return ("cmplwi", f"{pfx}{_GPR[ra]}, 0x{uimm:x}")
    if op in (24, 25, 26, 27, 28, 29):
        mn = {24: "ori", 25: "oris", 26: "xori", 27: "xoris", 28: "andi.", 29: "andis."}[op]
        if op == 24 and rd == ra and uimm == 0:
            return ("nop", "")
        return (mn, f"{_GPR[ra]}, {_GPR[rd]}, 0x{uimm:x}")

    if op in (20, 21, 23):
        sh = rb
        mb = (w >> 6) & 0x1F
        me = (w >> 1) & 0x1F
        if op == 21:
            if sh == 0 and me == 31:
                return ("clrlwi" + rc_dot, f"{_GPR[ra]}, {_GPR[rd]}, {mb}")
            if mb == 0 and me == 31 - sh:
                return ("slwi" + rc_dot, f"{_GPR[ra]}, {_GPR[rd]}, {sh}")
            if me == 31 and sh == 32 - mb:
                return ("srwi" + rc_dot, f"{_GPR[ra]}, {_GPR[rd]}, {mb}")
            return ("rlwinm" + rc_dot, f"{_GPR[ra]}, {_GPR[rd]}, {sh}, {mb}, {me}")
        if op == 20:
            return ("rlwimi" + rc_dot, f"{_GPR[ra]}, {_GPR[rd]}, {sh}, {mb}, {me}")
        return ("rlwnm" + rc_dot, f"{_GPR[ra]}, {_GPR[rd]}, {_GPR[rb]}, {mb}, {me}")

    if op in _LDST_D:
        mn = _LDST_D[op]
        reg = _FPR[rd] if op >= 48 else _GPR[rd]
        base = "0" if ra == 0 else _GPR[ra]
        return (mn, f"{reg}, {_fmt_simm(simm)}({base})")

    if op == 31:
        xo = (w >> 1) & 0x3FF
        if xo == 0:
            cr = rd >> 2
            pfx = f"cr{cr}, " if cr else ""
            return ("cmpw", f"{pfx}{_GPR[ra]}, {_GPR[rb]}")
        if xo == 32:
            cr = rd >> 2
            pfx = f"cr{cr}, " if cr else ""
            return ("cmplw", f"{pfx}{_GPR[ra]}, {_GPR[rb]}")
        if xo == 444 and rd == rb:
            return ("mr" + rc_dot, f"{_GPR[ra]}, {_GPR[rd]}")
        if xo == 339:
            spr = ((ra & 0x1F) | ((rb & 0x1F) << 5))
            if spr == 8:
                return ("mflr", _GPR[rd])
            if spr == 9:
                return ("mfctr", _GPR[rd])
            return ("mfspr", f"{_GPR[rd]}, {spr}")
        if xo == 467:
            spr = ((ra & 0x1F) | ((rb & 0x1F) << 5))
            if spr == 8:
                return ("mtlr", _GPR[rd])
            if spr == 9:
                return ("mtctr", _GPR[rd])
            return ("mtspr", f"{spr}, {_GPR[rd]}")
        if xo == 19:
            return ("mfcr", _GPR[rd])
        if xo == 824:
            return ("srawi" + rc_dot, f"{_GPR[ra]}, {_GPR[rd]}, {rb}")
        if xo in _X31_2OP:
            mn = _X31_2OP[xo]
            if xo in (26, 922, 954):
                return (mn + rc_dot, f"{_GPR[ra]}, {_GPR[rd]}")
            if xo in (104, 200, 202):
                return (mn + rc_dot, f"{_GPR[rd]}, {_GPR[ra]}")
            if xo in (28, 60, 124, 444, 412, 316, 284, 476, 24, 536, 792):
                return (mn + rc_dot, f"{_GPR[ra]}, {_GPR[rd]}, {_GPR[rb]}")
            return (mn + rc_dot, f"{_GPR[rd]}, {_GPR[ra]}, {_GPR[rb]}")
        return (f"ppc_x31_{xo}", f"{_GPR[rd]}, {_GPR[ra]}, {_GPR[rb]}")

    if op == 59:
        xo = (w >> 1) & 0x1F
        rc = (w >> 6) & 0x1F
        mn = _FP59.get(xo, f"fp59_{xo}")
        if xo in (28, 29, 30, 31):
            return (mn + rc_dot, f"{_FPR[rd]}, {_FPR[ra]}, {_FPR[rc]}, {_FPR[rb]}")
        if xo == 25:
            return (mn + rc_dot, f"{_FPR[rd]}, {_FPR[ra]}, {_FPR[rc]}")
        return (mn + rc_dot, f"{_FPR[rd]}, {_FPR[ra]}, {_FPR[rb]}")

    if op == 63:
        xo_a = (w >> 1) & 0x1F
        xo_x = (w >> 1) & 0x3FF
        rc = (w >> 6) & 0x1F
        if xo_x in _FP63_X:
            mn = _FP63_X[xo_x]
            if xo_x in (0, 32):
                cr = rd >> 2
                return (mn, f"cr{cr}, {_FPR[ra]}, {_FPR[rb]}")
            return (mn + rc_dot, f"{_FPR[rd]}, {_FPR[rb]}")
        if xo_a in _FP63_A:
            mn = _FP63_A[xo_a]
            if xo_a in (28, 29, 30, 31):
                return (mn + rc_dot, f"{_FPR[rd]}, {_FPR[ra]}, {_FPR[rc]}, {_FPR[rb]}")
            if xo_a == 25:
                return (mn + rc_dot, f"{_FPR[rd]}, {_FPR[ra]}, {_FPR[rc]}")
            return (mn + rc_dot, f"{_FPR[rd]}, {_FPR[ra]}, {_FPR[rb]}")

    if op in (4, 56, 57, 60, 61):
        return (f"ps_op{op}", f"0x{w:08x}")

    return (".long", f"0x{w:08x}")
