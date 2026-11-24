"""Bit-exact IEEE-754 `.rodata` float solver and compiler magic-division inverter.

Solves two classic blockers that stall decompilations at 90-99%:
  1. **1-ULP Float / Double Literals:** Converts raw 32-bit and 64-bit IEEE-754 target words
     from `.rodata`, `.sdata2`, `.lit4`, or ARM `$d` literal pools into the shortest C float
     literal guaranteed to round-trip to the exact bit pattern (`struct.pack` verified), plus
     recognizes exact rational/trigonometric constants (`1.0f / N`, `PI / 180.0f`, etc.).
  2. **Magic-Multiply Reciprocal Division (`mulhw` / `mult+mfhi` / `smull`):** Inverts
     compiler-generated reciprocal multiplication constants (`0x55555556`, `0x66666667`,
     `0xCCCCCCCD`, etc.) back into clean `x / K` C division expressions and proposes C
     candidates that replace raw `0x...` hex multiplies or 1-ULP floats automatically.
"""
from __future__ import annotations

import math
import re
import struct
from typing import Any

from kintoun.targets import TargetContext, TargetFunction

_F32_PI = 3.14159265358979323846


def _pack_f32_be(val: float) -> int:
    try:
        return struct.unpack(">I", struct.pack(">f", val))[0]
    except OverflowError:
        return -1


def _pack_f64_be(val: float) -> int:
    try:
        return struct.unpack(">Q", struct.pack(">d", val))[0]
    except OverflowError:
        return -1


def _build_named_f32_table() -> dict[int, str]:
    table: dict[int, str] = {}
    specials = [
        (_F32_PI / 180.0, "3.1415927f / 180.0f /* deg2rad */"),
        (180.0 / _F32_PI, "180.0f / 3.1415927f /* rad2deg */"),
        (_F32_PI, "3.1415927f /* pi */"),
        (2.0 * _F32_PI, "6.2831855f /* 2*pi */"),
        (0.5 * _F32_PI, "1.5707964f /* pi/2 */"),
        (0.25 * _F32_PI, "0.7853982f /* pi/4 */"),
        (math.sqrt(2.0), "1.4142135f /* sqrt(2) */"),
        (math.sqrt(0.5), "0.70710677f /* sqrt(0.5) */"),
    ]
    for val, expr in specials:
        for sign, pfx in ((1.0, ""), (-1.0, "-")):
            bits = _pack_f32_be(sign * val)
            if bits >= 0 and bits not in table:
                table[bits] = pfx + expr
    for denom in (3, 5, 6, 7, 9, 10, 12, 15, 24, 30, 60, 100, 120, 180, 255, 360, 1000):
        for sign, pfx in ((1.0, ""), (-1.0, "-")):
            bits = _pack_f32_be(sign / denom)
            if bits >= 0 and bits not in table:
                table[bits] = f"{pfx}(1.0f / {denom}.0f)"
    return table


_NAMED_F32 = _build_named_f32_table()


def solve_float32(word32: int) -> dict[str, Any] | None:
    """Decode a 32-bit IEEE-754 word into a guaranteed bit-exact C `float` literal."""
    w = word32 & 0xFFFFFFFF
    exp = (w >> 23) & 0xFF
    if exp in (0, 0xFF):
        if w == 0:
            return {"hex": "0x00000000", "c_literal": "0.0f", "exact_expr": "0.0f", "value": 0.0}
        if w == 0x80000000:
            return {"hex": "0x80000000", "c_literal": "-0.0f", "exact_expr": "-0.0f", "value": -0.0}
        return None
    # Filter implausible non-float pointers / integers (`1e-6 .. 1e7` normal gameplay/math range)
    val = struct.unpack(">f", struct.pack(">I", w))[0]
    aval = abs(val)
    if not (1e-6 <= aval <= 1e7):
        return None

    chosen: str | None = None
    for prec in range(1, 10):
        s = f"{val:.{prec}g}"
        if "." not in s and "e" not in s and "E" not in s:
            s += ".0"
        if _pack_f32_be(float(s)) == w:
            chosen = s + "f"
            break
    if chosen is None:
        s9 = f"{val:.9e}"
        chosen = s9 + "f"

    return {
        "hex": f"0x{w:08X}",
        "c_literal": chosen,
        "exact_expr": _NAMED_F32.get(w, chosen),
        "value": val,
    }


def solve_float64(word64: int) -> dict[str, Any] | None:
    """Decode a 64-bit IEEE-754 integer into a guaranteed bit-exact C `double` literal."""
    q = word64 & 0xFFFFFFFFFFFFFFFF
    exp = (q >> 52) & 0x7FF
    if exp in (0, 0x7FF):
        return None
    val = struct.unpack(">d", struct.pack(">Q", q))[0]
    aval = abs(val)
    if not (1e-9 <= aval <= 1e12):
        return None
    chosen: str | None = None
    for prec in range(1, 18):
        s = f"{val:.{prec}g}"
        if "." not in s and "e" not in s and "E" not in s:
            s += ".0"
        if _pack_f64_be(float(s)) == q:
            chosen = s
            break
    if chosen is None:
        chosen = f"{val:.17e}"
    return {"hex": f"0x{q:016X}", "c_literal": chosen, "value": val}


def _build_magic_div_table(max_divisor: int = 1000) -> dict[int, list[dict[str, Any]]]:
    """Precompute standard 32-bit signed & unsigned reciprocal-multiply constants for `d in 3..max_divisor`."""
    out: dict[int, list[dict[str, Any]]] = {}
    for d in range(3, max_divisor + 1):
        if (d & (d - 1)) == 0:
            continue  # Powers of two use shifts, not mulhw
        # Signed & unsigned magic constants (`ceil(2^(32+s) / d)` across valid shifts `s = 0..11`)
        for s in range(0, 12):
            num = 1 << (32 + s)
            m_ceil = (num + d - 1) // d
            if 0x20000000 <= m_ceil <= 0xFFFFFFFF:
                w32 = m_ceil & 0xFFFFFFFF
                is_signed = m_ceil < 0x80000000
                rec = {
                    "divisor": d,
                    "signed": is_signed,
                    "shift": s,
                    "c_hint": f"x / {d}" if is_signed else f"(s32)x / {d} (or (u32)x / {d})",
                }
                bucket = out.setdefault(w32, [])
                if not any(b["divisor"] == d for b in bucket):
                    bucket.append(rec)
    return out


_MAGIC_DIV32 = _build_magic_div_table()


def invert_magic_div32(word32: int) -> list[dict[str, Any]]:
    """Return candidate `x / K` divisor descriptors for a 32-bit reciprocal multiplier constant."""
    return list(_MAGIC_DIV32.get(word32 & 0xFFFFFFFF, ()))


def scan_target_constants(target_fn: TargetFunction, ctx: TargetContext) -> dict[str, list[dict[str, Any]]]:
    """Extract bit-exact float literals and magic-division constants referenced by `target_fn`."""
    floats: list[dict[str, Any]] = []
    magic_divs: list[dict[str, Any]] = []
    seen_f: set[int] = set()
    seen_m: set[int] = set()
    data = target_fn.data

    def _offer_word(w32: int, origin: str) -> None:
        w32 &= 0xFFFFFFFF
        if w32 not in seen_m:
            divs = invert_magic_div32(w32)
            if divs:
                seen_m.add(w32)
                top = divs[0]
                magic_divs.append(
                    {
                        "hex": f"0x{w32:08X}",
                        "divisor": top["divisor"],
                        "c_hint": top["c_hint"],
                        "origin": origin,
                    }
                )
        if w32 not in seen_f:
            finfo = solve_float32(w32)
            if finfo is not None:
                seen_f.add(w32)
                floats.append({**finfo, "origin": origin})

    if ctx.arch in ("arm", "arm_elf"):
        # Scan inline `$d` literal pools or 4-byte aligned words at tail / pool offsets
        data_ranges = [(s, e) for s, e, mode in (target_fn.intervals or ()) if mode == "$d"]
        if data_ranges:
            for s, e in data_ranges:
                for off in range(s, min(e, len(data)) - 3, 4):
                    w = struct.unpack_from("<I" if ctx.endian != "big" else ">I", data, off)[0]
                    _offer_word(w, f"$d+0x{off:X}")
        else:
            # Heuristic: scan PC-relative `ldr Rd, [pc, #imm]` targets inside `target_fn`
            for off in range(0, len(data) - 1, 2):
                hw = struct.unpack_from("<H", data, off)[0]
                if (hw >> 11) == 9:
                    pool_off = (((off + 4) & ~3) + (hw & 0xFF) * 4)
                    if 0 <= pool_off <= len(data) - 4:
                        w = struct.unpack_from("<I", data, pool_off)[0]
                        _offer_word(w, f"pool+0x{pool_off:X}")
    elif ctx.arch in ("mips", "mips_elf"):
        fmt = "<I" if ctx.endian != "big" else ">I"
        words = [struct.unpack_from(fmt, data, off)[0] for off in range(0, len(data) - (len(data) % 4), 4)]
        hi_reg: dict[int, int] = {}
        for idx, w in enumerate(words):
            op = (w >> 26) & 0x3F
            rs = (w >> 21) & 0x1F
            rt = (w >> 16) & 0x1F
            uimm = w & 0xFFFF
            simm = uimm - 0x10000 if (uimm & 0x8000) else uimm
            if op == 15:  # lui rt, imm
                hi_reg[rt] = uimm << 16
                if uimm != 0:
                    _offer_word(uimm << 16, f"lui+0x{idx * 4:X}")
            elif op == 13 and rs in hi_reg:  # ori rt, rs, uimm
                _offer_word(hi_reg[rs] | uimm, f"lui+ori+0x{idx * 4:X}")
            elif op == 9 and rs in hi_reg:  # addiu rt, rs, simm
                full = (hi_reg[rs] + simm) & 0xFFFFFFFF
                _offer_word(full, f"lui+addiu+0x{idx * 4:X}")
            elif op == 49:  # lwc1 ft, off(rs)
                addr = None
                if rs == 28 and ctx.gp:
                    addr = (ctx.gp + simm) & 0xFFFFFFFF
                elif rs in hi_reg:
                    addr = (hi_reg[rs] + simm) & 0xFFFFFFFF
                if addr is not None:
                    try:
                        raw4 = ctx.read(addr, 4)
                        _offer_word(struct.unpack(fmt, raw4)[0], f"rodata@0x{addr:08X}")
                    except ValueError:
                        pass
    else:  # PowerPC (`ppc_elf`)
        words = [struct.unpack_from(">I", data, off)[0] for off in range(0, len(data) - (len(data) % 4), 4)]
        hi_reg_ppc: dict[int, int] = {}
        for idx, w in enumerate(words):
            op = (w >> 26) & 0x3F
            rd = (w >> 21) & 0x1F
            ra = (w >> 16) & 0x1F
            uimm = w & 0xFFFF
            simm = uimm - 0x10000 if (uimm & 0x8000) else uimm
            if op == 15 and ra == 0:  # lis rd, simm
                hi_reg_ppc[rd] = (uimm << 16) & 0xFFFFFFFF
            elif op == 24 and ra in hi_reg_ppc:  # ori rd_out=ra, rs=rd, uimm
                # In PPC `ori rA, rS, UIMM`: target reg is `ra`, source reg is `rd`!
                pass
            if op == 24 and rd in hi_reg_ppc:
                _offer_word(hi_reg_ppc[rd] | uimm, f"lis+ori+0x{idx * 4:X}")
            elif op == 14 and ra in hi_reg_ppc and ra != 0:
                _offer_word((hi_reg_ppc[ra] + simm) & 0xFFFFFFFF, f"lis+addi+0x{idx * 4:X}")
            elif op == 48:  # lfs frD, d(rA)
                addr = None
                if ra in (2, 13):
                    base = ctx.sda_r2 if ra == 2 else ctx.sda_r13
                    if base:
                        addr = (base + simm) & 0xFFFFFFFF
                elif ra in hi_reg_ppc:
                    addr = (hi_reg_ppc[ra] + simm) & 0xFFFFFFFF
                if addr is not None:
                    try:
                        raw4 = ctx.read(addr, 4)
                        _offer_word(struct.unpack(">I", raw4)[0], f"rodata@0x{addr:08X}")
                    except ValueError:
                        pass

    return {"floats": floats[:16], "magic_divisions": magic_divs[:12]}


_FLOAT_LIT_RE = re.compile(r"(?<![A-Za-z0-9_.])(-?\d+\.\d+(?:[eE][+-]?\d+)?)f\b")
_HEX_MAGIC_RE = re.compile(r"\b0x([0-9A-Fa-f]{8})U?\b")


def constant_repair_variants(source: str, target_fn: TargetFunction, ctx: TargetContext) -> list[tuple[str, str]]:
    """Propose real-C variants snapping 1-3 ULP rounded floats to exact target `.rodata` bits."""
    scanned = scan_target_constants(target_fn, ctx)
    target_floats = scanned["floats"]
    if not target_floats:
        return []

    out: list[tuple[str, str]] = []
    # Snap any float literal within 0.1% relative tolerance (but different bits!) to exact target literal
    patched = source
    changed = False
    for m in _FLOAT_LIT_RE.finditer(source):
        lit_txt = m.group(1)
        try:
            cur_val = float(lit_txt)
            cur_bits = _pack_f32_be(cur_val)
        except ValueError:
            continue
        for tf in target_floats:
            t_val = tf["value"]
            t_bits = int(tf["hex"], 16)
            if cur_bits == t_bits or t_val == 0.0:
                continue
            rel_err = abs(cur_val - t_val) / max(abs(t_val), 1e-12)
            if rel_err <= 1e-3:
                patched = patched.replace(m.group(0), tf["c_literal"], 1)
                changed = True
                break
    if changed and patched != source:
        out.append(("exact_rodata_float", patched))
    return out
