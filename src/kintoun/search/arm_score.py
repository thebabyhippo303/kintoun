"""Dedicated ARM/Thumb (A32, Thumb-16, Thumb-32, and `$d` literal-pool) normalisation, scoring, and hints."""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
import difflib

from kintoun.arch.arm_disasm import (
    disasm_a32,
    disasm_thumb16,
    disasm_thumb32,
    is_thumb32_hw1,
)


@dataclass(frozen=True)
class ArmItem:
    """One instruction or `$d` literal-pool entry in an ARM/Thumb function stream."""

    offset: int
    size: int
    mode: str  # 'a', 't16', 't32', 'd'
    raw: int   # 32-bit word for 'a'/'d', 16-bit halfword for 't16'/'t32'
    hw2: int = 0  # second 16-bit halfword for 't32'
    pool_target_off: int | None = None  # byte offset of literal-pool word referenced by PC load


def infer_arm_intervals(
    data: bytes,
    default_thumb: bool = False,
    data_endian: str = "little",
    insn_endian: str = "little",
) -> list[tuple[int, int, str]]:
    """Infer `(start, end, mode)` intervals (`'a'`/`'t'` vs `'d'` literal pools) when mapping symbols are absent."""
    n = len(data)
    if n == 0:
        return []
    code_mode = "t" if default_thumb else "a"
    pool_offs: set[int] = set()

    if not default_thumb:
        for off in range(0, n - (n % 4), 4):
            if off in pool_offs:
                continue
            w = int.from_bytes(data[off : off + 4], insn_endian)
            # A32 LDR Rd, [PC, #+-imm12] (`cond != 0xF`, `top3 == 2`, `P=1`, `W=0`, `L=1`, `B=0`, `Rn=15`)
            if ((w >> 28) & 0xF) != 0xF and (w & 0x0F7F0000) == 0x051F0000:
                u = (w >> 23) & 1
                imm12 = w & 0xFFF
                disp = imm12 if u else -imm12
                target = off + 8 + disp
                if 0 <= target <= n - 4 and target % 4 == 0:
                    pool_offs.add(target)
    else:
        off = 0
        while off + 2 <= n:
            if off in pool_offs:
                off += 4
                continue
            hw1 = int.from_bytes(data[off : off + 2], insn_endian)
            if is_thumb32_hw1(hw1) and off + 4 <= n:
                hw2 = int.from_bytes(data[off + 2 : off + 4], insn_endian)
                # Thumb-2 LDR.W Rt, [PC, #+-imm12]
                if (hw1 & 0xFF7F) == 0xF85F:
                    u = (hw1 >> 7) & 1
                    disp = (hw2 & 0xFFF) if u else -(hw2 & 0xFFF)
                    target = ((off + 4) & ~3) + disp
                    if 0 <= target <= n - 4 and target % 4 == 0:
                        pool_offs.add(target)
                off += 4
            else:
                # Thumb-16 LDR Rd, [PC, #imm8*4] (`01001...`)
                if (hw1 >> 11) == 9:
                    target = ((off + 4) & ~3) + (hw1 & 0xFF) * 4
                    if 0 <= target <= n - 4 and target % 4 == 0:
                        pool_offs.add(target)
                off += 2

    if not pool_offs:
        return [(0, n, code_mode)]

    # Build contiguous intervals separating 4-byte literal pool words from code
    # Also mark trailing 2-byte alignment halfwords immediately before a pool as data padding
    data_bytes = [False] * n
    for poff in sorted(pool_offs):
        for b in range(poff, min(n, poff + 4)):
            data_bytes[b] = True
        # Thumb 2-byte alignment nop (`0x0000` or `0x46C0`) right before 4-byte aligned pool
        if default_thumb and poff >= 2 and not data_bytes[poff - 2]:
            pad = int.from_bytes(data[poff - 2 : poff], insn_endian)
            if pad == 0x0000:
                data_bytes[poff - 2] = data_bytes[poff - 1] = True
    # Trailing pool words after the first pool word at the end of a function if no code follows
    last_pool_end = max(pool_offs) + 4
    if last_pool_end == n or (n - last_pool_end <= 4 and data[last_pool_end:] == b"\x00" * (n - last_pool_end)):
        first_tail_pool = min(pool_offs)
        # If every instruction between first_tail_pool and n is pool or 4B constant after return
        all_pool = True
        pos = first_tail_pool
        while pos < n:
            if pos in pool_offs or data[pos : pos + 2] == b"\x00\x00":
                pos += 4 if pos + 4 <= n else 2
            else:
                all_pool = False
                break
        if all_pool:
            for b in range(first_tail_pool, n):
                data_bytes[b] = True

    intervals: list[tuple[int, int, str]] = []
    cur = 0
    while cur < n:
        m = "d" if data_bytes[cur] else code_mode
        end = cur + 1
        while end < n and ("d" if data_bytes[end] else code_mode) == m:
            end += 1
        intervals.append((cur, end, m))
        cur = end
    return intervals


def tokenize_arm(
    data: bytes,
    intervals: list[tuple[int, int, str]] | None = None,
    default_thumb: bool = False,
    data_endian: str = "little",
    insn_endian: str = "little",
) -> list[ArmItem]:
    """Segment raw ARM/Thumb bytes into `ArmItem`s using mapping-symbol or inferred intervals."""
    segs = intervals or infer_arm_intervals(data, default_thumb, data_endian, insn_endian)
    items: list[ArmItem] = []
    n = len(data)

    for seg_s, seg_e, mode in segs:
        pos = max(0, seg_s)
        stop = min(n, seg_e)
        if mode == "a":
            while pos + 4 <= stop:
                w = int.from_bytes(data[pos : pos + 4], insn_endian)
                pool_off = None
                if ((w >> 28) & 0xF) != 0xF and (w & 0x0F7F0000) == 0x051F0000:
                    disp = (w & 0xFFF) if ((w >> 23) & 1) else -(w & 0xFFF)
                    cand = pos + 8 + disp
                    if 0 <= cand <= n - 4:
                        pool_off = cand
                items.append(ArmItem(pos, 4, "a", w, 0, pool_off))
                pos += 4
            while pos < stop:
                items.append(ArmItem(pos, 1, "d", data[pos]))
                pos += 1
        elif mode == "t":
            while pos + 2 <= stop:
                hw1 = int.from_bytes(data[pos : pos + 2], insn_endian)
                if is_thumb32_hw1(hw1) and pos + 4 <= stop:
                    hw2 = int.from_bytes(data[pos + 2 : pos + 4], insn_endian)
                    pool_off = None
                    if (hw1 & 0xFF7F) == 0xF85F:
                        disp = (hw2 & 0xFFF) if ((hw1 >> 7) & 1) else -(hw2 & 0xFFF)
                        cand = ((pos + 4) & ~3) + disp
                        if 0 <= cand <= n - 4:
                            pool_off = cand
                    items.append(ArmItem(pos, 4, "t32", hw1, hw2, pool_off))
                    pos += 4
                else:
                    pool_off = None
                    if (hw1 >> 11) == 9:
                        cand = ((pos + 4) & ~3) + (hw1 & 0xFF) * 4
                        if 0 <= cand <= n - 4:
                            pool_off = cand
                    items.append(ArmItem(pos, 2, "t16", hw1, 0, pool_off))
                    pos += 2
            if pos < stop:
                items.append(ArmItem(pos, 1, "d", data[pos]))
        else:  # 'd' literal pool / inline data
            # Align to 4-byte boundary if Thumb left 2 bytes of zero padding before the pool
            if pos % 4 == 2 and pos + 2 <= stop:
                hw_pad = int.from_bytes(data[pos : pos + 2], data_endian)
                items.append(ArmItem(pos, 2, "d", hw_pad))
                pos += 2
            while pos + 4 <= stop:
                w = int.from_bytes(data[pos : pos + 4], data_endian)
                items.append(ArmItem(pos, 4, "d", w))
                pos += 4
            while pos + 2 <= stop:
                hw = int.from_bytes(data[pos : pos + 2], data_endian)
                items.append(ArmItem(pos, 2, "d", hw))
                pos += 2
            while pos < stop:
                items.append(ArmItem(pos, 1, "d", data[pos]))
                pos += 1
    return items


def _looks_like_reloc_addr(val: int, relocated_offsets: set[int], off: int) -> bool:
    if off in relocated_offsets:
        return True
    # GBA ROM/EWRAM/IWRAM (0x08.., 0x02.., 0x03..) or DS ITCM/ARM9 RAM (0x01FF.., 0x0200..0x023F..)
    top = (val >> 24) & 0xFF
    return top in (0x02, 0x03, 0x08, 0x09) and (val & 0xFFFFFF) != 0


def norm_arm_item(item: ArmItem, relocated_offsets: set[int] | None = None) -> int:
    """Relocation- and literal-pool-offset-insensitive normalisation of an `ArmItem`."""
    relocs = relocated_offsets or set()
    m = item.mode

    if m == "a":
        w = item.raw
        cond = (w >> 28) & 0xF
        if cond == 0xF and (w & 0xFE000000) == 0xFA000000:  # BLX label
            return 0xFA000000
        top3 = (w >> 25) & 7
        if top3 == 5:  # B / BL
            return w & 0xFF000000
        if (w & 0x0FB00000) == 0x03000000 and item.offset in relocs:  # relocated MOVW/MOVT
            return w & 0xFFF0F000
        if (w & 0x0F7F0000) == 0x051F0000:  # LDR Rd, [PC, #+-imm12]
            return w & 0xFF7FF000
        return w

    if m == "t16":
        h = item.raw
        top5 = (h >> 11) & 0x1F
        if top5 == 28:  # B imm11
            return h & 0xF800
        if top5 in (26, 27) and ((h >> 8) & 0xF) < 14:  # B<cond> imm8
            return h & 0xFF00
        if (h & 0xF500) == 0xB100:  # CBZ / CBNZ
            return h & 0xFD07
        if top5 in (9, 20):  # LDR Rd, [PC, #imm8*4] / ADR Rd, label
            return h & 0xFF00
        return h

    if m == "t32":
        h1, h2 = item.raw, item.hw2
        if (h1 & 0xF800) == 0xF000 and (h2 & 0x8000) == 0x8000:
            op2 = (h2 >> 12) & 7
            if op2 in (4, 5, 6, 7):  # BL / BLX
                return (0xF000 << 16) | (h2 & 0xD000)
            if op2 in (1, 3):  # B.W
                return (0xF000 << 16) | 0x9000
            if op2 in (0, 2) and ((h1 >> 6) & 0xF) < 14:  # B<cond>.W
                return ((h1 & 0xFBC0) << 16) | 0x8000
        if (h1 & 0xFB70) == 0xF240 and item.offset in relocs:  # relocated MOVW/MOVT
            return ((h1 & 0xFBF0) << 16) | (h2 & 0x8F00)
        if (h1 & 0xFF7F) == 0xF85F:  # LDR.W Rt, [PC, #+-imm12]
            return ((h1 & 0xFF7F) << 16) | (h2 & 0xF000)
        return (h1 << 16) | h2

    # mode == 'd'
    if item.size == 4 and _looks_like_reloc_addr(item.raw, relocs, item.offset):
        return 0xDDDD0000  # canonical relocated-symbol pool word tag
    return item.raw


def shape_arm_item(item: ArmItem, normed: int) -> int:
    """Register-allocation-invariant shape of an `ArmItem`."""
    m = item.mode
    if m == "a":
        w = item.raw
        cond = (w >> 28) & 0xF
        if cond == 0xF:
            return 0x10000000 | (normed & 0xFE000000)
        top3 = (w >> 25) & 7
        if (w & 0x0FFFFFF0) in (0x012FFF10, 0x012FFF30):  # BX / BLX Rm
            return 0x11000000 | (w & 0xFFFFFFF0)
        if top3 in (0, 1):
            # Preserve cond, opcode, S-bit, and whether Rn==sp/pc
            rn_role = 1 if ((w >> 16) & 0xF) == 13 else (2 if ((w >> 16) & 0xF) == 15 else 0)
            if top3 == 1:
                return 0x12000000 | (w & 0xFFF00000) | (rn_role << 16) | (w & 0xFFF)
            return 0x13000000 | (w & 0xFFF00000) | (rn_role << 16) | (w & 0xFF0)
        if top3 in (2, 3):
            rn_role = 1 if ((w >> 16) & 0xF) == 13 else (2 if ((w >> 16) & 0xF) == 15 else 0)
            return 0x14000000 | (w & 0xFFF00000) | (rn_role << 16) | (normed & 0xFFF)
        if top3 == 4:  # LDM/STM/PUSH/POP
            rn_role = 1 if ((w >> 16) & 0xF) == 13 else 0
            return 0x15000000 | (w & 0xFFF00000) | (rn_role << 16)
        if top3 == 5:
            return 0x16000000 | (w & 0xFF000000)
        return 0x17000000 | (normed & 0xFFF000F0)

    if m == "t16":
        h = item.raw
        top5 = (h >> 11) & 0x1F
        if top5 in (0, 1, 2):  # shift by imm
            return 0x20000000 | (h & 0xFFC0)
        if top5 == 3:  # add/sub 3-op
            return 0x21000000 | (h & 0xFE00) | ((h & 0x01C0) if (h & 0x0400) else 0)
        if top5 in (4, 5, 6, 7):  # movs/cmp/adds/subs imm8
            return 0x22000000 | (h & 0xF8FF)
        if (h >> 10) == 0b010000:  # ALU
            return 0x23000000 | (h & 0xFFC0)
        if (h >> 10) == 0b010001:  # Hi-reg / BX
            return 0x24000000 | (h & 0xFF00)
        if top5 == 9:  # LDR Rd, [PC, #imm]
            return 0x25000000 | 0x4800
        if top5 in (10, 11):  # reg-off load/store
            return 0x26000000 | (h & 0xFE00)
        if top5 in (12, 13, 14, 15, 16, 17):  # imm5 load/store
            return 0x27000000 | (h & 0xFFC0)
        if top5 in (18, 19, 20, 21):  # SP/PC rel
            return 0x28000000 | (h & 0xF8FF)
        if top5 in (22, 23):
            if (h & 0xF600) in (0xB400, 0xBC00):  # PUSH / POP
                return 0x29000000 | (h & 0xFF00)
            return 0x2A000000 | (normed & 0xFF80)
        if top5 in (24, 25):  # LDMIA / STMIA
            return 0x2B000000 | (h & 0xF800)
        if top5 in (26, 27, 28):  # B<cond> / B
            return 0x2C000000 | (normed & 0xFF00)
        return 0x2F000000 | normed

    if m == "t32":
        h1, h2 = item.raw, item.hw2
        if (h1 & 0xF800) == 0xF000 and (h2 & 0x8000) == 0x8000:
            return 0x30000000 | (normed & 0xFFFFD000)
        if (h1 & 0xFE40) == 0xE800:  # PUSH.W / POP.W / LDM.W / STM.W
            return 0x31000000 | (h1 & 0xFFF0)
        if (h1 & 0xFE00) == 0xF800:  # LDR.W / STR.W
            rn_role = 1 if (h1 & 0xF) == 13 else (2 if (h1 & 0xF) == 15 else 0)
            return 0x32000000 | ((h1 & 0xFFF0) << 8) | (rn_role << 4)
        return 0x33000000 | ((h1 & 0xFBF0) << 8) | ((h2 >> 4) & 0xF)

    # mode == 'd'
    return 0x40000000 | (item.size << 24) | (normed & 0x00FFFFFF)


def disasm_arm_item(item: ArmItem, base_va: int = 0) -> tuple[str, str]:
    pc = (base_va & ~1) + item.offset
    if item.mode == "a":
        return disasm_a32(item.raw, pc)
    if item.mode == "t16":
        return disasm_thumb16(item.raw, pc)
    if item.mode == "t32":
        return disasm_thumb32(item.raw, item.hw2, pc)
    if item.size == 4:
        return (".word", f"0x{item.raw:08x}")
    if item.size == 2:
        return (".short", f"0x{item.raw:04x}")
    return (".byte", f"0x{item.raw:02x}")


@dataclass
class ArmScore:
    total: int
    mism: int
    bits: int
    ours: list[ArmItem]
    target: list[ArmItem]
    ours_norm: list[int]
    target_norm: list[int]
    ops: list[tuple[str, int, int, int, int]] = field(default_factory=list)
    regdiff: int = 0
    ins: int = 0
    dele: int = 0
    opnd: int = 0
    hints: list[str] = field(default_factory=list)

    @property
    def key(self) -> tuple[int, int, int]:
        return (self.total, self.mism, self.bits)

    def mism_positional_only(self) -> int:
        return sum(
            1
            for ia, ib, na, nb in zip(self.ours, self.target, self.ours_norm, self.target_norm)
            if ia.mode != ib.mode or na != nb
        )

    @property
    def pct(self) -> float:
        n = max(len(self.ours), len(self.target), 1)
        return 100.0 * (min(len(self.ours), len(self.target)) - self.mism_positional_only()) / n

    @property
    def apct(self) -> float:
        n = max(len(self.ours), len(self.target), 1)
        same = sum(
            1
            for tag, i1, i2, j1, j2 in self.ops
            if tag == "equal"
            for k in range(i2 - i1)
            if self.ours[i1 + k].mode == self.target[j1 + k].mode
            and self.ours_norm[i1 + k] == self.target_norm[j1 + k]
        )
        return 100.0 * same / n

    def summary(self) -> str:
        return (
            f"total={self.total} aligned={self.apct:.1f}% mism={self.mism} "
            f"len {len(self.ours)}/{len(self.target)} regdiff={self.regdiff} "
            f"opnd={self.opnd} extra={self.ins} missing={self.dele}"
        )

    def diff(self, lines: int = 24, context: int = 1, base_va: int = 0) -> str:
        """Side-by-side aligned ARM/Thumb/literal-pool disassembly."""
        rows: list[tuple[str, int | None, int | None]] = []
        for tag, i1, i2, j1, j2 in self.ops:
            if tag == "equal":
                for k in range(i2 - i1):
                    same = (
                        self.ours[i1 + k].mode == self.target[j1 + k].mode
                        and self.ours_norm[i1 + k] == self.target_norm[j1 + k]
                    )
                    rows.append((" " if same else "!", i1 + k, j1 + k))
            elif tag == "replace":
                n = min(i2 - i1, j2 - j1)
                for k in range(n):
                    rows.append(("!", i1 + k, j1 + k))
                for k in range(n, i2 - i1):
                    rows.append(("-", i1 + k, None))
                for k in range(n, j2 - j1):
                    rows.append(("+", None, j1 + k))
            elif tag == "delete":
                for k in range(i1, i2):
                    rows.append(("-", k, None))
            else:
                for k in range(j1, j2):
                    rows.append(("+", None, k))

        keep: set[int] = set()
        for idx, (m, _, _) in enumerate(rows):
            if m != " ":
                for c in range(idx - context, idx + context + 1):
                    if 0 <= c < len(rows):
                        keep.add(c)

        out: list[str] = []
        shown = 0
        last = None
        for idx in sorted(keep):
            if shown >= lines:
                out.append(f"... ({sum(1 for r in rows if r[0] != ' ')} differing rows total)")
                break
            if last is not None and idx != last + 1:
                out.append("  ~")
            m, i, j = rows[idx]
            if i is not None:
                it_o = self.ours[i]
                mn_o, op_o = disasm_arm_item(it_o, base_va)
                o_str = f"{mn_o} {op_o}".strip()
                oi = f"{it_o.offset:4x}"
            else:
                o_str, oi = "-", "    "
            if j is not None:
                it_t = self.target[j]
                mn_t, op_t = disasm_arm_item(it_t, base_va)
                t_str = f"{mn_t} {op_t}".strip()
                ti = f"{it_t.offset:4x}"
            else:
                t_str, ti = "-", "    "
            out.append(f"{m}{oi}: {o_str:<32}| {ti}: {t_str}")
            shown += 1
            last = idx
        return "\n".join(out)


def score_arm(
    ours: list[ArmItem],
    target: list[ArmItem],
    ours_reloc_offs: set[int] | None = None,
    target_reloc_offs: set[int] | None = None,
    with_hints: bool = True,
) -> ArmScore:
    """Compute alignment-aware ARM/Thumb/literal-pool score between two `ArmItem` streams."""
    ours_norm = [norm_arm_item(it, ours_reloc_offs) for it in ours]
    target_norm = [norm_arm_item(it, target_reloc_offs) for it in target]
    sa = [shape_arm_item(it, nw) for it, nw in zip(ours, ours_norm)]
    sb = [shape_arm_item(it, nw) for it, nw in zip(target, target_norm)]

    sm = difflib.SequenceMatcher(None, sa, sb, autojunk=False)
    ops = sm.get_opcodes()
    total = regdiff = ins = dele = opnd = bits = 0

    for tag, i1, i2, j1, j2 in ops:
        if tag == "equal":
            for k in range(i2 - i1):
                a, b = ours_norm[i1 + k], target_norm[j1 + k]
                if a != b or ours[i1 + k].mode != target[j1 + k].mode:
                    regdiff += 1
                    total += 1
                    bits += (a ^ b).bit_count()
        elif tag == "replace":
            n = min(i2 - i1, j2 - j1)
            for k in range(n):
                ia, ib = ours[i1 + k], target[j1 + k]
                mna = disasm_arm_item(ia)[0].removesuffix(".w")
                mnb = disasm_arm_item(ib)[0].removesuffix(".w")
                total += 2 if mna == mnb else 3
                opnd += 1
                bits += (ours_norm[i1 + k] ^ target_norm[j1 + k]).bit_count()
            extra = (i2 - i1) - n
            miss = (j2 - j1) - n
            ins += extra
            dele += miss
            total += 3 * (extra + miss)
        elif tag == "delete":
            ins += i2 - i1
            total += 3 * (i2 - i1)
        else:
            dele += j2 - j1
            total += 3 * (j2 - j1)

    mism = (
        sum(
            1
            for ia, ib, na, nb in zip(ours, target, ours_norm, target_norm)
            if ia.mode != ib.mode or na != nb
        )
        + abs(len(ours) - len(target))
    )
    sc = ArmScore(
        total=total,
        mism=mism,
        bits=bits,
        ours=ours,
        target=target,
        ours_norm=ours_norm,
        target_norm=target_norm,
        ops=ops,
        regdiff=regdiff,
        ins=ins,
        dele=dele,
        opnd=opnd,
    )
    if with_hints and total:
        sc.hints = hints_arm(sc)
    return sc


_SIGNED_BRANCH_ARM = {
    "bge": "bcs", "bcs": "bge",
    "blt": "bcc", "bcc": "blt",
    "bgt": "bhi", "bhi": "bgt",
    "ble": "bls", "bls": "ble",
}
_MEM_WIDTH_ARM = {
    "ldrb": 1, "ldrsb": 1, "strb": 1, "ldrb.w": 1, "ldrsb.w": 1, "strb.w": 1,
    "ldrh": 2, "ldrsh": 2, "strh": 2, "ldrh.w": 2, "ldrsh.w": 2, "strh.w": 2,
    "ldr": 4, "str": 4, "ldr.w": 4, "str.w": 4,
    "ldrd": 8, "strd": 8,
}


def hints_arm(s: ArmScore) -> list[str]:
    """Generate actionable C-level decompilation hints from an aligned `ArmScore`."""
    H: list[str] = []
    o_dis = [disasm_arm_item(it) for it in s.ours]
    t_dis = [disasm_arm_item(it) for it in s.target]
    o_mn = [d[0] for d in o_dis]
    t_mn = [d[0] for d in t_dis]

    # Mode mismatch check (A32 vs Thumb)
    o_modes = {it.mode for it in s.ours if it.mode in ("a", "t16", "t32")}
    t_modes = {it.mode for it in s.target if it.mode in ("a", "t16", "t32")}
    if ("a" in o_modes) != ("a" in t_modes) and o_modes and t_modes:
        H.append(
            f"instruction set mismatch: ours is {'A32' if 'a' in o_modes else 'Thumb'} "
            f"while target is {'A32' if 'a' in t_modes else 'Thumb'} (check `-mthumb` / `-thumb` / `.thumb_func`)"
        )

    # Prologue push / saved registers check
    o_push = next((d[1] for d in o_dis[:4] if d[0].startswith("push")), None)
    t_push = next((d[1] for d in t_dis[:4] if d[0].startswith("push")), None)
    if o_push != t_push:
        H.append(
            f"prologue saved regs: ours `push {o_push or 'none'}` vs target `push {t_push or 'none'}` "
            "(adjust live temps across calls, declaration order, or `register` locals)"
        )

    # Thumb high-register spill (`mov r8..r11, rN`)
    o_hireg = sum(1 for mn, op in o_dis if mn == "mov" and any(r in op for r in ("r8", "r9", "r10", "r11")))
    t_hireg = sum(1 for mn, op in t_dis if mn == "mov" and any(r in op for r in ("r8", "r9", "r10", "r11")))
    if o_hireg != t_hireg:
        H.append(
            f"Thumb high-register (`r8-r11`) spills: ours {o_hireg} vs target {t_hireg} "
            "(Thumb low regs `r0-r7` are saturated; merge/split temps or reorder local declarations)"
        )

    pairs: list[tuple[int, int]] = []
    extra = Counter()
    missing = Counter()
    extra_at: dict[str, int] = {}
    missing_at: dict[str, int] = {}

    for tag, i1, i2, j1, j2 in s.ops:
        if tag == "equal":
            pairs += [
                (i1 + k, j1 + k)
                for k in range(i2 - i1)
                if s.ours_norm[i1 + k] != s.target_norm[j1 + k]
                or s.ours[i1 + k].mode != s.target[j1 + k].mode
            ]
        elif tag == "replace":
            n = min(i2 - i1, j2 - j1)
            pairs += [(i1 + k, j1 + k) for k in range(n)]
            for k in range(i1 + n, i2):
                extra[o_mn[k]] += 1
                extra_at.setdefault(o_mn[k], s.ours[k].offset)
            for k in range(j1 + n, j2):
                missing[t_mn[k]] += 1
                missing_at.setdefault(t_mn[k], s.target[k].offset)
        elif tag == "delete":
            for k in range(i1, i2):
                extra[o_mn[k]] += 1
                extra_at.setdefault(o_mn[k], s.ours[k].offset)
        else:
            for k in range(j1, j2):
                missing[t_mn[k]] += 1
                missing_at.setdefault(t_mn[k], s.target[k].offset)

    cats = Counter()
    where: dict[str, tuple[int, int]] = {}
    for i, j in pairs:
        a, b = o_mn[i], t_mn[j]
        ia, ib = s.ours[i], s.target[j]
        na, nb = s.ours_norm[i], s.target_norm[j]
        a_base, b_base = a.removesuffix(".w"), b.removesuffix(".w")
        if ia.mode == "d" and ib.mode == "d":
            key = "literal-pool"
        elif ia.mode != ib.mode and {ia.mode, ib.mode} == {"t16", "t32"} and a_base.removesuffix("s") == b_base.removesuffix("s"):
            key = "thumb-width"
        elif {a, b} == {"bl", "blx"}:
            key = "interworking"
        elif a == b:
            if shape_arm_item(ia, na) == shape_arm_item(ib, nb):
                key = "regalloc"
            elif "sp" in o_dis[i][1] or "sp" in t_dis[j][1]:
                key = "stack-slot"
            elif a in _MEM_WIDTH_ARM and "[pc" not in o_dis[i][1]:
                key = "field-offset"
            elif a in ("mov", "movs", "movw", "movt", "cmp", "adds", "subs", "add", "sub"):
                key = "immediate"
            else:
                key = "operand"
        elif _SIGNED_BRANCH_ARM.get(a_base) == b_base:
            key = "compare-signedness"
        elif {a_base, b_base} <= {"ldrb", "ldrsb"} or {a_base, b_base} <= {"ldrh", "ldrsh"}:
            key = "int-signedness"
        elif a in _MEM_WIDTH_ARM and b in _MEM_WIDTH_ARM and _MEM_WIDTH_ARM[a] != _MEM_WIDTH_ARM[b]:
            key = "field-width"
        elif a_base.startswith("b") and b_base.startswith("b"):
            key = "branch-polarity"
        else:
            key = f"{a}->{b}"
        cats[key] += 1
        where.setdefault(key, (i, j))

    ADVICE = {
        "regalloc": "register allocation: reorder local declarations, toggle `register` (`agbcc` allocates `r4-r7` by decl order), or split/merge temps",
        "literal-pool": "literal-pool `.word` differs: check 32-bit constant value, global symbol, or expression evaluation order",
        "thumb-width": "Thumb 16-bit vs 32-bit `.w` width differs: check `-march` (`armv4t`/`armv5te` vs `armv6t2+`) or high-reg `r8-r12` usage",
        "interworking": "interworking (`bl` vs `blx`): check callee ARM/Thumb state and `-mthumb-interwork`",
        "stack-slot": "stack frame/slot differs: check stack-allocated locals, array sizes, or spilled registers",
        "field-offset": "field offset: wrong struct member offset or array index on `[rN, #off]`",
        "immediate": "immediate differs: check constant value or loop bound",
        "compare-signedness": "compare signedness: flip signed (`s32`/`bge`/`blt`) <-> unsigned (`u32`/`bcs`/`bcc`)",
        "int-signedness": "narrow load signedness: flip `s8` <-> `u8` (`ldrsb`/`ldrb`) or `s16` <-> `u16` (`ldrsh`/`ldrh`)",
        "field-width": "field width: wrong load/store width (`u8`/`u16`/`u32`)",
        "branch-polarity": "branch polarity: invert `if`/`else` condition or swap branch bodies",
    }

    for key, count in cats.most_common():
        i, j = where[key]
        adv = ADVICE.get(key, f"{key} at aligned position")
        t_txt = f"{t_dis[j][0]} {t_dis[j][1]}".strip()
        o_txt = f"{o_dis[i][0]} {o_dis[i][1]}".strip()
        H.append(f"{count}x {adv} [first @+{s.target[j].offset:#x} target `{t_txt}` vs ours `{o_txt}`]")

    def fmt(counter: Counter, at_map: dict[str, int]) -> str:
        return ", ".join(f"{v}x {k}(@+{at_map[k]:#x})" for k, v in counter.most_common(6))

    if missing:
        H.append(f"missing in ours: {fmt(missing, missing_at)}")
    if extra:
        H.append(f"extra in ours: {fmt(extra, extra_at)}")
    if ("lsls" in missing and ("lsrs" in missing or "asrs" in missing)) and "lsls" not in extra:
        H.append(
            "target narrows via `lsls #24/#16` + `lsrs`/`asrs` (Thumb-1/`agbcc` idiom): "
            "use a `u8`/`s8`/`u16`/`s16` local or explicit cast"
        )
    if (".word" in extra or ".word" in missing) and extra.get(".word") != missing.get(".word"):
        H.append(
            f"literal pool size differs (ours {sum(1 for it in s.ours if it.mode == 'd')} vs "
            f"target {sum(1 for it in s.target if it.mode == 'd')} pool items): check large constants vs shifted immediates"
        )

    return H[:12]
