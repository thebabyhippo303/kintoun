"""Dedicated MIPS instruction normalisation, delay-slot-aware alignment, scoring, and codegen hints."""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
import difflib

from kintoun.arch.mips_disasm import disasm_mips_word

_SPECIAL_GPR_ROLES = {0: 1, 28: 2, 29: 3, 31: 4}  # $zero, $gp, $sp, $ra
_LOAD_OPS = {30, 32, 33, 34, 35, 36, 37, 38, 39, 48, 49, 53, 55}
_STORE_OPS = {31, 40, 41, 42, 43, 44, 45, 46, 56, 57, 61, 63}
_MEM_OPS = _LOAD_OPS | _STORE_OPS
_WIDTH_MIPS = {
    "lb": 1, "lbu": 1, "sb": 1,
    "lh": 2, "lhu": 2, "sh": 2,
    "lw": 4, "lwu": 4, "sw": 4, "lwl": 4, "lwr": 4, "swl": 4, "swr": 4, "lwc1": 4, "swc1": 4,
    "ld": 8, "sd": 8, "ldc1": 8, "sdc1": 8,
    "lq": 16, "sq": 16,
}
_SIGNED_CMP_MIPS = {
    "slt": "sltu",
    "sltu": "slt",
    "slti": "sltiu",
    "sltiu": "slti",
}


def words_mips(data: bytes, endian: str = "little") -> list[int]:
    """Unpack 32-bit MIPS instruction words in `little` or `big` byte order."""
    n = len(data) - (len(data) % 4)
    return [int.from_bytes(data[i : i + 4], endian) for i in range(0, n, 4)]


def is_branch_or_jump_mips(w: int) -> bool:
    """Return True if `w` is a MIPS branch or jump with an architectural delay slot."""
    op = (w >> 26) & 0x3F
    if op in (2, 3, 4, 5, 6, 7, 20, 21, 22, 23):
        return True
    if op == 1:
        rt = (w >> 16) & 0x1F
        return rt in (0, 1, 2, 3, 16, 17, 18, 19)
    if op == 0:
        return (w & 0x3F) in (8, 9)
    if op == 17:
        return ((w >> 21) & 0x1F) == 8
    return False


def _writes_gpr(w: int) -> int | None:
    """Return destination GPR written by `w`, or None."""
    op = (w >> 26) & 0x3F
    if op == 0:
        fn = w & 0x3F
        if fn in (8, 12, 13, 15, 17, 19, 26, 27, 28, 29, 30, 31, 41):
            return None
        rd = (w >> 11) & 0x1F
        return rd if rd != 0 else None
    if op in (8, 9, 10, 11, 12, 13, 14, 15, 24, 25) or op in _LOAD_OPS:
        if op in (49, 53):
            return None
        rt = (w >> 16) & 0x1F
        return rt if rt != 0 else None
    if op == 17 and ((w >> 21) & 0x1F) in (0, 2):  # mfc1 / cfc1
        rt = (w >> 16) & 0x1F
        return rt if rt != 0 else None
    if op == 28 and (w & 0x3F) in (0, 1, 2, 4, 16, 18, 24, 25, 32, 33):
        rd = (w >> 11) & 0x1F
        return rd if rd != 0 else None
    if op == 31:
        fn = w & 0x3F
        if fn in (0, 4):
            rt = (w >> 16) & 0x1F
            return rt if rt != 0 else None
        if fn == 32:
            rd = (w >> 11) & 0x1F
            return rd if rd != 0 else None
    return None


def norm_mips_word(w: int, lui_live: set[int] | None = None) -> int:
    """Relocation- and GP-insensitive normalisation of a single MIPS instruction word."""
    op = (w >> 26) & 0x3F
    if op in (2, 3):  # j / jal
        return w & 0xFC000000
    if op in (4, 5, 6, 7, 20, 21, 22, 23):  # branches
        return w & 0xFFFF0000
    if op == 1 and ((w >> 16) & 0x1F) in (0, 1, 2, 3, 16, 17, 18, 19):
        return w & 0xFFFF0000
    if op == 17 and ((w >> 21) & 0x1F) == 8:  # bc1f/bc1t
        return w & 0xFFFF0000
    if op == 15 and ((w >> 21) & 0x1F) == 0:  # lui
        return w & 0xFFFF0000
    rs = (w >> 21) & 0x1F
    if rs == 28 and (op == 9 or op in _MEM_OPS):  # $gp-relative small-data
        return w & 0xFFFF0000
    if lui_live and rs in lui_live and (op in (9, 13, 25) or op in _MEM_OPS):
        return w & 0xFFFF0000
    return w


def norm_mips_stream(words: list[int]) -> list[int]:
    """Context-aware MIPS stream normalisation (masks `lui` + paired `%lo` immediates)."""
    out: list[int] = []
    lui_live: set[int] = set()
    in_delay = False
    for w in words:
        out.append(norm_mips_word(w, lui_live))
        op = (w >> 26) & 0x3F
        rs = (w >> 21) & 0x1F
        rt = (w >> 16) & 0x1F
        if op == 15 and rs == 0 and rt != 0:
            lui_live.add(rt)
        else:
            dst = _writes_gpr(w)
            if dst is not None:
                # `addiu rd, rs, %lo(sym)` where rs in lui_live produces the symbol pointer in rd,
                # not a fresh unconsumed `lui`, so clear `dst` cleanly.
                lui_live.discard(dst)
        if in_delay:
            in_delay = False
        elif is_branch_or_jump_mips(w):
            in_delay = True
            if op == 3 or (op == 0 and (w & 0x3F) == 9):  # jal / jalr clobbers caller-saved temps after delay
                pass
    return out


def _role_tag(reg: int) -> int:
    return _SPECIAL_GPR_ROLES.get(reg, 0)


def shape_mips(w: int, normed: int) -> int:
    """Extract register-allocation-invariant instruction shape while preserving `$zero/$gp/$sp/$ra` roles."""
    if w == 0:
        return 0
    op = (w >> 26) & 0x3F
    rs = (w >> 21) & 0x1F
    rt = (w >> 16) & 0x1F
    rd = (w >> 11) & 0x1F

    if op == 0:
        fn = w & 0x3F
        role = (_role_tag(rs) << 6) | (_role_tag(rt) << 3) | _role_tag(rd)
        if fn in (0, 2, 3, 56, 58, 59, 60, 62, 63):  # shift by immediate keeps shift amount
            return (0x40 << 24) | (fn << 16) | (((w >> 6) & 0x1F) << 9) | role
        return (0x41 << 24) | (fn << 16) | role

    if op in (2, 3):
        return op << 26

    if op == 1:
        return (op << 26) | (rt << 16) | (_role_tag(rs) << 8)

    if op in (4, 5, 6, 7, 20, 21, 22, 23):
        return (op << 26) | (_role_tag(rs) << 19) | (_role_tag(rt) << 16)

    if op in (8, 9, 10, 11, 12, 13, 14, 15, 24, 25) or op in _MEM_OPS:
        # Mask general rs/rt, preserve special roles ($zero/$gp/$sp/$ra) and normed immediate
        role = (_role_tag(rs) << 20) | (_role_tag(rt) << 16)
        return (op << 26) | role | (normed & 0xFFFF)

    if op == 17:  # COP1
        if rs in (0, 2, 4, 6):
            return (op << 26) | (rs << 21) | (_role_tag(rt) << 16)
        if rs == 8:
            return (op << 26) | (rs << 21) | ((rt & 3) << 16)
        return (op << 26) | (rs << 21) | (w & 0x3F)

    if op == 28:
        return (op << 26) | (w & 0x3F)

    if op == 31:
        fn = w & 0x3F
        if fn in (0, 4, 32):
            return (op << 26) | (fn << 16) | (((w >> 6) & 0x1F) << 8)
        return (op << 26) | (_role_tag(rs) << 20) | (normed & 0xFFFF)

    return normed


def _detect_delay_slot_swaps(
    ours: list[int],
    target: list[int],
    ours_shapes: list[int],
    target_shapes: list[int],
    ops: list[tuple[str, int, int, int, int]],
) -> list[dict[str, int | str]]:
    """Identify branch/jump delay-slot fill or swap mismatches across aligned hunks."""
    swaps: list[dict[str, int | str]] = []
    # Scan branch positions in target and ours near differing opcodes
    diff_o = set()
    diff_t = set()
    for tag, i1, i2, j1, j2 in ops:
        if tag != "equal":
            diff_o.update(range(max(0, i1 - 2), min(len(ours), i2 + 2)))
            diff_t.update(range(max(0, j1 - 2), min(len(target), j2 + 2)))

    # Case 1: Ours has [X, Branch, nop] where Target has [Branch, X] (unfilled delay slot in ours)
    for i in sorted(diff_o):
        if i - 1 >= 0 and i + 1 < len(ours) and is_branch_or_jump_mips(ours[i]) and ours[i + 1] == 0:
            pre_shape = ours_shapes[i - 1]
            br_shape = ours_shapes[i]
            for j in sorted(diff_t):
                if j + 1 < len(target) and target_shapes[j] == br_shape and target_shapes[j + 1] == pre_shape:
                    swaps.append({"kind": "ours_unfilled", "ours_branch": i, "target_branch": j})
                    break

    # Case 2: Target has [X, Branch, nop] while Ours filled [Branch, X]
    for j in sorted(diff_t):
        if j - 1 >= 0 and j + 1 < len(target) and is_branch_or_jump_mips(target[j]) and target[j + 1] == 0:
            pre_shape = target_shapes[j - 1]
            br_shape = target_shapes[j]
            for i in sorted(diff_o):
                if i + 1 < len(ours) and ours_shapes[i] == br_shape and ours_shapes[i + 1] == pre_shape:
                    swaps.append({"kind": "target_unfilled", "ours_branch": i, "target_branch": j})
                    break

    # Case 3: Both filled delay slot, but swapped pre-branch and slot instruction: [X, Branch, Y] vs [Y, Branch, X]
    for i in sorted(diff_o):
        if 0 < i < len(ours) - 1 and is_branch_or_jump_mips(ours[i]) and ours[i + 1] != 0:
            for j in sorted(diff_t):
                if (
                    0 < j < len(target) - 1
                    and is_branch_or_jump_mips(target[j])
                    and ours_shapes[i] == target_shapes[j]
                    and ours_shapes[i - 1] == target_shapes[j + 1]
                    and ours_shapes[i + 1] == target_shapes[j - 1]
                    and ours_shapes[i - 1] != ours_shapes[i + 1]
                ):
                    swaps.append({"kind": "slot_swapped", "ours_branch": i, "target_branch": j})
                    break

    return swaps


@dataclass
class MipsScore:
    total: int
    mism: int
    bits: int
    ours: list[int]
    target: list[int]
    ours_norm: list[int]
    target_norm: list[int]
    ops: list[tuple[str, int, int, int, int]] = field(default_factory=list)
    regdiff: int = 0
    ins: int = 0
    dele: int = 0
    opnd: int = 0
    delay_swaps: list[dict[str, int | str]] = field(default_factory=list)
    hints: list[str] = field(default_factory=list)

    @property
    def key(self) -> tuple[int, int, int]:
        return (self.total, self.mism, self.bits)

    def mism_positional_only(self) -> int:
        return sum(1 for a, b in zip(self.ours_norm, self.target_norm) if a != b)

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
            if self.ours_norm[i1 + k] == self.target_norm[j1 + k]
        )
        return 100.0 * same / n

    def summary(self) -> str:
        return (
            f"total={self.total} aligned={self.apct:.1f}% mism={self.mism} "
            f"len {len(self.ours)}/{len(self.target)} regdiff={self.regdiff} "
            f"opnd={self.opnd} extra={self.ins} missing={self.dele}"
        )

    def diff(self, lines: int = 24, context: int = 1, base_va: int = 0) -> str:
        """Side-by-side aligned MIPS disassembly with delay-slot markers."""
        ours_slot = {i + 1 for i, w in enumerate(self.ours[:-1]) if is_branch_or_jump_mips(w)}
        targ_slot = {j + 1 for j, w in enumerate(self.target[:-1]) if is_branch_or_jump_mips(w)}

        rows: list[tuple[str, int | None, int | None]] = []
        for tag, i1, i2, j1, j2 in self.ops:
            if tag == "equal":
                for k in range(i2 - i1):
                    m = "!" if self.ours_norm[i1 + k] != self.target_norm[j1 + k] else " "
                    rows.append((m, i1 + k, j1 + k))
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
                mn_o, op_o = disasm_mips_word(self.ours[i], base_va + i * 4)
                prefix_o = "^" if i in ours_slot else " "
                o_str = f"{prefix_o}{mn_o}" + (f" {op_o}" if op_o else "")
                oi = f"{i * 4:4x}"
            else:
                o_str, oi = "-", "    "
            if j is not None:
                mn_t, op_t = disasm_mips_word(self.target[j], base_va + j * 4)
                prefix_t = "^" if j in targ_slot else " "
                t_str = f"{prefix_t}{mn_t}" + (f" {op_t}" if op_t else "")
                ti = f"{j * 4:4x}"
            else:
                t_str, ti = "-", "    "
            out.append(f"{m}{oi}: {o_str:<32}| {ti}: {t_str}")
            shown += 1
            last = idx
        return "\n".join(out)


def score_mips(ours: list[int], target: list[int], with_hints: bool = True) -> MipsScore:
    """Compute alignment- and delay-slot-aware MIPS score between two instruction word streams."""
    ours_norm = norm_mips_stream(ours)
    target_norm = norm_mips_stream(target)
    sa = [shape_mips(w, nw) for w, nw in zip(ours, ours_norm)]
    sb = [shape_mips(w, nw) for w, nw in zip(target, target_norm)]

    sm = difflib.SequenceMatcher(None, sa, sb, autojunk=False)
    ops = sm.get_opcodes()
    total = regdiff = ins = dele = opnd = bits = 0
    for tag, i1, i2, j1, j2 in ops:
        if tag == "equal":
            for k in range(i2 - i1):
                a, b = ours_norm[i1 + k], target_norm[j1 + k]
                if a != b:
                    regdiff += 1
                    total += 1
                    bits += (a ^ b).bit_count()
        elif tag == "replace":
            n = min(i2 - i1, j2 - j1)
            for k in range(n):
                a, b = ours[i1 + k], target[j1 + k]
                same_op = ((a >> 26) == (b >> 26)) and (((a >> 26) != 0) or ((a & 0x3F) == (b & 0x3F)))
                total += 2 if same_op else 3
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

    delay_swaps = _detect_delay_slot_swaps(ours, target, sa, sb, ops)
    # Discount pure delay-slot reorderings relative to unrelated missing/extra instructions
    if delay_swaps and total > 2:
        discount = min(total - 1, 2 * len(delay_swaps))
        total -= discount

    mism = sum(1 for a, b in zip(ours_norm, target_norm) if a != b) + abs(len(ours) - len(target))
    sc = MipsScore(
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
        delay_swaps=delay_swaps,
    )
    if with_hints and total:
        sc.hints = hints_mips(sc)
    return sc


def _prologue_frame(words: list[int]) -> tuple[int | None, int]:
    """Return `(index, frame_bytes)` for `addiu/daddiu $sp, $sp, -N` in the prologue."""
    for k, w in enumerate(words[:8]):
        op = (w >> 26) & 0x3F
        rs, rt = (w >> 21) & 0x1F, (w >> 16) & 0x1F
        if op in (9, 25) and rs == 29 and rt == 29:
            imm = w & 0xFFFF
            simm = imm - 0x10000 if imm & 0x8000 else imm
            if simm < 0:
                return k, -simm
    return None, 0


def _saved_s_regs(words: list[int]) -> list[str]:
    saved: list[str] = []
    for w in words[:16]:
        op = (w >> 26) & 0x3F
        rs, rt = (w >> 21) & 0x1F, (w >> 16) & 0x1F
        if op in (43, 63, 31) and rs == 29 and (16 <= rt <= 23 or rt == 30):
            name = "$fp" if rt == 30 else f"$s{rt - 16}"
            if name not in saved:
                saved.append(name)
    return saved


def _saves_ra(words: list[int]) -> bool:
    for w in words[:12]:
        op = (w >> 26) & 0x3F
        rs, rt = (w >> 21) & 0x1F, (w >> 16) & 0x1F
        if op in (43, 63, 31) and rs == 29 and rt == 31:
            return True
    return False


def hints_mips(s: MipsScore) -> list[str]:
    """Generate actionable C-level decompilation hints from an aligned `MipsScore`."""
    H: list[str] = []
    o_dis = [disasm_mips_word(w, i * 4) for i, w in enumerate(s.ours)]
    t_dis = [disasm_mips_word(w, j * 4) for j, w in enumerate(s.target)]
    o_mn = [d[0] for d in o_dis]
    t_mn = [d[0] for d in t_dis]

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
            ]
        elif tag == "replace":
            n = min(i2 - i1, j2 - j1)
            pairs += [(i1 + k, j1 + k) for k in range(n)]
            for k in range(i1 + n, i2):
                extra[o_mn[k]] += 1
                extra_at.setdefault(o_mn[k], k)
            for k in range(j1 + n, j2):
                missing[t_mn[k]] += 1
                missing_at.setdefault(t_mn[k], k)
        elif tag == "delete":
            for k in range(i1, i2):
                extra[o_mn[k]] += 1
                extra_at.setdefault(o_mn[k], k)
        else:
            for k in range(j1, j2):
                missing[t_mn[k]] += 1
                missing_at.setdefault(t_mn[k], k)

    # 1. Prologue / stack frame / $ra / $s0-$s7
    o_fidx, o_fsz = _prologue_frame(s.ours)
    t_fidx, t_fsz = _prologue_frame(s.target)
    if (o_fidx is None) != (t_fidx is None):
        H.append(
            "frame: target %s a stack frame; ours %s (check calls, address-taken locals, or stack arrays)"
            % ("allocates" if t_fidx is not None else "has no", "does not" if t_fidx is not None else "does")
        )
    elif o_fidx is not None and o_fsz != t_fsz:
        H.append(
            f"frame size: ours {o_fsz} bytes vs target {t_fsz} bytes (spilled temps, saved $s regs, or local arrays)"
        )

    o_ra, t_ra = _saves_ra(s.ours), _saves_ra(s.target)
    if o_ra != t_ra:
        H.append(
            "return address ($ra): target %s; ours %s"
            % ("saves $ra (calls a function)" if t_ra else "is a leaf", "is a leaf" if t_ra else "saves $ra")
        )

    o_s, t_s = _saved_s_regs(s.ours), _saved_s_regs(s.target)
    if o_s != t_s:
        H.append(
            f"callee-saved regs: ours {o_s or 'none'} vs target {t_s or 'none'}: "
            "adjust values live across `jal` calls (split/merge temps or recompute after call)"
        )

    # 2. Delay-slot diagnoses
    for ds in s.delay_swaps[:2]:
        ob, tb = int(ds["ours_branch"]), int(ds["target_branch"])
        if ds["kind"] == "ours_unfilled":
            H.append(
                f"delay-slot fill: target fills branch delay slot @+{tb * 4:#x} (`{t_mn[tb + 1]}`), "
                f"ours emits `nop` @+{(ob + 1) * 4:#x} (invert branch condition, simplify guard, or check -O2)"
            )
        elif ds["kind"] == "target_unfilled":
            H.append(
                f"delay-slot unfilled in target @+{tb * 4:#x}: target keeps `nop` in delay slot "
                "(try volatile/barrier, loop shape, or lower optimization level)"
            )
        else:
            H.append(
                f"delay-slot instruction order @+{tb * 4:#x}: swapped pre-branch and delay-slot instruction "
                "(reorder independent assignments before the branch/return)"
            )

    # 3. Aligned operand / opcode differences
    cats = Counter()
    where: dict[str, tuple[int, int]] = {}
    for i, j in pairs:
        a, b = o_mn[i], t_mn[j]
        wa, wb = s.ours[i], s.target[j]
        na, nb = s.ours_norm[i], s.target_norm[j]
        rs_a, rs_b = (wa >> 21) & 0x1F, (wb >> 21) & 0x1F
        key = None
        if a == b:
            if shape_mips(wa, na) == shape_mips(wb, nb):
                key = "regalloc"
            elif (a in _WIDTH_MIPS or a in ("addiu", "daddiu")) and (rs_a == 29 or rs_b == 29):
                key = "stack-slot"
            elif a in _WIDTH_MIPS and rs_a not in (0, 28, 29) and rs_b not in (0, 28, 29):
                key = "field-offset"
            elif a in ("sll", "srl", "sra", "andi", "ext", "ins"):
                key = "mask/shift"
            elif a in ("li", "addiu", "ori", "slti", "sltiu", "xori", "lui"):
                key = "immediate"
            elif is_branch_or_jump_mips(wa):
                key = "branch-target"
            else:
                key = "operand"
        elif _SIGNED_CMP_MIPS.get(a) == b:
            key = "compare-signedness"
        elif {a, b} <= {"lb", "lbu"} or {a, b} <= {"lh", "lhu"} or {a, b} <= {"lw", "lwu"}:
            key = "int-signedness"
        elif a in _WIDTH_MIPS and b in _WIDTH_MIPS and _WIDTH_MIPS[a] != _WIDTH_MIPS[b]:
            key = "field-width"
        elif (rs_a == 28) != (rs_b == 28) or ({a, b} <= {"lui", "lw", "lbu", "lh", "sw", "addiu"} and 28 in (rs_a, rs_b)):
            key = "gp-vs-lui"
        elif {a, b} <= {"mult", "multu", "mul", "sll", "addu"}:
            key = "mul-vs-shift"
        elif {a, b} <= {"div", "divu", "sra", "srl"}:
            key = "div-signedness"
        elif is_branch_or_jump_mips(wa) and is_branch_or_jump_mips(wb):
            key = "branch-polarity"
        elif {a, b} <= {"li", "addiu", "ori", "lui"}:
            key = "immediate"
        elif (a.endswith(".s") and b.endswith(".d")) or (a.endswith(".d") and b.endswith(".s")):
            key = "float-vs-double"
        else:
            key = f"{a}->{b}"
        cats[key] += 1
        where.setdefault(key, (i, j))

    ADVICE = {
        "regalloc": "register allocation: reorder local declarations, split/merge temporaries, or copy parameters ($a0-$a3 vs $v/$t/$s)",
        "stack-slot": "stack layout: declaration order or count of stack-resident locals/spills differs",
        "field-offset": "field offset: wrong struct member offset or pointer base (+0x.. displacement)",
        "immediate": "immediate differs: check integer constant, signed vs unsigned 16-bit literal (`addiu` vs `ori`), or loop bound",
        "compare-signedness": "compare signedness: flip s32 <-> u32 operands to switch `slt`/`slti` <-> `sltu`/`sltiu`",
        "int-signedness": "narrow load signedness: flip s8 <-> u8 (`lb`/`lbu`) or s16 <-> u16 (`lh`/`lhu`)",
        "field-width": "field width: wrong memory access size (u8/u16/u32/u64) at that offset",
        "gp-vs-lui": "global addressing ($gp vs lui/%lo): adjust `-G` small-data threshold, `extern T x;` vs `extern T x[];`, or `.sdata` section attribute",
        "mul-vs-shift": "multiply vs shift/add: rewrite `x * K` <-> `(x << n)` or check signed vs unsigned multiply",
        "div-signedness": "division signedness: s32 vs u32 on `/` or `%` (`div` vs `divu` / shift)",
        "branch-polarity": "branch polarity/likely: invert `if`/`else` condition or check branch-likely (`beql`/`bnel`) loop structure",
        "float-vs-double": "float vs double: use `1.0f` suffix and `f32` temps to avoid `cvt.d.s`/`cvt.s.d` double promotion",
        "mask/shift": "bit mask or shift differs: check cast width (`(u8)`/`(s16)`) or bitfield shift amount",
        "branch-target": "branch distance: block layout or size differs",
    }

    for key, count in cats.most_common():
        i, j = where[key]
        adv = ADVICE.get(key, f"{key} at aligned position")
        t_txt = f"{t_dis[j][0]} {t_dis[j][1]}".strip()
        o_txt = f"{o_dis[i][0]} {o_dis[i][1]}".strip()
        H.append(f"{count}x {adv} [first @+{j * 4:#x} target `{t_txt}` vs ours `{o_txt}`]")

    def fmt(counter: Counter, at_map: dict[str, int]) -> str:
        return ", ".join(f"{v}x {k}(@+{at_map[k] * 4:#x})" for k, v in counter.most_common(6))

    if missing:
        H.append(f"missing in ours: {fmt(missing, missing_at)}")
    if extra:
        H.append(f"extra in ours: {fmt(extra, extra_at)}")
    both = set(missing) & set(extra)
    if both:
        H.append(
            f"same opcodes both missing and extra ({', '.join(sorted(both))}): "
            "statement evaluation order, delay-slot scheduling, or temp lifetime"
        )
    if ("sll" in missing and "sra" in missing) and not ("sll" in extra and "sra" in extra):
        H.append("target sign-extends via `sll`+`sra`: add an explicit `(s16)` or `(s8)` cast on the int temp")
    if "andi" in missing and ("sll" in extra or "sra" in extra):
        H.append("target zero-extends via `andi 0xff/0xffff`: use unsigned `u8`/`u16` instead of signed `s8`/`s16`")
    if "cvt.d.s" in extra or "cvt.s.d" in extra:
        H.append("ours promotes float to double (`cvt.d.s`/`cvt.s.d`): add `f` suffix to float literals (`0.0f`, `1.0f`)")
    if "move" in extra and "move" not in missing:
        H.append("extra `move`: avoid copying an argument or return value into an unnecessary intermediate temp")
    if ("movz" in missing or "movn" in missing) and ("movz" not in extra and "movn" not in extra):
        H.append("target uses conditional move (`movz`/`movn`): try ternary `cond ? a : b` instead of `if`/`else`")

    return H[:12]
