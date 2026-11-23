#!/usr/bin/env python3
"""mt v4 scoring: alignment-aware, relocation/symbol-insensitive, with actionable hints.

score(ours_words, target_words) -> Score with
  .total   search objective (lower is better; 0 == byte match under norm)
  .mism    positional mismatch count (tkv3 meaning, shown as %)
  .hints   list of "what to change next" strings
  .diff()  aligned side-by-side listing
"""
from __future__ import annotations
import difflib, re, struct
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

A_FORM_XO = {18, 20, 21, 22, 23, 25, 26, 28, 29, 30, 31}


def norm(w):
    """match_one.norm: relocations and SDA/absolute loads masked."""
    op = w >> 26
    if op == 18: return w & 0xFC000003
    if op == 16: return w & 0xFFFF0003
    if op in (15, 14): return w & 0xFFFF0000
    if 32 <= op <= 55:
        ra = (w >> 16) & 0x1f
        if ra in (0, 2, 13): return w & 0xFFE00000
    return w


def reg_mask(w):
    """bits holding register numbers for this opcode (masked to get the 'shape')."""
    op = w >> 26
    if op in (14, 15) or 32 <= op <= 55: return 0x03FF0000
    if op in (7, 8, 10, 11, 12, 13, 24, 25, 26, 27, 28, 29, 20, 21): return 0x03FF0000
    if op == 23: return 0x03FFF800
    if op == 31: return 0x03FFF800
    if op in (59, 63):
        m = 0x03FFF800
        if (w >> 1) & 31 in A_FORM_XO and ((w >> 1) & 0x3FF) not in (0, 32, 40, 72, 136, 264, 12, 14, 15, 64, 38, 583, 711):
            m |= 0x7C0
        return m
    return 0


def shape(w):
    return norm(w) & ~reg_mask(w)


MN_CACHE = {}
def mnemonic(w):
    """cheap mnemonic for hints (capstone)."""
    if w in MN_CACHE: return MN_CACHE[w]
    try:
        from capstone import Cs, CS_ARCH_PPC, CS_MODE_32, CS_MODE_BIG_ENDIAN
        md = MN_CACHE.setdefault('_md', Cs(CS_ARCH_PPC, CS_MODE_32 | CS_MODE_BIG_ENDIAN))
        ins = list(md.disasm(w.to_bytes(4, 'big'), 0))
        r = (ins[0].mnemonic, ins[0].op_str) if ins else ('.long', f'{w:#x}')
    except Exception:
        r = ('?', '')
    MN_CACHE[w] = r
    return r


@dataclass
class Score:
    total: int
    mism: int
    bits: int
    ours: list
    target: list
    ops: list = field(default_factory=list)   # difflib opcodes on shapes
    regdiff: int = 0
    ins: int = 0
    dele: int = 0
    opnd: int = 0
    hints: list = field(default_factory=list)

    @property
    def key(self):
        return (self.total, self.mism, self.bits)

    @property
    def pct(self):
        n = max(len(self.ours), len(self.target), 1)
        return 100.0 * (min(len(self.ours), len(self.target)) - self.mism_positional_only()) / n

    def mism_positional_only(self):
        return sum(1 for a, b in zip(self.ours, self.target) if norm(a) != norm(b))

    @property
    def apct(self):
        """alignment-based match percentage (one missing instruction no longer shifts everything)."""
        n = max(len(self.ours), len(self.target), 1)
        same = sum(1 for tag, i1, i2, j1, j2 in self.ops if tag == 'equal'
                   for k in range(i2 - i1) if norm(self.ours[i1 + k]) == norm(self.target[j1 + k]))
        return 100.0 * same / n

    def summary(self):
        return (f'total={self.total} aligned={self.apct:.1f}% mism={self.mism} len {len(self.ours)}/{len(self.target)} '
                f'regdiff={self.regdiff} opnd={self.opnd} extra={self.ins} missing={self.dele}')

    def diff(self, lines=24, context=1):
        """aligned side-by-side: ' ' same, '!' same shape different regs/operands, '-' ours only, '+' target only"""
        rows = []
        for tag, i1, i2, j1, j2 in self.ops:
            if tag == 'equal':
                for k in range(i2 - i1):
                    a, b = self.ours[i1 + k], self.target[j1 + k]
                    rows.append(('!' if norm(a) != norm(b) else ' ', i1 + k, j1 + k))
            elif tag == 'replace':
                n = min(i2 - i1, j2 - j1)
                for k in range(n): rows.append(('!', i1 + k, j1 + k))
                for k in range(n, i2 - i1): rows.append(('-', i1 + k, None))
                for k in range(n, j2 - j1): rows.append(('+', None, j1 + k))
            elif tag == 'delete':
                for k in range(i1, i2): rows.append(('-', k, None))
            else:
                for k in range(j1, j2): rows.append(('+', None, k))
        keep = set()
        for idx, (m, _, _) in enumerate(rows):
            if m != ' ':
                for j in range(idx - context, idx + context + 1):
                    if 0 <= j < len(rows): keep.add(j)
        out = []; shown = 0; last = None
        for idx in sorted(keep):
            if shown >= lines: out.append(f'... ({sum(1 for r in rows if r[0] != " ")} differing rows total)'); break
            if last is not None and idx != last + 1: out.append('  ~')
            m, i, j = rows[idx]
            o = ' '.join(mnemonic(self.ours[i])) if i is not None else '-'
            t = ' '.join(mnemonic(self.target[j])) if j is not None else '-'
            oi = f'{i*4:4x}' if i is not None else '    '
            ti = f'{j*4:4x}' if j is not None else '    '
            out.append(f'{m}{oi}: {o:<32}| {ti}: {t}'); shown += 1; last = idx
        return '\n'.join(out)


def score(ours, target, with_hints=True):
    """ours/target: lists of 32-bit words."""
    sa = [shape(w) for w in ours]; sb = [shape(w) for w in target]
    sm = difflib.SequenceMatcher(None, sa, sb, autojunk=False)
    ops = sm.get_opcodes()
    total = regdiff = ins = dele = opnd = bits = 0
    for tag, i1, i2, j1, j2 in ops:
        if tag == 'equal':
            for k in range(i2 - i1):
                a, b = norm(ours[i1 + k]), norm(target[j1 + k])
                if a != b:
                    regdiff += 1; total += 1; bits += (a ^ b).bit_count()
        elif tag == 'replace':
            n = min(i2 - i1, j2 - j1)
            for k in range(n):
                a, b = ours[i1 + k], target[j1 + k]
                same_op = (a >> 26) == (b >> 26) and ((a >> 26) != 31 or ((a >> 1) & 0x3FF) == ((b >> 1) & 0x3FF))
                total += 2 if same_op else 3; opnd += 1; bits += (norm(a) ^ norm(b)).bit_count()
            extra = (i2 - i1) - n; miss = (j2 - j1) - n
            ins += extra; dele += miss; total += 3 * (extra + miss)
        elif tag == 'delete':
            ins += i2 - i1; total += 3 * (i2 - i1)
        else:
            dele += j2 - j1; total += 3 * (j2 - j1)
    mism = sum(1 for a, b in zip(ours, target) if norm(a) != norm(b)) + abs(len(ours) - len(target))
    s = Score(total, mism, bits, ours, target, ops, regdiff, ins, dele, opnd)
    if with_hints and total: s.hints = hints(s)
    return s


# ---------- hints ----------
SIGNED_CMP = {'cmpw': 'cmplw', 'cmpwi': 'cmplwi', 'cmplw': 'cmpw', 'cmplwi': 'cmpwi'}
WIDTH = {'lwz': 4, 'lhz': 2, 'lha': 2, 'lbz': 1, 'stw': 4, 'sth': 2, 'stb': 1}


def hints(s: Score):
    H = []
    o_mn = [mnemonic(w)[0] for w in s.ours]; t_mn = [mnemonic(w)[0] for w in s.target]
    pairs = []   # aligned (i, j) with differences
    extra = Counter(); missing = Counter(); extra_at = {}; missing_at = {}
    for tag, i1, i2, j1, j2 in s.ops:
        if tag == 'equal':
            pairs += [(i1 + k, j1 + k) for k in range(i2 - i1) if norm(s.ours[i1 + k]) != norm(s.target[j1 + k])]
        elif tag == 'replace':
            n = min(i2 - i1, j2 - j1)
            pairs += [(i1 + k, j1 + k) for k in range(n)]
            for k in range(i1 + n, i2): extra[o_mn[k]] += 1; extra_at.setdefault(o_mn[k], k)
            for k in range(j1 + n, j2): missing[t_mn[k]] += 1; missing_at.setdefault(t_mn[k], k)
        elif tag == 'delete':
            for k in range(i1, i2): extra[o_mn[k]] += 1; extra_at.setdefault(o_mn[k], k)
        else:
            for k in range(j1, j2): missing[t_mn[k]] += 1; missing_at.setdefault(t_mn[k], k)
    # 1. prologue / frame
    def first(mn, lst):
        for k, m in enumerate(lst[:10]):
            if m == mn: return k
        return None
    oo = first('stwu', o_mn); tt = first('stwu', t_mn)
    if (oo is None) != (tt is None):
        H.append('frame: target %s a stack frame; ours %s (check calls / locals whose address is taken / arrays)'
                 % ('has' if tt is not None else 'has no', 'does not' if tt is not None else 'does'))
    elif oo is not None and norm(s.ours[oo]) != norm(s.target[tt]):
        H.append(f'frame size: ours {mnemonic(s.ours[oo])[1]} vs target {mnemonic(s.target[tt])[1]} (spilled temps / local arrays / float->double temps)')
    if ('mflr' in t_mn[:4]) != ('mflr' in o_mn[:4]):
        H.append('link register: target %s; ours %s' % ('calls something' if 'mflr' in t_mn[:4] else 'is a leaf', 'is a leaf' if 'mflr' in t_mn[:4] else 'calls'))
    osv = [m for m in o_mn[:8] if m in ('stmw', 'stw')]; tsv = [m for m in t_mn[:8] if m in ('stmw', 'stw')]
    o_st = [mnemonic(w)[1] for w in s.ours[:8] if mnemonic(w)[0] in ('stmw',)]; t_st = [mnemonic(w)[1] for w in s.target[:8] if mnemonic(w)[0] in ('stmw',)]
    if o_st != t_st:
        H.append(f'callee-saved regs: ours {o_st or "none"} vs target {t_st or "none"}: change how many values live across calls (fewer/more temps, recompute vs keep)')
    # 2. aligned operand differences
    cats = Counter(); where = {}
    for i, j in pairs:
        a, b = o_mn[i], t_mn[j]; wa, wb = s.ours[i], s.target[j]
        key = None
        if a == b:
            if shape(wa) == shape(wb): key = 'regalloc'
            elif a in ('stw', 'lwz', 'stfs', 'lfs', 'stfd', 'lfd', 'stmw', 'lmw', 'addi', 'stwu') and ((wa >> 16) & 31) == 1:
                key = 'stack-slot'
            elif a in WIDTH or a.startswith(('lf', 'stf')): key = 'field-offset'
            elif a in ('rlwinm', 'rlwimi'): key = 'mask/shift'
            elif a in ('cmpwi', 'cmplwi', 'li', 'addi', 'ori', 'andi.', 'subfic', 'mulli'): key = 'immediate'
            elif a.startswith('b'): key = 'branch-target'
            else: key = 'operand'
        elif SIGNED_CMP.get(a) == b: key = 'compare-signedness'
        elif {a, b} <= {'lha', 'lhz'} or {a, b} <= {'extsh', 'clrlwi', 'rlwinm'} or {a, b} <= {'extsb', 'clrlwi', 'rlwinm'}: key = 'int-signedness'
        elif a in WIDTH and b in WIDTH and WIDTH[a] != WIDTH[b]: key = 'field-width'
        elif {a, b} <= {'lfs', 'lfd'} or {a, b} <= {'stfs', 'stfd'} or (a.startswith('f') and b.startswith('f') and (a.endswith('s')) != (b.endswith('s'))): key = 'float-vs-double'
        elif {a, b} <= {'mulli', 'slwi', 'rlwinm', 'add', 'mullw'}: key = 'mul-vs-shift'
        elif {a, b} <= {'divw', 'divwu', 'srawi', 'srwi', 'addze'}: key = 'div-signedness'
        elif a.startswith('b') and b.startswith('b'): key = 'branch-polarity'
        elif {a, b} <= {'lwz', 'lis', 'addi', 'lhz', 'lbz', 'lfs'} and (((wa >> 16) & 31) in (13, 2) or ((wb >> 16) & 31) in (13, 2)): key = 'sda-vs-absolute'
        elif {a, b} <= {'cmpw', 'cmpwi', 'cmplw', 'cmplwi'}: key = 'compare-form'
        else: key = f'{a}->{b}'
        cats[key] += 1; where.setdefault(key, (i, j))
    ADVICE = {
        'regalloc': 'register allocation: reorder local declarations/temps, merge or split temporaries, move a load next to its use, try `register`',
        'stack-slot': 'stack layout: order/number of locals that live in memory (arrays, address-taken vars, spills)',
        'field-offset': 'field offset: wrong struct offset or base pointer (check +0x.. values)',
        'immediate': 'immediate differs: constant value, loop bound, or field offset',
        'compare-signedness': 'compare signedness: make both operands signed (s32) or unsigned (u32) to flip cmpw<->cmplw',
        'int-signedness': 'char/short signedness: s16<->u16 or s8<->u8 on the field/local (extsh vs clrlwi)',
        'field-width': 'field width: wrong access size (u8/u16/u32) at that offset',
        'float-vs-double': 'float vs double: literal 1.0 vs 1.0f, f32 vs f64 temp, or a double-returning callee',
        'mul-vs-shift': 'multiply vs shift: x*4 vs x<<2 or signed vs unsigned multiply',
        'div-signedness': 'division signedness: s32 vs u32 operand of / or %',
        'branch-polarity': 'branch polarity: swap if/else bodies or negate the condition (also early-return vs nested if)',
        'sda-vs-absolute': 'global addressing: r13 (SDA) needs an extern of 8 bytes or less (`extern s32 lbl;`, other fields via (char *)&lbl + off, &lbl stays SDA too); lis/addi needs an array/struct > 8 bytes or __attribute__((section(".data")))',
        'compare-form': 'compare form: constant vs register operand (fold a temp into the compare or hoist it)',
        'mask/shift': 'bit mask or shift amount differs: cast width (u8/u16) or shift constant',
        'branch-target': 'branch distance: block order or size differs (likely a consequence of other diffs)',
    }
    for key, n in cats.most_common():
        i, j = where[key]
        adv = ADVICE.get(key, f'{key} at the same position')
        H.append(f'{n}x {adv} [first @+{j*4:#x} target `{" ".join(mnemonic(s.target[j]))}` vs ours `{" ".join(mnemonic(s.ours[i]))}`]')
    # 3. extra/missing instructions
    def fmt(c, at):
        return ', '.join(f'{v}x {k}(@+{at[k]*4:#x})' for k, v in c.most_common(6))
    if missing: H.append(f'missing in ours: {fmt(missing, missing_at)}')
    if extra: H.append(f'extra in ours: {fmt(extra, extra_at)}')
    both = set(missing) & set(extra)
    if both:
        H.append('same opcodes both missing and extra (%s): statement/evaluation order, or a temp that should (not) be reloaded' % ', '.join(sorted(both)))
    if ('extsh' in missing or 'extsb' in missing) and not ('extsh' in extra or 'extsb' in extra): H.append('target sign-extends a short/char: use s16/s8 for that field or local')
    if ('clrlwi' in missing or 'rlwinm' in missing) and 'extsh' in extra: H.append('target zero-extends: use u16/u8')
    if 'frsp' in missing: H.append('target rounds to single: an expression is computed in double (literal without f suffix, or f64 temp)')
    if 'frsp' in extra: H.append('ours rounds to single: use f32 literals (1.0f) / avoid double promotion')
    if 'mr' in extra and 'mr' not in missing: H.append('extra mr: a value is copied; let the callee arg be used directly or avoid a temp')
    if 'fmr' in extra: H.append('extra fmr: avoid copying a float into a second temp')
    if ('cror' in missing) or ('cror' in extra): H.append('float compare form: ProDG emits cror for <=/>= (vs < / >): flip the operator and swap operands')
    if 'mfcr' in t_mn[:6] and 'mfcr' not in o_mn[:6]:
        H.append('target saves CR in the prologue (mfcr r12): a flag lives in a condition register across the loop; write it as an int local set from one compare before the loop (e.g. neg = (c == 0x2D)) and tested after')
    if 'nop' in missing: H.append('target has nop padding (alignment) - usually ignorable')
    return H[:12]


def words_be(data: bytes) -> list[int]:
    """Unpack big-endian 32-bit instruction words."""
    return [int.from_bytes(data[i:i + 4], 'big') for i in range(0, len(data) - (len(data) % 4), 4)]

