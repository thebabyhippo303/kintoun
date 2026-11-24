"""Statement dependency helpers plus init, load/store target-order, register-copy, call-arg hoist, and spill-schedule mutations."""
import re
from kintoun.search.mutations_float import _FLOAT_SCENT, _FNEG_TYPEWORDS

_INIT_SIMPLE = re.compile(r'^( +)([^ ].*);$')

_INIT_CTRL = re.compile(r'^\s*(if|else|while|do|for|switch|case|default|return|goto|break|continue|\}|block_|[A-Za-z_]\w*:)')

_INIT_DECL = re.compile(r'^(    )(register )?((?:const )?(?:unsigned |signed )?(?:void|char|short|int|long|float|double|[us](?:8|16|32)|f(?:32|64)|M2C_UNK)\s*\**)\s*(\s*\w+)(\[\d+\])?;$')

_INIT_AGGDECL = re.compile(r'^(    )(?:union|struct|enum)\s*\{[^}\n]*\}\s*\w+\s*(?:\[\d+\])?;$')

_INIT_CALL = re.compile(r'\b(?!(?:if|for|while|switch|return|sizeof|typeof|M2C_FIELD)\b)\w+\s*\(')

_INIT_CONST = re.compile(r'-?(?:0x[0-9a-fA-F]+|\d+)[uUlL]*$')

_INIT_WRITE = re.compile(r'^ +(\w+) (?:[-+*/|&^]|<<|>>)?= ')

_INIT_IDENT = re.compile(r'[A-Za-z_]\w*')

_INIT_KW = frozenset(('if else for while do switch case default break continue return goto sizeof volatile '
                      'const static extern register auto typedef struct union enum').split())

_INIT_HEAD = re.compile(r'^(\s*)(for|while)\s*\(.*\)\s*\{\s*$')

_INIT_DO = re.compile(r'^\s*do\s*\{\s*$')

INIT_GATE_FRAC = 0.12

INIT_MIN_TARGET = 8

INIT_CAP = 4


def _init_idents(line):
    return {w for w in _INIT_IDENT.findall(line) if w not in _INIT_KW} - {'M2C_FIELD'}


def _init_assign(line):
    """Qualifying init assignment, or None (decls, control, calls stay fixed).

    The '=' requirement is load-bearing: without it '='-less lines (`i++;`,
    single-line `union {...} sp8;` decls) qualify as "assignments" and crash
    consumers (`_init_const` indexes split('=')[1]) or get permuted across
    real inits. Bare comparisons (`a == b;`, whose rhs starts with a second
    '=') are likewise not assignments and stay out. Aggregate one-liner
    decls are recognized explicitly so they join runs as fillers like other
    decls.
    """
    if not (_INIT_SIMPLE.match(line) and not _INIT_CTRL.match(line)
            and not _INIT_DECL.match(line) and not _INIT_AGGDECL.match(line)
            and not line.rstrip().endswith('{')
            and 'volatile' not in line and not _INIT_CALL.search(line)):
        return None
    parts = line.split('=', 1)
    if len(parts) < 2 or parts[1].lstrip().startswith('='):
        return None
    return line


def _init_const(line):
    # Same guard class as _lil_kind: run lines include `i++;` with no '='
    # (m_init_order IndexError fuzz-found on 11 bench rows' seeds).
    if '=' not in line:
        return False
    rhs = line.split('=', 1)[1].rsplit(';', 1)[0].strip()
    return bool(_INIT_CONST.fullmatch(rhs))


def _init_writes(line):
    m = _INIT_WRITE.match(line)
    if m:
        return {m[1]}
    lhs = line.split('=', 1)[0]
    return _init_idents(lhs)


def _init_independent(a, b):
    return not (_init_writes(a) & _init_idents(b)) and not (_init_writes(b) & _init_idents(a))


def _init_runs(lines, start, end):
    """Maximal decl/assignment runs in the head zone or right before a loop."""
    runs, cur = [], []
    def flush(end_idx):
        if sum(1 for _, q in cur if q) >= 2:
            runs.append((list(cur), end_idx))
        cur.clear()
    for i in range(start, end):
        line = lines[i]
        if _init_assign(line):
            cur.append((i, True))
        elif _INIT_DECL.match(line) or _INIT_AGGDECL.match(line) or not line.strip():
            cur.append((i, False))
        else:
            flush(i)
            # loop-preheader run ends at a loop header; other code breaks runs
            continue
    flush(end)
    out = []
    for run, after in runs:
        qual = [i for i, q in run if q]
        if len(qual) < 2:
            continue
        head_zone = run[0][0] - start <= 6
        pre_loop = after < len(lines) and (_INIT_HEAD.match(lines[after])
                                           or _INIT_DO.match(lines[after]))
        if head_zone or pre_loop:
            out.append(qual)
    return out


def m_init_order(text, cap=INIT_CAP):
    """Permute register/address init order: consts-first vs addresses-first.

    Closes the 98%+ reg-alloc/scheduling class (LevelAlo__DeleteObject 98.7%,
    Minimap__Destroy 98.4% li-vs-lis order at loop head, Device__Update 97.3%
    SDA addi): the compiler's choice of which value is materialized first
    follows C init order, but m_decl_order owns decl-decl swaps and
    m_swap_stmts owns adjacent assign-assign swaps only. This crosses the
    decl/assignment boundary by class (literal hoist vs const-first) in head
    and loop-preheader runs, keeping declarations fixed and respecting
    write/read edges across every reordered pair.
    """
    lines = text.split('\n')
    try:
        start = next(i for i, l in enumerate(lines)
                     if l.rstrip().endswith('{') and '(' in l and not l.startswith((' ', '\t')))
        end = max(i for i, l in enumerate(lines) if l == '}')
    except (StopIteration, ValueError):
        return
    seen = {text}
    made = 0
    vol = _mxo_volatiles(text)
    for qual in _init_runs(lines, start + 1, end):
        if made >= cap:
            return
        const = [i for i in qual if _init_const(lines[i])]
        other = [i for i in qual if not _init_const(lines[i])]
        if not const or not other:
            continue
        if vol and any(_init_idents(lines[i]) & vol for i in qual):
            continue
        for order in (const + other, other + const):
            if made >= cap:
                return
            if order == qual:
                continue
            ok = True
            pos = {idx: k for k, idx in enumerate(order)}
            for x in range(len(qual)):
                for y in range(x + 1, len(qual)):
                    a, b = qual[x], qual[y]
                    if pos[a] > pos[b] and not _init_independent(lines[a], lines[b]):
                        ok = False
                        break
                if not ok:
                    break
            if not ok:
                continue
            out = lines[:]
            stmts = [lines[i] for i in order]
            for idx, stmt in zip(qual, stmts):
                out[idx] = stmt
            cand = '\n'.join(out)
            if cand in seen:
                continue
            seen.add(cand)
            made += 1
            yield 'init_order', cand


def _init_shaped(score, ours_len, target_len):
    if target_len < INIT_MIN_TARGET:
        return False
    mism = getattr(score, 'mism', None)
    if not isinstance(mism, int):
        mism = 0
        for tag, i1, i2, j1, j2 in (score.ops or []):
            if tag != 'equal':
                mism += max(i2 - i1, j2 - j1)
    return mism / max(ours_len, target_len, 1) <= INIT_GATE_FRAC

_STO_STORE_OPS = (36, 38, 44, 52)

_STO_FIELD = re.compile(r'^(\s*)M2C_FIELD\((\w+),\s*([^,()]+?)\s*,\s*(-?(?:0x[0-9a-fA-F]+|\d+))\)\s*=\s*(.+);$')

_STO_CHAIN = re.compile(r'=\s*(\w+)\s*=(?!=)')

_STO_CALL = re.compile(r'\b(?!(?:if|for|while|switch|return|sizeof|typeof|M2C_FIELD)\b)\w+\s*\(')

_STO_IDENT = re.compile(r'[A-Za-z_]\w*')

_STO_KW = frozenset(('if else for while do switch case default break continue return goto sizeof volatile '
                      'const static extern register auto typedef struct union enum').split())

STO_CAP = 2


def _sto_target_order(target):
    """Observed store-offset sequence per base register in the target words."""
    seq = {}
    for w in target or []:
        if (w >> 26) not in _STO_STORE_OPS:
            continue
        base = (w >> 16) & 31
        off = w & 0xffff
        if off & 0x8000:
            off -= 0x10000
        seq.setdefault(base, []).append(off)
    return seq


def _sto_idents(line):
    return {w for w in _STO_IDENT.findall(line) if w not in _STO_KW} - {'M2C_FIELD'}


def m_store_tgtorder(text, target, cap=STO_CAP):
    """Swap adjacent same-struct stores when the target shows the opposite offset order.

    Closes store/load-order near-misses (AvatarMovement__ResetState stw order,
    Voice3D x,z,y, DVD lfs/f-order, HUD lis order) that ascending-only sort
    families cannot reach: real compilers emit declaration, use, and
    scheduling orders. Unlike fraction-gated families, each variant is backed
    by an observed target pair matched on offset VALUES (same struct layout),
    so it fires on mid-range functions too. Declarations are untouched;
    volatile, calls, cross-struct, field-cell reads, and chained-temp
    dependent pairs are skipped.
    """
    seq = _sto_target_order(target)
    if not seq:
        return
    inv = set()
    for offs in seq.values():
        for x in range(len(offs)):
            for y in range(x + 1, len(offs)):
                if offs[x] != offs[y]:
                    inv.add((offs[y], offs[x]))
    if not inv:
        return
    lines = text.split('\n')
    seen = {text}
    made = 0
    for i in range(len(lines) - 1):
        if made >= cap:
            return
        m1 = _STO_FIELD.match(lines[i])
        m2 = _STO_FIELD.match(lines[i + 1])
        if not (m1 and m2):
            continue
        if 'volatile' in lines[i] or 'volatile' in lines[i + 1]:
            continue
        if _STO_CALL.search(lines[i]) or _STO_CALL.search(lines[i + 1]):
            continue
        if m1[2] != m2[2]:
            continue
        a = int(m1[4], 16 if m1[4].lstrip('-').startswith(('0x', '0X')) else 10)
        b = int(m2[4], 16 if m2[4].lstrip('-').startswith(('0x', '0X')) else 10)
        if a == b or (a, b) not in inv:
            continue
        # Each line writes its (struct, field) cell, and possibly a chained
        # temp (`= t = ...`). Skip the swap when the other line's RHS reads
        # anything this line writes: the written field cell (struct+field
        # names both present on the RHS) or a chained temp.
        r1, r2 = lines[i].split('=', 1)[1], lines[i + 1].split('=', 1)[1]
        i1, i2 = _sto_idents(r1), _sto_idents(r2)
        c1 = _STO_CHAIN.search(lines[i])
        c2 = _STO_CHAIN.search(lines[i + 1])
        wr1 = {c1[1]} if c1 else set()
        wr2 = {c2[1]} if c2 else set()
        if m1[2] in i2 and m1[3] in i2:
            continue
        if m2[2] in i1 and m2[3] in i1:
            continue
        if i2 & wr1:
            continue
        if i1 & wr2:
            continue
        out = lines[:]
        out[i], out[i + 1] = out[i + 1], out[i]
        cand = '\n'.join(out)
        if cand in seen:
            continue
        seen.add(cand)
        made += 1
        yield 'store_tgtorder', cand

_LDO_LOAD_OPS = (32, 34, 40, 42, 48, 50)

_LDO_LOAD = re.compile(r'^(\s*)([\w\]]+?)\s*=\s*(.+);\s*$')

_LDO_FLD = re.compile(r'M2C_FIELD\((\w+),\s*([^,()]+?)\s*,\s*(-?(?:0x[0-9a-fA-F]+|\d+))\)')

_LDO_DECLKW = frozenset(('int long short char float double void unsigned signed '
                          'const static extern register volatile struct union enum').split())

LDO_CAP = 2


def _ldo_target_order(target):
    """Observed load-offset sequence per base register in the target words."""
    seq = {}
    for w in target or []:
        if (w >> 26) not in _LDO_LOAD_OPS:
            continue
        base = (w >> 16) & 31
        off = w & 0xffff
        if off & 0x8000:
            off -= 0x10000
        seq.setdefault(base, []).append(off)
    return seq


def m_load_tgtorder(text, target, cap=LDO_CAP):
    """Swap adjacent load statements when the target shows the opposite load-offset order.

    Mirror of m_store_tgtorder for the read side (Voice3D__Construct 96.7%
    lfs placed one stfs early, Exploder__ShrinkOrMarkForDeath 95.7% mr-vs-lfs
    swap, TerrainQuadtree__Load 95.2% addi order, Table__OpenDatabaseFile
    97.8% lwz displacement): each variant is backed by an observed target
    load pair matched on offset VALUES, so no fraction gate. Only plain-temp
    loads of the form `t = ...M2C_FIELD(s, ty, off)...;` with a single field
    read; declarations, volatile, calls, and read-after-write pairs skipped.
    """
    seq = _ldo_target_order(target)
    if not seq:
        return
    inv = set()
    for offs in seq.values():
        for x in range(len(offs)):
            for y in range(x + 1, len(offs)):
                if offs[x] != offs[y]:
                    inv.add((offs[y], offs[x]))
    if not inv:
        return
    lines = text.split('\n')
    seen = {text}
    made = 0
    for i in range(len(lines) - 1):
        if made >= cap:
            return
        m1 = _LDO_LOAD.match(lines[i])
        m2 = _LDO_LOAD.match(lines[i + 1])
        if not (m1 and m2):
            continue
        if 'volatile' in lines[i] or 'volatile' in lines[i + 1]:
            continue
        if _STO_CALL.search(lines[i]) or _STO_CALL.search(lines[i + 1]):
            continue
        lhs1, rhs1 = m1[2], m1[3]
        lhs2, rhs2 = m2[2], m2[3]
        if _LDO_DECLKW & (_sto_idents(lhs1) | _sto_idents(lhs2)):
            continue
        f1 = _LDO_FLD.findall(rhs1)
        f2 = _LDO_FLD.findall(rhs2)
        if len(f1) != 1 or len(f2) != 1:
            continue
        (s1, _, o1), (s2, _, o2) = f1[0], f2[0]
        if s1 != s2:
            continue
        a = int(o1, 16 if o1.lstrip('-').startswith(('0x', '0X')) else 10)
        b = int(o2, 16 if o2.lstrip('-').startswith(('0x', '0X')) else 10)
        if a == b or (a, b) not in inv:
            continue
        # Read-after-write either direction blocks the swap; each line writes
        # only its plain-temp LHS (stores cannot match _LDO_LOAD).
        w1 = lhs1.split('[')[0].strip()
        w2 = lhs2.split('[')[0].strip()
        if not w1.isidentifier() or not w2.isidentifier():
            continue
        if w1 in _sto_idents(rhs2):
            continue
        if w2 in _sto_idents(rhs1):
            continue
        out = lines[:]
        out[i], out[i + 1] = out[i + 1], out[i]
        cand = '\n'.join(out)
        if cand in seen:
            continue
        seen.add(cand)
        made += 1
        yield 'load_tgtorder', cand

_RCP_MR_XO = 444

_RCP_COPY = re.compile(r'^(\s*)([A-Za-z_]\w*)\s*=\s*([A-Za-z_]\w*)\s*;\s*$')

_RCP_ASSIGN = re.compile(r'^(\s*)([A-Za-z_]\w*(?:\[[^\]\n]*\])?)\s*=\s*(.+);\s*$')

_RCP_WORD = re.compile(r'[A-Za-z_]\w*')

_RCP_KW = frozenset(('if else for while do switch case default break continue return goto sizeof '
                      'const static extern register auto typedef struct union enum').split())

RCP_CAP = 2


def _rcp_mr_count(words):
    """Count `mr` (or RT,RA,RA) instructions in a word stream."""
    n = 0
    for w in words or []:
        if (w >> 26) != 31 or ((w >> 1) & 0x3ff) != _RCP_MR_XO:
            continue
        if ((w >> 16) & 31) == ((w >> 11) & 31):
            n += 1
    return n


def _rcp_idents(line):
    return {w for w in _RCP_WORD.findall(line) if w not in _RCP_KW} - {'M2C_FIELD'}


def m_regcopy(text, target, ours, cap=RCP_CAP):
    """Introduce or eliminate a temp copy to match the target's `mr` count.

    Register-allocation near-misses (Exploder__ShrinkOrMarkForDeath 95.7%
    mr-vs-lfs, Sound__InitSfx3DAndEnv 96.8% li-vs-mr arg setup,
    LevelAlo__DeleteObject 98.7%) come down to whether a value lives in one
    register or is copied to another: at C level that is the presence or
    absence of `t = u;` temp copies. The direction is read off the target:
    more `mr` there than here introduces `__typeof__(u) t = u;` copies at use
    sites; fewer removes single-definition plain copies. Calls, volatile,
    self-uses, and multiply-assigned temps are skipped.
    """
    want = _rcp_mr_count(target) - _rcp_mr_count(ours)
    if want == 0:
        return
    lines = text.split('\n')
    seen = {text}
    made = 0
    if want > 0:
        for i, line in enumerate(lines):
            if made >= cap:
                return
            if 'volatile' in line or _STO_CALL.search(line):
                continue
            m = _RCP_ASSIGN.match(line)
            if not m:
                continue
            lhs, rhs = m[2], m[3]
            if 'M2C_FIELD' in rhs:
                continue
            w = lhs.split('[')[0].strip()
            if not w.isidentifier():
                continue
            for u in sorted(_rcp_idents(rhs) - {w}):
                if made >= cap:
                    return
                decl = f'{m[1]}__typeof__({u}) t_b3rc{made} = {u};'
                new_rhs = re.sub(r'\b' + re.escape(u) + r'\b', f't_b3rc{made}', rhs, count=1)
                out = lines[:]
                out[i] = f'{m[1]}{lhs} = {new_rhs};'
                out.insert(i, decl)
                cand = '\n'.join(out)
                if cand in seen:
                    continue
                seen.add(cand)
                made += 1
                yield 'regcopy', cand
                break
    else:
        for i, line in enumerate(lines):
            if made >= cap:
                return
            m = _RCP_COPY.match(line)
            if not m:
                continue
            t, u = m[2], m[3]
            if t == u:
                continue
            if sum(1 for ln in lines if re.search(r'\b' + re.escape(t) + r'\s*=(?!=)', ln)) != 1:
                continue
            out = lines[:i] + lines[i + 1:]
            for j in range(i, len(out)):
                if re.search(r'\b' + re.escape(t) + r'\b', out[j]):
                    out[j] = re.sub(r'\b' + re.escape(t) + r'\b', u, out[j])
            cand = '\n'.join(out)
            if cand in seen:
                continue
            seen.add(cand)
            made += 1
            yield 'regcopy', cand

FCC_CAP = 2

_FCC_FMR_XO = 72  # fmr is primary 63, not primary-31 or-XO 444, so _rcp_mr_count never sees it


def _fcc_fmr_count(words):
    """Count `fmr` instructions in a word stream."""
    n = 0
    for w in words or []:
        if (w >> 26) != 63 or ((w >> 1) & 0x3ff) != _FCC_FMR_XO:
            continue
        n += 1
    return n


def m_fregcopy(text, target, ours, cap=FCC_CAP):
    """Introduce or eliminate a float temp copy to match the target's `fmr` count.

    Float twin of m_regcopy, which only counts integer `mr`: the float
    branch/copy residuals (FuzzyRange__Evaluate keeps 4 fmr f10/f12/f13
    copies, Voice__ApplyEffectSend 3 fmr f1/f2 copies, Simple rotors fmr
    pi/lim copies) sit on seeds with no copy temps at all, so the int
    twin never fires there. The direction is read off the target: more
    `fmr` there than here introduces `__typeof__(u) t = u;` copies at
    float use sites; fewer removes single-definition plain float copies.
    Only float-scented lines fire (the int side stays b3's). Calls,
    volatile, field-load right-hand sides, self-uses, and
    multiply-assigned temps are skipped, mirroring the twin.
    """
    want = _fcc_fmr_count(target) - _fcc_fmr_count(ours)
    if want == 0:
        return
    lines = text.split('\n')
    seen = {text}
    made = 0
    if want > 0:
        for i, line in enumerate(lines):
            if made >= cap:
                return
            if not _FLOAT_SCENT.search(line):
                continue
            if 'volatile' in line or _STO_CALL.search(line):
                continue
            m = _RCP_ASSIGN.match(line)
            if not m:
                continue
            lhs, rhs = m[2], m[3]
            if 'M2C_FIELD' in rhs:
                continue
            w = lhs.split('[')[0].strip()
            if not w.isidentifier():
                continue
            for u in sorted(_rcp_idents(rhs) - {w}):
                if made >= cap:
                    return
                # Member-adjacent idents are not copyable values: `bytes`
                # in `sp90.bytes` would rebind onto the scalar copy
                # (sp90.t_b2fc), and rebinding a member base loses its
                # member the same way. Type keywords (M2C_UNK especially)
                # are not values either. Both emit text that cannot
                # compile, so they stay put (int twin untouched).
                if u in _FNEG_TYPEWORDS:
                    continue
                if re.search(r'(?:\.|->)\s*' + re.escape(u) + r'\b|\b' + re.escape(u) + r'\s*(?:\.|->)', rhs):
                    continue
                # Fragments of numeric literals (`xFFFF` in `0xFFFF`,
                # `e5` in `1e5`) are not values either.
                if re.search(r'[0-9.]' + re.escape(u) + r'\b', rhs):
                    continue
                decl = f'{m[1]}__typeof__({u}) t_b2fc{made} = {u};'
                new_rhs = re.sub(r'\b' + re.escape(u) + r'\b', f't_b2fc{made}', rhs, count=1)
                out = lines[:]
                out[i] = f'{m[1]}{lhs} = {new_rhs};'
                out.insert(i, decl)
                cand = '\n'.join(out)
                if cand in seen:
                    continue
                seen.add(cand)
                made += 1
                yield 'fregcopy', cand
                break
    else:
        for i, line in enumerate(lines):
            if made >= cap:
                return
            if not _FLOAT_SCENT.search(line):
                continue
            m = _RCP_COPY.match(line)
            if not m:
                continue
            t, u = m[2], m[3]
            if t == u:
                continue
            if sum(1 for ln in lines if re.search(r'\b' + re.escape(t) + r'\s*=(?!=)', ln)) != 1:
                continue
            out = lines[:i] + lines[i + 1:]
            # Only genuine uses inline: a `t` that is a member part
            # (`x.t`, `p->t`) names a struct field, not the eliminated
            # copy, and rewriting it manufactures members. Member bases
            # (`t.x`) still inline like any other use; a bare `>`
            # (comparison) keeps matching too.
            bare = re.compile(r'(?<![\w.])(?<!->)' + re.escape(t) + r'\b')
            for j in range(i, len(out)):
                if bare.search(out[j]):
                    out[j] = bare.sub(u, out[j])
            cand = '\n'.join(out)
            if cand in seen:
                continue
            seen.add(cand)
            made += 1
            yield 'fregcopy', cand

CHO_CAP = 4

_CHO_PLAIN = re.compile(r'^( +)([^ ].*);$')

_CHO_CTRL = re.compile(r'^\s*(if|else|while|do|for|switch|case|default|return|goto|break|continue|\}|block_|[A-Za-z_]\w*:)')

_CHO_MACRO = re.compile(r'^[A-Z_][A-Z0-9_]*$')

_CHO_KW = frozenset(('sizeof', 'typeof', '__typeof__', 'return', 'if', 'while', 'for', 'switch'))

_CHO_SAFE_ARG = re.compile(r'^(-?(?:0x[0-9a-fA-F]+|\d+)(?:\.\d+)?f?|[A-Za-z_]\w*)$')

_CHO_CALLISH = re.compile(r'\b(?!M2C_FIELD\b)[A-Za-z_]\w*\s*\(')

_CHO_ASSIGN = re.compile(r'(?<![=!<>])=(?!=)')


def _cho_pure_arg(arg):
    """True for a complex arg safe to hoist into a __typeof__ temp.

    Each exclusion maps to a real failure mode: calls reorder side
    effects (and broke the pre-revival version), string literals do not
    assign (`t = "lit"` never compiles), bare `=` mutates, volatile
    reads are observable, ++/-- and M2C_BITWISE/M2C_ERROR are exotic or
    impure, braces/typeof/sizeof have no proven form. What remains
    (arithmetic, comparisons, casts, ternaries, member/array/deref reads
    through M2C_FIELD, address-of) hoists as one single evaluation exactly
    as the unsequenced call would, so any setup order is sound.
    """
    a = arg.strip()
    if len(a) < 2 or a[0] == '"' or '{' in a or '}' in a or ';' in a:
        return False
    if _CHO_ASSIGN.search(a):
        return False
    if 'volatile' in a or '++' in a or '--' in a:
        return False
    if 'M2C_BITWISE' in a or 'M2C_ERROR' in a:
        return False
    if 'sizeof' in a or 'typeof' in a:
        return False
    if _CHO_CALLISH.search(a):
        return False
    if a.count('(') != a.count(')'):
        return False
    return True


def _cho_split_args(args):
    out, depth, cur = [], 0, ''
    for ch in args:
        if ch in '([{':
            depth += 1
        elif ch in ')]}':
            depth -= 1
        if ch == ',' and depth == 0:
            out.append(cur.strip())
            cur = ''
        else:
            cur += ch
    if cur.strip():
        out.append(cur.strip())
    return out


def _cho_call_at(line):
    if not line.rstrip().endswith(';'):
        return None
    stack = []
    for pos, ch in enumerate(line):
        if ch == '(':
            stack.append(pos)
        elif ch == ')':
            if not stack:
                return None
            opener = stack.pop()
            if not stack and line[pos + 1:].strip() == ';':
                return opener, line[opener + 1:pos]
    return None


def _cho_is_call(line, open_pos):
    pre = line[:open_pos].rstrip()
    if pre.endswith(')'):
        return True
    m = re.search(r'([A-Za-z_]\w*)\s*$', pre)
    return bool(m) and not _CHO_MACRO.match(m[1]) and m[1] not in _CHO_KW


def _cho_orders(n):
    """Setup orders for hoisted call args: source, reversed, then each
    adjacent transposition of the source order.

    Source+reverse cannot express pairwise arg-setup permutations on 3+
    args (InitHeaps/Sound order pile needs e.g. middle-element moves).
    The caller yields source/reverse in phase 0 and transpositions in
    phase 1 on leftover cap, so existing variants are never displaced.
    """
    base = tuple(range(n))
    yield base
    yield tuple(reversed(range(n)))
    for p in range(n - 1):
        lst = list(base)
        lst[p], lst[p + 1] = lst[p + 1], lst[p]
        yield tuple(lst)


def m_constarg_hoist(text, cap=CHO_CAP):
    """Hoist compile-safe call args into temps: source, reverse, and
    pairwise-transposed setup orders.

    Revival of b3-call-argorder with its failure mode removed: the old
    version hoisted arbitrary complex expressions (11/17 variants failed
    to compile) and tied bench-invisible. Pass 1 hoists only literals
    and bare identifiers, so `__typeof__` temps always compile; pass 2
    additionally hoists pure-complex args (_cho_pure_arg: no calls,
    strings, assignments, volatile, macros), which compile by the same
    construction and evaluate exactly once, so any setup ORDER stays
    sound (Sound__InitSfx3DAndEnv 96.8% li-vs-mr arg-setup class).
    Pass 1 yields are identical to before (same sites, same order, same
    names); pass 2 visits only sites the first pass could not use.
    Transpositions yield in a second phase on leftover cap only, so no
    established variant at any site is ever displaced.
    Near-miss-gated at the call site via the shared _init_shaped gate.
    """
    lines = text.split('\n')
    try:
        start = next(i for i, l in enumerate(lines)
                     if l.rstrip().endswith('{') and '(' in l and not l.startswith((' ', '\t')))
        end = max(i for i, l in enumerate(lines) if l == '}')
    except (StopIteration, ValueError):
        return
    seen = {text}
    made = 0
    serial = 0
    vol = _mxo_volatiles(text)
    # Phase 0 yields every established variant (pass 1 then pass 2,
    # source/reverse); phase 1 adds transpositions on leftover cap only,
    # so a transposition at an early site can never crowd out an
    # established variant at a later site under the shared cap. Calls
    # with 5-6 args were excluded entirely (2415 sites corpus-wide carry
    # 2+ safe args); they run in a second sweep after every established
    # site in each phase/pass, so serial temp names for established
    # variants are byte-identical and new yields only fill leftover cap.
    # The wide sweep takes 5-10 args (SetupStage/sprintf/SwooshStreak/
    # ParticleMgr are real 7-10-arg setup orders); wider sites are
    # M2C_ERROR placeholder repetitions, and any site with an M2C_ERROR
    # or M2C_BITWISE arg is a broken seed whose hoists only burn cap.
    for wide in (False, True):
     for phase in (0, 1):
      for use_pure in (False, True):
       for i in range(start + 1, end):
        if made >= cap:
            return
        line = lines[i]
        if 'volatile' in line or not _CHO_PLAIN.match(line) or _CHO_CTRL.match(line):
            continue
        found = _cho_call_at(line)
        if not found:
            continue
        open_pos, args_str = found
        if not _cho_is_call(line, open_pos):
            continue
        args = _cho_split_args(args_str)
        if wide:
            if not 5 <= len(args) <= 10:
                continue
            if any('M2C_ERROR' in a or 'M2C_BITWISE' in a for a in args):
                continue
        elif not 2 <= len(args) <= 4:
            continue
        safe = [bool(_CHO_SAFE_ARG.match(a)) for a in args]
        if use_pure:
            old = list(safe)
            safe = [s or _cho_pure_arg(a) for s, a in zip(safe, args)]
            if safe == old:
                continue
        if vol:
            safe = [s and not (_sto_idents(a) & vol) for s, a in zip(safe, args)]
        if sum(safe) < 2:
            continue
        if phase == 1 and sum(safe) < 3:
            continue
        indent = line[:len(line) - len(line.lstrip())]
        names = []
        for _ in args:
            name = f'cho_t{serial}'
            serial += 1
            while re.search(r'\b' + re.escape(name) + r'\b', text):
                name = f'cho_t{serial}'
                serial += 1
            names.append(name)
        orders = _cho_orders(len(args))
        if phase == 0:
            orders = list(orders)[:2]
        else:
            orders = list(orders)[2:]
        for order in orders:
            if made >= cap:
                return
            decls = [f'    __typeof__({args[k]}) {names[k]};' for k in order if safe[k]]
            assigns = [f'{indent}{names[k]} = {args[k]};' for k in order if safe[k]]
            new_args = [names[k] if safe[k] else args[k] for k in range(len(args))]
            out = lines[:]
            out[i] = line[:open_pos + 1] + ', '.join(new_args) + ');'
            out[i:i] = assigns
            out[start + 1:start + 1] = decls
            candidate = '\n'.join(out)
            if candidate in seen:
                continue
            seen.add(candidate)
            made += 1
            yield 'constarg_hoist', candidate

CHM_CAP = 2

_CHM_LIT = re.compile(r'^-?(?:0x[0-9a-fA-F]+|\d+)(?:\.\d+)?f?$')

_CHM_IDENT = re.compile(r'^[A-Za-z_]\w*$')


def _chm_kind(arg, safe):
    if not safe:
        return None
    a = arg.strip()
    if _CHM_LIT.match(a):
        return 'lit'
    if _CHM_IDENT.match(a):
        return 'ident'
    return None


def m_cho_midfirst(text, cap=CHM_CAP):
    """Lit-first setup orders for symmetric ident-wrapped call sites.

    Census (b3-chomidfirst, 1144 real bench seed texts): 177 texts carry a
    const+ident call site; m_constarg_hoist fires on all 177 but only 155
    get BOTH setup directions. The other 22 are all multi-site texts whose
    lit sits between idents at both ends (`F(t, 3, u)`, the Sound
    96.8% li-vs-mr class): source and reverse both set up an ident first,
    and the transpositions that would set up the const first live in
    phase 1, which never fires once phase 0 fills the shared cap on the
    first two sites. Single-site symmetric texts are already covered by
    phase 1, so this family only adds what is unreachable: adjacent
    transpositions whose first setup is the literal, own cap, own
    `chm_t` temps (never colliding with `cho_t` serials), same
    construction/safety as constarg_hoist pass 1 (idents+literals only,
    same volatile guard). Near-miss-gated at the call site via the shared
    _init_shaped gate; deliberately NOT in m_startperm (its shared cap is
    text-major, so any new starter there would displace later texts'
    starters) and wired last among the order families in directed(), so no
    established yield is ever displaced.
    """
    lines = text.split('\n')
    try:
        start = next(i for i, l in enumerate(lines)
                     if l.rstrip().endswith('{') and '(' in l and not l.startswith((' ', '\t')))
        end = max(i for i, l in enumerate(lines) if l == '}')
    except (StopIteration, ValueError):
        return
    seen = {text}
    made = 0
    serial = 0
    vol = _mxo_volatiles(text)
    for i in range(start + 1, end):
        if made >= cap:
            return
        line = lines[i]
        if 'volatile' in line or not _CHO_PLAIN.match(line) or _CHO_CTRL.match(line):
            continue
        found = _cho_call_at(line)
        if not found:
            continue
        open_pos, args_str = found
        if not _cho_is_call(line, open_pos):
            continue
        args = _cho_split_args(args_str)
        if not 2 <= len(args) <= 4:
            continue
        safe = [bool(_CHO_SAFE_ARG.match(a)) for a in args]
        if vol:
            safe = [s and not (_sto_idents(a) & vol) for s, a in zip(safe, args)]
        if sum(safe) < 2:
            continue
        kinds = [_chm_kind(a, s) for s, a in zip(safe, args)]
        if not (kinds[0] == 'ident' and kinds[-1] == 'ident'):
            continue
        if 'lit' not in kinds[1:-1]:
            continue
        indent = line[:len(line) - len(line.lstrip())]
        names = []
        for _ in args:
            name = f'chm_t{serial}'
            serial += 1
            while re.search(r'\b' + re.escape(name) + r'\b', text):
                name = f'chm_t{serial}'
                serial += 1
            names.append(name)
        for order in list(_cho_orders(len(args)))[2:]:
            if made >= cap:
                return
            if kinds[order[0]] != 'lit':
                continue
            decls = [f'    __typeof__({args[k]}) {names[k]};' for k in order if safe[k]]
            assigns = [f'{indent}{names[k]} = {args[k]};' for k in order if safe[k]]
            new_args = [names[k] if safe[k] else args[k] for k in range(len(args))]
            out = lines[:]
            out[i] = line[:open_pos + 1] + ', '.join(new_args) + ');'
            out[i:i] = assigns
            out[start + 1:start + 1] = decls
            candidate = '\n'.join(out)
            if candidate in seen:
                continue
            seen.add(candidate)
            made += 1
            yield 'cho_midfirst', candidate

DSO_CAP = 2

_DSO_MFLD = re.compile(r'M2C_FIELD\(\s*([^,]+?)\s*,\s*([^,]+?)\s*,\s*(0x[0-9a-fA-F]+|\d+)\s*\)')

_DSO_DOT = re.compile(r'^([A-Za-z_]\w*)\.([A-Za-z_]\w*)\s*$')

_DSO_IDENT = re.compile(r'[A-Za-z_]\w*')

_DSO_DOTREAD = re.compile(r'([A-Za-z_]\w*)\.([A-Za-z_]\w*)')

_DSO_WIDTHS = {'s8': 1, 'u8': 1, 's16': 2, 'u16': 2, 's32': 4, 'u32': 4,
               'f32': 4, 's64': 8, 'u64': 8, 'f64': 8}

_DSO_PURE = frozenset(('copy', 'const', 'addr', 'cond', 'accum'))

_DSO_CALLISH = re.compile(r'\b(?!M2C_FIELD\b)[A-Za-z_]\w*\s*\(')

_DSO_FLOATLIT = re.compile(r'\d+\.\d+f?')


def _dso_root(expr):
    for w in _DSO_IDENT.findall(expr):
        if w not in _MXO_TYPES and w != 'M2C_FIELD':
            return w
    return None

_DSO_CAST = re.compile(r'\([^()]*\*[^()]*\)')

_DSO_IDENTDOTS = re.compile(r'[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*')


def _dso_base_root_off(base):
    """(stack/global root, folded const offset) for an M2C_FIELD base.

    Plain roots (`sp18`, `&sp18`, `((f32 *)sp18.bytes)`) yield offset 0; a
    single `root +/- const` folds the constant in. Anything else (calls,
    variables, derefs, subscripts, nested field reads in the arithmetic)
    yields None: ranges keyed without the base contribution misfire, e.g.
    `M2C_FIELD(sp18 + 4, s32 *, 4)` and `M2C_FIELD(sp18, s32 *, 8)` both
    write sp18+[8,12) but naive keys read [4,8) vs [8,12) as disjoint.
    """
    r = _dso_root(base)
    if r is None or not (r.startswith('sp') or r.startswith('lbl_')):
        return None
    tmp = _DSO_CAST.sub('', base)
    tmp = _DSO_IDENTDOTS.sub('', tmp, count=1)
    tmp = tmp.replace('(', '').replace(')', '').replace('&', '').strip()
    if not tmp:
        return (r, 0)
    m = re.fullmatch(r'\+\s*(0x[0-9a-fA-F]+|\d+)\s*', tmp)
    if m:
        return (r, _dso_off(m.group(1)))
    m = re.fullmatch(r'-\s*(0x[0-9a-fA-F]+|\d+)\s*', tmp)
    if m:
        off = _dso_off(m.group(1))
        return (r, -off) if off is not None else None
    return None


def _dso_width(t):
    """Byte width of an M2C_FIELD access type on PowerPC32.

    Known scalars use the table (so `u8 *` stays a 1-byte access); an
    unknown pointee behind a star (`void **`, `M2C_UNK *`) is still a
    4-byte pointer, which the old lookup returned as None, blinding all
    range-proofed families to void-pointer traffic (both-orders pile
    found by b3-bothorders-census). Unknown non-pointers stay None.
    """
    s = t.strip()
    w = _DSO_WIDTHS.get(s.rstrip('*').strip().split()[-1])
    if w is not None:
        return w
    if s.endswith('*'):
        return 4
    return None


def _dso_off(s):
    s = s.strip()
    try:
        return int(s, 16 if s.lower().startswith('0x') else 10)
    except ValueError:
        return None


def _dso_lhs_key(lhs):
    """('mem', root, lo, hi) for a provable stack/global write, else None.

    Member writes key by BASE with a member tag: same-base members may
    overlap (union risk; a whole-slot member like .value covers every
    numeric offset), so they only ever match a different base. Pointer-
    rooted, arrow, subscript and deref forms never qualify (may alias).
    """
    lhs = lhs.strip()
    m = _DSO_MFLD.fullmatch(lhs)
    if m:
        base, typ, off = m.group(1), m.group(2), m.group(3)
        if re.search(r'->|\[|^\*', base):
            return None
        bro = _dso_base_root_off(base)
        o, w = _dso_off(off), _dso_width(typ)
        if bro is None or o is None or w is None:
            return None
        r, boff = bro
        return ('mem', r, o + boff, o + boff + w)
    m = _DSO_DOT.fullmatch(lhs)
    if m and (m.group(1).startswith('sp') or m.group(1).startswith('lbl_')):
        return ('mem', m.group(1), m.group(2), m.group(2))
    return None


def _dso_mem_addrs(line):
    """Every memory address touched by a classified line, or None when any
    memory form on the line is unprovable (then the swap stays blocked)."""
    m = _MXO_ASSIGN.match(line)
    if not m:
        return []
    lhs, rhs = m.group(2).strip(), m.group(3).strip()
    out = []
    key = _dso_lhs_key(lhs)
    if key is not None:
        out.append(key)
    elif ('M2C_FIELD' in lhs or '->' in lhs or lhs.startswith('*')
          or '[' in lhs or '.' in lhs or lhs.startswith('lbl_')):
        return None
    for mm in _DSO_MFLD.finditer(rhs):
        base, typ, off = mm.group(1), mm.group(2), mm.group(3)
        if re.search(r'->|\[|^\*', base):
            return None
        bro = _dso_base_root_off(base)
        o, w = _dso_off(off), _dso_width(typ)
        if bro is None or o is None or w is None:
            return None
        r, boff = bro
        out.append(('mem', r, o + boff, o + boff + w))
    tmp = _DSO_MFLD.sub('', rhs)
    for dm in _DSO_DOTREAD.finditer(tmp):
        if dm.group(1).startswith('sp') or dm.group(1).startswith('lbl_'):
            out.append(('mem', dm.group(1), dm.group(2), dm.group(2)))
        else:
            return None
    tmp = _DSO_DOTREAD.sub('', tmp)
    if '->' in tmp or re.search(r'\*\s*[A-Za-z_(]', tmp.replace('**', '')) \
            or re.search(r'[A-Za-z_]\w*\s*\[', tmp):
        return None
    return out


def _dso_disjoint(a, b):
    if a[1] != b[1]:
        return True
    if isinstance(a[2], str) or isinstance(b[2], str):
        return False
    return a[3] <= b[2] or b[3] <= a[2]


def _dso_pure_rhs(rhs):
    """True when a rhs reads no memory and calls nothing: no M2C_FIELD,
    calls, member/arrow/deref/subscript reads (float literals stripped so
    `= 3.0f` stays pure). Address-of and pure arithmetic stay allowed."""
    if _DSO_MFLD.search(rhs) or _DSO_CALLISH.search(rhs) or '->' in rhs:
        return False
    tmp = _DSO_DOTREAD.sub('', rhs)
    tmp = _DSO_FLOATLIT.sub('', tmp)
    if '.' in tmp:
        return False
    tmp = tmp.replace('**', '')
    if re.search(r'\*\s*[A-Za-z_(]', tmp) or re.search(r'[A-Za-z_]\w*\s*\[', tmp):
        return False
    return True


def _dso_samebase_ok(a, b):
    """Same M2C_FIELD base, numeric-disjoint ranges, any root, pure rhs.

    Offsets from one base cannot overlap when the byte ranges are disjoint,
    whatever the base points to (stack slot, global, pointer, parameter).
    Pointer-included soundness needs two extra bars beyond the disjoint
    ranges: neither rhs may read memory or call (a `q->f` read could sit
    inside the other's written range when q aliases the base), and neither
    base may hide a call. Same-base members stay out (union risk).
    """
    mas, mbs = [], []
    for ln, bag in ((a, mas), (b, mbs)):
        m = _MXO_ASSIGN.match(ln)
        if not m:
            return False
        lhs, rhs = m.group(2).strip(), m.group(3).strip()
        fm = _DSO_MFLD.fullmatch(lhs)
        if not fm:
            return False
        base, typ, off = fm.group(1), fm.group(2), fm.group(3)
        if re.search(r'->|\[', base) or _DSO_CALLISH.search(base):
            return False
        o, w = _dso_off(off), _dso_width(typ)
        if o is None or w is None:
            return False
        if not _dso_pure_rhs(rhs):
            return False
        bag.append((base.strip(), o, o + w))
    (ba, oa, ca), (bb, ob, cb) = mas[0], mbs[0]
    return ba == bb and (ca <= ob or cb <= oa)


def _dso_pre(a, ka, b, kb):
    """Shared pre-check: rule-2-blocked pile only (store involved, ident
    shared, no temp write-cross)."""
    sa, sb = _mxo_idents(a), _mxo_idents(b)
    la, lb = _mxo_lhs(a), _mxo_lhs(b)
    if (la and la in sb) or (lb and lb in sa):
        return False
    return 'store' in (ka, kb) and bool(sa & sb)


def _dso_old_ok(a, b):
    ma, mb = _dso_mem_addrs(a), _dso_mem_addrs(b)
    return (ma is not None and mb is not None
            and all(_dso_disjoint(x, y) for x in ma for y in mb))


def _dso_guard_ok(a, ka, b, kb):
    """True only for the rule-2-blocked pile: a store is involved, an ident
    is shared (so no landed family takes the pair), rule 1 and the volatile
    rule both pass, and either every touched address parses stack/global and
    is pairwise disjoint, or both lines write numeric-disjoint ranges of one
    shared M2C_FIELD base with pure rhs. Anything unprovable stays blocked."""
    if not _dso_pre(a, ka, b, kb):
        return False
    return _dso_old_ok(a, b) or _dso_samebase_ok(a, b)


def m_disjoint_order(text, cap=DSO_CAP):
    """Swap adjacent store-involved pairs whose addresses are provably disjoint.

    Census (b3-depblock-audit, 1141 real bench seed texts): _mxo_dep rule 2
    (any shared ident with a store involved) blocks 13,489 adjacent pairs
    across 30 rows whose stack/global addresses this guard proves disjoint
    (store/store 12,207: multi-word struct-copy unroll order; load/store
    1,309; copy/store 580). No landed family takes them: same-kind stores
    need shared-base target evidence, mixed needs the dep to pass. This
    family takes exactly that blocked pile (rule-2-would-block required,
    so its yields are disjoint from every landed family's), own cap,
    volatile rule identical to _mxo_dep. Pointer-rooted, arrow, subscript
    and deref forms never qualify; same-base members never qualify (union
    risk); same-base numeric ranges must be disjoint. A second phase adds
    same-M2C_FIELD-base numeric-disjoint writes on any root (pointer and
    parameter bases included: offsets from one base cannot overlap) with
    pure rhs on both sides (no memory reads or calls, no calls in the
    base); it fills only leftover cap, so committed yields stay a strict
    prefix. Near-miss-gated at the call site via the shared _init_shaped
    gate, wired last among the order families in directed(), so no
    established yield is displaced.
    """
    lines = text.split('\n')
    vol = _mxo_volatiles(text)
    # Two phases: established (stack/global) hits first, same-base hits only
    # on leftover cap, so the committed yields are always a strict prefix.
    buckets = ([], [])
    for i in range(len(lines) - 1):
        ka, kb = _mxo_mixkind(lines[i]), _mxo_mixkind(lines[i + 1])
        if not ka or not kb:
            continue
        if 'volatile' in lines[i] or 'volatile' in lines[i + 1]:
            continue
        sa, sb = _mxo_idents(lines[i]), _mxo_idents(lines[i + 1])
        if vol and ((sa | sb) & vol) and not ({ka, kb} <= _DSO_PURE):
            continue
        if not _dso_pre(lines[i], ka, lines[i + 1], kb):
            continue
        if _dso_old_ok(lines[i], lines[i + 1]):
            buckets[0].append(i)
        elif _dso_samebase_ok(lines[i], lines[i + 1]):
            buckets[1].append(i)
    made = 0
    seen = {text}
    for i in buckets[0] + buckets[1]:
        if made >= cap:
            return
        out = lines[:]
        out[i], out[i + 1] = out[i + 1], out[i]
        cand = '\n'.join(out)
        if cand in seen:
            continue
        seen.add(cand)
        made += 1
        yield 'disjoint_order', cand

SPS_CAP = 2


def _sps_slot(lhs):
    """sp root of a stack-slot store lhs (M2C_FIELD or member), else None.

    Pointer/arrow/subscript/deref bases never qualify: only a textually
    confined stack slot lets the call-noninterference proof close.
    """
    lhs = lhs.strip()
    m = _DSO_MFLD.fullmatch(lhs)
    if m:
        base = m.group(1)
        if re.search(r'->|\[', base):
            return None
        idents = [w for w in _DSO_IDENT.findall(base) if w not in _MXO_TYPES
                  and w != 'M2C_FIELD']
        if not idents or not idents[0].startswith('sp'):
            return None
        return idents[0]
    m = _DSO_DOT.fullmatch(lhs)
    if m and m.group(1).startswith('sp'):
        return ('dot', m.group(1))
    return None


def m_spillsched_order(text, cap=SPS_CAP):
    """Sink/hoist a stack-slot store across an adjacent independent call.

    Census (b3-spillsched-census, 1132 real bench seed texts): 423 adjacent
    stack-store/call pairs on 8 rows (top: 224x `sp8.value = 0` next to
    `Timer__GetMilliseconds()`), both directions. No landed family moves
    call lines except callmove, which takes copy/const only, so this pile
    is unreachable: spill scheduling (zeroing/materialization order around
    calls) is invisible to the search. Soundness matches callmove's
    textual-independence proof plus slot confinement: the store writes one
    stack slot with pure rhs, shares no ident with the call, the slot is
    never address-taken outside an M2C_FIELD base (a bare `&spX` escapes;
    the `&spX` inside accesses is the confinement itself) and never named
    by the call, and the store line itself calls nothing (defensive; m2c
    lifts calls out, 0 corpus-wide). Non-stack stores, loads, volatile crossings and
    call-containing store lines stay out. Own cap, near-miss-gated via the
    shared _init_shaped gate, wired last in directed(): yields are
    disjoint from every landed family's by kind (store x call side).
    """
    lines = text.split('\n')
    # An `&spX` inside an M2C_FIELD base is the confined slot access itself,
    # never an escape: strip those spans before collecting taken addresses.
    taken = set(_CMV_TAKEN.findall(_DSO_MFLD.sub('', text)))
    vol = set(_CMV_VOLDECL.findall(text)) | _mxo_volatiles(text)
    made = 0
    seen = {text}
    for i in range(len(lines) - 1):
        if made >= cap:
            return
        a, b = lines[i], lines[i + 1]
        if _cmv_callside(a) and not _cmv_callside(b):
            call, mem = a, b
        elif _cmv_callside(b) and not _cmv_callside(a):
            call, mem = b, a
        else:
            continue
        if _mxo_mixkind(mem) != 'store':
            continue
        if 'volatile' in mem or _DSO_CALLISH.search(mem):
            continue
        m = _MXO_ASSIGN.match(mem)
        if not m:
            continue
        lhs, rhs = m.group(2).strip(), m.group(3).strip()
        slot = _sps_slot(lhs)
        if slot is None:
            continue
        base = slot[1] if isinstance(slot, tuple) else slot
        if _mxo_idents(mem) & _mxo_idents(call):
            continue
        if base in taken:
            continue
        if re.search(r'\b' + re.escape(base) + r'\b', call):
            continue
        if (_mxo_idents(mem) | _mxo_idents(call)) & vol:
            continue
        if not _dso_pure_rhs(rhs):
            continue
        out = lines[:]
        out[i], out[i + 1] = out[i + 1], out[i]
        cand = '\n'.join(out)
        if cand in seen:
            continue
        seen.add(cand)
        made += 1
        yield 'spillsched_order', cand

MXO_CAP = 2

_MXO_ASSIGN = re.compile(r'^(\s*)(.+?)\s*=\s*(.+);\s*$')

_MXO_CMPND = re.compile(r'<<=|>>=|\+=|-=|\*=|/=|%=|&=|\|=|\^=|\+\+|--')

_MXO_MEM = re.compile(r'M2C_FIELD|->|\[')

_MXO_DEREF = re.compile(r'(^|[=(,])\s*\*[A-Za-z_(]')

_MXO_ADDROF = re.compile(r'(^|[=(,])\s*&[A-Za-z_(]')

_MXO_MEMFLD = re.compile(r'[A-Za-z_]\w*\.[A-Za-z_]')

_MXO_COND = re.compile(r'==|!=|<=|>=|!(?!=)|(?<![<>=!])<(?![<=])|(?<![<>=!])>(?![>=])')

_MXO_INCDEC = re.compile(r'^\s*(?:(\+\+|--)\s*)?([A-Za-z_]\w*)\s*(?:(\+\+|--))?\s*;\s*$')

_MXO_COMPOUND = re.compile(r'^\s*([A-Za-z_]\w*)\s*(?:<<=|>>=|\+=|-=|\*=|/=|%=|&=|\|=|\^=)')


def _mxo_accum_temp(line):
    """Written temp of a counter read-write line (`i--`, `t += K`), else None."""
    m = _MXO_INCDEC.match(line)
    if m and bool(m.group(1)) != bool(m.group(3)):
        return m.group(2)
    m = _MXO_COMPOUND.match(line)
    if m:
        return m.group(1)
    return None

_MXO_LBL = re.compile(r'\blbl_\w+')

_MXO_FLOAT = re.compile(r'\bf(?:32|64)\b|\bfloat\b|\bdouble\b')

_MXO_TYPES = frozenset(('int long short char float double void unsigned signed const static '
                        'extern register volatile struct union enum s8 u8 s16 u16 s32 u32 f32 f64 '
                        'M2C_UNK size_t ssize_t').split())


def _mxo_idents(line):
    return {w for w in _STO_IDENT.findall(line) if w not in _MXO_TYPES} - {'M2C_FIELD'}


def _mxo_kind(line):
    """'copy' | 'load' | 'store' | 'const' | 'cond' | 'accum' | None for one
    simple data-movement statement ('cond' = pure comparison assignment,
    'accum' = counter read-write). Address derivations (`t = base +/- K`)
    stay None here so every other family keeps its exact run formation;
    mixed_order admits them through _mxo_mixkind below."""
    if not _init_assign(line):
        # Counter inc/dec carries no '=' but is still a single safe
        # statement; everything else '='-less stays out (crash/permute fix).
        if _INIT_SIMPLE.match(line) and not _INIT_CTRL.match(line):
            at = _mxo_accum_temp(line)
            if at is not None and not (_sto_idents(at) & _LDO_DECLKW):
                return 'accum'
        return None
    at = _mxo_accum_temp(line)
    if at is not None:
        return 'accum' if not (_sto_idents(at) & _LDO_DECLKW) else None
    if _MXO_CMPND.search(line):
        return None
    m = _MXO_ASSIGN.match(line)
    if not m:
        return None
    lhs, rhs = m[2].strip(), m[3].strip()
    if _STO_CHAIN.search(line):
        return None
    if re.search(r'\bM2C_(?!FIELD\b)\w*\s*\(', line):
        return None
    if lhs.startswith('lbl_'):
        return 'store'
    if lhs.startswith('*') or '->' in lhs or lhs.startswith('M2C_FIELD(') or '[' in lhs or '.' in lhs:
        return 'store'
    if not lhs.isidentifier():
        return None
    if _sto_idents(lhs) & _LDO_DECLKW:
        return None
    if _INIT_CONST.fullmatch(rhs):
        return 'const'
    if rhs.isidentifier() and not rhs.startswith('lbl_') and rhs not in _MXO_TYPES:
        return 'copy'
    if _MXO_MEM.search(rhs) or _MXO_DEREF.search(rhs) or _MXO_ADDROF.search(rhs) \
            or _MXO_LBL.search(rhs) or _MXO_MEMFLD.search(rhs):
        return 'load'
    if _MXO_COND.search(rhs):
        return 'cond'
    return None


def _mxo_lhs(line):
    """Plain-ident LHS temp of a qualified line, else None (stores/memory).

    Counter read-writes (`i--`, `t += K`) report their temp so dependency
    checks see the write; anything else unmodeled stays None (strict).
    """
    lhs = line.split('=', 1)[0].strip()
    if lhs.isidentifier():
        return lhs
    return _mxo_accum_temp(line)


def _mxo_volatiles(text):
    """Names declared volatile in this text (observable accesses)."""
    return set(_CMV_VOLDECL.findall(text)) - {'M2C_FIELD'}

_MXO_PURE = frozenset(('copy', 'const', 'addr', 'cond', 'accum'))


def _mxo_dep(a, ka, b, kb, vol=frozenset()):
    """True when swapping a/b is unsafe: a written temp read by the other
    side either direction, or any shared symbol when a store is involved
    (memory overlap is unmodeled, so stores stay strict). Shared pure reads
    (same base/pointer/global read twice) are safe and allowed. A volatile-
    declared access may only move across pure-register lines (copy/const/
    addr); crossing a load/store/call is unmodelable and blocked."""
    sa, sb = _mxo_idents(a), _mxo_idents(b)
    la, lb = _mxo_lhs(a), _mxo_lhs(b)
    if la and la in sb:
        return True
    if lb and lb in sa:
        return True
    if 'store' in (ka, kb) and (sa & sb):
        return True
    if vol and ((sa | sb) & vol) and not ({ka, kb} <= _MXO_PURE):
        return True
    return False


def _mxo_pairs(lines, clf=None):
    """Non-overlapping adjacent pairs from maximal runs of classifiable lines.

    Overlapping windows let cross pairs (the tail of one statement group with
    the head of the next) burn the cap ahead of the aligned pair the
    near-miss actually needs. Step by 2 from each run start, plus the final
    overlapping pair for odd runs so no adjacent pair is unreachable.
    """
    clf = clf or _mxo_kind
    runs, cur = [], []
    for i, line in enumerate(lines):
        if clf(line) and cur and i == cur[-1] + 1:
            cur.append(i)
        else:
            if len(cur) >= 2:
                runs.append(cur)
            cur = [i] if clf(line) else []
    if len(cur) >= 2:
        runs.append(cur)
    out = []
    for run in runs:
        for k in range(0, len(run) - 1, 2):
            out.append((run[k], run[k + 1]))
        if len(run) >= 3 and len(run) % 2 == 1:
            out.append((run[-2], run[-1]))
    return out


def _mxo_mixkind(line):
    """_mxo_kind plus 'addr' for `t = base +/- K` address derivations.

    Mixed-only: every other family uses the default runs, so their pair
    formation is byte-identical to before this change landed.
    """
    return _mxo_kind(line) or ('addr' if _adr_kind(line) else None)


def _mxo_samepure_ok(a, b, kind):
    """True for a same-kind const/accum swap worth generating.

    No family owns `t = 2; u = 3` (SaveGame__RestoreForReset 91.7% is li
    scheduling of two swapped const materializations) or adjacent counter
    updates (`i--; j++;`, mtctr/addi scheduling). Other same-kind pairs
    stay out: copy/load/store have dedicated families, addr-addr belongs
    to addr_order, cond-cond has zero corpus reach. Duplicate statements
    (`t = 2; u = 2;`, `i--; i--;`) can never help and are skipped; the
    whole-line check also keeps '='-less counter lines (`i++;`) away from
    a split('=')[1] crash.
    """
    if kind not in ('const', 'accum'):
        return False
    if a.strip() == b.strip():
        return False
    if '=' in a and '=' in b:
        if a.split('=', 1)[1].strip() == b.split('=', 1)[1].strip():
            return False
    return True

ADR_CAP = 2

_ADR_ARITH = re.compile(r'^(\s*)([A-Za-z_]\w*)\s*=\s*([A-Za-z_]\w*)\s*([+-])\s*'
                        r'(-?(?:0x[0-9a-fA-F]+|\d+)[uUlL]*)\s*;\s*$')


def _adr_kind(line):
    """True for one `t = base +/- const` address derivation (addi class)."""
    if not _init_assign(line):
        return False
    m = _ADR_ARITH.match(line)
    if not m:
        return False
    if _sto_idents(m[2]) & _LDO_DECLKW:
        return False
    if m[3] in _MXO_TYPES:
        return False
    return True

CMV_CAP = 2

_CMV_CALL = re.compile(r'\b(?!(?:if|for|while|switch|return|sizeof|typeof|M2C_FIELD)\b)\w+\s*\(')

_CMV_CTRL = re.compile(r'^\s*(if|else|while|do|for|switch|case|default|return|goto|break|continue|\}|[A-Za-z_]\w*:)')

_CMV_TAKEN = re.compile(r'&([A-Za-z_]\w*)')

_CMV_VOLDECL = re.compile(r'\bvolatile\b[^;\n]*?([A-Za-z_]\w*)\s*(?=[;=\[])')

_CMV_PROTO = re.compile(r'^\s*(?:extern\b|typedef\b|const\b|static\b|register\b|unsigned\b|signed\b'
                        r'|void\b|char\b|short\b|int\b|long\b|float\b|double\b'
                        r'|struct\b|union\b|enum\b)')


def _cmv_callside(line):
    """True for a single-statement call line (expression or pure assignment)."""
    s = line.strip()
    if not s.endswith(';') or s.count(';') != 1:
        return False
    if _CMV_CTRL.match(line) or line.rstrip().endswith('{') or 'volatile' in line:
        return False
    if not _CMV_CALL.search(line):
        return False
    if '=' not in s and _CMV_PROTO.match(line):
        return False
    return True
