"""Float-memory scheduling, load hoisting, alias sinking, global-pointer caching, and pointer-step rescaling mutations."""
import re
from kintoun.search.mutations_order_reg import (
    _ADR_ARITH,
    _DSO_IDENT,
    _DSO_MFLD,
    _LDO_DECLKW,
    _MXO_ASSIGN,
    _MXO_TYPES,
    _STO_CALL,
    _init_assign,
    _mxo_dep,
    _mxo_idents,
    _mxo_mixkind,
    _mxo_volatiles,
    _sto_idents,
)

FMEM_CAP = 2

_FMEM_DOT = re.compile(r'^(\s*)(sp[0-9A-Fa-f]+)\.(v\d+)\s*=\s*([^;{}]+);\s*(?:/\*.*\*/\s*)?$')

_FMEM_MFL = re.compile(r'^(\s*)M2C_FIELD\(([^,]+?)\s*,\s*(f32|f64|float|double)\s*\*,\s*(0x[0-9A-Fa-f]+|\d+)\)\s*=\s*([^;{}]+);\s*(?:/\*.*\*/\s*)?$')

_FMEM_RISKY_READ = re.compile(r'->|\[')

_FMEM_MFL_READ = re.compile(r'M2C_FIELD\(([^,]+?)\s*,\s*([\w ]+?)\s*\*,\s*([^(),]+)\)')

_FMEM_READ_WIDTH = {'f32': 4, 'float': 4, 's32': 4, 'u32': 4, 'int': 4,
                    'f64': 8, 'double': 8, 's16': 2, 'u16': 2, 's8': 1, 'u8': 1}

_FMEM_DOT_READ = re.compile(r'(sp[0-9A-Fa-f]+)\.(\w+)')

_FMEM_SLOT = re.compile(r'sp[0-9A-Fa-f]+')


def _fmem_key(line):
    """(kind, base, lane, width, rhs) for a swappable float store, else None."""
    m = _FMEM_DOT.match(line)
    if m is not None:
        return ('dot', m[2], m[3], 4, m[4])
    m = _FMEM_MFL.match(line)
    if m is not None:
        width = 8 if m[3] in ('f64', 'double') else 4
        return ('mfl', m[2], int(m[4], 0), width, m[5])
    return None


def _fmem_slot_word(slot, text):
    return re.search(r'\b' + re.escape(slot) + r'\b', text) is not None


def _fmem_rhs_intervals(slot, rhs):
    """Provable (offset, width) reads of slot in rhs, [] if none, None if opaque."""
    if not _fmem_slot_word(slot, rhs):
        return []
    out = []
    for m in _FMEM_MFL_READ.finditer(rhs):
        base, typ, off = m[1].strip(), m[2].strip(), m[3].strip()
        touches = _fmem_slot_word(slot, base) or _fmem_slot_word(slot, off)
        if not touches:
            continue
        if not _fmem_slot_word(slot, base):
            return None  # slot-derived offset through another base: opaque
        try:
            o = int(off, 0)
        except ValueError:
            return None
        w = _FMEM_READ_WIDTH.get(typ)
        if w is None:
            return None
        out.append((o, w))
    tmp = _FMEM_MFL_READ.sub(' ', rhs)
    for m in _FMEM_DOT_READ.finditer(tmp):
        if m[1] != slot:
            continue
        if re.fullmatch(r'v\d+', m[2]):
            out.append((int(m[2][1:]) * 4, 4))
        else:
            return None  # .value/.bytes/unknown member: overlaps every lane
    tmp = _FMEM_DOT_READ.sub(' ', tmp)
    if _fmem_slot_word(slot, tmp):
        return None  # bare, &address-of, or cast mention outside known reads
    return out


def _fmem_write_interval(a):
    if a[0] == 'dot':
        return (int(a[2][1:]) * 4, a[3])
    return (a[2], a[3])


def _fmem_rhs_safe(base, wa, wb, rhs):
    """RHS reads nothing either paired store writes (slot-level, not spelling)."""
    if _FMEM_RISKY_READ.search(rhs):
        return False  # member-pointer or subscript reads may alias the slot
    slot = _FMEM_SLOT.search(base)
    if slot is None:
        if re.search(r'\b' + re.escape(base) + r'\b', rhs):
            return False
        if _FMEM_MFL_READ.search(rhs):
            return False  # unslotted base: any field read may alias it
        return True
    reads = _fmem_rhs_intervals(slot.group(0), rhs)
    if reads is None:
        return False
    for o, w in reads:
        for wo, ww in (wa, wb):
            if o < wo + ww and wo < o + w:
                return False
    return True


def _fmem_swappable(a, b):
    """Same base, disjoint lanes, neither RHS reads a written lane."""
    if a[0] != b[0] or a[1] != b[1]:
        return False
    if a[0] == 'mfl':
        if a[3] != b[3] or abs(a[2] - b[2]) < a[3]:
            return False  # mixed widths or overlapping offsets never swap
    elif a[2] == b[2]:
        return False
    wa, wb = _fmem_write_interval(a), _fmem_write_interval(b)
    return _fmem_rhs_safe(a[1], wa, wb, a[4]) and _fmem_rhs_safe(a[1], wa, wb, b[4])


def m_fmem_order(text, cap=FMEM_CAP):
    """Swap one adjacent same-base float member-store pair (the x,z,y class).

    Measured on this project's MWCC: three member stores in source order
    v0,v1,v2 emit stfs in rotated order v2,v0,v1, and v0,v2,v1 emits
    v1,v0,v2, so no single source spelling reproduces another's word
    stream; local-struct stores keep source order instead. m2c recovers
    one order (e.g. v0,v2,v1 runs in the wild) while the target may hold
    any rotation, and the near-miss board carries the class
    (Voice3D__Construct 96.7%: one lfs/stfs interleave plus an x,z,y vec3
    emission). No existing family reorders stores (coverage-tested every
    order family on a vec3 triple: all yield zero; only constarg_hoist
    fires and it never moves a store). Two adjacent writes to disjoint
    lanes of one stack slot with RHS independent of that slot commute
    unconditionally (adjacent: no intervening code), so the only guards
    are same-kind pairs (DOT lanes vN vs M2C_FIELD offsets never mix:
    their lane maps are unverified against each other), distinct lanes
    (.value/.bytes excluded: they overlap every lane), exact same base
    expression (cast forms like ((f32 *)spEC.bytes) included; different
    strings never pair). RHS alias safety is slot-level, not spelling:
    every read of the written slot must be a provable (offset, width)
    disjoint from both written lanes (same-cast re-reads, cross-cast
    u32/float lane reads, DOT vN reads); bare, &address-of, .value,
    .bytes, member-pointer, subscript, or non-stack reads of the slot
    block the swap. Unslotted (arg/pointer) bases keep the strict rule:
    any field read blocks.
    Cap 2, deduped. Every adjacent pair is its own alternative (no
    skipping after a fire: in a v0,v2,v1 run both the (0,1) and the (1,2)
    single-swaps are reachable rotations, mirroring caseswap's per-pair
    alternatives); cap still bounds the total.
    """
    if '.v' not in text and 'M2C_FIELD' not in text:
        return
    lines = text.split('\n')
    made = 0
    seen = {text}
    i = 0
    while i + 1 < len(lines):
        if made >= cap:
            return
        a = _fmem_key(lines[i])
        b = _fmem_key(lines[i + 1])
        if a is not None and b is not None and _fmem_swappable(a, b):
            cand = '\n'.join(lines[:i] + [lines[i + 1], lines[i]] + lines[i + 2:])
            if cand not in seen:
                seen.add(cand)
                made += 1
                yield 'fmem_order', cand
        i += 1

FHOP_CAP = 2

_FHOP_MACRO_CALL = {'M2C_FIELD', 'M2C_BITWISE', '__typeof__', 'sizeof'}

_FHOP_IDENT_CALL = re.compile(r'\b([A-Za-z_]\w*)\s*\(')

_FHOP_CONTROL = re.compile(r'\b(if|while|for|switch|return|goto|break|continue|case|default|do|else)\b')

_FHOP_TYPEWORDS = {'int', 'float', 'double', 'char', 'short', 'long', 'signed',
                   'unsigned', 'const', 'static', 'extern', 'volatile', 'void',
                   'struct', 'union', 'enum', 's32', 'u32', 's16', 'u16',
                   's8', 'u8', 'f32', 'f64', 'size_t'}


def _fhop_middle_ok(mid, sa_line, sc_line, a, c):
    """True when a non-store line may be crossed by swapping the stores around it.

    Both stores move across mid (S below it, T above it), so mid must be
    independent of both: no calls/control/volatile (may touch anything), no
    labels/ternaries/strings/braces/comparisons (conservative), no pointer or
    subscript writes (may alias the slots), and def/use disjointness both
    ways: mid defines nothing either store reads (T would read it early, S
    would read it late), mid's base-slot mentions are provably disjoint lane
    reads, and mid never writes either base. A same-slot load reading
    disjoint lanes (the Voice3D interleave shape) passes; a load of a
    written lane, an address-of, or a bare slot mention blocks.
    """
    if _fmem_key(mid) is not None:
        return False  # adjacent store/store chains belong to m_fmem_order
    s = mid.strip()
    if not s.endswith(';'):
        return False
    if ':' in mid or '"' in mid or "'" in mid or '{' in mid or '}' in mid:
        return False
    if _FHOP_CONTROL.search(mid) or re.search(r'\bvolatile\b', mid):
        return False
    if '==' in mid or '!=' in mid or '->' in mid or '[' in mid:
        return False
    for m in _FHOP_IDENT_CALL.finditer(mid):
        if m[1] not in _FHOP_MACRO_CALL:
            return False  # a real call may read or write anything
    if '=' not in mid:
        return False
    lhs, rhs = mid.split('=', 1)
    if '*' in lhs or '&' in lhs:
        return False  # pointer write may alias the slots
    defs = set(re.findall(r'\b[A-Za-z_]\w*\b', lhs)) - _FHOP_TYPEWORDS
    uses_st = (set(re.findall(r'\b[A-Za-z_]\w*\b', a[4])) |
               set(re.findall(r'\b[A-Za-z_]\w*\b', c[4])))
    if defs & uses_st:
        return False
    base_words = (set(re.findall(r'\b[A-Za-z_]\w*\b', a[1])) |
                  set(re.findall(r'\b[A-Za-z_]\w*\b', c[1])))
    if defs & base_words:
        return False
    wa, wb = _fmem_write_interval(a), _fmem_write_interval(c)
    for base in (a[1], c[1]):
        slot = _FMEM_SLOT.search(base)
        if slot is not None:
            if not _fmem_slot_word(slot.group(0), mid):
                continue
            reads = _fmem_rhs_intervals(slot.group(0), mid)
            if reads is None:
                return False
            for o, w in reads:
                for wo, ww in (wa, wb):
                    if o < wo + ww and wo < o + w:
                        return False
        else:
            if re.search(r'\b' + re.escape(base) + r'\b', mid):
                return False
            if _FMEM_MFL_READ.search(mid):
                return False  # unslotted base: any field read may alias it
    return True


def m_fmem_hop(text, cap=FHOP_CAP):
    """Swap two same-base float stores across one independent middle line.

    m_fmem_order only swaps adjacent store pairs, so a store pair split by
    one interleaved line (a same-slot load as in Voice3D__Construct 96.7%,
    or any independent line) can never reorder: the beam has no single
    yield crossing the middle, and chaining two adjacent swaps needs an
    intermediate no family emits. Census on bench seeds: 108 tier-2 clean
    hops on the dev set, 656 on held-out, plus 12 same-slot load hops.
    Soundness rides the same slot-level lane proof as m_fmem_order for the
    store pair (_fmem_swappable) plus _fhop_middle_ok independence of the
    crossed line. Cap 2, deduped, per-pair alternatives like fmem_order.
    """
    if '.v' not in text and 'M2C_FIELD' not in text:
        return
    lines = text.split('\n')
    made = 0
    seen = {text}
    for i in range(len(lines) - 2):
        if made >= cap:
            return
        a = _fmem_key(lines[i])
        c = _fmem_key(lines[i + 2])
        if a is None or c is None:
            continue
        if not _fmem_swappable(a, c):
            continue
        if not _fhop_middle_ok(lines[i + 1], lines[i], lines[i + 2], a, c):
            continue
        cand = '\n'.join(lines[:i] + [lines[i + 2], lines[i + 1], lines[i]] + lines[i + 3:])
        if cand not in seen:
            seen.add(cand)
            made += 1
            yield 'fmem_hop', cand

LHO_CAP = 2

_LHO_LBL = re.compile(r'\blbl_[0-9A-Fa-f]+\b')

_LHO_BARE = re.compile(r'^[A-Za-z_]\w*$')

_LHO_DOTLHS = re.compile(r'^\s*([A-Za-z_]\w*)\.([A-Za-z_]\w*)\s*=')

_LHO_GLOBAL = re.compile(r'^\s*(lbl_[0-9A-Fa-f]+)\s*=')


def _lho_misses_global(line, lbls):
    """True when line's written lhs provably is not a lbls address.

    Stack slots (plain `&sp` MFLD bases, sp DOT members) and different
    data globals cannot be the loaded global; opaque-pointer MFLD bases
    (temp/arg/complex) could alias it at runtime, so they stay out.
    """
    if 'M2C_FIELD' in line:
        ms = list(_DSO_MFLD.finditer(line))
        if len(ms) != 1:
            return False
        base = ms[0].group(1)
        if re.search(r'->|\[', base):
            return False
        idents = [w for w in _DSO_IDENT.findall(base)
                  if w not in _MXO_TYPES and w != 'M2C_FIELD'
                  and w != 'bytes']
        return len(idents) == 1 and idents[0].startswith('sp') \
            and '&' in base
    m = _LHO_DOTLHS.match(line)
    if m:
        return m.group(1).startswith('sp')
    g = _LHO_GLOBAL.match(line)
    if g:
        return g.group(1) not in lbls
    return False


def m_loadhoist_order(text, cap=LHO_CAP):
    """Hoist a consumer-fed global load above 2+ independent stores.

    Census (b3-loadhoist-census, 1132 real bench seed texts): 14 unique
    load-consumer triples (307 occurrences) shaped `S..; spY = lbl_N;
    M2C_FIELD(&spY, ..) = ..` where the load feeds the store below and
    sits under 2+ dep-clean stores (Plant__Construct 96.3% via b4 FYI:
    the target hoists the SDA load up with the address setup while ours
    loads it right before its store). No single adjacent swap reaches a
    multi-store hoist in one yield: mixed/callpure move one line across
    one neighbor, so distance-2+ hoists need stepwise rounds the search
    may never spend. One yield moves the load to the top of its
    dep-clean store run with the consumer pinned below. Guards: load
    line with a lbl_ source (the SDA/global lane; MFLD loads stay with
    the macro families), bare-temp lhs read by the immediately following
    store (the pinned consumer), every crossed line store-kind,
    _mxo_dep clean across each crossed store (a crossed read of the
    loaded temp or write to its source blocks) plus a provable-miss
    proof per crossed store (an opaque-pointer write could alias the
    loaded global invisibly to dep, so only stack/global-distinct
    writers count toward reach), nonvolatile, reach >= 2
    (reach-1 is mixed's adjacent swap lane). Own cap, near-miss-gated
    via the shared _init_shaped gate, wired last in directed(): full
    hoists reorder same-kind others, which init_order never does, and no
    other family moves one line across two neighbors, so yields are
    disjoint by construction.
    """
    lines = text.split('\n')
    kinds = [_mxo_mixkind(l) for l in lines]
    vol = _mxo_volatiles(text)
    made = 0
    seen = {text}
    for i in range(1, len(lines) - 1):
        if made >= cap:
            return
        if kinds[i] != 'load' or kinds[i + 1] != 'store':
            continue
        a, b = lines[i], lines[i + 1]
        if 'M2C_FIELD' in a or not _LHO_LBL.search(a):
            continue
        ma = _MXO_ASSIGN.match(a)
        if not ma or not _LHO_BARE.match(ma.group(2).strip()):
            continue
        temp = ma.group(2).strip()
        if not re.search(r'\b' + re.escape(temp) + r'\b', b):
            continue
        top = i
        ok = True
        lbls = set(_LHO_LBL.findall(a))
        for j in range(i - 1, -1, -1):
            if kinds[j] != 'store':
                break
            try:
                if _mxo_dep(lines[j], 'store', a, 'load', vol):
                    break
            except Exception:
                ok = False
                break
            if (_mxo_idents(lines[j]) | _mxo_idents(a)) & vol:
                break
            if not _lho_misses_global(lines[j], lbls):
                break
            top = j
        if not ok:
            continue
        if i - top < 2:
            continue
        out = lines[:top] + [a] + lines[top:i] + lines[i + 1:]
        cand = '\n'.join(out)
        if cand in seen:
            continue
        seen.add(cand)
        made += 1
        yield 'loadhoist_order', cand

ASK_CAP = 2

_ASK_CASTDEF = re.compile(
    r'^(\s*)([A-Za-z_]\w*)\s*=\s*(\([^()]*\)\s*)?'
    r'([A-Za-z_]\w*\s*[+-]\s*-?(?:0x[0-9a-fA-F]+|\d+)[uUlL]*)\s*;\s*$')

_ASK_LOOP_OPEN = re.compile(
    r'^\s*(do\s*\{\s*|for\s*\(.*\)\s*\{\s*|while\s*\(.*\)\s*\{\s*)$')

_ASK_FLOW = re.compile(r'\bgoto\b|^\s*(?:case\b[^:]*:|default\s*:|[A-Za-z_]\w*\s*:)')


def _ask_plain_use(line, name):
    """Whole-word uses of `name` that are not member accesses (`s.t`, `p->t`)."""
    return re.compile(r'(?<![.\->\w])' + re.escape(name) + r'\b').search(line)


def _ask_assigns(line, name):
    """True when this line assigns (or inc/decs) the plain ident `name`."""
    if re.search(r'\b' + re.escape(name) + r'\s*(?:\+\+|--)', line):
        return True
    if re.search(r'(?:\+\+|--)\s*' + re.escape(name) + r'\b', line):
        return True
    return bool(re.search(r'(?<![.\->\w])' + re.escape(name)
                          + r'\s*(?:[+\-*/%&|^]?=)(?!=)', line))


def _ask_def(line):
    """(t, rhs, base) for one pure `t = base +/- K` address derivation.

    `_adr_kind` admits the bare form; a single cast on the base
    (`p = (char *)arg0 + 0x1a0`, the MenuSlider in-loop alias shape) is
    the same pure computation and joins here.
    """
    if not _init_assign(line):
        return None
    m = _ADR_ARITH.match(line)
    if m:
        t, base = m[2], m[3]
        rhs = line.split('=', 1)[1].rsplit(';', 1)[0].strip()
    else:
        m2 = _ASK_CASTDEF.match(line)
        if not m2 or not m2[3]:
            return None
        t = m2[2]
        rhs = (m2[3].strip() + ' ' + m2[4].strip()).strip()
        bm = re.match(r'([A-Za-z_]\w*)\s*[+-]', m2[4].strip())
        if not bm:
            return None
        base = bm[1]
    if _sto_idents(t) & _LDO_DECLKW:
        return None
    if base in _MXO_TYPES:
        return None
    if t in _sto_idents(rhs):
        return None
    return t, rhs, base


def _ask_bare_decl(line, name):
    """True for a bare declaration of `name` (`char *p;`, no initializer).

    The type-keyword lead keeps `return t;` and expression statements
    out: only a declared type word may open the line. Aggregate
    one-liners (`union {...} sp8;`) carry braces and stay out.
    """
    s = line.strip()
    if '=' in s or '(' in s or not s.endswith(';'):
        return False
    return bool(re.match(r'^(?:' + '|'.join(sorted(_MXO_TYPES)) + r')\b[\w\s\*]*\b'
                         + re.escape(name) + r'\s*;\s*$', s))


def _ask_regions(lines):
    """Brace-matched (open, close) for goto/label-free do/for/while blocks."""
    regs = []
    for i, ln in enumerate(lines):
        if not _ASK_LOOP_OPEN.match(ln):
            continue
        depth = ln.count('{') - ln.count('}')
        for j in range(i + 1, len(lines)):
            depth += lines[j].count('{') - lines[j].count('}')
            if depth <= 0:
                if not any(_ASK_FLOW.search(lines[k]) for k in range(i, j + 1)):
                    regs.append((i, j))
                break
    return regs


def m_alias_sink(text, cap=ASK_CAP):
    """Rematerialize a hoisted address temp at its in-loop uses (CSE-defeat).

    Census (1124 real bench seed texts, committed guards): 30 texts fire
    32 yields (loose probe: 102 texts / 614 pairs; goto/label regions,
    member-aware single-def, and address-taken guards cut the rest).
    The motivated row is
    MenuSlider__Increment (dev, HEAD 84.1%, b4 FYI 22:02 CT): the beam
    CSEs `arg0 + 0x1A0` into a temp live across the loop (and alias_make
    can plant the def inside the loop body with later uses outside it)
    while the target recomputes the address inline per iteration and keeps
    no such temp. Rematerialization is the classic reg-alloc trade (free
    the register holding the address, pay one addi per iteration) and no
    landed family produces it: order families permute lines, regcopy
    inserts/removes `t = u` copies, loadhoist moves loads.

    Soundness: the rhs is a pure computation (no calls/reads by the
    shared _init_assign qualifier); the base is provably unassigned
    between the def and the last replaced use (direct assignment and
    inc/dec scan; member writes like `p->base` cannot change a plain
    ident's value); the temp has exactly one definition, is never
    address-taken, and only post-def uses inside one loop region are
    rewritten, so loop-carried (pre-def) uses keep the temp. Volatile
    base/temp lines stay out, and regions with goto/labels (entry paths
    that skip the def) are skipped. The def drops only when no plain
    use remains. Own cap, near-miss-gated via the shared _init_shaped
    gate, wired last in directed().
    """
    lines = text.split('\n')
    regs = _ask_regions(lines)
    if not regs:
        return
    vol = _mxo_volatiles(text)
    made = 0
    seen = {text}
    for i, ln in enumerate(lines):
        if made >= cap:
            return
        got = _ask_def(ln)
        if not got:
            continue
        t, rhs, base = got
        if vol and (base in vol or t in vol):
            continue
        if sum(1 for q in lines if _ask_assigns(q, t)) != 1:
            continue
        if re.search(r'&\s*' + re.escape(t) + r'\b', text):
            continue
        for (a, b) in regs:
            if made >= cap:
                return
            uses = [j for j in range(max(a, i + 1), b + 1)
                    if _ask_plain_use(lines[j], t)
                    and not _ask_assigns(lines[j], t)]
            if not uses:
                continue
            if any('volatile' in lines[j] for j in uses):
                continue
            if any(_ask_assigns(lines[k], base)
                   for k in range(i + 1, max(uses) + 1)):
                continue
            pat = re.compile(r'(?<![.\->\w])' + re.escape(t) + r'\b')
            out = lines[:]
            for j in uses:
                out[j] = pat.sub('(' + rhs + ')', lines[j])
            if not any(_ask_plain_use(q, t) and not _ask_bare_decl(q, t)
                       for n, q in enumerate(out) if n != i):
                del out[i]
            cand = '\n'.join(out)
            if cand in seen:
                continue
            seen.add(cand)
            made += 1
            yield 'alias_sink', cand

GLB_CAP = 2

_GLB_LOAD_OPS = frozenset((32, 34, 40, 42, 46, 48, 50))

_GLB_LBL = re.compile(r'(?<![\w&])lbl_[0-9A-Fa-f]+\b')

_GLB_DECL = re.compile(r'^\s*extern\b[^;\n]*?\b(lbl_[0-9A-Fa-f]+)\b([^;\n]*);')

_GLB_FLOW = re.compile(r'\bgoto\b|^\s*(?:case\b[^:]*:|default\s*:|[A-Za-z_]\w*\s*:)')

_GLB_STR = re.compile(r'"(?:[^"\\\n]|\\.)*"|\'(?:[^\'\\\n]|\\.)*\'')


def _glb_depths(lines):
    """Brace depth before each line (string literals stripped first)."""
    depths = []
    depth = 0
    for ln in lines:
        depths.append(depth)
        code = _GLB_STR.sub('', ln)
        depth += code.count('{') - code.count('}')
    return depths


def _glb_sda_loads(words):
    """Count SDA-window (r13/r2) load instructions in a word stream."""
    n = 0
    for w in words or []:
        if (w >> 26) not in _GLB_LOAD_OPS:
            continue
        if ((w >> 16) & 31) in (13, 2):
            n += 1
    return n


def _glb_writes(line, lbl):
    """True when this line writes the global (plain, field, or address-of)."""
    if re.search(r'M2C_FIELD\s*\(\s*(?:&\s*)?' + lbl + r'\b[^)]*\)\s*=[^=]', line):
        return True
    if re.search(r'(?<![.\->\w])' + lbl
                 + r'\s*(?:[+\-*/%&|^]?=)(?!=)', line):
        return True
    return False


def m_globalcache(text, target, ours, cap=GLB_CAP):
    """Cache a repeatedly-read global in a temp across stores (SDA shape).

    Census (1126 real bench seed texts, SDA gate forced open): 568 texts
    fire 922 yields (tight sound-core pre-count 90: same global read 2+
    times with a store between, call/write-free span; real gated reach
    is target-dependent). The motivated rows are the 3 KB monsters
    (AI__CheckLineOfSight, b4 FYI 21:23 CT): the target keeps the SDA
    pointer in a register across the stores while ours reloads it per
    use, so positional strict collapses at the first extra load. The
    direction is read off the target like m_regcopy's mr count: more
    SDA-window loads here than there introduces
    `__typeof__(lbl) t_b3gcN = lbl;` at the first read and reuses the
    temp for later reads. No landed family does this: regcopy inserts
    single-site `t_b3rc` copies (one line each), order families permute
    lines, loadhoist moves loads above stores.

    Soundness: only pure reads are replaced (writes, address-taken, and
    call lines make the span dirty and block the pair); the global keeps
    its declaration (arrays/functions/no-decl stay out since the cache
    temp needs a copyable declared object); volatile globals stay out;
    all replaced reads share one block scope (same brace depth, never
    crossed, so the temp is always visible) and spans with goto/labels
    stay out (entry paths that skip the def). Own cap, target-evidenced
    (SDA-load count) like m_regcopy, wired next to it in directed():
    yields are disjoint by construction (t_b3gc temps spanning 2+ lines).
    """
    if _glb_sda_loads(ours) - _glb_sda_loads(target) <= 0:
        return
    lines = text.split('\n')
    decls = {}
    for ln in lines:
        m = _GLB_DECL.match(ln)
        if m:
            decls[m[1]] = m[2]
    vol = _mxo_volatiles(text)
    order = []
    for i, ln in enumerate(lines):
        if ln.strip().startswith('extern'):
            continue
        for m in _GLB_LBL.finditer(ln):
            if m.group(0) not in order:
                order.append(m.group(0))
    made = 0
    seen = {text}
    for lbl in order:
        if made >= cap:
            return
        tail = decls.get(lbl)
        if tail is None or vol and lbl in vol:
            continue
        if '(' in tail or '[' in tail:
            continue
        if re.search(r'&\s*' + lbl + r'\b', text):
            continue
        reads = []
        blocked = False
        for i, ln in enumerate(lines):
            if ln.strip().startswith('extern'):
                continue
            if not any(m.group(0) == lbl for m in _GLB_LBL.finditer(ln)):
                continue
            if _STO_CALL.search(ln) or _glb_writes(ln, lbl):
                if reads:
                    blocked = True
                    break
                continue
            reads.append(i)
        if reads and not blocked:
            for k in range(reads[0], reads[-1] + 1):
                if k in reads or lines[k].strip().startswith('extern'):
                    continue
                if (_STO_CALL.search(lines[k]) or _glb_writes(lines[k], lbl)
                        or re.search(r'&\s*' + lbl + r'\b', lines[k])):
                    blocked = True
                    break
        if reads and not blocked:
            depths = _glb_depths(lines)
            first, last = reads[0], reads[-1]
            if depths[first] != depths[last] or min(
                    depths[first:last + 1]) < depths[first]:
                blocked = True
            elif any(_GLB_FLOW.search(lines[k])
                     for k in range(first, last + 1)):
                blocked = True
        if blocked or len(reads) < 2:
            continue
        k = 0
        while re.search(r'\bt_b3gc%d\b' % k, text):
            k += 1
        temp = 't_b3gc%d' % k
        first = reads[0]
        indent = lines[first][:len(lines[first]) - len(lines[first].lstrip())]
        pat = re.compile(r'(?<![.\->\w])' + lbl + r'\b')
        out = lines[:]
        out.insert(first, '%s__typeof__(%s) %s = %s;' % (indent, lbl, temp, lbl))
        for j in reads:
            out[j + 1] = pat.sub(temp, lines[j])
        cand = '\n'.join(out)
        if cand in seen:
            continue
        seen.add(cand)
        made += 1
        yield 'globalcache', cand

PTRSTEP_CAP = 2

_PTRSTEP_DECL = re.compile(
    r'^\s*(?:const\s+)?(?:unsigned\s+|signed\s+)?'
    r'(char|short|int|long|float|double|s8|u8|s16|u16|s32|u32|f32|f64|M2C_UNK)'
    r'((?:\s+long)?(?:\s*\*)+)\s*(\w+)\s*;')

_PTRSTEP_ADJ = re.compile(r'^\s*(\w+)\s*([-+])=\s*(.+?)\s*;\s*$')

_PTRSTEP_SIZE = {'char': 1, 's8': 1, 'u8': 1, 'short': 2, 's16': 2, 'u16': 2,
                 'int': 4, 'long': 4, 'float': 4, 's32': 4, 'u32': 4,
                 'f32': 4, 'M2C_UNK': 4, 'double': 8, 'f64': 8}


def _ptrstep_target_imms(target):
    """Magnitudes of small addi/subi immediates in the target words."""
    imms = set()
    for w in target or []:
        if w >> 26 != 14:
            continue
        imm = w & 0xffff
        imm -= 0x10000 if imm & 0x8000 else 0
        if 0 < abs(imm) <= 128:
            imms.add(abs(imm))
    return imms


def m_ptrstep_rescale(text, target, cap=PTRSTEP_CAP):
    """Rescale typed-pointer constant steps by the pointee size, target-gated.

    Spark 10:56 1-byte class (EffectHandle__ResetSystem 1B: `s32 *p; p -= 4`
    compiles to subi 16 where the target steps one word with subi 4; the
    `-= 1` variant is byte-exact): m2c and hand seeds both confuse element
    steps with byte steps on typed pointers. For each `p -= K` / `p += K`
    on a multi-byte pointee, yield K/elsize and K*elsize variants, but only
    when the rescaled byte displacement appears as a small addi/subi
    immediate in the target, so blind parents spend nothing. Cap 2.
    """
    imms = _ptrstep_target_imms(target)
    if not imms:
        return
    lines = text.split('\n')
    decls = {}
    for line in lines:
        m = _PTRSTEP_DECL.match(line)
        if not m:
            continue
        base, stars, name = m[1], m[2], m[3]
        if base == 'long' and 'long' in stars:
            size = 8
        else:
            size = _PTRSTEP_SIZE.get(base)
        if size is None or size == 1:
            continue
        decls.setdefault(name, size)
    if not decls:
        return
    seen = {text}
    made = 0
    for i, line in enumerate(lines):
        if made >= cap:
            return
        m = _PTRSTEP_ADJ.match(line)
        if not m:
            continue
        name, op, rhs = m[1], m[2], m[3]
        size = decls.get(name)
        if size is None:
            continue
        try:
            step = int(rhs.strip().rstrip('uUlL'), 0)
        except ValueError:
            continue
        if step == 0:
            continue
        # Immediates are byte displacements: the seed step compiles to
        # step*elsize bytes. No already-evidenced skip: a coincidental
        # unrelated addi (EffectHandle's target also holds addi 16 next to
        # the real subi 4) would veto the true fix, and the variant gate
        # below is already target-evidenced with a cap bounding the cost.
        cands = []
        if step % size == 0 and step // size != step:
            cands.append(step // size)
        if abs(step * size * size) <= 128 and step * size != step:
            cands.append(step * size)
        for cand in cands:
            if made >= cap:
                return
            if abs(cand) * size not in imms:
                continue
            out = lines[:]
            out[i] = re.sub(r'[-+]=\s*' + re.escape(rhs.strip()) + r'(?=\s*;)',
                            f'{op}= {cand}', line, count=1)
            variant = '\n'.join(out)
            if variant in seen:
                continue
            seen.add(variant)
            made += 1
            yield 'ptrstep_rescale', variant
