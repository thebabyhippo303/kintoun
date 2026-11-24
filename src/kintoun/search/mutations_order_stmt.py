"""Call-address, pure-call, literal, memory-view, cross-base, mixed-statement, member, and declaration ordering mutations."""
import re
from kintoun.search.mutations_order_reg import (
    ADR_CAP,
    CMV_CAP,
    MXO_CAP,
    _CHO_CALLISH,
    _CHO_CTRL,
    _CHO_PLAIN,
    _CHO_SAFE_ARG,
    _CMV_TAKEN,
    _CMV_VOLDECL,
    _DSO_CALLISH,
    _DSO_FLOATLIT,
    _DSO_IDENT,
    _DSO_MFLD,
    _INIT_AGGDECL,
    _INIT_CONST,
    _INIT_DECL,
    _LDO_DECLKW,
    _LDO_FLD,
    _LDO_LOAD,
    _MXO_ASSIGN,
    _MXO_FLOAT,
    _MXO_TYPES,
    _STO_CALL,
    _STO_CHAIN,
    _STO_FIELD,
    _adr_kind,
    _cho_call_at,
    _cho_is_call,
    _cho_pure_arg,
    _cho_split_args,
    _cmv_callside,
    _dso_off,
    _dso_old_ok,
    _dso_pure_rhs,
    _dso_samebase_ok,
    _dso_width,
    _init_assign,
    _init_independent,
    _ldo_target_order,
    _mxo_dep,
    _mxo_idents,
    _mxo_kind,
    _mxo_lhs,
    _mxo_mixkind,
    _mxo_pairs,
    _mxo_samepure_ok,
    _mxo_volatiles,
    _sto_idents,
    _sto_target_order,
    m_init_order,
)

CAD_CAP = 2


def m_calladdr_order(text, cap=CAD_CAP):
    """Move an address materialization across an adjacent independent call.

    Census (b3-addrmove-census, 1132 real bench seed texts): 186 adjacent
    `t = base + K` / call pairs on 8 rows pass callmove's exact independence
    proof, but callmove moves copy/const only, so address-setup scheduling
    (addi order around calls) is unreachable. _adr_kind admits pure
    derivations only (ident base, const offset; calls, fields and
    ident+ident excluded by construction), so the moved line is a pure
    computation exactly like a copy: sound under the same proof (no shared
    ident either direction, moved idents never address-taken, nonvolatile,
    control never participates). Own cap, near-miss-gated via the shared
    _init_shaped gate, wired last in directed(): yields are disjoint from
    every landed family's by kind (addr x call side; callmove takes
    copy/const only).
    """
    lines = text.split('\n')
    taken = set(_CMV_TAKEN.findall(text))
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
        if not _adr_kind(mem):
            continue
        if 'volatile' in mem:
            continue
        mi, ci = _mxo_idents(mem), _mxo_idents(call)
        if mi & ci:
            continue
        if (mi | ci) & vol:
            continue
        if mi & taken:
            continue
        out = lines[:]
        out[i], out[i + 1] = out[i + 1], out[i]
        cand = '\n'.join(out)
        if cand in seen:
            continue
        seen.add(cand)
        made += 1
        yield 'calladdr_order', cand

CPU_CAP = 2

_CPU_CASTDOT = re.compile(r'\([A-Za-z_]\w*\s*\*+\)\s*[A-Za-z_]\w*\.[A-Za-z_]\w*')

_CPU_ADDRDOT = re.compile(r'&[A-Za-z_]\w*\.[A-Za-z_]\w*')


def _cpu_pure_rhs(rhs):
    """True when a rhs computes without reading memory or calling.

    Address-forming dots are computations, not reads: `&X.m` takes an
    address and `(T *)X.m` casts one, so those spellings are substituted
    away before the dot check. A remaining dot is a member read (or a
    disguised multiply like `(s.field * 2)`, whose dot the cast pattern
    cannot span), and blocks. Float literals are stripped first. Bare
    global reads (`t = lbl_X`, even float constants) are reads too: the
    callee may write any global, so only `&`-addressed globals
    (computations, stripped first) stay pure.
    """
    if _DSO_MFLD.search(rhs) or _DSO_CALLISH.search(rhs) or '->' in rhs:
        return False
    for m in re.finditer(r'\blbl_[0-9A-Fa-f]+\b', rhs):
        j = m.start()
        while j > 0 and rhs[j - 1] in ' \t':
            j -= 1
        if j > 0 and rhs[j - 1] == '&':
            k = j - 1
            while k > 0 and rhs[k - 1] in ' \t':
                k -= 1
            if k > 0 and rhs[k - 1] == ')':
                depth = 0
                while k > 0:
                    if rhs[k - 1] == ')':
                        depth += 1
                    elif rhs[k - 1] == '(':
                        depth -= 1
                        if depth == 0:
                            break
                    k -= 1
                while k > 0 and rhs[k - 1] in ' \t':
                    k -= 1
            if k == 0 or rhs[k - 1] in '(,=+-/%<>!?:~|^':
                continue  # genuine address-of: a computation, not a read
            if rhs[k - 1] == '*':
                q = k - 1
                while q > 0 and rhs[q - 1] in ' \t':
                    q -= 1
                if q > 0 and rhs[q - 1] not in '(,=+-*/%<>!?:~|^&':
                    continue  # binary multiply before &: still address-of
                # unary deref of an address (`*&lbl`): a real read
        return False
    tmp = _CPU_ADDRDOT.sub('&X', rhs)
    tmp = _CPU_CASTDOT.sub('P', tmp)
    tmp = _DSO_FLOATLIT.sub('', tmp)
    if '.' in tmp:
        return False
    tmp = tmp.replace('**', '')
    if re.search(r'\*\s*[A-Za-z_(]', tmp) or re.search(r'[A-Za-z_]\w*\s*\[', tmp):
        return False
    return True


def _cpu_confined_read(rhs):
    """sp slot(s) read through M2C_FIELD, or None when any read is wider.

    The slot-confinement twin of the spillsched store proof, mirrored for
    reads: the call cannot name an untaken, unpassed stack slot, so it can
    neither write what the load reads nor observe its timing. Loads write
    only their lhs temp (shared-ident cleared by the caller).
    Pointer-rooted reads stay out: the callee may write through its own
    pointers.
    """
    slots = set()
    for mm in _DSO_MFLD.finditer(rhs):
        base = mm.group(1)
        if re.search(r'->|\[', base):
            return None
        idents = [w for w in _DSO_IDENT.findall(base) if w not in _MXO_TYPES
                  and w != 'M2C_FIELD']
        if not idents or not idents[0].startswith('sp'):
            return None
        if _dso_off(mm.group(3)) is None or _dso_width(mm.group(2)) is None:
            return None
        slots.add(idents[0])
    tmp = _DSO_MFLD.sub('', rhs)
    if (_DSO_CALLISH.search(tmp) or '->' in tmp
            or re.search(r'[A-Za-z_]\w*\.[A-Za-z_]\w*', tmp)
            or re.search(r'\*\s*[A-Za-z_(]', tmp.replace('**', ''))
            or re.search(r'[A-Za-z_]\w*\s*\[', tmp)):
        return None
    return slots


def m_callpure_order(text, cap=CPU_CAP):
    """Move a call-independent load across an adjacent call.

    Census (b3-loadspill-census, 1132 real bench seed texts): 8,241
    call-adjacent loads split into 7,057 shared-ident (dependent), 629
    callee-visible pointer reads (unsound to move), 398 pure computations
    (casts, address-taken, constants: no memory read at all) and 27
    stack-confined reads. Only the last two move, under callmove's proof:
    no shared ident either direction, moved idents never address-taken
    outside M2C_FIELD bases and outside the pair itself, the call never
    names a read slot, nonvolatile, control never participates. Copy/const
    (callmove), addr (calladdr) and store (spillsched) lines stay out, so
    yields are disjoint from every landed family's by construction. Own
    cap, near-miss-gated via the shared _init_shaped gate, wired last in
    directed().
    """
    lines = text.split('\n')
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
        if _mxo_mixkind(mem) not in ('load', 'cond'):
            continue
        if _adr_kind(mem):
            continue
        if 'volatile' in mem:
            continue
        m = _MXO_ASSIGN.match(mem)
        if not m:
            continue
        lhs, rhs = m.group(2).strip(), m.group(3).strip()
        if not lhs.isidentifier():
            continue
        mi, ci = _mxo_idents(mem), _mxo_idents(call)
        if mi & ci:
            continue
        if (mi | ci) & vol:
            continue
        slots = _cpu_confined_read(rhs)
        if slots is None:
            if not _cpu_pure_rhs(rhs):
                continue
        elif not _cpu_pure_rhs(_DSO_MFLD.sub('', rhs)):
            # confined slots cover MFLD-sp reads only; any other read
            # (bare globals most importantly: the callee may write them)
            # must still be pure
            continue
        moved = mi
        outside = _DSO_MFLD.sub('', '\n'.join(lines[:i] + lines[i + 2:]))
        if moved & set(_CMV_TAKEN.findall(outside)):
            continue
        if slots and any(re.search(r'\b' + re.escape(s) + r'\b', call)
                         for s in slots):
            continue
        out = lines[:]
        out[i], out[i + 1] = out[i + 1], out[i]
        cand = '\n'.join(out)
        if cand in seen:
            continue
        seen.add(cand)
        made += 1
        yield 'callpure_order', cand

CHL_CAP = 2

_CHL_LIT = re.compile(r'^-?(?:0x[0-9a-fA-F]+|\d+)(?:\.\d+)?f?$')


def m_cholit_order(text, cap=CHL_CAP):
    """Hoist literal args above a nested-call site (const-first setup).

    Census (b3-callarg-census, 1132 real bench seed texts): 134 call sites
    mix a nested call with a literal, but constarg_hoist pass 2 already
    reaches 110 of them; the true gap is 24 sites on 2 rows where the call
    args block every hoist (e.g. `F(0x16, Gfx__PackColor(&sp8))`: only one
    safe arg, nothing pure to add). Hoisting a literal into a temp assigned
    above the call is unconditionally sound (zero reads, so no callee can
    observe or disturb it) and produces the const-first setup order no
    landed family yields. Literals only (idents stay: a copy across the
    nested call would read a local the callee might reach); sites
    constarg_hoist already takes stay out, so yields are disjoint from
    every landed family's by construction; M2C_ERROR/BITWISE sites stay
    out (broken-seed vacuum). Own cap, own `chl_t` temps, near-miss-gated
    via the shared _init_shaped gate, wired last in directed().
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
        if any('M2C_ERROR' in a or 'M2C_BITWISE' in a for a in args):
            continue
        if not any(_CHO_CALLISH.search(a) for a in args):
            continue
        lit_idx = [k for k, a in enumerate(args) if _CHL_LIT.match(a.strip())]
        if not lit_idx:
            continue
        safe = [bool(_CHO_SAFE_ARG.match(a)) for a in args]
        if sum(safe) >= 2:
            continue
        if any(_cho_pure_arg(a) and not s for s, a in zip(safe, args)):
            continue
        indent = line[:len(line) - len(line.lstrip())]
        names = {}
        for k in lit_idx:
            name = f'chl_t{serial}'
            serial += 1
            while re.search(r'\b' + re.escape(name) + r'\b', text):
                name = f'chl_t{serial}'
                serial += 1
            names[k] = name
        # One order per site: two lits would already satisfy constarg_hoist
        # pass 1 (two safe args), so gap sites always carry exactly the
        # hoisted lits in source order.
        decls = [f'    __typeof__({args[k]}) {names[k]};' for k in lit_idx]
        assigns = [f'{indent}{names[k]} = {args[k]};' for k in lit_idx]
        new_args = [names[k] if k in names else args[k] for k in range(len(args))]
        out = lines[:]
        out[i] = line[:open_pos + 1] + ', '.join(new_args) + ');'
        out[i:i] = assigns
        out[start + 1:start + 1] = decls
        candidate = '\n'.join(out)
        if candidate in seen:
            continue
        seen.add(candidate)
        made += 1
        yield 'cho_lit_order', candidate

MSM_CAP = 2


def _msm_nocall(line):
    return not _DSO_CALLISH.search(line)


def m_samemem_order(text, cap=MSM_CAP):
    """Swap adjacent dep-clean same-kind M2C_FIELD memory pairs.

    Census (b3-coveraudit, 1132 real bench seed texts): mixed-kind dep-clean
    non-lilis pairs are all taken corpus-wide (mixed takes every one), but
    same-kind dep-clean M2C_FIELD pairs are unowned textually: load/load
    14,025 (member_order excludes load/load pairs, plainload owns plain
    loads only, mixed skips same-kind) and store/store 4,640 (disjoint
    requires a shared ident, mixed skips same-kind, member needs
    struct-proofed dot spellings). Target-evidenced families cover some of
    these live with per-pair evidence; this family is the target-free
    surface. Loads commute unconditionally (two reads, no writes), so any
    base qualifies once rule 1 (temp write-cross), volatiles and calls
    clear. Stores use the disjoint address machinery unchanged (stack/
    global disjoint ranges, or same-base numeric-disjoint on any root with
    pure rhs). Shared-ident store pairs stay with disjoint_order (rule-2
    pile); DOT/arrow/plain spellings stay with member/plainload. Own cap,
    near-miss-gated via the shared _init_shaped gate, wired last in
    directed().
    """
    lines = text.split('\n')
    vol = _mxo_volatiles(text)
    made = 0
    seen = {text}
    for i in range(len(lines) - 1):
        if made >= cap:
            return
        a, b = lines[i], lines[i + 1]
        ka, kb = _mxo_mixkind(a), _mxo_mixkind(b)
        if ka is None or kb is None or ka != kb or ka not in ('load', 'store'):
            continue
        if not _DSO_MFLD.search(a) or not _DSO_MFLD.search(b):
            continue
        if 'volatile' in a or 'volatile' in b:
            continue
        if not _msm_nocall(a) or not _msm_nocall(b):
            continue
        sa, sb = _mxo_idents(a), _mxo_idents(b)
        la, lb = _mxo_lhs(a), _mxo_lhs(b)
        if (la and la in sb) or (lb and lb in sa):
            continue
        if vol and ((sa | sb) & vol):
            continue
        if ka == 'store':
            if sa & sb:
                continue
            ma = _MXO_ASSIGN.match(a)
            mb = _MXO_ASSIGN.match(b)
            if not ma or not mb:
                continue
            if not _DSO_MFLD.fullmatch(ma.group(2).strip()):
                continue
            if not _DSO_MFLD.fullmatch(mb.group(2).strip()):
                continue
            if not _dso_old_ok(a, b) and not _dso_samebase_ok(a, b):
                continue
        out = lines[:]
        out[i], out[i + 1] = out[i + 1], out[i]
        cand = '\n'.join(out)
        if cand in seen:
            continue
        seen.add(cand)
        made += 1
        yield 'samemem_order', cand

BVW_CAP = 2

_BVW_UNION = re.compile(r'union\s*\{([^}]*)\}\s*(sp[0-9A-Fa-f]+)\s*;')

_BVW_MEMBER = re.compile(r'^\s*(.+?)\s+(\w+)\s*(?:\[\s*(\d+)\s*\])?\s*$')

_BVW_SIZES = {'char': 1, 'signed char': 1, 'unsigned char': 1, 's8': 1, 'u8': 1,
              'short': 2, 'signed short': 2, 'unsigned short': 2, 's16': 2, 'u16': 2,
              'int': 4, 'signed int': 4, 'unsigned int': 4, 's32': 4, 'u32': 4,
              'float': 4, 'f32': 4, 'long': 4, 'signed long': 4, 'unsigned long': 4,
              'double': 8, 'f64': 8, 'long long': 8}

_BVW_DOTLHS = re.compile(r'^\s*([A-Za-z_]\w*)\.([A-Za-z_]\w*)\s*=')

_BVW_GLOBAL = re.compile(r'^\s*(lbl_[0-9A-Fa-f]+)\s*=')


def _bvw_layout(text):
    """Map union slot -> (bytes-offset, {member: size}) from in-text decls.

    Only `unsigned char bytes[N]` overlays with all preceding members of
    known scalar/pointer size count; anything else (structs, unknown
    types, bytes not present) stays out, so every returned offset is an
    exact PowerPC32 layout fact, never a guess.
    """
    out = {}
    for m in _BVW_UNION.finditer(text):
        off = 0
        members = {}
        ok = False
        for part in m.group(1).split(';'):
            part = part.strip()
            if not part:
                continue
            mm = _BVW_MEMBER.match(part)
            if not mm:
                off = None
                break
            typ, name, arr = mm.group(1).strip(), mm.group(2), mm.group(3)
            if name == 'bytes':
                if typ not in ('unsigned char', 'char', 's8', 'u8') or not arr:
                    off = None
                    break
                ok = True
                break
            if '*' in typ:
                size = 4
            else:
                base = re.sub(r'\s+', ' ', typ)
                if base not in _BVW_SIZES:
                    off = None
                    break
                size = _BVW_SIZES[base] * (int(arr) if arr else 1)
            members[name] = size
            off += size
        if ok and off is not None:
            out[m.group(2)] = (off, members)
    return out


def _bvw_mfld_range(line, layout):
    """Absolute [lo, hi) written by a single-MFLD store line, else None.

    `.bytes` bases resolve through the parsed union offset; `&sp` bases
    are direct. Temp/arg-pointer, member/arrow/subscript (non-bytes),
    call-hiding and unknown-width bases stay out.
    """
    ms = list(_DSO_MFLD.finditer(line))
    if len(ms) != 1:
        return None
    base = ms[0].group(1)
    if _DSO_CALLISH.search(base) or re.search(r'->|\[', base):
        return None
    try:
        off = _dso_off(ms[0].group(3))
        width = _dso_width(ms[0].group(2))
    except Exception:
        return None
    if off is None or width is None:
        return None
    idents = [w for w in _DSO_IDENT.findall(base)
              if w not in _MXO_TYPES and w != 'M2C_FIELD']
    others = [w for w in re.findall(r'\.([A-Za-z_]\w*)', base)
              if w != 'bytes']
    if others:
        return None
    if '.bytes' in base:
        if len(idents) != 2:
            return None
        slot = next((w for w in idents if w.startswith('sp')), None)
        if slot is None or slot not in layout:
            return None
        try:
            base_no = int(slot[2:], 16)
        except ValueError:
            return None
        lo = base_no + layout[slot][0] + off
        return (lo, lo + width)
    if len(idents) != 1 or not idents[0].startswith('sp') or '&' not in base:
        return None
    try:
        base_no = int(idents[0][2:], 16)
    except ValueError:
        return None
    return (base_no + off, base_no + off + width)


def _bvw_dot_span(line, layout):
    """(slot, member, width-or-None) written by a member-store lhs."""
    m = _BVW_DOTLHS.match(line)
    if not m or 'M2C_FIELD' in line:
        return None
    width = None
    if m.group(1) in layout:
        width = layout[m.group(1)][1].get(m.group(2))
    try:
        return (int(m.group(1)[2:], 16), m.group(2), width) \
            if m.group(1).startswith('sp') else None
    except ValueError:
        return None


def m_bytesview_order(text, cap=BVW_CAP):
    """Swap numeric-disjoint union-bytes/global member stores.

    Census (b3-unionbytes-census, 1132 real bench seed texts): 30 unique
    dep-clean store/store pairs (1058 occurrences) where one side writes
    through an `spX.bytes` union view (or a plain `&sp` MFLD) and the
    other writes a DOT member slot or a data global are taken by nobody:
    disjoint needs simple same/different roots and skips `.bytes` and
    cross-spelling pairs, member needs DOT on both sides, mixed skips
    same-kind stores, and same-li/lis pairs stay with lilcold (deferred
    below). The proof is exact PowerPC32 layout: union decls in the text
    pin the `.bytes` offset and member widths, so both written ranges are
    known and the swap fires only when they are disjoint. Guards: both
    sides store-kind, pure rhs via _dso_pure_rhs (no memory reads in the
    moved values, no calls), _mxo_dep clean, nonvolatile, no call hiding
    in the MFLD base. Unknown member widths fall back to the
    width-independent direction (MFLD range entirely below the DOT slot);
    globals live in data, stack slots on the stack, so a global side is
    always section-distinct. Own cap, near-miss-gated via the shared
    _init_shaped gate, wired last in directed(): yields are disjoint from
    every landed family's by construction (bytes-view/global cross pairs).
    """
    lines = text.split('\n')
    layout = _bvw_layout(text)
    if not layout:
        return
    vol = _mxo_volatiles(text)
    made = 0
    seen = {text}
    for i in range(len(lines) - 1):
        if made >= cap:
            return
        a, b = lines[i], lines[i + 1]
        if _mxo_mixkind(a) != 'store' or _mxo_mixkind(b) != 'store':
            continue
        ma, mb = _MXO_ASSIGN.match(a), _MXO_ASSIGN.match(b)
        if not ma or not mb:
            continue
        if not _dso_pure_rhs(ma.group(3)) or not _dso_pure_rhs(mb.group(3)):
            continue
        try:
            if {_lil_kind(a), _lil_kind(b)} == {'li', 'lis'}:
                continue
        except Exception:
            continue
        spans = []
        ok = True
        for ln in (a, b):
            if 'M2C_FIELD' in ln:
                rng = _bvw_mfld_range(ln, layout)
                if rng is None:
                    ok = False
                    break
                spans.append(('rng', rng))
            else:
                m = _BVW_DOTLHS.match(ln)
                g = _BVW_GLOBAL.match(ln)
                if m and 'M2C_FIELD' not in ln:
                    spans.append(('dot', ln))
                elif g:
                    spans.append(('glob', g.group(1)))
                else:
                    ok = False
                    break
        if not ok:
            continue
        if _mxo_dep(a, 'store', b, 'store', vol):
            continue
        if (_mxo_idents(a) | _mxo_idents(b)) & vol:
            continue
        kinds = [s[0] for s in spans]
        provable = False
        if 'glob' in kinds:
            globs = [s[1] for s in spans if s[0] == 'glob']
            if len(set(globs)) != len(globs):
                continue  # same global twice: order of writes matters
            # distinct data globals are section-distinct from stack storage
            # (write-write same-target pairs also die in _mxo_dep above)
            provable = True
        elif kinds == ['rng', 'rng']:
            (lo1, hi1), (lo2, hi2) = spans[0][1], spans[1][1]
            provable = hi1 <= lo2 or hi2 <= lo1
        elif set(kinds) == {'rng', 'dot'}:
            dot = spans[0] if spans[0][0] == 'dot' else spans[1]
            rng = spans[1][1] if spans[0][0] == 'dot' else spans[0][1]
            info = _bvw_dot_span(dot[1], layout)
            if info is None:
                continue
            slot, _, width = info
            if width is not None:
                provable = rng[1] <= slot or slot + width <= rng[0]
            else:
                provable = rng[1] <= slot
        else:
            continue  # dot+dot stays with member_order
        if not provable:
            continue
        out = lines[:]
        out[i], out[i + 1] = out[i + 1], out[i]
        cand = '\n'.join(out)
        if cand in seen:
            continue
        seen.add(cand)
        made += 1
        yield 'bytesview_order', cand

SML_CAP = 2


def m_sameload_order(text, cap=SML_CAP):
    """Swap adjacent same-source plain loads (the double-load pile).

    Census (b3-plainloadgap-census, 1132 real bench seed texts): 20 unique
    dep-clean load/load pairs where neither side is M2C_FIELD and both
    right-hand sides are textually identical (`sp28 = lbl_X; sp20 = lbl_X;`,
    1365 occurrences) are taken by nobody: plainload owns different-rhs
    pairs and pins the same-rhs skip in its tests ("useless variant"), the
    M2C_FIELD families need a macro side, and same-kind li/lis or const
    pairs stay with lilis/init. The skip is wrong for scheduling: reads
    commute and the link-time-constant/global rhs reads no state, so which
    temp the compiler materializes first follows source order (the DVD
    94.1% lfs-order class). Guards: both sides load-kind, no M2C_FIELD on
    either side (samemem/disjoint lane), textually equal rhs, no call in
    the rhs (defensive; calls never commute), _mxo_dep clean, nonvolatile.
    Own cap, near-miss-gated via the shared _init_shaped gate, wired last
    in directed(): yields are disjoint from every landed family's by
    construction (same-rhs plain loads). Deref/subscript/arrow rhs reads
    stay out even though dep-clean: reordering two `*p` reads is observable
    on undeclared-volatile MMIO, and the corpus pile is entirely lbl-rhs
    (1365/1365), so the guard costs nothing.
    """
    lines = text.split('\n')
    vol = _mxo_volatiles(text)
    made = 0
    seen = {text}
    for i in range(len(lines) - 1):
        if made >= cap:
            return
        a, b = lines[i], lines[i + 1]
        if _mxo_mixkind(a) != 'load' or _mxo_mixkind(b) != 'load':
            continue
        if 'M2C_FIELD' in a or 'M2C_FIELD' in b:
            continue
        ma, mb = _MXO_ASSIGN.match(a), _MXO_ASSIGN.match(b)
        if not ma or not mb:
            continue
        if ma.group(3).strip() != mb.group(3).strip():
            continue
        if _DSO_CALLISH.search(ma.group(3)):
            continue
        rhs = ma.group(3).replace('**', '')
        if (re.search(r'\*\s*[A-Za-z_(]', rhs) or '->' in rhs
                or re.search(r'[A-Za-z_]\w*\s*\[', rhs)):
            continue
        if _mxo_dep(a, 'load', b, 'load', vol):
            continue
        if (_mxo_idents(a) | _mxo_idents(b)) & vol:
            continue
        out = lines[:]
        out[i], out[i + 1] = out[i + 1], out[i]
        cand = '\n'.join(out)
        if cand in seen:
            continue
        seen.add(cand)
        made += 1
        yield 'sameload_order', cand

XBO_CAP = 2


def _xbo_off(s):
    return int(s, 16 if s.lstrip('-').startswith(('0x', '0X')) else 10)


def _xbo_inv(target, kind):
    seq = _sto_target_order(target) if kind == 'st' else _ldo_target_order(target)
    inv = set()
    for offs in seq.values():
        for x in range(len(offs)):
            for y in range(x + 1, len(offs)):
                if offs[x] != offs[y]:
                    inv.add((offs[y], offs[x]))
    return inv


def m_xbase_order(text, target, cap=XBO_CAP):
    """Swap adjacent same-class accesses with DIFFERENT base symbols on target inversion.

    The landed tgtorder families only fire when both lines share one base
    symbol, but real candidates mix bases (`saved_reg_r31` frame pointer vs
    `self`/arg bases) for neighboring accesses. Same offset-value evidence,
    same guards, weakest priority: same-symbol pairs stay with the landed
    families, mixed store/load pairs are skipped (unmodeled address overlap),
    and everything is capped.
    """
    sinv, linv = _xbo_inv(target, 'st'), _xbo_inv(target, 'ld')
    if not sinv and not linv:
        return
    lines = text.split('\n')
    seen = {text}
    made = 0
    for i in range(len(lines) - 1):
        if made >= cap:
            return
        if 'volatile' in lines[i] or 'volatile' in lines[i + 1]:
            continue
        if _STO_CALL.search(lines[i]) or _STO_CALL.search(lines[i + 1]):
            continue
        s1 = _STO_FIELD.match(lines[i])
        s2 = _STO_FIELD.match(lines[i + 1])
        if s1 and s2:
            if s1[2] == s2[2]:
                continue
            a, b = _xbo_off(s1[4]), _xbo_off(s2[4])
            if (a, b) not in sinv:
                continue
            r1, r2 = lines[i].split('=', 1)[1], lines[i + 1].split('=', 1)[1]
            i1, i2 = _sto_idents(r1), _sto_idents(r2)
            c1 = _STO_CHAIN.search(lines[i])
            c2 = _STO_CHAIN.search(lines[i + 1])
            if (s1[2] in i2 and s1[3] in i2) or (s2[2] in i1 and s2[3] in i1):
                continue
            if (c1 and c1[1] in i2) or (c2 and c2[1] in i1):
                continue
        else:
            l1 = _LDO_LOAD.match(lines[i])
            l2 = _LDO_LOAD.match(lines[i + 1])
            if not (l1 and l2):
                continue
            f1, f2 = _LDO_FLD.findall(l1[3]), _LDO_FLD.findall(l2[3])
            if len(f1) != 1 or len(f2) != 1 or f1[0][0] == f2[0][0]:
                continue
            a, b = _xbo_off(f1[0][2]), _xbo_off(f2[0][2])
            if (a, b) not in linv:
                continue
            if _LDO_DECLKW & (_sto_idents(l1[2]) | _sto_idents(l2[2])):
                continue
            w1, w2 = l1[2].split('[')[0].strip(), l2[2].split('[')[0].strip()
            if not w1.isidentifier() or not w2.isidentifier():
                continue
            if w1 in _sto_idents(l2[3]) or w2 in _sto_idents(l1[3]):
                continue
        out = lines[:]
        out[i], out[i + 1] = out[i + 1], out[i]
        cand = '\n'.join(out)
        if cand in seen:
            continue
        seen.add(cand)
        made += 1
        yield 'xbase_order', cand

ROT_CAP = 2


def m_rot3(text, target, cap=ROT_CAP):
    """Emit target-evidenced 3-permutations (rotations + reversal) of store triples.

    Adjacent single swaps cannot reach a 3-rotation in one variant under the
    per-parent quota (needs two sequential swaps): Voice3D__Construct 96.7%
    x,z,y field order is the adjacent case, but TerrainQuadtree__Load 95.2%
    3-addi order and deeper rotations need all three moved at once. For each
    same-struct adjacent M2C_FIELD store triple, count inversions among its 3
    offset pairs in the target stream: exactly 2 means the target holds a
    rotation (emit it), 3 means full reversal (emit it); 0-1 stay with the
    single-swap families. Every reordered pair passes the store guards.
    """
    sinv = _xbo_inv(target, 'st')
    if not sinv:
        return
    seq = _sto_target_order(target)
    lines = text.split('\n')
    seen = {text}
    made = 0
    for i in range(len(lines) - 2):
        if made >= cap:
            return
        ms = [_STO_FIELD.match(lines[i + k]) for k in range(3)]
        if not all(ms):
            continue
        if any('volatile' in lines[i + k] for k in range(3)):
            continue
        if any(_STO_CALL.search(lines[i + k]) for k in range(3)):
            continue
        if not (ms[0][2] == ms[1][2] == ms[2][2]):
            continue
        offs = [_xbo_off(ms[k][4]) for k in range(3)]
        if len(set(offs)) != 3:
            continue
        pairs = [(0, 1), (1, 2), (0, 2)]
        ninv = sum(1 for x, y in pairs if (offs[x], offs[y]) in sinv)
        if ninv == 2:
            holder = next((s for s in seq.values() if all(o in s for o in offs)), None)
            if holder is None:
                continue
            order = sorted(range(3), key=lambda k: holder.index(offs[k]))
        elif ninv == 3:
            order = [2, 1, 0]
        else:
            continue
        if order == [0, 1, 2]:
            continue
        ok = True
        rh = [lines[i + k].split('=', 1)[1] for k in range(3)]
        ih = [_sto_idents(r) for r in rh]
        ch = [_STO_CHAIN.search(lines[i + k]) for k in range(3)]
        wr = [{c[1]} if c else set() for c in ch]
        for x in range(3):
            for y in range(x + 1, 3):
                if ms[x][2] in ih[y] and ms[x][3] in ih[y]:
                    ok = False
                    break
                if ms[y][2] in ih[x] and ms[y][3] in ih[x]:
                    ok = False
                    break
                if ih[y] & wr[x] or ih[x] & wr[y]:
                    ok = False
                    break
            if not ok:
                break
        if not ok:
            continue
        out = lines[:]
        stmts = [lines[i + k] for k in order]
        for k, stmt in enumerate(stmts):
            out[i + k] = stmt
        cand = '\n'.join(out)
        if cand in seen:
            continue
        seen.add(cand)
        made += 1
        yield 'rot3', cand

LIL_CAP = 2

_LIL_ADDR = re.compile(r'^(lbl_\w+|&[A-Za-z_]\w*)$')


def _lil_target_bias(target):
    """Order of the first li vs first lis in the target: 'li' or 'lis' or None."""
    first = {}
    for w in target or []:
        op = w >> 26
        if op == 14 and ((w >> 16) & 31) == 0 and 'li' not in first:
            first['li'] = len(first)
        elif op == 15 and 'lis' not in first:
            first['lis'] = len(first)
        if len(first) == 2:
            break
    if len(first) != 2:
        return None
    return 'li' if first['li'] < first['lis'] else 'lis'


def _lil_kind(line):
    # b1 crashfix: _init_assign admits any indented `...;` line, including
    # `i++;`/`p--;` with no '=' (RigidBody__HandleCollision /
    # AvatarControls__BeginExplosionGrapple search died with IndexError,
    # zeroing both rows: live 32.3%/26.2% -> head 0.0%). Not an assignment.
    if '=' not in line:
        return None
    rhs = line.split('=', 1)[1].rsplit(';', 1)[0].strip()
    if _INIT_CONST.fullmatch(rhs):
        try:
            v = int(rhs.rstrip('uUlL'), 0)
        except ValueError:
            return None
        if -32768 <= v <= 32767:
            return 'li'
        return None
    if _LIL_ADDR.fullmatch(rhs) or 'lbl_' in rhs:
        return 'lis'
    return None


def m_lilis_order(text, target, cap=LIL_CAP):
    """Swap adjacent small-const/address init pairs to match target li/lis order.

    Spark 10:32 order-class target (Minimap__Destroy 98.4% li-vs-lis at loop
    head, App__InitializeMemoryHeaps 98.6%, LevelAlo__DeleteObject 98.7%):
    the compiler materializes `w = <small const>` with li and address inits
    with lis, and the two orders differ per function. Unlike the
    fraction-gated init-order family, each swap is directed: it fires only
    when the target's first-li-vs-lis order disagrees with ours, needs no
    gate, and respects write/read independence. Cap 2. A right-rotation
    across one intervening data line (`li,X,lis` -> `lis,li,X`) fires only
    when the trailing line already matches the target bias and both
    constituent adjacent swaps are independent, covering loop-head
    li-vs-lis orders no adjacent swap can reach (Minimap__Destroy 98.4%
    residual); rotations fill only leftover cap so established yields are
    never displaced.
    """
    bias = _lil_target_bias(target)
    if bias is None:
        return
    lines = text.split('\n')
    seen = {text}
    made = 0
    vol = _mxo_volatiles(text)
    for i in range(len(lines) - 1):
        if made >= cap:
            return
        a, b = lines[i], lines[i + 1]
        if not (_init_assign(a) and _init_assign(b)):
            continue
        ka, kb = _lil_kind(a), _lil_kind(b)
        if {ka, kb} != {'li', 'lis'}:
            continue
        ours = 'li' if ka == 'li' else 'lis'
        if ours == bias or not _init_independent(a, b):
            continue
        if vol and (_mxo_idents(a) & vol or _mxo_idents(b) & vol):
            continue
        out = lines[:]
        out[i], out[i + 1] = out[i + 1], out[i]
        cand = '\n'.join(out)
        if cand in seen:
            continue
        seen.add(cand)
        made += 1
        yield 'lilis_order', cand
    for i in range(len(lines) - 2):
        if made >= cap:
            return
        a, b, c = lines[i], lines[i + 1], lines[i + 2]
        if not (_init_assign(a) and _init_assign(b) and _init_assign(c)):
            continue
        ka, kc = _lil_kind(a), _lil_kind(c)
        if {ka, kc} != {'li', 'lis'} or kc != bias:
            continue
        if not _init_independent(b, c) or not _init_independent(a, c):
            continue
        if vol and (_mxo_idents(a) & vol or _mxo_idents(b) & vol
                    or _mxo_idents(c) & vol):
            continue
        out = lines[:]
        out[i], out[i + 1], out[i + 2] = c, a, b
        cand = '\n'.join(out)
        if cand in seen:
            continue
        seen.add(cand)
        made += 1
        yield 'lilis_order', cand

LILCOLD_CAP = 2


def m_lilcold_order(text, target, cap=LILCOLD_CAP):
    """Swap eligible li/lis pairs the directed arm stays silent on.

    Census (b3-lilcold-census, 1132 real bench seed texts): 1642 adjacent
    eligible li/lis pairs never fire under m_lilis_order whenever the
    target bias agrees with the current order or is absent (bias-None
    rows: 628/1132 seeds trigger this arm). Same guards as the directed
    arm (_init_assign both sides, kinds exactly {li, lis},
    _init_independent, volatile skip); the take-condition is the exact
    complement of the directed arm's, so the two never yield the same
    pair. Swaps identical to an m_init_order yield stay out via a lazily
    computed dup set replicating init's directed call (default cap, same
    text), so this family is disjoint from init_order too. Own cap,
    ungated like m_lilis_order, wired after the gated families in
    directed() so the init-first yield order is preserved.
    """
    bias = _lil_target_bias(target)
    lines = text.split('\n')
    seen = {text}
    made = 0
    vol = _mxo_volatiles(text)
    init_dupes = None
    for i in range(len(lines) - 1):
        if made >= cap:
            return
        a, b = lines[i], lines[i + 1]
        if not (_init_assign(a) and _init_assign(b)):
            continue
        ka, kb = _lil_kind(a), _lil_kind(b)
        if {ka, kb} != {'li', 'lis'}:
            continue
        ours = 'li' if ka == 'li' else 'lis'
        if bias is not None and ours != bias:
            continue
        if not _init_independent(a, b):
            continue
        if vol and (_mxo_idents(a) & vol or _mxo_idents(b) & vol):
            continue
        out = lines[:]
        out[i], out[i + 1] = out[i + 1], out[i]
        cand = '\n'.join(out)
        if cand in seen:
            continue
        if init_dupes is None:
            init_dupes = {c for _, c in m_init_order(text)}
        if cand in init_dupes:
            continue
        seen.add(cand)
        made += 1
        yield 'lilcold_order', cand


def m_mixed_order(text, cap=MXO_CAP):
    """Swap adjacent mixed-kind data-movement statements
    (copy/load/store/const/cond/accum/addr), plus same-kind const/const
    and accum/accum scheduling pairs.

    The landed target-evidenced families only swap same-kind pairs: stores
    with stores (store_tgtorder/xbase/rot3), loads with loads (load_tgtorder/
    xbase). The remaining 90-99% order shapes mix kinds: Exploder 95.7% is an
    `mr` temp-copy next to an `lfs` float load, Voice3D 96.7% is an `lfs`
    placed one `stfs` early (load vs store), SaveGame 91.7% is an `li`
    const materialization swapped with a neighbor (const lines were
    kind-None everywhere before). Address derivations (`t = base +/- K`,
    the addi class) join as 'addr' through the mixed-only _mxo_mixkind so
    they mix with the other six kinds: Scanf__BuildCharacterSet 96.2%
    differs only in cmpwi/mtctr/addi order before the fill loop
    (cond + accum + addr), and the TerrainQuadtree 95.2% 3-addi cluster
    sits next to non-addr neighbors; addr-addr pairs stay exclusively
    with addr_order (same-kind skip here). Addr neighbors join behind the
    established pairs in index order (stable), ahead of them only via the
    family's float-first policy when they touch float traffic. Same-kind
    const/const (`t = 2; u = 3`, the SaveGame 91.7% li-scheduling shape)
    and accum/accum (`i--; j++;`, counter scheduling) pairs belong to no
    other family, so mixed takes them when a duplicate check
    (_mxo_samepure_ok) passes, filling only cap left over by mixed-kind
    pairs; every other same-kind pair stays out. Each swap
    passes _mxo_dep (written temps never crossed, stores strict on any
    shared symbol; shared pure reads are safe); li-vs-lis pairs stay with
    lilis_order via the exact _lil_kind carve-out. General arithmetic
    (`a + b`, `a * b`), calls, volatile, decls, control, chained and
    compound assignments never classify. Near-miss-gated at the call site
    via the shared _init_shaped gate, non-overlapping run pairs first (see
    _mxo_pairs), float-involved pairs first (the convertible pile is float),
    cap 2. Odd-offset adjacent pairs the windows cannot reach pass the same
    guards and fill only leftover cap, so established yields are never
    displaced (Sound li-vs-mr / Exploder mr-vs-lfs / Voice3D lfs-vs-stfs
    class when the needed pair sits at an odd run offset).
    """
    lines = text.split('\n')
    vol = _mxo_volatiles(text)
    base = _mxo_pairs(lines)
    have = set(base)
    # Addr-involving pairs append behind the established pairs (stable
    # order; without this an addr line joining a run realigns and scrambles
    # them). The float-first sort below may still rank a float-touching addr
    # pair ahead of a non-float established pair under the cap: intended,
    # the convertible pile is float.
    extra = [p for p in _mxo_pairs(lines, _mxo_mixkind)
             if p not in have and 'addr' in (_mxo_mixkind(lines[p[0]]),
                                            _mxo_mixkind(lines[p[1]]))]
    formed = have | set(extra)
    # Odd-offset adjacent pairs the non-overlapping windows cannot reach
    # (39.9% of adjacent classifiable pairs corpus-wide): each even run
    # [a,b,c,d] yields (a,b),(c,d) but never (b,c), and odd runs miss
    # their interior odd offsets the same way. They pass the exact same
    # guards and fill only cap left over by the established pairs, so on
    # large texts (cap bound) behavior is byte-identical while small
    # 256-511B near-miss texts gain the missing first-try swaps.
    odd = []
    for i in range(len(lines) - 1):
        if (i, i + 1) in formed:
            continue
        if _mxo_mixkind(lines[i]) and _mxo_mixkind(lines[i + 1]):
            odd.append((i, i + 1))
    pairs = []
    same = []
    for i, j in base + extra:
        ka, kb = _mxo_mixkind(lines[i]), _mxo_mixkind(lines[j])
        if not ka or not kb:
            continue
        if ka == kb:
            if not _mxo_samepure_ok(lines[i], lines[j], ka):
                continue
            bucket = same
        else:
            bucket = pairs
        if {_lil_kind(lines[i]), _lil_kind(lines[j])} == {'li', 'lis'}:
            continue
        if _mxo_dep(lines[i], ka, lines[j], kb, vol):
            continue
        bucket.append(i)
    opairs = []
    osame = []
    for i, j in odd:
        ka, kb = _mxo_mixkind(lines[i]), _mxo_mixkind(lines[j])
        if ka == kb:
            if not _mxo_samepure_ok(lines[i], lines[j], ka):
                continue
            bucket = osame
        else:
            bucket = opairs
        if {_lil_kind(lines[i]), _lil_kind(lines[j])} == {'li', 'lis'}:
            continue
        if _mxo_dep(lines[i], ka, lines[j], kb, vol):
            continue
        bucket.append(i)
    # Same-kind scheduling pairs only fill cap left over by mixed-kind
    # pairs, so no established swap is displaced by the new coverage.
    pairs.extend(p for p in same if p not in pairs)
    pairs.sort(key=lambda i: not (_MXO_FLOAT.search(lines[i]) or _MXO_FLOAT.search(lines[i + 1])))
    # Odd-offset pairs sort float-first among themselves but always behind
    # every established pair: old yields are a strict prefix of new ones.
    opairs.extend(p for p in osame if p not in opairs)
    opairs.sort(key=lambda i: not (_MXO_FLOAT.search(lines[i]) or _MXO_FLOAT.search(lines[i + 1])))
    pairs.extend(p for p in opairs if p not in pairs)
    seen = {text}
    made = 0
    for i in pairs:
        if made >= cap:
            return
        out = lines[:]
        out[i], out[i + 1] = out[i + 1], out[i]
        cand = '\n'.join(out)
        if cand in seen:
            continue
        seen.add(cand)
        made += 1
        yield 'mixed_order', cand

PLO_CAP = 2


def m_plainload_order(text, cap=PLO_CAP):
    """Swap adjacent same-kind plain loads the M2C_FIELD families cannot see.

    m_load_tgtorder/xbase need `t = ...M2C_FIELD(s, ty, off)...` on both
    sides with target offset-value evidence, so plain loads never move:
    DVD__StartDriveErrorDialogThread 94.1% is two `lis`+`lfs` float-literal
    loads (`f = *(f32 *)lbl_X;`) in swapped order, and `t = *p;` / `t = p[i];`
    / `t = s->f;` pairs are likewise uncovered. Each swap needs both lines
    load-kind, a passing _mxo_dep check (same-base reads are safe: no store
    involved), and different RHS sources (same address twice is a useless
    variant). Pairs with an M2C_FIELD on both sides stay with the landed
    families (li-vs-lis pairs cannot reach here: a small-const rhs never
    classifies as a load, so lilis_order's pairs are untouched).
    Near-miss-gated at the call site via the shared _init_shaped gate,
    non-overlapping run pairs (see _mxo_pairs), float-involved pairs
    first, cap 2. Odd-offset pairs the windows cannot reach pass the same
    guards and fill only leftover cap, so established yields are never
    displaced.
    """
    lines = text.split('\n')
    vol = _mxo_volatiles(text)
    base = _mxo_pairs(lines)
    formed = set(base)
    pairs = []
    for i, j in base:
        if _mxo_kind(lines[i]) != 'load' or _mxo_kind(lines[j]) != 'load':
            continue
        if 'M2C_FIELD' in lines[i] and 'M2C_FIELD' in lines[j]:
            continue
        if _mxo_dep(lines[i], 'load', lines[j], 'load', vol):
            continue
        r1 = lines[i].split('=', 1)[1].strip()
        r2 = lines[j].split('=', 1)[1].strip()
        if r1 == r2:
            continue
        pairs.append(i)
    opairs = []
    for i in range(len(lines) - 1):
        if (i, i + 1) in formed:
            continue
        if _mxo_kind(lines[i]) != 'load' or _mxo_kind(lines[i + 1]) != 'load':
            continue
        if 'M2C_FIELD' in lines[i] and 'M2C_FIELD' in lines[i + 1]:
            continue
        if _mxo_dep(lines[i], 'load', lines[i + 1], 'load', vol):
            continue
        r1 = lines[i].split('=', 1)[1].strip()
        r2 = lines[i + 1].split('=', 1)[1].strip()
        if r1 == r2:
            continue
        opairs.append(i)
    pairs.sort(key=lambda i: not (_MXO_FLOAT.search(lines[i]) or _MXO_FLOAT.search(lines[i + 1])))
    opairs.sort(key=lambda i: not (_MXO_FLOAT.search(lines[i]) or _MXO_FLOAT.search(lines[i + 1])))
    pairs.extend(p for p in opairs if p not in pairs)
    seen = {text}
    made = 0
    for i in pairs:
        if made >= cap:
            return
        out = lines[:]
        out[i], out[i + 1] = out[i + 1], out[i]
        cand = '\n'.join(out)
        if cand in seen:
            continue
        seen.add(cand)
        made += 1
        yield 'plainload_order', cand


def m_addr_order(text, cap=ADR_CAP):
    """Swap adjacent address-arithmetic inits (`t = base +/- K`, the addi class).

    TerrainQuadtree__Load 95.2% is three `addi` pointer derivations in an
    order no family moves: init_order permutes const-vs-address groups but
    keeps within-group order, lilis_order needs a li-vs-lis pair, and the
    copy/load/store families never classify pure address arithmetic (the
    Scanf__BuildCharacterSet 96.2% loop-prologue `addi` is the same shape).
    Each swap needs write/read independence both directions (the shared base
    symbol is allowed: same-base derivations are the target shape; a temp
    written by one side and read by the other still blocks). Pure scheduling
    only: values are never rescaled (b1 owns pointer-step rescaling).
    Near-miss-gated at the call site via the shared _init_shaped gate,
    non-overlapping run pairs (see _mxo_pairs), cap 2.
    """
    lines = text.split('\n')
    pairs = []
    for i, j in _mxo_pairs(lines, _adr_kind):
        if not _init_independent(lines[i], lines[j]):
            continue
        pairs.append(i)
    seen = {text}
    made = 0
    for i in pairs:
        if made >= cap:
            return
        out = lines[:]
        out[i], out[i + 1] = out[i + 1], out[i]
        cand = '\n'.join(out)
        if cand in seen:
            continue
        seen.add(cand)
        made += 1
        yield 'addr_order', cand

CPY_CAP = 2


def m_samecopy_order(text, cap=CPY_CAP):
    """Swap adjacent independent temp copies (`t1 = u1; t2 = u2`).

    The remaining same-kind gap: loads pair in plainload_order, M2C stores
    in the landed families, address derivations in addr_order, but temp-copy
    definition order belongs to nobody, and it drives register coloring
    (AvatarMovement__ResetState 94.1% r9-vs-r10 for the 3rd vcall state
    ptr). Copies are register-only, so the _mxo_dep temp-crossing check is
    fully sound here with no memory caveat. Plain store pairs stay out
    deliberately (write-write aliasing is unprovable). Near-miss-gated at
    the call site via the shared _init_shaped gate, non-overlapping run
    pairs (see _mxo_pairs), cap 2. Odd-offset copy-copy pairs the windows
    cannot reach pass the same guards and fill only leftover cap, so
    established yields are never displaced.
    """
    lines = text.split('\n')
    base = _mxo_pairs(lines)
    formed = set(base)
    pairs = []
    for i, j in base:
        if _mxo_kind(lines[i]) != 'copy' or _mxo_kind(lines[j]) != 'copy':
            continue
        if _mxo_dep(lines[i], 'copy', lines[j], 'copy'):
            continue
        pairs.append(i)
    for i in range(len(lines) - 1):
        if (i, i + 1) in formed:
            continue
        if _mxo_kind(lines[i]) != 'copy' or _mxo_kind(lines[i + 1]) != 'copy':
            continue
        if _mxo_dep(lines[i], 'copy', lines[i + 1], 'copy'):
            continue
        pairs.append(i)
    seen = {text}
    made = 0
    for i in pairs:
        if made >= cap:
            return
        out = lines[:]
        out[i], out[i + 1] = out[i + 1], out[i]
        cand = '\n'.join(out)
        if cand in seen:
            continue
        seen.add(cand)
        made += 1
        yield 'samecopy_order', cand


def m_callmove_order(text, cap=CMV_CAP):
    """Swap a pure temp materialization across an adjacent independent call.

    Call-temporal scheduling belongs to nobody: every family leaves call
    lines fixed, so `t = u; foo(a);` vs `foo(a); t = u;` (mr-vs-bl order,
    the Breakable final-vcall / AvatarMovement vcall neighborhood) is
    unreachable. Only copy/const lines move (pure register traffic, never
    memory), and only when provably independent of the call: no shared
    significant ident either direction, none of the moved idents
    address-taken anywhere in the text, none volatile-declared. Control
    (return/goto/...) never participates (moves past it only degrade into
    dead code). Near-miss-gated at the call site via the shared _init_shaped
    gate, non-overlapping run pairs over the union of call/copy/const
    lines, cap 2. Odd seq-adjacencies the windows cannot reach pass the
    same guards and fill only leftover cap, so established yields are
    never displaced.
    """
    lines = text.split('\n')
    taken = set(_CMV_TAKEN.findall(text))
    vol = set(_CMV_VOLDECL.findall(text))
    seq = [i for i, l in enumerate(lines)
           if _cmv_callside(l) or _mxo_kind(l) in ('copy', 'const')]
    windows = [(seq[k], seq[k + 1]) for k in range(0, len(seq) - 1, 2)]
    if len(seq) >= 3 and len(seq) % 2 == 1:
        windows.append((seq[-2], seq[-1]))
    formed = set(windows)
    pairs = []
    for i, j in windows:
        if j != i + 1:
            continue
        ki, kj = _mxo_kind(lines[i]), _mxo_kind(lines[j])
        if ki in ('copy', 'const') and kj not in ('copy', 'const'):
            mover, other = i, j
        elif kj in ('copy', 'const') and ki not in ('copy', 'const'):
            mover, other = j, i
        else:
            continue
        if not _cmv_callside(lines[other]):
            continue
        if _mxo_idents(lines[mover]) & _mxo_idents(lines[other]):
            continue
        if _mxo_idents(lines[mover]) & (taken | vol):
            continue
        pairs.append(i)
    for k in range(len(seq) - 1):
        i, j = seq[k], seq[k + 1]
        if (i, j) in formed:
            continue
        if j != i + 1:
            continue
        ki, kj = _mxo_kind(lines[i]), _mxo_kind(lines[j])
        if ki in ('copy', 'const') and kj not in ('copy', 'const'):
            mover, other = i, j
        elif kj in ('copy', 'const') and ki not in ('copy', 'const'):
            mover, other = j, i
        else:
            continue
        if not _cmv_callside(lines[other]):
            continue
        if _mxo_idents(lines[mover]) & _mxo_idents(lines[other]):
            continue
        if _mxo_idents(lines[mover]) & (taken | vol):
            continue
        if i in pairs:
            continue
        pairs.append(i)
    seen = {text}
    made = 0
    for i in pairs:
        if made >= cap:
            return
        out = lines[:]
        out[i], out[i + 1] = out[i + 1], out[i]
        cand = '\n'.join(out)
        if cand in seen:
            continue
        seen.add(cand)
        made += 1
        yield 'callmove', cand

MBR_CAP = 2

_MBR_LANE = re.compile(r'\.v\d+\b')

_MBR_STORE = re.compile(r'^(\s*)([A-Za-z_]\w*)\.([A-Za-z_]\w*)\s*=\s*(.+);\s*$')

_MBR_LOAD = re.compile(r'^(\s*)([A-Za-z_]\w*)\s*=\s*([A-Za-z_]\w*)\.([A-Za-z_]\w*)\s*;\s*$')

_MBR_BITFIELD = re.compile(r':\s*\d')


def _mbr_op(line):
    """(base, field, is_store, temp) for exact member-store/load lines."""
    m = _MBR_STORE.match(line)
    if m:
        return (m.group(2), m.group(3), True, None)
    m = _MBR_LOAD.match(line)
    if m:
        return (m.group(3), m.group(4), False, m.group(2))
    return None


def _mbr_layout_ok(text, base):
    """True iff base provably names a struct object without bitfields.

    Same-base different-field stores are disjoint only for real structs:
    union members overlap and bitfields can share a word. Resolve from
    in-text evidence (direct `struct {...} base;` or a `typedef struct`
    name); anything else (unions, bitfields, unknown/elsewhere-defined
    types, parameters) stays fixed.
    """
    b = re.escape(base)
    m = re.search(r'\b(struct|union)\s*\{([^}\n]*)\}\s*' + b + r'\b', text)
    if m:
        return m.group(1) == 'struct' and not _MBR_BITFIELD.search(m.group(2))
    m = re.search(r'^\s*([A-Za-z_]\w*)\s+' + b + r'\b\s*(?:\[[^\];]*\])?\s*(?:=[^;]*)?;\s*$',
                  text, re.M)
    if not m or m.group(1) in ('struct', 'union'):
        return False
    t = re.search(r'typedef\s+(struct|union)\s*\{([^}]*)\}\s*' + re.escape(m.group(1)) +
                  r'\s*;', text)
    if not t:
        return False
    return t.group(1) == 'struct' and not _MBR_BITFIELD.search(t.group(2))


def _mbr_bare(line, base):
    """Base appears outside `base.` member access."""
    return bool(re.search(r'\b' + re.escape(base) + r'\b(?!\s*\.)', line))


def m_member_order(text, cap=MBR_CAP):
    """Swap adjacent same-struct different-field member accesses.

    The M2C_FIELD-only order families never see plain member traffic, yet it
    is pervasive (6600+ same-base store pairs in bench seeds), including the
    vec3-lane shape (`sp.v0/v1/v2`, the Voice3D x,z,y class) via in-text
    `typedef struct` lanes, and member load/store neighbors (`a = s.f` next
    to `s.g = b`, the lfs-vs-stfs class) that mixed_order cannot take (the
    shared base trips its store-strict rule). Each swap needs the same base,
    different fields, load/load pairs excluded (plainload owns them), no
    field, temp or bare-base crossover either direction, no volatile touch
    (a store is always involved), and in-text proof the base is a
    bitfield-free struct (unions, bitfields, unknown types stay fixed).
    Different-base pairs stay out (sound but unevidenced). Near-miss-gated
    at the call site via the shared _init_shaped gate, non-overlapping run
    pairs, cap 2. Odd-offset pairs the windows cannot reach pass the same
    guards and fill only leftover cap, so established yields are never
    displaced.
    """
    lines = text.split('\n')
    vol = _mxo_volatiles(text)
    base = _mxo_pairs(lines)
    formed = set(base)
    pairs = []
    for i, j in base:
        a, b = lines[i], lines[j]
        s1, s2 = _mbr_op(a), _mbr_op(b)
        if not (s1 and s2):
            continue
        (b1, f1, st1, t1), (b2, f2, st2, t2) = s1, s2
        if b1 != b2 or f1 == f2:
            continue
        if not (st1 or st2):
            continue
        base = b1
        if re.search(r'\b' + re.escape(base) + r'\.' + re.escape(f1) + r'\b', b):
            continue
        if re.search(r'\b' + re.escape(base) + r'\.' + re.escape(f2) + r'\b', a):
            continue
        if t1 and re.search(r'\b' + re.escape(t1) + r'\b', b):
            continue
        if t2 and re.search(r'\b' + re.escape(t2) + r'\b', a):
            continue
        if _mbr_bare(a, base) or _mbr_bare(b, base):
            continue
        if vol and (_mxo_idents(a) & vol or _mxo_idents(b) & vol):
            continue
        if not _mbr_layout_ok(text, base):
            continue
        pairs.append(i)
    opairs = []
    for i in range(len(lines) - 1):
        if (i, i + 1) in formed:
            continue
        a, b = lines[i], lines[i + 1]
        s1, s2 = _mbr_op(a), _mbr_op(b)
        if not (s1 and s2):
            continue
        (b1, f1, st1, t1), (b2, f2, st2, t2) = s1, s2
        if b1 != b2 or f1 == f2:
            continue
        if not (st1 or st2):
            continue
        base = b1
        if re.search(r'\b' + re.escape(base) + r'\.' + re.escape(f1) + r'\b', b):
            continue
        if re.search(r'\b' + re.escape(base) + r'\.' + re.escape(f2) + r'\b', a):
            continue
        if t1 and re.search(r'\b' + re.escape(t1) + r'\b', b):
            continue
        if t2 and re.search(r'\b' + re.escape(t2) + r'\b', a):
            continue
        if _mbr_bare(a, base) or _mbr_bare(b, base):
            continue
        if vol and (_mxo_idents(a) & vol or _mxo_idents(b) & vol):
            continue
        if not _mbr_layout_ok(text, base):
            continue
        opairs.append(i)
    pairs.sort(key=lambda i: (not (_MBR_LANE.search(lines[i]) or _MBR_LANE.search(lines[i + 1])),
                               not (_MXO_FLOAT.search(lines[i]) or _MXO_FLOAT.search(lines[i + 1]))))
    opairs.sort(key=lambda i: (not (_MBR_LANE.search(lines[i]) or _MBR_LANE.search(lines[i + 1])),
                                not (_MXO_FLOAT.search(lines[i]) or _MXO_FLOAT.search(lines[i + 1]))))
    pairs.extend(p for p in opairs if p not in pairs)
    seen = {text}
    made = 0
    for i in pairs:
        if made >= cap:
            return
        out = lines[:]
        out[i], out[i + 1] = out[i + 1], out[i]
        cand = '\n'.join(out)
        if cand in seen:
            continue
        seen.add(cand)
        made += 1
        yield 'member_order', cand

DEC_CAP = 2


def _dec_bare(line):
    """True for a bare declaration (no initializer): layout-only, no code."""
    return bool(_INIT_DECL.match(line) or _INIT_AGGDECL.match(line))


def m_decl_order(text, cap=DEC_CAP):
    """Swap adjacent bare declarations (`int a; int b;`).

    Bare decls emit no code, so swapping two adjacent ones only changes
    stack layout (slot offsets) — always sound (no values exist yet, and
    adjacency means no use can slip between them). The docstrings already
    reference this family for decl-decl swaps but it was never built, and
    two rows implicate layout (SphereAnimSet decl-order-fixed, HUD's
    144 decl/store perms). Initialized decls never move (their init store
    has ordering semantics). Near-miss-gated at the call site via the
    shared _init_shaped gate, non-overlapping decl runs, cap 2.
    """
    lines = text.split('\n')
    pairs = []
    for i, j in _mxo_pairs(lines, _dec_bare):
        pairs.append(i)
    seen = {text}
    made = 0
    for i in pairs:
        if made >= cap:
            return
        out = lines[:]
        out[i], out[i + 1] = out[i + 1], out[i]
        cand = '\n'.join(out)
        if cand in seen:
            continue
        seen.add(cand)
        made += 1
        yield 'decl_order', cand
