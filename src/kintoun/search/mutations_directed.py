"""Score-directed orchestration, SDA/frame/extern relocation guards, and fast local-merge/inline adapters."""
from kintoun.search.repairs import hypotheses
import itertools
import re
from kintoun.search.mutations_recovery import m_index_address, m_narrow_return
from kintoun.search.mutations_order_reg import (
    _init_shaped,
    m_cho_midfirst,
    m_constarg_hoist,
    m_disjoint_order,
    m_fregcopy,
    m_init_order,
    m_load_tgtorder,
    m_regcopy,
    m_spillsched_order,
    m_store_tgtorder,
)
from kintoun.search.mutations_order_stmt import (
    m_addr_order,
    m_bytesview_order,
    m_calladdr_order,
    m_callmove_order,
    m_callpure_order,
    m_cholit_order,
    m_decl_order,
    m_lilcold_order,
    m_lilis_order,
    m_member_order,
    m_mixed_order,
    m_plainload_order,
    m_rot3,
    m_samecopy_order,
    m_sameload_order,
    m_samemem_order,
)
from kintoun.search.mutations_mem import (
    m_alias_sink,
    m_fmem_hop,
    m_fmem_order,
    m_globalcache,
    m_loadhoist_order,
    m_ptrstep_rescale,
)
from kintoun.search.mutations_switch import m_case_order, m_caseswap_order, m_switch_lower

STARTPERM_CAP = 6


def m_startperm(texts, cap=STARTPERM_CAP):
    """Order/reg permutation variants of seed starts (Spark 11:46 direction).

    The 90-99% order pile (Minimap li/lis, Sound li-vs-mr, Exploder 2-insn
    swap, DVD lfs order, Avatar r9/r10) needs scheduling variants EVALUATED,
    not just generatable: under the compile cap the search grinds ~50-90
    draft variants before directed() moves surface. The text-only order
    families (init/constarg/mixed/plainload/member/samecopy/addr/callmove)
    need no
    score, so their first yields become early extra seeds next to b4's
    rebased/swap-union starters. Bounded (cap total across the given texts),
    deduped against the inputs, family priority matches directed() order.
    """
    fams = (m_init_order, m_constarg_hoist, m_mixed_order, m_plainload_order,
            m_member_order, m_samecopy_order, m_addr_order, m_callmove_order,
            m_decl_order)
    seen = set(texts)
    made = 0
    for text in texts:
        for fam in fams:
            try:
                for _, cand in fam(text):
                    if cand in seen:
                        continue
                    seen.add(cand)
                    made += 1
                    yield 'startperm', cand
                    if made >= cap:
                        return
            except (AttributeError, TypeError, ValueError, IndexError):
                continue


def directed(text,score,book,base,cfg):
    """Repairs use actual relocated instructions, preserving the original as a search alternative."""
    ours=[word&0xffffffff for word in score.ours]
    ops=score.ops
    # Target-backed store swaps need no fraction gate: every variant is
    # evidenced by an observed target inversion, so they go first.
    for family, candidate in m_store_tgtorder(text, score.target):
        yield family, candidate
    for family, candidate in m_load_tgtorder(text, score.target):
        yield family, candidate
    for family, candidate in m_regcopy(text, score.target, ours):
        yield family, candidate
    for family, candidate in m_fregcopy(text, score.target, ours):
        yield family, candidate
    for family, candidate in m_globalcache(text, score.target, ours):
        yield family, candidate
    for family, candidate in m_rot3(text, score.target):
        yield family, candidate
    for family, candidate in m_lilis_order(text, score.target):
        yield family, candidate
    for family, candidate in m_ptrstep_rescale(text, score.target):
        yield family, candidate
    try:
        initorder = _init_shaped(score, len(ours), len(score.target))
    except (AttributeError, TypeError, ValueError):
        initorder = False
    if initorder:
        # Per-parent directed quota usually compiles only the prefix, so
        # near-miss init-order variants go first; repairs still flow for every
        # other parent shape and on later rounds via tried_from.
        for family, candidate in m_init_order(text):
            yield family, candidate
        for family, candidate in m_constarg_hoist(text):
            yield family, candidate
        for family, candidate in m_mixed_order(text):
            yield family, candidate
        for family, candidate in m_plainload_order(text):
            yield family, candidate
        for family, candidate in m_addr_order(text):
            yield family, candidate
        for family, candidate in m_samecopy_order(text):
            yield family, candidate
        for family, candidate in m_member_order(text):
            yield family, candidate
        for family, candidate in m_decl_order(text):
            yield family, candidate
        for family, candidate in m_callmove_order(text):
            yield family, candidate
        for family, candidate in m_cho_midfirst(text):
            yield family, candidate
        for family, candidate in m_disjoint_order(text):
            yield family, candidate
        for family, candidate in m_spillsched_order(text):
            yield family, candidate
        for family, candidate in m_calladdr_order(text):
            yield family, candidate
        for family, candidate in m_callpure_order(text):
            yield family, candidate
        for family, candidate in m_cholit_order(text):
            yield family, candidate
        for family, candidate in m_samemem_order(text):
            yield family, candidate
        for family, candidate in m_sameload_order(text):
            yield family, candidate
        for family, candidate in m_bytesview_order(text):
            yield family, candidate
        for family, candidate in m_caseswap_order(text):
            yield family, candidate
        for family, candidate in m_loadhoist_order(text):
            yield family, candidate
        for family, candidate in m_alias_sink(text):
            yield family, candidate
    # Cold li/lis arm: ungated like m_lilis_order (bias-absent rows never
    # open the gate), but wired after the gated families so the
    # init-first yield order pinned by test_directed_yields_init_order_first
    # is preserved.
    for family, candidate in m_lilcold_order(text, score.target):
        yield family, candidate
    ours=[word&0xffffffff for word in score.ours]
    ops=score.ops
    unknown=getattr(score,'unresolved',{})
    if unknown:
        pairs=[]
        for tag,i1,i2,j1,j2 in (ops or [('equal',0,len(ours),0,len(score.target))]):
            if tag in ('equal','replace'):
                pairs.extend(('equal',i1+k,i1+k+1,j1+k,j1+k+1) for k in range(min(i2-i1,j2-j1)) if i1+k not in unknown)
        ops=pairs
        if not ops:return
    repairs=hypotheses(ours,score.target,text,base,book.functions and {a:n for a,(n,_) in book.functions.items()},
                       book.objects,cfg['sda_r13'],cfg['sda_r2'],ops,limit=32)
    # b4: a permuted / transposed field layout (twin WorldToLocal vs LocalToWorld)
    # needs every offset pair at once; one at a time each step may not improve.
    pairs={r['ours']:r['target'] for r in repairs if r['category'] in ('field_offset','offset')
           and isinstance(r.get('ours'),int) and isinstance(r.get('target'),int)}
    if len(pairs)>=2:
        candidate=_remap_offsets(text,pairs)
        if candidate and candidate!=text:yield 'target_offset',candidate
    for repair in repairs:
        category=repair['category']
        if category=='global':
            target=repair['target_symbol']
            if not re.fullmatch(r'\w+',target):continue
            for declaration in re.finditer(r'^extern [^;\n]*\b(\w+)\s*(?:__attribute__[^;]*)?;',text,re.M):
                name=declaration[1]
                try:address=book.address(name)
                except ValueError:continue
                if address==int(repair['ours'],16):
                    yield 'target_global',re.sub(r'\b'+re.escape(name)+r'\b',target,text)
        elif category=='callee':
            target=repair['target']
            if not re.fullmatch(r'\w+',target):continue
            try:old_address=book.address(repair['ours'])
            except ValueError:continue
            for match in re.finditer(r'\b(\w+)\s*\(',text):
                name=match[1]
                try:address=book.address(name)
                except ValueError:continue
                if address==old_address:
                    yield 'target_callee',re.sub(r'\b'+re.escape(name)+r'\b',target,text)
        elif category=='literal' and repair.get('suggested_edit'):
            edit=repair['suggested_edit'];yield 'target_literal',text.replace(edit['old'],edit['new'],1)
        elif category in ('field_offset','offset'):
            old,new=repair['ours'],repair['target']
            for match in re.finditer(r'M2C_FIELD\(\w+,\s*[\w *]+,\s*(0x[\da-fA-F]+|\d+)\)',text):
                if int(match[1],0)==old:
                    yield 'target_offset',text[:match.start(1)]+hex(new)+text[match.end(1):]
            # b4: matched-src (twin) spelling of a field: (char *)x + 40
            for match in re.finditer(r'\(char \*\)\s*\(?\w+\)?\s*\+\s*(0x[\da-fA-F]+|\d+)\)',text):
                if int(match[1],0)==old:
                    yield 'target_offset',text[:match.start(1)]+(hex(new) if match[1].startswith('0x') else str(new))+text[match.end(1):]
    indexed=any(w>>26==31 and (w>>1)&1023 in (23,55,87,119,151,183,279,343,535,567,599,631,663,695,727) for w in score.target)
    if indexed:yield from m_index_address(text)
    if any(w>>26==31 and (w>>1)&1023==922 for w in score.target):yield from m_narrow_return(text)
    if 'switch (' in text or 'switch(' in text:yield from m_case_order(text)
    if 'switch (' in text or 'switch(' in text:yield from m_switch_lower(text)
    if '.v' in text or 'M2C_FIELD' in text:yield from m_fmem_order(text)
    if '.v' in text or 'M2C_FIELD' in text:yield from m_fmem_hop(text)


def _frame_size(words):
    for w in words[:10]:
        if w >> 26 == 37 and (w >> 21) & 31 == 1 and (w >> 16) & 31 == 1:
            offset = w & 0xffff
            return 0x10000 - offset if offset & 0x8000 else None
    return None

_UNION_BYTES = re.compile(r'^( +union \{[^}\n]*\bbytes\[)(\d+)(\]; \} (?:unk)?sp[0-9A-Fa-f]+;)', re.M)

_SDA_EXTERN=re.compile(r'^(extern [^;\n]*?\b([A-Za-z_]\w*))( __attribute__\(\(section\("\.\w+"\)\)\))?;$',re.M)


def sda_guard(text, book, r13, r2):
    """b4: an extern scalar whose address lies outside both SDA21 windows
    (r13/r2 +-32K) can never be reached r13/r2-relative, yet without a
    section the compiler treats it as small data and emits an unresolvable
    SDA21 relocation (the base global_section family strips the attribute;
    86/1086 bench results ended exactly so). Such declarations keep .data."""
    def far(name):
        try:address=book.address(name)
        except (ValueError,AttributeError):return False
        return not any(base-0x8000<=address<=base+0x7fff for base in (r13,r2))
    def fix(match):
        if match[3] or '(' in match[1] or '[' in match[1] or not far(match[2]):return match[0]
        return match[1]+' __attribute__((section(".data")));'
    return _SDA_EXTERN.sub(fix,text)


def _remap_offsets(text, pairs):
    """Rewrite every field offset in `pairs` (old -> new, bytes) in one pass:
    M2C_FIELD(x, T, K), (char *)x + K, and name[k] on 4-byte element pointers."""
    sig = re.search(r'^[^\n;#]*\b\w+\s*\(([^{};]*)\)\s*\{', text, re.M)
    if not sig:
        return None
    four = set(re.findall(r'\b(?:f32|s32|u32|float|int)\s*\*\s*(\w+)', text))
    def field(m):
        old = int(m[2], 0)
        return m[1] + hex(pairs[old]) + m[3] if old in pairs else m[0]
    out = re.sub(r'(M2C_FIELD\(\w+,\s*[\w *]+,\s*)(0x[\da-fA-F]+|\d+)(\))', field, text)
    out = re.sub(r'(\(char \*\)\s*\(?\w+\)?\s*\+\s*)(0x[\da-fA-F]+|\d+)(\))', field, out)
    def index(m):
        if m[1] not in four:
            return m[0]
        old = int(m[2], 0) * 4
        return f'{m[1]}[{pairs[old] // 4}]' if old in pairs and pairs[old] % 4 == 0 else m[0]
    return re.sub(r'\b(\w+)\[(0x[\da-fA-F]+|\d+)\]', index, out)


def frame_unions(text, score, limit=2):
    """b4: m2c stack objects are `union { ...; unsigned char bytes[N]; } spX;`.
    mt_target.stack_arrays only resizes plain arrays, so a frame-size mismatch
    against the target is never repaired for these. Resize one union by the
    exact stwu delta (largest union first, then the last-declared one)."""
    current, desired = _frame_size(score.ours or []), _frame_size(score.target or [])
    if current is None or desired is None or current == desired:
        return
    delta = desired - current
    unions = list(_UNION_BYTES.finditer(text))
    if not unions:
        # No stack object to grow: a volatile pad keeps its slot (a plain
        # unused array is dropped by the compiler) and takes up the delta.
        if delta > 0 and delta % 4 == 0:
            signature = re.search(r'^[^\n;#]*\b\w+\s*\([^{};]*\)\s*\{', text, re.M)
            if signature and 'mt_pad[' not in text:
                yield 'frame_union', (text[:signature.end()] + f'\n    volatile s32 mt_pad[{delta // 4}];'
                                      + text[signature.end():])
        return
    order = sorted(unions, key=lambda m: -int(m[2]))[:2] + unions[-1:]
    seen = set()
    for match in order:
        size = int(match[2]) + delta
        if size < 4 or size > 65536 or match.start() in seen:
            continue
        seen.add(match.start())
        yield 'frame_union', text[:match.start(2)] + str(size) + text[match.end(2):]
        if len(seen) >= limit:
            return

_C_ESCAPES = {'n': 10, 't': 9, 'r': 13, '0': 0, '\\': 92, '"': 34, "'": 39}


def _c_string_bytes(body):
    out, i = bytearray(), 0
    while i < len(body):
        c = body[i]
        if c == '\\' and i + 1 < len(body):
            n = body[i + 1]
            if n == 'x':
                j = i + 2
                while j < len(body) and body[j] in '0123456789abcdefABCDEF': j += 1
                out.append(int(body[i + 2:j], 16) & 0xff); i = j; continue
            if n in '01234567' and n != '0' or (n == '0' and i + 2 < len(body) and body[i + 2] in '01234567'):
                j = i + 1
                while j < len(body) and j < i + 4 and body[j] in '01234567': j += 1
                out.append(int(body[i + 1:j], 8) & 0xff); i = j; continue
            out.append(_C_ESCAPES.get(n, ord(n))); i += 2; continue
        out.append(ord(c)); i += 1
    return bytes(out)


def extern_relocs(text, score, target_refs, read):
    """b4 (Spark 10:35): data the source defines itself - a string literal or a
    static variable - has no identity in the target's link (strict verify:
    '.rodata: no exact constant placement' / '.sdata: automatic placement'),
    so a match can never resolve. The target's own instruction at each
    unresolved position names the real object: a string literal becomes the
    extern whose bytes equal it; a static becomes the extern at the target's
    address (each one-to-one pairing is offered as a variant)."""
    unresolved = getattr(score, 'unresolved', None) or {}
    # A named global the link cannot place (e.g. SDA21 out of r13/r2 range):
    # the target's instruction at that position gives the intended object.
    renamed = text
    for k, message in unresolved.items():
        named = re.match(r'(lbl_[0-9A-Fa-f]{8})#\d+: SDA', str(message))
        address = target_refs.get(4 * int(k))
        if not named or address is None: continue
        symbol = f'lbl_{address:08X}'
        if symbol != named[1] and re.search(r'\b' + named[1] + r'\b', renamed):
            renamed = re.sub(r'\b' + named[1] + r'\b', symbol, renamed)
    if renamed != text:
        yield 'extern_reloc', renamed
    # Only source-defined data; 'ambiguous constant placement' is the linker's
    # placement problem (place-resolve), not a missing identity.
    keys = [int(k) for k in unresolved
            if re.search(r'no exact constant placement|automatic placement', str(unresolved[k]))]
    addresses, data_addresses = [], []
    for k in sorted(keys):
        address = target_refs.get(4 * k)
        if address is None: continue
        bucket = data_addresses if 'automatic placement' in str(unresolved[k]) else addresses
        if address not in bucket: bucket.append(address)
    if not addresses and not data_addresses:
        return
    out = text
    for match in sorted(set(re.findall(r'(?<!section\()"((?:[^"\\\n]|\\.)*)"', text)), key=len, reverse=True):
        want = _c_string_bytes(match) + b'\0'
        for address in addresses:
            try:
                if (read(address, len(want)) or b'') == want:
                    symbol = f'lbl_{address:08X}'
                    out = out.replace(f'"{match}"', symbol)
                    if f'extern char {symbol}[];' not in out:
                        out = f'extern char {symbol}[];\n' + out
                    break
            except Exception:
                continue
    # Literals whose bytes match no target object (e.g. " " where the target
    # string is "\t"): pair them in order of use with the unpaired target
    # addresses that hold a NUL-terminated string.
    used = {int(m, 16) for m in re.findall(r'\blbl_([0-9A-F]{8})\b', out)}
    spare = [x for x in addresses if x not in used and _is_c_string(read, x)]
    left = [m for m in re.findall(r'(?<!section\()"((?:[^"\\\n]|\\.)*)"', out)]
    left = list(dict.fromkeys(left))
    if spare and left and len(left) == len(spare):
        for literal, address in zip(left, spare):
            symbol = f'lbl_{address:08X}'
            out = out.replace(f'"{literal}"', symbol, 1)
            if f'extern char {symbol}[];' not in out:
                out = f'extern char {symbol}[];\n' + out
    if out != text:
        yield 'extern_reloc', _hoist_externs(out)
        text = out
    statics = re.findall(r'^\s*static\s+((?:volatile\s+|const\s+)*[A-Za-z_][\w ]*?)\s+(\**)\s*([A-Za-z_]\w*)\s*(\[[^\]]*\])?\s*(?:=\s*[^;]*)?;', text, re.M)
    statics = [s for s in statics if '(' not in s[0]]
    if not statics or len(statics) > 3:
        return
    import itertools
    # Statics pair only with small-data objects (.sdata/.sbss automatic
    # placement); rodata misses are compiler constants, not source statics.
    if len(data_addresses) < len(statics):
        return
    for perm in itertools.islice(itertools.permutations(data_addresses, len(statics)), 6):
        new = text
        for (kind, stars, name, array, ), address in zip(statics, perm):
            symbol = f'lbl_{address:08X}'
            new = re.sub(r'^\s*static\s+[^;\n]*\b' + re.escape(name) + r'\b[^;\n]*;[ \t]*\n', '', new, count=1, flags=re.M)
            new = re.sub(r'\b' + re.escape(name) + r'\b', symbol, new)
            new = f'extern {kind} {stars}{symbol}{array};\n' + new
        if new != text:
            yield 'extern_reloc', _hoist_externs(new)


def _is_c_string(read, address, limit=64):
    try:
        data = read(address, limit)
    except Exception:
        return False
    if not data:
        return False
    end = data.find(b'\0')
    return end >= 1 and all(32 <= b < 127 or b in (9, 10, 13) for b in data[:end])


def _hoist_externs(text):
    """Keep the typedef/#define prelude first: move added externs after it."""
    lines = text.split('\n')
    added = [l for l in lines if re.match(r'^extern [^;]*\blbl_[0-9A-F]{8}\b', l)]
    rest = [l for l in lines if l not in added]
    last = max((i for i, l in enumerate(rest) if l.startswith(('typedef', '#define'))), default=-1)
    return '\n'.join(rest[:last + 1] + list(dict.fromkeys(added)) + rest[last + 1:])

_WORD = re.compile(r'\w+')


def var_merge_fast(base):
    """b4: mt_mut.m_var_merge with one identifier index per call instead of a
    `\\bv\\b` regex per (local, line): expand_seeds closes over var_merge up to
    40 times per seed, and on 3 KB+ functions (~200 locals x 1000 lines) the
    span scan alone took 28.6 of a 25 s budget before the first compile.
    Local names are pure \\w runs, so `\\bv\\b` matches a line exactly when v is
    one of its maximal \\w tokens; yields are identical to the original."""
    import mt_mut

    def m_var_merge(t):
        lines, s, e = mt_mut.body_range(t)
        decls = {}
        for i in range(s, e):
            m = mt_mut.DECL.match(lines[i])
            if m and not m[5]: decls[m[4].strip()] = (i, (m[3].strip()))
        where = {}
        for i in range(s, e):
            for token in set(_WORD.findall(lines[i])):
                if token in decls: where.setdefault(token, []).append(i)
        def span(v):
            us = [i for i in where.get(v, ()) if i != decls[v][0]]
            return (min(us), max(us)) if us else None
        spans = {v: span(v) for v in decls}
        names = [v for v in decls if spans[v]]
        stem = lambda v: re.sub(r'_\d+$', '', v)
        pairs = []
        for x, a in enumerate(names):
            for b in names[x + 1:]:
                if decls[a][1] != decls[b][1]: continue
                sa, sb = spans[a], spans[b]
                first, second = (a, b) if sa[0] <= sb[0] else (b, a)
                sf, ss = spans[first], spans[second]
                ok = sf[1] < ss[0] or (sf[1] == ss[0] and re.match(r' +' + re.escape(second) + r' = ', lines[ss[0]]) is not None)
                if ok:
                    pairs.append((0 if stem(a) == stem(b) else 1, a, b))
        pairs.sort()
        for _, a, b in pairs[:12]:
            keep, drop = (a, b) if spans[a][0] < spans[b][0] else (b, a)
            out = [re.sub(r'\b' + re.escape(drop) + r'\b', keep, l) if i != decls[drop][0] else None for i, l in enumerate(lines)]
            yield 'var_merge', '\n'.join(l for l in out if l is not None)

    m_var_merge.__doc__ = base.__doc__
    m_var_merge.__name__ = base.__name__
    return m_var_merge


def temp_merge_fast(base):
    """b4: mt_mut.m_temp_merge rewriting only the lines that can change.
    Each yield re.sub'd every line of the text (1466 yields x ~1000 lines on a
    3 KB function: 1.7 s per beam parent, enumerated without a deadline check,
    so 3 KB+ rows overran a 25 s budget by ~20 s). Body lines outside the
    dropped local's use sites contain no `\\bgone\\b` match, so re.sub leaves
    them unchanged; lines outside the body are still substituted. Yields are
    identical to the original."""
    import mt_mut

    def m_temp_merge(t):
        lines, s, e = mt_mut.body_range(t)
        decls = {}
        for i in range(s, e):
            m = mt_mut.DECL.match(lines[i])
            if m: decls[m[4].strip()] = (i, m[3].strip())
        use_sites = {}
        for v, (declaration, _) in decls.items():
            pattern = re.compile(r'\b' + re.escape(v) + r'\b')
            use_sites[v] = [k for k in range(s, e) if k != declaration and pattern.search(lines[k])]
        names = list(decls)
        outside = [k for k in range(len(lines)) if not s <= k < e]
        for x, a in enumerate(names):
            for b in names[x + 1:]:
                if decls[a][1] != decls[b][1]: continue
                ua, ub = use_sites[a], use_sites[b]
                if not ua or not ub: continue
                if max(ua) < min(ub) or max(ub) < min(ua):
                    keep, gone = (a, b) if min(ua) < min(ub) else (b, a)
                    first_gone = min(use_sites[gone])
                    if not re.match(r' +' + re.escape(gone) + r' = ', lines[first_gone]): continue
                    pattern = r'\b' + re.escape(gone) + r'\b'
                    out = list(lines)
                    for k in (*use_sites[gone], *outside):
                        out[k] = re.sub(pattern, keep, lines[k])
                    out[decls[gone][0]] = None
                    yield 'temp_merge', '\n'.join(l for l in out if l is not None)

    m_temp_merge.__doc__ = base.__doc__
    m_temp_merge.__name__ = base.__name__
    return m_temp_merge


def capped_mutations(text, per_family, families=None):
    """b4: mt_mut.mutations(text) keeping a deterministic uniform sample of at
    most `per_family` candidates per family (reservoir seeded by the text).
    The beam samples a family by weight (count capped at 4) and then one
    candidate uniformly, so a uniform per-family subset leaves each pick's
    distribution unchanged. On a 3 KB function the full list was 6828
    candidates / 197 MB per beam parent - over MutationCache's 16 MB limit,
    so it was rebuilt every round and spiked worker memory near the bench
    guard. Cross-family dedupe and first-family attribution match the original."""
    import hashlib
    import random
    import mt_mut
    seen = {hash(text)}
    pools, counts, rngs, order = {}, {}, {}, []
    for f in (families or mt_mut.FAMILIES):
        try:
            for fam, nt in f(text):
                key = hash(nt)
                if key in seen: continue
                seen.add(key)
                if fam not in pools:
                    pools[fam] = []; counts[fam] = 0; order.append(fam)
                    rngs[fam] = random.Random(hashlib.sha1((fam + '\0' + text).encode()).digest())
                counts[fam] += 1
                pool = pools[fam]
                if len(pool) < per_family:
                    pool.append(nt)
                else:
                    j = rngs[fam].randrange(counts[fam])
                    if j < per_family: pool[j] = nt
        except Exception:
            continue
    return [(fam, nt) for fam in order for nt in pools[fam]]


def inline_temp_fast(base):
    """b4: mt_mut.m_inline_temp with use sites from one identifier index per
    call instead of a `\\bvar\\b` regex over every body line per assignment
    (~0.25 s per 3 KB beam parent). Local names are pure \\w runs, so the
    index finds exactly the regex's lines; yields are identical."""
    import mt_mut

    def m_inline_temp(t):
        lines, s, e = mt_mut.body_range(t)
        names = {mt_mut.DECL.match(l)[4].strip(): i for i, l in enumerate(lines[s:e], s) if mt_mut.DECL.match(l)}
        where = {}
        for k in range(s, e):
            for token in set(_WORD.findall(lines[k])):
                if token in names: where.setdefault(token, []).append(k)
        for i in range(s, e):
            m = re.fullmatch(r'( +)(\w+) = (.+);', lines[i])
            if not m or m[2] not in names: continue
            var, expr = m[2], m[3]
            uses = [j for j in where.get(var, ()) if j != i and j != names[var]]
            if len(uses) != 1: continue
            j = uses[0]
            if j < i or lines[j].lstrip().startswith(var + ' =') and '==' not in lines[j]: continue
            if len(re.findall(r'\b' + re.escape(var) + r'\b', lines[j])) != 1: continue
            out = lines[:]
            rep = expr if re.fullmatch(r'[\w.]+|M2C_FIELD\([^()]*\)|\w+\([^()]*\)|&\w+', expr) else '(' + expr + ')'
            out[j] = re.sub(r'\b' + re.escape(var) + r'\b', lambda _: rep, lines[j])
            del out[i]
            di = names[var] - (1 if names[var] > i else 0)
            if not any(re.search(r'\b' + re.escape(var) + r'\b', l) for k, l in enumerate(out) if k != di):
                del out[di]
            yield 'inline_temp', '\n'.join(out)

    m_inline_temp.__doc__ = base.__doc__
    m_inline_temp.__name__ = base.__name__
    return m_inline_temp


def m_abs_struct(text):
    """b4: engine_seeds.abs_struct as a beam family, so the struct spelling of a
    constant-offset global composes with the rewrites the best parent already has."""
    import engine_seeds
    out = engine_seeds.abs_struct(text)
    if out:
        yield 'abs_struct', out
