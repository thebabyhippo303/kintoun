"""Switch-statement case ordering, if-chain lowering, and adjacent case-pair swap mutations."""
import re

_SWITCH_HEAD = re.compile(r'^( +)switch\s*\([^;{}]*\)\s*\{\s*(?:/\*.*\*/\s*)?$')

_CASE_LABEL = re.compile(r'^( +)(case\s+[^:;{}]+|default)\s*:(?:\s*/\*.*\*/\s*)?$')

_CASE_TAIL = re.compile(r'^(break|return\b[^;]*|goto\s+\w+|continue)\s*;')

CASE_ORDER_CAP = 2


def _switch_close(lines, head):
    """Index of the brace-balanced closing line, or None (nested switch inside also disqualifies)."""
    depth = 0
    for i in range(head, len(lines)):
        line = lines[i]
        if '"' in line or "'" in line:
            return None
        for ch in line:
            if ch == '{':
                depth += 1
            elif ch == '}':
                depth -= 1
                if depth == 0:
                    return i
    return None


def _case_blocks(lines, head, close, indent, skip_nested=False):
    """(label_idx, body_first, body_last) per top-level case/default block, or None.

    With skip_nested, a nested switch region is jumped over instead of
    disqualifying the whole outer switch: its deeper-indented labels can
    never match the outer indent, and bodies move/copy intact (every
    block still provably terminated), so reordering and lowering stay
    semantics-preserving. Default False keeps every existing caller as is.
    """
    labels = []
    i = head + 1
    while i < close:
        line = lines[i]
        if skip_nested and _SWITCH_HEAD.match(line) and i != head:
            nested_close = _switch_close(lines, i)
            if nested_close is None or nested_close >= close:
                return None
            i = nested_close + 1
            continue
        if re.search(r'\bswitch\s*\(', line):
            return None
        m = _CASE_LABEL.match(line)
        if m and m[1] == indent:
            labels.append(i)
        elif re.match(r'^( +)(case|default)\b', line):
            return None  # mis-indented or trailing-code label: not m2c shape
        i += 1
    if len(labels) < 2:
        return None
    blocks = []
    for k, lab in enumerate(labels):
        first = lab + 1
        last = (labels[k + 1] if k + 1 < len(labels) else close) - 1
        while last >= first and not lines[last].strip():
            last -= 1
        if last < first:
            return None
        tail = re.sub(r'/\*.*\*/', '', lines[last]).strip()
        if not _CASE_TAIL.match(tail):
            return None  # fallthrough: reordering changes semantics
        blocks.append((lab, first, last))
    return blocks


def m_case_order(text, cap=CASE_ORDER_CAP):
    """Reorder break-terminated switch cases: MWCC lowering follows source order.

    Measured on this project's MWCC: identical switches with rotated case
    order or moved default compile to different word streams (dense 6-case:
    31 vs 30 words; sparse 4-case: 23 vs 22), so the compiler's compare-tree
    shape follows C source order and m2c's recovered order is one guess of
    several. No existing family touches case order (m_swap_stmts needs SIMPLE
    pairs; b3 init_order owns head-zone decl/assign runs), so switches are a
    gap: 5 dev + 2 holdout bench seeds contain one. Two yields max per
    switch (not per parent: 102 dev texts carry two eligible switches
    and the shared counter starved the second entirely): default
    last<->first move, then case reversal with default pinned.
    Seed-side switch gate (target compare-trees need CFG decode the
    search layer does not expose); every block must provably terminate or
    the whole switch is skipped. Nested switches ride inside their
    bodies intact (deeper labels never match the outer indent).
    """
    if 'switch (' not in text and 'switch(' not in text:
        return
    lines = text.split('\n')
    seen = {text}
    for i, line in enumerate(lines):
        m = _SWITCH_HEAD.match(line)
        if not m:
            continue
        close = _switch_close(lines, i)
        if close is None:
            continue
        blocks = _case_blocks(lines, i, close, m[1], skip_nested=True)
        if not blocks:
            continue
        is_default = [lines[lab].strip().startswith('default') for lab, _, _ in blocks]
        if sum(is_default) > 1:
            continue
        made = 0
        order = list(range(len(blocks)))

        def build(perm):
            out = lines[:i + 1]
            for b in perm:
                lab, first, last = blocks[b]
                out.append(lines[lab])
                out.extend(lines[first:last + 1])
            out.extend(lines[close:])
            return '\n'.join(out)

        if True in is_default:
            d = is_default.index(True)
            rest = [b for b in order if b != d]
            if d == len(blocks) - 1:
                cand = build([d] + rest)  # default last -> first
            else:
                cand = build(rest + [d])  # default first/middle -> last
            if cand is not None and cand not in seen and made < cap:
                seen.add(cand)
                yield 'case_order', cand
                made += 1
        cases = [b for b in order if not is_default[b]]
        rev = list(reversed(cases))
        if rev != cases and made < cap:
            perm = []
            ci = iter(rev)
            for b in order:
                perm.append(next(ci) if not is_default[b] else b)
            cand = build(perm)
            if cand not in seen:
                seen.add(cand)
                yield 'case_order', cand
                made += 1

LOWER_CAP = 1


def m_switch_lower(text, cap=LOWER_CAP):
    """Lower a fully-terminated switch to an if/else chain (one yield max per switch).

    Same switch lowering can come from either a C switch or an equivalent
    if/else chain (measured on this project's MWCC: identical 6-case dense
    switch vs if-chain compile to 31 vs 25 words), and m2c's recovered
    switch is one guess of several, so the lowering direction is a gap no
    existing family covers. Same safety basis as m_case_order (every block
    provably terminated or the switch is skipped), plus: terminal
    `break;` is dropped (illegal outside switch) while `continue;`,
    `return`/`goto` stay: `continue` binds the same enclosing loop in
    the lowered chain, and dropping it miscompiles whenever code follows
    (measured orig=3112 vs dropped=4112 on a loop switch with trailing
    code); the switch condition must be a pure
    variable/member (never re-evaluated per branch); comma-case, stacked
    labels and all-default switches bail. == tests are disjoint, so
    case-branch order is semantics-free and a first/middle default always
    becomes the final else.
    """
    if 'switch (' not in text and 'switch(' not in text:
        return
    lines = text.split('\n')
    for i, line in enumerate(lines):
        m = _SWITCH_HEAD.match(line)
        if not m:
            continue
        cond = re.search(r'switch\s*\((.*)\)\s*\{', line)
        if not cond:
            continue
        var = cond[1].strip()
        if not re.fullmatch(r'[A-Za-z_]\w*(?:\.\w+|->[A-Za-z_]\w*|\[\w+\])*', var):
            continue  # calls/side effects must not be re-evaluated per branch
        close = _switch_close(lines, i)
        if close is None:
            continue
        blocks = _case_blocks(lines, i, close, m[1], skip_nested=True)
        if not blocks:
            continue
        ind = m[1]
        branches = []
        dflt = None
        ok = True
        for k, (lab, first_ln, last_ln) in enumerate(blocks):
            labtxt = lines[lab].strip()
            body = [l for l in lines[first_ln:last_ln + 1] if l.strip()]
            if not body:
                ok = False
                break
            tail = re.sub(r'/\*.*\*/', '', body[-1]).strip()
            if tail == 'break;':
                body = body[:-1]
            elif not _CASE_TAIL.match(tail):
                ok = False
                break
            if not body:
                ok = False  # block was ONLY `break;` -> empty branch
                break
            if labtxt.startswith('default'):
                if dflt is not None:
                    ok = False
                    break
                dflt = body
                continue
            vals = re.match(r'case\s+(.+):', labtxt)
            if not vals or ',' in vals[1]:
                ok = False
                break
            branches.append((vals[1].strip(), body))
        if not ok or not branches:
            continue  # all-default or unsafe shape
        out = lines[:i]
        for j, (val, body) in enumerate(branches):
            kw = 'if' if j == 0 else 'else if'
            out.append(f'{ind}{kw} ({var} == {val}) {{')
            out.extend(body)
            out.append(f'{ind}}}')
        if dflt is not None:
            out.append(f'{ind}else {{')
            out.extend(dflt)
            out.append(f'{ind}}}')
        out.extend(lines[close + 1:])  # drop the switch's own closing brace
        yield 'switch_lower', '\n'.join(out)

CSW_CAP = 2


def m_caseswap_order(text, cap=CSW_CAP):
    """Swap one adjacent non-default case-block pair (the 2-byte class).

    Census (b3-caseswap-census, 1132 real bench seed texts): 780 adjacent
    break-terminated non-default case pairs (32 unique) are unreachable:
    case_order yields only a default move plus a full reversal with
    default pinned, so a single transposed pair (ParticleDef__Fixup 99%:
    case-0xFFFD/0xFFFE labels swapped, 2 branch bytes) needs a reversal
    that overshoots everywhere else. Same safety basis as case_order
    (reuses _switch_close/_case_blocks: every block provably terminated,
    no nested switch, m2c label shape), restricted to non-default pairs
    (default moves stay with case_order) and skipping any swap identical
    to a case_order yield via a lazily computed dup set. Own cap,
    near-miss-gated via the shared _init_shaped gate, wired last in
    directed(): yields are disjoint from every landed family's by
    construction (multi-line block transpositions).
    """
    if 'switch (' not in text and 'switch(' not in text:
        return
    lines = text.split('\n')
    made = 0
    seen = {text}
    codupes = None
    for i, line in enumerate(lines):
        if made >= cap:
            return
        m = _SWITCH_HEAD.match(line)
        if not m:
            continue
        try:
            close = _switch_close(lines, i)
            if close is None:
                continue
            blocks = _case_blocks(lines, i, close, m[1])
        except Exception:
            continue
        if not blocks:
            continue
        is_default = [lines[lab].strip().startswith('default')
                      for lab, _, _ in blocks]
        if sum(is_default) > 1:
            continue
        order = list(range(len(blocks)))
        for k in range(len(blocks) - 1):
            if made >= cap:
                return
            if is_default[k] or is_default[k + 1]:
                continue
            perm = order[:k] + [k + 1, k] + order[k + 2:]
            out = lines[:i + 1]
            for b in perm:
                lab, first, last = blocks[b]
                out.append(lines[lab])
                out.extend(lines[first:last + 1])
            out.extend(lines[close:])
            cand = '\n'.join(out)
            if cand in seen:
                continue
            if codupes is None:
                try:
                    codupes = {c for _, c in m_case_order(text)}
                except Exception:
                    codupes = set()
            if cand in codupes:
                continue
            seen.add(cand)
            made += 1
            yield 'caseswap_order', cand
