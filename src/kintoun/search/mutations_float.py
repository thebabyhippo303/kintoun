"""Floating-point FMA, negation, double-add, width-conversion, punning, and compare mutations."""
import re
from kintoun.search.mutations_recovery import current_evaluator

# A float operand: dotted name with one optional call/paren group (M2C_FIELD,
# sinf(x), (f32)y), a parenthesised simple expression, or a number. Atomic:
# once an alternative matches, the trailing lookaheads must take it or leave
# it; backtracking to a shorter prefix (temp_f2 -> temp_f + stranded 2) would
# manufacture uncompiling text, so it is forbidden here.
_ATOM=(r'(?>[A-Za-z_][\w.]*(?:\([^()]*(?:\([^()]*\)[^()]*)*\))?'
        r'|\(f32\)\s*[A-Za-z_][\w.]*|0x[\da-fA-F]+|\d+(?:\.\d*)?f?|\.\d+f?|\([^()]*\))')

_FLOAT_SCENT=re.compile(r'f32|f64|float|double|temp_f|var_f|\bsp[0-9A-Fa-f]+\b|\.v\d|M2C_FIELD\([^,]+,\s*f32|\d\.\d')


def _fma_before(line,start):
    """(nearest non-space char before start, preceding word or '').

    The word distinguishes a call-looking predecessor (f-(a*b), binary minus,
    skip) from a keyword (return-(a*b), unary negation, allow).
    """
    j=start-1
    while j>=0 and line[j] in ' \t':j-=1
    if j<0:return '', ''
    match=re.search(r'[A-Za-z_][\w.]*$',line[:j+1])
    word=match[0] if match and j+1==match.end() else ''
    return line[j],word


def _fma_lead_ok(before,word):
    """A (-A)*B / A*(-B) / (-A)*(-B) match is a whole product (not a chain
    fragment, member/call split) when its left edge is a statement/operator
    boundary. A preceding word only passes for the `return` keyword. `!` is
    excluded: !-a*b is (!(-a))*b, not a negation of a product."""
    if word:return word=='return'
    return before in ('','(','=','+',',',';',':','{','&','|','<','>','?','-','[')


def _fma_unary_ok(before,word):
    """A -(A*B) match is unary negation (not binary minus) at the same
    boundaries, plus after a multiplicative operator (the factor is kept).
    `!` is excluded for the same reason as above."""
    if word:return word=='return'
    return before in ('','(','=','+',',',';',':','{','&','|','<','>','?','-','*','/','%','[')


def _fma_glued_minus(line,start):
    """A match starting immediately after '-' is predecrement (--a), not
    negation. Space-separated minuses (x - -a) never abut, so plain
    adjacency is exactly the predecrement shape."""
    return start>0 and line[start-1]=='-'


def _fma_sub_ok(line,start):
    """An A-B match is a whole difference when its left edge is a boundary.
    A '>' edge is a comparison (x > a-b, allow) unless it is really member
    access (p->x-y, skip). Longer *-chains are excluded like the lead guard.
    A itself preceded by '-' is never a unit: either negated (-a-b) or a
    later link of a subtraction chain (x-a-b); rewriting reassociates."""
    j=start-1
    while j>=0 and line[j] in ' \t':j-=1
    if j>=0 and line[j]=='-':return False
    before,word=_fma_before(line,start)
    if word:return word=='return'
    if before=='>':
        k=start-1
        while k>=0 and line[k] in ' \t':k-=1
        k-=1  # over the '>'
        while k>=0 and line[k] in ' \t':k-=1
        if k>=0 and line[k]=='-':return False
        return True
    return before in ('','(','=','+',',',';',':','{','&','|','<','?','-','[')


def _fma_wanted(target):
    """Target shows an instruction only a negation move produces: single-
    precision FMA (fmadds/fmsubs/fnmadds/fnmsubs) or float negation/abs."""
    try:words=list(target)
    except TypeError:return False
    for word in words:
        try:value=int(word)&0xffffffff
        except (TypeError,ValueError):continue
        if value>>26==59 and (value>>1)&31 in (28,29,30,31):return True
        if value>>26==63 and (value>>1)&1023 in (40,136,264):return True
    return False


def m_fma_negate(text,target=None):
    """Float negation placement across products, gated on target evidence.

    The blind search samples every family on every parent, so an always-on
    float family spends capped compiles where no float gap exists (measured
    last cycle: ties plus mean regression from sampling dilution). The gate
    reads the current search evaluator's target words through the shared
    ContextVar and yields nothing unless the target actually contains FMA or
    float-negation instructions. Same value-safe moves as before, now free
    where they cannot help.
    """
    if target is None:
        evaluator=current_evaluator.get()
        target=getattr(evaluator,'target',None) if evaluator is not None else None
    if not _fma_wanted(target):return
    yield from _fma_negate_moves(text)


def _fma_negate_moves(text):
    """Float negation placement across products toggles FMA codegen.

    Measured on this project's MWCC: (-a)*b+c compiles to fneg+fmadds while
    -(a*b)+c gives fmul+fneg+fadds, and a*(-b)+c also reaches fneg+fmadds.
    Bare -a*b gives fneg+fmul while -(a*b) gives fmul+fneg. The abstract C
    values are identical (exact negation, symmetric rounding), so each move
    only changes instruction selection. m_commute swaps operands but never
    moves a minus across '*', and m_float_expr never negates, so no existing
    family reaches these shapes. First usable match per rule only: tiny,
    high-precision yields for the compile-capped search. Guards keep every
    yield compiling with identical values: member-access splits (p->x),
    longer *-chains (a*b*(-c)), call-arg splits (f(-a)*b), logical negation
    (!-a*b), and predecrement (--a*b) are skipped, never rewritten.
    """
    rules=[
        # -A*B -> -(A*B): bare m2c negation form to post-multiply fneg order.
        # The match must be a whole product, so the lead guard (not the unary
        # one) applies: x*-a*b is a chain fragment, not a unit. B must not
        # continue into member/call/subscript.
        (r'-\s*('+_ATOM+r')\s*\*\s*('+_ATOM+r')(?!\s*(?:->|\.|\[|\())',
         lambda m:'-('+m[1]+' * '+m[2]+')','lead'),
        # A-B -> -(B-A): fsub to fsub+fneg. B must not extend into a further
        # multiply/divide (a-b*c stays put) or member/call/subscript.
        (r'('+_ATOM+r')\s*-\s*('+_ATOM+r')(?!\s*(?:[*/%(\[.])|\s*->)',
         lambda m:'-('+m[2]+' - '+m[1]+')','sub'),
        # (-A)*B -> -(A*B). B must not continue into member/call/subscript;
        # match must not start inside a call (f(-a)*b) or extend a chain (x*(-a)*B).
        (r'\(-\s*('+_ATOM+r')\)\s*\*\s*('+_ATOM+r')(?!\s*(?:->|\.|\[|\())',
         lambda m:'-('+m[1]+' * '+m[2]+')','lead'),
        # -(A*B) -> (-A)*B. Self-delimiting left; only a binary minus or a
        # call-looking predecessor (f-(a*b)) forbids the move.
        (r'-\(('+_ATOM+r')\s*\*\s*('+_ATOM+r')\)',lambda m:'(-'+m[1]+') * '+m[2],'unary'),
        # A*(-B) -> -(A*B). A must be a whole operand: no member/deref split,
        # no longer chain to its left.
        (r'(?<![\w.>*])('+_ATOM+r')\s*\*\s*\(-\s*('+_ATOM+r')\)',
         lambda m:'-('+m[1]+' * '+m[2]+')','lead'),
        # -(A*B) -> A*(-B); same self-delimiting form as the (-A)*B move.
        (r'-\(('+_ATOM+r')\s*\*\s*('+_ATOM+r')\)',lambda m:m[1]+' * (-'+m[2]+')','unary'),
        # (-A)*(-B) -> A*B (double negation drops out, product can fuse).
        (r'\(-\s*('+_ATOM+r')\)\s*\*\s*\(-\s*('+_ATOM+r')\)',lambda m:m[1]+' * '+m[2],'lead'),
        # -(B-A) -> (A-B): drop a redundant outer negation around a difference.
        # Parenthesised so the result stays one factor (x*-(a-b) keeps working).
        (r'-\(('+_ATOM+r')\s*-\s*('+_ATOM+r')\)(?!\s*[*/%])',
         lambda m:'('+m[2]+' - '+m[1]+')','unary'),
    ]
    lines=text.split('\n')
    yielded=0
    for pattern,build,guard in rules:
        if yielded>=8:break
        expression=re.compile(pattern)
        done=False
        for i,line in enumerate(lines):
            if done or yielded>=8:break
            if not _FLOAT_SCENT.search(line):continue
            at=0
            while at<=len(line):
                match=expression.search(line,at)
                if not match:break
                if guard in ('bare','lead') and _fma_glued_minus(line,match.start()):
                    at=match.start()+1;continue  # predecrement, not negation
                if guard=='sub':ok=_fma_sub_ok(line,match.start())
                else:
                    before,word=_fma_before(line,match.start())
                    if guard=='lead':ok=_fma_lead_ok(before,word)
                    elif guard=='unary':ok=_fma_unary_ok(before,word)
                    else:ok=True
                if not ok:
                    at=match.start()+1;continue
                candidate=lines[:];candidate[i]=line[:match.start()]+build(match)+line[match.end():]
                yield 'fma_negate','\n'.join(candidate);yielded+=1;done=True;break

FNEG_CAP = 2

# A balanced M2C_FIELD span (up to two nesting levels: simple args and
# ((f32 *)sp.bytes)/(expr) bases) is an opaque value operand: interior
# cast/type stars and commas are not operators. Alternation branches are
# first-char disjoint, so the match stays linear. M2C_BITWISE is
# deliberately excluded (pun lane owns it).
_MFLD_SPAN = re.compile(r'M2C_FIELD\((?:[^()]|\((?:[^()]|\([^()]*\))*\))*\)')

_FNEG_ATOM = r'(?:'+_MFLD_SPAN.pattern+r'|'+_ATOM+r')'

_FNEG_PROD = re.compile(r'(?P<a>'+_FNEG_ATOM+r')\s*\*\s*(?P<b>'+_FNEG_ATOM+r')(?!\s*(?:->|\.|\[|\())')

_FNEG_OPERATOR = re.compile(r'[+\-*/%<>!&|?:]')

_FNEG_MACRO_FLOAT = re.compile(r'\b(?:f32|float|f64|double)\s*\*(?!\*)')


def _fneg_macro_ok(operand):
    """A macro operand must read a float (f32/float/f64/double pointee)
    and not be a pointer macro (`**`): negating an address does not
    compile, and compiling seeds never multiply one, so rejection
    loses nothing."""
    if 'M2C_FIELD(' not in operand:
        return True
    return '**' not in operand and _FNEG_MACRO_FLOAT.search(operand) is not None


def _fneg_op_scan(s):
    """Operator veto for a product operand, blind to macro spans."""
    return _FNEG_OPERATOR.search(_MFLD_SPAN.sub('', s))

# Declaration fragments are not products: `void *arg0` in a signature
# (or `f32 *p` in a decl) matches A*B with a bare type keyword as A,
# and negating it emits uncompiling text (measured on
# Camera__AdvanceRotationAngle's scented signature line). m2c value
# temps are never bare type keywords, so they stay put.
_FNEG_TYPEWORDS = frozenset((
    'void', 'char', 'short', 'int', 'long', 'float', 'double',
    'signed', 'unsigned', 'const', 'volatile', 'static', 'extern',
    'register', 'struct', 'union', 'enum',
    'f32', 'f64', 's8', 's16', 's32', 's64',
    'u8', 'u16', 'u32', 'u64', 'M2C_UNK'))


def _fneg_minus_paren(line, start):
    """True when start sits directly in a (...) group opened right after
    '-' (unary `-(A*B)`, binary `x - (A*B)`, diff-of-products tails).

    Negating the product inside flips the outer subtraction (-P becomes
    P): a two-sign hypothesis outside the intro contract, which owns
    negation-free seeds while fma_negate owns negated ones (its
    distribute moves already team the `-(A*B)` shape). A bare '-' edge
    already refuses; this is the parenthesised edge. `--`/`->` cannot
    open a group in valid seeds, so any '-' qualifies. Backward paren
    scan is approximate over string literals; miscounts only ever miss
    a hypothesis, never manufacture one.
    """
    depth = 0
    quote = None
    i = start - 1
    while i >= 0:
        ch = line[i]
        if quote is not None:
            if ch == quote:
                quote = None
        elif ch in ('"', "'"):
            quote = ch
        elif ch == ')':
            depth += 1
        elif ch == '(':
            if depth == 0:
                j = i - 1
                while j >= 0 and line[j] in ' \t':
                    j -= 1
                return j >= 0 and line[j] == '-'
            depth -= 1
        i -= 1
    return False


def _fneg_intro_ok(line, start):
    """An A*B match takes a leading minus when its left edge is a
    statement/operator boundary that is not itself a minus, multiply,
    divide, or member access.

    Mirrors _fma_lead_ok minus '-': the sibling consumes its leading
    minus inside the pattern, but here a '-' edge would emit '--'
    (predecrement) or reassociate a subtraction chain, and '*'/'/' edges
    are longer-chain fragments whose rounding order a rewrite would
    change. A '>' edge is a comparison (x > a*b, allow) unless it is
    really member access (p->x*y, skip), checked like _fma_sub_ok.
    A match inside a minus-prefixed paren group is likewise out: the
    negation would flip the outer subtraction, not recover a spill.
    """
    if _fneg_minus_paren(line, start):
        return False
    before, word = _fma_before(line, start)
    if word:
        return word == 'return'
    if before == '>':
        k = start - 1
        while k >= 0 and line[k] in ' \t':
            k -= 1
        k -= 1  # over the '>'
        while k >= 0 and line[k] in ' \t':
            k -= 1
        if k >= 0 and line[k] == '-':
            return False
        return True
    return before in ('', '(', '=', '+', ',', ';', ':', '{', '&', '|',
                      '<', '?', '[')


def m_fneg_intro(text,target=None):
    """Introduce a bare leading minus on float products, gated on target evidence.

    Inverse of the m_fma_negate `-A*B -> -(A*B)` move for seeds that
    carry no negation at all: RigidBody__HandleCollision's 36 drafts
    multiply vec3 parts by a temp with zero minus signs anywhere, while
    live negates a spilled multiplicand first (fneg f0,f0 then fmuls).
    Measured on this project's MWCC, bare `-a*b` is exactly the
    fneg-then-fmul shape (post-multiply `-(a*b)` is fmul-then-fneg, and
    the existing move covers that direction from here). Each yield
    negates exactly one whole product; the value is identical (exact
    negation, symmetric rounding), so exact match decides. Cap 2,
    float-scented lines only.
    """
    if target is None:
        evaluator=current_evaluator.get()
        target=getattr(evaluator,'target',None) if evaluator is not None else None
    if not _fma_wanted(target):return
    yield from _fneg_intro_moves(text)


def _fneg_intro_moves(text):
    lines=text.split('\n')
    yielded=0
    for i,line in enumerate(lines):
        if yielded>=FNEG_CAP:break
        if not _FLOAT_SCENT.search(line):continue
        at=0
        while at<=len(line):
            if yielded>=FNEG_CAP:break
            match=_FNEG_PROD.search(line,at)
            if not match:break
            # B must not carry its own minus (a*-b would drop it) and
            # must not be glued to one (--b is predecrement).
            blead=line[:match.start('b')].rstrip()
            if blead.endswith('-') or _fma_glued_minus(line,match.start('b')):
                at=match.start()+1;continue
            # A must not be a bare declaration type (`void *arg0` is a
            # signature fragment, not a product; see _FNEG_TYPEWORDS).
            if match['a'] in _FNEG_TYPEWORDS:
                at=match.start()+1;continue
            if not _fneg_intro_ok(line,match.start('a')):
                at=match.start()+1;continue
            # Composite operands stay out: negating a sum or product
            # cannot recover a dropped spill negation (spills negate
            # single registers), and its fneg placement matches no
            # fneg-first target shape. Plain idents, calls with
            # operator-free args, casts, and balanced M2C_FIELD macros
            # (interior stars blinded) still ride; macro operands must
            # read floats, never addresses.
            if (_fneg_op_scan(match['a'])
                    or _fneg_op_scan(match['b'])
                    or not _fneg_macro_ok(match['a'])
                    or not _fneg_macro_ok(match['b'])):
                at=match.start()+1;continue
            candidate=lines[:]
            candidate[i]=(line[:match.start()]+'-'+match['a']
                          +' * '+match['b']+line[match.end():])
            yield 'fneg_intro','\n'.join(candidate);yielded+=1
            at=match.end()

FNEGZ_CAP = 2

_FNEG_ZERO = re.compile(r'-\s*(?P<a>'+_FNEG_ATOM+r')(?!\s*(?:->|\.|\(|\[))')


def _fneg_zero_wanted(target):
    """Target subtracts single-precision floats: primary 59, XO 20 (fsubs).

    Only an fsubs can match a `0.0f - A` yield, so without one the family
    spends capped compiles where it cannot help. Same ContextVar pattern
    as the sibling gates.
    """
    try:words=list(target)
    except TypeError:return False
    for word in words:
        try:value=int(word)&0xffffffff
        except (TypeError,ValueError):continue
        if value>>26==59 and (value>>1)&31==20:return True
    return False


def m_fneg_zero(text,target=None):
    """Bare float negation as zero-subtraction, gated on target fsubs.

    Measured on this project's MWCC: `-x` is one fneg word while
    `0.0f - x` is pool-load plus lfs plus fsubs (int `0 - x` lowers
    identically), so the two spellings never share a word stream and no
    existing family bridges them: fneg_intro only ADDS negation to
    products, fma_negate only moves it across products and differences,
    distsum only distributes over sums. Seeds spell 456 bare lane
    negations plus 345 ident, 192 MFLD and 53 product ones, and never
    spell `0.0f - x` (0 sites), so one direction suffices. Values match
    except a signed-zero-only edge (+0.0 negates to -0.0 but subtracts
    to +0.0), the same tolerance class the distsum fuzz accepted; exact
    match still decides. Operands ride _FNEG_ATOM (idents, calls with
    operator-free args, casts, balanced M2C_FIELD spans) with the
    sibling lead/macro/operator guards, so predecrement, binary minus,
    chain fragments and address negations stay out. Cap 2,
    float-scented lines only.
    """
    if target is None:
        evaluator=current_evaluator.get()
        target=getattr(evaluator,'target',None) if evaluator is not None else None
    if not _fneg_zero_wanted(target):return
    yield from _fneg_zero_moves(text)


def _fneg_zero_moves(text):
    lines=text.split('\n')
    yielded=0
    for i,line in enumerate(lines):
        if yielded>=FNEGZ_CAP:break
        if not _FLOAT_SCENT.search(line):continue
        at=0
        while at<=len(line):
            if yielded>=FNEGZ_CAP:break
            match=_FNEG_ZERO.search(line,at)
            if not match:break
            if match['a'] in _FNEG_TYPEWORDS:
                at=match.start()+1;continue
            if (_fneg_op_scan(match['a'])
                    or not _fneg_macro_ok(match['a'])):
                at=match.start()+1;continue
            if not _fneg_intro_ok(line,match.start()):
                at=match.start()+1;continue
            candidate=lines[:]
            candidate[i]=line[:match.start()]+'0.0f - '+match['a']+line[match.end():]
            yield 'fneg_zero','\n'.join(candidate);yielded+=1
            at=match.end()


def _fneg_sum_split(inner):
    """Split a balanced sum/difference on top-level +/-; (terms, seps).

    Paren depth is tracked so `-(a + f(b - c))` splits once, not three
    times; the caller guarantees balance, so a nonzero end depth can
    only come from a string-literal paren, which the term veto then
    rejects via its quote characters ('"' not an issue; kept simple
    like the sibling scanners)."""
    terms = []
    seps = []
    depth = 0
    cur = ''
    for ch in inner:
        if ch == '(':
            depth += 1
            cur += ch
        elif ch == ')':
            depth -= 1
            cur += ch
        elif depth == 0 and ch in '+-':
            terms.append(cur)
            seps.append(ch)
            cur = ''
        else:
            cur += ch
    terms.append(cur)
    return terms, seps


def _fneg_distsum_moves(text):
    """Distribute a leading minus over a parenthesised float sum.

    Measured on this project's MWCC: `-(a+b+c)` compiles to
    fadds,fadds,fneg (negation last) while `-a-b-c` gives
    fneg,fsub,fsub (negation first), identical values except all-zero
    inputs can flip signed zero (-(-0+0+0) is -0, distributed is +0;
    fuzzed 336k pairs: 2 mismatches, both that case; NaN-sign behavior
    is the same scored-hypothesis basis as the sibling negation moves,
    exact match deciding). No existing family moves a minus across
    '+'/'-':
    fma_negate owns products and fneg_intro adds negation to
    negation-free products, so Mover__Respond-style `-(sum)` seeds
    (15 corpus sites) fire nothing today. Each yield distributes
    exactly one group (`-(A+B-C)` -> `(-A-B+C)`); terms must be
    operator-free atoms (same veto as the intro operands, so nested
    sums, comparisons, and calls with operators stay out) and lone
    `-(a)` paren strips stay out. The build keeps its own parens
    (measured: `(-a-b-c)` selects identically to `-a-b-c`), so the
    result stays one factor in every edge context (`x*-(a+b)`,
    `-(a+b)*c`, `sizeof(-(a+b))`, comparisons) with no edge guard.
    Cap 2, float-scented lines only.
    """
    lines = text.split('\n')
    yielded = 0
    for i, line in enumerate(lines):
        if yielded >= FNEG_CAP:
            break
        if not _FLOAT_SCENT.search(line):
            continue
        at = 0
        while at <= len(line):
            if yielded >= FNEG_CAP:
                break
            match = re.search(r'-\s*\(', line[at:])
            if not match:
                break
            start = at + match.start()
            paren = line.find('(', start)
            close = _fcmp_matching(line, paren)
            if close < 0:
                at = start + 1
                continue
            inner = line[paren + 1:close]
            terms, seps = _fneg_sum_split(inner)
            terms = [t.strip() for t in terms]
            if (len(terms) < 2 or any(not t for t in terms)
                    or any(t in _FNEG_TYPEWORDS for t in terms)
                    or any(_fneg_op_scan(t) for t in terms)
                    or any(not _fneg_macro_ok(t) for t in terms)
                    or any(re.search(r'["\']', t) for t in terms)):
                at = start + 1
                continue
            # Binary-minus context (w-(...) or (...)-(...)) keeps its
            # minus: replacing from the paren emits `w - (-a-b)`.
            # Unary position replaces from the minus itself.
            before, word = _fma_before(line, start)
            binary = (before in (')', ']') or (
                word and word not in _FNEG_TYPEWORDS
                and word not in ('return', 'sizeof', 'typeof',
                                 'alignof', '_Alignof', 'case')))
            build = '(-' + terms[0] + ''.join(
                (' - ' if s == '+' else ' + ') + t
                for s, t in zip(seps, terms[1:])) + ')'
            rep = paren if binary else start
            candidate = lines[:]
            candidate[i] = line[:rep] + build + line[close + 1:]
            yield 'fneg_distsum', '\n'.join(candidate)
            yielded += 1
            at = close + 1


def m_fneg_distsum(text, target=None):
    """Introduce fneg-first codegen by distributing over float sums.

    Gated on the same FMA/negation target evidence as the sibling
    negation families through the shared ContextVar.
    """
    if target is None:
        evaluator = current_evaluator.get()
        target = getattr(evaluator, 'target', None) if evaluator is not None else None
    if not _fma_wanted(target):
        return
    yield from _fneg_distsum_moves(text)

FTWICE_CAP = 2

_FTWICE_TWO = r'(?:2\.0f?|(?<![\w.])2(?![\w.]))'

# Plain value atom only (identifiers and dotted field names): a call
# operand would evaluate twice under doubling, and a numeric operand
# is a fold, not this idiom. Arrow member access stays out like the
# sibling member-split guard (double volatile load); dotted names ride.
_FTWICE_ATOM = r'[A-Za-z_][\w.]*'

_FTWICE_L = re.compile(r'(?P<a>'+_FTWICE_ATOM+r')\s*\*\s*(?P<two>'+_FTWICE_TWO+r')(?![\w.])')

_FTWICE_R = re.compile(r'(?P<two>'+_FTWICE_TWO+r')(?![\w.])\s*\*\s*(?P<a>'+_FTWICE_ATOM+r')')


def _ftwice_wanted(target):
    """Target adds single-precision floats: fadds words.

    MWCC strength-reduces float times-two to an add (measured on
    Simple__RotateToXAngleRotVelImpl / RotateToZAngleRotVelImpl: every
    seed spells `(2.0f * lbl_803DE520) - lbl_803DE500` while live
    carries 0 fmuls and exactly the fadds count of an `x + x`
    lowering). Only a target with fadds evidence can use this family.
    """
    try:words=list(target)
    except TypeError:return False
    for word in words:
        try:value=int(word)&0xffffffff
        except (TypeError,ValueError):continue
        if value>>26==59 and (value>>1)&31==21:return True
    return False


def _ftwice_ok(line,start,end):
    """A 2.0f*A match is a whole doubling (not a longer-chain fragment
    or a member/call/subscript split) when its left edge is a
    statement/operator boundary and the value does not continue into
    member, call, or subscript on the right. Mirrors the sibling lead
    guard, plus '*'/'/'/'%'/'('/')'/']' left edges: those are longer
    multiplicative chains or dereferences whose grouping a rewrite
    would change (a/2.0f*b is not a/(b+b)).
    """
    before,word=_fma_before(line,start)
    if word:return word=='return'
    if before in ('*','/','%','.',')',']'):return False
    if before not in ('','(','=','+',',',';',':','{','&','|',
                      '<','>','?','-','[','!'):return False
    if re.match(r'\s*(?:->|\.|\(|\[)',line[end:]) is not None:return False
    # A trailing multiplicative operator makes this the head of a
    # longer chain ((a*2)*b is not (a+a)*b in rounding order), so the
    # pair is a fragment like the sibling's chain-left rule.
    return re.match(r'\s*[* /%]',line[end:]) is None


def m_ftwice_add(text,target=None):
    """Rewrite float times-two as a self-add, gated on target evidence.

    MWCC lowers `2.0f * A` to `A + A` (fadds, never fmuls): the
    Simple rotor Impls' live code has 0 fmuls with the exact fadds
    count of the doubled form, but every m2c seed spells the multiply.
    The value is bit-identical (2*x == x+x for all IEEE inputs
    including NaN/Inf/signed zero, no fast-math needed), so exact
    match decides. Each yield doubles exactly one literal-two product,
    either operand order; call/numeric/arrow operands and longer-chain
    fragments are skipped. Cap 2, float-scented lines only.
    """
    if target is None:
        evaluator=current_evaluator.get()
        target=getattr(evaluator,'target',None) if evaluator is not None else None
    if not _ftwice_wanted(target):return
    yield from _ftwice_add_moves(text)


def _ftwice_add_moves(text):
    lines=text.split('\n')
    yielded=0
    for i,line in enumerate(lines):
        if yielded>=FTWICE_CAP:break
        if not _FLOAT_SCENT.search(line):continue
        at=0
        while at<=len(line):
            if yielded>=FTWICE_CAP:break
            mL=_FTWICE_L.search(line,at)
            mR=_FTWICE_R.search(line,at)
            if mL is not None and mR is not None:
                match=mL if mL.start()<=mR.start() else mR
            else:
                match=mL if mL is not None else mR
            if match is None:break
            if not _ftwice_ok(line,match.start(),match.end()):
                at=match.start()+1;continue
            candidate=lines[:]
            candidate[i]=(line[:match.start()]+'('+match['a']
                          +' + '+match['a']+')'+line[match.end():])
            yield 'ftwice_add','\n'.join(candidate);yielded+=1
            at=match.end()

FCONV_CAP = 4

_FCONV_XO = frozenset((12, 15))  # frsp (double->float narrow), fctiwz (float->int)

_FCONV_DECL = re.compile(r'^([ \t]*(?:register[ \t]+)?)(f64|double)([ \t]+(?:\*+)?)(\w+)((?:\[[^\];]*\])*(?:[ \t]*=[ \t]*[^;]+)?[ \t]*;.*)$')

_AGG_KEYWORD = re.compile(r'\bstruct\b|\bunion\b|\benum\b|[{};]')


def _fconv_in_aggregate(lines, idx):
    """True when line idx sits inside a struct/union/enum brace block.

    Retyping a field changes member offsets and sizeof (wrong code that
    still compiles); only local declarations are safe to convert. A
    braceless `struct S *p;` declaration resets the pending keyword so
    it cannot poison the next brace block open.
    """
    stack = []
    pending = False
    for ln in lines[:idx]:
        code = re.sub(r'"(?:[^"\\]|\\.)*"', '""', ln.split('//')[0])
        for m in _AGG_KEYWORD.finditer(code):
            tok = m[0]
            if tok == '{':
                stack.append(pending)
                pending = False
            elif tok == '}':
                if stack:
                    stack.pop()
            elif tok == ';':
                pending = False
            else:
                pending = True
    return any(stack)

_FCONV_NARROW = {'f64': 'f32', 'double': 'float'}


def _fconv_wanted(target):
    """Target narrows or converts FP values: frsp (double->float) or
    fctiwz (float->int). A narrowed temp is the only C shape that adds
    either instruction, so anything else cannot use this family."""
    try:words=list(target)
    except TypeError:return False
    for word in words:
        try:value=int(word)&0xffffffff
        except (TypeError,ValueError):continue
        if value>>26==63 and (value>>1)&1023 in _FCONV_XO:return True
    return False


def m_fconv_narrow(text,target=None):
    """FP temp narrowing, gated on target conversion evidence.

    m2c types unknown float temporaries f64/double while the original kept
    them float: the seed then computes in double (fadd, no frsp) where the
    target narrows (frsp) or converts from float (fctiwz needs a float
    operand, not a double-helper-call path). Measured on this project's
    MWCC: an f64 temp costs one extra word plus frsp versus the f32 form,
    while explicit (float)/(s32) casts on already-typed expressions compile
    identically, so only the declaration type toggles selection. One yield
    per f64/double temp declaration, cap 4: bare, initialized (measured: an
    f64 init costs a word plus frsp versus f32), pointer temps (measured:
    f64* costs lfd plus frsp versus f32* lfs), and arrays (measured: f64
    buf costs a word plus frsp and a larger frame versus f32 buf).
    """
    if target is None:
        evaluator=current_evaluator.get()
        target=getattr(evaluator,'target',None) if evaluator is not None else None
    if not _fconv_wanted(target):return
    yield from _fconv_narrow_moves(text)


def _fconv_narrow_moves(text):
    lines=text.split('\n')
    yielded=0
    for i,line in enumerate(lines):
        if yielded>=FCONV_CAP:break
        match=_FCONV_DECL.match(line)
        if not match:continue  # funcs never match: '(' fits neither brackets, init, nor ';'
        if _fconv_in_aggregate(lines, i):continue  # struct fields: layout
        candidate=lines[:]
        candidate[i]=match[1]+_FCONV_NARROW[match[2]]+match[3]+match[4]+match[5]
        yield 'fconv_narrow','\n'.join(candidate);yielded+=1

_FWIDE_MAP = {'f32': 'f64', 'float': 'double'}

_FWIDE_DECL = re.compile(r'^([ \t]*(?:register[ \t]+)?)(f32|float)([ \t]+(?:\*+)?)(\w+)((?:\[[^\];]*\])*(?:[ \t]*=[ \t]*[^;]+)?[ \t]*;.*)$')


def m_fconv_widen(text,target=None):
    """FP temp widening, gated on target conversion evidence.

    The mirror of m_fconv_narrow for the direction the bench rows actually
    show: m2c types double-kept temporaries f32/float while the original
    kept them double, so the seed computes in float (fadds, lfs/stfs)
    where the target computes in double and narrows (frsp) or converts
    (fctiwz shares the double-context gate). Censused 2026-10-17: 17
    bench targets carry frsp/fctiwz while their seeds hold zero
    f64/double declarations (m2c's `(f32)(f64)lbl` sandwich folds to
    identical code under MWCC, probed, so it is not the gap). Measured
    on this project's MWCC: an f64 temp costs one extra word plus frsp
    versus the f32 form, so each widened decl is the only C shape that
    can add the missing conversion. One yield per f32/float local decl,
    cap 4 (shared FCONV_CAP): bare, initialized, pointer, and array
    temps. `extern`/`typedef` lines are skipped: extern f32 globals are
    ubiquitous (every float object in .data) and retyping them would eat
    the cap with near-certain losers; extern mistypes stay in the
    extern/context lane. Storage-class decls (`static`) and function
    declarations cannot match the shape (no '=' and no ';'-reach past
    '('), same as narrow.
    """
    if target is None:
        evaluator=current_evaluator.get()
        target=getattr(evaluator,'target',None) if evaluator is not None else None
    if not _fconv_wanted(target):return
    yield from _fconv_widen_moves(text)


def _fconv_widen_moves(text):
    lines=text.split('\n')
    yielded=0
    for i,line in enumerate(lines):
        if yielded>=FCONV_CAP:break
        match=_FWIDE_DECL.match(line)
        if not match:continue  # funcs never match: '(' fits neither brackets, init, nor ';'
        if line.strip().startswith(('extern', 'typedef')):continue
        if _fconv_in_aggregate(lines, i):continue  # struct fields: layout
        candidate=lines[:]
        candidate[i]=match[1]+_FWIDE_MAP[match[2]]+match[3]+match[4]+match[5]
        yield 'fconv_widen','\n'.join(candidate);yielded+=1

FPUN_CAP = 2

# Magic-double int->float constant, read off live rodata (Sphere
# 0x80349F00 lfd target): 0x4330000080000000 = 2**52 + 2**31, exact.
_FPUN_MAGIC = '4503601774854144.0'

# Measured primary-63 XOs (DOL ground truth): frsp 12 (FluffLoop
# 0x80051cc4), fctiwz 15 (matched UiByteAnimator 0x80260bdc), fsub 20
# (Sphere 0x8026bbb8), fmr 72, fcmpu 0, fcmpo 32.
_FPUN_FRSP_XO = 12

_FPUN_FCTIWZ_XO = 15

_FPUN_FSUB_XO = 20

# Int operand atoms for the pun source shape: int-typed field loads and
# m2c int temps (temp_r/var_r). Plain int vars are untyped line-locally
# and stay out. The field-load head tolerates one nesting level for the
# m2c idiom M2C_FIELD(M2C_FIELD(..), T *, K).
_FPUN_MFC = (r'M2C_FIELD\s*\((?:[^(),]|\([^()]*\))*,\s*'
             r'(?:(?:un)?signed\s+)?')

_FPUN_INTT = r'(?:[su](?:8|16|32)|char|short|int|long)\b'

_FPUN_FLTT = r'(?:f32|f64|float|double)\b'

_FPUN_INT = (r'(?:'+_FPUN_MFC+_FPUN_INTT+r'[^,]*,[^)]*\)'
             r'|\b(?:temp|var)_r\w*)')

_FPUN_DCAST = re.compile(r'\(f32\)\s*\(f64\)\s*(?P<x>'+_FPUN_INT+r')')

_FPUN_FCAST = re.compile(r'\(f64\)\s*(?P<x>'+_FPUN_INT+r')')

_FPUN_SCAST = re.compile(r'\(f32\)\s*(?P<x>'+_FPUN_INT+r')')

# Cast keywords for the paren-operand pass, longest first: the operand
# must start with '(' there, which the atom patterns above can never
# match, so the two passes are disjoint by construction.
_FPUN_CASTKW = re.compile(r'\(f32\)\s*\(f64\)\s*|\(f64\)\s*|\(f32\)\s*')


def _fpun_wanted(target):
    """Target converts int->float through a bit-pun, not fctiwz.

    The magic-double shape is fingerprinted exactly: an xoris with
    0x8000 (D-form, sign flip), an lfd (D-form, double traffic), a
    double fsub, and an frsp rounding the result, with no fctiwz
    anywhere. Sphere__ResetProperties carries it twice; arithmetic-cast
    rows (UiByteAnimator) fail the xoris clause.
    """
    try:words=list(target)
    except TypeError:return False
    seen=set()
    for word in words:
        try:value=int(word)&0xffffffff
        except (TypeError,ValueError):continue
        prim=value>>26
        if prim==27 and (value&0xffff)==0x8000:seen.add('xor')
        elif prim==50:seen.add('lfd')
        elif prim==63:
            xo=(value>>1)&1023
            if xo==_FPUN_FCTIWZ_XO:return False
            if xo==_FPUN_FSUB_XO:seen.add('fsub')
            elif xo==_FPUN_FRSP_XO:seen.add('frsp')
    return seen>= {'xor','lfd','fsub','frsp'}


def m_fconv_pun(text,target=None):
    """Rewrite int->float casts as magic-double union bit-puns.

    Seeds spell int->float as arithmetic casts (`(f32)(f64)x`, `(f64)x`,
    `(f32)x`), which MWCC lowers through fctiwz. Some targets instead
    carry the classic bit-pun (Sphere__ResetProperties twice: xoris
    0x8000 sign flip, stack pair with 0x43300000 high, lfd, fsub the
    rodata double 4503601774854144.0, frsp) with no fctiwz at all, and no
    pun family exists anywhere. Each yield rewrites exactly one cast to
    an equivalent statement-expression union pun (the operand is
    evaluated once); the constant is read off live rodata, exact. Like
    reassociation this is a scored hypothesis, exact match deciding.
    Cap 2, float-scented lines only.
    """
    if target is None:
        evaluator=current_evaluator.get()
        target=getattr(evaluator,'target',None) if evaluator is not None else None
    if not _fpun_wanted(target):return
    yield from _fconv_pun_moves(text)


def _fpun_paren(line, pos):
    """Balanced paren group starting at pos, or None (never crosses ;{}")."""
    depth = 0
    for end in range(pos, len(line)):
        char = line[end]
        if char == '(':
            depth += 1
        elif char == ')':
            depth -= 1
            if depth == 0:
                return line[pos:end + 1]
        elif char in ';{}"':
            return None
    return None

# Stack-slot integer evidence for the pun paren pass: m2c stack int
# temps (spNN) carry no temp_r-style name, but a bitwise operator (&,
# |, >>, <<) proves integer operands (floats cannot shift or bit-and;
# FogFx-style (f32)(f64)(sp & mask) seeds fired nothing before this).
_FPUN_SP = re.compile(r'\bsp\d+\b')

_FPUN_BITOP = re.compile(r'(?<!&)&(?!&)|(?<!\|)\|(?!\|)|>>|<<')


def _fpun_spbit(inner):
    """True for spNN-headed bitwise integer operands.

    A lone & is address-of unless a value precedes it (identifier
    char, digit, ) or ]); && / || / &= / |= never match the guarded
    patterns (the = cases are vetoed upstream). Shifts need no context
    (adjacent >> / << cannot be comparisons). Residual: (T)&sp (cast
    of an address) reads as binary; unobserved in corpus, and a
    misfire scores low like any wrong-value hypothesis.
    """
    if _FPUN_SP.search(inner) is None:
        return False
    for match in _FPUN_BITOP.finditer(inner):
        if match.group() in ('>>', '<<'):
            return True
        j = match.start() - 1
        while j >= 0 and inner[j] in ' \t':
            j -= 1
        if j >= 0 and (inner[j].isalnum() or inner[j] == '_'
                       or inner[j] in ')]'):
            return True
    return False


def _fpun_intexpr(inner):
    """True for a paren-wrapped integer arithmetic operand.

    Requires int evidence (int temps, int-typed field loads, or
    sp-slot-headed bitwise operands) and vetoes anything float (float
    temps, float field loads, float literals, unknown-typed lbl_
    globals, member access) plus sequencing hazards (assignments,
    ternaries, inc/dec, volatile, error markers). The pun evaluates
    its operand once, parenthesized, so anything passing here converts
    exactly like the original cast.
    """
    if re.search(r'[;{}"=?]|\.|\->|volatile|M2C_ERROR|\+\+|--', inner):
        return False
    if not (re.search(r'\b(?:temp|var)_r\w*|'+_FPUN_MFC+_FPUN_INTT, inner)
            or _fpun_spbit(inner)):
        return False
    if re.search(r'\b(?:temp|var)_f\w*|'+_FPUN_MFC+_FPUN_FLTT
                 +r'|\blbl_[0-9A-Fa-f]+', inner):
        return False
    return True


def _fpun_file_scope(lines, idx):
    """True when line idx sits outside any brace block (file scope).

    The pun yield declares a union inside a statement expression,
    which is illegal outside a function body (uncompiling text).
    """
    depth = 0
    for ln in lines[:idx]:
        code = re.sub(r'"(?:[^"\\]|\\.)*"', '""', ln.split('//')[0])
        depth += code.count('{') - code.count('}')
    return depth <= 0


def _fconv_pun_moves(text):
    lines=text.split('\n')
    yielded=0
    for i,line in enumerate(lines):
        if yielded>=FPUN_CAP:break
        if not _FLOAT_SCENT.search(line):continue
        if 'M2C_ERROR' in line:continue
        if _fpun_file_scope(lines, i):continue
        for match in _FPUN_CASTKW.finditer(line):
            if yielded>=FPUN_CAP:break
            tail = line[match.end():]
            gap = len(tail) - len(tail.lstrip())
            if not tail.lstrip().startswith('('):
                continue
            group = _fpun_paren(line, match.end() + gap)
            if group is None:
                continue
            if not _fpun_intexpr(group[1:-1]):
                continue
            narrow = match.group().startswith('(f32)')
            candidate=lines[:]
            candidate[i]=(line[:match.start()]
                          +_fpun_text(group, f'u_b2pun{i}', narrow)
                          +line[match.end() + gap + len(group):])
            yield 'fconv_pun', '\n'.join(candidate);yielded+=1
        # Longest shape first; the bare casts skip anything already
        # covered so one site yields exactly one spelling.
        dcasts=[match for match in _FPUN_DCAST.finditer(line)]
        for match in dcasts:
            if yielded>=FPUN_CAP:break
            yield _fpun_yield(lines,i,line,match,match['x'],True)
            yielded+=1
        spans=[match.span() for match in dcasts]
        for match in _FPUN_FCAST.finditer(line):
            if yielded>=FPUN_CAP:break
            if any(start<=match.start() and match.end()<=end
                   for start,end in spans):continue
            spans.append(match.span())
            yield _fpun_yield(lines,i,line,match,match['x'],False)
            yielded+=1
        for match in _FPUN_SCAST.finditer(line):
            if yielded>=FPUN_CAP:break
            if any(start<=match.start() and match.end()<=end
                   for start,end in spans):continue
            yield _fpun_yield(lines,i,line,match,match['x'],True)
            yielded+=1


def _fpun_text(x, name, narrow):
    return ('({ union { u32 w[2]; f64 d; } '+name+'; '+name+'.w[0] = 0x43300000u; '
            +name+'.w[1] = (u32)('+x+') ^ 0x80000000u; '
            +('(f32)(' if narrow else '(')+name+'.d - '+_FPUN_MAGIC+'); })')


def _fpun_yield(lines,i,line,match,x,narrow):
    candidate=lines[:]
    candidate[i]=line[:match.start()]+_fpun_text(x, f'u_b2pun{i}', narrow)+line[match.end():]
    return 'fconv_pun','\n'.join(candidate)

FCMP_CAP = 4

_FCMP_XO = frozenset((0, 32))  # fcmpu, fcmpo

_FCMP_DUAL = {'<': '>=', '>': '<=', '<=': '>', '>=': '<'}

# Member-tailed operand for this family only (shared _ATOM untouched):
# p->x and p->q->x match whole, so the dual never splits an access.
# s.v already rides inside _ATOM's dotted names.
_FCMP_ATOM = r'(?:'+_ATOM+r'(?:->[A-Za-z_]\w*)*)'

_FCMP_OP = re.compile(r'(?P<a>'+_FCMP_ATOM+r')\s*(?P<op><=|>=|<|>)\s*(?P<b>'+_FCMP_ATOM+r')')

_FCMP_NEG = re.compile(r'!\(\s*(?P<a>'+_FCMP_ATOM+r')\s*(?P<op><=|>=|<|>)\s*(?P<b>'+_FCMP_ATOM+r')\s*\)')


def _fcmp_wanted(target):
    """Target compares FP values: fcmpu (unordered) or fcmpo (ordered).
    Only a negated ordered compare can add or remove that shape."""
    try:words=list(target)
    except TypeError:return False
    for word in words:
        try:value=int(word)&0xffffffff
        except (TypeError,ValueError):continue
        if value>>26==63 and (value>>1)&1023 in _FCMP_XO:return True
    return False


def _fcmp_member(line,start):
    """A match starting after -> or . would split a member access, and one
    starting after [ would rewrite a subscript index into a boolean. A
    match starting after an arithmetic operator is a chain fragment, not
    a whole comparison: swapping or dualing `b < c` inside `a + b < c`,
    `-a < b`, or `a * b < c` emits compiling wrong code (measured:
    `t0 + t2 > t1`, `-t1 > t0`, `t0 * t2 > t1`). Dereference splits
    (`*p < x` -> `*x > p`) die on the same `*` edge."""
    return re.search(r'(?:->|\.|\[|[*/%+-])\s*$',line[:start]) is not None


def _fcmp_wrapped(line,start,end):
    """A match that is the direct content of !(...) belongs to the
    un-negating rule, not the negating one."""
    return (re.search(r'!\(\s*$',line[:start]) is not None
            and re.match(r'\s*\)',line[end:]) is not None)


def _fcmp_trail(line,end):
    """A match running into -> . ( [ continues into member/call/subscript."""
    return re.match(r'\s*(?:->|\.|\(|\[)',line[end:]) is not None


def m_fcmp_negate(text,target=None):
    """Float ordered-compare De Morgan duals, gated on target compare evidence.

    MWCC selects the fcmpu CR field and branch from the written form:
    measured here, `a < b` is 4 words on cr7 while `!(a >= b)` is 6 words
    on cr0, so seeds with the dual of the original miss by 2+ words per
    compare (Cube__ClipSegmentStart carries 16 fcmpu). Each yield rewrites
    exactly one ordered compare to its dual, adding or removing one outer
    negation; ==/!= are skipped (measured identical either way) as are
    member-access operands (a later angle). NaN inputs distinguish the
    duals, so like reassociation this is a scored hypothesis, exact match
    deciding. Cap 4, float-scented lines only. A second wide pass duals
    whole !(S op L) conditions whose operands are composite (sums,
    calls, casts: AvatarControls__BeginExplosionGrapple spells its only
    compare as !((sum) <= lbl), unreachable to the atom rule); the dual
    never modifies S or L so delimitation is the only risk, handled by
    balanced-paren scanning with redundant-wrap stripping. Cap 2.
    """
    if target is None:
        evaluator=current_evaluator.get()
        target=getattr(evaluator,'target',None) if evaluator is not None else None
    if not _fcmp_wanted(target):return
    yield from _fcmp_negate_moves(text)
    yield from _fcmp_negate_wide_moves(text)


def _fcmp_negate_moves(text):
    lines=text.split('\n')
    yielded=0
    for i,line in enumerate(lines):
        if yielded>=FCMP_CAP:break
        if not _FLOAT_SCENT.search(line):continue
        for match in _FCMP_NEG.finditer(line):
            if yielded>=FCMP_CAP:break
            if _fcmp_member(line,match.start('a')):continue
            if _fcmp_trail(line,match.end('b')):continue
            dual=_FCMP_DUAL[match['op']]
            new=match['a']+' '+dual+' '+match['b']
            candidate=lines[:]
            candidate[i]=line[:match.start()]+new+line[match.end():]
            yield 'fcmp_negate','\n'.join(candidate);yielded+=1
        for match in _FCMP_OP.finditer(line):
            if yielded>=FCMP_CAP:break
            if _fcmp_member(line,match.start()):continue
            if _fcmp_wrapped(line,match.start(),match.end()):continue
            # Spaced bangs (! (...)) belong to the wide pass: negating
            # here double-wraps (!(a>=b)), which no live single compare
            # shows. (Swap keeps firing there: !(b>a) is a clean single.)
            if re.search(r'!\s*\(\s*$',line[:match.start()]):continue
            if _fcmp_trail(line,match.end()):continue
            dual=_FCMP_DUAL[match['op']]
            new='!('+match['a']+' '+dual+' '+match['b']+')'
            candidate=lines[:]
            candidate[i]=line[:match.start()]+new+line[match.end():]
            yield 'fcmp_negate','\n'.join(candidate);yielded+=1

_FCMP_WIDE_CAP = 2


def _fcmp_matching(text, open_at):
    """Index of the paren matching text[open_at], or -1.

    String and char literals are opaque: an unbalanced paren inside
    one must not move the depth count.
    """
    depth = 0
    quote = None
    j = open_at
    while j < len(text):
        ch = text[j]
        if quote is not None:
            if ch == '\\':
                j += 2
                continue
            if ch == quote:
                quote = None
        elif ch in ('"', "'"):
            quote = ch
        elif ch == '(':
            depth += 1
        elif ch == ')':
            depth -= 1
            if depth == 0:
                return j
        j += 1
    return -1


def _fcmp_wide_split(content):
    """Split a whole !(...) condition into (S, op, L), or None.

    Redundant fully-wrapping parens are stripped first then the content
    must hold exactly one top-level ordered compare (==/!= skipped like
    the atom rule) with no top-level combiner, ternary, comma or
    assignment. Operands stay verbatim: the dual only flips the
    operator, so composite sums, calls, casts, strings and member
    access are all safe; only correct delimitation matters.
    """
    text = content.strip()
    while text.startswith('(') and _fcmp_matching(text, 0) == len(text) - 1:
        text = text[1:-1].strip()
        if not text:
            return None
    ops = []
    depth = 0
    quote = None
    i = 0
    while i < len(text):
        ch = text[i]
        if quote is not None:
            if ch == '\\':
                i += 2
                continue
            if ch == quote:
                quote = None
        elif ch in ('"', "'"):
            quote = ch
        elif ch in '([{':
            depth += 1
        elif ch in ')]}':
            depth -= 1
        elif depth == 0:
            two = text[i:i+2]
            if two in ('<=', '>='):
                ops.append((i, two))
                i += 2
                continue
            if two in ('==', '!=') or ch in '&|?:;,':
                return None
            if ch == '<' or ch == '>':
                if ch == '>' and i > 0 and text[i-1] == '-':
                    pass  # arrow tail, not a compare
                elif ch == '<' and text[i+1:i+2] == '<':
                    i += 2
                    continue  # shift, not a compare
                elif ch == '>' and text[i+1:i+2] == '>':
                    i += 2
                    continue  # shift, not a compare
                else:
                    ops.append((i, ch))
            elif ch == '=':
                return None  # assignment, not a compare
        i += 1
    if len(ops) != 1:
        return None
    at, op = ops[0]
    s, l = text[:at].strip(), text[at+len(op):].strip()
    if not s or not l:
        return None
    return s, op, l


def _fcmp_negate_wide_moves(text):
    lines = text.split('\n')
    yielded = 0
    for i, line in enumerate(lines):
        if yielded >= _FCMP_WIDE_CAP:
            break
        if not _FLOAT_SCENT.search(line):
            continue
        at = 0
        while at < len(line):
            if yielded >= _FCMP_WIDE_CAP:
                break
            bang = line.find('!', at)
            if bang < 0:
                break
            j = bang + 1
            while j < len(line) and line[j] in ' \t':
                j += 1
            if j >= len(line) or line[j] != '(':
                at = bang + 1
                continue
            if _FCMP_NEG.match(line, bang):
                at = bang + 1
                continue  # atom rule owns this site
            close = _fcmp_matching(line, j)
            if close < 0:
                at = bang + 1
                continue
            split = _fcmp_wide_split(line[j+1:close])
            if split is None:
                at = bang + 1
                continue
            s, op, l = split
            candidate = lines[:]
            candidate[i] = line[:bang] + s + ' ' + _FCMP_DUAL[op] + ' ' + l + line[close+1:]
            yield 'fcmp_negate', '\n'.join(candidate)
            yielded += 1
            at = close + 1

FCSWAP_CAP = 4

_FCMP_SWAP = {'<': '>', '>': '<', '<=': '>=', '>=': '<='}


def m_fcmp_swap(text,target=None):
    """Float ordered-compare operand swaps, gated on target compare evidence.

    MWCC emits fcmpu operands as written (measured on byte-matched
    Math__AbsGreaterThan, Rand__RangeFloat, Vector3__ZeroTinyComponents:
    direct `a < b` is fcmpu crD,a,b while the swapped source would be
    fcmpu crD,b,a), so `b > a` is a distinct shape from `a < b` with
    identical semantics including NaN. The RA/RB order changes pseudo
    creation order, a lever on FPR coloring ties the other spellings cannot
    move: Avatar__GetRelativeDirectionRatio sits at 90.4% on a pure f11/f12
    swap of divisor-vs-zero across `!(q >= ZERO)` tails, immune to
    declaration/temp/register/statement-order tries, and no tried variant
    ever spelled the comparands swapped. Each yield swaps exactly one
    ordered compare, direct or negated; ==/!= are skipped (measured
    identical either way) as are member-access splits and subscript
    indices. Cap 4, float-scented lines only.
    """
    if target is None:
        evaluator=current_evaluator.get()
        target=getattr(evaluator,'target',None) if evaluator is not None else None
    if not _fcmp_wanted(target):return
    yield from _fcmp_swap_moves(text)


def _fcmp_swap_moves(text):
    lines=text.split('\n')
    yielded=0
    for i,line in enumerate(lines):
        if yielded>=FCSWAP_CAP:break
        if not _FLOAT_SCENT.search(line):continue
        neg_spans=[match.span() for match in _FCMP_NEG.finditer(line)]
        for match in _FCMP_NEG.finditer(line):
            if yielded>=FCSWAP_CAP:break
            if _fcmp_member(line,match.start('a')):continue
            if _fcmp_trail(line,match.end('b')):continue
            swap=_FCMP_SWAP[match['op']]
            new='!('+match['b']+' '+swap+' '+match['a']+')'
            candidate=lines[:]
            candidate[i]=line[:match.start()]+new+line[match.end():]
            yield 'fcmp_swap','\n'.join(candidate);yielded+=1
        for match in _FCMP_OP.finditer(line):
            if yielded>=FCSWAP_CAP:break
            if _fcmp_member(line,match.start()):continue
            if _fcmp_wrapped(line,match.start(),match.end()):continue
            if _fcmp_trail(line,match.end()):continue
            if any(start<=match.start() and match.end()<=end
                   for start,end in neg_spans):continue
            swap=_FCMP_SWAP[match['op']]
            new=match['b']+' '+swap+' '+match['a']
            candidate=lines[:]
            candidate[i]=line[:match.start()]+new+line[match.end():]
            yield 'fcmp_swap','\n'.join(candidate);yielded+=1

FCEQSWAP_CAP = 4

_FCMP_EQOP = re.compile(r'(?P<a>'+_FCMP_ATOM+r')\s*(?P<op>==|!=)\s*(?P<b>'+_FCMP_ATOM+r')')


def m_fcmp_eqswap(text,target=None):
    """Float equality-compare operand swaps, gated on target compare evidence.

    Re-measured on this project's MWCC: `a == b` emits fcmpu with RA/RB
    as written while `b == a` swaps the RA/RB encoding (and likewise
    !=), so equality operand order is a distinct shape with
    unconditionally identical semantics: ==/!= commute in IEEE 754 for
    every input including NaN and signed zeros, the strongest safety
    basis of any float family (no dual map, no negation, values
    bit-identical). The RA/RB order moves FPR coloring ties the other
    spellings cannot (same Avatar Ratio f11/f12 class as the ordered
    swap). Each yield swaps exactly one ==/!=, direct or inside !(...):
    the wrapped skip is deliberately absent because !(a==b) and a!=b
    compile byte-identically (measured), so unlike the ordered case no
    un-negating rule owns the site. Same member/trail guards as the
    ordered swap, same _fcmp_wanted gate, self-compares skipped. Cap 4,
    float-scented lines only.
    """
    if target is None:
        evaluator=current_evaluator.get()
        target=getattr(evaluator,'target',None) if evaluator is not None else None
    if not _fcmp_wanted(target):return
    yield from _fcmp_eqswap_moves(text)


def _fcmp_eqswap_moves(text):
    lines=text.split('\n')
    yielded=0
    for i,line in enumerate(lines):
        if yielded>=FCEQSWAP_CAP:break
        if not _FLOAT_SCENT.search(line):continue
        for match in _FCMP_EQOP.finditer(line):
            if yielded>=FCEQSWAP_CAP:break
            if _fcmp_member(line,match.start()):continue
            if _fcmp_trail(line,match.end()):continue
            if match['a'].strip()==match['b'].strip():continue
            new=match['b']+' '+match['op']+' '+match['a']
            candidate=lines[:]
            candidate[i]=line[:match.start()]+new+line[match.end():]
            yield 'fcmp_eqswap','\n'.join(candidate);yielded+=1
