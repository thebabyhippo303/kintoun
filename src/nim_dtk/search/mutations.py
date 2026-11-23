"""TKV5 real-C proposal families distilled from engine notes. Every proposal must compile and score."""
import itertools
import re
from contextvars import ContextVar
from nim_dtk.search.repairs import hypotheses

# The search evaluator for the current thread, published by engine.install's
# search wrapper (same ContextVar the directed() path already uses). Lets a
# blind FAMILIES entry read target-instruction evidence without changing the
# single-argument family protocol. Outside a wrapped search it stays None.
current_evaluator=ContextVar('tkv5_fma_target',default=None)


def recover_pointer_seeds(text):
    """m2c can emit **(s32 *)expr, which dereferences a scalar and cannot compile.
    Offer both scalar and pointer-valued interpretations; scoring chooses the layout.
    """
    pattern=r'\*\s*\*\s*\(\s*(s32|u32|int|f32|float|s16|u16|s8|u8)\s*\*\s*\)'
    if not re.search(pattern,text):return []
    return [re.sub(pattern,lambda m:'**('+m[1]+' **)',text),
            re.sub(pattern,'**(void ***)',text)]


def recover_load_seeds(text):
    """Typed FP destination provides a candidate load type for m2c's invalid void deref."""
    types={m[2]:m[1] for m in re.finditer(r'^\s*(f32|f64|float|double)\s+(\w+)\s*;',text,re.M)}
    def edit(match):
        name,expression=match[2],match[3]
        if name not in types:return match[0]
        depth=0
        for char in expression:
            if char=='(':depth+=1
            elif char==')':depth-=1
            if depth<0:return match[0]  # Already has a cast, e.g. *(f32 *)(expr).
        if depth or any(c in expression for c in '\"\'{};'):return match[0]
        return match[1]+name+' = *('+types[name]+' *)('+expression+');'
    variant=re.sub(r'^(\s*)(\w+) = \*\(([^\n]+)\);',edit,text,flags=re.M)
    return [variant] if variant!=text else []


def m_extern_const(text):
    """CCameraAvatar note: readonly float externs can stay in FP registers across stores."""
    for match in re.finditer(r'^extern (f32|f64|float|double) (\w+)([^;\n]*);',text,re.M):
        if re.search(r'\b'+re.escape(match[2])+r'\s*(?:[+*/-]?=|\+\+|--)',text):continue
        yield 'extern_const',text[:match.start(1)]+'const '+text[match.start(1):]


def m_fp_prototype(text):
    """Near-miss note: sweep complete 1-4 FP argument mode combinations, not only one flip."""
    patterns=[r'(\(\s*\*\s*\w*\s*\)\s*\()([^()]*)\)', r'^((?:extern )?[\w *]+\s+\w+\s*\()([^(){};]*)\)\s*;']
    for match in itertools.chain.from_iterable(re.finditer(pattern,text,re.M) for pattern in patterns):
        args=match[2].split(',');places=[i for i,a in enumerate(args) if re.search(r'\b(f32|f64|float|double)\b',a)]
        if not 1<=len(places)<=4:continue
        for modes in itertools.product(('f32','f64'),repeat=len(places)):
            changed=args[:]
            for i,mode in zip(places,modes):changed[i]=re.sub(r'\b(f32|f64|float|double)\b',mode,changed[i])
            replacement=','.join(changed)
            if replacement!=match[2]:yield 'fp_prototype',text[:match.start(2)]+replacement+text[match.end(2):]


def m_index_address(text):
    """UIList/Bilinear notes: offer explicit scaled-byte addressing and both operand orders."""
    types={}
    for match in re.finditer(r'\b(f32|float|s32|u32|int|f64|double|s16|u16|s8|u8)\s*\*\s*(\w+)\b',text):types[match[2]]=match[1]
    widths={'s8':0,'u8':0,'s16':1,'u16':1,'s32':2,'u32':2,'int':2,'f32':2,'float':2,'f64':3,'double':3}
    for match in re.finditer(r'\b(\w+)\[([A-Za-z_]\w*)\]',text):
        if match[1] not in types:continue
        typ=types[match[1]];index=match[2];base=match[1];shift=widths[typ]
        offset=f'({index} << {shift})' if shift else index
        for address in (f'(char *){base} + {offset}',f'{offset} + (s32){base}',f'(s32){base} + {offset}'):
            yield 'index_address',text[:match.start()]+f'*({typ} *)({address})'+text[match.end():]
    for match in re.finditer(r'\*\((f32|float|s32|u32|f64|double) \*\)\s*\((\w+) \+ \((\w+) \* (4|8)\)\)',text):
        typ,base,index,width=match.groups();offset=f'({index} << {2 if width=="4" else 3})'
        for address in (f'{offset} + (s32){base}',f'(s32){base} + {offset}',f'(char *){base} + {offset}'):
            yield 'index_address',text[:match.start()]+f'*({typ} *)({address})'+text[match.end():]


def m_narrow_return(text):
    for match in re.finditer(r'^(M2C_UNK|s32|u32|int) (\w+)\([^;{}]*\);',text,re.M):
        for typ in ('s16','u16'):
            yield 'narrow_return',text[:match.start(1)]+typ+text[match.end(1):]


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
        # One yield per switch by construction (no loop); the per-head
        # budget is structural, so no counter is needed.


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
