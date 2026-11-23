"""Small, source-only repairs for malformed m2c engine seeds.

Each repair retains the original seed as a search alternative. No target bytes,
matched implementation, or compiler flags are changed here.
"""
from __future__ import annotations

import re


_CARRY = re.compile(r'\(0\s*-\s*([A-Za-z_]\w*)\)\s*\+\s*\1\s*\+\s*M2C_CARRY')
_INDEXED_WORD = re.compile(r'\*\(\([^;\n]+?\)\s*\+\s*M2C_FIELD\([^;()\n]+\)\)')
_STACK_REF = re.compile(r'\b(sp\d+)\s*\[')
_STACK_DECL = re.compile(r'\b(?:char|[us](?:8|16|32)|int|float|f32|f64)\s+(sp\d+)\s*\[')
_VOID_POINTER_PROTO = re.compile(r'^\s*(?:extern\s+)?void\s*\*\s*([A-Za-z_]\w*)\s*\(', re.M)
# b4: unary deref of m2c byte-scaled integer arithmetic: *(((s8) i * 4) + base)
_SCALED_DEREF = re.compile(r'(\((f32|f64|[us](?:8|16|32))\)\s*)?(?<![\w)\]])\*\(\(\(?[^;\n]*?\*\s*([248])\)')
# b4: unary deref of an absolute address: *(0x8033C9D9 + i)
_ABS_DEREF = re.compile(r'(?<![\w)\]])\*\((0x[0-9A-Fa-f]{8}\s*\+)')
_SAVED_REG = re.compile(r'\bsaved_reg_(r\d+)\b')
_SCALE_TYPE = {'2': 's16', '4': 's32', '8': 'f64'}


def repair_seed(text: str, name: str, address: int) -> str:
    """Repair evidenced syntax faults before the first ProDG compile.

    A call to the target entry is recursive, never a C symbol named `.L_addr`.
    `subfic x,0; adde x,x,...` materializes the zero predicate in m2c's
    M2C_CARRY form. Indexed word loads need an explicit pointer cast when m2c
    has represented the base address as a scalar. Missing spN arrays are
    minimal stack objects; scoring, not this repair, judges their layout.
    """
    entry = f'.L_{address:08X}'
    text = re.sub(r'^[^;\n]*' + re.escape(entry) + r'\([^;\n]*\);\s*\n',
                  '', text, flags=re.M)
    text = re.sub(r'\.L_([0-9A-Fa-f]{8})\b',
                  lambda m: name if int(m[1], 16) == address else m[0], text)
    text = _CARRY.sub(lambda m: f'({m[1]} == 0)', text)
    floats = set(re.findall(r'^extern (?:const )?f32 (\w+)', text, re.M)) | set(re.findall(r'^\s+f32 (\w+);', text, re.M))
    float_unions = set(re.findall(r'union \{ f32 value;[^}]*\} (\w+);', text)) | set(re.findall(r'mt_vec3_f32 (\w+);', text))
    def float_lhs(start):
        line = text[text.rfind('\n', 0, start) + 1:start]
        lhs = re.fullmatch(r'\s*(\w+)(?:\.(value|v[012]))? = ', line)
        return bool(lhs) and (lhs[1] in floats or (lhs[2] is not None and lhs[1] in float_unions))
    def indexed(m):
        # b4: an indexed word feeding float arithmetic (`* lbl_F`, `+ temp_f`) or stored
        # straight into an f32 lvalue is an f32 element (lfsx)
        nxt = re.match(r'\s*[-+*/]\s*\(?(\w+)', text[m.end():])
        use = nxt and (nxt[1] in floats or re.fullmatch(r'(?:temp|var)_f\w*', nxt[1]))
        converted = re.search(r'\((?:f64|f32)\)\s*$', text[:m.start()])  # an int being converted to float
        elem = 'f32' if (use or float_lhs(m.start())) and not converted else 's32'
        return m[0].replace('*(', f'*({elem} *)(', 1)
    text = _INDEXED_WORD.sub(indexed, text)
    for callee in set(_VOID_POINTER_PROTO.findall(text)):
        # m2c sometimes dereferences a void*-returning callee in a scalar
        # assignment. The explicit scalar cast supplies the load width.
        pattern = re.compile(r'\(([us](?:8|16|32)|f32|f64)\)\s*\*\s*' +
                             re.escape(callee) + r'\s*\(')
        text = pattern.sub(lambda m: f'*({m[1]} *){callee}(', text)
    text = _repair_b4(text, name, address)
    text = _repair_b4_spill(text)
    text = _repair_b4_types(text)
    text = _repair_b4_stray_case(text)
    text = _repair_b4_div_guard(text)
    text = _repair_b4_vtable_arg(text)
    text = _repair_b4_vcall_arity(text)
    text = _repair_b4_byte_index_temps(text)
    missing = sorted(set(_STACK_REF.findall(text)) - set(_STACK_DECL.findall(text)))
    if missing:
        signature = re.search(r'\b' + re.escape(name) + r'\s*\([^{};]*\)\s*\{', text)
        if signature:
            declarations = ''.join(f'\n    s32 {local}[4];' for local in missing)
            text = text[:signature.end()] + declarations + text[signature.end():]
    return text


def _repair_b4(text: str, name: str, address: int) -> str:
    """Bench compile-failure classes (builder 4): seeds that never compile.

    A `.L_addr` call into another function's body is a C call to that address.
    m2c byte-scaled indexed loads and absolute-address loads get an explicit
    element pointer (scale 4 -> s32, 2 -> s16; an unscaled absolute table is a
    byte table; an explicit (f32) conversion means a float element). An
    undeclared `saved_reg_rN` is a caller-held pointer. A signature that starts
    at arg1 lost an unused leading r3 argument.
    """
    text = re.sub(r'\.L_([0-9A-Fa-f]{8})\b', lambda m: f'fn_{m[1].upper()}', text)
    # A renamed label can duplicate an existing fn_ prototype; drop repeats.
    seen, lines = set(), []
    for line in text.split('\n'):
        key = line.strip()
        if re.match(r'^M2C_UNK fn_[0-9A-F]{8}\(', key) and key in seen: continue
        seen.add(key); lines.append(line)
    text = '\n'.join(lines)
    floats = set(re.findall(r'^extern (?:const )?f32 (\w+)', text, re.M)) | set(re.findall(r'^\s+f32 (\w+);', text, re.M))
    def float_use(end):
        # the deref feeds float arithmetic: `<deref> * lbl_F` / `+ temp_f1` with an f32 operand
        depth, k = 1, end
        while k < len(text) and depth:
            depth += {'(': 1, ')': -1}.get(text[k], 0)
            k += 1
        nxt = re.match(r'\s*[-+*/]\s*\(?(\w+)', text[k:])
        return bool(nxt) and (nxt[1] in floats or re.fullmatch(r'(?:temp|var)_f\w*', nxt[1]) is not None)
    def scaled(m):
        cast, kind, scale = m[1] or '', m[2], m[3]
        elem = kind if kind in ('f32', 'f64') else _SCALE_TYPE[scale]
        if elem == 's32' and not cast and float_use(m.start() + 2) and not re.search(r'\((?:f64|f32)\)\s*$', text[:m.start()]):
            elem = 'f32'
        return f'{cast}*({elem} *)(({m[0][len(cast) + 3:]}'
    text = _SCALED_DEREF.sub(scaled, text)
    # Pointer difference divided by a struct size (multiply by magic inverse).
    text = re.sub(r'\(\(([A-Za-z_]\w*) - (M2C_FIELD\([^;()\n]+\)|[A-Za-z_]\w*)\) \* (0x[0-9A-Fa-f]{8})\)',
                  lambda m: f'(((s32) {m[1]} - (s32) {m[2]}) * {m[3]})', text)
    def absolute(m):
        # element width from the index scale of the whole sum: *(0x80.. + (i * 4)) is a word table
        depth, end = 1, m.end()
        while end < len(text) and depth:
            depth += {'(': 1, ')': -1}.get(text[end], 0)
            end += 1
        inner = text[m.start(1):end - 1]
        scale = re.search(r'\*\s*([24])\)\s*$', inner)
        if not scale:
            # b4: the index variable itself was scaled (idx = x * 4 / x << 2)
            idx = re.fullmatch(r'0x[0-9A-Fa-f]{8}\s*\+\s*(\w+)', inner.strip())
            pre = idx and re.search(r'^\s+' + idx[1] + r' = [^;]*(?:\* ([24])|<< ([12]));$', text, re.M)
            if pre:
                scale = ('4' if (pre[1] == '4' or pre[2] == '2') else '2',) * 2
        elem = _SCALE_TYPE[scale[1]] if scale else 'u8'
        return f'*({elem} *)({m[1]}'
    text = _ABS_DEREF.sub(absolute, text)
    # m2c applied a label's lo16 twice: `&lbl_80389240 - 0x6DC0` where lo16(0x80389240)
    # is -0x6DC0 means the register held the label's own address (lis + addi lo16)
    def lo16(m):
        address = int(m[1], 16)
        low = (address & 0xffff) - (0x10000 if address & 0x8000 else 0)
        k = int(m[3], 16) * (1 if m[2] == '+' else -1)
        return f'&lbl_{m[1]}' if k == low and low else m[0]
    text = re.sub(r'&lbl_([0-9A-Fa-f]{8}) ([-+]) (0x[0-9A-Fa-f]+)\b', lo16, text)
    text = _repair_b4_large(text, name)
    if 'M2C_STRUCT_COPY(' in text and not re.search(r'#define\s+M2C_STRUCT_COPY\b', text):
        text = ('#define M2C_STRUCT_COPY(dst, src, size) ({ typedef struct { s32 w[(size) / 4]; } mt_copy_t; '
                '*(mt_copy_t *)(dst) = *(mt_copy_t *)(src); })\n' + text)
    text = _repair_b4_arity(text, name)
    saved = sorted(set(_SAVED_REG.findall(text)))
    signature = re.search(r'\b' + re.escape(name) + r'\s*\(([^{};]*)\)\s*\{', text)
    if signature:
        params = signature[1]
        parts = [p.strip() for p in params.split(',')] if params.strip() not in ('', 'void') else []
        numbered = [(int(n[0]), p) for p in parts for n in [re.findall(r'\barg(\d+)$', p)] if n]
        ints = [p for p in parts if re.search(r'\barg\d+$', p)]
        if numbered and len(numbered) == len(ints) and parts[:len(ints)] == ints and \
                [n for n, _ in numbered] != list(range(len(ints))):
            # Unused integer argument registers were dropped; refill every slot.
            have = dict(numbered)
            filled = [have.get(i, f'void *arg{i}') for i in range(max(have) + 1)]
            filled += [p for p in [q.strip() for q in params.split(',')] if not re.search(r'\barg\d+$', p)]
            text = text[:signature.start(1)] + ', '.join(filled) + text[signature.end(1):]
            signature = re.search(r'\b' + re.escape(name) + r'\s*\(([^{};]*)\)\s*\{', text)
        if saved and not re.search(r'\b(?:char|void|s32)\s*\*?\s*saved_reg_', text):
            decl = ''.join(f'\n    char *saved_reg_{r};' for r in saved)
            text = text[:signature.end()] + decl + text[signature.end():]
    return text


def _repair_b4_spill(text: str) -> str:
    """m2c gives a reused register spill slot (`f32 sp164; /* compiler-managed */`)
    one type, so a slot that holds a float in one live range and an integer or
    pointer register in another (`sp164 = temp_r6_5;`, `M2C_FIELD(sp164, ...)`)
    fails the compile ('incompatible types in assignment', 'cannot convert to a
    pointer type'; 8/124 bench first seeds). Each live range that starts with a
    store of an int/pointer temp becomes its own local of that temp's type
    (spill slots are compiler-managed, so splitting them changes no layout)."""
    types = {m[2]: m[1].strip() for m in re.finditer(
        r'^\s+((?:[us](?:8|16|32|64)|f32|f64|M2C_UNK|void|\w+)(?: \*+| )\s*)(\w+);', text, re.M)}
    for decl in list(re.finditer(r'^(\s+)f32 (sp[0-9A-F]+);', text, re.M)):
        local = decl[2]
        lines = text.split('\n')
        current, split, kinds = None, False, {}
        for n, line in enumerate(lines):
            if not re.search(r'\b' + local + r'\b', line) or re.match(r'\s+f32 ' + local + ';', line):
                continue
            store = re.match(r'(\s+)' + local + r' = (\w+);', line)
            if store and not types.get(store[2], 'f32').startswith(('f32', 'f64')):
                kind = types[store[2]]
                if kind == 'M2C_UNK':
                    kind = 's32'
                current = kinds.setdefault(kind, f'{local}_{len(kinds)}')
                split = True
            elif re.match(r'\s+' + local + r' = ', line):
                current = None
            if current:
                lines[n] = re.sub(r'(?<![&\w])' + local + r'\b', current, line)
        if split:
            text = '\n'.join(lines)
            extra = ''.join(f'\n{decl[1]}{k}{"" if k.endswith("*") else " "}{v};' for k, v in kinds.items())
            end = text.index('\n', text.index(decl[0]))
            text = text[:end] + extra + text[end:]
    return text


def _repair_b4_types(text: str) -> str:
    """Seeds whose every draft fails on a type fault (builder 4 census: 8/124
    bench rows). `M2C_BITWISE(u64, x)` of a 32-bit x fails m2c's own width
    assert and is the plain conversion; `**(T *)p` on an int load means the
    word loaded is a pointer (`**(T **)p`); `*(int-field + k)` dereferences a
    word m2c typed as an integer (`*(s32 *)(...)`) or as void * (`*(void **)(...)`); `int - ptr` is a pointer
    difference whose left side m2c typed as an integer; an undeclared
    `saved_reg_fN` is a caller-held float."""
    types = {m[2]: m[1].strip() for m in re.finditer(
        r'^\s+((?:[us](?:8|16|32)|f32|M2C_UNK|void|\w+)(?: \*+| )\s*)(\w+);', text, re.M)}
    head = re.search(r'^[^\n;#=]*\b\w+\s*\(([^{};]*)\)\s*\{', text, re.M)
    for param in (head[1].split(',') if head else []):
        m = re.fullmatch(r'\s*((?:const )?\w+(?: \*+| )\s*)(\w+)\s*', param)
        if m and m[2] not in types:
            types[m[2]] = m[1].strip()
    narrow = {k for k, v in types.items() if v in ('s8', 'u8', 's16', 'u16', 's32', 'u32', 'f32', 'M2C_UNK')}
    # lhs = *(*(s32 *)(a + b) + i): the loaded word is a pointer to lhs's type
    text = re.sub(r'(\b(\w+) = )\*\(\*\(([us]32) \*\)\(',
                  lambda m: f'{m[1]}*({types[m[2]]} *)(*({m[3]} *)(' if types.get(m[2]) in ('s8', 'u8', 's16', 'u16', 's32', 'u32') else m[0], text)
    text = re.sub(r'M2C_BITWISE\(u64, (\w+)\)', lambda m: f'((u64) {m[1]})' if m[1] in narrow else m[0], text)
    # M2C_BITWISE(T, *p) where p points to a narrower type: the bits are T-wide memory at p
    globals_ = {m[2]: m[1].strip() for m in re.finditer(r'^extern ((?:[us](?:8|16)|char) \*)\s*(\w+);', text, re.M)}
    small = {k: v for k, v in {**globals_, **types}.items() if re.fullmatch(r'(?:[us](?:8|16)|char) \*', v)}
    text = re.sub(r'M2C_BITWISE\((f32|[us]32), \*(\w+)\)',
                  lambda m: f'(*({m[1]} *){m[2]})' if m[2] in small else m[0], text)
    text = re.sub(r'\*\*\(([us](?:8|16|32)|f32) \*\)\(', r'**(\1 **)(', text)
    text = re.sub(r'(=\s*)\*\((M2C_FIELD\([^()]*(?:\([^()]*\))?[^()]*, [us]32 \*, (?:0x[\dA-Fa-f]+|\d+)\) \+ )',
                  r'\1*(s32 *)(\2', text)
    # *(s32 *)(field + s8 index): an unscaled byte index addresses a byte array (a word
    # array scales its index by 4) - the AnimScript VM type-tag stack
    bytes_ = {k for k, v in types.items() if v in ('s8', 'u8')}
    def byte_elem(m):
        idx = m[3].strip()
        is_byte = idx.startswith('(s8) ') or idx.startswith('(u8) ') or idx in bytes_
        return f'*({"s8" if not idx.startswith("(u8) ") else "u8"} *)({m[2]} + {idx})' if is_byte else m[0]
    text = re.sub(r'\*\((s32|u32) \*\)\((M2C_FIELD\(\w+, [us]32 \*, (?:0x[\dA-Fa-f]+|\d+)\)) \+ ((?:\([us]8\) )?(?:M2C_FIELD\(\w+, [us]8 \*, (?:0x[\dA-Fa-f]+|\d+)\)|\w+))\)',
                  byte_elem, text)
    # storing a (f32) value through an int lvalue converts it back to int (fctiwz);
    # m2c means the float bits (VM value slots punned between s32 and f32)
    text = re.sub(r'^(\s+)\*\((?:s32|u32) \*\)(\([^;=]*\)) = \(f32\) ', r'\1*(f32 *)\2 = (f32) ', text, flags=re.M)
    text = re.sub(r'^(\s+)M2C_FIELD\(([^;=]*), (?:s32|u32) \*, (0x[0-9A-Fa-f]+|\d+)\) = \(f32\) ', r'\1M2C_FIELD(\2, f32 *, \3) = (f32) ', text, flags=re.M)
    fvars = {k for k, v in types.items() if v == 'f32'} | set(re.findall(r'^extern (?:const )?f32 (\w+)', text, re.M))
    def float_var_store(m):
        # an int-typed field assigned a plain f32 value is a punned float slot when the
        # same field is read back as M2C_BITWISE(f32, ..) somewhere
        field = f'M2C_FIELD({m[2]}, s32 *, {m[3]})'
        if m[4] in fvars and f'M2C_BITWISE(f32, {field})' in text:
            return f'{m[1]}M2C_FIELD({m[2]}, f32 *, {m[3]}) = {m[4]};'
        return m[0]
    text = re.sub(r'^(\s+)M2C_FIELD\((\w+), s32 \*, (0x[0-9A-Fa-f]+|\d+)\) = (\w+);$', float_var_store, text, flags=re.M)
    fptrs = {k for k, v in types.items() if v.replace(' ', '') == 'f32*'}
    text = re.sub(r'^(\s+\*(\w+) [-+*/]= )\*\((?:s32|u32) \*\)',
                  lambda m: m[1] + '*(f32 *)' if m[2] in fptrs else m[0], text, flags=re.M)
    # M2C_FIELD(*(int field + i * K), T, off): m2c's struct-element notation - as a field
    # base the element's address is meant, the unary * on an int is spurious
    text = re.sub(r'M2C_FIELD\(\*\((M2C_FIELD\([^()]*(?:\([^()]*\))?[^()]*, [us]32 \*, (?:0x[\dA-Fa-f]+|\d+)\) \+ \([^()]*\))\), ',
                  r'M2C_FIELD((\1), ', text)
    # *(&spN + E): m2c's byte offset into a stack buffer it typed as a scalar; scalar
    # pointer arithmetic scales E by the element size (s32: *4) - address it bytewise
    scalars = {k for k, v in types.items() if re.fullmatch(r'sp[0-9A-F]+', k) and v in ('s32', 'u32', 's16', 'u16', 'f32')}
    text = re.sub(r'\*\(&(sp[0-9A-F]+) \+ ([^()]+?)\)',
                  lambda m: f'*(s8 *)((u8 *)&{m[1]} + {m[2]})' if m[1] in scalars else m[0], text)
    # *(void-pointer field + k) is a word load (gcc byte-scales void * sums)
    text = re.sub(r'(?<![\w)])\*\((M2C_FIELD\([^()]*(?:\([^()]*\))?[^()]*, void \*\*, (?:0x[\dA-Fa-f]+|\d+)\) \+ )',
                  r'*(void **)(\1', text)
    pointers = {k: v for k, v in types.items() if v.endswith('*')}
    def difference(m):
        left, right = m[1], m[2]
        if right not in pointers or left in pointers or left.startswith('('):
            return m[0]
        if left in types and left not in narrow:
            return m[0]
        return f'({pointers[right]}) {left} - {right}'
    text = re.sub(r'(?<![\w)\]])((?:M2C_FIELD\(\w+, [us]32 \*, (?:0x[\dA-Fa-f]+|\d+)\))|\w+) - (\w+)\b(?!\s*[\[(])', difference, text)
    # (void-ptr - k) - other-ptr: incompatible pointer difference, taken bytewise
    text = re.sub(r'\((\w+) - (\w+)\) - (\w+)\b(?!\s*[\[(])',
                  lambda m: f'((s32) {m[1]} - {m[2]}) - (s32) {m[3]}' if pointers.get(m[1]) == 'void *' and m[3] in pointers
                  and pointers[m[3]] != 'void *' and m[2] not in pointers else m[0], text)
    floats = sorted(set(re.findall(r'\bsaved_reg_(f\d+)\b', text)) - set(re.findall(r'\bf\d+\s+saved_reg_(f\d+);', text)))
    signature = re.search(r'^[^\n;#]*\b\w+\s*\([^{};]*\)\s*\{', text, re.M)
    if floats and signature:
        decl = ''.join(f'\n    f32 saved_reg_{r};' for r in floats)
        text = text[:signature.end()] + decl + text[signature.end():]
    return text


def _repair_b4_stray_case(text: str) -> str:
    """m2c can print a jump-table label outside its switch (`} else {\n case 2:\n }`
    at the function end: that case leaves the function), which never compiles.
    Move each such label into the last switch closed before it as `case N: break;`."""
    lines = text.split('\n')
    stack, last_close, stray = [], None, []
    for n, line in enumerate(lines):
        code = re.sub(r'/\*.*?\*/|"(?:\\.|[^"\\])*"', '', line)
        case = re.match(r'\s*(case [^:]+|default):\s*$', code)
        if case and 'switch' not in stack:
            stray.append((n, case[1]))
        for ch in code:
            if ch == '{':
                stack.append('switch' if re.search(r'\bswitch\s*\(', code) and 'switch' not in stack[-1:] and code.rstrip().endswith('{') and code.count('{') == 1 else 'block')
            elif ch == '}' and stack:
                if stack.pop() == 'switch':
                    last_close = n
    if not stray or last_close is None or last_close > stray[0][0]:
        return text
    for n, label in reversed(stray):
        del lines[n]
    indent = re.match(r'\s*', lines[last_close])[0]
    lines[last_close:last_close] = [f'{indent}{label}:\n{indent}    break;' for _, label in stray]
    return '\n'.join(lines)


_UNSET_CR = re.compile(r'M2C_ERROR\(/\* Read from unset register \$cr\d_(eq|lt|gt) \*/\)')
_COMPARE = re.compile(r'\b(?:if|while) \(((?:\([us]\d+\) )?(?:M2C_FIELD\([^()]*\)|[\w.]+)) (==|!=|<=|>=|<|>) ((?:\([us]\d+\) )?(?:M2C_FIELD\([^()]*\)|[\w.]+))\)')
_BIT = {'eq': {'==': '==', '!=': '=='}, 'lt': {'<': '<', '>=': '<'}, 'gt': {'>': '>', '<=': '>'}}


def cr_reads(text: str) -> str:
    """A comparison kept in a non-volatile CR field (cmpwi cr4,r29,0 ... bl ...
    bne cr4) reaches m2c as `M2C_ERROR(/* Read from unset register $cr0_eq */)`,
    which compiles as 0 and deletes the branch with its calls (FluffLoop: 4 of
    7 calls). Use that bit of the nearest preceding comparison: an m2c
    `temp_crN_<bit>`/`var_crN_<bit> = ...` flag when one exists, else `if (a op b)` with an
    operator that tests the same bit. Reads with no such comparison stay."""
    def bit_of(m):
        bit, before = m[1], text[:m.start()]
        flags = re.findall(r'\b((?:temp|var)_cr\d_' + bit + r'(?:_\d+)?) = ', before)
        if flags:
            return flags[-1]
        for c in reversed(list(_COMPARE.finditer(before))):
            op = _BIT[bit].get(c[2])
            if op:
                return f'({c[1]} {op} {c[3]})'
            if bit == 'eq' or c[2] in ('==', '!='):
                continue
            break
        return m[0]
    return _UNSET_CR.sub(bit_of, text)


_DIV_GUARD = re.compile(r'(if \(\(s32\) \(u8\) \(M2C_BITWISE\(u32, (\w+)\) >> 0x17U\) != 0\) \{\n\s+\w+ = )0 \+ M2C_CARRY;')


def _repair_b4_div_guard(text: str) -> str:
    """An inlined float divide-overflow guard (vector normalize sites: a = sqrtf(..),
    b = 1.0f, both spilled; bad = exp(a) == 0 ? 1 : exp(b) >= exp(a) + 127 through
    rlwinm/addi/subfc/adde) reaches m2c with the carry compare lost: `var = 0 +
    M2C_CARRY`, which is 0 and kills the branch. b is the other stack float
    stored in the lines just above; rebuild the unsigned compare."""
    def fix(m):
        a = m[2]
        before = text[:m.start()].split('\n')[-5:]
        others = [x[1] for x in (re.match(r'\s+(sp[0-9A-F]+) = [^;]+;$', l) for l in before) if x and x[1] != a]
        if not others:
            return m[0]
        b = others[-1]
        return (f'{m[1]}(u32) (u8) (M2C_BITWISE(u32, {b}) >> 0x17U) >= '
                f'(u32) ((u8) (M2C_BITWISE(u32, {a}) >> 0x17U) + 0x7F);')
    return _DIV_GUARD.sub(fix, text)


def postdec_loop(text: str) -> str:
    """`do { ...; f = n == 0; n -= 1; ...; } while (f == 0);` is m2c's spelling of a
    post-decrement loop test kept in cr0 (target: cmpwi n,0 / addi n,-1 / ... / bne).
    As a C flag it costs subfic/adde + a second compare. When n is not used again
    before the loop's end, write `} while (n-- != 0);` and drop the flag."""
    lines = text.split('\n')
    for i, line in enumerate(lines):
        m = re.fullmatch(r'(\s+)(temp_cr\d_\w+) = (\w+) == 0;', line)
        if not m or i + 1 >= len(lines) or lines[i + 1].strip() != f'{m[3]} -= 1;':
            continue
        flag, n = m[2], m[3]
        end = next((k for k in range(i + 2, len(lines)) if lines[k].strip() == f'}} while ({flag} == 0);'), None)
        if end is None or len(re.findall(r'\b' + flag + r'\b', text)) != 3:
            continue
        if any(re.search(r'\b' + n + r'\b', lines[k]) for k in range(i + 2, end)):
            continue
        lines[end] = lines[end].replace(f'while ({flag} == 0)', f'while ({n}-- != 0)')
        lines[i] = lines[i + 1] = None
        lines = [l for l in lines if l is not None]
        lines = [l for l in lines if not re.fullmatch(r'\s+s32 ' + flag + ';', l)]
        return postdec_loop('\n'.join(lines))
    return '\n'.join(lines)


_VCALL = re.compile(r'M2C_FIELD\((\w+), ([^;]*?)\(\*\*\)\(([^()]*)\), (0x[0-9A-Fa-f]+|\d+)\)\(')


def _repair_b4_vtable_arg(text: str) -> str:
    """m2c types a virtual call from the registers live at the `blrl`, so when
    r4 still holds the vtable pointer it passes that vtable temp as a trailing
    argument (`M2C_FIELD(t, R (**)(void *, void *), 0x14)(obj + .., t)`): an
    extra `mr r4, rV` the target does not have. Drop a trailing argument that is
    the vtable temp itself, and its parameter in the function-pointer type."""
    out, pos = text, 0
    while True:
        m = _VCALL.search(out, pos)
        if not m:
            return out
        parsed = _call_args(out, m.end() - 1)
        params = [p.strip() for p in m[3].split(',')] if m[3].strip() else []
        if parsed and len(parsed[0]) >= 2 and parsed[0][-1] == m[1] and len(params) == len(parsed[0]):
            args, end = parsed
            head = f'M2C_FIELD({m[1]}, {m[2]}(**)({", ".join(params[:-1])}), {m[4]})('
            out = out[:m.start()] + head + ', '.join(args[:-1]) + ')' + out[end:]
            pos = m.start() + len(head)
        else:
            pos = m.end()


def _repair_b4_vcall_arity(text: str) -> str:
    """A virtual call whose function-pointer type lists more parameters than the
    call passes ('too few arguments to function'): m2c typed the pointer from
    every live argument register at some other call through the same slot.
    Trim the type to the arguments this call passes."""
    out, pos = text, 0
    while True:
        m = _VCALL.search(out, pos)
        if not m:
            return out
        parsed = _call_args(out, m.end() - 1)
        params = [p.strip() for p in m[3].split(',')] if m[3].strip() else []
        if parsed and len(parsed[0]) < len(params) and '...' not in params:
            args, end = parsed
            head = f'M2C_FIELD({m[1]}, {m[2]}(**)({", ".join(params[:len(args)]) or "void"}), {m[4]})('
            out = out[:m.start()] + head + out[m.end():]
            pos = m.start() + len(head)
        else:
            pos = m.end()


def _repair_b4_byte_index_temps(text: str) -> str:
    """m2c types a temp from its lbz (u8) - e.g. the AnimScript VM stack pointer
    read from a u8 field, decremented and used as a signed index `(s8) t`. As a
    u8 local every `t - 1` is re-truncated (clrlwi) before the stb / extsb; the
    original was an int. Retype u8 temps that are read through an (s8) cast as
    s32 (stores into the u8 field still truncate, the (s8) cast still extends):
    AnimScript__OpPlayAnimation 78 -> 43, 9/26 such rows better, 0 worse."""
    for name in [m[1] for m in re.finditer(r'^\s+u8 ((?:temp|var)_r\w+);', text, re.M)]:
        if re.search(r'\(s8\) ' + name + r'\b', text):
            text = re.sub(r'^(\s+)u8 ' + name + ';', r'\1s32 ' + name + ';', text, count=1, flags=re.M)
    return text


_VARARG_CALL = re.compile(r'\b(?:sprintf|printf|OSReport|snprintf|vsprintf)\s*\(')


def _repair_b4_large(text: str, name: str) -> str:
    """Compile-failure classes seen in >1K bench seeds (builder 4).

    switch on a pointer-typed temp, an undefined M2C_CARRY, stack temps
    referenced without a declaration, a unary * applied to a variable declared
    as an integer, and int - pointer differences in printf-style varargs.
    """
    pointers = set(re.findall(r'^\s*[A-Za-z_][\w ]*\*\s*([A-Za-z_]\w*);', text, re.M))
    text = re.sub(r'\bswitch \(([A-Za-z_]\w*)\)',
                  lambda m: f'switch ((s32) {m[1]})' if m[1] in pointers else m[0], text)
    if 'M2C_CARRY' in text and not re.search(r'#define\s+M2C_CARRY\b', text):
        text = '#define M2C_CARRY 0\n' + text
    signature = re.search(r'\b' + re.escape(name) + r'\s*\([^{};]*\)\s*\{', text)
    if not signature:
        return text
    head, body = text[:signature.end()], text[signature.end():]
    pointers = set(re.findall(r'^\s*[A-Za-z_][\w ]*\*\s*([A-Za-z_]\w*);', body, re.M))
    declared = set(re.findall(r'^(?!\s*return\b)[^=\n]*[\s*}]((?:unk)?sp[0-9A-Fa-f]+)\s*(?:\[[^\]]*\])?\s*;\s*(?:/\*.*\*/)?$', body, re.M))
    used = set(re.findall(r'(?<![.\w>])((?:unk)?sp[0-9A-Fa-f]+)\b', body))
    missing = sorted(used - declared - set(re.findall(r'\b((?:unk)?sp[0-9A-Fa-f]+)\b', head)))
    if missing:
        body = ''.join(f'\n    s32 {local};' for local in missing) + body
    for var in sorted(set(re.findall(r'(?:^|[=(,;{}&|!~?:])\s*\*\s*([A-Za-z_]\w*)\b(?!\s*\()', body, re.M))):
        decl = re.search(r'^(\s*)(s32|u32|M2C_UNK|s16|u16|s8|u8) ' + re.escape(var) + r';', body, re.M)
        if decl:
            # Cast at the dereference; re-declaring as a pointer would rescale
            # the variable's integer arithmetic elsewhere.
            elem = 's32' if decl[2] == 'M2C_UNK' else decl[2]
            body = re.sub(r'((?:^|[=(,;{}&|!~?:])\s*)\*\s*' + re.escape(var) + r'\b(?!\s*\()',
                          lambda m: f'{m[1]}*({elem} *){var}', body, flags=re.M)
    def varargs(line):
        if not _VARARG_CALL.search(line):
            return line
        return re.sub(r'(?<![\w)*&>.])([A-Za-z_]\w*) - ([A-Za-z_]\w*)\b(?!\s*[\[(])',
                      lambda m: f'(s32) {m[1]} - (s32) {m[2]}' if m[2] in pointers else m[0], line)
    body = '\n'.join(varargs(line) for line in body.split('\n'))
    # pointer + pointer (relocation fixups: field = offset + base) is invalid C.
    # b4: pointer parameters and `(T *) expr` casts count as pointers too.
    pointers |= set(re.findall(r'\*\s*([A-Za-z_]\w*)\s*(?=[,)])', head[signature.start():]))
    body = re.sub(r'(?<![\w.>*&])([A-Za-z_]\w*) \+ ([A-Za-z_]\w*)\b(?!\s*[\[(])',
                  lambda m: f'(s32) {m[1]} + {m[2]}' if m[1] in pointers and m[2] in pointers else m[0], body)
    body = re.sub(r'(?<![\w.>*&)])([A-Za-z_]\w*) \+ (?=\((?:void|[us](?:8|16|32)|f32|char) \*\))',
                  lambda m: f'(s32) {m[1]} + ' if m[1] in pointers else m[0], body)
    # m2c sometimes declares a field expression as a local: `s32 *M2C_FIELD(...);`
    body = re.sub(r'^\s*(?:[us](?:8|16|32)|f32|f64|M2C_UNK|void)\s*\**\s*M2C_FIELD\([^\n]*\);[ \t]*\n', '', body, flags=re.M)
    widths = {'s8': 1, 'u8': 1, 's16': 2, 'u16': 2, 's32': 4, 'u32': 4, 'f32': 4, 'M2C_UNK': 4, 'f64': 8, 's64': 8, 'u64': 8}
    def bitwise(m):
        decl = re.search(r'^\s*(\w+)\s+' + re.escape(m[2]) + r'\s*;', body, re.M)
        if decl and decl[1] in widths and m[1] in widths and widths[decl[1]] != widths[m[1]]:
            return f'*({m[1]} *)&{m[2]}'
        return m[0]
    body = re.sub(r'M2C_BITWISE\((\w+), ((?:unk)?sp[0-9A-Fa-f]+)\)', bitwise, body)
    return head + body


_PROTO = re.compile(r'^((?:extern\s+)?[A-Za-z_][\w ]*?[\s*]+)([A-Za-z_]\w*)\(([^()]*)\);[ \t]*$', re.M)


def _call_arities(text: str, callee: str):
    for m in re.finditer(r'(?<![\w.])' + re.escape(callee) + r'\s*\(', text):
        depth, args, i, empty = 1, 1, m.end(), True
        while i < len(text) and depth:
            c = text[i]
            if c in '([': depth += 1
            elif c in ')]': depth -= 1
            elif c == ',' and depth == 1: args += 1
            elif c == ';': break
            if depth and not c.isspace(): empty = False
            i += 1
        if depth == 0:
            yield 0 if empty else args


def _repair_b4_arity(text: str, name: str) -> str:
    """A context prototype whose arity disagrees with m2c's call sites stops the
    compile ("too few/many arguments"). Such a callee gets an unprototyped
    declaration instead; integer and pointer arguments pass identically."""
    for m in list(_PROTO.finditer(text)):
        ret, callee, params = m[1], m[2], m[3].strip()
        if callee == name or '...' in params or '(' in params:
            continue
        want = 0 if params in ('', 'void') else params.count(',') + 1
        body = text[m.end():]
        if any(n != want for n in _call_arities(body, callee)):
            text = text.replace(m[0], f'{ret}{callee}();', 1)
    return text


def recursive_seed(text: str, name: str, address: int):
    """b4: m2c renders a self call as `.L_<entry>(...)`; repair_seed drops that
    line, so the target's recursion disappears. Keep it as a real recursive
    call. m2c lists only the argument registers it saw set before the call; a
    missing trailing argument is the caller's own parameter still in place."""
    entry = f'.L_{address:08X}'
    if entry + '(' not in text:
        return None
    signature = re.search(r'\b' + re.escape(name) + r'\s*\(([^{};]*)\)\s*\{', text)
    if not signature:
        return None
    params = [p.strip() for p in signature[1].split(',') if p.strip() not in ('', 'void')]
    own = [re.findall(r'(\w+)\s*$', p)[0] for p in params]
    text = re.sub(r'^[A-Za-z_][\w ]*\**\s*' + re.escape(entry) + r'\([^;\n]*\);[ \t]*\n', '', text, flags=re.M)
    def call(m, before):
        args = [a.strip() for a in _split_args(m[1])]
        if len(args) < len(own):
            # An own parameter m2c names is still in its own register; an
            # empty slot holds the m2c temp last assigned to that register.
            slots = [None] * len(own)
            for a in [a for a in args if a in own]:
                slots[own.index(a)] = a
            rest = [a for a in args if a not in own]
            for i in range(len(own)):
                if slots[i] is None and rest:
                    slots[i] = rest.pop(0)
                if slots[i] is None:
                    temps = re.findall(r'\b((?:temp|var)_r%d(?:_\d+)?) = ' % (3 + i), before)
                    slots[i] = temps[-1] if temps else own[i]
            args = slots
        return f'{name}({", ".join(args[:len(own)])})'
    out, i = [], 0
    while True:
        j = text.find(entry + '(', i)
        if j < 0:
            out.append(text[i:]); break
        out.append(text[i:j])
        k, depth = j + len(entry) + 1, 1
        while k < len(text) and depth:
            depth += {'(': 1, ')': -1}.get(text[k], 0); k += 1
        out.append(call(re.match(r'(.*)', text[j + len(entry) + 1:k - 1], re.S), text[:j]))
        i = k
    return repair_seed(''.join(out), name, address)


def _split_args(s):
    parts, depth, cur = [], 0, ''
    for c in s:
        if c in '([': depth += 1
        elif c in ')]': depth -= 1
        if c == ',' and depth == 0:
            parts.append(cur); cur = ''
        else:
            cur += c
    if cur.strip(): parts.append(cur)
    return parts


def rebase_fields(text: str):
    """b4 (Spark 10:53, from Sonnet-m's SoundDriver__Destroy win): m2c names
    `t = base + K;` and then still addresses the same object through the
    original base, M2C_FIELD(base, T, K + o), next to M2C_FIELD(t, T, o).
    The target compiles every access through t (one base register). Rewrite
    accesses after the single assignment of t to go through t. Returns None
    when nothing changes (offered as an extra seed; the original stays)."""
    out = text
    for m in re.finditer(r'^[ \t]*(\w+) = (\w+) \+ (0x[0-9A-Fa-f]+|\d+);[ \t]*$', text, re.M):
        temp, base, k = m[1], m[2], int(m[3], 0)
        if temp == base or len(re.findall(r'^\s*' + re.escape(temp) + r' = ', text, re.M)) != 1:
            continue
        pos = out.find(m[0])
        if pos < 0:
            continue
        def sub(f):
            rel = int(f[2], 0) - k
            if rel < 0 or rel >= 0x8000:
                return f[0]
            return f'M2C_FIELD({temp}, {f[1]}, {hex(rel) if rel else 0})'
        tail = re.sub(r'M2C_FIELD\(' + re.escape(base) + r', ((?:[^,()]|\([^()]*\))+?), (0x[0-9A-Fa-f]+|\d+)\)', sub, out[pos + len(m[0]):])
        out = out[:pos + len(m[0])] + tail
    return None if out == text else out


def swap_union(text: str):
    """b4 (TerrainMeshNode__ByteSwap class): an endian swap through a stack
    word (`po[0] = pi[3]; ... out`) reaches m2c as `union { u8 value;
    unsigned char bytes[N]; } spX;` typed from its first byte store, so the
    swapped word is read back with lbz instead of lwz/lhz. Store that first
    byte through bytes[0] and widen value (N == 4 or a later (u32) read -> u32,
    N == 2 or a (u16)/(s16) read -> u16). Returns None when nothing changes."""
    out = text
    for m in re.finditer(r'union \{ ([us]8) value; unsigned char bytes\[(\d+)\]; \} (\w+);', text):
        name, n = m[3], int(m[2])
        reads = re.findall(r'\((\w+)\) ' + re.escape(name) + r'\.value\b', text)
        if n == 4 or any(r in ('u32', 's32') for r in reads) and n >= 4:
            wide = 'u32'
        elif n == 2 or any(r in ('u16', 's16') for r in reads) and n >= 2:
            wide = 'u16'
        else:
            continue
        if not re.search(r'\(\(u8 \*\)' + re.escape(name) + r'\.bytes\), u8 \*, [1-3]\) =', text):
            continue
        out = out.replace(m[0], f'union {{ {wide} value; unsigned char bytes[{n}]; }} {name};', 1)
        out = re.sub(r'(^|[;{]\s*)' + re.escape(name) + r'\.value = ', lambda f: f[1] + name + '.bytes[0] = ', out, flags=re.M)
    return None if out == text else out


def abs_symbols(text: str, objects):
    """b4: m2c prints data addresses as integers (`(s8 *)0x8031A110`,
    `*(u8 *)(0x8033C9D9 + c)`). ProDG folds an integer address into the
    access (addis + lbz -0x3627) and never relocates it; the target loads the
    object's relocated address (lis/addi, hoisted out of loops) and strict
    verify needs that symbol identity. Rewrite each literal that falls inside a
    known data object as `((u32) &lbl_X + off)`, declaring missing externs.
    objects: address -> (name, size, ...). Returns None when nothing changes."""
    signature = re.search(r'^[^\n;#]*\b\w+\s*\([^{};]*\)\s*\{', text, re.M)
    if not signature or not objects:
        return None
    head, body = text[:signature.start()], text[signature.start():]
    import bisect
    starts = sorted(objects)
    declare = []
    def sub(m):
        a = int(m[1], 16)
        if not 0x80003100 <= a < 0x81800000:
            return m[0]
        i = bisect.bisect_right(starts, a) - 1
        if i < 0:
            return m[0]
        base = starts[i]
        name, size = objects[base][0], objects[base][1]
        if not name or a - base >= max(size, 1):
            return m[0]
        if not re.search(r'\b' + re.escape(name) + r'\b', head) and name not in declare:
            declare.append(name)
        return f'((u32) &{name} + {hex(a - base)})' if a != base else f'((u32) &{name})'
    out = re.sub(r'(?<![\w.])0x(80[0-9A-Fa-f]{6})(?![\w.])', sub, body)
    if out == body:
        return None
    return head + ''.join(f'extern u8 {n}[];\n' for n in declare) + out


def abs_functions(text: str, functions):
    """b4: m2c prints a function's address used as data (handler tables,
    callbacks: `M2C_FIELD(t, s32 *, 0x10) = 0x8024C030;`) as an integer, which
    builds with lis+ori and no relocation; the target relocates it (lis+addi).
    Name it: ((u32) &Func), declaring `void Func(void);` when missing.
    functions: address -> (name, size). Returns None when nothing changes."""
    signature = re.search(r'^[^\n;#]*\b(\w+)\s*\([^{};]*\)\s*\{', text, re.M)
    if not signature or not functions:
        return None
    head, body = text[:signature.start()], text[signature.start():]
    declare = []
    def sub(m):
        entry = functions.get(int(m[1], 16))
        name = entry[0] if isinstance(entry, tuple) else entry
        if not name or not re.fullmatch(r'[A-Za-z_]\w*', name) or name == signature[1]:
            return m[0]
        if not re.search(r'\b' + re.escape(name) + r'\b', head) and name not in declare:
            declare.append(name)
        return f'((u32) &{name})'
    out = re.sub(r'(?<![\w.])0x(80[0-9A-Fa-f]{6})(?![\w.])', sub, body)
    if out == body:
        return None
    return head + ''.join(f'void {n}(void);\n' for n in declare) + out


def lit16_sign(text: str, target_words):
    """b4: m2c prints some sign-extended 16-bit immediates as unsigned 16-bit
    hex (`Sphere__SetLayer(x, 0xFF38)` for `li r4, -200`; `return 0xFFFF` for
    `li r3, -1`). As an int argument/value 0xFF38 needs lis+ori; the target
    has one li. Rewrite 0x8000-0xFFFF literals in argument / assignment /
    return position (never comparisons: a promoted u16 still compares against
    0xFFFF) to the negative value, only when the target has `li rD, value`.
    Returns None when nothing changes."""
    negative = {(w & 0xffff) - 0x10000 for w in target_words
                if w >> 26 == 14 and (w >> 16) & 31 == 0 and w & 0x8000}
    if not negative:
        return None
    def sub(m):
        v = int(m[2], 16) - 0x10000
        return f'{m[1]}{v}' if v in negative else m[0]
    out = re.sub(r'((?:[(,]|(?<![=!<>])=|\breturn)\s*(?:\((?:void|[us](?:8|16|32)|M2C_UNK) ?\**\)\s*)?)0x([89A-Fa-f][0-9A-Fa-f]{3})(?![\w.])', sub, text)
    return None if out == text else out


def abs_base(text: str, objects):
    """b4 (RenderState__SetDefaults): a global object whose fields are read
    more than once, across calls, is addressed in the target through one
    callee-saved base (lis/addi r30 once, then lwz 0x3c(r30) / lbz 0x40(r30));
    m2c's M2C_FIELD((void *)0x803AD9E4, ...) / M2C_FIELD(&lbl_X, ...) compiles
    to a fresh lis + lo16 per access. Address such a base through a local
    `u8 *` assigned right before the statement of its first use.
    Returns None when nothing changes."""
    signature = re.search(r'^[^\n;#]*\b\w+\s*\([^{};]*\)\s*\{[ \t]*\n', text, re.M)
    if not signature:
        return None
    head, body = text[:signature.end()], text[signature.end():]
    pattern = re.compile(r'M2C_FIELD\((\(void \*\)0x(80[0-9A-Fa-f]{6})|&(lbl_[0-9A-Fa-f]{8}))\s*,')
    counts = {}
    for m in pattern.finditer(body):
        counts[m[1]] = counts.get(m[1], 0) + 1
    out, decls, extern = body, [], []
    for n, (base, uses) in enumerate(sorted(counts.items(), key=lambda kv: body.find(kv[0]))):
        if uses < 2:
            continue
        m = re.search(r'0x(80[0-9A-Fa-f]{6})', base)
        if m:
            address = int(m[1], 16)
            entry = objects.get(address) if objects else None
            if not entry or not entry[0]:
                continue
            symbol = entry[0]
            if not re.search(r'\b' + re.escape(symbol) + r'\b', head + body):
                extern.append(symbol)
        else:
            symbol = base[1:]
        local = f'mt_base{n}'
        first = out.find('M2C_FIELD(' + base)
        line = out.rfind('\n', 0, first) + 1
        indent = re.match(r'[ \t]*', out[line:])[0]
        out = out[:line] + f'{indent}{local} = (u8 *) &{symbol};\n' + out[line:]
        out = out.replace('M2C_FIELD(' + base + ',', 'M2C_FIELD(' + local + ',')
        decls.append(f'    u8 *{local};\n')
    if not decls:
        return None
    sig_start = signature.start()
    return (head[:sig_start] + ''.join(f'extern u8 {s}[];\n' for s in extern) + head[sig_start:]
            + ''.join(decls) + out)


_MEMBER_INDEX = re.compile(r'\*\(([^()]+?\*)\)\((\w+) \+ (0x[0-9A-Fa-f]+|\d+) \+ \(([^()]*?(?:\([^()]*\))?[^()]*?) \* ([248])\)\)')
_ELEM_SIZE = {'s32': 4, 'u32': 4, 'f32': 4, 'M2C_UNK': 4, 's16': 2, 'u16': 2, 'f64': 8, 's64': 8, 'u64': 8}


def member_array(text: str):
    """b4 (AnimScript__Op* family): m2c writes a member-array element as
    `*(void **)(arg0 + 0xF0 + (arg1 * 4))`; ProDG folds 0xF0 into the load
    displacement (add + lwz 0xf0) while the target, compiled from
    `self->vars[i]`, forms the array address first (addi r3,r3,0xf0 + lwzx).
    Index a struct whose array member sits at that offset instead.
    Returns None when nothing changes."""
    signature = re.search(r'^[^\n;#]*\b\w+\s*\([^{};]*\)\s*\{', text, re.M)
    if not signature:
        return None
    structs = {}
    def sub(m):
        cast, base, offset, index, scale = m[1], m[2], int(m[3], 0), m[4], int(m[5])
        elem = cast[:-1].strip()
        size = 4 if elem.endswith('*') else _ELEM_SIZE.get(elem)
        if size != scale or not 0 < offset < 0x8000:
            return m[0]
        tag = f'mt_arr_{offset:X}_{re.sub(r"[^A-Za-z0-9]", "", elem.replace("*", "p"))}'
        structs[tag] = f'struct {tag} {{ u8 pad[{offset:#x}]; {elem} a[1]; }};\n'
        return f'((struct {tag} *)({base}))->a[{index}]'
    body = _MEMBER_INDEX.sub(sub, text[signature.start():])
    if not structs:
        return None
    return text[:signature.start()] + ''.join(structs.values()) + body


def signed_temps(text: str, relaxed: bool = False):
    """b4 (AnimScript__OpBitAnd): m2c declares a byte temp `u8 t` from the
    lbz that produced it and then reads it only as `(s8) t`; the unsigned
    declaration costs a clrlwi before the extsb. Declare a u8/u16 temp s8/s16
    when every read is the signed cast (plain stores of t into a field of the
    same width are fine; relaxed also accepts `(u8) (t - 1)` truncating
    stores, which helps stack-pop ops but costs others, so it is a second
    seed). Returns None when nothing changes."""
    out = text
    for m in re.finditer(r'^( +)u(8|16) ((?:temp|var)_\w+);', text, re.M):
        name, bits = m[3], m[2]
        uses = [u for u in re.finditer(r'(?<![\w.>])' + re.escape(name) + r'\b', text) if u.start() > m.end()]
        signed = 0
        for u in uses:
            before, after = text[max(0, u.start() - 8):u.start()], text[u.end():u.end() + 4]
            if before.endswith(f'(s{bits}) '):
                signed += 1
            elif relaxed and before.endswith(f'(u{bits}) (') and re.match(r'\s*[-+]\s*\w+\)', text[u.end():u.end() + 12]):
                continue  # truncated back to the same width: sign-neutral
            elif re.match(r'\s*=[^=]', after) or re.search(r'= $', before) and re.match(r';', after):
                continue  # assignment to it, or a plain whole-value store
            else:
                signed = -1
                break
        if signed > 0:
            out = out.replace(m[0], f'{m[1]}s{bits} {name};', 1)
            out = re.sub(r'\(s' + bits + r'\) ' + re.escape(name) + r'\b', name, out)
    return None if out == text else out


def _same_bound(guard, loop, before):
    """The guard's bound and the loop's bound name the same value: equal up to
    an int cast, or the guard tests a temp last assigned the loop's bound."""
    strip = lambda e: re.sub(r'^\((?:s|u)32\) ', '', e.strip())
    if strip(guard) == strip(loop):
        return True
    if re.fullmatch(r'\w+', guard):
        assign = next((re.fullmatch(r'\s*' + guard + r' = (.+);', l) for l in reversed(before)
                       if re.fullmatch(r'\s*' + guard + r' = .+;', l)), None)
        return bool(assign) and strip(assign[1]) == strip(loop)
    return False


def counter_guard(text: str):
    """b4 (Sphere__UpdateHandles 98%): a for loop `for (i = 0; i < n; i++)`
    reaches m2c as `i = 0; ...; if (n > 0) { do { ... } while (i < n); }`;
    the target's guard compares the counter register (cmpw r29,r0), ours
    compares n with 0. mt_mut.m_guarded_loop only fires when `i = 0;` sits on
    the line right above the guard. Rewrite the guard as `if (i < n)` when
    i = 0 was assigned earlier in the same block and nothing between writes
    i. Returns None when nothing changes."""
    lines = text.split('\n')
    out = lines[:]
    for g, line in enumerate(lines):
        m = re.fullmatch(r'( +)if \((.+) > 0\) \{', line)
        if not m:
            continue
        indent, bound = m[1], m[2]
        end = next((k for k in range(g + 1, len(lines)) if lines[k] in (indent + '}', indent + '} else {')), None)
        if end is None:
            continue
        cond = re.fullmatch(re.escape(indent) + r'    \} while \((\w+) < (.+)\);', lines[end - 1])
        if not cond:
            # m2c goto loop near the guard's top: `loop_N: ... if (i >= n) { goto
            # block_M; } goto loop_N;` or `if (i < n) { ...; goto loop_N; }`
            label = next((re.fullmatch(r'\s*(loop_\d+):', lines[k]) for k in range(g + 1, min(g + 4, end))
                          if re.fullmatch(r'\s*loop_\d+:', lines[k])), None)
            cond = label and next((c for c in (re.fullmatch(r' +if \((\w+) (?:>=|<) (.+)\) \{', lines[k]) for k in range(g + 1, end)) if c), None)
            if cond and ' < ' in lines[lines.index(cond[0], g + 1)] and not any(
                    f'goto {label[1]};' in lines[k] for k in range(lines.index(cond[0], g + 1), end)):
                cond = None
        if not cond or not _same_bound(bound, cond[2], lines[:g]):
            continue
        var = cond[1]
        init = next((k for k in range(g - 1, -1, -1)
                     if re.fullmatch(re.escape(indent) + re.escape(var) + r' = 0;', lines[k])
                     or not lines[k].startswith(indent) or lines[k].strip().endswith('{')), None)
        if init is None or lines[init].strip() != var + ' = 0;':
            continue
        if any(re.search(r'\b' + re.escape(var) + r'\b', lines[k]) for k in range(init + 1, g)):
            continue
        out[g] = f'{indent}if ({var} < {bound}) {{'
    return None if out == lines else '\n'.join(out)


def _f32_slot(expr, aliases):
    """(base, offset) of an f32 lvalue in m2c's spellings, else None."""
    e = expr.strip()
    m = re.fullmatch(r'(\w+)\.v([012])', e)
    if m:
        return '&' + m[1], 4 * int(m[2])
    m = re.fullmatch(r'(\w+)\.value', e)
    if m:
        return '&' + m[1], 0
    m = re.fullmatch(r'M2C_FIELD\(\(\(f32 \*\)(\w+)\.bytes\), f32 \*, (0x[0-9A-Fa-f]+|\d+)\)', e)
    if m:
        return '&' + m[1], int(m[2], 0)
    m = re.fullmatch(r'M2C_FIELD\((&?\w+), f32 \*, (0x[0-9A-Fa-f]+|\d+)\)', e)
    if m:
        base, off = m[1], int(m[2], 0)
        while base in aliases:
            base, extra = aliases[base]
            off += extra
        return base, off
    return None


def vec3_copy(text: str):
    """b4 (CCameraStick__Update / Dende / CFilterSmooth class): a vec3 struct
    assignment reaches m2c as three f32 component copies in mixed spellings
    (`sp18.v0 = M2C_FIELD(arg0, f32 *, 0xC); sp18.v1 = M2C_FIELD(t, f32 *, 4)`
    with t = arg0 + 0xC). ProDG copies the struct through integer registers
    (lwz x3 / stw x3) but the components through FPRs. Three adjacent copies
    covering K, K+4, K+8 on both sides (any line order, alias temps resolved)
    become one struct copy. Returns None when nothing changes."""
    aliases = {}
    for m in re.finditer(r'^\s+(\w+) = (&?\w+) \+ (0x[0-9A-Fa-f]+|\d+);$', text, re.M):
        if len(re.findall(r'^\s+' + m[1] + r' = ', text, re.M)) == 1:
            aliases[m[1]] = (m[2], int(m[3], 0))
    copy = re.compile(r'^(\s+)(.+?) = (?:\(f32\) )?(.+);$')
    lines = text.split('\n')
    out, i, used = [], 0, False
    while i < len(lines):
        group = []
        for k in range(i, min(i + 3, len(lines))):
            m = copy.match(lines[k])
            if not m:
                break
            d, s = _f32_slot(m[2], aliases), _f32_slot(m[3], aliases)
            if not d or not s:
                break
            group.append((m[1], d, s))
        if len(group) == 3 and len({g[1][0] for g in group}) == 1 and len({g[2][0] for g in group}) == 1:
            pairs = sorted((d[1], s[1]) for _, d, s in group)
            k0, s0 = pairs[0]
            if [p for p in pairs] == [(k0, s0), (k0 + 4, s0 + 4), (k0 + 8, s0 + 8)]:
                indent, dst, src = group[0][0], group[0][1][0], group[0][2][0]
                out.append(f'{indent}*(mt_b4_vec3 *)((char *){dst} + {k0}) = *(mt_b4_vec3 *)((char *){src} + {s0});')
                i += 3
                used = True
                continue
        out.append(lines[i])
        i += 1
    if not used:
        return None
    body = '\n'.join(out)
    signature = re.search(r'^[^\n;#]*\b\w+\s*\([^{};]*\)\s*\{', body, re.M)
    if not signature:
        return None
    return body[:signature.start()] + 'typedef struct { f32 v[3]; } mt_b4_vec3;\n' + body[signature.start():]


def _target_addresses(words):
    """Absolute addresses the target builds or accesses with lis rD,H + addi/load/store L(rD)."""
    his, out = {}, set()
    for w in words:
        op, rd, ra, imm = w >> 26, (w >> 21) & 31, (w >> 16) & 31, w & 0xffff
        simm = imm - 0x10000 if imm & 0x8000 else imm
        if op == 15 and ra == 0:
            his[rd] = imm << 16
        elif (op == 14 or 32 <= op <= 55) and ra in his:
            out.add((his[ra] + simm) & 0xffffffff)
    return out


def label_rebase(text: str, objects, target_words, window=0x2000):
    """b4 (ParticleMgr__LoadLibrary class): the address book splits one big
    global (a singleton struct) into several lbl_ objects, so the seed names
    lbl_803AD4B8 where the original addressed lbl_803AD05C + 0x45C; ProDG then
    materializes every label with its own lis/addi. When the target never
    builds a label's address but does build a lower one within `window`,
    address the label from that one. Returns None when nothing changes."""
    built = _target_addresses(target_words or [])
    if not built:
        return None
    labels = sorted({int(a, 16) for a in re.findall(r'\blbl_([0-9A-F]{8})\b', text)})
    bases = sorted(a for a in built if a in objects)
    moves = {}
    for a in labels:
        size = max(objects[a][1], 1) if a in objects else 1
        if any(a <= b < a + size for b in built):
            continue  # the target reaches this label (or a field of it) itself
        lower = [b for b in bases if b < a and a - b <= window]
        if lower:
            moves[a] = lower[-1]
    if not moves:
        return None
    out = text
    declared = set(re.findall(r'\bextern [^;\n]*\blbl_([0-9A-F]{8})\b', out))
    extra = []
    for a, b in moves.items():
        name, base = f'lbl_{a:08X}', f'lbl_{b:08X}'
        decl = re.search(r'^extern ([^;\n]*?)\s*\b' + name + r'\b(\[\])?[^;\n]*;\n', out, re.M)
        ref = f'((u8 *)&{base} + 0x{a - b:X})'
        out = re.sub(r'&' + name + r'\b', ref, out)
        if decl and decl[2]:
            out = re.sub(r'(?<![\w&])' + name + r'\b(?!\[)', ref, out[:decl.start()]) + decl[0] + re.sub(r'(?<![\w&])' + name + r'\b(?!\[)', ref, out[decl.end():])
        elif decl:
            kind = decl[1].strip() or 's32'
            body_start = decl.end()
            out = out[:body_start] + re.sub(r'(?<![\w&])' + name + r'\b', f'(*({kind} *){ref})', out[body_start:])
        if f'{b:08X}' not in declared:
            extra.append(f'extern u8 {base}[];\n')
            declared.add(f'{b:08X}')
    signature = re.search(r'^[^\n;#]*\b\w+\s*\([^{};]*\)\s*\{', out, re.M)
    if extra and signature:
        out = out[:signature.start()] + ''.join(extra) + out[signature.start():]
    return None if out == text else out


_MAGIC_SIGNED = bytes.fromhex('4330000080000000')
_MAGIC_UNSIGNED = bytes.fromhex('4330000000000000')


def _balanced(text, j):
    """Index just past the bracket group opening at text[j]."""
    depth = 0
    while j < len(text):
        depth += 1 if text[j] in '([' else -1 if text[j] in ')]' else 0
        j += 1
        if depth == 0:
            return j
    return None


def _primary_end(text, i):
    """End index of the C operand starting at text[i]: a cast applies to the
    operand after it, *(...) / (...) are taken whole, an identifier takes its
    member / call / index chain. None when it does not parse."""
    cast = re.match(r'\((?:const )?(?:[us](?:8|16|32|64)|f32|f64|void|M2C_UNK)(?: \*+)?\) ?', text[i:])
    if cast:
        return _primary_end(text, i + cast.end())
    j = i
    if text.startswith('*', j):
        return _primary_end(text, j + 1)
    if text.startswith('(', j):
        return _balanced(text, j)
    m = re.match(r'[A-Za-z_]\w*', text[j:])
    if not m:
        return None
    j += m.end()
    while j < len(text):
        m = re.match(r'\.\w+|->\w+', text[j:])
        if m:
            j += m.end()
        elif text[j] in '([':
            j = _balanced(text, j)
            if j is None:
                return None
        else:
            break
    return j


def i2f_magic(text: str, target_words, read):
    """b4: ProDG converts int -> float through the 0x4330000080000000 magic
    double, an anonymous rodata constant in our object; the target's link has
    one shared copy, so strict verify reports '.rodata: ambiguous constant
    placement' and the row can never be exact (340 unmatched functions convert).
    The matched sources spell the conversion out against an extern at the
    target's own constant: union { hi = 0x43300000; lo = x ^ 0x80000000 } - lbl.
    Rewrite m2c's `(f64) <int expr>` that way for the magic constants the target
    loads (lis + lfd). Returns None when there is nothing to rewrite."""
    try:
        addresses = sorted(_target_addresses(target_words or []))
        signed = [a for a in addresses if read(a, 8) == _MAGIC_SIGNED]
        unsigned = [a for a in addresses if read(a, 8) == _MAGIC_UNSIGNED]
    except Exception:
        return None
    if not signed and not unsigned:
        return None
    out, pos, used = text, 0, set()
    sig = re.search(r'^[^\n;#]*\b\w+\s*\([^{};]*\)\s*\{', out, re.M)
    if not sig:
        return None
    pos = sig.end()
    while True:
        m = re.compile(r'\(f64\) ').search(out, pos)
        if not m:
            break
        end = _primary_end(out, m.end())
        operand = out[m.end():end] if end else ''
        is_unsigned = operand.startswith('(u32) ')
        pool = unsigned if is_unsigned else signed
        if not operand or not pool:
            pos = m.end()
            continue
        macro = 'MT_U2D' if is_unsigned else 'MT_I2D'
        used.add((macro, pool[0]))
        new = f'{macro}({operand})'
        out = out[:m.start()] + new + out[end:]
        pos = m.start() + len(new)
    if not used:
        return None
    head = ''
    for macro, address in sorted(used):
        name = f'lbl_{address:08X}'
        if not re.search(r'\b' + name + r'\b', out[:sig.start()]):
            head += f'extern f64 {name} __attribute__((section(".rodata")));\n'
        low = '(u32) (x) ^ 0x80000000u' if macro == 'MT_I2D' else '(u32) (x)'
        head += (f'#define {macro}(x) ({{ struct {{ u32 hi, lo; }} mt_w; '
                 f'mt_w.hi = 0x43300000u; mt_w.lo = {low}; *(f64 *)&mt_w - {name}; }})\n')
    sig = re.search(r'^[^\n;#]*\b\w+\s*\([^{};]*\)\s*\{', out, re.M)
    return out[:sig.start()] + head + out[sig.start():]


_FLIP = {'==': '!=', '!=': '==', '<': '>=', '>=': '<', '>': '<=', '<=': '>'}


def flip_conditions(text: str, limit: int = 6):
    """b4 (AnimScript__OpJumpIfStackEqual from its NotEqual twin): opposite-pair
    siblings (Equal/NotEqual, True/False, Greater/LessEqual) compile to the same
    code except one branch sense, and no search mutation negates a comparison.
    Variants of a (twin) seed with one `if (a op b)` comparison negated, at most
    `limit`, in source order."""
    body = text.find('{', max(0, re.search(r'^[^\n;#]*\b\w+\s*\([^{};]*\)\s*\{', text, re.M).start()
                              if re.search(r'^[^\n;#]*\b\w+\s*\([^{};]*\)\s*\{', text, re.M) else 0))
    out = []
    for m in re.finditer(r'\bif \(([^()]*?) (==|!=|<=|>=|<|>) ([^()]*?)\) \{', text[body:]):
        start = body + m.start(2)
        out.append(text[:start] + _FLIP[m[2]] + text[start + len(m[2]):])
        if len(out) >= limit:
            return out
    # Set/Clear siblings: one flag update 'x |= m' <-> 'x &= ~m' (and the plain
    # expression forms 'a | m' <-> 'a & ~m')
    for m in re.finditer(r'(\|=|&= ~|\| (?!\|)|& ~)\s*', text[body:]):
        start, end, op = body + m.start(1), body + m.end(), m[1]
        new = {'|=': '&= ~', '&= ~': '|= ', '| ': '& ~', '& ~': '| '}[op]
        out.append(text[:start] + new + text[end:])
        if len(out) >= limit:
            break
    return out


def compose(text: str, objects, target_words, relaxed: bool = False):
    """b4: the b4 address/literal/union seed rewrites applied in sequence (each one alone is its own
    extra seed, so a row that needs two never got both). None if unchanged."""
    out = text
    for rewrite in (swap_union, member_array, counter_guard, vec3_copy, lambda t: signed_temps(t, relaxed), lambda t: abs_base(t, objects), lambda t: abs_symbols(t, objects),
                    lambda t: lit16_sign(t, target_words), lambda t: label_rebase(t, objects, target_words)):
        out = rewrite(out) or out
    return None if out == text else out


_VARARGS = {'sprintf': (1, 's32 sprintf(char *, const char *, ...);'),
            'printf': (0, 's32 printf(const char *, ...);'),
            'OSReport': (0, 'void OSReport(const char *, ...);'),
            'snprintf': (2, 's32 snprintf(char *, u32, const char *, ...);'),
            # printf-style helpers declared variadic in src/ (format index;
            # prototype built from m2c's return type and leading params)
            'Debug__FormatMessage': (0, None), 'String__FormatTemp': (0, None),
            'Assert_FormatMessage': (0, None), 'CmdCon__Print': (1, None),
            'CmdCon__PrintError': (1, None), 'CmdCon__PrintNotify': (1, None),
            'DebugSession__Printf': (1, None)}
_CONVERSION = re.compile(r'%[-+ #0]*(\*|\d+)?(?:\.(\*|\d+))?(?:hh|h|ll|l|L)?([diouxXcspfFeEgGn%])')


def _call_args(text, start):
    """(args, end) for the call whose '(' is at text[start]; None if unbalanced."""
    depth, args, last, quote = 0, [], start + 1, None
    for i in range(start, len(text)):
        c = text[i]
        if quote:
            if c == '\\':
                continue
            if c == quote and text[i - 1] != '\\':
                quote = None
            continue
        if c in '"\'':
            quote = c
        elif c == '(':
            depth += 1
        elif c == ')':
            depth -= 1
            if depth == 0:
                args.append(text[last:i].strip())
                return [a for a in args if a], i + 1
        elif c == ',' and depth == 1:
            args.append(text[last:i].strip())
            last = i + 1
    return None


def vararg_calls(text: str, read):
    """b4 (Collision__FindTerrain / CFilterCollide class, 13/225 sampled rows):
    m2c has no prototype for sprintf/OSReport, so it declares one fixed arg per
    argument register (r3-r10 then f1-f8), passes M2C_ERROR for the unset ones and
    folds a preceding call's 'f1 return' into the next call as an argument. The
    target makes ordinary variadic calls (crclr 6). Rebuild every such call from
    its format string (read from the binary through read(address, n) -> bytes):
    one argument per conversion, taken in register order, a nested printf-family
    call in a dropped slot becomes its own statement first, and the prototype is
    the real variadic one. Calls whose format cannot be read are left alone."""
    out = text
    for name, (fmt_index, proto) in _VARARGS.items():
        decl = re.search(r'^[^\n;()]*\b' + name + r'\(([^;{}]*)\);[ \t]*$', out, re.M)
        if not decl or '...' in decl[1]:
            continue
        params = [p.strip() for p in decl[1].split(',')]
        if proto is None:
            if len(params) <= fmt_index:
                continue
            ret = decl[0][:decl.start(1) - decl.start() - len(name) - 1].strip() or 's32'
            proto = f'{ret}{"" if ret.endswith("*") else " "}{name}(' + ', '.join(params[:fmt_index] + ['const char *', '...']) + ');'
        slots, ints, floats = [], 0, 0
        for p in params:
            if re.match(r'(?:f32|f64|float|double)\b(?!\s*\*)', p):
                slots.append(('f', floats)); floats += 1
            else:
                slots.append(('r', ints)); ints += 1
        def fmt_of(arg):
            m = re.fullmatch(r'(?:\(\w+ \*\)\s*)?&?(lbl_|0x)([0-9A-Fa-f]{8})', arg.strip())
            if not m:
                return None
            raw = b''
            try:
                while len(raw) < 512:
                    c = read(int(m[2], 16) + len(raw), 1)
                    if not c or c == b'\0':
                        break
                    raw += c
            except Exception:
                return None
            return raw.decode('latin-1')
        def rebuild(call_args):
            if len(call_args) != len(slots) or len(call_args) <= fmt_index:
                return None
            fmt = fmt_of(call_args[fmt_index])
            if fmt is None:
                return None
            pools = {'r': [], 'f': []}
            for arg, (kind, _) in zip(call_args[fmt_index + 1:], slots[fmt_index + 1:]):
                pools[kind].append(arg)
            used, hoist = [], []
            for conv in _CONVERSION.finditer(fmt):
                if conv[3] == '%':
                    continue
                for star in (conv[1], conv[2]):
                    if star == '*':
                        if not pools['r']:
                            return None
                        used.append(pools['r'].pop(0))
                kind = 'f' if conv[3] in 'fFeEgG' else 'r'
                if not pools[kind]:
                    return None
                used.append(pools[kind].pop(0))
            for arg in pools['r'] + pools['f']:
                if re.match(r'\w+\(', arg) and not arg.startswith('M2C_'):
                    hoist.append(arg)
            used = ['0' if a.startswith('M2C_ERROR(') else a for a in used]
            return call_args[:fmt_index + 1] + used, hoist
        pos, before, rebuilt = decl.end(), out, set()
        pattern = re.compile(r'\b' + name + r'\(')
        while True:
            m = pattern.search(out, pos)
            if not m:
                break
            parsed = _call_args(out, m.end() - 1)
            if parsed and out[m.start():parsed[1]] in rebuilt:
                pos = parsed[1]
                continue
            done = parsed and rebuild(parsed[0])
            if not done:
                # all calls or none: a fixed-arity call left next to the
                # variadic prototype would not compile
                out = None
                break
            (new_args, hoist), end = done, parsed[1]
            call = f'{name}(' + ', '.join(new_args) + ')'
            rebuilt.add(call)
            line_start = out.rfind('\n', 0, m.start()) + 1
            indent = re.match(r'[ \t]*', out[line_start:])[0]
            prefix = ''.join(f'{indent}{h};\n' for h in hoist)
            out = out[:line_start] + prefix + out[line_start:m.start()] + call + out[end:]
            # hoisted calls (still in m2c form) are the next ones scanned
            pos = line_start if hoist else line_start + len(prefix) + (m.start() - line_start) + len(name) + 1
        if out is None:
            out = before
            continue
        out = out.replace(decl[0], proto, 1)
    return None if out == text else out


_ABS_FIELD = re.compile(r'M2C_FIELD\(\s*(?:\(void \*\)\s*\(\(u32\) &(?P<a>\w+)\)|&(?P<b>\w+))\s*,\s*'
                        r'(?P<t>[us](?:8|16|32)|f32|f64|void \*) \*\s*,\s*(?P<k>0x[0-9A-Fa-f]+|\d+)\)')
_ABS_SIZES = {'s8': 1, 'u8': 1, 's16': 2, 'u16': 2, 's32': 4, 'u32': 4, 'f32': 4, 'f64': 8, 'void *': 4}


def abs_struct(text: str):
    """b4: a global m2c (or abs_symbols) reaches only through constant-offset
    fields - `M2C_FIELD(&lbl_X, s32 *, 0x3C)`, `M2C_FIELD((void *)((u32)
    &lbl_X), u8 *, 0x40)` - is declared as a struct with those members.
    ProDG folds `sym+K` into each access (lis + lwz sym+K@l) for a byte
    array, but keeps a struct's address in a register and reaches members by
    offset (addi r30 + lwz 0x3c(r30)), as the target does: RenderState__
    SetDefaults 3 words off -> exact. Needs >= 2 distinct offsets, one type per
    offset, aligned non-overlapping members and every body use a field access.
    Returns None when nothing changes."""
    signature = re.search(r'^[^\n;#]*\b\w+\s*\([^{};]*\)\s*\{', text, re.M)
    if not signature:
        return None
    head, body = text[:signature.start()], text[signature.start():]
    uses = {}
    for m in _ABS_FIELD.finditer(body):
        uses.setdefault(m['a'] or m['b'], []).append(m)
    out_head, out_body = head, body
    changed = False
    for name, ms in uses.items():
        if not name.startswith('lbl_'):
            continue
        if len(re.findall(r'\b' + re.escape(name) + r'\b', body)) != len(ms):
            continue
        fields = {}
        ok = True
        for m in ms:
            k = int(m['k'], 0)
            if fields.setdefault(k, m['t']) != m['t']:
                ok = False
        if not ok or len(fields) < 2:
            continue
        end = 0
        members = []
        for k in sorted(fields):
            size = _ABS_SIZES[fields[k]]
            if k % size or k < end:
                ok = False; break
            if k > end:
                members.append(f'u8 pad_{end:X}[0x{k - end:X}];')
            members.append(f'{fields[k]} f{k:X};')
            end = k + size
        if not ok:
            continue
        decl = re.search(r'^extern [^\n;]*\b' + re.escape(name) + r'\b[^\n;]*;$', out_head, re.M)
        if not decl:
            continue
        struct = f'mt_b4_{name}_t'
        out_head = (out_head[:decl.start()] + f'typedef struct {{ {" ".join(members)} }} {struct};\n'
                    f'extern {struct} {name};' + out_head[decl.end():])
        out_body = re.sub(_ABS_FIELD, lambda m: f'{name}.f{int(m["k"], 0):X}' if (m['a'] or m['b']) == name else m[0], out_body)
        changed = True
    return out_head + out_body if changed else None
