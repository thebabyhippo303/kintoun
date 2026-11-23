#!/usr/bin/env python3
"""mt v4 mutations: source rewrites that change ProDG codegen (real C only).

Every generator yields (family, new_text). Mutations need not preserve C semantics
exactly: a candidate is only ever accepted when its bytes match the DOL, which is
the behavioural ground truth. Families are weighted by the search (mt_search) and
by learned priors (mt_learn).
"""
from __future__ import annotations
import re

PRIM = r'(?:unsigned |signed )?(?:void|char|short|int|long|float|double|[us](?:8|16|32)|f(?:32|64)|M2C_UNK)'
DECL = re.compile(r'^(    )(register )?((?:const )?' + PRIM + r'\s*\**)(\s*\w+)(\[\d+\])?;$')
STORE = re.compile(r' +M2C_FIELD\((\w+), [us](8|16|32) \*, (0x[\da-fA-F]+|\d+)\) = -?(?:0x[\da-fA-F]+|\d+);$')
FIELD = re.compile(r'M2C_FIELD\((\w+), ([us](?:8|16|32)|f32|f64) \*, (0x[\da-fA-F]+|\d+)\)')
SIMPLE = re.compile(r'^( +)([^ ].*);$')
CTRL = re.compile(r'^\s*(if|else|while|do|for|switch|case|default|return|goto|break|continue|\}|block_|[A-Za-z_]\w*:)')
TYPE_FLIP = {'s32': 'u32', 'u32': 's32', 's16': 'u16', 'u16': 's16', 's8': 'u8', 'u8': 's8', 'int': 'unsigned int',
             'unsigned int': 'int', 'short': 'unsigned short', 'unsigned short': 'short', 'char': 'unsigned char',
             'unsigned char': 'char', 'f32': 'f64', 'f64': 'f32', 'float': 'double', 'double': 'float'}
NEG = [(r'==', '!='), (r'!=', '=='), (r'<=', '>'), (r'>=', '<'), (r'<', '>='), (r'>', '<=')]


def body_range(t):
    """(start, end) line indices of the function body (after the first '{' line)."""
    lines = t.split('\n')
    s = next((i for i, l in enumerate(lines) if l.rstrip().endswith('{') and '(' in l and not l.startswith((' ', '\t'))), None)
    if s is None: return lines, 0, len(lines)
    e = max(i for i, l in enumerate(lines) if l == '}')
    return lines, s + 1, e


def indent_of(l):
    return len(l) - len(l.lstrip(' '))


def block_end(lines, i):
    """for a line ending with '{' at indent k, index of its closing line at indent k ('}' or '} else {' or '} while (...);')."""
    k = indent_of(lines[i])
    for j in range(i + 1, len(lines)):
        if indent_of(lines[j]) == k and lines[j].lstrip().startswith('}'): return j
    return None


def negate(c):
    c = c.strip()
    if c.startswith('!(') and c.endswith(')') and balanced(c[1:]): return c[2:-1]
    if c.startswith('!') and re.fullmatch(r'!\w+(\([^()]*\))?', c): return c[1:]
    if re.fullmatch(r'\w+', c): return '!' + c
    depth = 0
    for i, ch in enumerate(c):
        if ch == '(': depth += 1
        elif ch == ')': depth -= 1
        elif depth == 0 and c[i:i + 2] in ('&&', '||'): return '!(' + c + ')'
    for a, b in NEG:
        m = re.search(r'(?<![<>=!])' + re.escape(a) + r'(?!=)', c)
        if m:
            # only top-level operators (not inside parens)
            if c[:m.start()].count('(') == c[:m.start()].count(')'):
                return c[:m.start()] + b + c[m.end():]
    return '!(' + c + ')'


def balanced(s):
    d = 0
    for ch in s:
        if ch == '(': d += 1
        elif ch == ')':
            d -= 1
            if d < 0: return False
    return d == 0


# ---------- families ----------

def m_decl_order(t):
    lines, s, e = body_range(t)
    decl = [i for i in range(s, e) if DECL.match(lines[i])]
    for x, i in enumerate(decl):
        for j in decl[x + 1:]:
            if all(DECL.match(l) or not l.strip() for l in lines[i:j + 1]):
                out = lines[:]; out[i], out[j] = out[j], out[i]
                yield 'decl_order', '\n'.join(out)
    # move one decl to the front / back
    if len(decl) > 2:
        for i in decl[1:]:
            out = lines[:]; l = out.pop(i); out.insert(decl[0], l); yield 'decl_order', '\n'.join(out)
        for i in decl[:-1]:
            out = lines[:]; l = out.pop(i); out.insert(decl[-1], l); yield 'decl_order', '\n'.join(out)


def m_register(t):
    lines, s, e = body_range(t)
    for i in range(s, e):
        m = DECL.match(lines[i])
        if not m: continue
        out = lines[:]
        out[i] = lines[i].replace('register ', '', 1) if m[2] else '    register ' + lines[i].strip()
        yield 'register', '\n'.join(out)


def m_local_type(t):
    lines, s, e = body_range(t)
    for i in range(s, e):
        m = DECL.match(lines[i])
        if not m: continue
        ty = m[3].strip(); base = ty.rstrip('*').strip(); stars = ty[len(base):].strip()
        if base in TYPE_FLIP and not stars:
            out = lines[:]; out[i] = f'{m[1]}{m[2] or ""}{TYPE_FLIP[base]} {m[4].strip()}{m[5] or ""};'
            yield 'local_type', '\n'.join(out)
        if base in ('void', 'char', 'u8', 's8') and stars == '*':
            for nb in ('void', 'char', 'u8'):
                if nb != base:
                    out = lines[:]; out[i] = f'{m[1]}{m[2] or ""}{nb} *{m[4].strip()};'
                    yield 'local_type', '\n'.join(out)
        if stars == '*' and base not in ('void', 'char', 'u8', 's8'):
            out = lines[:]; out[i] = f'{m[1]}{m[2] or ""}void *{m[4].strip()};'
            yield 'local_type', '\n'.join(out)
        if not stars and base in ('s32', 'u32'):
            out = lines[:]; out[i] = f'{m[1]}{m[2] or ""}void *{m[4].strip()};'
            yield 'local_type', '\n'.join(out)
        if stars == '*' and base == 'void':
            out = lines[:]; out[i] = f'{m[1]}{m[2] or ""}s32{m[4]};'
            yield 'local_type', '\n'.join(out)


def m_param_type(t):
    lines, s, e = body_range(t)
    sig = lines[s - 1]
    m = re.match(r'^(.*?\w+)\((.*)\)\s*\{$', sig)
    if not m: return
    params = [p.strip() for p in m[2].split(',')] if m[2].strip() and m[2].strip() != 'void' else []
    for k, p in enumerate(params):
        pm = re.match(r'^((?:const )?' + PRIM + r')\s*(\**)\s*(\w+)$', p)
        if not pm: continue
        base, stars, name = pm.groups()
        alts = []
        if not stars and base in TYPE_FLIP: alts.append(TYPE_FLIP[base] + ' ' + name)
        if not stars and base in ('s32', 'u32', 'int'): alts.append('void *' + name)
        if stars == '*' and base == 'void': alts += ['s32 ' + name, 'char *' + name, 'u8 *' + name]
        if stars == '*' and base in ('char', 'u8', 's8', 'u32', 's32', 'u16', 's16', 'f32'): alts.append('void *' + name)
        for a in alts:
            np = params[:]; np[k] = a
            out = lines[:]; out[s - 1] = f'{m[1]}({", ".join(np)}) {{'
            yield 'param_type', '\n'.join(out)
    # return type flips
    rm = re.match(r'^(' + PRIM + r')(\s*\**\s*)(\w+\(.*\)\s*\{)$', sig)
    if rm and rm[1] in TYPE_FLIP and not rm[2].strip():
        out = lines[:]; out[s - 1] = f'{TYPE_FLIP[rm[1]]} {rm[3]}'; yield 'param_type', '\n'.join(out)


def m_field_type(t):
    seen = set()
    for m in FIELD.finditer(t):
        ty = m[2]
        if ty not in TYPE_FLIP or ty.startswith('f'): continue
        key = (m[1], m[3], ty)
        if key in seen: continue
        seen.add(key)
        # flip every occurrence of this base/offset/type
        pat = re.compile(r'M2C_FIELD\(' + re.escape(m[1]) + r', ' + ty + r' \*, ' + re.escape(m[3]) + r'\)')
        yield 'field_type', pat.sub(f'M2C_FIELD({m[1]}, {TYPE_FLIP[ty]} *, {m[3]})', t)
        # single occurrence flip
        yield 'field_type', t[:m.start()] + f'M2C_FIELD({m[1]}, {TYPE_FLIP[ty]} *, {m[3]})' + t[m.end():]


def m_cast_strip(t):
    for m in re.finditer(r'\((?:s32|u32|s16|u16|s8|u8|f32|f64|int|unsigned int)\) (?=M2C_FIELD|\w|\()', t):
        yield 'cast_strip', t[:m.start()] + t[m.end():]
    # also drop one explicit pointer cast like (u8 *) or (char *)
    for m in re.finditer(r'\((?:void|char|u8|s8|s32|u32) \*\) ', t):
        yield 'cast_strip', t[:m.start()] + t[m.end():]


def m_inline_temp(t):
    """fold `tmp = expr;` into its single use (any following statement in the same block)."""
    lines, s, e = body_range(t)
    names = {DECL.match(l)[4].strip(): i for i, l in enumerate(lines[s:e], s) if DECL.match(l)}
    for i in range(s, e):
        m = re.fullmatch(r'( +)(\w+) = (.+);', lines[i])
        if not m or m[2] not in names: continue
        var, expr = m[2], m[3]
        uses = [j for j in range(s, e) if j != i and re.search(r'\b' + re.escape(var) + r'\b', lines[j]) and j != names[var]]
        if len(uses) != 1: continue
        j = uses[0]
        if j < i or lines[j].lstrip().startswith(var + ' =') and '==' not in lines[j]: continue
        if len(re.findall(r'\b' + re.escape(var) + r'\b', lines[j])) != 1: continue
        out = lines[:]
        rep = expr if re.fullmatch(r'[\w.]+|M2C_FIELD\([^()]*\)|\w+\([^()]*\)|&\w+', expr) else '(' + expr + ')'
        out[j] = re.sub(r'\b' + re.escape(var) + r'\b', lambda _: rep, lines[j])
        del out[i]
        # drop the declaration when it is now unused
        di = names[var] - (1 if names[var] > i else 0)
        if not any(re.search(r'\b' + re.escape(var) + r'\b', l) for k, l in enumerate(out) if k != di):
            del out[di]
        yield 'inline_temp', '\n'.join(out)


def m_hoist_cse(t):
    """introduce a temp for a repeated field read / call-free expression."""
    lines, s, e = body_range(t)
    decl = [i for i in range(s, e) if DECL.match(lines[i])]
    if not decl: return
    cnt = {}
    for m in FIELD.finditer('\n'.join(lines[s:e])):
        cnt[m[0]] = cnt.get(m[0], 0) + 1
    for expr, n in cnt.items():
        if n < 2: continue
        fm = FIELD.match(expr); ty = fm[2]
        base_hits = [i for i in range(s, e) if expr in lines[i]]
        if len(base_hits) < 2: continue
        first = base_hits[0]
        if any(lines[k].lstrip().startswith(('do {', 'while', 'for')) for k in range(s, first)): pass
        name = 'tmp_' + fm[3].replace('0x', '')
        while re.search(r'\b' + name + r'\b', t): name += '_'
        out = lines[:]
        for i in base_hits: out[i] = out[i].replace(expr, name)
        ind = re.match(r' *', lines[first])[0]
        out.insert(first, f'{ind}{name} = {expr};')
        out.insert(decl[0], f'    {ty} {name};')
        yield 'hoist_cse', '\n'.join(out)
    # hoist a repeated base pointer: M2C_FIELD(X, ...) where X is an expression used twice
    for m in set(re.findall(r'M2C_FIELD\((\w+ \+ 0x[\dA-Fa-f]+), ', '\n'.join(lines[s:e]))):
        pass


def m_split_load(t):
    """assign a field read to a fresh typed local right before the statement using it (tkv3 family)."""
    lines, s, e = body_range(t)
    decl = [i for i in range(s, e) if DECL.match(lines[i])]
    if not decl or 'volatile' in t: return
    for i in range(s, e):
        if not re.match(r' +(\w+ = |return |\w+\()', lines[i]) or lines[i].lstrip().startswith(('if', 'while', 'do', 'for')): continue
        for m in FIELD.finditer(lines[i]):
            if re.fullmatch(r' +\w+ = ' + re.escape(m[0]) + r';', lines[i]): continue
            name = 'ld_' + m[3].replace('0x', '')
            while re.search(r'\b' + name + r'\b', t): name += '_'
            out = lines[:]; ind = re.match(r' *', lines[i])[0]
            out[i] = lines[i][:m.start()] + name + lines[i][m.end():]
            out.insert(i, f'{ind}{name} = {m[0]};')
            out.insert(decl[0], f'    {m[2]} {name};')
            yield 'split_load', '\n'.join(out)


def m_swap_stmts(t):
    lines, s, e = body_range(t)
    for i in range(s, e - 1):
        a, b = lines[i], lines[i + 1]
        if indent_of(a) != indent_of(b): continue
        if not (SIMPLE.match(a) and SIMPLE.match(b)) or CTRL.match(a) or CTRL.match(b) or DECL.match(a) or DECL.match(b): continue
        if a.rstrip().endswith('{') or b.rstrip().endswith('{'): continue
        # do not swap two statements where the second reads what the first writes
        wa = re.match(r' +(\w+) = ', a)
        if wa and re.search(r'\b' + wa[1] + r'\b', b): continue
        wb = re.match(r' +(\w+) = ', b)
        if wb and re.search(r'\b' + wb[1] + r'\b', a): continue
        out = lines[:]; out[i], out[i + 1] = b, a
        yield 'swap_stmts', '\n'.join(out)


def m_ordered_stores(t):
    """sort a run of constant stores on one base by ascending offset."""
    if 'volatile' in t: return
    lines = t.split('\n'); out = lines[:]; i = 0; changed = False
    while i < len(lines):
        first = STORE.fullmatch(lines[i])
        if not first: i += 1; continue
        end = i
        while end < len(lines) and STORE.fullmatch(lines[end]) and STORE.fullmatch(lines[end])[1] == first[1]: end += 1
        srt = sorted(lines[i:end], key=lambda l: int(STORE.fullmatch(l)[3], 0))
        if srt != lines[i:end]: out[i:end] = srt; changed = True
        i = end
    if changed: yield 'ordered_stores', '\n'.join(out)


def m_if_invert(t):
    lines, s, e = body_range(t)
    for i in range(s, e):
        m = re.match(r'^( +)if \((.*)\) \{$', lines[i])
        if not m: continue
        j = block_end(lines, i)
        if j is None: continue
        if lines[j] == m[1] + '} else {':
            k = block_end(lines, j)
            if k is None or lines[k] != m[1] + '}': continue
            then = lines[i + 1:j]; els = lines[j + 1:k]
            out = lines[:i] + [f'{m[1]}if ({negate(m[2])}) {{'] + els + [m[1] + '} else {'] + then + lines[k:]
            yield 'if_invert', '\n'.join(out)
        elif lines[j] == m[1] + '}':
            then = lines[i + 1:j]
            last = then[-1].strip() if then else ''
            # `if (c) { ...; return/goto; } REST` -> `if (!c) { REST } else { ...; return }` only when REST is the tail of the block
            k = j + 1
            while k < e and indent_of(lines[k]) >= len(m[1]) and not (indent_of(lines[k]) == len(m[1]) and lines[k].lstrip().startswith('}')): k += 1
            rest = lines[j + 1:k]
            if rest and last.startswith(('return', 'goto')) and len(rest) <= 12 and not any(re.match(r'\s*\w+:$', l) for l in rest):
                out = lines[:i] + [f'{m[1]}if ({negate(m[2])}) {{'] + ['    ' + l for l in rest] + [m[1] + '} else {'] + then + [m[1] + '}'] + lines[k:]
                yield 'if_invert', '\n'.join(out)
            # `if (c) { A }` where A is the tail -> `if (!c) return; A`  (early return)
            if not rest and len(m[1]) == 4 and k >= e - 1 and not any('return' in l for l in then):
                out = lines[:i] + [f'{m[1]}if ({negate(m[2])}) {{', m[1] + '    return;', m[1] + '}'] + [l[4:] for l in then] + lines[j + 1:]
                yield 'if_invert', '\n'.join(out)


def m_cond_rewrite(t):
    lines, s, e = body_range(t)
    for i in range(s, e):
        m = re.match(r'^( +)(if|while|\} while) \((.*)\)( \{|;)$', lines[i])
        if not m: continue
        c = m[3]
        outs = []
        # commute comparison: a OP b -> b OP' a
        cm = re.fullmatch(r'(.+?) (<|>|<=|>=|==|!=) (.+)', c)
        if cm and balanced(cm[1]) and balanced(cm[3]):
            flip = {'<': '>', '>': '<', '<=': '>=', '>=': '<=', '==': '==', '!=': '!='}
            outs.append(f'{cm[3]} {flip[cm[2]]} {cm[1]}')
        # !(a >= b) -> a < b  and  a < b -> !(a >= b)   (float compare form)
        nm = re.fullmatch(r'!\((.+?) (<|>|<=|>=) (.+)\)', c)
        if nm and balanced(nm[1]) and balanced(nm[3]):
            inv = {'<': '>=', '>': '<=', '<=': '>', '>=': '<'}
            outs.append(f'{nm[1]} {inv[nm[2]]} {nm[3]}')
        elif cm and cm[2] in ('<', '>', '<=', '>='):
            inv = {'<': '>=', '>': '<=', '<=': '>', '>=': '<'}
            outs.append(f'!({cm[1]} {inv[cm[2]]} {cm[3]})')
        # x != 0 -> x ; x == 0 -> !x
        zm = re.fullmatch(r'(.+) (!=|==) (0|NULL)', c)
        if zm and balanced(zm[1]): outs.append(zm[1] if zm[2] == '!=' else '!' + (zm[1] if re.fullmatch(r'\w+|\w+\([^()]*\)', zm[1]) else '(' + zm[1] + ')'))
        # (a != 0) || (b != 0)  <->  (a | b) != 0   (ProDG: `or.` vs two compares)
        om = re.fullmatch(r'\((\w+) != 0\) \|\| \((\w+) != 0\)', c)
        if om: outs.append(f'({om[1]} | {om[2]}) != 0')
        om = re.fullmatch(r'\((\w+) \| (\w+)\) != 0', c)
        if om: outs.append(f'({om[1]} != 0) || ({om[2]} != 0)')
        om = re.fullmatch(r'\((\w+) == 0\) && \((\w+) == 0\)', c)
        if om: outs.append(f'({om[1]} | {om[2]}) == 0')
        # && split into nested ifs
        if m[2] == 'if' and m[4] == ' {':
            am = re.fullmatch(r'\((.+)\) && \((.+)\)', c)
            if am and balanced(am[1]) and balanced(am[2]):
                j = block_end(lines, i)
                if j is not None and lines[j] == m[1] + '}':
                    out = lines[:i] + [f'{m[1]}if ({am[1]}) {{', f'{m[1]}    if ({am[2]}) {{'] + ['    ' + l for l in lines[i + 1:j]] + [m[1] + '    }', m[1] + '}'] + lines[j + 1:]
                    yield 'cond_rewrite', '\n'.join(out)
        for nc in outs:
            out = lines[:]; out[i] = f'{m[1]}{m[2]} ({nc}){m[4]}'
            yield 'cond_rewrite', '\n'.join(out)


def m_loop_shape(t):
    lines, s, e = body_range(t)
    for i in range(s, e):
        ind = re.match(r' *', lines[i])[0]
        # do { B } while (C);  ->  while (C) { B }   (ProDG top-tested loops lay out the same way after -O2 for many bodies)
        if lines[i] == ind + 'do {':
            j = block_end(lines, i)
            if j is None: continue
            wm = re.match(r'^ +\} while \((.*)\);$', lines[j])
            if not wm: continue
            body = lines[i + 1:j]
            yield 'loop_shape', '\n'.join(lines[:i] + [f'{ind}while ({wm[1]}) {{'] + body + [ind + '}'] + lines[j + 1:])
            # count-down -> for
            dm = re.fullmatch(r'(\w+) != 0', wm[1])
            if dm and body and re.fullmatch(r' +' + dm[1] + r' -= 1;', body[-1]):
                init = next((k for k in range(i - 1, s - 1, -1) if re.fullmatch(r' +' + dm[1] + r' = (\w+);', lines[k])), None)
                if init is not None:
                    n = re.fullmatch(r' +' + dm[1] + r' = (\w+);', lines[init])[1]
                    out = lines[:init] + lines[init + 1:i] + [f'{ind}for ({dm[1]} = 0; {dm[1]} < {n}; {dm[1]} += 1) {{'] + body[:-1] + [ind + '}'] + lines[j + 1:]
                    yield 'loop_shape', '\n'.join(out)
            # for-style with increment at end: do { B; i += 1; } while (i < n)  ->  for (; i < n; i += 1) { B }
            im = re.fullmatch(r'(\w+) (<|<=|!=) (\w+)', wm[1])
            if im and body and re.fullmatch(r' +' + im[1] + r' (\+= 1|\+\+);', body[-1]):
                out = lines[:i] + [f'{ind}for (; {wm[1]}; {im[1]} += 1) {{'] + body[:-1] + [ind + '}'] + lines[j + 1:]
                yield 'loop_shape', '\n'.join(out)
        wm = re.match(r'^( +)while \((.*)\) \{$', lines[i])
        if wm:
            j = block_end(lines, i)
            if j is None or lines[j] != wm[1] + '}': continue
            body = lines[i + 1:j]
            out = lines[:i] + [f'{ind}if ({wm[2]}) {{', f'{ind}    do {{'] + ['    ' + l for l in body] + [f'{ind}    }} while ({wm[2]});', ind + '}'] + lines[j + 1:]
            yield 'loop_shape', '\n'.join(out)
        fm = re.match(r'^( +)for \((.*?); (.*?); (.*?)\) \{$', lines[i])
        if fm:
            j = block_end(lines, i)
            if j is None: continue
            body = lines[i + 1:j]
            pre = [f'{ind}{fm[2]};'] if fm[2].strip() else []
            out = lines[:i] + pre + [f'{ind}while ({fm[3]}) {{'] + body + [f'{ind}    {fm[4]};', ind + '}'] + lines[j + 1:]
            yield 'loop_shape', '\n'.join(out)


def m_return_style(t):
    lines, s, e = body_range(t)
    for i in range(s, e - 1):
        m = re.fullmatch(r'( +)(\w+) = (.+);', lines[i])
        if m and lines[i + 1] == f'{m[1]}return {m[2]};':
            out = lines[:i] + [f'{m[1]}return {m[3]};'] + lines[i + 2:]
            yield 'return_style', '\n'.join(out)
    # phi boolean (tkv3): v = 1; if (x == 0) { v = 0; } return v;  ->  return x != 0;
    pat = re.compile(r'(?P<indent> +)(?P<v>\w+) = (?P<a>[01]);\n(?P=indent)if \((?P<expr>[^\n]+)\) \{\n +(?P=v) = (?P<b>[01]);\n(?P=indent)\}\n(?P=indent)return (?P=v);')
    for m in pat.finditer(t):
        cond = m['expr'] if m['b'] == '1' else negate(m['expr'])
        yield 'return_style', t[:m.start()] + m['indent'] + f'return {cond};' + t[m.end():]
    # ternary <-> if/else assignment
    for i in range(s, e):
        m = re.match(r'^( +)if \((.*)\) \{$', lines[i])
        if not m: continue
        j = block_end(lines, i)
        if j is None or lines[j] != m[1] + '} else {': continue
        k = block_end(lines, j)
        if k is None or j - i != 2 or k - j != 2: continue
        a = re.fullmatch(r' +(\w+) = (.+);', lines[i + 1]); b = re.fullmatch(r' +(\w+) = (.+);', lines[j + 1])
        if a and b and a[1] == b[1]:
            yield 'return_style', '\n'.join(lines[:i] + [f'{m[1]}{a[1]} = ({m[2]}) ? {a[2]} : {b[2]};'] + lines[k + 1:])
    for i in range(s, e):
        m = re.fullmatch(r'( +)(\w+) = \((.+)\) \? (.+) : (.+);', lines[i])
        if m:
            yield 'return_style', '\n'.join(lines[:i] + [f'{m[1]}if ({m[3]}) {{', f'{m[1]}    {m[2]} = {m[4]};', f'{m[1]}}} else {{', f'{m[1]}    {m[2]} = {m[5]};', m[1] + '}'] + lines[i + 1:])


def m_arith(t):
    for m in re.finditer(r'\b(\w+) \* (2|4|8|16|32|64|128|256)\b', t):
        yield 'arith', t[:m.start()] + f'{m[1]} << {int(m[2]).bit_length() - 1}' + t[m.end():]
    for m in re.finditer(r'\b(\w+) << (\d)\b', t):
        yield 'arith', t[:m.start()] + f'{m[1]} * {1 << int(m[2])}' + t[m.end():]
    for m in re.finditer(r'\(f32\) (\d+)\b', t):
        yield 'arith', t[:m.start()] + f'{m[1]}.0f' + t[m.end():]
    for m in re.finditer(r'(?<![\w.])(\d+\.\d+)f\b', t):
        yield 'arith', t[:m.start()] + m[1] + t[m.end():]
    for m in re.finditer(r'(?<![\w.])(\d+\.\d+)(?![\wf.])', t):
        yield 'arith', t[:m.start()] + m[1] + 'f' + t[m.end():]
    for m in re.finditer(r'\b(\w+) \+ (0x[\dA-Fa-f]+|\d+)\b(?!\))', t):
        pass


def m_global_section(t):
    for m in re.finditer(r'^(extern [^;\n]*?)( __attribute__\(\(section\("\.\w+"\)\)\))?;$', t, flags=re.M):
        if m[2]: yield 'global_section', t[:m.start()] + m[1] + ';' + t[m.end():]
        else: yield 'global_section', t[:m.start()] + m[1] + ' __attribute__((section(".data")));' + t[m.end():]


def m_var_split(t):
    """a local assigned twice -> second assignment uses a fresh variable until the next assignment."""
    lines, s, e = body_range(t)
    decls = {DECL.match(l)[4].strip(): (i, DECL.match(l)) for i, l in enumerate(lines[s:e], s) if DECL.match(l)}
    for var, (di, dm) in decls.items():
        asg = [i for i in range(s, e) if re.match(r' +' + re.escape(var) + r' = ', lines[i])]
        if len(asg) < 2: continue
        for a in asg[1:]:
            new = var + '_b'
            while re.search(r'\b' + new + r'\b', t): new += '_'
            out = lines[:]; nxt = next((k for k in asg if k > a), e)
            if any(re.search(r'\b' + re.escape(var) + r'\b', lines[k]) for k in range(nxt, e)) and nxt == e: pass
            for k in range(a, nxt):
                out[k] = re.sub(r'\b' + re.escape(var) + r'\b', new, out[k])
            out.insert(di + 1, f'    {dm[3]}{new};' if dm[3].endswith('*') else f'    {dm[3]} {new};')
            yield 'var_split', '\n'.join(out)


def m_callee_proto(t):
    """flip a borrowed callee's void/int return and pointer/int arg types."""
    for m in re.finditer(r'^(M2C_UNK|void|s32|u32|void \*|f32) (\w+)\(([^)]*)\);$', t, flags=re.M):
        ret, name, args = m.groups()
        for nr in ('void', 's32', 'void *', 'f32'):
            if nr != ret: yield 'callee_proto', t[:m.start()] + f'{nr} {name}({args});' + t[m.end():]
        al = [a.strip() for a in args.split(',')] if args.strip() else []
        for k, a in enumerate(al):
            alt = {'s32': 'void *', 'void *': 's32', 'u32': 's32', 'f32': 'f64', 'f64': 'f32', 'M2C_UNK': 'void *'}.get(a)
            if alt:
                na = al[:]; na[k] = alt
                yield 'callee_proto', t[:m.start()] + f'{ret} {name}({", ".join(na)});' + t[m.end():]
        if al and al[-1] != '...':
            yield 'callee_proto', t[:m.start()] + f'{ret} {name}({", ".join(al)}, ...);' + t[m.end():]


def m_goto_inline(t):
    """replace `goto L;` with a copy of L's block when it ends in return (undo cross-jumping)."""
    lines, s, e = body_range(t)
    labels = {m[1]: i for i, l in enumerate(lines) if (m := re.fullmatch(r'\s*(\w+):', l))}
    for i in range(s, e):
        m = re.fullmatch(r'( +)goto (\w+);', lines[i])
        if not m or m[2] not in labels: continue
        li = labels[m[2]]
        blk = []
        for j in range(li + 1, e):
            l = lines[j]
            if indent_of(l) < indent_of(lines[li + 1]) or re.fullmatch(r'\s*\w+:', l): break
            blk.append(l)
            if l.strip().startswith('return'): break
        if not blk or not blk[-1].strip().startswith('return') or len(blk) > 10: continue
        if any(x.rstrip().endswith('{') for x in blk): continue
        base = indent_of(blk[0])
        out = lines[:i] + [m[1] + x[base:] for x in blk] + lines[i + 1:]
        # drop the label if no goto remains
        if not any(re.search(r'\bgoto ' + m[2] + r'\b', l) for l in out):
            out = [l for l in out if not re.fullmatch(r'\s*' + m[2] + ':', l)]
        yield 'goto_inline', '\n'.join(out)


VEC3_TYPEDEF = 'typedef struct { f32 x, y, z; } Vec3;'


def ensure_vec3(t):
    if re.search(r'\bVec3\b', t.split('\n{', 1)[0]) and 'typedef' in t and '} Vec3;' in t: return t
    if '} Vec3;' in t: return t
    i = t.find('#define NULL 0')
    if i >= 0:
        j = t.index('\n', i) + 1
        return t[:j] + VEC3_TYPEDEF + '\n' + t[j:]
    return VEC3_TYPEDEF + '\n' + t


def m_alias_fold(t):
    """fold `tmp = base + K;` into its M2C_FIELD uses (tmp used only as a field base)."""
    lines, s, e = body_range(t)
    for i in range(s, e):
        m = re.fullmatch(r' +(\w+) = (\w+) \+ (0x[\dA-Fa-f]+|\d+);', lines[i])
        if not m: continue
        var, base, k = m[1], m[2], int(m[3], 0)
        uses = [j for j in range(s, e) if j != i and re.search(r'\b' + var + r'\b', lines[j])]
        if not uses or any(not DECL.match(lines[j]) and not re.search(r'M2C_FIELD\(' + var + r', ', lines[j]) for j in uses): continue
        if any(re.search(r'\b' + var + r'\b(?![, ])', lines[j]) and not DECL.match(lines[j]) for j in uses): continue
        if any(re.search(r'(?<!M2C_FIELD\()\b' + var + r'\b', lines[j]) and not DECL.match(lines[j]) for j in uses): continue
        out = lines[:]
        for j in uses:
            if DECL.match(lines[j]): continue
            out[j] = re.sub(r'M2C_FIELD\(' + var + r', ([^,]+), (0x[\dA-Fa-f]+|\d+)\)',
                            lambda mm: f'M2C_FIELD({base}, {mm[1]}, {int(mm[2], 0) + k:#x})', lines[j])
        del out[i]
        di = [j for j in uses if DECL.match(lines[j])]
        for j in sorted(di, reverse=True):
            if not any(re.search(r'\b' + var + r'\b', l) for kk, l in enumerate(out) if kk != (j - (1 if j > i else 0))):
                del out[j - (1 if j > i else 0)]
        yield 'alias_fold', '\n'.join(out)


def m_struct_copy(t):
    """three word/float copies at +0/+4/+8 -> one 12-byte struct assignment (ProDG emits lwz/stw triples)."""
    lines, s, e = body_range(t)
    ST = re.compile(r'( +)M2C_FIELD\((\w+), ([us]32|f32) \*, (0x[\dA-Fa-f]+|\d+)\) = (?:\([us]32|f32\) )?M2C_FIELD\((\w+), ([us]32|f32) \*, (0x[\dA-Fa-f]+|\d+)\);')
    SP = re.compile(r'( +)(sp[\dA-Fa-f]+|\w+) = (?:\([us]32|f32\) )?M2C_FIELD\((\w+), ([us]32|f32) \*, (0x[\dA-Fa-f]+|\d+)\);')
    for i in range(s, e):
        m = ST.fullmatch(lines[i])
        if not m: continue
        grp = {int(m[4], 0) - 0: (i, m)}
        d0, s0 = int(m[4], 0), int(m[7], 0)
        found = {0: i}
        for j in range(i + 1, min(e, i + 7)):
            mm = ST.fullmatch(lines[j])
            if not mm or mm[2] != m[2] or mm[5] != m[5]: continue
            dk, sk = int(mm[4], 0), int(mm[7], 0)
            for base_d in (d0, d0 - 4, d0 - 8):
                pass
            found[(dk, sk)] = j
        # find an origin (D, S) such that offsets D..D+8 / S..S+8 all present
        cands = [(int(mm[4], 0), int(mm[7], 0), j) for j in range(i, min(e, i + 7)) if (mm := ST.fullmatch(lines[j])) and mm[2] == m[2] and mm[5] == m[5]]
        offs = {(d, sx): j for d, sx, j in cands}
        for d, sx, j in cands:
            trip = [(d + k, sx + k) for k in (0, 4, 8)]
            if all(tp in offs for tp in trip) and offs[trip[0]] == i or (all(tp in offs for tp in trip) and i == min(offs[tp] for tp in trip)):
                idxs = sorted(offs[tp] for tp in trip)
                if len(set(idxs)) != 3: continue
                out = lines[:]
                out[idxs[0]] = f'{m[1]}*(Vec3 *)((char *){m[2]} + {d:#x}) = *(Vec3 *)((char *){m[5]} + {sx:#x});'
                for k in idxs[1:][::-1]: del out[k]
                yield 'struct_copy', ensure_vec3('\n'.join(out))
                break
    # stack temps: spA = M2C_FIELD(S, T *, s); spA+4 = ...+4; spA+8 = ...+8  -> Vec3 local copy
    # (a `temp = M2C_FIELD(...); spB = temp;` pair inside the window counts as a direct load)
    for i in range(s, e):
        m = SP.fullmatch(lines[i])
        if not m or not re.fullmatch(r'sp[\dA-Fa-f]+', m[2]): continue
        base, s0 = m[3], int(m[5], 0)
        win = list(range(i, min(e, i + 8)))
        loads = {}   # line -> (spname, offset)
        drop = set()
        temps = {}
        for j in range(max(s, i - 4), win[-1] + 1):
            mm = SP.fullmatch(lines[j])
            if not mm or mm[3] != base: continue
            if re.fullmatch(r'sp[\dA-Fa-f]+', mm[2]):
                if j >= i: loads[j] = (mm[2], int(mm[5], 0))
            elif mm[2].startswith('temp_'): temps[mm[2]] = (j, int(mm[5], 0))
        for j in win:
            t = re.fullmatch(r' +(sp[\dA-Fa-f]+) = (temp_\w+);', lines[j])
            if t and t[2] in temps:
                loads[j] = (t[1], temps[t[2]][1])
                if sum(1 for l in lines[s:e] if re.search(r'\b' + t[2] + r'\b', l)) == 3: drop.add(temps[t[2]][0])
        base_off = min((off for _, off in loads.values()), default=s0)
        hits = {off - base_off: (j, nm) for j, (nm, off) in loads.items() if off - base_off in (0, 4, 8)}
        if set(hits) != {0, 4, 8} or min(j for j, _ in hits.values()) != i: continue
        s0 = base_off
        names = [hits[k][1] for k in (0, 4, 8)]
        try: sp0 = int(names[0][2:], 16)
        except ValueError: continue
        if [int(n[2:], 16) for n in names] != [sp0, sp0 + 4, sp0 + 8]: continue
        vec = 'vec_' + names[0]
        out = lines[:]
        out[i] = f'{m[1]}{vec} = *(Vec3 *)((char *){base} + {s0:#x});'
        for k in sorted(({hits[0][0], hits[4][0], hits[8][0]} - {i}) | drop, reverse=True): del out[k]
        rest = '\n'.join(out)
        used = {n: len(re.findall(r'\b' + n + r'\b', rest)) for n in names}
        if all(used[n] <= 1 for n in names):
            out = [l for l in out if not (DECL.match(l) and DECL.match(l)[4].strip() in names)]
        for tn, (tj, _) in temps.items():
            if tj in drop and len(re.findall(r'\b' + tn + r'\b', '\n'.join(out))) == 1:
                out = [l for l in out if not (DECL.match(l) and DECL.match(l)[4].strip() == tn)]
        if not any(re.fullmatch(r' +Vec3 ' + vec + ';', l) for l in out):
            decl_at = next((k for k, l in enumerate(out) if DECL.match(l)), None)
            if decl_at is None: continue
            out.insert(decl_at, f'    Vec3 {vec};')
        yield 'struct_copy', ensure_vec3('\n'.join(out))


def m_array_size(t):
    for m in re.finditer(r'^( +)(char|u8|s8|s16|s32|u32|f32) (\w+)\[(\d+)\];$', t, flags=re.M):
        n = int(m[4])
        for d in (-8, -4, 4, 8, 16):
            if n + d >= 4: yield 'array_size', t[:m.start()] + f'{m[1]}{m[2]} {m[3]}[{n + d}];' + t[m.end():]
        if m[2] == 'char':
            yield 'array_size', t[:m.start()] + f'{m[1]}u8 {m[3]}[{n}];' + t[m.end():]


def split_args(a):
    out, depth, cur = [], 0, ''
    for ch in a:
        if ch in '([': depth += 1
        elif ch in ')]': depth -= 1
        if ch == ',' and depth == 0: out.append(cur.strip()); cur = ''
        else: cur += ch
    if cur.strip(): out.append(cur.strip())
    return out


def m_call_trim(t):
    """drop trailing arguments of an indirect call (m2c passes every live register to unknown pointers)."""
    lines, s, e = body_range(t)
    for i in range(s, e):
        m = re.fullmatch(r'( +)(?:(\w+) = )?(temp_\w+|M2C_FIELD\([^;]*?\(\*\*\)\([^;]*?\), (?:0x[\dA-Fa-f]+|\d+)\))\((.*)\);', lines[i])
        if not m: continue
        args = split_args(m[4])
        if len(args) < 2: continue
        for drop in (1, 2, 3, 4):
            if len(args) - drop < 1: break
            new_args = args[:-drop]
            callee = m[3]
            cm = re.search(r'\(\*\*\)\(([^()]*)\)', callee)
            if cm:
                types = split_args(cm[1])
                if len(types) == len(args): callee = callee[:cm.start(1)] + ', '.join(types[:-drop]) + callee[cm.end(1):]
            out = lines[:]
            out[i] = f'{m[1]}{m[2] + " = " if m[2] else ""}{callee}({", ".join(new_args)});'
            if not cm:
                for k in range(s, e):
                    dm = re.fullmatch(r'( +)(.*)\(\*' + re.escape(m[3]) + r'\)\(([^()]*)\);', lines[k])
                    if dm:
                        types = split_args(dm[3])
                        if len(types) == len(args): out[k] = f'{dm[1]}{dm[2]}(*{m[3]})({", ".join(types[:-drop])});'
            yield 'call_trim', '\n'.join(out)

BINOP = re.compile(r'(?<![\w.)\]])((?:\([^()]*\)|[\w.]+(?:\([^()]*\))?)) (\*|\+|&|\||\^) ((?:\([^()]*\)|[\w.]+(?:\([^()]*\))?))(?![\w(])')


def m_commute(t):
    """a * b -> b * a, a + b -> b + a (operand order decides which register holds which value)."""
    lines, s, e = body_range(t)
    seen = set()
    for i in range(s, e):
        for m in BINOP.finditer(lines[i]):
            if m[1] == m[3] or re.fullmatch(r'-?(?:0x[\dA-Fa-f]+|\d+(?:\.\d+)?f?)', m[1]): continue
            if 'M2C_FIELD' in m[0] and '(' in m[1] and '(' in m[3]: pass
            out = lines[:]; out[i] = lines[i][:m.start()] + f'{m[3]} {m[2]} {m[1]}' + lines[i][m.end():]
            k = '\n'.join(out)
            if k not in seen: seen.add(k); yield 'commute', k


def m_float_expr(t):
    """float expression shapes: reassociate products/sums, (f32) casts, pull a binary subexpression into a temp."""
    lines, s, e = body_range(t)
    decl = [i for i in range(s, e) if DECL.match(lines[i])]
    ftemps = {DECL.match(l)[4].strip() for l in lines[s:e] if DECL.match(l) and DECL.match(l)[3].strip() in ('f32', 'f64')}
    for i in range(s, e):
        line = lines[i]
        if not re.search(r'\bf(?:32|64)\b|[fF]\d|\b(?:temp|var)_f\d|\d\.\d', line) and not any(re.search(r'\b' + v + r'\b', line) for v in ftemps):
            continue
        # (a * b) * c  <->  a * (b * c) ; (a + b) + c <-> a + (b + c)
        for m in re.finditer(r'\(([^()]+?) (\*|\+) ([^()]+?)\) \2 ([\w.]+(?:\([^()]*\))?)', line):
            out = lines[:]; out[i] = line[:m.start()] + f'{m[1]} {m[2]} ({m[3]} {m[2]} {m[4]})' + line[m.end():]
            yield 'float_expr', '\n'.join(out)
        for m in re.finditer(r'([\w.]+(?:\([^()]*\))?) (\*|\+) \(([^()]+?) \2 ([^()]+?)\)', line):
            out = lines[:]; out[i] = line[:m.start()] + f'({m[1]} {m[2]} {m[3]}) {m[2]} {m[4]}' + line[m.end():]
            yield 'float_expr', '\n'.join(out)
        # insert / remove (f32) around a parenthesised binary expression
        for m in re.finditer(r'(?<!\(f32\) )\(([^()]+ [-+*/] [^()]+)\)', line):
            out = lines[:]; out[i] = line[:m.start()] + f'(f32) ({m[1]})' + line[m.end():]
            yield 'float_expr', '\n'.join(out)
        for m in re.finditer(r'\(f32\) \(([^()]+)\)', line):
            out = lines[:]; out[i] = line[:m.start()] + f'({m[1]})' + line[m.end():]
            yield 'float_expr', '\n'.join(out)
        # hoist a parenthesised binary subexpression into a fresh f32 temp right before the statement
        if decl and re.match(r' +(?:\w+ = |return |M2C_FIELD\()', line) and not line.lstrip().startswith(('if', 'while')):
            for m in re.finditer(r'\(([^()]+ [-+*/] [^()]+)\)', line):
                name = 'fx'
                while re.search(r'\b' + name + r'\b', t): name += '_'
                out = lines[:]; ind = re.match(r' *', line)[0]
                out[i] = line[:m.start()] + name + line[m.end():]
                out.insert(i, f'{ind}{name} = {m[1]};')
                out.insert(decl[0], f'    f32 {name};')
                yield 'float_expr', '\n'.join(out)
        # f32 <-> f64 on a float literal expression: 0.5f <-> 0.5 handled by m_arith; here: double temp
    # f64 temp for an f32 temp whose value feeds a double op (frsp hints)
    for i in decl:
        dm = DECL.match(lines[i])
        if dm[3].strip() == 'f32':
            out = lines[:]; out[i] = f'    f64 {dm[4].strip()};'; yield 'float_expr', '\n'.join(out)


def m_cr_flag(t):
    """hoist a condition that is tested more than once into an int flag computed once (CR-bit flags)."""
    lines, s, e = body_range(t)
    decl = [i for i in range(s, e) if DECL.match(lines[i])]
    if not decl: return
    conds = {}
    for i in range(s, e):
        m = re.match(r'^ +(?:if|\} while|while) \((.*)\)(?: \{|;)$', lines[i])
        if not m: continue
        c = m[1]
        for sub in set(re.findall(r'\(?(\w+ (?:==|!=|<|>|<=|>=) (?:\w+|0x[\dA-Fa-f]+))\)?', c)) | ({c} if re.fullmatch(r'\w+ (?:==|!=|<|>|<=|>=) \w+', c) else set()):
            conds.setdefault(sub, []).append(i)
    for cond, where in conds.items():
        if len(where) < 2: continue
        first = where[0]
        var = re.match(r'(\w+)', cond)[1]
        # the hoisted compare must sit after the variable's last assignment before `first`
        asg = [k for k in range(s, first) if re.match(r' +' + re.escape(var) + r' = ', lines[k])]
        at = (asg[-1] + 1) if asg else decl[-1] + 1
        while at < first and (DECL.match(lines[at]) or not lines[at].strip()): at += 1
        name = 'flag'
        while re.search(r'\b' + name + r'\b', t): name += '_'
        out = lines[:]
        for i in where: out[i] = out[i].replace(cond, name)
        ind = re.match(r' *', lines[at])[0] or '    '
        out.insert(at, f'{ind}{name} = {cond};')
        out.insert(decl[0], f'    s32 {name};')
        yield 'cr_flag', '\n'.join(out)



def m_bool_assign(t):
    """m2c phi boolean `v = 1; if (X) { v = 0; }` -> `v = !(X);` (GCC folds `a || b` on side-effect-free operands into this)."""
    pat = re.compile(r'(?P<i> +)(?P<v>\w+) = (?P<a>[01]);\n(?P=i)if \((?P<c>[^\n]+)\) \{\n(?P=i)    (?P=v) = (?P<b>[01]);\n(?P=i)\}\n')
    for m in pat.finditer(t):
        if m['a'] == m['b']: continue
        cond = m['c'] if m['b'] == '1' else negate(m['c'])
        cond = re.sub(r'^\(s32\) ', '', cond)
        yield 'bool_assign', t[:m.start()] + f"{m['i']}{m['v']} = {cond};\n" + t[m.end():]


def m_bool_phi(t):
    """the reverse of bool_assign: `v = a != b;` -> `v = 1; if (!(a != b)) { v = 0; }`."""
    for m in re.finditer(r'^( +)(\w+) = ([^;=\n]+ (?:!=|==) [^;\n]+);$', t, flags=re.M):
        yield 'bool_phi', t[:m.start()] + f"{m[1]}{m[2]} = 1;\n{m[1]}if ({negate(m[3])}) {{\n{m[1]}    {m[2]} = 0;\n{m[1]}}}" + t[m.end():]

def m_temp_merge(t):
    """merge two same-typed locals whose live ranges do not overlap (ProDG reused one register)."""
    lines, s, e = body_range(t)
    decls = {}
    for i in range(s, e):
        m = DECL.match(lines[i])
        if m: decls[m[4].strip()] = (i, m[3].strip())
    def uses(v):
        return [k for k in range(s, e) if k != decls[v][0] and re.search(r'\b' + re.escape(v) + r'\b', lines[k])]
    names = list(decls)
    for x, a in enumerate(names):
        for b in names[x + 1:]:
            if decls[a][1] != decls[b][1]: continue
            ua, ub = uses(a), uses(b)
            if not ua or not ub: continue
            if max(ua) < min(ub) or max(ub) < min(ua):
                keep, gone = (a, b) if min(ua) < min(ub) else (b, a)
                # the second value must start with an assignment, not a read
                first_gone = min(uses(gone))
                if not re.match(r' +' + re.escape(gone) + r' = ', lines[first_gone]): continue
                out = [re.sub(r'\b' + re.escape(gone) + r'\b', keep, l) if k != decls[gone][0] else None for k, l in enumerate(lines)]
                yield 'temp_merge', '\n'.join(l for l in out if l is not None)



def m_var_merge(t):
    """merge two same-typed locals whose live ranges do not overlap (m2c splits one C variable into var_X, var_X_2, ...)."""
    lines, s, e = body_range(t)
    decls = {}
    for i in range(s, e):
        m = DECL.match(lines[i])
        if m and not m[5]: decls[m[4].strip()] = (i, (m[3].strip()))
    def span(v):
        us = [i for i in range(s, e) if i != decls[v][0] and re.search(r'\b' + re.escape(v) + r'\b', lines[i])]
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

def m_bool_phi(t):
    """v = 1; if (c) { v = 0; }  ->  v = !(c);   and   v = 0; if (c) { v = 1; } -> v = (c) != 0  (branch-materialised booleans)."""
    pat = re.compile(r'(?P<indent> +)(?P<v>\w+) = (?P<a>[01]);\n(?P=indent)if \((?P<expr>[^\n]+)\) \{\n +(?P=v) = (?P<b>[01]);\n(?P=indent)\}\n')
    for m in pat.finditer(t):
        if m['a'] == m['b']: continue
        cond = m['expr'] if m['b'] == '1' else negate(m['expr'])
        yield 'bool_phi', t[:m.start()] + m['indent'] + f"{m['v']} = {cond};\n" + t[m.end():]
    # reverse: v = (expr); where expr is a comparison  ->  phi form
    lines, s, e = body_range(t)
    for i in range(s, e):
        m = re.fullmatch(r'( +)(\w+) = \(?([^;()]+ (?:==|!=|<|>|<=|>=) [^;()]+)\)?;', lines[i])
        if not m or m[2].startswith('M2C'): continue
        yield 'bool_phi', '\n'.join(lines[:i] + [f'{m[1]}{m[2]} = 1;', f'{m[1]}if ({negate(m[3])}) {{', f'{m[1]}    {m[2]} = 0;', f'{m[1]}}}'] + lines[i + 1:])


def m_alias_make(t):
    """introduce `p = base + K` for a cluster of far field accesses (ProDG hoists a base register)."""
    lines, s, e = body_range(t)
    decl = [i for i in range(s, e) if DECL.match(lines[i])]
    if not decl: return
    F2 = re.compile(r'M2C_FIELD\((\w+|\(\w+ \+ (?:0x[\dA-Fa-f]+|\d+)\)), ([^,()]+(?:\([^()]*\))?[^,()]*), (0x[\dA-Fa-f]+|\d+)\)')
    def parse(mm):
        b = mm[1]; off = int(mm[3], 0)
        pm = re.fullmatch(r'\((\w+) \+ (0x[\dA-Fa-f]+|\d+)\)', b)
        if pm: b = pm[1]; off += int(pm[2], 0)
        return b, off
    groups = {}
    for mm in F2.finditer('\n'.join(lines[s:e])):
        b, off = parse(mm)
        if off >= 0x40: groups.setdefault(b, []).append(off)
    for base, offs in groups.items():
        if len(offs) < 2: continue
        for k in sorted({o & ~0xF for o in offs} | {min(offs)}):
            near = [o for o in offs if 0 <= o - k < 0x40]
            if len(near) < 2: continue
            name = 'p_' + f'{k:x}'
            while re.search(r'\b' + name + r'\b', t): name += '_'
            out = lines[:]; first = None
            for i in range(s, e):
                def rep(mm):
                    b, o = parse(mm)
                    return f'M2C_FIELD({name}, {mm[2]}, {o - k:#x})' if b == base and o in near else mm[0]
                nl = F2.sub(rep, out[i])
                if nl != out[i] and first is None: first = i
                out[i] = nl
            if first is None: continue
            ind = re.match(r' *', lines[first])[0]
            out.insert(first, f'{ind}{name} = (char *){base} + {k:#x};')
            out.insert(decl[0], f'    char *{name};')
            yield 'alias_make', '\n'.join(out)



FAMILIES = [m_bool_phi, m_alias_make, m_temp_merge, m_commute, m_float_expr, m_cr_flag, m_call_trim, m_array_size, m_struct_copy, m_alias_fold, m_goto_inline, m_decl_order, m_register, m_local_type, m_param_type, m_field_type, m_cast_strip, m_inline_temp,
            m_hoist_cse, m_split_load, m_swap_stmts, m_ordered_stores, m_if_invert, m_cond_rewrite, m_loop_shape,
            m_return_style, m_arith, m_global_section, m_var_split, m_callee_proto]


def mutations(t, families=None):
    """yield (family, text) for every applicable rewrite (deduplicated)."""
    seen = {t}
    for f in (families or FAMILIES):
        try:
            for fam, nt in f(t):
                if nt not in seen:
                    seen.add(nt); yield fam, nt
        except Exception:
            continue


if __name__ == '__main__':
    import sys, collections
    t = open(sys.argv[1]).read()
    c = collections.Counter(f for f, _ in mutations(t))
    print(sum(c.values()), dict(c))
