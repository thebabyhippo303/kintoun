"""Instruction-backed C repair hypotheses. These propose experiments, never facts about source."""
import re
from nim_dtk.arch.ppc_elf import symbol_name


def signed(value, bits):
    return value - (1 << bits) if value & (1 << (bits - 1)) else value


def branch_address(word, pc):
    return ((0 if word & 2 else pc) + signed(word & 0x3fffffc, 26)) & 0xffffffff


def literal_locations(source, value):
    if value < 0: return []
    # Preserve positions, excluding literals in comments, strings, and characters.
    masked = re.sub(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'',
                    lambda m: ''.join('\n' if c == '\n' else ' ' for c in m[0]), source, flags=re.S)
    matches = []
    pattern = r'(?<![\w.])(?:0[xX][\da-fA-F]+|0[0-7]*|[1-9]\d*)[uUlL]*(?![\w.])'
    for match in re.finditer(pattern, masked):
        token = match[0]; number = re.sub(r'[uUlL]+$', '', token)
        base = 16 if number.lower().startswith('0x') else (8 if len(number) > 1 and number[0] == '0' else 10)
        if int(number, base) != value: continue
        start = source.rfind('\n', 0, match.start()) + 1
        end = source.find('\n', match.end()); end = len(source) if end < 0 else end
        # Preprocessor constants have no reliable one-to-one instruction mapping.
        if source[start:end].lstrip().startswith('#'): continue
        matches.append({'line': source.count('\n', 0, start) + 1, 'text': source[start:end],
                        'start': match.start() - start, 'end': match.end() - start})
    return matches


def immediate_edit(source, old, new):
    locations = literal_locations(source, old)
    public = [{'line': item['line'], 'text': item['text']} for item in locations[:8]]
    if len(locations) != 1: return public, None
    location = locations[0]; line = location['text']
    if source.count(line) != 1: return public, None
    token = line[location['start']:location['end']]
    suffix = re.search(r'[uUlL]*$', token)[0]
    replacement = (hex(new) if token.lower().startswith('0x') and new >= 0 else str(new)) + suffix
    return public, {'old': line, 'new': line[:location['start']] + replacement + line[location['end']:]}


def hypotheses(ours, target, source, va, symbols, objects, sda, sda2, ops=None, limit=8):
    """Use alignment so an insertion does not create many false operand diagnoses."""
    pairs = []
    if ops:
        for tag, i1, i2, j1, j2 in ops:
            if tag not in ('equal', 'replace'): continue
            pairs.extend((i1 + k, j1 + k) for k in range(min(i2 - i1, j2 - j1)))
    else: pairs = list(zip(range(len(ours)), range(len(target))))
    out = []; seen = set()
    for i, j in pairs:
        a, b = ours[i], target[j]
        if a == b: continue
        op, target_op = a >> 26, b >> 26
        if op != target_op: continue
        ra, rb = (a >> 16) & 31, (b >> 16) & 31
        x, y = signed(a & 0xffff, 16), signed(b & 0xffff, 16)
        repair = {'ours_offset': i * 4, 'target_offset': j * 4, 'confidence': 'hypothesis'}
        if op == 18 and a & 1 and b & 1:
            aa, bb = branch_address(a, va + 4*i), branch_address(b, va + 4*j)
            if aa == bb: continue
            repair.update(category='callee', ours=symbols.get(aa, f'0x{aa:08X}'),
                          target=symbols.get(bb, f'0x{bb:08X}'),
                          action='Check the called function and its declaration; do not tune registers to hide a wrong callee.')
        elif (op == 14 or 32 <= op <= 55) and ra in (2, 13) and rb in (2, 13):
            aa = ((sda if ra == 13 else sda2) + x) & 0xffffffff
            bb = ((sda if rb == 13 else sda2) + y) & 0xffffffff
            if aa == bb: continue
            repair.update(category='global', ours=f'0x{aa:08X}', target=f'0x{bb:08X}',
                          target_symbol=symbol_name(objects,bb), ours_symbol=symbol_name(objects,aa),
                          action=f'Use target global {symbol_name(objects,bb)} ({bb:#010X}); ours refers to {symbol_name(objects,aa)} ({aa:#010X}). Check the extern and address expression.')
        elif op == 14 and ra == rb == 0 and x != y:
            repair.update(category='literal', ours=x, target=y,
                          action='Test the target integer literal in C; a unique source occurrence is only a hypothesis.')
            locations, edit = immediate_edit(source, x, y)
            repair['source_locations'] = locations
            if edit: repair['suggested_edit'] = edit
        elif op == 37 and ra == rb == 1 and (a >> 21) & 31 == (b >> 21) & 31 == 1 and x != y:
            repair.update(category='frame', ours=-x, target=-y,
                          action='Check address-taken locals, array sizes, and live values across calls; the frame size is compiler-generated.')
        elif op == 16 and (a & 0xffff0003) == (b & 0xffff0003) and x != y:
            repair.update(category='block_layout', action='The branch condition agrees, but its destination differs. Check block ordering, shared tails, and duplicated tests.')
        elif 32 <= op <= 55 and ra == rb and ra not in (0,1,2,13) and x != y:
            repair.update(category='field_offset', ours=x, target=y,
                          action=f'Test the struct/member offset {y:#x} instead of {x:#x} on r{ra}; confirm the same object base in the target.')
        elif op == 14 and ra == rb and x != y:
            repair.update(category='offset', ours=x, target=y,
                          action='Check pointer arithmetic, array stride, and integer offsets at these aligned instructions.')
        else: continue
        key = (repair['category'], str(repair.get('ours')), str(repair.get('target')))
        if key in seen: continue
        seen.add(key); out.append(repair)
    priority = {'callee': 0, 'global': 1, 'literal': 2, 'frame': 3, 'offset': 4, 'block_layout': 6, 'field_offset': 4}
    return sorted(out, key=lambda item: priority[item['category']])[:limit]
