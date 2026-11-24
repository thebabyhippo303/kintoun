"""Decompiler seed compile-recovery helpers and prototype/cast/extern/index mutations."""
from contextvars import ContextVar
import itertools
import re

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
