"""Real-world MIPS decompiler (`m2c` / Ghidra) seed repairs and target-evidenced C expansions.

Built for PS2 Emotion Engine (`ee-gcc`, `mwccps2`), PSP Allegrex (`psp-gcc`, `mwccpsp`, `pspsnc`),
and MIPS32 (`mips-gcc` LE and BE):
- Self-contained `M2C_FIELD` / `M2C_BITWISE` / `M2C_CARRY` / `M2C_ERROR` / integer & float prelude injection;
- Repair of both `m2c --valid-syntax` and raw `m2c` pseudo-C (`?`, `->unkX`, `*(void *)`, `void *` pointer math);
- Skipped o32/EABI `$a0..$a7` & `$f12..$f19` argument slot refilling, `saved_reg_*` and `spXX` spill splitting;
- Hardware MMIO (`0x1000....` PS2 EE/DMA/GS, `0xBC00....` PSP) `volatile` protection against `-O2` loop hoisting / dead-store elimination;
- Strict C89 declaration hoisting for Sony `ee-gcc` 2.95/2.96 and Metrowerks `mwccps2` / `mwccpsp`;
- Full MIPS address-space symbolization (`abs_symbols`, `abs_functions`, `abs_base`, `abs_struct`, `label_rebase`, `raw_addr_rebase`) across PS2 (`0x00100000..`), PSP (`0x08800000..`), and KSEG0 (`0x80000000..`);
- `$gp` small-data window guard (`mips_gp_guard`) and `.rodata`/`.sdata` constant/string matching (`mips_extern_relocs`);
- Single-precision COP1 `.s` float literal enforcement (`1.0` -> `1.0f`), narrow `sll+sra`/`seb`/`seh` casts, reciprocal division cleanup, `movz`/`movn` ternaries, `beql`/`bnel` loops, and short-circuit `||` branch merging.
"""
from __future__ import annotations

from bisect import bisect_right
import itertools
import re
import struct
from typing import Any, Callable, Iterator

from kintoun.search import seeds as ppc_seeds

_STD_TYPES = (
    ("s8", "typedef signed char s8;"),
    ("u8", "typedef unsigned char u8;"),
    ("s16", "typedef signed short s16;"),
    ("u16", "typedef unsigned short u16;"),
    ("s32", "typedef int s32;"),
    ("u32", "typedef unsigned int u32;"),
    ("s64", "typedef long long s64;"),
    ("u64", "typedef unsigned long long u64;"),
    ("f32", "typedef float f32;"),
    ("f64", "typedef double f64;"),
    ("vs8", "typedef volatile signed char vs8;"),
    ("vu8", "typedef volatile unsigned char vu8;"),
    ("vs16", "typedef volatile signed short vs16;"),
    ("vu16", "typedef volatile unsigned short vu16;"),
    ("vs32", "typedef volatile int vs32;"),
    ("vu32", "typedef volatile unsigned int vu32;"),
    ("M2C_UNK", "typedef int M2C_UNK;"),
)

_STD_MACROS = (
    ("NULL", "#ifndef NULL\n#define NULL ((void *)0)\n#endif"),
    ("M2C_FIELD", "#define M2C_FIELD(p, type, off) (*(type)((unsigned char *)(p) + (off)))"),
    ("M2C_BITWISE", "#define M2C_BITWISE(type, expr) ({ __typeof__(expr) _m2c_v = (expr); *(type *)&_m2c_v; })"),
    ("M2C_CARRY", "#define M2C_CARRY 0"),
    ("M2C_ERROR", "#define M2C_ERROR(msg) 0"),
    ("M2C_SYNC", "#define M2C_SYNC() ((void)0)"),
    ("M2C_BREAK", "#define M2C_BREAK(code) ((void)0)"),
    ("M2C_MEMCPY_ALIGNED", "#define M2C_MEMCPY_ALIGNED(d, s, n) __builtin_memcpy((d), (s), (n))"),
)

_SHIFT_SEXT16_RE = re.compile(r"\(\s*\(s32\)\s*\(\s*([^;()\n]+?)\s*<<\s*(?:16|0x10)\s*\)\s*\)\s*>>\s*(?:16|0x10)")
_SHIFT_SEXT8_RE = re.compile(r"\(\s*\(s32\)\s*\(\s*([^;()\n]+?)\s*<<\s*(?:24|0x18)\s*\)\s*\)\s*>>\s*(?:24|0x18)")
_SHIFT_ZEXT16_RE = re.compile(r"\(\s*\(u32\)\s*\(\s*([^;()\n]+?)\s*<<\s*(?:16|0x10)\s*\)\s*\)\s*>>\s*(?:16|0x10)")
_SHIFT_ZEXT8_RE = re.compile(r"\(\s*\(u32\)\s*\(\s*([^;()\n]+?)\s*<<\s*(?:24|0x18)\s*\)\s*\)\s*>>\s*(?:24|0x18)")
_SAVED_MIPS_GPR_RE = re.compile(r"\bsaved_reg_(s[0-8]|fp|gp|ra|v[01]|a[0-7]|t[0-9])\b")
_SAVED_MIPS_FPR_RE = re.compile(r"\bsaved_reg_(f(?:[0-9]|[12][0-9]|3[01]))\b")
_EXTERN_SCALAR_RE = re.compile(
    r"^extern\s+((?:const\s+|volatile\s+)?(?:s32|u32|s16|u16|s8|u8|s64|u64|int|unsigned(?:\s+int)?|short|unsigned\s+short|char|unsigned\s+char|f32|f64|float|double|\w+\s*\*+))\s*([A-Za-z_]\w*)\s*;$",
    re.M,
)
_EXTERN_ARRAY_RE = re.compile(
    r"^extern\s+((?:const\s+|volatile\s+)?(?:s32|u32|s16|u16|s8|u8|int|short|char|f32|float))\s+([A-Za-z_]\w*)\[\]\s*;$",
    re.M,
)
_MIPS_DATA_ADDR_RE = re.compile(r"(?<![\w.])0x([0-9A-Fa-f]{6,8})(?![\w.])")

# Reciprocal magic multipliers commonly emitted by GCC / MWCC on MIPS `mult` + `sra`:
# value -> (divisor, extra_shift)
_RECIP_MAGICS: dict[int, Callable[[int], int | None]] = {
    0x55555556: lambda s: 3 * (1 << s),
    0x66666667: lambda s: 5 * (1 << max(0, s - 1)) if s >= 1 else None,
    0x92492493: lambda s: None,  # uses +x form
    0x38E38E39: lambda s: 9 * (1 << max(0, s - 1)) if s >= 1 else None,
    0x2E8BA2E9: lambda s: 11 * (1 << max(0, s - 1)) if s >= 1 else None,
    0x4EC4EC4F: lambda s: 13 * (1 << max(0, s - 2)) if s >= 2 else None,
}

_MEM_OPS_MIPS = {
    30, 31, 32, 33, 34, 35, 36, 37, 38, 39,
    40, 41, 42, 43, 44, 45, 46, 48, 49, 53, 55, 56, 57, 61, 63,
}


def _is_mips_ram_addr(addr: int) -> bool:
    """True if `addr` falls inside a standard PS2, PSP, N64/PS1, or `.o` data/code range."""
    return (
        0x00100000 <= addr < 0x02000000      # PS2 EE main RAM (32 MB)
        or 0x08800000 <= addr < 0x0C000000   # PSP user RAM (32/64 MB)
        or 0x80000000 <= addr < 0x82000000   # N64 / PS1 KSEG0 RAM
        or 0x00400000 <= addr < 0x00800000   # Synthetic `.o` target region
        or 0x10004000 <= addr < 0x10010000   # Synthetic `$gp` region
    )


def _is_mips_mmio_addr(addr: int) -> bool:
    """True if `addr` is a PS2 EE/GS (`0x10000000..0x13FFFFFF`) or PSP uncached (`0xBC000000..`) hardware register."""
    return (
        0x10000000 <= addr < 0x14000000
        or 0xBC000000 <= addr < 0xC0000000
        or 0xA0000000 <= addr < 0xBFC00000
    )


_CORE_INT_NAMES = frozenset(("s8", "u8", "s16", "u16", "s32", "u32"))


def ensure_mips_prelude(text: str, use_c89_bitwise: bool = False) -> str:
    """Prepend missing standard decomp typedefs and `M2C_*` macros referenced by `text`."""
    has_any_decomp_t = bool(re.search(r"\b(?:s8|u8|s16|u16|s32|u32|s64|u64|f32|f64|M2C_UNK|M2C_FIELD)\b", text))
    lines_to_add: list[str] = []
    for tname, tdef in _STD_TYPES:
        want = (has_any_decomp_t and tname in _CORE_INT_NAMES) or bool(re.search(r"\b" + tname + r"\b", text))
        if want and not re.search(
            r"\btypedef\b[^;]*\b" + tname + r"\s*;|#\s*define\s+" + tname + r"\b", text
        ):
            lines_to_add.append(tdef)
    for mname, mdef in _STD_MACROS:
        if re.search(r"\b" + mname + r"\b", text) and not re.search(r"#\s*define\s+" + mname + r"\b", text):
            if mname == "M2C_BITWISE" and use_c89_bitwise:
                lines_to_add.append(
                    "#define M2C_BITWISE(type, expr) (*(type *)&(expr))"
                )
            else:
                lines_to_add.append(mdef)
    if not lines_to_add:
        return text
    return "\n".join(lines_to_add) + "\n\n" + text


def repair_mips_pseudo_syntax(text: str) -> str:
    """Repair raw `m2c` pseudo-C (`?`, `->unkX`, `M2C_ERROR(/*...*/)`, `*(void *)`, `void *` arithmetic)."""
    out = text
    # 0. Replace `M2C_ERROR(...)` (including C89-invalid empty-token `M2C_ERROR(/* ... */)`) directly with `0`
    out = re.sub(r"\bM2C_ERROR\(\s*(?:/\*.*?\*/|[^()])*\)", "0", out)

    # 1. Direct hex function calls: `(? (*)(s32, ?))0x00101290(a, b)` or `((void (*)(void))0x0880521C)()`
    new_protos: list[str] = []

    def _fix_hex_call(m: re.Match[str]) -> str:
        ret_raw = m.group(1).strip()
        addr = int(m.group(2), 16)
        fname = f"fn_{addr:08X}"
        ret_t = "s32" if ret_raw in ("?", "s32", "int", "M2C_UNK") else ("void" if ret_raw == "void" else ret_raw)
        proto = f"{ret_t} {fname}();"
        if proto not in new_protos and not re.search(r"\b" + fname + r"\s*\(", out):
            new_protos.append(proto)
        return fname

    out = re.sub(
        r"\(\s*([A-Za-z0-9_*?\s]+?)\s*\(\s*\*\s*\)\s*\([^()]*\)\s*\)\s*0x([0-9A-Fa-f]{4,8})(?=\s*\()",
        _fix_hex_call,
        out,
    )
    # 2. Replace `?` unknown types in parameter lists / locals with `M2C_UNK` / `s32`
    out = re.sub(r"(?<=[(,])\s*\?\s*(?=[,)])", " M2C_UNK", out)
    out = re.sub(r"(?<=[(,])\s*\?\s+(\*+\s*\w+|\w+)", r" s32 \1", out)
    out = re.sub(r"^(\s*)\?\s+(\*+\s*\w+|\w+)\s*;", r"\1s32 \2;", out, flags=re.M)

    # 3. `base->unk10` / `base->unk_10` -> `M2C_FIELD(base, s32 *, 0x10)`
    out = re.sub(
        r"\b([A-Za-z_]\w*)->unk_?([0-9A-Fa-f]+)\b",
        lambda m: f"M2C_FIELD({m.group(1)}, s32 *, 0x{m.group(2)})",
        out,
    )

    # 4. ALL `*(void *)` / `*(volatile void *)` / `*(const void *)` dereferences (both lvalue and rvalue!)
    out = re.sub(r"\*\(\s*((?:volatile\s+|const\s+)?)void\s*\*\s*\)", r"*(\1s32 *)", out)

    # 4b. Integer-expression dereferences emitted by `m2c`:
    #     `*(0x4AAE70 + (i * 4))` or `*(*(s32 *)0x08A3DCDC + (k * 4))` -> `*(s32 *)(u32)(...)`
    out = re.sub(
        r"\*\(\s*(0x[0-9A-Fa-f]+\s*[+-]\s*[^;\n=]+?)\s*\)(?=\s*(?:[=;,)\]]|\+=|-=))",
        r"*(s32 *)(u32)(\1)",
        out,
    )
    out = re.sub(
        r"\*\(\s*(\*\(\s*[us](?:8|16|32)\s*\*\s*\)\s*0x[0-9A-Fa-f]+\s*[+-]\s*[^;\n=]+?)\s*\)(?=\s*(?:[=;,)\]]|\+=|-=))",
        r"*(s32 *)(u32)(\1)",
        out,
    )

    # 5. `void *var` (local or param) used in pointer arithmetic (`+`, `-`, `+=`, `-=`) -> `u8 *var` (strict ANSI C / MWCC!)
    u8_upgraded: set[str] = set()
    for m in list(re.finditer(r"(^|[ \t(,])void\s*\*\s*(\w+)\b(?=\s*[;,)])", out, re.M)):
        vname = m.group(2)
        if re.search(r"\b" + re.escape(vname) + r"\s*(?:[+-]=|[+-]\s*(?!=))", out):
            out = re.sub(r"\bvoid\s*\*\s*" + re.escape(vname) + r"\b", f"u8 *{vname}", out)
            u8_upgraded.add(vname)

    # Collect all pointer-typed variables (`T *v` or `T **v`) to catch `ptrA + ptrB` and `f32 *` vs pointer clashes
    ptr_vars = {
        pm.group(1)
        for pm in re.finditer(
            r"(?:^|[ \t(,])(?:const\s+|volatile\s+)?[A-Za-z_]\w*\s*\*+\s*(\w+)\b(?=\s*[;,)])",
            out,
            re.M,
        )
    }
    # 4c. `*(intVarA + expr)` where `intVarA` is an integer variable (not a pointer variable) -> `*(s32 *)(u32)(...)`
    def _fix_int_var_deref(m: re.Match[str]) -> str:
        lhs_var = m.group(1)
        if lhs_var in ptr_vars or lhs_var in u8_upgraded:
            return m.group(0)
        return f"*(s32 *)(u32)({lhs_var}{m.group(2)})"

    out = re.sub(
        r"\*\(\s*([A-Za-z_]\w*)(\s*[+-]\s*[^;()\n=]+?)\s*\)(?=\s*(?:[=;,)\]+-]))",
        _fix_int_var_deref,
        out,
    )
    if ptr_vars:
        # Fix `ptrA + ptrB` (when `m2c` types a relative byte offset as a pointer) -> `((u8 *)ptrA + (s32)ptrB)`
        for pa in sorted(ptr_vars, key=len, reverse=True):
            for pb in sorted(ptr_vars, key=len, reverse=True):
                if pa == pb:
                    continue
                out = re.sub(
                    r"\b" + re.escape(pa) + r"\s*\+\s*" + re.escape(pb) + r"\b",
                    f"((u8 *){pa} + (s32){pb})",
                    out,
                )
        # Fix `M2C_FIELD(base, f32 *, off) != ptr` / `= ptr` when `m2c` mis-types a pointer slot as `f32 *`
        ptr_alt = "|".join(re.escape(p) for p in sorted(ptr_vars, key=len, reverse=True))
        out = re.sub(
            r"M2C_FIELD\(\s*([^,]+?)\s*,\s*f(?:32|64)\s*\*\s*,\s*([^)]+?)\s*\)(?=\s*(?:==|!=|=)\s*(?:NULL|\b(?:"
            + ptr_alt
            + r")\b))",
            r"M2C_FIELD(\1, void **, \2)",
            out,
        )

    # If an upgraded `u8 *` expression (`v + K`) is assigned to a scalar `s32`/`u32` temp, cast `(s32)(...)`
    if u8_upgraded:
        scalar_vars = {
            sm.group(1)
            for sm in re.finditer(r"^[ \t]+(?:s32|u32|int|unsigned)\s+(\w+)\s*;", out, re.M)
        }
        for sv in scalar_vars:
            for uv in u8_upgraded:
                out = re.sub(
                    r"^([ \t]+" + re.escape(sv) + r"\s*=\s*)(" + re.escape(uv) + r"\s*[+-]\s*[^;\n]+);",
                    r"\1(s32)(\2);",
                    out,
                    flags=re.M,
                )
        # Also if a prototype expects `(s32, ...)` where `u8 *` is passed, or `M2C_FIELD(..., void ***, ...)` + ptr
        out = re.sub(
            r"\(\s*void\s*\*\s*\)\s*(\([^;\n]+?\))\s*\+\s*(\w+)",
            r"((u8 *)\1 + (s32)(\2))",
            out,
        )

    if new_protos:
        out = "\n".join(new_protos) + "\n" + out
    return out


def protect_mips_mmio_volatile(text: str) -> str:
    """Upgrade raw dereferences of PS2/PSP hardware MMIO addresses (`0x1000....`, `0xBC00....`) to `volatile`."""
    def _sub_cast(m: re.Match[str]) -> str:
        typ, addr_s = m.group(1), m.group(2)
        addr = int(addr_s, 16)
        if not _is_mips_mmio_addr(addr) or "volatile" in typ:
            return m.group(0)
        return f"*(volatile {typ} *){addr_s}"

    out = re.sub(r"\*\(\s*((?:[us](?:8|16|32|64)|int|short|char))\s*\*\s*\)\s*(0x[0-9A-Fa-f]{8})\b", _sub_cast, text)

    def _sub_mfld(m: re.Match[str]) -> str:
        addr_s, typ, off = m.group(1), m.group(2), m.group(3)
        if not _is_mips_mmio_addr(int(addr_s, 16)) or "volatile" in typ:
            return m.group(0)
        return f"M2C_FIELD((void *){addr_s}, volatile {typ}, {off})"

    out = re.sub(
        r"M2C_FIELD\(\s*\(void\s*\*\)\s*(0x[0-9A-Fa-f]{8})\s*,\s*([^,]+?)\s*,\s*([^)]+)\)",
        _sub_mfld,
        out,
    )
    return out


def hoist_c89_declarations(text: str) -> str:
    """Move mid-function bare local declarations (`T x;` or `T x = init;`) to the top of the function body.

    Required for Sony `ee-gcc` 2.95, `agbcc`, and strict C89 Metrowerks modes when mutations
    insert helper temporaries mid-block.
    """
    lines = text.split("\n")
    sig_idx = next(
        (i for i, l in enumerate(lines) if l.rstrip().endswith("{") and "(" in l and not l.startswith((" ", "\t"))),
        None,
    )
    if sig_idx is None:
        return text
    end_idx = max((i for i, l in enumerate(lines) if l == "}"), default=-1)
    if end_idx <= sig_idx + 1:
        return text

    decl_init_re = re.compile(
        r"^([ \t]{4})(__typeof__\([^()]+\)|(?:register\s+)?(?:volatile\s+|const\s+)?(?:unsigned\s+|signed\s+)?(?:s8|u8|s16|u16|s32|u32|s64|u64|f32|f64|vs32|vu32|int|short|char|long|float|double|void|M2C_UNK)(?:\s*\*+|\s+))([A-Za-z_]\w*)\s*(?:=\s*([^;]+))?;$"
    )
    seen_stmt = False
    hoisted_decls: list[str] = []
    body_out: list[str] = []
    depth = 1

    for idx in range(sig_idx + 1, end_idx):
        ln = lines[idx]
        stripped = ln.strip()
        if not stripped:
            body_out.append(ln)
            continue
        if depth == 1:
            m = decl_init_re.match(ln)
            if m:
                indent, tpart, vname, rhs = m.groups()
                if not seen_stmt and rhs is None and not tpart.startswith("__typeof__"):
                    body_out.append(ln)
                elif rhs is not None and not tpart.startswith("__typeof__"):
                    sep = "" if tpart.endswith(("*", " ")) else " "
                    if seen_stmt:
                        hoisted_decls.append(f"    {tpart.strip()}{'' if tpart.strip().endswith('*') else ' '}{vname};")
                        body_out.append(f"{indent}{vname} = {rhs};")
                    else:
                        body_out.append(ln)
                elif seen_stmt and rhs is None:
                    hoisted_decls.append(ln)
                else:
                    body_out.append(ln)
                depth += ln.count("{") - ln.count("}")
                continue
        if stripped and not stripped.startswith(("/*", "//")):
            seen_stmt = True
        body_out.append(ln)
        depth += ln.count("{") - ln.count("}")

    if not hoisted_decls:
        return text
    # Insert hoisted declarations right after any existing leading declarations
    insert_at = 0
    while insert_at < len(body_out) and (not body_out[insert_at].strip() or decl_init_re.match(body_out[insert_at])):
        insert_at += 1
    merged_body = body_out[:insert_at] + hoisted_decls + body_out[insert_at:]
    return "\n".join(lines[: sig_idx + 1] + merged_body + lines[end_idx:])


def mips_resolve_gp_reg(text: str, gp: int) -> str:
    """Resolve `m2c` `saved_reg_gp` accesses (`lw/sw/addiu ..., off($gp)`) into `.sdata` symbols at `gp + off`!"""
    if not gp or "saved_reg_gp" not in text:
        return text
    sig = re.search(r"^[^\n;#]*\b\w+\s*\([^{};]*\)\s*\{", text, re.M)
    if not sig:
        return text
    head, body = text[: sig.start()], text[sig.start() :]
    decls: dict[str, str] = {}

    # 1. `M2C_FIELD(saved_reg_gp, TYPE *, OFF)` -> `lbl_XXXXXXXX`
    mf_pat = re.compile(
        r"M2C_FIELD\(\s*saved_reg_gp\s*,\s*([^,]+?)\s*\*\s*,\s*(-?(?:0x[0-9A-Fa-f]+|\d+))\s*\)"
    )
    while True:
        m = mf_pat.search(body)
        if not m:
            break
        val_t = m.group(1).strip()
        off = int(m.group(2), 0)
        addr = (gp + off) & 0xFFFFFFFF
        sym = f"lbl_{addr:08X}"
        sep = "" if val_t.endswith("*") else " "
        decls.setdefault(sym, f'extern {val_t}{sep}{sym} __attribute__((section(".sdata")));\n')
        body = body[: m.start()] + sym + body[m.end() :]

    # 2. `(saved_reg_gp + OFF)` or `(saved_reg_gp - OFF)` -> `((s32)&lbl_XXXXXXXX)`
    add_pat = re.compile(r"\(?\s*saved_reg_gp\s*([+-])\s*(0x[0-9A-Fa-f]+|\d+)\s*\)?")

    def _sub_gp_add(m: re.Match[str]) -> str:
        sign = -1 if m.group(1) == "-" else 1
        off = sign * int(m.group(2), 0)
        addr = (gp + off) & 0xFFFFFFFF
        sym = f"lbl_{addr:08X}"
        decls.setdefault(sym, f'extern u8 {sym} __attribute__((section(".sdata")));\n')
        return f"((s32)&{sym})"

    body = add_pat.sub(_sub_gp_add, body)

    # Drop unused `s32 saved_reg_gp;` declaration if all uses were resolved
    if "saved_reg_gp" not in re.sub(r"^[ \t]+s32\s+saved_reg_gp\s*;\s*$", "", body, flags=re.M):
        body = re.sub(r"^[ \t]+s32\s+saved_reg_gp\s*;\s*\n", "", body, flags=re.M)

    new_decls = [d for s, d in decls.items() if not re.search(r"\b" + s + r"\b", head)]
    return ensure_mips_prelude(head + "".join(new_decls) + body)


def repair_mips_seed(text: str, name: str, address: int, gp: int = 0) -> str:
    """Repair real-world `m2c` MIPS/R5900/Allegrex syntax and type faults while preserving pure C."""
    repaired = repair_mips_pseudo_syntax(text)
    repaired = ppc_seeds.repair_seed(repaired, name, address)
    repaired = protect_mips_mmio_volatile(repaired)
    if gp:
        repaired = mips_resolve_gp_reg(repaired, gp)

    # Refill skipped MIPS o32/EABI integer argument slots (`arg0..arg7`)
    sig = re.search(r"\b" + re.escape(name) + r"\s*\(([^{};]*)\)\s*\{", repaired)
    if sig:
        params = sig.group(1)
        parts = [p.strip() for p in params.split(",")] if params.strip() not in ("", "void") else []
        numbered = [(int(n[0]), p) for p in parts for n in [re.findall(r"\barg(\d+)$", p)] if n]
        ints = [p for p in parts if re.search(r"\barg\d+$", p)]
        if numbered and len(numbered) == len(ints) and [n for n, _ in numbered] != list(range(len(ints))):
            have = dict(numbered)
            max_slot = min(max(have), 7)
            filled = [have.get(i, f"s32 arg{i}") for i in range(max_slot + 1)]
            filled += [p for p in parts if not re.search(r"\barg\d+$", p)]
            repaired = repaired[: sig.start(1)] + ", ".join(filled) + repaired[sig.end(1) :]

    # Declare any MIPS `saved_reg_s0..s8/fp/gp/ra`, `saved_reg_f20..f31`, or bare `sp` stack-base buffer
    saved_gprs = sorted(set(_SAVED_MIPS_GPR_RE.findall(repaired)))
    saved_fprs = sorted(set(_SAVED_MIPS_FPR_RE.findall(repaired)))
    sig = re.search(r"\b" + re.escape(name) + r"\s*\(([^{};]*)\)\s*\{", repaired)
    if sig:
        body_no_comments = re.sub(r"/\*.*?\*/|//[^\n]*", "", repaired[sig.end() :], flags=re.S)
        needs_bare_sp = (
            bool(re.search(r"(?<![\w.>])\bsp\b", body_no_comments))
            and not re.search(r"\bsp\b", sig.group(1))
            and not re.search(r"^[ \t]+[^;\n]*\bsp\s*(?:\[[^\]]*\])?\s*;", repaired[sig.end() :], re.M)
        )
        extra_decls: list[str] = []
        if needs_bare_sp:
            extra_decls.append("\n    s32 sp[4];")
        for r in saved_gprs:
            if not re.search(r"\b(?:char|void|s32|u32)\s*\*?\s*saved_reg_" + re.escape(r) + r"\b", repaired):
                extra_decls.append(f"\n    s32 saved_reg_{r};")
        for r in saved_fprs:
            if not re.search(r"\b(?:f32|f64|float|double)\s+saved_reg_" + re.escape(r) + r"\b", repaired):
                extra_decls.append(f"\n    f32 saved_reg_{r};")
        if extra_decls:
            repaired = repaired[: sig.end()] + "".join(extra_decls) + repaired[sig.end() :]

    repaired = hoist_c89_declarations(repaired)
    repaired = ensure_mips_prelude(repaired)
    return repaired


def _target_symbol_addresses_mips(words: list[int], gp: int = 0) -> tuple[set[int], set[int], set[int]]:
    """Decode `(lui_sym_addrs, lui_ori_addrs, gp_addrs)` from a relocated MIPS target instruction stream.

    On MIPS (`ee-gcc`, `mwccps2`, `psp-gcc`, `mwccpsp`), `lui + addiu` (`op in (9, 25)`) or `lui + mem`
    is ALWAYS a symbol relocation (`R_MIPS_HI16` + `R_MIPS_LO16`), whereas integer constants use `lui + ori` (`op == 13`).
    """
    his: dict[int, int] = {}
    lui_sym_addrs: set[int] = set()
    lui_ori_addrs: set[int] = set()
    gp_addrs: set[int] = set()
    for w in words or []:
        op = (w >> 26) & 0x3F
        rs = (w >> 21) & 0x1F
        rt = (w >> 16) & 0x1F
        uimm = w & 0xFFFF
        simm = uimm - 0x10000 if (uimm & 0x8000) else uimm
        if op == 15 and rs == 0 and rt != 0:
            his[rt] = (uimm << 16) & 0xFFFFFFFF
            continue
        if gp and rs == 28 and (op in (9, 25) or op in _MEM_OPS_MIPS):
            gp_addrs.add((gp + simm) & 0xFFFFFFFF)
        if rs in his:
            if op == 13:
                lui_ori_addrs.add((his[rs] | uimm) & 0xFFFFFFFF)
                if rt == rs:
                    his.pop(rs, None)
                continue
            if op in (9, 25) or op in _MEM_OPS_MIPS:
                lui_sym_addrs.add((his[rs] + simm) & 0xFFFFFFFF)
                if op in (9, 25) and rt == rs:
                    his.pop(rs, None)
                continue
        if op == 0 and (w & 0x3F) not in (8, 12, 13, 15, 26, 27):
            his.pop((w >> 11) & 0x1F, None)
        elif op in (8, 9, 10, 11, 12, 13, 14, 24, 25) or (op in _MEM_OPS_MIPS and op not in (40, 41, 42, 43, 44, 45, 46, 57, 61, 63, 31)):
            his.pop(rt, None)
    return lui_sym_addrs, lui_ori_addrs, gp_addrs


def target_built_addresses_mips(words: list[int], gp: int = 0) -> tuple[set[int], set[int]]:
    """Decode `(lui_built_addrs, gp_built_addrs)` from a relocated MIPS target instruction stream."""
    lui_sym, lui_ori, gp_addrs = _target_symbol_addresses_mips(words, gp=gp)
    return (lui_sym | lui_ori), gp_addrs


def mips_abs_symbols(text: str, objects: dict[int, tuple[str, int]], gp: int = 0) -> str | None:
    """Rewrite raw MIPS integer data addresses (`0x0010....`, `0x0880....`, `0x8000....`) into symbol references."""
    sig = re.search(r"^[^\n;#]*\b\w+\s*\([^{};]*\)\s*\{", text, re.M)
    if not sig or not objects:
        return None
    head, body = text[: sig.start()], text[sig.start() :]
    starts = sorted(objects)
    declare: list[tuple[str, bool]] = []
    seen_decl: set[str] = set()

    def _sub(m: re.Match[str]) -> str:
        a = int(m.group(1), 16)
        if not _is_mips_ram_addr(a):
            return m.group(0)
        i = bisect_right(starts, a) - 1
        if i < 0:
            return m.group(0)
        base = starts[i]
        name, size = objects[base][0], objects[base][1]
        if not name or a - base >= max(size, 1):
            return m.group(0)
        if not re.search(r"\b" + re.escape(name) + r"\b", head) and name not in seen_decl:
            in_gp = bool(gp and (gp - 0x8000 <= base <= gp + 0x7FFF) and size <= 8)
            seen_decl.add(name)
            declare.append((name, in_gp))
        return f"((u8 *)&{name} + 0x{a - base:X})" if a != base else f"(&{name})"

    out = _MIPS_DATA_ADDR_RE.sub(_sub, body)
    if out == body:
        return None
    ext_lines = [
        f'extern u8 {n} __attribute__((section(".sdata")));\n' if in_gp else f"extern u8 {n}[];\n"
        for n, in_gp in declare
    ]
    return head + "".join(ext_lines) + out


def mips_abs_functions(text: str, functions: dict[int, str] | dict[int, tuple[str, int]]) -> str | None:
    """Rewrite MIPS function addresses used as data callbacks/vtables into `&Func`."""
    sig = re.search(r"^[^\n;#]*\b(\w+)\s*\([^{};]*\)\s*\{", text, re.M)
    if not sig or not functions:
        return None
    head, body = text[: sig.start()], text[sig.start() :]
    declare: list[str] = []

    def _sub(m: re.Match[str]) -> str:
        a = int(m.group(1), 16)
        entry = functions.get(a)
        fname = entry[0] if isinstance(entry, tuple) else entry
        if not fname or not re.fullmatch(r"[A-Za-z_]\w*", fname) or fname == sig.group(1):
            return m.group(0)
        if not re.search(r"\b" + re.escape(fname) + r"\b", head) and fname not in declare:
            declare.append(fname)
        return f"(&{fname})"

    out = _MIPS_DATA_ADDR_RE.sub(_sub, body)
    if out == body:
        return None
    return head + "".join(f"void {n}(void);\n" for n in declare) + out


def mips_raw_addr_rebase(text: str, target_words: list[int], gp: int = 0) -> str | None:
    """Convert raw `0x......` RAM literals in `m2c` output into `lbl_XXXXXXXX` externs matching target `$gp` or `lui+%lo`."""
    sig = re.search(r"^[^\n;#]*\b\w+\s*\([^{};]*\)\s*\{", text, re.M)
    if not sig or not target_words:
        return None
    lui_sym_addrs, lui_ori_addrs, gp_addrs = _target_symbol_addresses_mips(target_words, gp=gp)
    lui_addrs = lui_sym_addrs | lui_ori_addrs
    if not lui_addrs and not gp_addrs:
        return None
    head, body = text[: sig.start()], text[sig.start() :]
    all_bases = sorted(lui_sym_addrs | gp_addrs) or sorted(lui_addrs | gp_addrs)
    decls: dict[str, str] = {}

    # 1. Direct typed dereferences `*(T *)0x08A78600` or `*(T *)0x5030D0`
    def _sub_deref(m: re.Match[str]) -> str:
        typ, addr_s = m.group(1).strip(), m.group(2)
        addr = int(addr_s, 16)
        if not _is_mips_ram_addr(addr):
            return m.group(0)
        if addr in gp_addrs:
            sym = f"lbl_{addr:08X}"
            decls.setdefault(sym, f'extern {typ} {sym} __attribute__((section(".sdata")));\n')
            return sym
        if addr in lui_addrs:
            sym = f"lbl_{addr:08X}"
            decls.setdefault(sym, f'extern {typ} {sym} __attribute__((section(".data")));\n')
            return sym
        # Check if target built a nearby base address within 0x1000 bytes!
        idx = bisect_right(all_bases, addr) - 1
        if idx >= 0 and 0 < addr - all_bases[idx] <= 0x1000:
            base = all_bases[idx]
            sym = f"lbl_{base:08X}"
            sec_attr = ' __attribute__((section(".sdata")))' if base in gp_addrs else ""
            decls.setdefault(sym, f"extern u8 {sym}[]{sec_attr};\n")
            return f"(*({typ} *)((u8 *){sym} + 0x{addr - base:X}))"
        return m.group(0)

    out = re.sub(
        r"\*\(\s*((?:volatile\s+|const\s+)?(?:[us](?:8|16|32|64)|f32|f64|int|short|char|float|double))\s*\*\s*\)\s*(0x[0-9A-Fa-f]{5,8})\b",
        _sub_deref,
        body,
    )

    # 2. Pointer casts `(void *)0x08AEFC00` / `(u8 *)0x5030D0`
    def _sub_ptr(m: re.Match[str]) -> str:
        cast_t, addr_s = m.group(1), m.group(2)
        addr = int(addr_s, 16)
        if not _is_mips_ram_addr(addr):
            return m.group(0)
        if addr in gp_addrs or addr in lui_addrs:
            sym = f"lbl_{addr:08X}"
            if sym not in decls:
                sec = ".sdata" if addr in gp_addrs else ".data"
                decls[sym] = f'extern u8 {sym} __attribute__((section("{sec}")));\n'
            return f"({cast_t})&{sym}"
        return m.group(0)

    out = re.sub(r"\(\s*((?:void|u8|s8|char|s32|u32|f32)\s*\*+)\s*\)\s*(0x[0-9A-Fa-f]{5,8})\b", _sub_ptr, out)

    # 3. Bare address arguments/assignments (`fn(0x5030D0)`): when target built `addr` via `lui+addiu` or `$gp+simm`,
    # it is a relocated symbol address (`&lbl_XXXXXXXX`), NOT an integer constant (`lui+ori`)!
    sym_only_addrs = lui_sym_addrs | gp_addrs
    if sym_only_addrs:
        def _sub_bare_sym(m: re.Match[str]) -> str:
            addr = int(m.group(1), 16)
            if addr not in sym_only_addrs or not _is_mips_ram_addr(addr):
                return m.group(0)
            sym = f"lbl_{addr:08X}"
            if sym not in decls:
                sec = ".sdata" if addr in gp_addrs else ".data"
                decls[sym] = f'extern u8 {sym} __attribute__((section("{sec}")));\n'
            return f"((s32)&{sym})"

        out = re.sub(r"(?<![\w.])0x([0-9A-Fa-f]{5,8})(?![\w.])", _sub_bare_sym, out)

    if out == body:
        return None
    new_decls = [d for s, d in decls.items() if not re.search(r"\b" + s + r"\b", head)]
    return ensure_mips_prelude(head + "".join(new_decls) + out)


def mips_label_rebase(
    text: str,
    objects: dict[int, tuple[str, int]],
    target_words: list[int],
    gp: int = 0,
    window: int = 0x2000,
) -> str | None:
    """Rebase split `lbl_XXXXXXXX` symbols onto the base symbol actually materialized by `target_words`."""
    lui_built, gp_built = target_built_addresses_mips(target_words or [], gp=gp)
    built = lui_built | gp_built
    if not built:
        return None
    labels = sorted({int(a, 16) for a in re.findall(r"\blbl_([0-9A-Fa-f]{8})\b", text)})
    if not labels:
        return None
    bases = sorted(a for a in built if (not objects or a in objects))
    if not bases:
        bases = sorted(built)
    moves: dict[int, int] = {}
    for a in labels:
        size = max(objects[a][1], 1) if a in objects else 1
        if any(a <= b < a + size for b in built):
            continue
        lower = [b for b in bases if b < a and a - b <= window]
        if lower:
            moves[a] = lower[-1]
    if not moves:
        return None
    out = text
    declared = {m.upper() for m in re.findall(r"\bextern [^;\n]*\blbl_([0-9A-Fa-f]{8})\b", out)}
    extra: list[str] = []
    for a, b in moves.items():
        name, base = f"lbl_{a:08X}", f"lbl_{b:08X}"
        decl = re.search(r"^extern ([^;\n]*?)\s*\b" + name + r"\b(\[\])?[^;\n]*;\n", out, re.M)
        ref = f"((u8 *)&{base} + 0x{a - b:X})"
        out = re.sub(r"&" + name + r"\b", ref, out)
        if decl and decl.group(2):
            out = (
                re.sub(r"(?<![\w&])" + name + r"\b(?!\[)", ref, out[: decl.start()])
                + decl.group(0)
                + re.sub(r"(?<![\w&])" + name + r"\b(?!\[)", ref, out[decl.end() :])
            )
        elif decl:
            kind = re.sub(r"__attribute__\(\([^)]*\)\)", "", decl.group(1)).strip() or "s32"
            body_start = decl.end()
            out = out[:body_start] + re.sub(r"(?<![\w&])" + name + r"\b", f"(*({kind} *){ref})", out[body_start:])
        if f"{b:08X}" not in declared:
            sec_attr = ' __attribute__((section(".sdata")))' if b in gp_built else ""
            extra.append(f"extern u8 {base}[]{sec_attr};\n")
            declared.add(f"{b:08X}")
    sig = re.search(r"^[^\n;#]*\b\w+\s*\([^{};]*\)\s*\{", out, re.M)
    if extra and sig:
        out = out[: sig.start()] + "".join(extra) + out[sig.start() :]
    return out if out != text else None


def synthesize_m2c_structs(text: str) -> str | None:
    """Convert `void *p` + `M2C_FIELD(p, T *, off)` into a clean padded C `struct` (`p->f_off`).

    Crucial on `agbcc` (Thumb) and `ee-gcc`/`mwcc`: `(*(T *)((u8 *)p + off))` forces byte-pointer
    arithmetic and extra scratch registers, whereas real `struct` member accesses (`p->f_off`)
    use native struct addressing modes and preserve constant registers across stores!
    """
    if "M2C_FIELD(" not in text:
        return None
    sig = re.search(r"^[^\n;#]*\b\w+\s*\([^{};]*\)\s*\{", text, re.M)
    if not sig:
        return None
    head, rest = text[: sig.start()], text[sig.start() :]
    size_map = {
        "u8": 1, "s8": 1, "char": 1, "signed char": 1, "unsigned char": 1,
        "u16": 2, "s16": 2, "short": 2, "unsigned short": 2,
        "u32": 4, "s32": 4, "int": 4, "unsigned int": 4, "f32": 4, "float": 4, "M2C_UNK": 4,
    }
    ptr_vars = [
        m.group(1)
        for m in re.finditer(r"(?:^|[ \t(,])void\s*\*\s*([A-Za-z_]\w*)\b(?=\s*[;,)])", rest, re.M)
    ]
    if not ptr_vars:
        return None

    tdefs: list[str] = []
    new_rest = rest
    changed = False
    mf_re_tpl = r"M2C_FIELD\(\s*{v}\s*,\s*([^,()]+?)\s*\*\s*,\s*(0x[0-9A-Fa-f]+|\d+)\s*\)"

    for v in dict.fromkeys(ptr_vars):
        v_re = re.compile(mf_re_tpl.format(v=re.escape(v)))
        hits = list(v_re.finditer(new_rest))
        if len(hits) < 2:
            continue
        fields: dict[int, tuple[str, int]] = {}
        conflict = False
        for hm in hits:
            ft = re.sub(r"\s+", " ", hm.group(1).strip())
            off = int(hm.group(2), 0)
            is_ptr = ft.endswith("*")
            base_ft = ft.replace("volatile ", "").replace("const ", "").strip()
            sz = 4 if is_ptr else size_map.get(base_ft, 0)
            if sz == 0 or off < 0 or off > 0x1000 or off % sz != 0:
                conflict = True
                break
            if off in fields and fields[off][1] != sz:
                conflict = True
                break
            fields.setdefault(off, (ft, sz))
        if conflict or not fields:
            continue
        # Verify non-overlapping sorted fields
        cur = 0
        members: list[str] = []
        for off in sorted(fields):
            ft, sz = fields[off]
            if off < cur:
                conflict = True
                break
            if off > cur:
                members.append(f"u8 pad_{cur:X}[0x{off - cur:X}];")
            sep = "" if ft.endswith("*") else " "
            members.append(f"{ft}{sep}f_{off:X};")
            cur = off + sz
        if conflict or not members:
            continue
        sname = f"mt_s_{v}_t"
        if sname in text:
            continue
        tdefs.append(f"typedef struct {{ {' '.join(members)} }} {sname};\n")
        new_rest = re.sub(r"\bvoid\s*\*\s*" + re.escape(v) + r"\b", f"{sname} *{v}", new_rest)
        new_rest = v_re.sub(lambda m: f"{v}->f_{int(m.group(2), 0):X}", new_rest)
        changed = True

    if not changed:
        return None
    out = head + "".join(tdefs) + new_rest
    # Drop unused `#define M2C_FIELD` if no `M2C_FIELD(` calls remain
    body_only = out[out.find("typedef struct") :]
    if "M2C_FIELD(" not in body_only:
        out = re.sub(r"^#\s*define\s+M2C_FIELD\([^\n]+\n", "", out, flags=re.M)
    return ensure_mips_prelude(out)


def narrow_shift_casts(text: str) -> str | None:
    """Fold MIPS shift-pair sign/zero-extension idioms (`(x << 16) >> 16`) into `(s16)`/`(s8)`/`(u16)`/`(u8)`."""
    out = _SHIFT_SEXT16_RE.sub(r"((s16)(\1))", text)
    out = _SHIFT_SEXT8_RE.sub(r"((s8)(\1))", out)
    out = _SHIFT_ZEXT16_RE.sub(r"((u16)(\1))", out)
    out = _SHIFT_ZEXT8_RE.sub(r"((u8)(\1))", out)
    return out if out != text else None


def lit16_sign_mips(text: str, target_words: list[int]) -> str | None:
    """Rewrite `0x8000..0xFFFF` hex literals to negative ints when target uses `addiu rt, $zero, -N`."""
    negatives = {
        (w & 0xFFFF) - 0x10000
        for w in (target_words or [])
        if ((w >> 26) & 0x3F) in (9, 25) and ((w >> 21) & 0x1F) == 0 and (w & 0x8000)
    }
    if not negatives:
        return None

    def _sub(m: re.Match[str]) -> str:
        val = int(m.group(2), 16) - 0x10000
        return f"{m.group(1)}{val}" if val in negatives else m.group(0)

    out = re.sub(
        r"((?:[(,]|(?<![=!<>])=|\breturn)\s*(?:\((?:void|[us](?:8|16|32)|int|M2C_UNK)\s*\**\)\s*)?)0x([89A-Fa-f][0-9A-Fa-f]{3})(?![\w.])",
        _sub,
        text,
    )
    return out if out != text else None


def mips_single_float_literals(text: str, target_words: list[int]) -> str | None:
    """Suffix double literals (`1.0` -> `1.0f`) and narrow `f64` locals to `f32` when target uses COP1 `.s` only.

    Critical on PS2 R5900 and PSP Allegrex (single-precision hardware FPU only: unsuffixed `1.0`
    forces soft-float `__adddf3`/`__extendsfdf2` calls!).
    """
    has_single = False
    has_double = False
    for w in target_words or []:
        op = (w >> 26) & 0x3F
        if op == 49 or op == 57:  # lwc1 / swc1
            has_single = True
        elif op == 53 or op == 61:  # ldc1 / sdc1
            has_double = True
        elif op == 17:
            fmt = (w >> 21) & 0x1F
            if fmt == 16:
                has_single = True
            elif fmt == 17:
                has_double = True
    if not has_single or has_double:
        return None

    # Suffix bare floating literals `0.0`, `1.5`, `.5` without `f`/`F` outside strings
    out = re.sub(r'(?<!["\w.])(\d+\.\d+|\.\d+)(?![fFdD\w.])', r"\1f", text)
    out = re.sub(r"^([ \t]+)(?:f64|double)(\s+\w+\s*(?:=[^;]+)?;)", r"\1f32\2", out, flags=re.M)
    out = re.sub(r"\(\s*(?:f64|double)\s*\)\s*", "(f32)", out)
    return out if out != text else None


def mips_div_magic_cleanup(text: str) -> str | None:
    """Fold `m2c` 64-bit reciprocal-multiply signed division idioms back into `x / C`."""
    pat = re.compile(
        r"\(\s*\(\s*s32\s*\)\s*\(\s*\(\s*\(\s*s64\s*\)\s*(\w+)\s*\*\s*(0x[0-9A-Fa-f]+)\s*\)\s*>>\s*(3[2-9]|[45]\d)\s*\)\s*\)\s*-\s*\(\s*\1\s*>>\s*(?:31|0x1[fF])\s*\)"
    )

    def _sub(m: re.Match[str]) -> str:
        var, mult_s, sh_s = m.group(1), m.group(2), m.group(3)
        mult = int(mult_s, 16)
        extra_sh = int(sh_s) - 32
        fn = _RECIP_MAGICS.get(mult)
        div = fn(extra_sh) if fn else None
        return f"({var} / {div})" if div else m.group(0)

    out = pat.sub(_sub, text)
    return out if out != text else None


def mips_movz_ternary(text: str, target_words: list[int]) -> str | None:
    """Rewrite simple `if (cond) { x = a; } else { x = b; }` into `x = cond ? a : b;` when target uses `movz`/`movn`."""
    has_cmov = any(((w >> 26) & 0x3F) == 0 and (w & 0x3F) in (10, 11) for w in (target_words or []))
    if not has_cmov:
        return None
    pat = re.compile(
        r"^([ \t]+)if\s*\(([^;\n{}]+)\)\s*\{\n\1    (\w+)\s*=\s*([^;\n{}]+);\n\1\}\s*else\s*\{\n\1    \3\s*=\s*([^;\n{}]+);\n\1\}",
        re.M,
    )
    out = pat.sub(r"\1\3 = (\2) ? (\4) : (\5);", text, count=1)
    return out if out != text else None


def mips_shortcircuit_or_merge(text: str) -> str | None:
    """Collapse `m2c`'s `if (c1 == 0) { if (c2) { BODY } } else { BODY }` back into `if (c1 != 0 || (c2)) { BODY }`."""
    pat = re.compile(
        r"^([ \t]+)if\s*\(([^;\n{}]+?)\s*(==|!=)\s*0\)\s*\{\n"
        r"\1    if\s*\(([^;\n{}]+)\)\s*\{\n"
        r"((?:\1        [^\n]+\n)+)"
        r"\1    \}\n"
        r"\1\}\s*else\s*\{\n"
        r"((?:\1    [^\n]+\n)+)"
        r"\1\}",
        re.M,
    )

    def _merge(m: re.Match[str]) -> str:
        ind, lhs, eq_op, c2, body_inner, body_else = m.groups()
        norm_inner = [l[4:] if l.startswith("    ") else l for l in body_inner.splitlines()]
        norm_else = body_else.splitlines()
        if [l.strip() for l in norm_inner] != [l.strip() for l in norm_else]:
            return m.group(0)
        flipped = "!=" if eq_op == "==" else "=="
        joined_body = "\n".join(norm_else)
        return f"{ind}if (({lhs} {flipped} 0) || ({c2})) {{\n{joined_body}\n{ind}}}"

    out = pat.sub(_merge, text)
    return out if out != text else None


def mips_gp_guard(
    text: str,
    external: dict[str, int] | None = None,
    gp: int = 0,
) -> str:
    """MIPS counterpart of `sda_guard`: prevent out-of-range `R_MIPS_GPREL16` relocations on far externs."""
    if not gp or not external:
        return text

    def _fix(m: re.Match[str]) -> str:
        typ, sym = m.group(1), m.group(2)
        if sym not in external:
            return m.group(0)
        addr = external[sym]
        if not (gp - 0x8000 <= addr <= gp + 0x7FFF):
            return f'extern {typ} {sym} __attribute__((section(".data")));'
        return m.group(0)

    return _EXTERN_SCALAR_RE.sub(_fix, text)


def gp_extern_variants(text: str) -> Iterator[tuple[str, str]]:
    """Toggle extern declarations between GP-eligible scalar `.sdata` and non-GP `.data` forms."""
    for m in _EXTERN_SCALAR_RE.finditer(text):
        typ, sym = m.group(1).strip(), m.group(2)
        sep = "" if typ.endswith("*") else " "
        yield "mips_gp_sdata", text[: m.start()] + f'extern {typ}{sep}{sym} __attribute__((section(".sdata")));' + text[m.end() :]
        yield "mips_gp_data", text[: m.start()] + f'extern {typ}{sep}{sym} __attribute__((section(".data")));' + text[m.end() :]
    for m in _EXTERN_ARRAY_RE.finditer(text):
        typ, sym = m.group(1).strip(), m.group(2)
        if re.search(r"\b" + re.escape(sym) + r"\s*\[0\]", text):
            v_scalar = text[: m.start()] + f"extern {typ} {sym};" + text[m.end() :]
            v_scalar = re.sub(r"\b" + re.escape(sym) + r"\s*\[0\]", sym, v_scalar)
            yield "mips_gp_scalar", v_scalar


def mips_target_ref_by_word(words: list[int], gp: int = 0) -> dict[int, int]:
    """Map word index `k` to resolved 32-bit target address for `lui+%lo` and `$gp+simm` instructions."""
    his: dict[int, tuple[int, int]] = {}
    refs: dict[int, int] = {}
    for k, w in enumerate(words or []):
        op = (w >> 26) & 0x3F
        rs = (w >> 21) & 0x1F
        rt = (w >> 16) & 0x1F
        uimm = w & 0xFFFF
        simm = uimm - 0x10000 if (uimm & 0x8000) else uimm
        if op == 15 and rs == 0 and rt != 0:
            his[rt] = (k, (uimm << 16) & 0xFFFFFFFF)
            continue
        if gp and rs == 28 and (op in (9, 25) or op in _MEM_OPS_MIPS):
            refs[k] = (gp + simm) & 0xFFFFFFFF
            continue
        if rs in his:
            lui_k, hi_v = his[rs]
            if op == 13:
                full = (hi_v | uimm) & 0xFFFFFFFF
                refs[lui_k] = full
                refs[k] = full
                if rt == rs:
                    his.pop(rs, None)
                continue
            if op in (9, 25) or op in _MEM_OPS_MIPS:
                full = (hi_v + simm) & 0xFFFFFFFF
                refs[lui_k] = full
                refs[k] = full
                if op in (9, 25) and rt == rs:
                    his.pop(rs, None)
                continue
    return refs


def mips_extern_relocs(
    text: str,
    unresolved: dict[int, str] | None,
    target_words: list[int] | None,
    gp: int = 0,
    read_mem: Any = None,
    endian: str = "little",
) -> Iterator[tuple[str, str]]:
    """MIPS counterpart of `extern_relocs`: bind unresolved `.rodata` strings/floats and `static` locals to target symbols."""
    if not unresolved or not target_words:
        return
    refs = mips_target_ref_by_word(target_words, gp=gp)
    if not refs:
        return

    ro_addrs: list[int] = []
    data_addrs: list[int] = []
    for k_raw, msg in sorted(unresolved.items(), key=lambda kv: int(kv[0])):
        addr = refs.get(int(k_raw))
        if addr is None:
            continue
        if "constant placement" in str(msg) or ".rodata" in str(msg) or ".lit" in str(msg):
            if addr not in ro_addrs:
                ro_addrs.append(addr)
        else:
            if addr not in data_addrs:
                data_addrs.append(addr)

    # 1. Out-of-range R_MIPS_GPREL16 on an existing extern -> mark `.data`
    if any("GPREL16" in str(v) and "out of signed 16-bit range" in str(v) for v in unresolved.values()):
        for _, cand in gp_extern_variants(text):
            if 'section(".data")' in cand:
                yield "mips_extern_reloc", cand

    # 2. Match C string literals against target readonly bytes
    if read_mem is not None and ro_addrs:
        out = text
        for lit in sorted(set(re.findall(r'(?<!section\()"((?:[^"\\\n]|\\.)*)"', text)), key=len, reverse=True):
            want = ppc_seeds. _c_string_bytes(lit) + b"\0" if hasattr(ppc_seeds, "_c_string_bytes") else (lit.encode("latin-1", "ignore") + b"\0")
            for addr in ro_addrs:
                try:
                    if read_mem(addr, len(want)) == want:
                        sym = f"lbl_{addr:08X}"
                        out = out.replace(f'"{lit}"', sym)
                        if f"extern char {sym}[];" not in out:
                            out = f"extern char {sym}[];\n" + out
                        break
                except Exception:
                    continue
        if out != text:
            yield "mips_extern_reloc", out

    # 3. Match 32-bit float literals in `.rodata` / `.lit4` when constant placement is ambiguous/missing
    if read_mem is not None and ro_addrs:
        out_f = text
        fmt_f = "<f" if endian == "little" else ">f"
        for flit_m in list(re.finditer(r"(?<![\w.])(-?\d+\.\d+f)(?![\w.])", text)):
            f_tok = flit_m.group(1)
            try:
                f_val = float(f_tok[:-1])
                f_bytes = struct.pack(fmt_f, f_val)
            except Exception:
                continue
            for addr in ro_addrs:
                try:
                    if read_mem(addr, 4) == f_bytes:
                        sym = f"lbl_{addr:08X}"
                        sec = ".sdata" if (gp and gp - 0x8000 <= addr <= gp + 0x7FFF) else ".rodata"
                        decl = f'extern const float {sym} __attribute__((section("{sec}")));\n'
                        out_f = out_f.replace(f_tok, sym, 1)
                        if sym not in out_f[: out_f.find(sym)]:
                            out_f = decl + out_f
                        break
                except Exception:
                    continue
        if out_f != text:
            yield "mips_extern_reloc", out_f

    # 4. Pair `static` local/file variables with target data addresses
    all_data = data_addrs or ro_addrs
    statics = [
        s
        for s in re.findall(
            r"^\s*static\s+((?:volatile\s+|const\s+)*[A-Za-z_][\w ]*?)\s+(\**)\s*([A-Za-z_]\w*)\s*(\[[^\]]*\])?\s*(?:=\s*[^;]*)?;",
            text,
            re.M,
        )
        if "(" not in s[0]
    ]
    if statics and len(statics) <= 3 and len(all_data) >= len(statics):
        for perm in itertools.islice(itertools.permutations(all_data, len(statics)), 6):
            cand = text
            for (kind, stars, name, arr), addr in zip(statics, perm):
                sym = f"lbl_{addr:08X}"
                sec = ".sdata" if (gp and gp - 0x8000 <= addr <= gp + 0x7FFF and not arr) else ".data"
                cand = re.sub(r"^\s*static\s+[^;\n]*\b" + re.escape(name) + r"\b[^;\n]*;[ \t]*\n", "", cand, count=1, flags=re.M)
                cand = re.sub(r"\b" + re.escape(name) + r"\b", sym, cand)
                cand = f'extern {kind} {stars}{sym}{arr} __attribute__((section("{sec}")));\n' + cand
            if cand != text:
                yield "mips_extern_reloc", cand


def mips_seed_variants(
    source: str,
    target_words: list[int] | None = None,
    objects: dict[int, tuple[str, int]] | None = None,
    functions: dict[int, str] | None = None,
    gp: int = 0,
    external: dict[str, int] | None = None,
) -> Iterator[tuple[str, str]]:
    """Yield MIPS-idiomatic C seed variants backed by target instruction and symbol evidence."""
    seen: set[str] = {source}

    def _emit(tag: str, cand: str | None) -> Iterator[tuple[str, str]]:
        if cand and cand not in seen:
            seen.add(cand)
            yield tag, cand

    if gp:
        resolved_gp = mips_resolve_gp_reg(source, gp)
        if resolved_gp != source:
            yield from _emit("mips_gp_resolve", resolved_gp)
    if gp and external:
        yield from _emit("mips_gp_guard", mips_gp_guard(source, external=external, gp=gp))
    yield from _emit("mips_narrow_cast", narrow_shift_casts(source))
    yield from _emit("mips_synth_struct", synthesize_m2c_structs(source))
    yield from _emit("mips_div_magic", mips_div_magic_cleanup(source))
    yield from _emit("mips_or_merge", mips_shortcircuit_or_merge(source))
    yield from _emit("mips_rebase_fields", ppc_seeds.rebase_fields(source))
    yield from _emit("mips_member_array", ppc_seeds.member_array(source))
    yield from _emit("mips_counter_guard", ppc_seeds.counter_guard(source))
    yield from _emit("mips_signed_temps", ppc_seeds.signed_temps(source))
    yield from _emit("mips_swap_union", ppc_seeds.swap_union(source))
    yield from _emit("mips_abs_struct", ppc_seeds.abs_struct(source))

    if objects:
        yield from _emit("mips_abs_symbols", mips_abs_symbols(source, objects, gp=gp))
    if functions:
        yield from _emit("mips_abs_functions", mips_abs_functions(source, functions))
    if target_words:
        yield from _emit("mips_lit16_sign", lit16_sign_mips(source, target_words))
        yield from _emit("mips_single_float", mips_single_float_literals(source, target_words))
        yield from _emit("mips_movz_ternary", mips_movz_ternary(source, target_words))
        yield from _emit("mips_raw_addr_rebase", mips_raw_addr_rebase(source, target_words, gp=gp))
        yield from _emit("mips_label_rebase", mips_label_rebase(source, objects or {}, target_words, gp=gp))

    for tag, cand in gp_extern_variants(source):
        yield from _emit(tag, cand)
