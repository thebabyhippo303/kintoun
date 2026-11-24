"""Real-world ARM/Thumb (`agbcc`, `arm-none-eabi-gcc`, `mwccarm`, `armcc`) seed repairs and target-evidenced C transforms.

Built for Game Boy Advance (`agbcc` ARM7TDMI Thumb + IWRAM ARM) and Nintendo DS (`mwccarm` ARM946E-S):
- Self-contained C89-clean `M2C_FIELD` / `M2C_BITWISE` / `M2C_CARRY` / `M2C_ERROR` & GBA/DS integer prelude;
- Repair of both `m2c --valid-syntax` and raw `m2c` pseudo-C (`?`, `->unkX`, `*(void *)`, `void *` pointer math);
- Strict C89 declaration hoisting (`agbcc` GCC 2.95 rejects mid-block variable declarations);
- Hardware MMIO (`0x04000000..0x04FFFFFF` GBA/DS REG_*) `volatile` protection + AGB DMA3 dummy-read recovery;
- Skipped AAPCS `r0..r3` (`arg0..arg3`) parameter slot refilling, `saved_reg_r4..lr`, CPSR condition temps, and `spXX` spills;
- Target `$d` literal-pool & `MOVW+MOVT` symbolization and rebasing (`arm_raw_pool_rebase`, `arm_label_rebase`, `arm_abs_symbols`, `arm_abs_functions`) — automatically recovering struct base addresses like `0x03001890 + 0x30` from `0x030018C0`!
- Thumb-1 `lsls 24; lsrs/asrs 24` and `lsls 16; lsrs/asrs 16` narrow cast & local-type recovery;
- Short-circuit `||` duplicate-branch call merging (`m2c` GBA Thumb pattern) and `.rodata` pool `extern_relocs`.
"""
from __future__ import annotations

from bisect import bisect_right
import itertools
import re
from typing import Any, Iterator

from kintoun.search import mips_seeds, seeds as ppc_seeds
from kintoun.search.arm_score import ArmItem

_ARM_STD_TYPES = (
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
    ("BOOL", "typedef int BOOL;"),
    ("M2C_UNK", "typedef int M2C_UNK;"),
)

_ARM_STD_MACROS = (
    ("NULL", "#ifndef NULL\n#define NULL ((void *)0)\n#endif"),
    ("M2C_FIELD", "#define M2C_FIELD(p, type, off) (*(type)((unsigned char *)(p) + (off)))"),
    ("M2C_BITWISE", "#define M2C_BITWISE(type, expr) (*(type *)&(expr))"),
    ("M2C_CARRY", "#define M2C_CARRY 0"),
    ("M2C_ERROR", "#define M2C_ERROR(msg) 0"),
    ("M2C_MEMCPY_ALIGNED", "#define M2C_MEMCPY_ALIGNED(d, s, n) memcpy((d), (s), (n))"),
)

_SAVED_ARM_REG_RE = re.compile(r"\bsaved_reg_(r(?:1[0-2]|[0-9])|sp|lr|fp|ip|sl|sb)\b")
_CPSR_FLAG_RE = re.compile(r"\b((?:temp|var)_(?:czn|[cznv]))\b")
_THUMB_ZEXT8_RE = re.compile(r"\(\s*\(u32\)\s*\(\s*([^;()\n]+?)\s*<<\s*(?:24|0x18)\s*\)\s*\)\s*>>\s*(?:24|0x18)")
_THUMB_ZEXT16_RE = re.compile(r"\(\s*\(u32\)\s*\(\s*([^;()\n]+?)\s*<<\s*(?:16|0x10)\s*\)\s*\)\s*>>\s*(?:16|0x10)")
_THUMB_SEXT8_RE = re.compile(r"\(\s*\(s32\)\s*\(\s*([^;()\n]+?)\s*<<\s*(?:24|0x18)\s*\)\s*\)\s*>>\s*(?:24|0x18)")
_THUMB_SEXT16_RE = re.compile(r"\(\s*\(s32\)\s*\(\s*([^;()\n]+?)\s*<<\s*(?:16|0x10)\s*\)\s*\)\s*>>\s*(?:16|0x10)")
_POSTINC_STMT_RE = re.compile(r"^([ \t]+)(\w+)\s*\+=\s*1;$", re.M)
_PREINC_STMT_RE = re.compile(r"^([ \t]+)(\w+)\+\+;$", re.M)
_ARM_ADDR_RE = re.compile(r"(?<![\w.])0x(0[1-9A-Fa-f][0-9A-Fa-f]{6})(?![\w.])")


def _is_arm_ram_or_rom_addr(addr: int) -> bool:
    """True if `addr` is in GBA EWRAM/IWRAM/VRAM/PAL/OAM/ROM (`0x02..0x09`) or DS ITCM/ARM9 (`0x01FF..0x027F`)."""
    return (
        0x01FF8000 <= addr < 0x03810000
        or 0x05000000 <= addr < 0x0A000000
    )


def _is_arm_mmio_addr(addr: int) -> bool:
    """True if `addr` is a GBA or Nintendo DS hardware register (`0x04000000..0x04FFFFFF`)."""
    return 0x04000000 <= addr < 0x05000000


_CORE_ARM_INT_NAMES = frozenset(("s8", "u8", "s16", "u16", "s32", "u32"))


def ensure_arm_prelude(text: str) -> str:
    """Prepend C89-compatible GBA/DS typedefs and `M2C_*` macros referenced by `text`."""
    has_any_decomp_t = bool(re.search(r"\b(?:s8|u8|s16|u16|s32|u32|s64|u64|f32|f64|M2C_UNK|M2C_FIELD)\b", text))
    lines_to_add: list[str] = []
    for tname, tdef in _ARM_STD_TYPES:
        want = (has_any_decomp_t and tname in _CORE_ARM_INT_NAMES) or bool(re.search(r"\b" + tname + r"\b", text))
        if want and not re.search(
            r"\btypedef\b[^;]*\b" + tname + r"\s*;|#\s*define\s+" + tname + r"\b", text
        ):
            lines_to_add.append(tdef)
    for mname, mdef in _ARM_STD_MACROS:
        if re.search(r"\b" + mname + r"\b", text) and not re.search(r"#\s*define\s+" + mname + r"\b", text):
            lines_to_add.append(mdef)
    if not lines_to_add:
        return text
    return "\n".join(lines_to_add) + "\n\n" + text


def protect_arm_mmio_volatile(text: str) -> str:
    """Upgrade GBA/DS hardware register accesses (`0x0400....`) to `volatile` so `-O2` preserves all MMIO/DMA writes."""
    def _sub_cast(m: re.Match[str]) -> str:
        typ, addr_s = m.group(1), m.group(2)
        if not _is_arm_mmio_addr(int(addr_s, 16)) or "volatile" in typ:
            return m.group(0)
        return f"*(volatile {typ} *){addr_s}"

    out = re.sub(
        r"\*\(\s*((?:[us](?:8|16|32)|int|short|char))\s*\*\s*\)\s*(0x04[0-9A-Fa-f]{6})\b",
        _sub_cast,
        text,
    )

    def _sub_mfld(m: re.Match[str]) -> str:
        addr_s, typ, off = m.group(1), m.group(2).strip(), m.group(3)
        if not _is_arm_mmio_addr(int(addr_s, 16)) or "volatile" in typ:
            return m.group(0)
        return f"M2C_FIELD((void *){addr_s}, volatile {typ}, {off})"

    out = re.sub(
        r"M2C_FIELD\(\s*\(void\s*\*\)\s*(0x04[0-9A-Fa-f]{6})\s*,\s*([^,]+?)\s*,\s*([^)]+)\)",
        _sub_mfld,
        out,
    )
    return out


def repair_arm_seed(text: str, name: str, address: int) -> str:
    """Repair real-world `m2c --target gba` / `arm` syntax, MMIO volatility, and `agbcc` C89 compliance."""
    even_addr = address & ~1
    repaired = mips_seeds.repair_mips_pseudo_syntax(text)
    repaired = ppc_seeds.repair_seed(repaired, name, even_addr)
    repaired = protect_arm_mmio_volatile(repaired)

    # Refill skipped AAPCS `r0..r3` (`arg0..arg3`) parameter slots
    sig = re.search(r"\b" + re.escape(name) + r"\s*\(([^{};]*)\)\s*\{", repaired)
    if sig:
        params = sig.group(1)
        parts = [p.strip() for p in params.split(",")] if params.strip() not in ("", "void") else []
        numbered = [(int(n[0]), p) for p in parts for n in [re.findall(r"\barg(\d+)$", p)] if n]
        ints = [p for p in parts if re.search(r"\barg\d+$", p)]
        if numbered and len(numbered) == len(ints) and [n for n, _ in numbered] != list(range(len(ints))):
            have = dict(numbered)
            max_slot = min(max(have), 3)
            filled = [have.get(i, f"s32 arg{i}") for i in range(max_slot + 1)]
            filled += [p for p in parts if not re.search(r"\barg\d+$", p)]
            repaired = repaired[: sig.start(1)] + ", ".join(filled) + repaired[sig.end(1) :]

    saved = sorted(set(_SAVED_ARM_REG_RE.findall(repaired)))
    cpsr_flags = sorted(set(_CPSR_FLAG_RE.findall(repaired)))
    sig = re.search(r"\b" + re.escape(name) + r"\s*\(([^{};]*)\)\s*\{", repaired)
    if sig:
        body_no_comments = re.sub(r"/\*.*?\*/|//[^\n]*", "", repaired[sig.end() :], flags=re.S)
        needs_bare_sp = (
            bool(re.search(r"(?<![\w.>])\bsp\b", body_no_comments))
            and not re.search(r"\bsp\b", sig.group(1))
            and not re.search(r"^[ \t]+[^;\n]*\bsp\s*(?:\[[^\]]*\])?\s*;", repaired[sig.end() :], re.M)
        )
        extra: list[str] = []
        if needs_bare_sp:
            extra.append("\n    u8 sp[0x10];")
        for r in saved:
            if not re.search(r"\b(?:char|void|s32|u32)\s*\*?\s*saved_reg_" + re.escape(r) + r"\b", repaired):
                extra.append(f"\n    s32 saved_reg_{r};")
        for flg in cpsr_flags:
            if not re.search(r"\b(?:s32|u32|int)\s+" + re.escape(flg) + r"\s*;", repaired):
                extra.append(f"\n    s32 {flg};")
        if extra:
            repaired = repaired[: sig.end()] + "".join(extra) + repaired[sig.end() :]

    repaired = mips_seeds.hoist_c89_declarations(repaired)
    repaired = ensure_arm_prelude(repaired)
    return repaired


def target_pool_addresses_arm(target_items: list[ArmItem] | None) -> list[int]:
    """Extract ordered 32-bit constants/addresses from `$d` literal pools and `MOVW+MOVT` pairs in `target_items`."""
    if not target_items:
        return []
    out: list[int] = []
    for it in target_items:
        if it.mode == "d" and it.size == 4 and it.raw not in out:
            out.append(it.raw)
    # Also scan MOVW+MOVT pairs
    from kintoun.search.arm_repairs import _movw_movt_pairs

    for _movw_idx, full_val in _movw_movt_pairs(target_items).values():
        if full_val not in out:
            out.append(full_val)
    return out


def arm_abs_symbols(text: str, objects: dict[int, tuple[str, int]]) -> str | None:
    """Rewrite raw GBA/DS RAM/ROM data addresses (`0x02..`, `0x03..`, `0x08..`) into known symbol references."""
    sig = re.search(r"^[^\n;#]*\b\w+\s*\([^{};]*\)\s*\{", text, re.M)
    if not sig or not objects:
        return None
    head, body = text[: sig.start()], text[sig.start() :]
    starts = sorted(objects)
    declare: list[str] = []

    def _sub(m: re.Match[str]) -> str:
        a = int(m.group(1), 16)
        if not _is_arm_ram_or_rom_addr(a):
            return m.group(0)
        i = bisect_right(starts, a) - 1
        if i < 0:
            return m.group(0)
        base = starts[i]
        name, size = objects[base][0], objects[base][1]
        if not name or a - base >= max(size, 1):
            return m.group(0)
        if not re.search(r"\b" + re.escape(name) + r"\b", head) and name not in declare:
            declare.append(name)
        return f"((u8 *)&{name} + 0x{a - base:X})" if a != base else f"(&{name})"

    out = _ARM_ADDR_RE.sub(_sub, body)
    if out == body:
        return None
    return head + "".join(f"extern u8 {n}[];\n" for n in declare) + out


def arm_abs_functions(
    text: str,
    functions: dict[int, str] | dict[int, tuple[str, int]],
) -> str | None:
    """Rewrite GBA/DS function pointers (including `+1` Thumb entry addresses like `0x08001C35`) into `&Func`."""
    sig = re.search(r"^[^\n;#]*\b(\w+)\s*\([^{};]*\)\s*\{", text, re.M)
    if not sig or not functions:
        return None
    head, body = text[: sig.start()], text[sig.start() :]
    declare: list[str] = []

    def _sub(m: re.Match[str]) -> str:
        a = int(m.group(1), 16)
        even = a & ~1
        entry = functions.get(even) or functions.get(a)
        fname = entry[0] if isinstance(entry, tuple) else entry
        if not fname or not re.fullmatch(r"[A-Za-z_]\w*", fname) or fname == sig.group(1):
            return m.group(0)
        if not re.search(r"\b" + re.escape(fname) + r"\b", head) and fname not in declare:
            declare.append(fname)
        return f"(&{fname})"

    out = _ARM_ADDR_RE.sub(_sub, body)
    if out == body:
        return None
    return head + "".join(f"void {n}(void);\n" for n in declare) + out


def arm_raw_pool_rebase(text: str, target_items: list[ArmItem] | None) -> str | None:
    """Rebase raw GBA/DS addresses (`*(u8 *)0x030018C0`) onto the exact struct bases in target's `$d` literal pool!

    In Thumb-1 (`agbcc`), `ldrb [r0, #imm5]` reaches only `0..31` and `ldrh`/`strh` reaches `0..62`.
    For larger struct offsets (`gState.field_30` at `0x03001890 + 0x30 = 0x030018C0`), `agbcc` places
    `0x03001890` in the `$d` literal pool and emits `ldr r0, =0x03001890; adds r0, #0x30; ldrb r0, [r0, #0]`,
    which `m2c` folds into `*(u8 *)0x030018C0`! Inspecting `target_items` `$d` pool recovers `0x03001890 + 0x30`
    automatically!
    """
    sig = re.search(r"^[^\n;#]*\b\w+\s*\([^{};]*\)\s*\{", text, re.M)
    if not sig or not target_items:
        return None
    pool_addrs = sorted(a for a in target_pool_addresses_arm(target_items) if _is_arm_ram_or_rom_addr(a))
    if not pool_addrs:
        return None
    head, body = text[: sig.start()], text[sig.start() :]
    decls: dict[str, str] = {}
    struct_fields_by_base: dict[int, dict[int, str]] = {}

    # Collect every `*(T *)0xADDR` in `body` that matches a pool address directly OR rebases within `0xFF` bytes
    deref_re = re.compile(
        r"\*\(\s*((?:volatile\s+|const\s+)?(?:[us](?:8|16|32)|int|short|char|void\s*\*+))\s*\*\s*\)\s*(0x0[1-9A-Fa-f][0-9A-Fa-f]{6})\b"
    )
    direct_scalars: dict[int, str] = {}
    for m in deref_re.finditer(body):
        typ, addr_s = m.group(1).strip(), m.group(2)
        addr = int(addr_s, 16)
        if not _is_arm_ram_or_rom_addr(addr):
            continue
        if addr in pool_addrs:
            direct_scalars.setdefault(addr, typ)
            continue
        idx = bisect_right(pool_addrs, addr) - 1
        if idx >= 0 and 0 <= addr - pool_addrs[idx] <= 0xFF:
            base = pool_addrs[idx]
            struct_fields_by_base.setdefault(base, {})[addr - base] = typ

    # Also match indexed ROM/RAM array lookups `*(T *)(0x087004B4 + (expr * S))` where `0x087004B4` is in `pool_addrs`
    idx_arr_re = re.compile(
        r"\*\(\s*((?:const\s+)?(?:[us](?:8|16|32)|int|short|char))\s*\*\s*\)\s*\(\s*(0x0[1-9A-Fa-f][0-9A-Fa-f]{6})\s*\+\s*\(\s*([^;\n]+?)\s*\*\s*([24])\s*\)\s*\)"
    )
    elem_sz_map = {"u16": 2, "s16": 2, "short": 2, "u32": 4, "s32": 4, "int": 4}
    array_decls: dict[str, str] = {}

    def _replace_idx_arr(m: re.Match[str]) -> str:
        etyp, addr_s, idx_expr, mult_s = m.group(1).strip(), m.group(2), m.group(3).strip(), int(m.group(4))
        addr = int(addr_s, 16)
        raw_et = etyp.replace("const ", "").strip()
        if addr not in pool_addrs or elem_sz_map.get(raw_et) != mult_s:
            return m.group(0)
        sym = f"lbl_{addr:08X}"
        c_qual = "const " if addr >= 0x08000000 and "const" not in etyp else ""
        array_decls.setdefault(sym, f"extern {c_qual}{etyp} {sym}[];\n")
        return f"{sym}[{idx_expr}]"

    out_body = idx_arr_re.sub(_replace_idx_arr, body)

    if not struct_fields_by_base and not direct_scalars and out_body == body:
        return None

    # Build clean C89 `struct` definitions for each rebased pool base so `agbcc` emits `ldr r0, =lbl_BASE; adds r0, #off`!
    struct_defs: list[str] = []
    size_map = {"u8": 1, "s8": 1, "char": 1, "u16": 2, "s16": 2, "short": 2, "u32": 4, "s32": 4, "int": 4}
    valid_bases: set[int] = set()

    for base, f_map in sorted(struct_fields_by_base.items()):
        if base in direct_scalars:
            f_map.setdefault(0, direct_scalars[base])
        cur = 0
        members: list[str] = []
        ok = True
        for off in sorted(f_map):
            raw_t = f_map[off].replace("volatile ", "").replace("const ", "").strip()
            sz = 4 if raw_t.endswith("*") else size_map.get(raw_t, 4)
            if off < cur or off % sz != 0:
                ok = False
                break
            if off > cur:
                members.append(f"u8 pad_{cur:X}[0x{off - cur:X}];")
            sep = "" if f_map[off].endswith("*") else " "
            members.append(f"{f_map[off]}{sep}f_{off:X};")
            cur = off + sz
        if ok and members:
            sname = f"mt_pool_{base:08X}_t"
            sym = f"lbl_{base:08X}"
            struct_defs.append(f"typedef struct {{ {' '.join(members)} }} {sname};\n")
            decls[sym] = f"extern {sname} {sym};\n"
            valid_bases.add(base)

    for s_addr, s_typ in sorted(direct_scalars.items()):
        if s_addr not in valid_bases:
            sym = f"lbl_{s_addr:08X}"
            sep = "" if s_typ.endswith("*") else " "
            decls.setdefault(sym, f"extern {s_typ}{sep}{sym};\n")
    decls.update(array_decls)

    def _replace_deref(m: re.Match[str]) -> str:
        typ, addr_s = m.group(1).strip(), m.group(2)
        addr = int(addr_s, 16)
        if addr in pool_addrs:
            if addr in valid_bases and 0 in struct_fields_by_base.get(addr, {}):
                return f"lbl_{addr:08X}.f_0"
            if addr in direct_scalars and addr not in valid_bases:
                return f"lbl_{addr:08X}"
        idx = bisect_right(pool_addrs, addr) - 1
        if idx >= 0:
            base = pool_addrs[idx]
            rel = addr - base
            if base in valid_bases and rel in struct_fields_by_base[base]:
                return f"lbl_{base:08X}.f_{rel:X}"
        return m.group(0)

    out_body = deref_re.sub(_replace_deref, out_body)
    if out_body == body:
        return None
    new_decls = [d for s, d in decls.items() if not re.search(r"\b" + s + r"\b", head)]
    return ensure_arm_prelude(head + "".join(struct_defs) + "".join(new_decls) + out_body)


def arm_label_rebase(
    text: str,
    objects: dict[int, tuple[str, int]],
    target_items: list[ArmItem] | None,
    window: int = 0x1000,
) -> str | None:
    """Rebase `lbl_XXXXXXXX` externs onto lower base symbols present in `target_items` `$d` pool."""
    built = set(target_pool_addresses_arm(target_items))
    if not built:
        return None
    labels = sorted({int(a, 16) for a in re.findall(r"\blbl_([0-9A-Fa-f]{8})\b", text)})
    if not labels:
        return None
    bases = sorted(a for a in built if (not objects or a in objects)) or sorted(built)
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
        if decl and not decl.group(2):
            kind = decl.group(1).strip() or "s32"
            out = out[: decl.end()] + re.sub(r"(?<![\w&])" + name + r"\b", f"(*({kind} *){ref})", out[decl.end() :])
        if f"{b:08X}" not in declared:
            extra.append(f"extern u8 {base}[];\n")
            declared.add(f"{b:08X}")
    sig = re.search(r"^[^\n;#]*\b\w+\s*\([^{};]*\)\s*\{", out, re.M)
    if extra and sig:
        out = out[: sig.start()] + "".join(extra) + out[sig.start() :]
    return out if out != text else None


def fold_thumb_shift_casts(text: str) -> str | None:
    """Fold Thumb-1 shift-pair idioms (`(x << 24) >> 24`) into `(u8)`/`(s8)`/`(u16)`/`(s16)` casts."""
    out = _THUMB_ZEXT8_RE.sub(r"((u8)(\1))", text)
    out = _THUMB_ZEXT16_RE.sub(r"((u16)(\1))", out)
    out = _THUMB_SEXT8_RE.sub(r"((s8)(\1))", out)
    out = _THUMB_SEXT16_RE.sub(r"((s16)(\1))", out)
    return out if out != text else None


def arm_dma_flush_reads(text: str, target_items: list[ArmItem] | None) -> str | None:
    """Recover Nintendo AGB SDK `DmaCopy`/`DmaFill` pipeline-flush dummy reads (`ldr rX, [rDMA, #8]`).

    On GBA (`AZJE70`, `BDBE70`), official `DmaSet` macros emit `*(vu32 *)REG_DMAxCNT = ctrl; *(vu32 *)REG_DMAxCNT;`
    (an unused volatile load from `+8` right after writing DMA control). `m2c` drops the unused volatile read!
    """
    if not target_items or "0x040000" not in text:
        return None
    # Check if target has back-to-back `str rA, [rB, #8]` followed by `ldr rC, [rB, #8]`!
    has_dma_flush = False
    for k in range(len(target_items) - 1):
        a, b = target_items[k], target_items[k + 1]
        if a.mode == "t16" and b.mode == "t16":
            # Thumb str rA, [rB, #8] (`0x6080 | rb<<3 | ra`) followed by ldr rC, [rB, #8] (`0x6880 | rb<<3 | rc`)
            if (a.raw & 0xFFC0) == 0x6080 and (b.raw & 0xFFC0) == 0x6880 and ((a.raw >> 3) & 7) == ((b.raw >> 3) & 7):
                has_dma_flush = True
                break
    if not has_dma_flush:
        return None

    pat = re.compile(
        r"^([ \t]+)(M2C_FIELD\(\s*\(void\s*\*\)\s*0x040000(?:B0|BC|C8|D4)\s*,\s*volatile\s+[^,]+,\s*8\s*\))\s*=\s*([^;\n]+);$",
        re.M,
    )
    out = pat.sub(r"\1\2 = \3;\n\1(void)\2;", text)
    return out if out != text else None


def agbcc_inc_variants(text: str) -> Iterator[tuple[str, str]]:
    """Toggle `x += 1;` <-> `x++;` (`agbcc` GCC 2.95 sometimes allocates different Thumb low regs)."""
    if _POSTINC_STMT_RE.search(text):
        yield "arm_postinc", _POSTINC_STMT_RE.sub(r"\1\2++;", text, count=1)
    if _PREINC_STMT_RE.search(text):
        yield "arm_addassign1", _PREINC_STMT_RE.sub(r"\1\2 += 1;", text, count=1)


def arm_extern_relocs(
    text: str,
    unresolved: dict[int, str] | None,
    target_items: list[ArmItem] | None,
    read_mem: Any = None,
) -> Iterator[tuple[str, str]]:
    """ARM/Thumb counterpart of `extern_relocs`: bind unresolved `.rodata` strings & statics via target `$d` pool words."""
    if not unresolved or not target_items:
        return
    pool_addrs = target_pool_addresses_arm(target_items)
    if not pool_addrs:
        return

    if read_mem is not None:
        out = text
        for lit in sorted(set(re.findall(r'(?<!section\()"((?:[^"\\\n]|\\.)*)"', text)), key=len, reverse=True):
            want = lit.encode("latin-1", "ignore") + b"\0"
            for addr in pool_addrs:
                try:
                    if read_mem(addr, len(want)) == want:
                        sym = f"lbl_{addr:08X}"
                        out = out.replace(f'"{lit}"', sym)
                        if f"extern const char {sym}[];" not in out:
                            out = f"extern const char {sym}[];\n" + out
                        break
                except Exception:
                    continue
        if out != text:
            yield "arm_extern_reloc", out

    ram_addrs = [a for a in pool_addrs if 0x01FF8000 <= a < 0x04000000]
    statics = [
        s
        for s in re.findall(
            r"^\s*static\s+((?:volatile\s+|const\s+)*[A-Za-z_][\w ]*?)\s+(\**)\s*([A-Za-z_]\w*)\s*(\[[^\]]*\])?\s*(?:=\s*[^;]*)?;",
            text,
            re.M,
        )
        if "(" not in s[0]
    ]
    if statics and len(statics) <= 3 and len(ram_addrs) >= len(statics):
        for perm in itertools.islice(itertools.permutations(ram_addrs, len(statics)), 6):
            cand = text
            for (kind, stars, name, arr), addr in zip(statics, perm):
                sym = f"lbl_{addr:08X}"
                cand = re.sub(r"^\s*static\s+[^;\n]*\b" + re.escape(name) + r"\b[^;\n]*;[ \t]*\n", "", cand, count=1, flags=re.M)
                cand = re.sub(r"\b" + re.escape(name) + r"\b", sym, cand)
                cand = f"extern {kind} {stars}{sym}{arr};\n" + cand
            if cand != text:
                yield "arm_extern_reloc", cand


def arm_seed_variants(
    source: str,
    target_items: list[ArmItem] | None = None,
    objects: dict[int, tuple[str, int]] | None = None,
    functions: dict[int, str] | None = None,
) -> Iterator[tuple[str, str]]:
    """Yield ARM/Thumb-idiomatic C seed variants backed by target `$d` literal-pool and instruction evidence."""
    seen: set[str] = {source}

    def _emit(tag: str, cand: str | None) -> Iterator[tuple[str, str]]:
        if cand and cand not in seen:
            seen.add(cand)
            yield tag, cand

    yield from _emit("arm_shift_cast", fold_thumb_shift_casts(source))
    synth = mips_seeds.synthesize_m2c_structs(source)
    if synth:
        yield from _emit("arm_synth_struct", ensure_arm_prelude(synth))
    yield from _emit("arm_or_merge", mips_seeds.mips_shortcircuit_or_merge(source))
    yield from _emit("arm_rebase_fields", ppc_seeds.rebase_fields(source))
    yield from _emit("arm_member_array", ppc_seeds.member_array(source))
    yield from _emit("arm_counter_guard", ppc_seeds.counter_guard(source))
    yield from _emit("arm_signed_temps", ppc_seeds.signed_temps(source))
    yield from _emit("arm_swap_union", ppc_seeds.swap_union(source))
    yield from _emit("arm_abs_struct", ppc_seeds.abs_struct(source))

    if objects:
        yield from _emit("arm_abs_symbols", arm_abs_symbols(source, objects))
    if functions:
        yield from _emit("arm_abs_functions", arm_abs_functions(source, functions))
    if target_items:
        reb = arm_raw_pool_rebase(source, target_items)
        yield from _emit("arm_raw_pool_rebase", reb)
        if reb:
            reb_synth = mips_seeds.synthesize_m2c_structs(reb)
            if reb_synth:
                yield from _emit("arm_pool_plus_struct", ensure_arm_prelude(reb_synth))
        yield from _emit("arm_label_rebase", arm_label_rebase(source, objects or {}, target_items))
        yield from _emit("arm_dma_flush", arm_dma_flush_reads(source, target_items))
        # Compose `or_merge` + `raw_pool_rebase` (exact GBA `AZJE70` pattern!)
        merged = mips_seeds.mips_shortcircuit_or_merge(source)
        if merged:
            yield from _emit("arm_or_plus_pool_rebase", arm_raw_pool_rebase(merged, target_items))

    for tag, cand in agbcc_inc_variants(source):
        yield from _emit(tag, cand)
