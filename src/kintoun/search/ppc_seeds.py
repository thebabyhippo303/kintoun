"""Real-world PowerPC / GameCube (`prodg-wine`, `mwcc-wine`) seed repairs and DOL rebasing.

Applies the decompiler seed pipeline to PowerPC (`m2c` / `dtk` / blind DOL):
- Self-contained C89/ProDG/MWCC prelude (`s8..u64`, `f32`, `f64`, `M2C_UNK`, `M2C_FIELD`, C89 `M2C_BITWISE`);
- Repair of raw `m2c` pseudo-C (`M2C_ERROR`, `?` types, `*(void *)`, `void *` arithmetic, pointer+pointer offsets, integer-expression dereferences, float/pointer field clashes, and strict C89 declaration hoisting);
- `r13` (`_SDA_BASE_`) and `r2` (`_SDA2_BASE_`) `saved_reg_r13` / `saved_reg_r2` small-data symbol resolution;
- Target-instruction-evidenced `ppc_raw_addr_rebase` scanning `lis + addi/load/store` pairs vs `lis + ori` integer constants to turn raw `0x80XXXXXX` GameCube RAM literals into relocated `extern` globals & struct-offset accesses;
- `struct M2C_UNK_N` layout synthesis (`synthesize_m2c_structs`), single-precision `1.0f` float enforcement when target uses `lfs`/`fadds`/`fmuls` without double ops, `0x43300000` int-to-float magic recovery, and `sda_guard`.
"""
from __future__ import annotations

from bisect import bisect_right
import re
from typing import Any, Iterator

from kintoun.search import mutations as ppc_mutations
from kintoun.search import score as ppc_score
from kintoun.search import seeds as ppc_base_seeds
from kintoun.search.mips_seeds import (
    ensure_mips_prelude,
    hoist_c89_declarations,
    mips_single_float_literals,
    repair_mips_pseudo_syntax,
    synthesize_m2c_structs,
)

_GC_RAM_LO = 0x80000000
_GC_RAM_HI = 0x81800000
_PPC_ADDR_RE = re.compile(r"(?<![\w.])0x(8[01][0-9A-Fa-f]{6})(?![\w.])")


def _signed16(v: int) -> int:
    v &= 0xFFFF
    return v - 0x10000 if (v & 0x8000) else v


def ppc_resolve_sda_regs(text: str, sda_r13: int = 0, sda_r2: int = 0) -> str:
    """Resolve `m2c` `saved_reg_r13` / `_SDA_BASE_` and `saved_reg_r2` / `_SDA2_BASE_` accesses into `lbl_XXXXXXXX`."""
    if (not sda_r13 and not sda_r2) or not re.search(r"\b(?:saved_reg_r13|saved_reg_r2|_SDA_BASE_|_SDA2_BASE_)\b", text):
        return text
    sig = re.search(r"^[^\n;#]*\b\w+\s*\([^{};]*\)\s*\{", text, re.M)
    if not sig:
        return text
    head, body = text[: sig.start()], text[sig.start() :]
    decls: dict[str, str] = {}

    bases = []
    if sda_r13:
        bases.extend([("saved_reg_r13", sda_r13, ".sdata"), ("_SDA_BASE_", sda_r13, ".sdata")])
    if sda_r2:
        bases.extend([("saved_reg_r2", sda_r2, ".sdata2"), ("_SDA2_BASE_", sda_r2, ".sdata2")])

    for reg_tok, base_va, sec_name in bases:
        if reg_tok not in body:
            continue
        mf_pat = re.compile(
            r"M2C_FIELD\(\s*" + re.escape(reg_tok) + r"\s*,\s*([^,]+?)\s*\*\s*,\s*(-?(?:0x[0-9A-Fa-f]+|\d+))\s*\)"
        )
        while True:
            m = mf_pat.search(body)
            if not m:
                break
            val_t = m.group(1).strip()
            off = int(m.group(2), 0)
            addr = (base_va + off) & 0xFFFFFFFF
            sym = f"lbl_{addr:08X}"
            sep = "" if val_t.endswith("*") else " "
            decls.setdefault(sym, f'extern {val_t}{sep}{sym} __attribute__((section("{sec_name}")));\n')
            body = body[: m.start()] + sym + body[m.end() :]

        cast_pat = re.compile(
            r"\*\(\s*([A-Za-z_][\w\s]*?)\s*\*\s*\)\s*\(\s*"
            + re.escape(reg_tok)
            + r"\s*([+-])\s*(0x[0-9A-Fa-f]+|\d+)\s*\)"
        )
        while True:
            m = cast_pat.search(body)
            if not m:
                break
            val_t = m.group(1).strip()
            off = int(m.group(3), 0) * (-1 if m.group(2) == "-" else 1)
            addr = (base_va + off) & 0xFFFFFFFF
            sym = f"lbl_{addr:08X}"
            decls.setdefault(sym, f'extern {val_t} {sym} __attribute__((section("{sec_name}")));\n')
            body = body[: m.start()] + sym + body[m.end() :]

    if not decls:
        return text
    add_lines = [d for sym, d in sorted(decls.items()) if not re.search(r"\b" + sym + r"\b", head)]
    return head + "".join(add_lines) + body


def ppc_demote_far_sda_externs(text: str, sda_r13: int = 0, sda_r2: int = 0) -> str:
    """Rewrite scalar `extern T lbl_80XXXXXX;` outside SDA windows to `extern T lbl_80XXXXXX[16];` (`sym[0]`) for MWCC."""
    if not sda_r13 and not sda_r2:
        return text
    sig = re.search(r"^[^\n;#]*\b\w+\s*\([^{};]*\)\s*\{", text, re.M)
    if not sig:
        return text
    head, body = text[: sig.start()], text[sig.start() :]
    far_syms: list[str] = []

    def _rewrite_decl(m: re.Match[str]) -> str:
        prefix, sname, addr_hex = m.group(1), m.group(2), m.group(3)
        if "[" in prefix or "(" in prefix:
            return m.group(0)
        addr = int(addr_hex, 16)
        in_r13 = bool(sda_r13 and (sda_r13 - 0x8000 <= addr <= sda_r13 + 0x7FFF))
        in_r2 = bool(sda_r2 and (sda_r2 - 0x8000 <= addr <= sda_r2 + 0x7FFF))
        if in_r13 or in_r2:
            return m.group(0)
        far_syms.append(sname)
        return f"{prefix}{sname}[16];"

    new_head = re.sub(
        r"^(extern\s+[^;\n\[]*?\b)((?:lbl|D|_)?(8[01][0-9A-Fa-f]{6}))(?:\s+__attribute__\([^;]*\))?\s*;",
        _rewrite_decl,
        head,
        flags=re.M,
    )
    if not far_syms:
        return text
    new_body = body
    for sname in far_syms:
        new_body = re.sub(r"(?<!&)\b" + re.escape(sname) + r"\b(?!\s*\[)", f"{sname}[0]", new_body)
        new_body = re.sub(r"&\s*\b" + re.escape(sname) + r"\b(?!\s*\[)", sname, new_body)
    return new_head + new_body


def repair_ppc_seed(
    text: str,
    name: str,
    address: int,
    sda_r13: int = 0,
    sda_r2: int = 0,
) -> str:
    """Repair raw `m2c` PowerPC output into clean C89 for SN ProDG and Metrowerks MWCC."""
    step = repair_mips_pseudo_syntax(text)
    step = ppc_base_seeds.repair_seed(step, name, address)
    step = ppc_resolve_sda_regs(step, sda_r13=sda_r13, sda_r2=sda_r2)
    step = ppc_demote_far_sda_externs(step, sda_r13=sda_r13, sda_r2=sda_r2)
    # Remove any leftover `s32 saved_reg_r13;` declarations if unused
    for rtok in ("saved_reg_r13", "saved_reg_r2"):
        if len(re.findall(r"\b" + rtok + r"\b", step)) == 1:
            step = re.sub(r"^[ \t]+[^\n;]*\b" + rtok + r"\s*;\n?", "", step, flags=re.M)
    # Ensure `sp` array exists if bare `sp` is referenced
    if re.search(r"(?<![\w.])sp(?![\w.])", step) and not re.search(r"\bsp\s*(?:\[|;)", step):
        sig = re.search(r"^[^\n;#]*\b\w+\s*\([^{};]*\)\s*\{", step, re.M)
        if sig:
            step = step[: sig.end()] + "\n    s32 sp[4];" + step[sig.end() :]
    step = ensure_mips_prelude(step, use_c89_bitwise=True)
    step = hoist_c89_declarations(step)
    return step


def _extract_ppc_target_bases(
    target_words: list[int],
    sda_r13: int = 0,
    sda_r2: int = 0,
) -> tuple[list[int], set[int], set[int]]:
    """Scan PowerPC target words for `lis + addi/mem` symbol bases vs `lis + ori` constants and SDA globals."""
    hi_reg: dict[int, int] = {}
    bases: set[int] = set()
    sda_addrs: set[int] = set()
    const_only: set[int] = set()
    real_sym_bases: set[int] = set()

    for w in target_words:
        op = (w >> 26) & 0x3F
        rd = (w >> 21) & 0x1F
        ra = (w >> 16) & 0x1F
        uimm = w & 0xFFFF
        simm = _signed16(uimm)

        if op == 15 and ra == 0:  # lis rD, uimm
            hi_reg[rd] = uimm
            continue

        if (op == 14 or 32 <= op <= 55) and ra in (13, 2):
            base_va = sda_r13 if ra == 13 else sda_r2
            if base_va:
                addr = (base_va + simm) & 0xFFFFFFFF
                if _GC_RAM_LO <= addr < _GC_RAM_HI:
                    bases.add(addr)
                    sda_addrs.add(addr)
                    real_sym_bases.add(addr)

        if ra in hi_reg:
            hi = hi_reg[ra]
            if op == 14:  # addi rD, rA, simm (HA + LO symbol address!)
                full = ((hi << 16) + simm) & 0xFFFFFFFF
                if _GC_RAM_LO <= full < _GC_RAM_HI:
                    bases.add(full)
                    real_sym_bases.add(full)
                if rd == ra:
                    hi_reg.pop(ra, None)
                continue
            if 32 <= op <= 55:  # lwz/stw/lhz/lbz/lfs/lfd/stfs/stfd rD, simm(rA)
                full = ((hi << 16) + simm) & 0xFFFFFFFF
                if _GC_RAM_LO <= full < _GC_RAM_HI:
                    bases.add(full)
                    real_sym_bases.add(full)
                if op in (33, 35, 37, 39, 41, 43, 45, 47, 49, 51, 53, 55) or rd == ra:
                    hi_reg.pop(ra, None)
                continue
            if op == 24:  # ori rD, rA, uimm (integer constant, NOT HA/LO relocation)
                full = ((hi << 16) | uimm) & 0xFFFFFFFF
                const_only.add(full)
                if rd == ra:
                    hi_reg.pop(ra, None)
                continue

        # Clobber destination GPR on ALU / integer load ops
        if op in (7, 8, 10, 11, 12, 13, 14, 20, 21, 23, 32, 33, 34, 35, 40, 41, 42, 43):
            hi_reg.pop(rd, None)
        elif op in (24, 25, 26, 27, 28, 29):
            hi_reg.pop(ra, None)  # rA is destination on ori/oris/xori/andi.
        elif op == 31:
            xo = (w >> 1) & 0x3FF
            if xo in (28, 60, 124, 284, 316, 412, 444, 476, 24, 536, 792, 824, 922, 954):
                hi_reg.pop(ra, None)
            else:
                hi_reg.pop(rd, None)

    return sorted(bases), sda_addrs, (const_only - real_sym_bases)


def ppc_raw_addr_rebase(
    text: str,
    target_words: list[int],
    sda_r13: int = 0,
    sda_r2: int = 0,
) -> str | None:
    """Turn raw `0x80XXXXXX` GameCube RAM literals in `m2c` C into relocated `extern` globals & `M2C_FIELD` offsets."""
    if not _PPC_ADDR_RE.search(text):
        return None
    sig = re.search(r"^[^\n;#]*\b\w+\s*\([^{};]*\)\s*\{", text, re.M)
    if not sig:
        return None
    head, body = text[: sig.start()], text[sig.start() :]
    bases, sda_addrs, const_only = _extract_ppc_target_bases(target_words, sda_r13=sda_r13, sda_r2=sda_r2)

    raw_addrs = sorted(
        {
            int(m.group(1), 16)
            for m in _PPC_ADDR_RE.finditer(body)
            if _GC_RAM_LO <= int(m.group(1), 16) < _GC_RAM_HI and int(m.group(1), 16) not in const_only
        }
    )
    if not raw_addrs:
        return None

    chosen_base: dict[int, tuple[int, int]] = {}
    for addr in raw_addrs:
        idx = bisect_right(bases, addr) - 1
        if idx >= 0 and 0 <= addr - bases[idx] <= 0x1000:
            chosen_base[addr] = (bases[idx], addr - bases[idx])
        else:
            chosen_base[addr] = (addr, 0)

    base_has_nonzero_off = {b for b, off in chosen_base.values() if off > 0}
    decls: dict[str, str] = {}
    new_body = body

    def _is_sda(baddr: int) -> bool:
        if baddr in sda_addrs:
            if sda_r13 and (sda_r13 - 0x8000 <= baddr <= sda_r13 + 0x7FFF):
                return True
            if sda_r2 and (sda_r2 - 0x8000 <= baddr <= sda_r2 + 0x7FFF):
                return True
        return False

    deref_pat = re.compile(
        r"\*\(\s*((?:volatile\s+|const\s+)?(?:[us](?:8|16|32|64)|f32|f64|int|unsigned(?:\s+int)?|short|unsigned\s+short|char|unsigned\s+char|float|double|void\s*\*|[A-Za-z_]\w*\s*\*))\s*\*\s*\)\s*0x(8[01][0-9A-Fa-f]{6})(?![\w.])"
    )

    def _sub_deref(m: re.Match[str]) -> str:
        val_t = re.sub(r"\s+", " ", m.group(1).strip())
        addr = int(m.group(2), 16)
        if addr not in chosen_base:
            return m.group(0)
        baddr, off = chosen_base[addr]
        sym = f"lbl_{baddr:08X}"
        if off == 0 and baddr not in base_has_nonzero_off:
            sep = "" if val_t.endswith("*") else " "
            if _is_sda(baddr):
                decls.setdefault(sym, f"extern {val_t}{sep}{sym};\n")
                return sym
            # Size > 8 bytes forces both SN ProDG and Metrowerks MWCC out of `.sdata` (`ADDR16_HA`+`LO`)!
            decls.setdefault(sym, f"extern {val_t}{sep}{sym}[16];\n")
            return f"{sym}[0]"
        decls.setdefault(sym, f"extern u8 {sym}[0x1000];\n")
        return f"M2C_FIELD({sym}, {val_t} *, {hex(off)})"

    new_body = deref_pat.sub(_sub_deref, new_body)

    def _sub_bare(m: re.Match[str]) -> str:
        addr = int(m.group(1), 16)
        if addr not in chosen_base:
            return m.group(0)
        baddr, off = chosen_base[addr]
        sym = f"lbl_{baddr:08X}"
        decls.setdefault(sym, f"extern u8 {sym}[0x1000];\n")
        return f"((void *)({sym} + {hex(off)}))" if off else f"((void *){sym})"

    new_body = _PPC_ADDR_RE.sub(_sub_bare, new_body)
    if new_body == body:
        return None

    add_lines = [d for sym, d in sorted(decls.items()) if not re.search(r"\b" + sym + r"\b", head)]
    return head + "".join(add_lines) + new_body


def _target_uses_single_fp_only(target_words: list[int]) -> bool:
    has_single = False
    for w in target_words:
        op = (w >> 26) & 0x3F
        if op in (48, 49, 52, 53):  # lfs, lfsu, stfs, stfsu
            has_single = True
        elif op == 59:  # single-precision FP arithmetic (fadds, fsubs, fmuls, fdivs, fmadds)
            has_single = True
        elif op == 63 and ((w >> 1) & 0x1F) in (18, 20, 21, 25, 28, 29, 30, 31):
            # double-precision fdiv/fsub/fadd/fmul/fmsub/fmadd/fnmsub/fnmadd
            return False
    return has_single


def ppc_seed_variants(
    source: str,
    target_fn: Any,
    ctx: Any,
) -> Iterator[tuple[str, str]]:
    """Yield GameCube / PowerPC seed expansions modeled on the MIPS seeds."""
    if target_fn is None or not getattr(target_fn, "data", b""):
        return
    target_words = ppc_score.words_be(target_fn.data)
    r13 = getattr(ctx, "sda_r13", 0) if ctx else 0
    r2 = getattr(ctx, "sda_r2", 0) if ctx else 0
    objs = getattr(ctx, "objs", {}) if ctx else {}
    funcs = getattr(ctx, "funcs", {}) if ctx else {}
    by_addr = getattr(ctx, "by_addr", {}) if ctx else {}

    seen = {source}

    def _emit(tag: str, cand: str | None) -> Iterator[tuple[str, str]]:
        if cand and cand not in seen:
            c89 = hoist_c89_declarations(ensure_mips_prelude(cand, use_c89_bitwise=True))
            if c89 not in seen:
                seen.add(c89)
                yield tag, c89

    # 1. Raw `m2c` repair + SDA reg resolution + raw DOL address rebasing
    repaired = repair_ppc_seed(source, target_fn.name, target_fn.va, sda_r13=r13, sda_r2=r2)
    yield from _emit("ppc_seed_repair", repaired)

    base_src = repaired if repaired != source else source
    rebased = ppc_raw_addr_rebase(base_src, target_words, sda_r13=r13, sda_r2=r2)
    if rebased:
        yield from _emit("ppc_seed_rebase", rebased)
        base_src = rebased

    # 2. Synthesize `struct M2C_UNK_N` from `M2C_FIELD` accesses
    yield from _emit("ppc_synth_struct", synthesize_m2c_structs(base_src))

    # 3. Single-precision float literal suffix (`1.0` -> `1.0f`) when target uses single-FP ops
    if _target_uses_single_fp_only(target_words):
        yield from _emit("ppc_single_floats", mips_single_float_literals(base_src, target_words))

    # 4. PowerPC seeds (`compose`, `lit16_sign`, `i2f_magic`, `abs_symbols`, `abs_functions`, `rebase_fields`, etc.)
    if objs:
        yield from _emit("ppc_compose", ppc_base_seeds.compose(base_src, objs, target_words))
        yield from _emit("ppc_abs_symbols", ppc_base_seeds.abs_symbols(base_src, objs))
        yield from _emit("ppc_abs_base", ppc_base_seeds.abs_base(base_src, objs))
    if by_addr:
        yield from _emit("ppc_abs_functions", ppc_base_seeds.abs_functions(base_src, by_addr))
    yield from _emit("ppc_lit16_sign", ppc_base_seeds.lit16_sign(base_src, target_words))
    if ctx is not None and hasattr(ctx, "read"):
        yield from _emit("ppc_i2f_magic", ppc_base_seeds.i2f_magic(base_src, target_words, ctx.read))
    yield from _emit("ppc_rebase_fields", ppc_base_seeds.rebase_fields(base_src))
    yield from _emit("ppc_swap_union", ppc_base_seeds.swap_union(base_src))
    yield from _emit("ppc_postdec_loop", ppc_base_seeds.postdec_loop(base_src))
    yield from _emit("ppc_counter_guard", ppc_base_seeds.counter_guard(base_src))
    yield from _emit("ppc_vec3_copy", ppc_base_seeds.vec3_copy(base_src))
    yield from _emit("ppc_signed_temps", ppc_base_seeds.signed_temps(base_src))

    # 5. SDA section guard so out-of-range globals emit `lis+addi` instead of unresolvable `SDA21`
    if ctx is not None and (r13 or r2):
        class _Book:
            objects = objs
            functions = {va: (n, sz) for n, (va, sz) in funcs.items()}
            @staticmethod
            def address(sym_name: str) -> int:
                if sym_name in ctx.external:
                    return ctx.external[sym_name]
                m = re.fullmatch(r"(?:lbl|fn|func|D)_([0-9A-Fa-f]{8})", sym_name)
                if m:
                    return int(m.group(1), 16)
                raise ValueError(sym_name)

        guarded = ppc_mutations.sda_guard(base_src, _Book, r13, r2)
        if guarded != base_src:
            yield from _emit("ppc_sda_guard", guarded)
