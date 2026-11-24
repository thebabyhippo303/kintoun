"""Dedicated multi-architecture function blocker check, static difficulty scorer, and `context_pack`.

Provides per-ISA (`ppc_elf`, `mips_elf`, `arm_elf`) static binary inspection with zero external
dependencies:
  - `check_function`: fast structural check detecting non-plain-C instructions (paired-single,
    COP0/VU0/VFPU, MCR/MRC/MRS/SWI, cache/privileged ops, inline trap words).
  - `score_difficulty`: static + history difficulty model (`0..100`, `easy`/`medium`/`hard`/`brutal`)
    plus exact and coarse masked opcode-shape fingerprints.
  - `build_context_pack`: compact ~1.5k-token one-screen brief for humans and AI agents with
    stdlib disassembly, resolved callees/globals, matched prototypes, shape-similar solved C
    examples from `src/`, and cached near-miss hints.
"""
from __future__ import annotations

from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import struct
from typing import Any

from kintoun.arch.arm_disasm import disasm_a32, disasm_thumb16, disasm_thumb32, is_thumb32_hw1
from kintoun.arch.mips_disasm import disasm_mips_word
from kintoun.arch.ppc_disasm import disasm_ppc_word
from kintoun.config import KintounConfig
from kintoun.targets import TargetContext, TargetFunction

DIFFICULTY_TIERS: tuple[tuple[int, str], ...] = (
    (25, "easy"),
    (50, "medium"),
    (75, "hard"),
    (101, "brutal"),
)

_PPC_PRIV_XO = frozenset({83, 146, 210, 242, 306, 370, 566, 598})
_PPC_CACHE_XO = frozenset({54, 86, 278, 470, 982, 1014})
_PPC_FLOAT_XO = frozenset({535, 567, 599, 631, 663, 695, 727, 759, 983})
_PPC_USER_SPR = frozenset({1, 8, 9})
_PPC_GQR_SPR = frozenset(range(912, 920))


def _tier_for(score: int) -> str:
    for limit, name in DIFFICULTY_TIERS:
        if score < limit:
            return name
    return "brutal"


def _decode_ppc_features(target_fn: TargetFunction, ctx: TargetContext) -> dict[str, Any]:
    data = target_fn.data
    words = [struct.unpack_from(">I", data, off)[0] for off in range(0, len(data) - (len(data) % 4), 4)]
    feats: Counter[str] = Counter()
    blockers: list[str] = []
    callees: list[str] = []
    globals_used: set[str] = set()
    exact_shape: list[Any] = []
    coarse_shape: list[str] = []
    disasm_lines: list[str] = []

    saw_blr = False
    for idx, w in enumerate(words):
        pc = target_fn.va + idx * 4
        mn, ops = disasm_ppc_word(w, pc)
        if len(disasm_lines) < 96:
            disasm_lines.append(f"  {pc:08X}: {w:08X}  {mn:<8} {ops}".rstrip())

        op = (w >> 26) & 0x3F
        shape_tok: Any = op
        coarse = "A"

        if saw_blr and idx < len(words) - 1 and w != 0:
            # Check if any branch jumps past `blr`; if no internal jump reaches here and word is trap-like
            if w in (0x00000001, 0x7FE00008):
                feats["trap_word"] += 1
                blockers.append(f"trap word 0x{w:08X} at +0x{idx * 4:X}")
        if w == 0x4E800020:
            saw_blr = True

        if op == 18:
            li = w & 0x03FFFFFC
            if li & 0x02000000:
                li -= 0x04000000
            tgt = (li if (w & 2) else (pc + li)) & 0xFFFFFFFF
            if w & 1:
                feats["calls"] += 1
                coarse = "C"
                cname = ctx.by_addr.get(tgt, f"0x{tgt:08X}")
                if cname not in callees:
                    callees.append(cname)
            else:
                feats["jumps"] += 1
                coarse = "B"
                if li < 0 and not (w & 2):
                    feats["loops"] += 1
            shape_tok = (18, w & 1)
        elif op == 16:
            bd = w & 0xFFFC
            if bd & 0x8000:
                bd -= 0x10000
            bo = (w >> 21) & 0x1F
            if (bo & 0x14) != 0x14:
                feats["cond_branches"] += 1
            if bd < 0:
                feats["loops"] += 1
            shape_tok = (16, w & 1)
            coarse = "B"
        elif op == 19:
            xo = (w >> 1) & 0x3FF
            shape_tok = (19, xo, w & 1)
            if xo == 528:
                if w & 1:
                    feats["indirect_calls"] += 1
                    coarse = "C"
                else:
                    feats["switches"] += 1
                    coarse = "B"
            elif xo == 16:
                coarse = "R"
            elif xo in (50, 150):
                feats["privileged"] += 1
                blockers.append(f"privileged op (xo={xo}) at +0x{idx * 4:X}")
        elif op == 31:
            xo = (w >> 1) & 0x3FF
            shape_tok = (31, xo)
            if xo in (339, 467):
                spr = (((w >> 16) & 0x1F) | (((w >> 11) & 0x1F) << 5))
                if spr in _PPC_GQR_SPR:
                    feats["paired_single"] += 1
                    blockers.append(f"Gekko GQR SPR {spr} at +0x{idx * 4:X}")
                elif spr not in _PPC_USER_SPR:
                    feats["privileged"] += 1
                    blockers.append(f"non-user SPR {spr} at +0x{idx * 4:X}")
            elif xo in _PPC_PRIV_XO:
                feats["privileged"] += 1
                blockers.append(f"privileged PPC op (xo={xo}) at +0x{idx * 4:X}")
            elif xo in _PPC_CACHE_XO:
                feats["cache_ops"] += 1
                blockers.append(f"cache instruction (xo={xo}) at +0x{idx * 4:X}")
            elif xo == 4:  # tw
                feats["trap_word"] += 1
                blockers.append(f"trap instruction at +0x{idx * 4:X}")
            elif xo in _PPC_FLOAT_XO:
                feats["float_ops"] += 1
                coarse = "F"
        elif 48 <= op <= 55:
            feats["float_ops"] += 1
            coarse = "F"
        elif op in (59, 63):
            xo = (w >> 1) & 0x3FF
            feats["float_ops"] += 1
            coarse = "F"
            if op == 63 and xo in (14, 15):
                feats["int_float_conv"] += 1
            shape_tok = (op, xo & 0x1F if (xo & 0x1F) >= 18 else xo)
        elif op in (4, 56, 57, 60, 61):
            feats["paired_single"] += 1
            blockers.append(f"Gekko paired-single op {op} at +0x{idx * 4:X}")
            coarse = "F"
        elif op == 17 or op == 3:
            feats["privileged"] += 1
            blockers.append(f"system/trap opcode {op} at +0x{idx * 4:X}")
        elif 32 <= op <= 47:
            ra = (w >> 16) & 0x1F
            simm = (w & 0xFFFF) - (0x10000 if (w & 0x8000) else 0)
            if ra in (13, 2):
                base = ctx.sda_r13 if ra == 13 else ctx.sda_r2
                if base:
                    gaddr = (base + simm) & 0xFFFFFFFF
                    if gaddr in ctx.objs:
                        globals_used.add(ctx.objs[gaddr][0])
            coarse = "L" if (op < 36 or 40 <= op < 44 or op == 46) else "S"
        elif op == 15 and (w & 0xFFFF) == 0x4330:
            feats["int_float_conv"] += 1

        exact_shape.append(shape_tok)
        if not coarse_shape or coarse_shape[-1] != coarse:
            coarse_shape.append(coarse)

    feats["ninstr"] = len(words)
    return {
        "features": dict(feats),
        "blockers": blockers[:6],
        "callees": callees[:24],
        "globals": sorted(globals_used)[:24],
        "shape_hash": hashlib.sha1(repr(exact_shape).encode("utf-8")).hexdigest()[:16],
        "coarse_hash": hashlib.sha1("".join(coarse_shape).encode("utf-8")).hexdigest()[:16],
        "disasm": "\n".join(disasm_lines),
    }


def _decode_mips_features(target_fn: TargetFunction, ctx: TargetContext) -> dict[str, Any]:
    data = target_fn.data
    fmt = "<I" if ctx.endian != "big" else ">I"
    words = [struct.unpack_from(fmt, data, off)[0] for off in range(0, len(data) - (len(data) % 4), 4)]
    feats: Counter[str] = Counter()
    blockers: list[str] = []
    callees: list[str] = []
    globals_used: set[str] = set()
    exact_shape: list[Any] = []
    coarse_shape: list[str] = []
    disasm_lines: list[str] = []

    for idx, w in enumerate(words):
        pc = target_fn.va + idx * 4
        mn, ops = disasm_mips_word(w, pc)
        if len(disasm_lines) < 96:
            disasm_lines.append(f"  {pc:08X}: {w:08X}  {mn:<8} {ops}".rstrip())

        op = (w >> 26) & 0x3F
        fn = w & 0x3F
        rs = (w >> 21) & 0x1F
        simm = (w & 0xFFFF) - (0x10000 if (w & 0x8000) else 0)
        shape_tok: Any = op
        coarse = "A"

        if op == 3:  # jal
            feats["calls"] += 1
            coarse = "C"
            tgt = ((pc + 4) & 0xF0000000) | ((w & 0x03FFFFFF) << 2)
            cname = ctx.by_addr.get(tgt, f"0x{tgt:08X}")
            if cname not in callees:
                callees.append(cname)
        elif op == 2:  # j
            feats["jumps"] += 1
            coarse = "B"
        elif op == 0:
            shape_tok = (0, fn)
            if fn == 9:  # jalr
                feats["indirect_calls"] += 1
                coarse = "C"
            elif fn == 8:  # jr
                if rs == 31:
                    coarse = "R"
                else:
                    feats["switches"] += 1
                    coarse = "B"
            elif fn in (12, 13):  # syscall / break
                feats["privileged"] += 1
                blockers.append(f"MIPS {mn} at +0x{idx * 4:X}")
        elif op in (4, 5, 6, 7, 20, 21, 22, 23):
            feats["cond_branches"] += 1
            coarse = "B"
            if simm < 0:
                feats["loops"] += 1
        elif op == 1:
            rt = (w >> 16) & 0x1F
            shape_tok = (1, rt)
            if rt in (0, 1, 2, 3, 16, 17, 18, 19):
                feats["cond_branches"] += 1
                coarse = "B"
                if simm < 0:
                    feats["loops"] += 1
        elif op == 16:  # COP0
            feats["privileged"] += 1
            blockers.append(f"MIPS COP0 ({mn}) at +0x{idx * 4:X}")
        elif op == 17:  # COP1 FP
            feats["float_ops"] += 1
            coarse = "F"
            if fn in (32, 33, 36):  # cvt.s.w / cvt.d.w / cvt.w.s
                feats["int_float_conv"] += 1
            shape_tok = (17, rs, fn)
        elif op in (18, 50, 54, 58, 62):  # COP2 / VU0 / VFPU
            feats["vector_ops"] += 1
            blockers.append(f"MIPS COP2/VFPU/VU0 ({mn}) at +0x{idx * 4:X}")
        elif op == 47:  # cache
            feats["cache_ops"] += 1
            blockers.append(f"MIPS cache op at +0x{idx * 4:X}")
        elif op in (49, 53, 57, 61):
            feats["float_ops"] += 1
            coarse = "F"
        elif 32 <= op <= 46:
            if rs == 28 and ctx.gp:
                gaddr = (ctx.gp + simm) & 0xFFFFFFFF
                if gaddr in ctx.objs:
                    globals_used.add(ctx.objs[gaddr][0])
            coarse = "L" if op < 40 else "S"

        exact_shape.append(shape_tok)
        if not coarse_shape or coarse_shape[-1] != coarse:
            coarse_shape.append(coarse)

    feats["ninstr"] = len(words)
    return {
        "features": dict(feats),
        "blockers": blockers[:6],
        "callees": callees[:24],
        "globals": sorted(globals_used)[:24],
        "shape_hash": hashlib.sha1(repr(exact_shape).encode("utf-8")).hexdigest()[:16],
        "coarse_hash": hashlib.sha1("".join(coarse_shape).encode("utf-8")).hexdigest()[:16],
        "disasm": "\n".join(disasm_lines),
    }


def _decode_arm_features(target_fn: TargetFunction, ctx: TargetContext) -> dict[str, Any]:
    data = target_fn.data
    feats: Counter[str] = Counter()
    blockers: list[str] = []
    callees: list[str] = []
    globals_used: set[str] = set()
    exact_shape: list[Any] = []
    coarse_shape: list[str] = []
    disasm_lines: list[str] = []

    if target_fn.is_thumb:
        data_ranges = [(s, e) for s, e, mode in (target_fn.intervals or ()) if mode == "$d"]
        items: list[tuple[int, int, int, str, str]] = []
        off = 0
        end = len(data)
        while off + 2 <= end:
            in_pool = any(s <= off < e for s, e in data_ranges)
            if in_pool and off + 4 <= end:
                w32 = struct.unpack_from("<I", data, off)[0]
                items.append((off, 4, w32, ".word", f"0x{w32:08x}"))
                off += 4
                continue
            hw1 = struct.unpack_from("<H", data, off)[0]
            if is_thumb32_hw1(hw1) and off + 4 <= end:
                hw2 = struct.unpack_from("<H", data, off + 2)[0]
                mn_t, ops_t = disasm_thumb32(hw1, hw2, target_fn.va + off)
                items.append((off, 4, (hw1 << 16) | hw2, mn_t, ops_t))
                off += 4
            else:
                mn_t, ops_t = disasm_thumb16(hw1, target_fn.va + off)
                items.append((off, 2, hw1, mn_t, ops_t))
                off += 2
        for off, size, raw_val, mn, ops in items:
            pc = target_fn.va + off
            if len(disasm_lines) < 96:
                hx = f"{raw_val:04X}" if size == 2 else f"{raw_val:08X}"
                disasm_lines.append(f"  {pc:08X}: {hx:<8}  {mn:<8} {ops}".rstrip())
            if mn.startswith("."):
                # Literal pool word -> check if it points to a known global/object
                if size == 4 and raw_val in ctx.objs:
                    globals_used.add(ctx.objs[raw_val][0])
                continue
            feats["ninstr"] += 1
            coarse = "A"
            if mn in ("bl", "blx"):
                feats["calls"] += 1
                coarse = "C"
                m = re.search(r"0x([0-9a-fA-F]+)", ops)
                if m:
                    tgt = int(m.group(1), 16)
                    cname = ctx.by_addr.get(tgt & ~1, f"0x{tgt:08X}")
                    if cname not in callees:
                        callees.append(cname)
                    if "aeabi_i2f" in cname or "floatsisf" in cname or "fixsfsi" in cname:
                        feats["int_float_conv"] += 1
                    elif "aeabi_f" in cname or "aeabi_d" in cname or "mulsf3" in cname or "addsf3" in cname:
                        feats["float_ops"] += 1
            elif mn == "bx" and "pc" in ops:
                blockers.append(f"inline Thumb->ARM mode switch `bx pc` at +0x{off:X}")
            elif mn == "bx" and "lr" not in ops:
                feats["indirect_calls"] += 1
                coarse = "C"
            elif mn in ("swi", "svc", "bkpt"):
                feats["privileged"] += 1
                blockers.append(f"Thumb `{mn}` trap at +0x{off:X}")
            elif mn.startswith("b") and mn not in ("bic", "bics"):
                if mn != "b":
                    feats["cond_branches"] += 1
                else:
                    feats["jumps"] += 1
                m = re.search(r"0x([0-9a-fA-F]+)", ops)
                if m and int(m.group(1), 16) < pc:
                    feats["loops"] += 1
                coarse = "B"
            elif mn.startswith(("ldr", "pop")):
                coarse = "R" if (mn == "pop" and "pc" in ops) else "L"
            elif mn.startswith(("str", "push")):
                coarse = "S"
            exact_shape.append(mn)
            if not coarse_shape or coarse_shape[-1] != coarse:
                coarse_shape.append(coarse)
    else:
        fmt = "<I" if ctx.endian != "big" else ">I"
        words = [struct.unpack_from(fmt, data, off)[0] for off in range(0, len(data) - (len(data) % 4), 4)]
        for idx, w in enumerate(words):
            pc = target_fn.va + idx * 4
            mn, ops = disasm_a32(w, pc)
            if len(disasm_lines) < 96:
                disasm_lines.append(f"  {pc:08X}: {w:08X}  {mn:<8} {ops}".rstrip())
            feats["ninstr"] += 1
            coarse = "A"
            if mn.startswith(("mcr", "mrc", "cdp", "mrs", "msr", "swi", "svc")):
                feats["privileged"] += 1
                blockers.append(f"A32 system/coproc `{mn}` at +0x{idx * 4:X}")
            elif mn.startswith(("bl", "blx")):
                feats["calls"] += 1
                coarse = "C"
                m = re.search(r"0x([0-9a-fA-F]+)", ops)
                if m:
                    tgt = int(m.group(1), 16)
                    cname = ctx.by_addr.get(tgt & ~1, f"0x{tgt:08X}")
                    if cname not in callees:
                        callees.append(cname)
            elif mn.startswith("b") and not mn.startswith("bic"):
                if mn != "b":
                    feats["cond_branches"] += 1
                m = re.search(r"0x([0-9a-fA-F]+)", ops)
                if m and int(m.group(1), 16) < pc:
                    feats["loops"] += 1
                coarse = "B"
            elif mn.startswith("ldr") and ops.startswith("pc,"):
                feats["switches"] += 1
                coarse = "B"
            exact_shape.append(mn)
            if not coarse_shape or coarse_shape[-1] != coarse:
                coarse_shape.append(coarse)

    return {
        "features": dict(feats),
        "blockers": blockers[:6],
        "callees": callees[:24],
        "globals": sorted(globals_used)[:24],
        "shape_hash": hashlib.sha1(repr(exact_shape).encode("utf-8")).hexdigest()[:16],
        "coarse_hash": hashlib.sha1("".join(coarse_shape).encode("utf-8")).hexdigest()[:16],
        "disasm": "\n".join(disasm_lines),
    }


def decode_target_features(target_fn: TargetFunction, ctx: TargetContext) -> dict[str, Any]:
    """Dispatch to the dedicated per-ISA binary feature decoder."""
    if ctx.arch in ("mips", "mips_elf"):
        return _decode_mips_features(target_fn, ctx)
    if ctx.arch in ("arm", "arm_elf"):
        return _decode_arm_features(target_fn, ctx)
    return _decode_ppc_features(target_fn, ctx)


def check_function(
    target_fn: TargetFunction,
    ctx: TargetContext,
    *,
    configured_preset: str = "",
) -> dict[str, Any]:
    """Fast structural check: determine if `target_fn` is matchable in plain C or has non-C / wrong-compiler blockers."""
    from kintoun.compiler_id import fingerprint_compiler

    dec = decode_target_features(target_fn, ctx)
    comp_fp = fingerprint_compiler(target_fn, ctx, configured_preset=configured_preset)
    blockers = list(dec["blockers"])
    plain_c = len(blockers) == 0 and target_fn.size > 0
    return {
        "name": target_fn.name,
        "addr": f"0x{target_fn.va:08X}",
        "arch": ctx.arch,
        "size_bytes": target_fn.size,
        "plain_c": plain_c,
        "verdict": "plain-c" if plain_c else "not-plain-c",
        "blockers": blockers,
        "compiler_fingerprint": comp_fp,
        "features": dec["features"],
        "callees": dec["callees"],
        "globals": dec["globals"],
        "shape_hash": dec["shape_hash"],
        "coarse_hash": dec["coarse_hash"],
    }


def score_difficulty(
    target_fn: TargetFunction,
    ctx: TargetContext,
    *,
    timeouts: int = 0,
    best_pct: float = 0.0,
    shape_matches: int = 0,
) -> dict[str, Any]:
    """Compute a `0..100` difficulty score (`easy`, `medium`, `hard`, `brutal`) and feature tags."""
    dec = decode_target_features(target_fn, ctx)
    f = dec["features"]
    size = target_fn.size
    ninstr = max(1, int(f.get("ninstr", size // 4)))

    tags: list[str] = ["small<128B" if size < 128 else "mid128-511B" if size < 512 else "large>=512B"]
    raw = min(38.0, size / 24.0)
    raw += min(14.0, f.get("cond_branches", 0) * 1.4)
    raw += min(12.0, f.get("loops", 0) * 4.0)
    raw += min(16.0, f.get("switches", 0) * 10.0)
    raw += min(14.0, f.get("indirect_calls", 0) * 6.0)
    raw += min(10.0, f.get("calls", 0) * 1.2)
    raw += min(16.0, f.get("float_ops", 0) * 1.1)
    raw += min(12.0, f.get("int_float_conv", 0) * 6.0)

    if f.get("float_ops", 0) >= 3 or f.get("float_ops", 0) / ninstr > 0.12:
        tags.append("float")
    if f.get("int_float_conv"):
        tags.append("int-float")
    if f.get("switches"):
        tags.append("switch")
    if f.get("loops"):
        tags.append("loop")
    if f.get("indirect_calls"):
        tags.append("indirect-call")
    if not f.get("calls") and not f.get("indirect_calls"):
        tags.append("leaf")
        raw -= 6.0
    if dec["blockers"]:
        tags.append("non-plain-c")
        raw = max(raw, 92.0)

    raw += min(20.0, timeouts * 8.0)
    if best_pct >= 90.0:
        tags.append("near-miss")
        raw -= 10.0
    if shape_matches > 0:
        tags.append("has-similar-match")
        raw -= min(10.0, shape_matches * 4.0)

    score = max(0, min(100, int(round(raw))))
    tier = _tier_for(score)
    time_mult = 1.5 if tier == "brutal" else 1.25 if tier == "hard" else 1.0
    from kintoun.similarity import extract_numeric_features, predict_match_probability

    match_prob = predict_match_probability(extract_numeric_features(target_fn, ctx))
    return {
        "name": target_fn.name,
        "addr": f"0x{target_fn.va:08X}",
        "score": score,
        "tier": tier,
        "tags": tags,
        "estimated_match_prob": match_prob,
        "recommended_time_multiplier": time_mult,
        "plain_c": len(dec["blockers"]) == 0,
        "blockers": dec["blockers"],
        "shape_hash": dec["shape_hash"],
        "coarse_hash": dec["coarse_hash"],
    }


_FUNC_DEF_RE = re.compile(
    r"(?m)^(?P<sig>[A-Za-z_][\w\s\*]+?\b(?P<name>[A-Za-z_]\w*)\s*\([^;{}]*\))\s*\{"
)


def _scan_matched_sources(src_dir: Path | None, callees: set[str], max_files: int = 250) -> tuple[list[str], list[dict[str, str]]]:
    """Scan existing project `src/` C files for callee prototypes and compact solved C examples."""
    if src_dir is None or not src_dir.is_dir():
        return [], []
    protos: list[str] = []
    examples: list[dict[str, str]] = []
    files = sorted(src_dir.rglob("*.c"))[:max_files]
    for cfile in files:
        try:
            txt = cfile.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for m in _FUNC_DEF_RE.finditer(txt):
            fname = m.group("name")
            sig = " ".join(m.group("sig").split()) + ";"
            if fname in callees and sig not in protos:
                protos.append(sig)
            if len(examples) < 2 and len(txt) <= 1400:
                examples.append({"file": str(cfile.name), "function": fname, "snippet": txt.strip()[:700]})
    return protos[:16], examples[:2]


def build_context_pack(
    target_fn: TargetFunction,
    ctx: TargetContext,
    cfg: KintounConfig | None = None,
    *,
    src_dir: Path | None = None,
    max_disasm_lines: int = 64,
) -> dict[str, Any]:
    """Build a compact ~1.5k-token one-call brief for `target_fn`."""
    from kintoun.compiler_id import fingerprint_compiler
    from kintoun.constants import scan_target_constants
    from kintoun.xref import analyze_function_xrefs_and_inlines

    dec = decode_target_features(target_fn, ctx)
    diff = score_difficulty(target_fn, ctx)
    active_preset = cfg.compiler_for(target_fn.va).preset if cfg is not None else ""
    comp_fp = fingerprint_compiler(target_fn, ctx, configured_preset=active_preset)
    consts = scan_target_constants(target_fn, ctx)

    eff_src = src_dir
    if eff_src is None and cfg is not None:
        cand_src = cfg.root / "src"
        if cand_src.is_dir():
            eff_src = cand_src

    cache_root = (
        (cfg.resolve_path(cfg.search.cache_dir) or (cfg.root / ".kintoun" / "cache"))
        if cfg is not None
        else None
    )
    xref_info = analyze_function_xrefs_and_inlines(
        target_fn,
        ctx,
        src_dir=eff_src,
        cache_dir=cache_root,
    )

    from kintoun.similarity import find_similar_functions

    protos, fallback_examples = _scan_matched_sources(eff_src, set(dec["callees"]))
    sim_examples = find_similar_functions(
        target_fn,
        ctx,
        src_dir=eff_src,
        incoming_callers=xref_info["incoming_callers"],
        top_k=3,
    )
    examples = sim_examples if sim_examples else fallback_examples
    hint_data: dict[str, Any] | None = None
    if cache_root is not None:
        hint_path = cache_root.parent / "hints" / f"{target_fn.name}.json"
        if hint_path.is_file():
            try:
                hint_data = json.loads(hint_path.read_text(encoding="utf-8"))
            except Exception:
                hint_data = None

    disasm_trimmed = "\n".join(dec["disasm"].splitlines()[:max_disasm_lines])
    return {
        "name": target_fn.name,
        "addr": f"0x{target_fn.va:08X}",
        "arch": ctx.arch,
        "size_bytes": target_fn.size,
        "verdict": "plain-c" if not dec["blockers"] else "not-plain-c",
        "blockers": dec["blockers"],
        "compiler_fingerprint": comp_fp,
        "difficulty": {
            "score": diff["score"],
            "tier": diff["tier"],
            "tags": diff["tags"],
            "estimated_match_prob": diff["estimated_match_prob"],
            "recommended_time_multiplier": diff["recommended_time_multiplier"],
        },
        "incoming_callers": xref_info["incoming_callers"],
        "vtable_or_data_refs": xref_info["vtable_or_data_refs"],
        "callees": dec["callees"],
        "callee_prototypes": protos,
        "globals": dec["globals"],
        "field_offset_consensus": xref_info["field_offset_consensus"],
        "inlined_helper_candidates": xref_info["inlined_helper_candidates"],
        "corpus_inline_defs": xref_info["corpus_inline_defs"],
        "exact_floats": consts["floats"],
        "magic_divisions": consts["magic_divisions"],
        "similar_examples": examples,
        "near_miss_hint": hint_data,
        "disassembly": disasm_trimmed,
    }
