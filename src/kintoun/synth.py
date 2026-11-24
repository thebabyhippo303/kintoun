"""Deterministic binary-fact struct, vtable, and debug assert-string synthesizer (`kintoun synth-headers`).

Extracts concrete C header scaffolds directly from unmatched binary instructions and `.rodata`/`.data`
segments across PowerPC (`ppc_elf`), MIPS (`mips_elf`), and ARM/Thumb (`arm_elf`) without guessing
compiler-fragile bitfields:
  - **Argument-pointer struct layouts:** Decodes load/store widths and signed/float types off `arg0`
    (`r3` on PowerPC, `$a0` on MIPS, `r0` on ARM/Thumb, tracking prologue `this`-pointer moves)
    grouped by `Class__` prefix or vtable ownership, emitting byte-accurate `struct` definitions
    with explicit `_pad_0xXX` arrays and static offset comments.
  - **Contiguous `.rodata`/`.data` vtables:** Identifies function-pointer tables (`>= 2` consecutive
    known function addresses) and emits typed `struct <Owner>_Vtable` slot definitions.
  - **Debug assert & source-file strings:** Extracts `.c`/`.cpp`/`.h` source filenames, assertion
    expressions, and format strings from data segments and cross-references referencing functions.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from pathlib import Path
import re
import struct
from typing import Any

from kintoun.targets import TargetContext

_TYPE_SIZE = {
    "u8": 1,
    "s8": 1,
    "u16": 2,
    "s16": 2,
    "s32": 4,
    "u32": 4,
    "f32": 4,
    "f64": 8,
    "s64": 8,
}

_PPC_MEM_OPS: dict[int, tuple[str, int]] = {
    32: ("s32", 4),  # lwz
    34: ("u8", 1),   # lbz
    36: ("s32", 4),  # stw
    38: ("u8", 1),   # stb
    40: ("u16", 2),  # lhz
    42: ("s16", 2),  # lha
    44: ("u16", 2),  # sth
    48: ("f32", 4),  # lfs
    50: ("f64", 8),  # lfd
    52: ("f32", 4),  # stfs
    54: ("f64", 8),  # stfd
}

_MIPS_MEM_OPS: dict[int, tuple[str, int]] = {
    32: ("s8", 1),   # lb
    33: ("s16", 2),  # lh
    35: ("s32", 4),  # lw
    36: ("u8", 1),   # lbu
    37: ("u16", 2),  # lhu
    40: ("s8", 1),   # sb
    41: ("s16", 2),  # sh
    43: ("s32", 4),  # sw
    49: ("f32", 4),  # lwc1
    53: ("f64", 8),  # ldc1
    57: ("f32", 4),  # swc1
    61: ("f64", 8),  # sdc1
}

_SRC_FILE_STR_RE = re.compile(r"[A-Za-z0-9_./\\-]+\.(?:c|cpp|cc|cxx|h|hpp)\b")
_ASSERT_HINT_RE = re.compile(r"(?:assert|ASSERT|NULL|nullptr|!=\s*0|<=\s*\w+|%\d*[dsfxp])")


def _decode_ppc_arg0_fields(data: bytes) -> list[tuple[int, str]]:
    """Track `r3` (and callee-save copies `mr rX, r3`) across a PowerPC function's loads/stores."""
    tracked = {3}
    accesses: list[tuple[int, str]] = []
    for off in range(0, len(data) - (len(data) % 4), 4):
        w = struct.unpack_from(">I", data, off)[0]
        op = (w >> 26) & 0x3F
        # `mr rA, rS` is `or rA, rS, rS` (op=31, xo=444) or `addi rD, rA, 0`
        if op == 31 and ((w >> 1) & 0x3FF) == 444:
            rs = (w >> 21) & 0x1F
            ra = (w >> 16) & 0x1F
            rb = (w >> 11) & 0x1F
            if rs == rb and rs in tracked and ra not in (0, 1, 2, 13):
                tracked.add(ra)
            elif ra in tracked and rs != rb:
                tracked.discard(ra)
            continue
        if op == 18 and (w & 1):  # `bl` clobbers volatile `r3`!
            tracked.discard(3)
            continue
        if op in _PPC_MEM_OPS:
            rt = (w >> 21) & 0x1F
            ra = (w >> 16) & 0x1F
            simm = (w & 0xFFFF) - (0x10000 if (w & 0x8000) else 0)
            ty, _sz = _PPC_MEM_OPS[op]
            if ra in tracked and 0 <= simm <= 0x1000:
                accesses.append((simm, ty))
            # If load overwrites a tracked register (`lwz r3, ...`), stop tracking that register unless after recording
            if op in (32, 34, 40, 42) and rt in tracked:
                tracked.discard(rt)
    return accesses


def _decode_mips_arg0_fields(data: bytes, endian: str) -> list[tuple[int, str]]:
    """Track `$a0` (`$4`, plus `move $sX, $a0`) across a MIPS function's loads/stores."""
    fmt = "<I" if endian != "big" else ">I"
    tracked = {4}
    accesses: list[tuple[int, str]] = []
    pending_clobber_a0 = False
    for off in range(0, len(data) - (len(data) % 4), 4):
        w = struct.unpack_from(fmt, data, off)[0]
        op = (w >> 26) & 0x3F
        rs = (w >> 21) & 0x1F
        rt = (w >> 16) & 0x1F
        rd = (w >> 11) & 0x1F
        fn = w & 0x3F
        # `addu/or/daddu rd, rs, $zero` -> register move
        if op == 0 and fn in (0x21, 0x25, 0x2D) and rt == 0:
            if rs in tracked and 16 <= rd <= 23:
                tracked.add(rd)
        elif op in _MIPS_MEM_OPS:
            simm = (w & 0xFFFF) - (0x10000 if (w & 0x8000) else 0)
            ty, _sz = _MIPS_MEM_OPS[op]
            if rs in tracked and 0 <= simm <= 0x1000:
                accesses.append((simm, ty))
            if op in (32, 33, 35, 36, 37) and rt in tracked:
                tracked.discard(rt)
        if pending_clobber_a0:
            tracked.discard(4)
            pending_clobber_a0 = False
        if op == 3:  # `jal` clobbers `$a0` after delay slot
            pending_clobber_a0 = True
    return accesses


def _decode_arm_arg0_fields(data: bytes, is_thumb: bool, endian: str) -> list[tuple[int, str]]:
    """Track `r0` (and `mov r4..r7, r0`) across ARM A32 or Thumb-16 loads/stores."""
    tracked = {0}
    accesses: list[tuple[int, str]] = []
    if is_thumb:
        for off in range(0, len(data) - (len(data) % 2), 2):
            hw = struct.unpack_from("<H", data, off)[0]
            # `adds rD, rS, #0` (`0001110_000_rs_rd`) or `mov rD, rM` (`01000110...`)
            if (hw & 0xFFC0) == 0x1C00:
                rs = (hw >> 3) & 7
                rd = hw & 7
                if rs in tracked and rd >= 4:
                    tracked.add(rd)
            # Thumb immediate offset load/store: `011_B_L_imm5_rn_rt` (`ldr/str`/`ldrb/strb`)
            elif (hw >> 13) == 0b011:
                is_byte = bool((hw >> 12) & 1)
                is_load = bool((hw >> 11) & 1)
                imm5 = (hw >> 6) & 0x1F
                rn = (hw >> 3) & 7
                rt = hw & 7
                byte_off = imm5 if is_byte else (imm5 * 4)
                if rn in tracked:
                    accesses.append((byte_off, "u8" if is_byte else "s32"))
                if is_load and rt in tracked:
                    tracked.discard(rt)
            # Thumb halfword `ldrh/strh`: `1000_L_imm5_rn_rt`
            elif (hw >> 12) == 0b1000:
                is_load = bool((hw >> 11) & 1)
                imm5 = (hw >> 6) & 0x1F
                rn = (hw >> 3) & 7
                rt = hw & 7
                if rn in tracked:
                    accesses.append((imm5 * 2, "u16"))
                if is_load and rt in tracked:
                    tracked.discard(rt)
            elif (hw & 0xF800) == 0xF000:  # Thumb `bl`
                tracked.discard(0)
    else:
        fmt = "<I" if endian != "big" else ">I"
        for off in range(0, len(data) - (len(data) % 4), 4):
            w = struct.unpack_from(fmt, data, off)[0]
            # Single data transfer `ldr/str`/`ldrb/strb` immediate pre-indexed (`(w >> 26) == 1`)
            if ((w >> 26) & 0b11) == 0b01 and not ((w >> 25) & 1) and ((w >> 24) & 1) and ((w >> 23) & 1):
                is_byte = bool((w >> 22) & 1)
                is_load = bool((w >> 20) & 1)
                rn = (w >> 16) & 0xF
                rt = (w >> 12) & 0xF
                imm12 = w & 0xFFF
                if rn in tracked and imm12 <= 0x1000:
                    accesses.append((imm12, "u8" if is_byte else "s32"))
                if is_load and rt in tracked:
                    tracked.discard(rt)
            elif ((w >> 24) & 0xF) == 0xB:  # `bl`
                tracked.discard(0)
    return accesses


def scan_vtables(ctx: TargetContext, min_slots: int = 2) -> list[dict[str, Any]]:
    """Scan `ctx.data_segments` for contiguous arrays of `>= min_slots` function pointers."""
    if not ctx.by_addr or not ctx.data_segments:
        return []
    fmt = "<I" if (ctx.arch in ("mips", "mips_elf", "arm", "arm_elf") and ctx.endian != "big") else ">I"
    is_arm = ctx.arch in ("arm", "arm_elf")
    known = ctx.by_addr

    vtables: list[dict[str, Any]] = []
    for seg_va, seg_bytes in ctx.data_segments:
        n_words = len(seg_bytes) // 4
        i = 0
        while i < n_words:
            run: list[str] = []
            start_va = seg_va + i * 4
            while i < n_words:
                ptr = struct.unpack_from(fmt, seg_bytes, i * 4)[0]
                lookup = (ptr & ~1) if is_arm else ptr
                if lookup in known:
                    run.append(known[lookup])
                    i += 1
                else:
                    break
            if len(run) >= min_slots:
                sym_name = ctx.objs.get(start_va, ("", 0))[0]
                if not sym_name:
                    prefixes = [fn.split("__", 1)[0] for fn in run if "__" in fn]
                    dom_cls = Counter(prefixes).most_common(1)[0][0] if prefixes else f"Vtable_{start_va:08X}"
                    sym_name = f"{dom_cls}_vtable"
                vtables.append(
                    {
                        "name": sym_name,
                        "addr": f"0x{start_va:08X}",
                        "slot_count": len(run),
                        "slots": run[:48],
                    }
                )
            else:
                i += 1
    return vtables[:64]


def scan_debug_strings(ctx: TargetContext) -> list[dict[str, Any]]:
    """Extract ASCII `.c`/`.cpp`/`.h` source paths, assert expressions, and format strings from data segments."""
    findings: list[dict[str, Any]] = []
    for seg_va, seg_bytes in ctx.data_segments:
        for m in re.finditer(rb"[\x20-\x7e]{5,160}\x00", seg_bytes):
            s_va = seg_va + m.start()
            txt = m.group(0)[:-1].decode("ascii", errors="ignore").strip()
            src_m = _SRC_FILE_STR_RE.search(txt)
            is_assert = bool(_ASSERT_HINT_RE.search(txt))
            if not src_m and not is_assert:
                continue
            findings.append(
                {
                    "addr": f"0x{s_va:08X}",
                    "kind": "source_file" if src_m else "assert_or_fmt",
                    "source_file": src_m.group(0) if src_m else "",
                    "text": txt[:120],
                }
            )
            if len(findings) >= 120:
                return findings
    return findings


def _build_struct_fields(votes: dict[int, Counter[str]], has_vtable: bool = False) -> list[dict[str, Any]]:
    """Lay out non-overlapping C struct fields + explicit padding arrays from `(offset -> type)` votes."""
    merged_votes: dict[int, Counter[str]] = defaultdict(Counter, votes)
    if has_vtable and 0 not in merged_votes:
        merged_votes[0]["void*"] += 2
    elif has_vtable and 0 in merged_votes:
        merged_votes[0]["void*"] += 10

    fields: list[dict[str, Any]] = []
    cursor = 0
    for off in sorted(merged_votes):
        if off < cursor:
            continue
        if off > cursor:
            gap = off - cursor
            fields.append(
                {
                    "offset": f"0x{cursor:02X}",
                    "c_decl": f"u8 _pad_0x{cursor:02X}[0x{gap:X}];",
                    "size": gap,
                    "votes": 0,
                    "conflict": None,
                }
            )
            cursor = off

        ranked = merged_votes[off].most_common()
        top_ty, top_n = ranked[0]
        sz = 4 if top_ty == "void*" else _TYPE_SIZE.get(top_ty, 4)
        # Ensure field size doesn't overrun the next observed offset
        higher_offs = [o for o in merged_votes if o > off]
        if higher_offs and off + sz > higher_offs[0]:
            gap_to_next = higher_offs[0] - off
            if gap_to_next == 2:
                top_ty, sz = "u16", 2
            elif gap_to_next == 1:
                top_ty, sz = "u8", 1
        conflict = ", ".join(f"{t}:{c}" for t, c in ranked[1:3]) if len(ranked) > 1 else None
        fname = "vtable" if (off == 0 and has_vtable) else f"unk_0x{off:02X}"
        c_ty = "void*" if top_ty == "void*" else top_ty
        fields.append(
            {
                "offset": f"0x{off:02X}",
                "c_decl": f"{c_ty} {fname};",
                "size": sz,
                "votes": top_n,
                "conflict": conflict,
            }
        )
        cursor = off + sz
    return fields


def synthesize_project_headers(
    ctx: TargetContext,
    *,
    class_filter: str = "",
    min_functions: int = 1,
    out_header: Path | None = None,
) -> dict[str, Any]:
    """Synthesize factual C `struct` layouts, `vtable` structs, and debug-string hints from `ctx`."""
    vtables = scan_vtables(ctx)
    vtable_classes = {vt["name"].removesuffix("_vtable") for vt in vtables}
    debug_strings = scan_debug_strings(ctx)

    grouped_votes: dict[str, dict[int, Counter[str]]] = defaultdict(lambda: defaultdict(Counter))
    group_fn_counts: Counter[str] = Counter()

    for fname, (fva, fsz) in sorted(ctx.funcs.items(), key=lambda kv: kv[1][0]):
        if fsz <= 0 or fsz > 0x4000:
            continue
        cls = fname.split("__", 1)[0] if "__" in fname else (fname.split("_", 1)[0] if "_" in fname else "")
        if not cls:
            continue
        if class_filter and cls != class_filter:
            continue
        try:
            raw = ctx.read(fva, fsz)
        except ValueError:
            continue

        if ctx.arch in ("mips", "mips_elf"):
            accs = _decode_mips_arg0_fields(raw, ctx.endian)
        elif ctx.arch in ("arm", "arm_elf"):
            accs = _decode_arm_arg0_fields(raw, ctx.thumb or (fva in ctx.thumb_addrs), ctx.endian)
        else:
            accs = _decode_ppc_arg0_fields(raw)

        if accs:
            group_fn_counts[cls] += 1
            for off, ty in accs:
                grouped_votes[cls][off][ty] += 1

    structs_out: list[dict[str, Any]] = []
    for cls, votes in sorted(grouped_votes.items()):
        if group_fn_counts[cls] < min_functions or not votes:
            continue
        fields = _build_struct_fields(votes, has_vtable=(cls in vtable_classes))
        total_sz = sum(f["size"] for f in fields)
        structs_out.append(
            {
                "name": cls,
                "functions_analyzed": group_fn_counts[cls],
                "min_size_bytes": total_sz,
                "has_vtable": cls in vtable_classes,
                "fields": fields,
            }
        )

    header_text = render_synthesized_header(structs_out, vtables, debug_strings)
    if out_header is not None:
        out_p = Path(out_header)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        out_p.write_text(header_text, encoding="utf-8")

    return {
        "arch": ctx.arch,
        "structs": structs_out,
        "vtables": vtables,
        "debug_strings": debug_strings[:40],
        "output_header": str(out_header) if out_header else None,
        "header_code": header_text,
    }


def render_synthesized_header(
    structs: list[dict[str, Any]],
    vtables: list[dict[str, Any]],
    debug_strings: list[dict[str, Any]],
) -> str:
    """Render synthesized structs, vtables, and debug-string comments as an `#ifndef`-guarded `.h` file."""
    lines = [
        "#ifndef KINTOUN_SYNTH_TYPES_H",
        "#define KINTOUN_SYNTH_TYPES_H",
        "",
        "/* Auto-synthesized from binary load/store offsets and data tables (no guessed bitfields). */",
        "typedef signed char s8;",
        "typedef short s16;",
        "typedef int s32;",
        "typedef unsigned char u8;",
        "typedef unsigned short u16;",
        "typedef unsigned int u32;",
        "typedef float f32;",
        "typedef double f64;",
        "",
    ]

    if debug_strings:
        lines.append("/* Discovered .rodata source/assert strings:")
        for ds in debug_strings[:16]:
            lines.append(f" *   {ds['addr']} [{ds['kind']}]: {ds['text'].replace('*/', '* /')}")
        lines.append(" */")
        lines.append("")

    for vt in vtables:
        vt_ident = re.sub(r"[^A-Za-z0-9_]", "_", vt["name"])
        lines.append(f"/* Vtable at {vt['addr']} ({vt['slot_count']} slots) */")
        lines.append(f"typedef struct {vt_ident} {{")
        for idx, fn in enumerate(vt["slots"]):
            slot_id = re.sub(r"[^A-Za-z0-9_]", "_", fn)
            lines.append(f"    /* +0x{idx * 4:02X} */ void (*slot_{idx:02d}_{slot_id})(void* self);")
        lines.append(f"}} {vt_ident};")
        lines.append("")

    for st in structs:
        sname = re.sub(r"[^A-Za-z0-9_]", "_", st["name"])
        lines.append(
            f"/* Inferred from {st['functions_analyzed']} function(s), observed span >= 0x{st['min_size_bytes']:X} bytes */"
        )
        lines.append(f"typedef struct {sname} {{")
        for f in st["fields"]:
            note = f" /* {f['votes']}x" + (f", alt: {f['conflict']}" if f["conflict"] else "") + " */" if f["votes"] else ""
            lines.append(f"    /* +{f['offset']} */ {f['c_decl']}{note}")
        lines.append(f"}} {sname};")
        lines.append("")

    lines.append("#endif /* KINTOUN_SYNTH_TYPES_H */")
    lines.append("")
    return "\n".join(lines)
