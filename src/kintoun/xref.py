"""Binary-wide cross-reference (`xref`), struct-field consensus, and inlined-helper detector.

Builds a fast cached index across the target binary and matched `src/` C files to surface three
high-leverage signals inside `kintoun context`:
  1. **Incoming Callers & Vtable / Jump-Table References:** Every function calling `target_fn`
     (`bl` on PPC, `jal` on MIPS, `bl`/`blx` on ARM/Thumb) plus data/vtable slots holding
     `target_fn`'s address.
  2. **Struct-Offset Type Consensus:** Aggregates `M2C_FIELD(...)`, pointer-offset casts, and
     struct definitions across already-matched `src/` files (grouped by `Class__` prefix and
     globally) so matchers know whether `+0x1C` is `s16`, `u16`, or `f32`.
  3. **Inlined-Helper Detector (Binary-Wide Sliding Window):** Hashes normalized 5-instruction
     windows across functions in the binary to detect repeated `static inline` helper sequences
     inside `target_fn` and link any already-matched C files containing the same window.
"""
from __future__ import annotations

from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import re
import struct
from typing import Any

from kintoun.arch.arm_disasm import disasm_a32, disasm_thumb16, disasm_thumb32, is_thumb32_hw1
from kintoun.search import score as ppc_score
from kintoun.targets import TargetContext, TargetFunction

_WINDOW_LEN = 5

_M2C_FIELD_RE = re.compile(
    r"M2C_FIELD\(\s*\w+\s*,\s*([A-Za-z_][\w\s\*]*?)\s*,\s*(0x[0-9A-Fa-f]+|\d+)\s*\)"
)
_PTR_CAST_OFFSET_RE = re.compile(
    r"\*\s*\(\s*([A-Za-z_][\w\s]*?)\s*\*\s*\)\s*\(\s*\(\s*(?:u8|s8|char|unsigned char)\s*\*\s*\)\s*\w+\s*\+\s*(0x[0-9A-Fa-f]+|\d+)\s*\)"
)
_INLINE_FN_RE = re.compile(
    r"(?ms)^static\s+inline\s+[A-Za-z_][\w\s\*]*?\b([A-Za-z_]\w*)\s*\([^;{}]*\)\s*\{.*?\n\}"
)


def _norm_mips_shape(w: int) -> int:
    op = (w >> 26) & 0x3F
    if op == 0:
        return (op << 6) | (w & 0x3F)
    if op == 17:
        return (op << 11) | (((w >> 21) & 0x1F) << 6) | (w & 0x3F)
    return op << 16


def _func_shapes_and_calls(
    fn_va: int,
    data: bytes,
    ctx: TargetContext,
    is_thumb: bool = False,
) -> tuple[list[int], list[Any]]:
    """Extract `(direct_callee_vas, normalized_shape_tokens)` for one function."""
    callees: list[int] = []
    shapes: list[Any] = []

    if ctx.arch in ("mips", "mips_elf"):
        fmt = "<I" if ctx.endian != "big" else ">I"
        for off in range(0, len(data) - (len(data) % 4), 4):
            w = struct.unpack_from(fmt, data, off)[0]
            if w == 0:
                continue  # skip delay-slot nops for cleaner inline-window matching
            pc = fn_va + off
            op = (w >> 26) & 0x3F
            if op == 3:  # jal
                tgt = ((pc + 4) & 0xF0000000) | ((w & 0x03FFFFFF) << 2)
                callees.append(tgt)
            shapes.append(_norm_mips_shape(w))
    elif ctx.arch in ("arm", "arm_elf"):
        if is_thumb:
            off = 0
            end = len(data)
            while off + 2 <= end:
                hw1 = struct.unpack_from("<H", data, off)[0]
                pc = fn_va + off
                if is_thumb32_hw1(hw1) and off + 4 <= end:
                    hw2 = struct.unpack_from("<H", data, off + 2)[0]
                    mn, ops = disasm_thumb32(hw1, hw2, pc)
                    if mn in ("bl", "blx"):
                        m = re.search(r"0x([0-9a-fA-F]+)", ops)
                        if m:
                            callees.append(int(m.group(1), 16) & ~1)
                    shapes.append(mn)
                    off += 4
                else:
                    mn, _ops = disasm_thumb16(hw1, pc)
                    if mn != "nop" and not mn.startswith("."):
                        shapes.append(mn)
                    off += 2
        else:
            fmt = "<I" if ctx.endian != "big" else ">I"
            for off in range(0, len(data) - (len(data) % 4), 4):
                w = struct.unpack_from(fmt, data, off)[0]
                pc = fn_va + off
                mn, ops = disasm_a32(w, pc)
                if mn.startswith(("bl", "blx")):
                    m = re.search(r"0x([0-9a-fA-F]+)", ops)
                    if m:
                        callees.append(int(m.group(1), 16) & ~1)
                shapes.append(mn)
    else:  # PowerPC (`ppc_elf`)
        for off in range(0, len(data) - (len(data) % 4), 4):
            w = struct.unpack_from(">I", data, off)[0]
            pc = fn_va + off
            op = (w >> 26) & 0x3F
            if op == 18 and (w & 1):
                li = w & 0x03FFFFFC
                if li & 0x02000000:
                    li -= 0x04000000
                tgt = (li if (w & 2) else (pc + li)) & 0xFFFFFFFF
                callees.append(tgt)
            shapes.append(ppc_score.shape(w))

    return callees, shapes


def _window_hash(tokens: list[Any]) -> str:
    return hashlib.sha1(repr(tokens).encode("utf-8")).hexdigest()[:12]


_MEM_INDEX_CACHE: dict[str, dict[str, Any]] = {}


def get_binary_xref_index(ctx: TargetContext, cache_dir: Path | None = None) -> dict[str, Any]:
    """Build or load cached binary xref + sliding-window index for `ctx`."""
    if not ctx.funcs:
        return {"callers": {}, "vtable_refs": {}, "window_owners": {}}

    sig_src = f"{ctx.arch}:{len(ctx.funcs)}:{len(ctx._image)}:{sorted(ctx.funcs.items())[:8]}"
    idx_key = hashlib.sha1(sig_src.encode("utf-8")).hexdigest()[:16]
    if idx_key in _MEM_INDEX_CACHE:
        return _MEM_INDEX_CACHE[idx_key]

    disk_path = (Path(cache_dir) / f"xref_{idx_key}.json") if cache_dir else None
    if disk_path and disk_path.is_file():
        try:
            loaded = json.loads(disk_path.read_text(encoding="utf-8"))
            _MEM_INDEX_CACHE[idx_key] = loaded
            return loaded
        except Exception:
            pass

    callers: dict[str, list[str]] = defaultdict(list)
    vtable_refs: dict[str, list[str]] = defaultdict(list)
    window_owners: dict[str, list[str]] = defaultdict(list)

    # Cap full sliding-window indexing cleanly so 10,000-function binaries stay sub-second
    fn_items = sorted(ctx.funcs.items(), key=lambda kv: kv[1][0])
    for fname, (fva, fsz) in fn_items:
        if fsz <= 0 or fsz > 0x4000:
            continue
        try:
            raw = ctx.read(fva, fsz)
        except ValueError:
            continue
        is_th = ctx.thumb or (fva in ctx.thumb_addrs)
        c_vas, shapes = _func_shapes_and_calls(fva, raw, ctx, is_thumb=is_th)
        for cva in c_vas:
            key = f"0x{cva:08X}"
            lst = callers[key]
            if fname not in lst and len(lst) < 24:
                lst.append(fname)

        # Record unique 5-instruction normalized windows per function (skip trivial tiny functions)
        if len(shapes) >= _WINDOW_LEN + 2:
            seen_w: set[str] = set()
            for i in range(0, len(shapes) - _WINDOW_LEN + 1):
                wh = _window_hash(shapes[i : i + _WINDOW_LEN])
                if wh in seen_w:
                    continue
                seen_w.add(wh)
                owners = window_owners[wh]
                if len(owners) < 32:
                    owners.append(fname)

    # Scan data segments for vtable / jump-table / callback pointers to known functions
    known_vas = set(ctx.by_addr.keys())
    if known_vas and ctx.data_segments:
        fmt = "<I" if (ctx.arch in ("mips", "mips_elf", "arm", "arm_elf") and ctx.endian != "big") else ">I"
        is_arm = ctx.arch in ("arm", "arm_elf")
        for seg_va, seg_bytes in ctx.data_segments:
            for off in range(0, len(seg_bytes) - 3, 4):
                ptr = struct.unpack_from(fmt, seg_bytes, off)[0]
                lookup = (ptr & ~1) if is_arm else ptr
                if lookup in known_vas:
                    slot_va = seg_va + off
                    obj_name = ctx.objs.get(slot_va, (f"0x{slot_va:08X}", 4))[0]
                    k = f"0x{lookup:08X}"
                    refs = vtable_refs[k]
                    if obj_name not in refs and len(refs) < 16:
                        refs.append(obj_name)

    # Keep only multi-function windows (`>= 3` functions share the window -> candidate inlined helper)
    hot_windows = {wh: owners for wh, owners in window_owners.items() if len(owners) >= 3}
    built = {
        "callers": dict(callers),
        "vtable_refs": dict(vtable_refs),
        "window_owners": hot_windows,
    }
    if len(_MEM_INDEX_CACHE) < 8:
        _MEM_INDEX_CACHE[idx_key] = built
    if disk_path:
        try:
            disk_path.parent.mkdir(parents=True, exist_ok=True)
            tmp = disk_path.with_suffix(".tmp")
            tmp.write_text(json.dumps(built), encoding="utf-8")
            tmp.replace(disk_path)
        except OSError:
            pass
    return built


def scan_corpus_consensus(
    src_dir: Path | None,
    target_class: str = "",
    max_files: int = 300,
) -> dict[str, Any]:
    """Mine matched `src/` C files for struct-field offset consensus and `static inline` helpers."""
    if src_dir is None or not src_dir.is_dir():
        return {"class_fields": {}, "global_fields": {}, "inline_helpers": [], "matched_files": {}}

    class_votes: dict[int, Counter[str]] = defaultdict(Counter)
    global_votes: dict[int, Counter[str]] = defaultdict(Counter)
    inlines: list[dict[str, str]] = []
    seen_inlines: set[str] = set()
    matched_files: dict[str, str] = {}

    for cfile in sorted(src_dir.rglob("*.c"))[:max_files]:
        try:
            txt = cfile.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        stem = cfile.stem
        parent = cfile.parent.name
        fn_guess = f"{parent}__{stem}" if parent and parent != "src" else stem
        matched_files[fn_guess] = str(cfile)
        matched_files[stem] = str(cfile)
        is_same_class = bool(target_class) and (parent == target_class or stem.startswith(target_class + "__"))

        for rx in (_M2C_FIELD_RE, _PTR_CAST_OFFSET_RE):
            for m in rx.finditer(txt):
                raw_ty = " ".join(m.group(1).replace("*", "").split())
                off = int(m.group(2), 0)
                if raw_ty:
                    global_votes[off][raw_ty] += 1
                    if is_same_class:
                        class_votes[off][raw_ty] += 1

        for im in _INLINE_FN_RE.finditer(txt):
            iname = im.group(1)
            if iname not in seen_inlines and len(inlines) < 16:
                seen_inlines.add(iname)
                inlines.append({"name": iname, "file": cfile.name, "code": im.group(0)[:400]})

    def _summarize(votes: dict[int, Counter[str]]) -> dict[str, str]:
        out: dict[str, str] = {}
        for off in sorted(votes)[:24]:
            top_ty, count = votes[off].most_common(1)[0]
            out[f"+0x{off:X}"] = f"{top_ty} ({count}x)"
        return out

    return {
        "class_fields": _summarize(class_votes),
        "global_fields": _summarize(global_votes),
        "inline_helpers": inlines,
        "matched_files": matched_files,
    }


def analyze_function_xrefs_and_inlines(
    target_fn: TargetFunction,
    ctx: TargetContext,
    *,
    src_dir: Path | None = None,
    cache_dir: Path | None = None,
) -> dict[str, Any]:
    """Return incoming callers, vtable refs, struct-offset consensus, and inlined-helper candidates."""
    idx = get_binary_xref_index(ctx, cache_dir=cache_dir)
    addr_key = f"0x{target_fn.va:08X}"
    cls_prefix = target_fn.name.split("__", 1)[0] if "__" in target_fn.name else ""
    corpus = scan_corpus_consensus(src_dir, target_class=cls_prefix)

    # Detect repeated 5-instruction normalized windows inside `target_fn`
    _c, shapes = _func_shapes_and_calls(
        target_fn.va,
        target_fn.data,
        ctx,
        is_thumb=target_fn.is_thumb,
    )
    inlined_candidates: list[dict[str, Any]] = []
    hot_windows = idx.get("window_owners") or {}
    matched_map = corpus["matched_files"]
    seen_wh: set[str] = set()

    for i in range(0, max(0, len(shapes) - _WINDOW_LEN + 1)):
        wh = _window_hash(shapes[i : i + _WINDOW_LEN])
        if wh in seen_wh or wh not in hot_windows:
            continue
        seen_wh.add(wh)
        peers = [fn for fn in hot_windows[wh] if fn != target_fn.name]
        if len(peers) < 2:
            continue
        matched_peers = [fn for fn in peers if fn in matched_map]
        inlined_candidates.append(
            {
                "insn_index_range": f"{i}..{i + _WINDOW_LEN - 1}",
                "shared_by_functions": len(peers) + 1,
                "sample_peers": peers[:5],
                "matched_peers": matched_peers[:3],
            }
        )
        if len(inlined_candidates) >= 6:
            break

    return {
        "incoming_callers": idx.get("callers", {}).get(addr_key, []),
        "vtable_or_data_refs": idx.get("vtable_refs", {}).get(addr_key, []),
        "field_offset_consensus": corpus["class_fields"] or corpus["global_fields"],
        "inlined_helper_candidates": inlined_candidates,
        "corpus_inline_defs": corpus["inline_helpers"][:4],
    }
