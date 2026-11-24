"""Dedicated strict matching-C verifier for ARM/Thumb ELF32 targets (`agbcc`, `arm-none-eabi-gcc`, `mwccarm`, `armcc`)."""
from __future__ import annotations

import hashlib
from pathlib import Path
import tempfile
from typing import Any

from kintoun.arch.arm_elf import ArmObject, compare_arm_bytes, link_arm_function
from kintoun.compiler import CompilerBackend, compile_failure
from kintoun.search import arm_repairs, arm_score
from kintoun.targets import TargetContext, TargetFunction
from kintoun.verify import VERIFIER_VERSION, real_c_violation


def verify_arm_source(
    source_text: str,
    target_fn: TargetFunction,
    ctx: TargetContext,
    compiler: CompilerBackend,
    *,
    lines: int = 24,
    forbid_asm: bool = True,
    partial_link: bool = False,
    placement_cache: dict[Any, Any] | None = None,
) -> dict[str, Any]:
    """Compile C source to an ARM/Thumb ELF32 object, relocate strictly, and score against `target_fn`."""
    lines = max(0, min(int(lines), 100))
    align_req = 2 if (target_fn.is_thumb or ctx.thumb) else 4
    if target_fn.size <= 0 or target_fn.size % align_req:
        raise ValueError(f"ARM/Thumb target function must have a nonempty, {align_req}-byte-aligned extent")

    if forbid_asm:
        bad = real_c_violation(source_text)
        if bad:
            return {
                "verified": False,
                "status": "invalid_candidate",
                "name": target_fn.name,
                "addr": f"0x{target_fn.va:08X}",
                "error": f"REAL C ONLY: found '{bad}'",
                "verifier": VERIFIER_VERSION,
            }

    raw_bytes = source_text.encode("utf-8")
    result: dict[str, Any] = {
        "verified": False,
        "name": target_fn.name,
        "addr": f"0x{target_fn.va:08X}",
        "candidate_sha256": hashlib.sha256(raw_bytes).hexdigest(),
        "verifier": VERIFIER_VERSION,
    }

    with tempfile.TemporaryDirectory(prefix="kintoun_") as tmp:
        src_path = Path(tmp) / "candidate.c"
        obj_path = Path(tmp) / "candidate.o"
        src_path.write_bytes(raw_bytes)
        compiled = compiler.compile_c(src_path, obj_path)
        if compiled.returncode != 0 or not obj_path.is_file():
            result["status"] = "compile_error"
            result["error"] = "compile failed: " + compile_failure(compiled.stderr or compiled.stdout)
            return result
        obj_bytes = obj_path.read_bytes()

    try:
        elf = ArmObject(obj_bytes)
    except ValueError as exc:
        result["status"] = "invalid_object"
        result["error"] = str(exc)
        return result

    if ctx.endian and elf.endian != ctx.endian:
        result["status"] = "invalid_object"
        result["error"] = f"ARM endianness mismatch: candidate is {elf.endian}-endian, target is {ctx.endian}-endian"
        return result

    defined = elf.defined_functions()
    matches = [s for s in defined if s.name == target_fn.name]
    if len(matches) == 1:
        fn_sym = matches[0]
    elif len(defined) == 1:
        fn_sym = defined[0]
        result["definition_identity"] = "sole compiled function bound to target"
    else:
        result["status"] = "error"
        result["error"] = f"expected function '{target_fn.name}'; found {[s.name for s in defined]}"
        return result

    result["defined_name"] = fn_sym.name
    section = elf.sections[fn_sym.section]
    start, length = fn_sym.offset, fn_sym.size
    cand_align = 2 if fn_sym.is_thumb else 4
    if start % cand_align or length % 2:
        result["status"] = "error"
        result["error"] = "compiled ARM/Thumb function extent is misaligned"
        return result

    ours_raw = section.data[start : start + length]
    ours_intervals = elf.mapping_intervals(
        fn_sym.section,
        start,
        start + length,
        default_mode="t" if fn_sym.is_thumb else "a",
    )
    ours_reloc_offs = {
        rel.offset - start
        for rel in elf.relocations(fn_sym.section)
        if start <= rel.offset < start + length
    }
    target_intervals = list(target_fn.intervals) if target_fn.intervals else None
    target_reloc_offs = set(target_fn.reloc_offsets)

    ours_items = arm_score.tokenize_arm(
        ours_raw,
        intervals=ours_intervals,
        default_thumb=fn_sym.is_thumb,
        data_endian=elf.endian,
        insn_endian=elf.insn_endian,
    )
    target_items = arm_score.tokenize_arm(
        target_fn.data,
        intervals=target_intervals,
        default_thumb=target_fn.is_thumb or ctx.thumb,
        data_endian=ctx.endian or elf.endian,
        insn_endian=elf.insn_endian,
    )
    sc = arm_score.score_arm(
        ours_items,
        target_items,
        ours_reloc_offs=ours_reloc_offs,
        target_reloc_offs=target_reloc_offs,
    )
    result["search"] = {
        "normalized_pct": sc.pct,
        "aligned_pct": sc.apct,
        "total": sc.total,
        "mism": sc.mism,
        "hints": sc.hints,
        "diff": sc.diff(lines, base_va=target_fn.va) if lines else "",
    }
    in_search = placement_cache is not None
    if in_search:
        result["_ours_intervals"] = [list(iv) for iv in ours_intervals]
        result["_cand_thumb"] = fn_sym.is_thumb

    evidence: dict[str, Any] = {}
    try:
        linked, evidence, _unknown = link_arm_function(
            elf=elf,
            function=fn_sym,
            va=target_fn.va,
            target_bytes=target_fn.data,
            external=ctx.external,
            function_addresses=ctx.by_addr,
            object_addresses=ctx.objs,
            data_segments=ctx.data_segments,
            read_mem=ctx.read,
            thumb_addrs=ctx.thumb_addrs,
            sb=ctx.sb,
            explicit_layout=ctx.layout_for(target_fn.name),
            partial=partial_link,
            placement_cache=placement_cache,
            allow_hex_fallback=ctx.allow_hex_fallback,
        )
        unit_offs = [it.offset for it in target_items]
        cmp_res = compare_arm_bytes(linked, target_fn.data, unit_offsets=unit_offs)
        result.update(cmp_res)
        if in_search:
            result["_linked_hex"] = linked.hex()
            if _unknown:
                result["_unresolved"] = {str(k): v for k, v in _unknown.items()}
        if not result["verified"]:
            linked_items = arm_score.tokenize_arm(
                linked,
                intervals=ours_intervals,
                default_thumb=fn_sym.is_thumb,
                data_endian=elf.endian,
                insn_endian=elf.insn_endian,
            )
            sc_linked = arm_score.score_arm(
                linked_items,
                target_items,
                ours_reloc_offs=ours_reloc_offs,
                target_reloc_offs=target_reloc_offs,
            )
            result["search"] = {
                "normalized_pct": sc_linked.pct,
                "aligned_pct": sc_linked.apct,
                "total": sc_linked.total,
                "mism": sc_linked.mism,
                "hints": sc_linked.hints,
                "diff": sc_linked.diff(lines, base_va=target_fn.va) if lines else "",
            }
            all_repairs = arm_repairs.hypotheses(
                linked_items,
                target_items,
                source_text,
                target_fn.va,
                ctx.by_addr,
                ctx.objs,
                ops=sc_linked.ops,
                limit=64,
            )
            result["repairs"] = all_repairs[:8]
        else:
            result["search"] = {
                "normalized_pct": 100.0,
                "aligned_pct": 100.0,
                "total": 0,
                "mism": 0,
                "hints": [],
                "diff": "",
            }
            result["repairs"] = []
        result["status"] = "verified" if result["verified"] else "mismatch"
    except ValueError as exc:
        result.update(
            error=str(exc),
            status="unresolved",
            ours_bytes=length,
            target_bytes=target_fn.size,
        )
        if in_search:
            try:
                p_linked, _, p_unknown = link_arm_function(
                    elf=elf,
                    function=fn_sym,
                    va=target_fn.va,
                    target_bytes=target_fn.data,
                    external=ctx.external,
                    function_addresses=ctx.by_addr,
                    object_addresses=ctx.objs,
                    data_segments=ctx.data_segments,
                    read_mem=ctx.read,
                    thumb_addrs=ctx.thumb_addrs,
                    sb=ctx.sb,
                    explicit_layout=ctx.layout_for(target_fn.name),
                    partial=True,
                    placement_cache=None,
                    allow_hex_fallback=ctx.allow_hex_fallback,
                )
                result["_linked_hex"] = p_linked.hex()
                result["_unresolved"] = {str(k): v for k, v in p_unknown.items()}
                p_items = arm_score.tokenize_arm(
                    p_linked,
                    intervals=ours_intervals,
                    default_thumb=fn_sym.is_thumb,
                    data_endian=elf.endian,
                    insn_endian=elf.insn_endian,
                )
                sc_p = arm_score.score_arm(
                    p_items,
                    target_items,
                    ours_reloc_offs=ours_reloc_offs,
                    target_reloc_offs=target_reloc_offs,
                    with_hints=False,
                )
                result["repairs"] = arm_repairs.hypotheses(
                    p_items,
                    target_items,
                    source_text,
                    target_fn.va,
                    ctx.by_addr,
                    ctx.objs,
                    ops=sc_p.ops,
                    limit=16,
                )[:8]
            except Exception:
                result["_linked_hex"] = ours_raw.hex()

    result["placements"] = evidence
    return result
