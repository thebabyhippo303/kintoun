"""Dedicated strict matching-C verifier for MIPS ELF32 targets (`ee-gcc`, `mwccps2`, `psp-gcc`, `mwccpsp`, `pspsnc`, `mips-gcc`)."""
from __future__ import annotations

import hashlib
from pathlib import Path
import tempfile
from typing import Any

from kintoun.arch.mips_elf import MipsObject, compare_mips_bytes, link_mips_function
from kintoun.compiler import CompilerBackend, compile_failure
from kintoun.search import mips_repairs, mips_score
from kintoun.targets import TargetContext, TargetFunction
from kintoun.verify import VERIFIER_VERSION, real_c_violation


def verify_mips_source(
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
    """Compile C source to a MIPS ELF32 object, relocate strictly, and score against `target_fn`."""
    lines = max(0, min(int(lines), 100))
    if target_fn.size <= 0 or target_fn.size % 4:
        raise ValueError("MIPS target function must have a nonempty, 4-byte-aligned extent")

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
        elf = MipsObject(obj_bytes)
    except ValueError as exc:
        result["status"] = "invalid_object"
        result["error"] = str(exc)
        return result

    if ctx.endian and elf.endian != ctx.endian:
        result["status"] = "invalid_object"
        result["error"] = f"MIPS endianness mismatch: candidate is {elf.endian}-endian, target is {ctx.endian}-endian"
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
    start, length = fn_sym.value, fn_sym.size
    if start % 4 or length % 4:
        result["status"] = "error"
        result["error"] = "compiled MIPS function extent is not 4-byte aligned"
        return result

    endian = ctx.endian or elf.endian
    ours_raw = section.data[start : start + length]
    ours_words = mips_score.words_mips(ours_raw, endian)
    target_words = mips_score.words_mips(target_fn.data, endian)
    sc = mips_score.score_mips(ours_words, target_words)
    result["search"] = {
        "normalized_pct": sc.pct,
        "aligned_pct": sc.apct,
        "total": sc.total,
        "mism": sc.mism,
        "hints": sc.hints,
        "diff": sc.diff(lines, base_va=target_fn.va) if lines else "",
    }
    in_search = placement_cache is not None
    if in_search and sc.delay_swaps:
        result["_delay_swaps"] = sc.delay_swaps

    evidence: dict[str, Any] = {}
    try:
        linked, evidence, _unknown = link_mips_function(
            elf=elf,
            function=fn_sym,
            va=target_fn.va,
            target_bytes=target_fn.data,
            external=ctx.external,
            function_addresses=ctx.by_addr,
            object_addresses=ctx.objs,
            data_segments=ctx.data_segments,
            read_mem=ctx.read,
            gp=ctx.gp,
            explicit_layout=ctx.layout_for(target_fn.name),
            partial=partial_link,
            placement_cache=placement_cache,
            allow_hex_fallback=ctx.allow_hex_fallback,
        )
        cmp_res = compare_mips_bytes(linked, target_fn.data)
        result.update(cmp_res)
        linked_words = mips_score.words_mips(linked, endian)
        if in_search:
            result["_ours_words"] = linked_words
            if _unknown:
                result["_unresolved"] = {str(k): v for k, v in _unknown.items()}
        if not result["verified"]:
            sc_linked = mips_score.score_mips(linked_words, target_words)
            diff_txt = sc_linked.diff(lines, base_va=target_fn.va) if lines else ""
            if lines and not diff_txt and len(linked_words) == len(target_words):
                from kintoun.arch.mips_disasm import disasm_mips_word

                raw_diffs: list[str] = []
                for idx_w, (ow, tw) in enumerate(zip(linked_words, target_words)):
                    if ow != tw:
                        pc = target_fn.va + idx_w * 4
                        omn, oops = disasm_mips_word(ow, pc)
                        tmn, tops = disasm_mips_word(tw, pc)
                        raw_diffs.append(
                            f"! {pc:08X}: {omn} {oops}".rstrip()
                            + f"  !=  {tmn} {tops}".rstrip()
                            + f"  (0x{ow:08X} vs 0x{tw:08X})"
                        )
                        if len(raw_diffs) >= lines:
                            break
                diff_txt = "\n".join(raw_diffs)
            result["search"] = {
                "normalized_pct": sc_linked.pct,
                "aligned_pct": sc_linked.apct,
                "total": sc_linked.total,
                "mism": sc_linked.mism,
                "hints": sc_linked.hints,
                "diff": diff_txt,
            }
            if in_search and sc_linked.delay_swaps:
                result["_delay_swaps"] = sc_linked.delay_swaps
            all_repairs = mips_repairs.hypotheses(
                linked_words,
                target_words,
                source_text,
                target_fn.va,
                ctx.by_addr,
                ctx.objs,
                gp=ctx.gp,
                ops=sc_linked.ops,
                delay_swaps=sc_linked.delay_swaps,
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
                p_linked, _, p_unknown = link_mips_function(
                    elf=elf,
                    function=fn_sym,
                    va=target_fn.va,
                    target_bytes=target_fn.data,
                    external=ctx.external,
                    function_addresses=ctx.by_addr,
                    object_addresses=ctx.objs,
                    data_segments=ctx.data_segments,
                    read_mem=ctx.read,
                    gp=ctx.gp,
                    explicit_layout=ctx.layout_for(target_fn.name),
                    partial=True,
                    placement_cache=None,
                    allow_hex_fallback=ctx.allow_hex_fallback,
                )
                p_words = mips_score.words_mips(p_linked, endian)
                result["_ours_words"] = p_words
                result["_unresolved"] = {str(k): v for k, v in p_unknown.items()}
                sc_p = mips_score.score_mips(p_words, target_words, with_hints=False)
                result["repairs"] = mips_repairs.hypotheses(
                    p_words,
                    target_words,
                    source_text,
                    target_fn.va,
                    ctx.by_addr,
                    ctx.objs,
                    gp=ctx.gp,
                    ops=sc_p.ops,
                    delay_swaps=sc.delay_swaps,
                    limit=16,
                )[:8]
            except Exception:
                result["_ours_words"] = ours_words

    result["placements"] = evidence
    return result
