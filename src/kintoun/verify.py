"""Strict matching-C verifier for Kintoun."""
from __future__ import annotations

import hashlib
from pathlib import Path
import re
import tempfile
from typing import Any

from kintoun.arch.elf import Object
from kintoun.arch.ppc_elf import compare_bytes, link_function
from kintoun.compiler import CompilerBackend, compile_failure
from kintoun.search import repairs as repair_mod
from kintoun.search import score as score_mod
from kintoun.targets import TargetContext, TargetFunction

VERIFIER_VERSION = "kintoun-strict-v1"

_ASM_CHEAT_RE = re.compile(
    r"\b(?:asm|__asm__|__asm|GLOBAL_ASM|opcode)\b|"
    r"__attribute__\s*\(\(\s*naked\b|"
    r"\.(?:long|4byte|word|byte)\b|"
    r"#\s*pragma\s*(?:asm|inline_asm)\b",
    re.I,
)


def real_c_violation(source: str) -> str | None:
    """Return the first disallowed inline-asm / raw-data construct, or None if clean C."""
    clean = re.sub(r"/\*.*?\*/|//[^\n]*", "", source, flags=re.S)
    match = _ASM_CHEAT_RE.search(clean)
    return match.group(0) if match else None


def verify_source(
    source_text: str,
    target_fn: TargetFunction,
    ctx: TargetContext,
    compiler: CompilerBackend,
    *,
    lines: int = 24,
    forbid_asm: bool = True,
    partial_link: bool = False,
    placement_cache: dict[Any, Any] | None = None,
    _include_words: bool = False,
) -> dict[str, Any]:
    """Compile C source, relocate against target, and return strict byte-match & score report."""
    if ctx.arch in ("mips", "mips_elf"):
        from kintoun.verify_mips import verify_mips_source

        return verify_mips_source(
            source_text,
            target_fn,
            ctx,
            compiler,
            lines=lines,
            forbid_asm=forbid_asm,
            partial_link=partial_link,
            placement_cache=placement_cache,
        )
    if ctx.arch in ("arm", "arm_elf"):
        from kintoun.verify_arm import verify_arm_source

        return verify_arm_source(
            source_text,
            target_fn,
            ctx,
            compiler,
            lines=lines,
            forbid_asm=forbid_asm,
            partial_link=partial_link,
            placement_cache=placement_cache,
        )
    lines = max(0, min(int(lines), 100))
    if target_fn.size <= 0 or target_fn.size % 4:
        raise ValueError("target function must have a nonempty, 4-byte-aligned extent")

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
        elf = Object(obj_bytes)
    except ValueError as exc:
        result["status"] = "invalid_object"
        result["error"] = str(exc)
        return result

    defined = [
        sym
        for table in elf.tables.values()
        for sym in table
        if (sym.info & 15) == 2 and 0 < sym.section < len(elf.sections) and sym.size > 0
    ]
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
        result["error"] = "compiled function extent is not 4-byte aligned"
        return result

    ours_raw = section.data[start : start + length]
    ours_words = score_mod.words_be(ours_raw)
    target_words = score_mod.words_be(target_fn.data)
    sc = score_mod.score(ours_words, target_words)
    result["search"] = {
        "normalized_pct": sc.pct,
        "aligned_pct": sc.apct,
        "total": sc.total,
        "mism": sc.mism,
        "hints": sc.hints,
        "diff": sc.diff(lines) if lines else "",
    }

    # Auto-bind hex-addressed decomp externs (`lbl_80XXXXXX`, `fn_80XXXXXX`, `D_80XXXXXX`) not yet in `symbols.txt`
    ext_map = ctx.external
    by_addr = ctx.by_addr
    objs = ctx.objs
    hex_syms = set(re.findall(r"\b((?:lbl|fn|func|D)_[0-9A-Fa-f]{8})\b", source_text))
    missing_hex = [s for s in hex_syms if s not in ext_map]
    if missing_hex:
        ext_map = dict(ctx.external)
        by_addr = dict(ctx.by_addr)
        objs = dict(ctx.objs)
        for sname in missing_hex:
            addr = int(sname.split("_", 1)[1], 16)
            ext_map[sname] = addr
            if sname.startswith(("fn_", "func_")):
                by_addr.setdefault(addr, sname)
            else:
                objs.setdefault(addr, (sname, 4))

    evidence: dict[str, Any] = {}
    try:
        linked, evidence, _unknown = link_function(
            elf=elf,
            function=fn_sym,
            va=target_fn.va,
            target_bytes=target_fn.data,
            external=ext_map,
            function_addresses=by_addr,
            object_addresses=objs,
            data_segments=ctx.data_segments,
            read_mem=ctx.read,
            sda_r13=ctx.sda_r13,
            sda_r2=ctx.sda_r2,
            explicit_layout=ctx.layout_for(target_fn.name),
            partial=partial_link,
            placement_cache=placement_cache,
        )
        cmp_res = compare_bytes(linked, target_fn.data)
        result.update(cmp_res)
        linked_words = score_mod.words_be(linked)
        if _include_words:
            result["_ours_words"] = linked_words
            result["_ops"] = getattr(sc, "ops", None)
        if not result["verified"]:
            if lines and not result["search"]["diff"] and len(linked_words) == len(target_words):
                from kintoun.arch.ppc_disasm import disasm_ppc_word

                raw_diffs: list[str] = []
                for idx_w, (ow, tw) in enumerate(zip(linked_words, target_words)):
                    if ow != tw:
                        pc = target_fn.va + idx_w * 4
                        omn, oops = disasm_ppc_word(ow, pc)
                        tmn, tops = disasm_ppc_word(tw, pc)
                        raw_diffs.append(
                            f"! {pc:08X}: {omn} {oops}".rstrip()
                            + f"  !=  {tmn} {tops}".rstrip()
                            + f"  (0x{ow:08X} vs 0x{tw:08X})"
                        )
                        if len(raw_diffs) >= lines:
                            break
                result["search"]["diff"] = "\n".join(raw_diffs)
            all_repairs = repair_mod.hypotheses(
                linked_words,
                target_words,
                source_text,
                target_fn.va,
                by_addr,
                objs,
                ctx.sda_r13,
                ctx.sda_r2,
                getattr(sc, "ops", None),
                limit=64,
            )
            result["repairs"] = all_repairs[:8]
        else:
            result["repairs"] = []
        result["status"] = "verified" if result["verified"] else "mismatch"
    except ValueError as exc:
        if _include_words:
            result["_ours_words"] = ours_words
            result["_ops"] = getattr(sc, "ops", None)
        result.update(
            error=str(exc),
            status="unresolved",
            ours_bytes=length,
            target_bytes=target_fn.size,
        )

    result["placements"] = evidence
    return result
