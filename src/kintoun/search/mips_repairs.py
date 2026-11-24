"""MIPS instruction-backed C repair hypotheses.

Covers `callee`, `global` (`$gp` small-data and `lui`+`%lo` pairs), `literal`
(`li`/`addiu`, `ori`, `lui`, and 32-bit `lui`+`ori`/`addiu` pairs), `field_offset`,
`frame`/`$sp`, `delay_slot`, and `gp_small_data` addressing mismatches.
"""
from __future__ import annotations

import re
from typing import Any

from kintoun.arch.mips_disasm import GPR_NAMES, disasm_mips_word
from kintoun.arch.mips_elf import symbol_name_mips
from kintoun.search.mips_score import is_branch_or_jump_mips
from kintoun.search.repairs import immediate_edit, signed

_MEM_OPS = {
    30, 31, 32, 33, 34, 35, 36, 37, 38, 39,
    40, 41, 42, 43, 44, 45, 46, 48, 49, 53, 55, 56, 57, 61, 63,
}


def _jal_target(word: int, pc: int) -> int:
    return (((pc + 4) & 0xF0000000) | ((word & 0x03FFFFFF) << 2)) & 0xFFFFFFFF


def _signed_immediate_edit(source: str, old: int, new: int) -> tuple[list[dict[str, Any]], dict[str, str] | None]:
    """Locate positive or negative integer literals in `source` and build a one-site edit if unique."""
    if old >= 0:
        return immediate_edit(source, old, new)
    mag = -old
    masked = re.sub(
        r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'',
        lambda m: "".join("\n" if c == "\n" else " " for c in m[0]),
        source,
        flags=re.S,
    )
    pattern = r"-\s*(?:0[xX][\da-fA-F]+|0[0-7]*|[1-9]\d*)[uUlL]*(?![\w.])"
    locations = []
    for match in re.finditer(pattern, masked):
        raw_num = re.sub(r"[uUlL]+$", "", match[0].lstrip("-").strip())
        base = 16 if raw_num.lower().startswith("0x") else (8 if len(raw_num) > 1 and raw_num[0] == "0" else 10)
        if int(raw_num, base) != mag:
            continue
        start = source.rfind("\n", 0, match.start()) + 1
        end = source.find("\n", match.end())
        end = len(source) if end < 0 else end
        if source[start:end].lstrip().startswith("#"):
            continue
        locations.append(
            {
                "line": source.count("\n", 0, start) + 1,
                "text": source[start:end],
                "start": match.start() - start,
                "end": match.end() - start,
            }
        )
    public = [{"line": it["line"], "text": it["text"]} for it in locations[:8]]
    if len(locations) != 1:
        return public, None
    loc = locations[0]
    line = loc["text"]
    if source.count(line) != 1:
        return public, None
    replacement = str(new)
    return public, {"old": line, "new": line[: loc["start"]] + replacement + line[loc["end"] :]}


def _lui_pairs(words: list[int]) -> dict[int, tuple[int, int, str]]:
    """Map index `k` of the second instruction in a `lui rt, hi` + `ori/addiu/mem` pair to `(lui_idx, full_u32, kind)`."""
    active: dict[int, tuple[int, int]] = {}  # reg -> (idx, hi16)
    pairs: dict[int, tuple[int, int, str]] = {}
    for k, w in enumerate(words):
        op = (w >> 26) & 0x3F
        rs, rt = (w >> 21) & 0x1F, (w >> 16) & 0x1F
        uimm = w & 0xFFFF
        simm = signed(uimm, 16)
        if op == 15 and rs == 0 and rt != 0:
            active[rt] = (k, uimm)
            continue
        if rs in active:
            lui_idx, hi16 = active[rs]
            if op == 13:  # ori rt, rs, lo16 -> unsigned 32-bit literal
                full = ((hi16 << 16) | uimm) & 0xFFFFFFFF
                pairs[k] = (lui_idx, full, "ori")
                if rt in active and rt != rs:
                    active.pop(rt, None)
                if rt == rs:
                    active.pop(rs, None)
                continue
            if op in (9, 25) or op in _MEM_OPS:  # addiu / load / store `%lo`
                full = ((hi16 << 16) + simm) & 0xFFFFFFFF
                pairs[k] = (lui_idx, full, "lo_signed")
                if op in (9, 25) and rt == rs:
                    active.pop(rs, None)
                continue
        # Invalidate clobbered destination register
        if op == 0 and (w & 0x3F) not in (8, 12, 13, 15, 26, 27):
            active.pop((w >> 11) & 0x1F, None)
        elif op in (8, 9, 10, 11, 12, 13, 14, 24, 25) or op in _MEM_OPS:
            if op not in (40, 41, 42, 43, 44, 45, 46, 57, 61, 63, 31):
                active.pop(rt, None)
    return pairs


def hypotheses(
    ours: list[int],
    target: list[int],
    source: str,
    va: int,
    symbols: dict[int, str],
    objects: dict[int, tuple[str, int]],
    gp: int = 0,
    ops: list[tuple[str, int, int, int, int]] | None = None,
    delay_swaps: list[dict[str, Any]] | None = None,
    limit: int = 8,
) -> list[dict[str, Any]]:
    """Build prioritized, instruction-backed MIPS repair hypotheses from relocated word streams."""
    pairs: list[tuple[int, int]] = []
    if ops:
        for tag, i1, i2, j1, j2 in ops:
            if tag not in ("equal", "replace"):
                continue
            pairs.extend((i1 + k, j1 + k) for k in range(min(i2 - i1, j2 - j1)))
    else:
        pairs = list(zip(range(len(ours)), range(len(target))))

    ours_lui = _lui_pairs(ours)
    targ_lui = _lui_pairs(target)
    consumed_lui_o = {v[0] for v in ours_lui.values()}
    consumed_lui_t = {v[0] for v in targ_lui.values()}

    out: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()

    def _emit(rep: dict[str, Any]) -> None:
        key = (rep["category"], str(rep.get("ours")), str(rep.get("target")))
        if key not in seen:
            seen.add(key)
            out.append(rep)

    # Delay-slot hypotheses
    for ds in delay_swaps or []:
        ob, tb = int(ds["ours_branch"]), int(ds["target_branch"])
        kind = str(ds["kind"])
        t_slot = " ".join(x for x in disasm_mips_word(target[min(tb + 1, len(target) - 1)], va + (tb + 1) * 4) if x)
        o_slot = " ".join(x for x in disasm_mips_word(ours[min(ob + 1, len(ours) - 1)], va + (ob + 1) * 4) if x)
        _emit(
            {
                "ours_offset": ob * 4,
                "target_offset": tb * 4,
                "confidence": "hypothesis",
                "category": "delay_slot",
                "ours": o_slot,
                "target": t_slot,
                "action": (
                    "Target fills the branch/jump delay slot differently "
                    f"(`{t_slot}` vs `{o_slot}`). Try inverting the branch condition, "
                    "reordering the statement right before the branch/return, or adjusting loop guards."
                ),
            }
        )

    for i, j in pairs:
        a, b = ours[i], target[j]
        if a == b:
            continue
        op_a, op_b = (a >> 26) & 0x3F, (b >> 26) & 0x3F
        rs_a, rs_b = (a >> 21) & 0x1F, (b >> 21) & 0x1F
        rt_a, rt_b = (a >> 16) & 0x1F, (b >> 16) & 0x1F
        u_a, u_b = a & 0xFFFF, b & 0xFFFF
        s_a, s_b = signed(u_a, 16), signed(u_b, 16)
        base_rep: dict[str, Any] = {
            "ours_offset": i * 4,
            "target_offset": j * 4,
            "confidence": "hypothesis",
        }

        # 1. Callee mismatch (`jal` or external tail-call `j`)
        if op_a == op_b and op_a in (2, 3):
            aa, bb = _jal_target(a, va + 4 * i), _jal_target(b, va + 4 * j)
            fn_end = va + 4 * len(target)
            is_ext_j = (op_a == 3) or (not (va <= aa < fn_end) or not (va <= bb < fn_end))
            if aa != bb and is_ext_j:
                rep = dict(base_rep)
                rep.update(
                    category="callee",
                    ours=symbols.get(aa, f"0x{aa:08X}"),
                    target=symbols.get(bb, f"0x{bb:08X}"),
                    action="Check the called function and its prototype; do not permute registers around a wrong callee.",
                )
                _emit(rep)
            continue

        # 2. `$gp` vs `lui` small-data addressing mode mismatch
        if (rs_a == 28) != (rs_b == 28) and (op_a in _MEM_OPS or op_a in (9, 15)) and (op_b in _MEM_OPS or op_b in (9, 15)):
            rep = dict(base_rep)
            mode_o = "$gp-relative" if rs_a == 28 else "lui+%lo"
            mode_t = "$gp-relative" if rs_b == 28 else "lui+%lo"
            rep.update(
                category="gp_small_data",
                ours=mode_o,
                target=mode_t,
                action=(
                    f"Target addresses this global via {mode_t} while ours uses {mode_o}. "
                    "Check `-G` small-data threshold, `extern T sym;` (small data) vs `extern T sym[];` "
                    "(non-GP), or `__attribute__((section(\".sdata\")))`."
                ),
            )
            _emit(rep)
            continue

        # 3. `$gp`-relative global mismatch
        if gp and rs_a == 28 and rs_b == 28 and (op_a == op_b) and (op_a == 9 or op_a in _MEM_OPS):
            aa = (gp + s_a) & 0xFFFFFFFF
            bb = (gp + s_b) & 0xFFFFFFFF
            if aa != bb:
                rep = dict(base_rep)
                rep.update(
                    category="global",
                    ours=f"0x{aa:08X}",
                    target=f"0x{bb:08X}",
                    ours_symbol=symbol_name_mips(objects, aa),
                    target_symbol=symbol_name_mips(objects, bb),
                    action=(
                        f"Use target `$gp` global {symbol_name_mips(objects, bb)} (0x{bb:08X}); "
                        f"ours refers to {symbol_name_mips(objects, aa)} (0x{aa:08X})."
                    ),
                )
                _emit(rep)
            continue

        # 4. Paired 32-bit `lui` + `ori`/`addiu`/mem (either global symbol or 32-bit constant!)
        if i in ours_lui and j in targ_lui:
            _, full_a, kind_a = ours_lui[i]
            _, full_b, kind_b = targ_lui[j]
            if full_a != full_b:
                in_objs = (full_a in objects or full_b in objects or full_a in symbols or full_b in symbols)
                if in_objs and op_a in (_MEM_OPS | {9, 25}):
                    rep = dict(base_rep)
                    rep.update(
                        category="global",
                        ours=f"0x{full_a:08X}",
                        target=f"0x{full_b:08X}",
                        ours_symbol=symbols.get(full_a) or symbol_name_mips(objects, full_a),
                        target_symbol=symbols.get(full_b) or symbol_name_mips(objects, full_b),
                        action=(
                            f"Use target global {symbol_name_mips(objects, full_b)} (0x{full_b:08X}); "
                            f"ours refers to {symbol_name_mips(objects, full_a)} (0x{full_a:08X})."
                        ),
                    )
                    _emit(rep)
                else:
                    val_a = full_a if kind_a == "ori" else signed(full_a, 32)
                    val_b = full_b if kind_b == "ori" else signed(full_b, 32)
                    rep = dict(base_rep)
                    rep.update(
                        category="literal",
                        ours=val_a,
                        target=val_b,
                        action="Test the target 32-bit constant in C (`lui`+`ori`/`addiu` immediate pair).",
                    )
                    locs, edit = _signed_immediate_edit(source, full_a, full_b)
                    if not edit and val_a != full_a:
                        locs, edit = _signed_immediate_edit(source, val_a, val_b)
                    rep["source_locations"] = locs
                    if edit:
                        rep["suggested_edit"] = edit
                    _emit(rep)
            continue

        # Skip the `lui` half if its consumer pair was already analyzed above
        if op_a == 15 and op_b == 15 and (i in consumed_lui_o or j in consumed_lui_t):
            continue

        # 5. Standalone upper-16 literal (`lui rt, imm` with zero low bits, e.g. 0x10000 or float bits)
        if op_a == 15 and op_b == 15 and rs_a == 0 and rs_b == 0 and u_a != u_b:
            full_a, full_b = u_a << 16, u_b << 16
            rep = dict(base_rep)
            rep.update(
                category="literal",
                ours=full_a,
                target=full_b,
                action="Test the target upper-16-bit constant (`lui` immediate << 16) in C.",
            )
            locs, edit = _signed_immediate_edit(source, full_a, full_b)
            rep["source_locations"] = locs
            if edit:
                rep["suggested_edit"] = edit
            _emit(rep)
            continue

        # 6. Stack frame allocation (`addiu/daddiu $sp, $sp, -N`)
        if op_a in (9, 25) and op_b in (9, 25) and rs_a == rt_a == 29 and rs_b == rt_b == 29 and s_a < 0 and s_b < 0 and s_a != s_b:
            rep = dict(base_rep)
            rep.update(
                category="frame",
                ours=-s_a,
                target=-s_b,
                action="Check stack-allocated locals, array sizes, and callee-saved register spills (`$sp` frame size).",
            )
            _emit(rep)
            continue

        # 7. Small integer literal (`li`: `addiu rt, $zero, simm` or `ori rt, $zero, uimm`)
        if op_a in (9, 13) and op_b in (9, 13) and rs_a == 0 and rs_b == 0:
            val_a = u_a if op_a == 13 else s_a
            val_b = u_b if op_b == 13 else s_b
            if val_a != val_b:
                rep = dict(base_rep)
                rep.update(
                    category="literal",
                    ours=val_a,
                    target=val_b,
                    action="Test the target integer literal in C (`li` / `addiu` / `ori` immediate).",
                )
                locs, edit = _signed_immediate_edit(source, val_a, val_b)
                rep["source_locations"] = locs
                if edit:
                    rep["suggested_edit"] = edit
                _emit(rep)
            continue

        # Also catch arithmetic/compare immediates (`addiu`, `slti`, `sltiu`, `andi`, `ori`, `xori`) on non-zero/sp/gp
        if op_a == op_b and op_a in (10, 11, 12, 13, 14) and u_a != u_b:
            val_a = s_a if op_a in (10, 11) else u_a
            val_b = s_b if op_b in (10, 11) else u_b
            rep = dict(base_rep)
            rep.update(
                category="literal",
                ours=val_a,
                target=val_b,
                action="Test the target ALU/compare immediate constant in C.",
            )
            locs, edit = _signed_immediate_edit(source, val_a, val_b)
            rep["source_locations"] = locs
            if edit:
                rep["suggested_edit"] = edit
            _emit(rep)
            continue

        # 8. Struct field offset on memory loads/stores
        if op_a == op_b and op_a in _MEM_OPS and rs_a not in (0, 28, 29) and rs_b not in (0, 28, 29) and s_a != s_b:
            rep = dict(base_rep)
            rep.update(
                category="field_offset",
                ours=s_a,
                target=s_b,
                action=(
                    f"Test struct/member byte offset {s_b:#x} instead of {s_a:#x} on "
                    f"{GPR_NAMES[rs_b]}; confirm the base pointer matches."
                ),
            )
            _emit(rep)
            continue

        # 9. Pointer / integer `addiu` immediate on non-$zero/$sp/$gp register
        if op_a == op_b and op_a in (8, 9, 24, 25) and rs_a not in (0, 28, 29) and rs_b not in (0, 28, 29) and s_a != s_b:
            locs, edit = _signed_immediate_edit(source, s_a, s_b)
            rep = dict(base_rep)
            if locs:
                rep.update(
                    category="literal",
                    ours=s_a,
                    target=s_b,
                    action="Test the target additive integer constant in C (`addiu` immediate).",
                    source_locations=locs,
                )
                if edit:
                    rep["suggested_edit"] = edit
            else:
                rep.update(
                    category="offset",
                    ours=s_a,
                    target=s_b,
                    action="Check pointer arithmetic, array stride, or additive constant at this instruction.",
                )
            _emit(rep)

    priority = {
        "callee": 0,
        "global": 1,
        "gp_small_data": 2,
        "literal": 3,
        "field_offset": 4,
        "offset": 4,
        "delay_slot": 5,
        "frame": 6,
    }
    return sorted(out, key=lambda item: priority.get(item["category"], 9))[:limit]
