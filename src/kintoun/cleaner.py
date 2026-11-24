"""Byte-verified post-match C code cleaner and `goto` restructurer (`kintoun clean`).

Simplifies raw `m2c`, permuter, or AI-generated matched C into human-reviewable C while strictly
preserving `different_bytes == 0`:
  1. Strips leftover `KINTOUN_*` / `PERM_*` single-choice wrappers and `do { ... } while (0);` shells.
  2. Restructures forward `if (cond) goto label; ... label:` guards into structured `if (!cond) { ... }`.
  3. Restructures backward `label: ... if (cond) goto label;` loops into `do { ... } while (cond);`.
  4. Prunes unused local variable declarations (`temp_*`, `var_*`, `phi_*`, etc.).
  5. Inlines single-use temporary assignments (`temp_r3 = expr; return temp_r3;` -> `return expr;`).
  6. Removes no-op self-assignments (`x = x;`), duplicate casts (`(s32)(s32)x`), and `return (x);` parens.

Every single candidate rewrite is tested through `verify_source` and kept ONLY when `verified == True`
remains byte-exact.
"""
from __future__ import annotations

import re
from typing import Any

from kintoun.compiler import CompilerBackend
from kintoun.macros import expand_perm_macros, has_perm_macros
from kintoun.search.base_mutations import negate
from kintoun.targets import TargetContext, TargetFunction
from kintoun.verify import verify_source

_LOCAL_DECL_RE = re.compile(
    r"^(?P<indent>[ \t]+)(?:register\s+)?(?P<type>(?:unsigned\s+|signed\s+|const\s+)*"
    r"(?:void|char|short|int|long|float|double|[us](?:8|16|32|64)|f(?:32|64)|[A-Za-z_]\w*)\s*\**)\s*"
    r"(?P<name>[A-Za-z_]\w*)\s*;\s*$"
)
_SELF_ASSIGN_RE = re.compile(r"^[ \t]*([A-Za-z_]\w*)\s*=\s*\1\s*;\s*$")
_DO_WHILE_ZERO_RE = re.compile(
    r"(?ms)^(?P<ind>[ \t]*)do\s*\{\n(?P<body>.*?)\n(?P=ind)\}\s*while\s*\(\s*0\s*\)\s*;"
)
_FWD_GOTO_RE = re.compile(
    r"(?ms)^(?P<ind>[ \t]*)if\s*\((?P<cond>[^\n]+?)\)\s*\{\s*\n?"
    r"[ \t]*goto\s+(?P<lbl>[A-Za-z_]\w*)\s*;\s*\n?"
    r"(?P=ind)\}\n"
    r"(?P<mid>(?:(?!\bgoto\s+(?P=lbl)\b)(?!^[ \t]*[A-Za-z_]\w*[ \t]*:).+\n)+)"
    r"^[ \t]*(?P=lbl)[ \t]*:[ \t]*;?[ \t]*\n?"
)
_FWD_GOTO_BRACES_FREE_RE = re.compile(
    r"(?ms)^(?P<ind>[ \t]*)if\s*\((?P<cond>[^\n]+?)\)\s+goto\s+(?P<lbl>[A-Za-z_]\w*)\s*;\s*\n"
    r"(?P<mid>(?:(?!\bgoto\s+(?P=lbl)\b)(?!^[ \t]*[A-Za-z_]\w*[ \t]*:).+\n)+)"
    r"^[ \t]*(?P=lbl)[ \t]*:[ \t]*;?[ \t]*\n?"
)
_BWD_DO_WHILE_RE = re.compile(
    r"(?ms)^[ \t]*(?P<lbl>[A-Za-z_]\w*)[ \t]*:[ \t]*\n"
    r"(?P<body>(?:(?!\bgoto\s+(?P=lbl)\b).+\n)+)"
    r"^(?P<ind>[ \t]*)if\s*\((?P<cond>[^\n]+?)\)\s*(?:\{\s*)?goto\s+(?P=lbl)\s*;\s*(?:\}\s*)?\n"
)
_SINGLE_USE_RET_RE = re.compile(
    r"(?m)^(?P<ind>[ \t]+)(?P<var>(?:temp|var|phi)_[A-Za-z0-9_]*)\s*=\s*(?P<expr>[^;\n]+);\n"
    r"[ \t]*return\s+(?P=var)\s*;"
)
_DUP_CAST_RE = re.compile(r"\(\s*([us](?:8|16|32)|f(?:32|64)|int|short|char|float|double)\s*\)\s*\(\s*\1\s*\)")
_RET_PARENS_RE = re.compile(r"(?m)^([ \t]*return)\s+\(([^();\n]+)\)\s*;")


def _propose_single_cleanup(code: str) -> list[tuple[str, str]]:
    """Yield `(step_name, candidate_code)` single-site readability improvements from `code`."""
    proposals: list[tuple[str, str]] = []

    # 1. Resolve deterministic single-option `KINTOUN_*` / `PERM_*` wrappers
    if has_perm_macros(code):
        exp = expand_perm_macros(code, max_variants=2)
        if exp["variants"] and exp["variants"][0] != code:
            proposals.append(("unwrap_perm_macro", exp["variants"][0]))

    # 2. Remove `do { ... } while (0);` wrappers
    m_dw = _DO_WHILE_ZERO_RE.search(code)
    if m_dw:
        unindented = "\n".join(
            (ln[4:] if ln.startswith("    ") else ln) for ln in m_dw.group("body").splitlines()
        )
        proposals.append(("unwrap_do_while_0", code[: m_dw.start()] + unindented + code[m_dw.end() :]))

    # 3. Remove `x = x;` no-op self-assignments
    lines = code.splitlines()
    for i, ln in enumerate(lines):
        if _SELF_ASSIGN_RE.match(ln):
            cand = "\n".join(lines[:i] + lines[i + 1 :]) + ("\n" if code.endswith("\n") else "")
            proposals.append(("remove_self_assign", cand))
            break

    # 4. Forward `if (cond) goto L; ... L:` -> `if (!cond) { ... }` (only when `L` has no other `goto L`)
    for rx in (_FWD_GOTO_RE, _FWD_GOTO_BRACES_FREE_RE):
        for m in rx.finditer(code):
            lbl = m.group("lbl")
            if len(re.findall(rf"\bgoto\s+{re.escape(lbl)}\b", code)) != 1:
                continue
            ind = m.group("ind")
            inv_cond = negate(m.group("cond").strip())
            mid_indented = "\n".join(
                ("    " + ln if ln.strip() else ln) for ln in m.group("mid").rstrip("\n").splitlines()
            )
            replacement = f"{ind}if ({inv_cond}) {{\n{mid_indented}\n{ind}}}\n"
            proposals.append((f"degoto_if:{lbl}", code[: m.start()] + replacement + code[m.end() :]))
            break

    # 5. Backward `L: ... if (cond) goto L;` -> `do { ... } while (cond);`
    for m in _BWD_DO_WHILE_RE.finditer(code):
        lbl = m.group("lbl")
        if len(re.findall(rf"\bgoto\s+{re.escape(lbl)}\b", code)) != 1:
            continue
        ind = m.group("ind")
        body_indented = "\n".join(
            ("    " + ln if ln.strip() else ln) for ln in m.group("body").rstrip("\n").splitlines()
        )
        cond = m.group("cond").strip()
        replacement = f"{ind}do {{\n{body_indented}\n{ind}}} while ({cond});\n"
        proposals.append((f"degoto_do_while:{lbl}", code[: m.start()] + replacement + code[m.end() :]))
        break

    # 6. Inline single-use `temp_r3 = expr; return temp_r3;` -> `return expr;`
    for m in _SINGLE_USE_RET_RE.finditer(code):
        var = m.group("var")
        # Only inline if `var` occurs solely in its declaration + this assign + this return (`<= 3` token hits)
        if len(re.findall(rf"\b{re.escape(var)}\b", code)) <= 3:
            rep = f"{m.group('ind')}return {m.group('expr').strip()};"
            proposals.append((f"inline_return_temp:{var}", code[: m.start()] + rep + code[m.end() :]))
            break

    # 7. Prune unused local variable declarations (one variable at a time, since stack/regalloc may depend on some!)
    for i, ln in enumerate(lines):
        dm = _LOCAL_DECL_RE.match(ln)
        if not dm:
            continue
        vname = dm.group("name")
        rest = "\n".join(lines[:i] + lines[i + 1 :])
        if not re.search(rf"\b{re.escape(vname)}\b", rest):
            cand = rest + ("\n" if code.endswith("\n") else "")
            proposals.append((f"remove_unused_local:{vname}", cand))

    # 8. Strip duplicate identical casts `(s32)(s32)x` -> `(s32)x`
    m_dc = _DUP_CAST_RE.search(code)
    if m_dc:
        proposals.append(
            ("strip_duplicate_cast", code[: m_dc.start()] + f"({m_dc.group(1)})" + code[m_dc.end() :])
        )

    # 9. Strip redundant `return (x);` outer parens -> `return x;`
    m_rp = _RET_PARENS_RE.search(code)
    if m_rp:
        proposals.append(
            ("strip_return_parens", code[: m_rp.start()] + f"{m_rp.group(1)} {m_rp.group(2).strip()};" + code[m_rp.end() :])
        )

    return proposals


def clean_matched_source(
    source: str,
    target_fn: TargetFunction,
    ctx: TargetContext,
    compiler: CompilerBackend,
    *,
    max_passes: int = 32,
    forbid_asm: bool = True,
) -> dict[str, Any]:
    """Greedily simplify a verified C match while strictly preserving `different_bytes == 0`."""
    initial = verify_source(source, target_fn, ctx, compiler, lines=12, forbid_asm=forbid_asm)
    if not initial.get("verified"):
        return {
            "ok": False,
            "verified": False,
            "error": (
                f"input source is not byte-verified ({initial.get('status')}: "
                f"{initial.get('different_bytes')} bytes differ); match the function before running clean"
            ),
            "cleaned_code": source,
            "applied_steps": [],
            "reverted_steps": 0,
        }

    cur_code = source
    applied: list[str] = []
    rejected_candidates: set[str] = set()
    reverted = 0

    for _ in range(max_passes):
        accepted_this_pass = False
        for step_name, cand_code in _propose_single_cleanup(cur_code):
            if cand_code == cur_code or cand_code in rejected_candidates:
                continue
            ver = verify_source(cand_code, target_fn, ctx, compiler, lines=8, forbid_asm=forbid_asm)
            if ver.get("verified"):
                cur_code = cand_code
                applied.append(step_name)
                accepted_this_pass = True
                break
            rejected_candidates.add(cand_code)
            reverted += 1
        if not accepted_this_pass:
            break

    orig_lines = len([ln for ln in source.splitlines() if ln.strip()])
    clean_lines = len([ln for ln in cur_code.splitlines() if ln.strip()])
    return {
        "ok": True,
        "verified": True,
        "name": target_fn.name,
        "addr": f"0x{target_fn.va:08X}",
        "changed": cur_code != source,
        "applied_steps": applied,
        "reverted_steps": reverted,
        "lines_before": orig_lines,
        "lines_after": clean_lines,
        "lines_saved": orig_lines - clean_lines,
        "cleaned_code": cur_code,
    }
