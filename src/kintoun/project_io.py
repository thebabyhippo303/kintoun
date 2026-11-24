"""Multi-function decomp project importer, linker `.map` parser, header slicer, and post-match integrator.

Eliminates manual scratch extraction and custom JS integrator scripts on `INCLUDE_ASM` /
`GLOBAL_ASM` repositories (GBA `agbcc`, PS2/PSP/N64 `splat`, GameCube/Wii `dtk` & MWCC/ProDG):
  - `parse_linker_map`: parses GNU `ld`, Metrowerks `mwld`, and `dtk` `.map` files in pure stdlib.
  - `discover_tu_compile_flags`: reads per-file `-I`, `-D`, and optimization flags from
    `compile_commands.json` or `build.ninja`.
  - `slice_project_types_and_decls`: transitively extracts `typedef` / `struct` / `union` / `enum`
    definitions and prototypes from local project `.h` headers without shelling out to `cpp`.
  - `import_project_function`: locates `INCLUDE_ASM(..., fn)` or `#pragma GLOBAL_ASM("...fn...")`
    across `src/` and produces a self-contained compilable candidate `.c`.
  - `integrate_matched_function`: splices a verified C match back into the multi-function `.c`
    file, strips duplicate declarations, and strictly verifies the integrated TU before saving.
"""
from __future__ import annotations

import json
from pathlib import Path
import re
import shlex
from typing import Any

from kintoun.compiler import CompilerBackend
from kintoun.targets import TargetContext, TargetFunction
from kintoun.verify import real_c_violation, verify_source

# Matches both 2-arg `INCLUDE_ASM("asm/...", func_name);` and 3-arg `INCLUDE_ASM(s32, "asm/...", func_name);`
_INCLUDE_ASM_RE = re.compile(
    r"^[ \t]*INCLUDE_ASM\s*\(\s*(?:[^,\n]+,\s*)?\"(?P<folder>[^\"]+)\"\s*,\s*(?P<func>[A-Za-z_]\w*)\s*\)\s*;?[ \t]*$",
    re.MULTILINE,
)
_PRAGMA_GLOBAL_ASM_RE = re.compile(
    r"^[ \t]*#pragma\s+GLOBAL_ASM\s*\(\s*\"(?P<asm_path>[^\"]+)\"\s*\)[ \t]*$",
    re.MULTILINE,
)
_MACRO_GLOBAL_ASM_RE = re.compile(
    r"^[ \t]*GLOBAL_ASM\s*\(\s*\"(?P<asm_path>[^\"]+\.s)\"\s*\)\s*;?[ \t]*$",
    re.MULTILINE,
)
_LOCAL_INCLUDE_RE = re.compile(r'^[ \t]*#\s*include\s*"([^"]+)"', re.MULTILINE)
_FUNC_DECL_RE = re.compile(
    r"(?m)^(?P<decl>(?:extern\s+|static\s+)?[A-Za-z_][\w\s\*]+?\b(?P<name>[A-Za-z_]\w*)\s*\([^;{}]*\))\s*;"
)
_FUNC_DEF_HEAD_RE = re.compile(
    r"(?m)^(?P<head>(?:static\s+(?:inline\s+|__inline\s+)?)?[A-Za-z_][\w\s\*]*?\b(?P<name>[A-Za-z_]\w*)\s*\([^;{}]*\))\s*\{"
)

# GNU ld single-line:  ` 0x08001234                MyFunc` or ` 0x80004000   0x48  MyFunc`
_GNU_SYM_RE = re.compile(
    r"^\s+0x([0-9A-Fa-f]{6,16})\s+(?:0x([0-9A-Fa-f]+)\s+)?([A-Za-z_][A-Za-z0-9_.$]*)\s*$"
)
_GNU_SEC_OBJ_RE = re.compile(
    r"^\s*(\.[A-Za-z0-9_.$]+)\s+0x([0-9A-Fa-f]{6,16})\s+0x([0-9A-Fa-f]+)\s+(\S+\.o(?:\([^)]+\))?)\s*$"
)
# Metrowerks / dtk map: `  00000040 000084 80003140  4 MyFunc   foo.o`
_MWLD_SYM_RE = re.compile(
    r"^\s*[0-9A-Fa-f]{8}\s+([0-9A-Fa-f]{6,8})\s+([0-9A-Fa-f]{8})\s+(?:\d+\s+)?([A-Za-z_][A-Za-z0-9_.$]*)(?:\s+(\S+\.o\b))?"
)


def parse_linker_map(map_path: Path) -> dict[str, dict[str, Any]]:
    """Parse GNU `ld`, Metrowerks `mwld`, or `dtk` `.map` files into `{symbol: {va, size, section, obj_path}}`."""
    text = Path(map_path).read_text(encoding="utf-8", errors="replace")
    entries: list[dict[str, Any]] = []
    cur_section = ".text"
    cur_obj = ""
    cur_sec_end = 0

    for line in text.splitlines():
        m_sec = _GNU_SEC_OBJ_RE.match(line)
        if m_sec:
            cur_section = m_sec.group(1)
            sec_va = int(m_sec.group(2), 16)
            sec_sz = int(m_sec.group(3), 16)
            cur_sec_end = sec_va + sec_sz
            cur_obj = m_sec.group(4)
            continue

        m_mw = _MWLD_SYM_RE.match(line)
        if m_mw:
            sz = int(m_mw.group(1), 16)
            va = int(m_mw.group(2), 16)
            sym = m_mw.group(3)
            obj = m_mw.group(4) or cur_obj
            if not sym.startswith("."):
                entries.append(
                    {"name": sym, "va": va, "size": sz, "section": cur_section, "obj_path": obj, "_sec_end": 0}
                )
            continue

        m_gnu = _GNU_SYM_RE.match(line)
        if m_gnu:
            va = int(m_gnu.group(1), 16)
            sz = int(m_gnu.group(2), 16) if m_gnu.group(2) else 0
            sym = m_gnu.group(3)
            if sym not in ("PROVIDE", "ASSERT") and not sym.startswith("."):
                entries.append(
                    {
                        "name": sym,
                        "va": va,
                        "size": sz,
                        "section": cur_section,
                        "obj_path": cur_obj,
                        "_sec_end": cur_sec_end,
                    }
                )

    # Sort by VA to infer GNU ld symbol sizes from consecutive symbol addresses when size is omitted
    entries.sort(key=lambda item: (item["va"], 0 if not item["name"].endswith(".NON_MATCHING") else 1))
    by_name: dict[str, dict[str, Any]] = {}
    for i, item in enumerate(entries):
        name = item["name"]
        if name.endswith(".NON_MATCHING"):
            base = name.removesuffix(".NON_MATCHING")
            if base in by_name:
                continue
            name = base
        sz = int(item["size"])
        if sz == 0:
            # Infer distance to next distinct VA in same section or section end
            for j in range(i + 1, len(entries)):
                nxt = entries[j]
                if nxt["va"] > item["va"] and nxt["section"] == item["section"]:
                    sz = nxt["va"] - item["va"]
                    break
            if sz == 0 and item["_sec_end"] > item["va"]:
                sz = item["_sec_end"] - item["va"]
        by_name[name] = {
            "va": item["va"] & ~1,
            "thumb": bool(item["va"] & 1),
            "size": max(0, sz),
            "section": item["section"],
            "obj_path": item["obj_path"],
        }
    return by_name


def discover_tu_compile_flags(project_root: Path, c_file: Path) -> dict[str, Any]:
    """Extract per-TU include dirs (`-I`), defines (`-D`), and flags from `compile_commands.json` or `build.ninja`."""
    root = Path(project_root).resolve()
    target_c = Path(c_file).resolve()
    rel_c = ""
    try:
        rel_c = target_c.relative_to(root).as_posix()
    except ValueError:
        rel_c = target_c.name

    for cand_cc in (root / "compile_commands.json", root / "build" / "compile_commands.json"):
        if cand_cc.is_file():
            try:
                rows = json.loads(cand_cc.read_text(encoding="utf-8", errors="replace"))
            except Exception:
                rows = []
            for row in rows if isinstance(rows, list) else []:
                f_str = str(row.get("file", ""))
                d_str = str(row.get("directory", root))
                f_abs = (Path(d_str) / f_str).resolve() if f_str else None
                if f_abs == target_c or f_str.replace("\\", "/").endswith(rel_c):
                    args = row.get("arguments")
                    if not isinstance(args, list):
                        args = shlex.split(str(row.get("command", "")))
                    return _classify_compiler_tokens([str(a) for a in args], Path(d_str))

    for cand_ninja in (root / "build.ninja", root / "build" / "build.ninja"):
        if cand_ninja.is_file():
            try:
                ntxt = cand_ninja.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            flags_vars: dict[str, str] = {}
            for m in re.finditer(r"(?m)^([A-Za-z0-9_]+)\s*=\s*(.+)$", ntxt):
                flags_vars[m.group(1)] = m.group(2).strip()
            pat = re.compile(
                r"(?m)^build\s+\S+:\s+([A-Za-z0-9_.-]+)\s+" + re.escape(rel_c) + r"\b(?P<block>(?:\n\s+.+)*)"
            )
            m_b = pat.search(ntxt)
            if m_b:
                local_vars = dict(flags_vars)
                for lm in re.finditer(r"(?m)^\s+([A-Za-z0-9_]+)\s*=\s*(.+)$", m_b.group("block") or ""):
                    local_vars[lm.group(1)] = lm.group(2).strip()
                raw_flags = " ".join(
                    local_vars.get(k, "") for k in ("cflags", "CFLAGS", "flags", "FLAGS", "includes", "INCLUDES")
                )
                if raw_flags.strip():
                    return _classify_compiler_tokens(shlex.split(raw_flags), root)

    return {"include_dirs": [], "defines": [], "opt_flags": [], "raw_flags": []}


def _classify_compiler_tokens(tokens: list[str], base_dir: Path) -> dict[str, Any]:
    inc_dirs: list[str] = []
    defines: list[str] = []
    opt_flags: list[str] = []
    keep_raw: list[str] = []
    skip_next = False
    for i, tok in enumerate(tokens):
        if skip_next:
            skip_next = False
            continue
        if tok in ("-o", "-MF", "-MT", "-MQ", "-x"):
            skip_next = True
            continue
        if tok in ("-MD", "-MMD", "-MP"):
            continue
        if tok == "-I" and i + 1 < len(tokens):
            inc_dirs.append(str((base_dir / tokens[i + 1]).resolve()))
            keep_raw.extend(["-I", str((base_dir / tokens[i + 1]).resolve())])
            skip_next = True
        elif tok.startswith("-I") and len(tok) > 2:
            p = (base_dir / tok[2:]).resolve()
            inc_dirs.append(str(p))
            keep_raw.append(f"-I{p}")
        elif tok == "-D" and i + 1 < len(tokens):
            defines.append(tokens[i + 1])
            keep_raw.extend(["-D", tokens[i + 1]])
            skip_next = True
        elif tok.startswith("-D") and len(tok) > 2:
            defines.append(tok[2:])
            keep_raw.append(tok)
        elif tok.startswith("-O") or tok in ("-g", "-G0", "-G8", "-mthumb", "-fno-pic", "-mno-abicalls", "-nodefaults"):
            opt_flags.append(tok)
            keep_raw.append(tok)
    return {
        "include_dirs": inc_dirs,
        "defines": defines,
        "opt_flags": opt_flags,
        "raw_flags": keep_raw,
    }


def _extract_balanced_type_blocks(header_text: str) -> list[str]:
    """Extract top-level `typedef`, `struct`, `union`, and `enum` definitions from a C header."""
    cleaned = re.sub(r"/\*.*?\*/", "", header_text, flags=re.DOTALL)
    cleaned = re.sub(r"//[^\n]*", "", cleaned)
    blocks: list[str] = []
    n = len(cleaned)
    i = 0
    kw_re = re.compile(r"(?m)^[ \t]*(typedef|struct|union|enum)\b")
    while i < n:
        m = kw_re.search(cleaned, i)
        if m is None:
            break
        start = m.start()
        j = start
        brace = 0
        while j < n:
            ch = cleaned[j]
            if ch == "{":
                brace += 1
            elif ch == "}":
                brace = max(0, brace - 1)
            elif ch == ";" and brace == 0:
                stmt = cleaned[start : j + 1].strip()
                if stmt and len(stmt) <= 2400:
                    blocks.append(stmt)
                j += 1
                break
            j += 1
        i = max(j, m.end())
    return blocks


def slice_project_types_and_decls(
    c_file: Path,
    project_root: Path,
    *,
    target_func: str = "",
    extra_include_dirs: list[Path] | None = None,
    max_headers: int = 24,
) -> dict[str, Any]:
    """Walk local `#include "..."` headers transitively and slice typedefs, structs, enums, and prototypes."""
    root = Path(project_root).resolve()
    c_path = Path(c_file).resolve()
    search_dirs: list[Path] = [c_path.parent, root, root / "include", root / "src"]
    for d in extra_include_dirs or []:
        dp = Path(d)
        if dp.is_dir() and dp not in search_dirs:
            search_dirs.append(dp)

    visited: set[Path] = set()
    queue: list[Path] = []
    try:
        c_text = c_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        c_text = ""

    def _enqueue_includes(txt: str, cur_dir: Path) -> None:
        for inc_m in _LOCAL_INCLUDE_RE.finditer(txt):
            rel_inc = inc_m.group(1)
            for sdir in [cur_dir, *search_dirs]:
                cand_h = (sdir / rel_inc).resolve()
                if cand_h.is_file() and cand_h not in visited and len(visited) + len(queue) < max_headers:
                    queue.append(cand_h)
                    break

    _enqueue_includes(c_text, c_path.parent)
    type_blocks: list[str] = []
    seen_types: set[str] = set()
    declarations: dict[str, str] = {}

    while queue and len(visited) < max_headers:
        hdr = queue.pop(0)
        if hdr in visited:
            continue
        visited.add(hdr)
        try:
            htxt = hdr.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        _enqueue_includes(htxt, hdr.parent)
        for blk in _extract_balanced_type_blocks(htxt):
            if blk not in seen_types:
                seen_types.add(blk)
                type_blocks.append(blk)
        for dm in _FUNC_DECL_RE.finditer(htxt):
            fn = dm.group("name")
            if fn not in ("INCLUDE_ASM", "GLOBAL_ASM", "if", "while", "for", "switch", "return"):
                declarations.setdefault(fn, " ".join(dm.group("decl").split()) + ";")

    for dm in _FUNC_DECL_RE.finditer(c_text):
        fn = dm.group("name")
        if fn not in ("INCLUDE_ASM", "GLOBAL_ASM", "if", "while", "for", "switch", "return"):
            declarations.setdefault(fn, " ".join(dm.group("decl").split()) + ";")

    return {
        "headers_scanned": [str(p) for p in visited],
        "type_definitions": type_blocks[:40],
        "function_declarations": declarations,
        "target_declaration": declarations.get(target_func, ""),
    }


def find_stub_in_project(project_root: Path, func_name: str, c_file: Path | None = None) -> dict[str, Any] | None:
    """Locate `INCLUDE_ASM(..., func_name)` or `#pragma GLOBAL_ASM("...func_name...")` in `c_file` or `src/`."""
    candidates = [Path(c_file)] if c_file is not None else sorted((Path(project_root) / "src").rglob("*.c"))
    if not candidates and c_file is None:
        candidates = sorted(Path(project_root).rglob("*.c"))[:400]

    for cf in candidates:
        if not cf.is_file():
            continue
        try:
            txt = cf.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for m in _INCLUDE_ASM_RE.finditer(txt):
            if m.group("func") == func_name:
                asm_rel = Path(m.group("folder")) / f"{func_name}.s"
                asm_path = Path(project_root) / asm_rel
                return {
                    "c_file": cf,
                    "stub_kind": "INCLUDE_ASM",
                    "stub_text": m.group(0),
                    "span": (m.start(), m.end()),
                    "asm_path": asm_path if asm_path.is_file() else None,
                }
        for kind, rx in (("PRAGMA_GLOBAL_ASM", _PRAGMA_GLOBAL_ASM_RE), ("GLOBAL_ASM", _MACRO_GLOBAL_ASM_RE)):
            for m in rx.finditer(txt):
                apath_s = m.group("asm_path")
                if Path(apath_s).stem == func_name or apath_s.endswith(f"/{func_name}.s"):
                    asm_path = Path(project_root) / apath_s
                    return {
                        "c_file": cf,
                        "stub_kind": kind,
                        "stub_text": m.group(0),
                        "span": (m.start(), m.end()),
                        "asm_path": asm_path if asm_path.is_file() else None,
                    }
    return None


def import_project_function(
    project_root: Path,
    func_name: str,
    *,
    c_file: Path | None = None,
    map_file: Path | None = None,
    out_candidate: Path | None = None,
) -> dict[str, Any]:
    """Extract a standalone compilable candidate `.c` + TU flags + map metadata for `func_name`."""
    root = Path(project_root).resolve()
    stub = find_stub_in_project(root, func_name, c_file=c_file)
    if stub is None and c_file is None:
        raise ValueError(f"no INCLUDE_ASM or GLOBAL_ASM stub found for '{func_name}' under {root}")

    src_c = stub["c_file"] if stub is not None else Path(c_file).resolve()
    tu_flags = discover_tu_compile_flags(root, src_c)
    inc_paths = [Path(p) for p in tu_flags["include_dirs"]]
    sliced = slice_project_types_and_decls(src_c, root, target_func=func_name, extra_include_dirs=inc_paths)

    asm_callees: list[str] = []
    asm_text = ""
    if stub and stub["asm_path"] is not None:
        asm_text = stub["asm_path"].read_text(encoding="utf-8", errors="replace")
        for cm in re.finditer(r"\b(?:bl|jal|blx)\s+([A-Za-z_][A-Za-z0-9_]*)", asm_text):
            callee = cm.group(1)
            if callee != func_name and callee not in asm_callees:
                asm_callees.append(callee)

    map_info: dict[str, Any] | None = None
    if map_file is not None and Path(map_file).is_file():
        parsed_map = parse_linker_map(Path(map_file))
        map_info = parsed_map.get(func_name)

    prelude = [
        "typedef signed char s8;",
        "typedef short s16;",
        "typedef int s32;",
        "typedef unsigned char u8;",
        "typedef unsigned short u16;",
        "typedef unsigned int u32;",
        "typedef float f32;",
        "typedef double f64;",
    ]
    existing_blob = "\n".join(sliced["type_definitions"])
    kept_std = [td for td in prelude if td.split()[-1].rstrip(";") not in existing_blob]
    lines: list[str] = []
    if kept_std:
        lines.extend(kept_std)
        lines.append("")
    if sliced["type_definitions"]:
        lines.extend(sliced["type_definitions"][:24])
        lines.append("")
    for callee in asm_callees[:20]:
        if callee in sliced["function_declarations"]:
            lines.append(sliced["function_declarations"][callee])
    if asm_callees:
        lines.append("")

    target_decl = sliced["target_declaration"]
    if target_decl:
        sig = re.sub(r"^\s*extern\s+", "", target_decl[:-1]).strip()
        is_void = bool(re.match(r"^(?:static\s+)?void\s+[A-Za-z_]", sig))
        body = "    return;\n" if is_void else "    return 0;\n"
        lines.append(f"{sig} {{\n{body}}}")
    else:
        lines.append(f"s32 {func_name}(void) {{\n    return 0;\n}}")

    candidate_code = "\n".join(lines).strip() + "\n"
    if out_candidate is not None:
        out_p = Path(out_candidate)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        out_p.write_text(candidate_code, encoding="utf-8")

    return {
        "function": func_name,
        "c_file": str(src_c),
        "stub_kind": stub["stub_kind"] if stub else None,
        "asm_path": str(stub["asm_path"]) if (stub and stub["asm_path"]) else None,
        "asm_callees": asm_callees,
        "tu_flags": tu_flags,
        "map_symbol": map_info,
        "headers_scanned": len(sliced["headers_scanned"]),
        "candidate_path": str(out_candidate) if out_candidate else None,
        "candidate_code": candidate_code,
    }


def _extract_c_function_blocks(code: str) -> dict[str, str]:
    """Map `{func_name: full_definition_text}` for top-level C function definitions in `code`."""
    defs: dict[str, str] = {}
    n = len(code)
    for m in _FUNC_DEF_HEAD_RE.finditer(code):
        fname = m.group("name")
        if fname in ("if", "while", "for", "switch"):
            continue
        brace_open = code.find("{", m.end() - 1)
        if brace_open < 0:
            continue
        depth = 0
        j = brace_open
        while j < n:
            ch = code[j]
            if ch in ('"', "'"):
                q = ch
                j += 1
                while j < n:
                    if code[j] == "\\":
                        j += 2
                        continue
                    if code[j] == q:
                        j += 1
                        break
                    j += 1
                continue
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    defs[fname] = code[m.start() : j + 1].strip()
                    break
            j += 1
    return defs


def strip_duplicate_declarations(existing_tu_text: str, candidate_code: str, target_func: str) -> str:
    """Extract `target_func` (plus new `static inline` helpers) and strip declarations already in `existing_tu_text`."""
    cand_defs = _extract_c_function_blocks(candidate_code)
    existing_defs = _extract_c_function_blocks(existing_tu_text)
    existing_decls = {m.group("name") for m in _FUNC_DECL_RE.finditer(existing_tu_text)} | set(existing_defs)

    if target_func not in cand_defs:
        raise ValueError(f"candidate code does not contain a C definition for '{target_func}'")

    kept_parts: list[str] = []
    # Preserve any new `static inline` helpers defined in `candidate_code` that aren't in `existing_tu_text`
    for hname, hdef in cand_defs.items():
        if hname != target_func and hname not in existing_decls and "inline" in hdef.split("{", 1)[0]:
            kept_parts.append(hdef)

    # Preserve only `extern` function declarations referenced inside `target_func` that aren't already declared in TU
    body_text = cand_defs[target_func]
    for dm in _FUNC_DECL_RE.finditer(candidate_code):
        dname = dm.group("name")
        if dname == target_func or dname in existing_decls:
            continue
        if re.search(rf"\b{re.escape(dname)}\s*\(", body_text):
            decl_line = " ".join(dm.group("decl").split()) + ";"
            if not decl_line.startswith("extern "):
                decl_line = "extern " + decl_line
            kept_parts.append(decl_line)

    kept_parts.append(cand_defs[target_func])
    return "\n\n".join(kept_parts)


def integrate_matched_function(
    matched_code: str,
    project_c_file: Path,
    func_name: str,
    *,
    verify: bool = False,
    target_fn: TargetFunction | None = None,
    ctx: TargetContext | None = None,
    compiler: CompilerBackend | None = None,
    forbid_asm: bool = True,
    write: bool = True,
) -> dict[str, Any]:
    """Replace `INCLUDE_ASM` / `GLOBAL_ASM` (or existing definition) in `project_c_file` with `matched_code`.

    When `verify=True` (with `target_fn`, `ctx`, `compiler`), compiles and strictly verifies the
    entire integrated multi-function TU BEFORE modifying `project_c_file`, preventing broken builds.
    """
    if forbid_asm:
        bad = real_c_violation(matched_code)
        if bad:
            return {"ok": False, "error": f"REAL C ONLY: rejected '{bad}'"}

    c_path = Path(project_c_file)
    orig_text = c_path.read_text(encoding="utf-8")
    stub = find_stub_in_project(c_path.parent, func_name, c_file=c_path)

    cleaned_splice = strip_duplicate_declarations(orig_text, matched_code, func_name)

    if stub is not None:
        s_start, s_end = stub["span"]
        integrated_text = orig_text[:s_start] + cleaned_splice + orig_text[s_end:]
        replaced_kind = stub["stub_kind"]
    else:
        existing_defs = _extract_c_function_blocks(orig_text)
        if func_name not in existing_defs:
            return {
                "ok": False,
                "error": f"neither INCLUDE_ASM/GLOBAL_ASM stub nor existing definition for '{func_name}' found in {c_path}",
            }
        old_def = existing_defs[func_name]
        integrated_text = orig_text.replace(old_def, cleaned_splice, 1)
        replaced_kind = "existing_definition"

    ver_res: dict[str, Any] | None = None
    if verify:
        if target_fn is None or ctx is None or compiler is None:
            raise ValueError("verify=True requires target_fn, ctx, and compiler")
        # Strictly verify the integrated multi-function TU (note: TU may contain other INCLUDE_ASM stubs;
        # strip remaining unrelated INCLUDE_ASM/GLOBAL_ASM stubs ONLY in the ephemeral verification copy
        # if `forbid_asm` would trip on neighbor stubs, while keeping all C declarations & functions intact!)
        verify_copy = _INCLUDE_ASM_RE.sub("/* stub */", integrated_text)
        verify_copy = _PRAGMA_GLOBAL_ASM_RE.sub("/* stub */", verify_copy)
        verify_copy = _MACRO_GLOBAL_ASM_RE.sub("/* stub */", verify_copy)
        ver_res = verify_source(verify_copy, target_fn, ctx, compiler, lines=16, forbid_asm=forbid_asm)
        if not ver_res.get("verified"):
            return {
                "ok": False,
                "verified": False,
                "error": (
                    f"integrated TU failed strict verification ({ver_res.get('status')}): "
                    f"{ver_res.get('error') or str(ver_res.get('different_bytes')) + ' bytes differ'}"
                ),
                "verification": ver_res,
            }

    if write:
        c_path.write_text(integrated_text, encoding="utf-8")

    return {
        "ok": True,
        "verified": bool(ver_res.get("verified")) if ver_res is not None else None,
        "function": func_name,
        "c_file": str(c_path),
        "replaced": replaced_kind,
        "spliced_code": cleaned_splice,
    }
