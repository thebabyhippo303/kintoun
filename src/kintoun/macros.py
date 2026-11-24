"""Parametric user permutation macro DSL (`PERM_*` and `KINTOUN_*`) in pure Python stdlib.

Provides a zero-dependency superset of `decomp-permuter`'s inline C permutation macros without
requiring `cpp`, `pycparser`, or `PLY`, and feeds top-scoring macro expansions directly into
Kintoun's multi-step beam search and register permuter:

Supported macros (both `PERM_*` and `KINTOUN_*` prefixes):
  - `PERM_GENERAL(alt1, alt2, ...)` / `KINTOUN_ALT(...)`: choose one C snippet alternative.
  - `PERM_INT(lo, hi)` / `KINTOUN_INT(lo, hi)`: integer literal in `[lo, hi]` inclusive.
  - `PERM_LINESWAP(lines...)` / `KINTOUN_LINESWAP(...)`: permute statement lines inside the block.
  - `PERM_ONCE([key,] code)` / `KINTOUN_ONCE(...)`: emit `code` at exactly one site sharing `key`.
  - `PERM_VAR(name, val)` + `PERM_VAR(name)`: bind `name` once and substitute consistently everywhere.
  - `PERM_SAMELINE(code)` / `PERM_FORCE_SAMELINE(code)`: collapse internal newlines onto one line.
  - `PERM_RANDOMIZE(code)` / `PERM_IGNORE(code)`: drop-in compatibility wrappers unwrapping `code`.
  - Escaped commas inside macro arguments: write `(,)` to emit a literal `,` without splitting args.
"""
from __future__ import annotations

from dataclasses import dataclass
import itertools
import math
import random
import re
from typing import Any

_MACRO_NAMES = frozenset(
    {
        "PERM_GENERAL",
        "PERM_INT",
        "PERM_LINESWAP",
        "PERM_ONCE",
        "PERM_VAR",
        "PERM_SAMELINE",
        "PERM_FORCE_SAMELINE",
        "PERM_RANDOMIZE",
        "PERM_IGNORE",
        "KINTOUN_ALT",
        "KINTOUN_GENERAL",
        "KINTOUN_INT",
        "KINTOUN_LINESWAP",
        "KINTOUN_ONCE",
        "KINTOUN_VAR",
        "KINTOUN_SAMELINE",
        "KINTOUN_IGNORE",
    }
)

_MACRO_HEAD_RE = re.compile(r"\b(" + "|".join(sorted(_MACRO_NAMES, key=len, reverse=True)) + r")\s*\(")
_ESCAPED_COMMA_SENTINEL = "\x00KINTOUN_COMMA\x00"


@dataclass(frozen=True)
class _MacroCall:
    name: str
    start: int
    end: int
    args: tuple[str, ...]


def has_perm_macros(source: str) -> bool:
    """Fast check returning True if `source` contains any `PERM_*` or `KINTOUN_*` macro call."""
    if "PERM_" not in source and "KINTOUN_" not in source:
        return False
    return bool(_find_outer_macros(source))


def _scan_balanced_parens(text: str, open_paren_idx: int) -> int:
    """Given `text[open_paren_idx] == '('`, return index after matching `)` respecting strings/comments."""
    n = len(text)
    depth = 0
    i = open_paren_idx
    while i < n:
        ch = text[i]
        if ch == "/" and i + 1 < n and text[i + 1] == "/":
            nl = text.find("\n", i + 2)
            i = n if nl < 0 else nl + 1
            continue
        if ch == "/" and i + 1 < n and text[i + 1] == "*":
            end_c = text.find("*/", i + 2)
            if end_c < 0:
                raise ValueError("unterminated block comment inside PERM macro")
            i = end_c + 2
            continue
        if ch in ('"', "'"):
            quote = ch
            i += 1
            while i < n:
                if text[i] == "\\":
                    i += 2
                    continue
                if text[i] == quote:
                    i += 1
                    break
                i += 1
            continue
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    raise ValueError("unbalanced parentheses in PERM macro")


def _split_macro_args(inner: str) -> tuple[str, ...]:
    """Split top-level comma-separated macro arguments while honoring `(,)` escapes and nested brackets."""
    protected = inner.replace("(,)", _ESCAPED_COMMA_SENTINEL)
    parts: list[str] = []
    cur: list[str] = []
    n = len(protected)
    i = 0
    paren = 0
    brace = 0
    bracket = 0
    while i < n:
        ch = protected[i]
        if ch == "/" and i + 1 < n and protected[i + 1] == "/":
            nl = protected.find("\n", i + 2)
            end = n if nl < 0 else nl + 1
            cur.append(protected[i:end])
            i = end
            continue
        if ch == "/" and i + 1 < n and protected[i + 1] == "*":
            end_c = protected.find("*/", i + 2)
            end = n if end_c < 0 else end_c + 2
            cur.append(protected[i:end])
            i = end
            continue
        if ch in ('"', "'"):
            quote = ch
            start_q = i
            i += 1
            while i < n:
                if protected[i] == "\\":
                    i += 2
                    continue
                if protected[i] == quote:
                    i += 1
                    break
                i += 1
            cur.append(protected[start_q:i])
            continue
        if ch == "(":
            paren += 1
        elif ch == ")":
            paren = max(0, paren - 1)
        elif ch == "{":
            brace += 1
        elif ch == "}":
            brace = max(0, brace - 1)
        elif ch == "[":
            bracket += 1
        elif ch == "]":
            bracket = max(0, bracket - 1)
        elif ch == "," and paren == 0 and brace == 0 and bracket == 0:
            raw_p = "".join(cur).replace(_ESCAPED_COMMA_SENTINEL, ",")
            parts.append(raw_p.strip(" \t") if "\n" not in raw_p else raw_p)
            cur = []
            i += 1
            continue
        cur.append(ch)
        i += 1
    last_p = "".join(cur).replace(_ESCAPED_COMMA_SENTINEL, ",")
    parts.append(last_p.strip(" \t") if "\n" not in last_p else last_p)
    return tuple(parts)


def _comment_and_string_spans(text: str) -> list[tuple[int, int]]:
    spans: list[tuple[int, int]] = []
    n = len(text)
    i = 0
    while i < n:
        ch = text[i]
        if ch == "/" and i + 1 < n and text[i + 1] == "/":
            nl = text.find("\n", i + 2)
            end = n if nl < 0 else nl
            spans.append((i, end))
            i = end + 1
            continue
        if ch == "/" and i + 1 < n and text[i + 1] == "*":
            end_c = text.find("*/", i + 2)
            end = n if end_c < 0 else end_c + 2
            spans.append((i, end))
            i = end
            continue
        if ch in ('"', "'"):
            quote = ch
            s = i
            i += 1
            while i < n:
                if text[i] == "\\":
                    i += 2
                    continue
                if text[i] == quote:
                    i += 1
                    break
                i += 1
            spans.append((s, i))
            continue
        i += 1
    return spans


def _in_spans(pos: int, spans: list[tuple[int, int]]) -> bool:
    for s, e in spans:
        if s <= pos < e:
            return True
        if s > pos:
            break
    return False


def _find_outer_macros(text: str) -> list[_MacroCall]:
    """Find non-overlapping top-level `PERM_*` / `KINTOUN_*` macro calls in `text`."""
    ignored = _comment_and_string_spans(text)
    calls: list[_MacroCall] = []
    pos = 0
    while pos < len(text):
        m = _MACRO_HEAD_RE.search(text, pos)
        if m is None:
            break
        if _in_spans(m.start(), ignored):
            pos = m.end()
            continue
        open_idx = m.end() - 1
        close_end = _scan_balanced_parens(text, open_idx)
        inner = text[open_idx + 1 : close_end - 1]
        calls.append(_MacroCall(name=m.group(1), start=m.start(), end=close_end, args=_split_macro_args(inner)))
        pos = close_end
    return calls


def _parse_int_bound(raw: str) -> int:
    s = raw.strip()
    return int(s, 0)


def _lineswap_options(body: str, rng: random.Random, max_perms: int = 24) -> list[str]:
    raw_lines = body.splitlines()
    code_lines = [ln for ln in raw_lines if ln.strip()]
    if len(code_lines) <= 1:
        return [body]
    joiner = "\n"
    if len(code_lines) <= 4 and math.factorial(len(code_lines)) <= max_perms:
        return [joiner.join(p) for p in itertools.permutations(code_lines)]

    seen: set[tuple[str, ...]] = {tuple(code_lines)}
    ordered: list[tuple[str, ...]] = [tuple(code_lines)]
    # Adjacent swaps + pairwise swaps first (highest match yield on C statement scheduling)
    for i in range(len(code_lines) - 1):
        cand = list(code_lines)
        cand[i], cand[i + 1] = cand[i + 1], cand[i]
        t = tuple(cand)
        if t not in seen:
            seen.add(t)
            ordered.append(t)
            if len(ordered) >= max_perms:
                return [joiner.join(p) for p in ordered]
    for i in range(len(code_lines)):
        for j in range(i + 2, len(code_lines)):
            cand = list(code_lines)
            cand[i], cand[j] = cand[j], cand[i]
            t = tuple(cand)
            if t not in seen:
                seen.add(t)
                ordered.append(t)
                if len(ordered) >= max_perms:
                    return [joiner.join(p) for p in ordered]
    attempts = 0
    while len(ordered) < max_perms and attempts < max_perms * 6:
        attempts += 1
        cand = list(code_lines)
        rng.shuffle(cand)
        t = tuple(cand)
        if t not in seen:
            seen.add(t)
            ordered.append(t)
    return [joiner.join(p) for p in ordered]


def _collapse_sameline(code: str) -> str:
    lines = [ln.strip() for ln in code.splitlines() if ln.strip()]
    return " ".join(lines)


def _preprocess_deterministic_wrappers(text: str) -> str:
    """Resolve `PERM_RANDOMIZE`, `PERM_IGNORE`, and `PERM_SAMELINE` wrappers cleanly."""
    calls = _find_outer_macros(text)
    if not calls:
        return text
    out: list[str] = []
    cur = 0
    for c in calls:
        out.append(text[cur : c.start])
        if c.name in ("PERM_RANDOMIZE", "PERM_IGNORE", "KINTOUN_IGNORE"):
            inner = ",".join(c.args)
            out.append(_preprocess_deterministic_wrappers(inner))
        elif c.name in ("PERM_SAMELINE", "PERM_FORCE_SAMELINE", "KINTOUN_SAMELINE"):
            inner = _preprocess_deterministic_wrappers(",".join(c.args))
            out.append(_collapse_sameline(inner))
        else:
            rebuilt_args = [_preprocess_deterministic_wrappers(a) for a in c.args]
            escaped_args = [a.replace(",", "(,)") if False else a for a in rebuilt_args]
            # Preserve original slice when nested deterministic wrappers didn't change args
            if list(rebuilt_args) == list(c.args):
                out.append(text[c.start : c.end])
            else:
                out.append(f"{c.name}(" + ", ".join(escaped_args) + ")")
        cur = c.end
    out.append(text[cur:])
    return "".join(out)


def count_perm_combinations(source: str) -> int:
    """Estimate total Cartesian product size of top-level `PERM_*` / `KINTOUN_*` macros in `source`."""
    cleaned = _preprocess_deterministic_wrappers(source)
    calls = _find_outer_macros(cleaned)
    if not calls:
        return 1
    total = 1
    once_groups: dict[str, int] = {}
    var_defs: dict[str, list[str]] = {}
    for c in calls:
        if c.name in ("PERM_GENERAL", "KINTOUN_ALT", "KINTOUN_GENERAL"):
            total *= max(1, sum(count_perm_combinations(a) for a in c.args))
        elif c.name in ("PERM_INT", "KINTOUN_INT") and len(c.args) == 2:
            lo, hi = _parse_int_bound(c.args[0]), _parse_int_bound(c.args[1])
            if hi < lo:
                lo, hi = hi, lo
            total *= max(1, hi - lo + 1)
        elif c.name in ("PERM_LINESWAP", "KINTOUN_LINESWAP"):
            raw_block = ",".join(c.args)
            n_lines = len([ln for ln in raw_block.splitlines() if ln.strip()])
            perm_n = math.factorial(n_lines) if n_lines <= 4 else 24
            total *= max(1, perm_n * count_perm_combinations(raw_block))
        elif c.name in ("PERM_ONCE", "KINTOUN_ONCE"):
            key = c.args[0].strip() if len(c.args) >= 2 else c.args[0].strip()
            once_groups[key] = once_groups.get(key, 0) + 1
        elif c.name in ("PERM_VAR", "KINTOUN_VAR") and len(c.args) >= 2:
            vname = c.args[0].strip()
            vexpr = ",".join(c.args[1:]).strip()
            sub_n = count_perm_combinations(vexpr)
            var_defs[vname] = [str(sub_n)]
            total *= max(1, sub_n)
    for count in once_groups.values():
        total *= max(1, count)
    return total


def _expand_single_level(
    text: str,
    *,
    max_variants: int,
    rng: random.Random,
) -> list[str]:
    calls = _find_outer_macros(text)
    if not calls:
        return [text]

    # Separate variable definitions (`PERM_VAR(k, val)`), `PERM_ONCE` groups, and independent site choices
    var_choices: dict[str, list[str]] = {}
    once_sites: dict[str, list[int]] = {}
    site_options: dict[int, list[str]] = {}

    for idx, c in enumerate(calls):
        if c.name in ("PERM_VAR", "KINTOUN_VAR"):
            if len(c.args) >= 2:
                vname = c.args[0].strip()
                val_raw = ",".join(c.args[1:]).strip()
                expanded_vals = expand_perm_macros_raw(val_raw, max_variants=min(64, max_variants), rng=rng)
                var_choices[vname] = expanded_vals or [val_raw]
                site_options[idx] = [""]
            else:
                site_options[idx] = [""]  # Filled from chosen `var_choices[vname]`
        elif c.name in ("PERM_ONCE", "KINTOUN_ONCE"):
            key = c.args[0].strip()
            once_sites.setdefault(key, []).append(idx)
        elif c.name in ("PERM_GENERAL", "KINTOUN_ALT", "KINTOUN_GENERAL"):
            opts: list[str] = []
            for arg in c.args:
                opts.extend(expand_perm_macros_raw(arg, max_variants=min(32, max_variants), rng=rng))
            site_options[idx] = opts or [""]
        elif c.name in ("PERM_INT", "KINTOUN_INT"):
            if len(c.args) != 2:
                raise ValueError(f"{c.name} expects (lo, hi), got {len(c.args)} args")
            lo, hi = _parse_int_bound(c.args[0]), _parse_int_bound(c.args[1])
            if hi < lo:
                lo, hi = hi, lo
            span = hi - lo + 1
            if span <= 64:
                site_options[idx] = [str(v) for v in range(lo, hi + 1)]
            else:
                vals = [lo, hi, (lo + hi) // 2]
                while len(vals) < 32:
                    v = rng.randint(lo, hi)
                    if v not in vals:
                        vals.append(v)
                site_options[idx] = [str(v) for v in vals]
        elif c.name in ("PERM_LINESWAP", "KINTOUN_LINESWAP"):
            raw_block = ",".join(c.args)
            sub_blocks = expand_perm_macros_raw(raw_block, max_variants=min(12, max_variants), rng=rng)
            swapped: list[str] = []
            for blk in sub_blocks:
                for p in _lineswap_options(blk, rng=rng, max_perms=min(24, max_variants)):
                    if p not in swapped:
                        swapped.append(p)
            site_options[idx] = swapped or [raw_block]
        else:
            site_options[idx] = [",".join(c.args)]

    # Build factor axes: each axis is `(kind, key, choices_count)`
    axes: list[tuple[str, Any, int]] = []
    for vname, vopts in var_choices.items():
        if len(vopts) > 1:
            axes.append(("var", vname, len(vopts)))
    for okey, idxs in once_sites.items():
        if len(idxs) > 1:
            axes.append(("once", okey, len(idxs)))
    for idx, opts in sorted(site_options.items()):
        if len(opts) > 1:
            axes.append(("site", idx, len(opts)))

    if not axes:
        return [_render_assignment(text, calls, var_choices, once_sites, site_options, {})]

    total_prod = 1
    for _, _, sz in axes:
        total_prod *= sz

    assignments: list[tuple[int, ...]] = []
    if total_prod <= max_variants:
        assignments = list(itertools.product(*(range(sz) for _, _, sz in axes)))
    else:
        seen_t: set[tuple[int, ...]] = set()
        base = tuple(0 for _ in axes)
        seen_t.add(base)
        assignments.append(base)
        # Coordinate-descent single-axis sweeps first so every individual macro option gets tested!
        for axis_i, (_, _, sz) in enumerate(axes):
            for val_i in range(1, sz):
                vec = list(base)
                vec[axis_i] = val_i
                t = tuple(vec)
                if t not in seen_t:
                    seen_t.add(t)
                    assignments.append(t)
                    if len(assignments) >= max_variants:
                        break
            if len(assignments) >= max_variants:
                break
        # Stratified random joint combinations for multi-site interactions
        attempts = 0
        while len(assignments) < max_variants and attempts < max_variants * 8:
            attempts += 1
            t = tuple(rng.randrange(sz) for _, _, sz in axes)
            if t not in seen_t:
                seen_t.add(t)
                assignments.append(t)

    rendered: list[str] = []
    seen_code: set[str] = set()
    for vec in assignments:
        choice_map = {(axes[i][0], axes[i][1]): vec[i] for i in range(len(axes))}
        cand = _render_assignment(text, calls, var_choices, once_sites, site_options, choice_map)
        cand = _preprocess_deterministic_wrappers(cand)
        if cand not in seen_code:
            seen_code.add(cand)
            rendered.append(cand)
    return rendered


def _render_assignment(
    text: str,
    calls: list[_MacroCall],
    var_choices: dict[str, list[str]],
    once_sites: dict[str, list[int]],
    site_options: dict[int, list[str]],
    choice_map: dict[tuple[str, Any], int],
) -> str:
    chosen_vars: dict[str, str] = {}
    for vname, vopts in var_choices.items():
        chosen_vars[vname] = vopts[choice_map.get(("var", vname), 0)]

    active_once_site: dict[str, int] = {}
    for okey, idxs in once_sites.items():
        winner_pos = choice_map.get(("once", okey), 0)
        active_once_site[okey] = idxs[min(winner_pos, len(idxs) - 1)]

    pieces: list[str] = []
    cur = 0
    for idx, c in enumerate(calls):
        pieces.append(text[cur : c.start])
        if c.name in ("PERM_VAR", "KINTOUN_VAR"):
            if len(c.args) == 1:
                vname = c.args[0].strip()
                pieces.append(chosen_vars.get(vname, ""))
        elif c.name in ("PERM_ONCE", "KINTOUN_ONCE"):
            okey = c.args[0].strip()
            stmt = ",".join(c.args[1:]) if len(c.args) >= 2 else c.args[0]
            if active_once_site.get(okey) == idx:
                pieces.append(stmt)
        else:
            opts = site_options.get(idx, [""])
            pick = choice_map.get(("site", idx), 0)
            pieces.append(opts[min(pick, len(opts) - 1)])
        cur = c.end
    pieces.append(text[cur:])
    out = "".join(pieces)
    # Substitute any remaining `PERM_VAR(name)` reads introduced inside nested `PERM_GENERAL` expansions
    if chosen_vars and ("PERM_VAR" in out or "KINTOUN_VAR" in out):
        sub_calls = _find_outer_macros(out)
        if any(sc.name in ("PERM_VAR", "KINTOUN_VAR") and len(sc.args) == 1 for sc in sub_calls):
            sub_pieces: list[str] = []
            scur = 0
            for sc in sub_calls:
                sub_pieces.append(out[scur : sc.start])
                if sc.name in ("PERM_VAR", "KINTOUN_VAR") and len(sc.args) == 1:
                    sub_pieces.append(chosen_vars.get(sc.args[0].strip(), ""))
                else:
                    sub_pieces.append(out[sc.start : sc.end])
                scur = sc.end
            sub_pieces.append(out[scur:])
            out = "".join(sub_pieces)
    return out


def expand_perm_macros_raw(
    source: str,
    *,
    max_variants: int = 256,
    rng: random.Random | None = None,
) -> list[str]:
    cleaned = _preprocess_deterministic_wrappers(source)
    if not _find_outer_macros(cleaned):
        return [cleaned]
    eff_rng = rng if rng is not None else random.Random(0)
    return _expand_single_level(cleaned, max_variants=max(1, max_variants), rng=eff_rng)


def expand_perm_macros(
    source: str,
    *,
    max_variants: int = 256,
    seed: int = 0,
) -> dict[str, Any]:
    """Expand `PERM_*` / `KINTOUN_*` macros into valid standalone C candidate strings.

    Returns metadata (`has_macros`, `total_combinations`, `exhaustive`, `variants`) so callers
    and `runner.py` can evaluate user-specified macro combinations and feed the top candidates
    directly into Kintoun's beam search.
    """
    if not has_perm_macros(source):
        return {
            "has_macros": False,
            "total_combinations": 1,
            "exhaustive": True,
            "variants": [source],
        }
    total = count_perm_combinations(source)
    rng = random.Random(seed)
    variants = expand_perm_macros_raw(source, max_variants=max_variants, rng=rng)
    return {
        "has_macros": True,
        "total_combinations": total,
        "exhaustive": total <= len(variants),
        "variants": variants,
    }
