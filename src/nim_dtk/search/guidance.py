"""Score-guided real-C search priorities and one-site repair proposals."""
from __future__ import annotations

import json
from pathlib import Path
import re
import time
from typing import Any, Iterator

from nim_dtk.search import mutations as engine_mutations

REGISTER = (
    "register", "decl_order", "temp_merge", "inline_temp", "var_split",
    "split_load", "hoist_cse", "swap_stmts", "alias_make", "commute",
)
BRANCH = ("if_invert", "cond_rewrite", "loop_shape", "return_style", "bool_phi")
TYPES = (
    "local_type", "param_type", "field_type", "cast_strip", "callee_proto",
    "float_expr", "fp_prototype", "extern_const",
)
ORDER = ("swap_stmts", "ordered_stores", "decl_order", "inline_temp", "split_load")

_prior_cache: dict[str, tuple[float, dict[str, float]]] = {}


def load_priors(priors_path: Path | None = None, metrics_path: Path | None = None) -> dict[str, float]:
    """Load optional learned family weights from JSON files."""
    cache_key = f"{priors_path}|{metrics_path}"
    now = time.monotonic()
    cached = _prior_cache.get(cache_key)
    if cached and now - cached[0] < 30.0:
        return cached[1]
    raw: dict[str, Any] = {}
    if priors_path is not None:
        try:
            raw = json.loads(priors_path.read_text())
        except (OSError, ValueError):
            raw = {}
    values = {
        name: float(weight)
        for name, weight in raw.items()
        if name != "_hist" and isinstance(weight, (int, float)) and 0 < weight <= 10
    }
    if metrics_path is not None:
        try:
            outcomes = json.loads(metrics_path.read_text())["windows"]["21600"]["family_outcomes"]
        except (OSError, ValueError, KeyError, TypeError):
            outcomes = {}
        for name, row in outcomes.items():
            trials = row.get("trials", 0)
            if trials < 8:
                continue
            successes = row.get("improvements", 0)
            failures = row.get("compile_errors", 0)
            learned = min(2.0, max(0.2, 12 * (successes + 1) / (trials + 10)))
            learned *= max(0.25, 1 - failures / trials)
            blend = trials / (trials + 30)
            values[name] = (1 - blend) * values.get(name, 1.0) + blend * learned
    _prior_cache[cache_key] = (now, values)
    return values


def near_miss(result: dict[str, Any] | None) -> bool:
    if not result or result.get("status") != "mismatch":
        return False
    search = result.get("search") or {}
    pct = search.get("normalized_pct", 0)
    if isinstance(pct, (int, float)) and pct >= 80:
        return True
    target = result.get("target_bytes") or 0
    difference = result.get("different_bytes")
    return bool(target and isinstance(difference, int) and difference <= target * 0.2)


def priorities(result: dict[str, Any] | None) -> tuple[str, ...]:
    """Order mutation families by strict score hints while retaining exploration."""
    hints = " ".join((result or {}).get("search", {}).get("hints", [])).lower()
    preferred: list[str] = []
    if "register allocation" in hints or "callee-saved" in hints or "extra mr" in hints:
        preferred.extend(REGISTER)
    if "branch polarity" in hints or "condition register" in hints:
        preferred.extend(BRANCH)
    if "evaluation order" in hints:
        preferred.extend(ORDER)
    if any(w in hints for w in ("signedness", "field width", "float vs double", "zero-extends", "sign-extends")):
        preferred.extend(TYPES)
    if "global addressing" in hints:
        preferred.extend(("global_section", "field_type", "cast_strip"))
    if near_miss(result) and not preferred:
        preferred.extend(REGISTER + ORDER + BRANCH)
    return tuple(dict.fromkeys(preferred))


def repair_proposals(source: str, result: dict[str, Any] | None) -> Iterator[tuple[str, str]]:
    """Yield exact one-site edits suggested by relocated-byte repair hypotheses."""
    seen: set[str] = set()
    for repair in (result or {}).get("repairs", [])[:16]:
        category = repair.get("category", "repair")
        edit = repair.get("suggested_edit") or {}
        old, new = edit.get("old"), edit.get("new")
        if isinstance(old, str) and old and isinstance(new, str) and old != new and source.count(old) == 1:
            candidate = source.replace(old, new, 1)
            if candidate not in seen:
                seen.add(candidate)
                yield "target_" + category, candidate
        if category not in ("field_offset", "offset"):
            continue
        try:
            before, after = int(str(repair["ours"]), 0), int(str(repair["target"]), 0)
        except (KeyError, TypeError, ValueError):
            continue
        for match in re.finditer(r"M2C_FIELD\([^,\n]+,\s*[^,\n]+,\s*(0x[\da-fA-F]+|\d+)\s*\)", source):
            offset = re.search(r"(0x[\da-fA-F]+|\d+)\s*\)$", match[0])
            if not offset:
                continue
            token = offset[1]
            value = int(token, 16 if token.lower().startswith("0x") else 10)
            if value != before:
                continue
            start = match.start() + offset.start(1)
            end = match.start() + offset.end(1)
            candidate = source[:start] + hex(after) + source[end:]
            if candidate not in seen:
                seen.add(candidate)
                yield "target_offset", candidate


def recovery_proposals(source: str) -> Iterator[tuple[str, str]]:
    """Small set of typed fixes for malformed decompiler output."""
    for text in [
        *engine_mutations.recover_pointer_seeds(source),
        *engine_mutations.recover_load_seeds(source),
    ]:
        if text != source:
            yield "compile_recovery", text
