"""Real-C live-range register permuter for strict near misses.

Generates valid C source variants targeting register allocation and live-range
ordering. The verifier compiles, caches, and strictly scores each candidate
before accepting any improvement.
"""
from __future__ import annotations

from itertools import islice
import json
from pathlib import Path
import re
from typing import Any, Iterator

FAMILIES = (
    "m_var_split",
    "m_temp_merge",
    "m_alias_make",
    "m_if_invert",
    "m_loop_shape",
    "m_inline_temp",
    "m_split_load",
    "m_cast_strip",
    "m_decl_order",
    "m_register",
)
COMPOSE = (
    ("m_var_split", "m_temp_merge"),
    ("m_temp_merge", "m_var_split"),
    ("m_alias_make", "m_temp_merge"),
    ("m_loop_shape", "m_var_split"),
    ("m_decl_order", "m_inline_temp"),
    ("m_split_load", "m_cast_strip"),
)
DECL = re.compile(r"^(    )(s32|u32|s16|u16|s8|u8|int|float|f32|f64|double)\s+(\w+);$")


def live_outcomes(metrics_path: Path | None = None) -> dict[str, Any]:
    """Read optional aggregate family outcome counts; missing file is harmless."""
    if metrics_path is None:
        return {}
    try:
        rows = json.loads(metrics_path.read_text())["windows"]["3600"]["family_outcomes"]
        return rows if isinstance(rows, dict) else {}
    except (OSError, ValueError, KeyError, TypeError):
        return {}


def ranked_families(outcomes: dict[str, Any]) -> tuple[str, ...]:
    """Rank families by strict improvements per trial, penalizing compile errors."""
    def _score(name: str) -> tuple[float, int]:
        base = name.removeprefix("m_")
        row = outcomes.get("reg_" + base, {})
        if row.get("trials", 0) < 32:
            row = outcomes.get(base, {})
        trials = max(0, row.get("trials", 0))
        improvements = max(0, min(trials, row.get("improvements", 0)))
        errors = max(0, min(trials, row.get("compile_errors", 0)))
        return -((improvements + 1.0) / (trials + 30.0) * (1.0 - 0.5 * errors / (trials + 10.0))), FAMILIES.index(name)

    return tuple(sorted(FAMILIES, key=_score))


def _decl_rotations(source: str, limit: int = 8) -> Iterator[tuple[str, str]]:
    lines = source.split("\n")
    start = next((i + 1 for i, line in enumerate(lines) if line.rstrip().endswith("{") and "(" in line), 0)
    idx = [i for i in range(start, min(len(lines), start + 40)) if DECL.match(lines[i])]
    if len(idx) < 2:
        return
    emitted = 0
    for shift in range(1, min(len(idx), 5)):
        if emitted >= limit:
            break
        out = list(lines)
        vals = [lines[i] for i in idx]
        rotated = vals[shift:] + vals[:shift]
        for pos, val in zip(idx, rotated):
            out[pos] = val
        text = "\n".join(out)
        if text != source:
            emitted += 1
            yield "reg_decl_rot", text


def variants(
    source: str,
    mut_mod: Any,
    limit: int = 24,
    metrics_path: Path | None = None,
) -> Iterator[tuple[str, str]]:
    """Yield up to `limit` real-C live-range variants for register-allocation near misses."""
    if limit <= 0:
        return
    seen = {source}
    emitted = 0
    outcomes = live_outcomes(metrics_path)
    ordered = ranked_families(outcomes)

    for family, text in _decl_rotations(source, limit=min(4, limit)):
        if text not in seen:
            seen.add(text)
            emitted += 1
            yield family, text
            if emitted >= limit:
                return

    first_pass: dict[str, list[str]] = {}
    for name in ordered:
        fn = getattr(mut_mod, name, None)
        if fn is None:
            continue
        tag = "reg_" + name.removeprefix("m_")
        bucket: list[str] = []
        for _, text in islice(fn(source), 6):
            if text not in seen:
                seen.add(text)
                bucket.append(text)
                emitted += 1
                yield tag, text
                if emitted >= limit:
                    return
        if bucket:
            first_pass[name] = bucket

    for first_name, second_name in COMPOSE:
        second_fn = getattr(mut_mod, second_name, None)
        if second_fn is None or first_name not in first_pass:
            continue
        tag = f"reg_{first_name.removeprefix('m_')}+{second_name.removeprefix('m_')}"
        for base_text in first_pass[first_name][:2]:
            for _, text in islice(second_fn(base_text), 2):
                if text not in seen:
                    seen.add(text)
                    emitted += 1
                    yield tag, text
                    if emitted >= limit:
                        return
