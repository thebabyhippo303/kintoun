"""Zero-dependency per-ISA opcode-bigram TF-IDF similarity search and logistic match-probability model.

Replaces heavyweight 3 GB PyTorch/HuggingFace embedding pipelines with a sub-second pure-stdlib
engine supporting PowerPC (`ppc_elf`), MIPS (`mips_elf`), and ARM/Thumb (`arm_elf`):
  - `extract_asm_signature`: decodes normalized register-invariant opcode unigrams, opcode bigrams,
    control-flow bigrams, and structural ratios per ISA.
  - `find_similar_functions`: TF-IDF cosine-similarity search across matched functions in `src/`,
    returning top-K structurally nearest `(asm, C)` examples plus solved incoming callers.
  - `fit_project_difficulty_model` & `predict_match_probability`: pure-stdlib L2-regularized
    logistic regression trained on solved vs unsolved functions in the active project (with smooth
    analytical fallback when `< 6` labeled functions exist).
"""
from __future__ import annotations

from collections import Counter
import hashlib
import json
import math
from pathlib import Path
import re
import struct
from typing import Any

from kintoun.arch.arm_disasm import disasm_a32, disasm_thumb16, disasm_thumb32, is_thumb32_hw1
from kintoun.arch.mips_disasm import disasm_mips_word
from kintoun.arch.ppc_disasm import disasm_ppc_word
from kintoun.inspect_fn import decode_target_features
from kintoun.project_io import _extract_c_function_blocks
from kintoun.targets import TargetContext, TargetFunction

FEATURE_NAMES: tuple[str, ...] = (
    "log2_insns",
    "branch_density",
    "loop_count",
    "switch_flag",
    "call_density",
    "indirect_call_flag",
    "float_density",
    "int_float_conv",
    "leaf_flag",
    "blocker_flag",
)

# Calibrated prior weights (used before a repo accumulates >= 6 labeled outcomes)
_PRIOR_WEIGHTS: tuple[float, ...] = (
    -0.55,  # log2_insns (larger = lower immediate match rate)
    -2.20,  # branch_density
    -0.45,  # loop_count
    -1.35,  # switch_flag
    -1.40,  # call_density
    -1.10,  # indirect_call_flag
    -1.50,  # float_density
    -0.90,  # int_float_conv
    +0.65,  # leaf_flag (leaf functions match much faster)
    -4.00,  # blocker_flag (non-plain-C)
)
_PRIOR_BIAS: float = 2.65


def _opcode_stream(target_fn: TargetFunction, ctx: TargetContext) -> list[str]:
    """Decode normalized mnemonic sequence for `target_fn` using dedicated per-ISA stdlib decoders."""
    data = target_fn.data
    arch = ctx.arch
    ops: list[str] = []
    if arch in ("mips", "mips_elf"):
        fmt = "<I" if ctx.endian != "big" else ">I"
        for off in range(0, len(data) - (len(data) % 4), 4):
            w = struct.unpack_from(fmt, data, off)[0]
            if w == 0:
                ops.append("nop")
            else:
                mn, _ = disasm_mips_word(w, target_fn.va + off)
                ops.append(mn)
    elif arch in ("arm", "arm_elf"):
        if target_fn.is_thumb or ctx.thumb:
            data_ranges = [(s, e) for s, e, mode in (target_fn.intervals or ()) if mode == "$d"]
            off = 0
            end = len(data)
            while off + 2 <= end:
                if any(s <= off < e for s, e in data_ranges) and off + 4 <= end:
                    off += 4
                    continue
                hw1 = struct.unpack_from("<H", data, off)[0]
                if is_thumb32_hw1(hw1) and off + 4 <= end:
                    hw2 = struct.unpack_from("<H", data, off + 2)[0]
                    mn, _ = disasm_thumb32(hw1, hw2, target_fn.va + off)
                    ops.append(mn)
                    off += 4
                else:
                    mn, _ = disasm_thumb16(hw1, target_fn.va + off)
                    ops.append(mn)
                    off += 2
        else:
            fmt = "<I" if ctx.endian != "big" else ">I"
            for off in range(0, len(data) - (len(data) % 4), 4):
                w = struct.unpack_from(fmt, data, off)[0]
                mn, _ = disasm_a32(w, target_fn.va + off)
                ops.append(mn)
    else:
        for off in range(0, len(data) - (len(data) % 4), 4):
            w = struct.unpack_from(">I", data, off)[0]
            mn, _ = disasm_ppc_word(w, target_fn.va + off)
            ops.append(mn)
    return ops


def extract_numeric_features(target_fn: TargetFunction, ctx: TargetContext) -> list[float]:
    """Extract the 10-element structural feature vector used by logistic calibration & 2D Atlas projection."""
    dec = decode_target_features(target_fn, ctx)
    f = dec["features"]
    ninstr = max(1, int(f.get("ninstr", max(1, target_fn.size // 4))))
    calls = float(f.get("calls", 0))
    ind_calls = float(f.get("indirect_calls", 0))
    return [
        math.log2(ninstr + 1.0),
        float(f.get("cond_branches", 0) + f.get("jumps", 0)) / ninstr,
        min(6.0, float(f.get("loops", 0))),
        1.0 if f.get("switches", 0) > 0 else 0.0,
        calls / ninstr,
        1.0 if ind_calls > 0 else 0.0,
        float(f.get("float_ops", 0)) / ninstr,
        min(3.0, float(f.get("int_float_conv", 0))),
        1.0 if (calls == 0 and ind_calls == 0) else 0.0,
        1.0 if dec["blockers"] else 0.0,
    ]


def extract_asm_signature(target_fn: TargetFunction, ctx: TargetContext) -> Counter[str]:
    """Build sparse bag-of-ngrams (`op:<mn>`, `bg:<mn1>_<mn2>`) for fast TF-IDF cosine similarity."""
    ops = _opcode_stream(target_fn, ctx)
    counts: Counter[str] = Counter()
    for mn in ops:
        counts[f"op:{mn}"] += 1
    for i in range(len(ops) - 1):
        counts[f"bg:{ops[i]}>{ops[i + 1]}"] += 1
    # Bucket length so tiny getters don't match 400-instruction state machines
    n_bucket = "xs" if len(ops) < 10 else "sm" if len(ops) < 32 else "md" if len(ops) < 96 else "lg"
    counts[f"sz:{n_bucket}"] += 2
    return counts


def _sigmoid(z: float) -> float:
    if z >= 35.0:
        return 1.0
    if z <= -35.0:
        return 0.0
    return 1.0 / (1.0 + math.exp(-z))


def fit_project_difficulty_model(
    samples: list[tuple[list[float], int]],
    *,
    l2_reg: float = 0.25,
    lr: float = 0.08,
    epochs: int = 220,
) -> dict[str, Any]:
    """Train pure-stdlib L2-regularized logistic regression (`y=1` matched, `y=0` timed-out/quarantined).

    Falls back to `_PRIOR_WEIGHTS` when fewer than 6 labeled examples or only 1 class is present.
    """
    pos = sum(1 for _, y in samples if y == 1)
    neg = sum(1 for _, y in samples if y == 0)
    if len(samples) < 6 or pos == 0 or neg == 0:
        return {
            "trained": False,
            "sample_count": len(samples),
            "weights": list(_PRIOR_WEIGHTS),
            "bias": _PRIOR_BIAS,
            "feature_names": list(FEATURE_NAMES),
        }

    dim = len(FEATURE_NAMES)
    # Standardize features for fast, stable gradient convergence
    means = [sum(x[j] for x, _ in samples) / len(samples) for j in range(dim)]
    stds = [
        max(1e-6, math.sqrt(sum((x[j] - means[j]) ** 2 for x, _ in samples) / len(samples)))
        for j in range(dim)
    ]
    norm_x = [[(x[j] - means[j]) / stds[j] for j in range(dim)] for x, _ in samples]
    ys = [float(y) for _, y in samples]

    w = [0.0] * dim
    b = 0.0
    n = float(len(samples))
    for _ in range(epochs):
        grad_w = [0.0] * dim
        grad_b = 0.0
        for xi, yi in zip(norm_x, ys):
            pred = _sigmoid(sum(w[j] * xi[j] for j in range(dim)) + b)
            err = pred - yi
            for j in range(dim):
                grad_w[j] += err * xi[j]
            grad_b += err
        for j in range(dim):
            w[j] -= lr * ((grad_w[j] / n) + l2_reg * w[j])
        b -= lr * (grad_b / n)

    # Unscale weights back to raw feature space: `w_raw[j] = w[j] / stds[j]`
    raw_w = [w[j] / stds[j] for j in range(dim)]
    raw_b = b - sum(w[j] * means[j] / stds[j] for j in range(dim))
    return {
        "trained": True,
        "sample_count": len(samples),
        "positive": pos,
        "negative": neg,
        "weights": [round(v, 6) for v in raw_w],
        "bias": round(raw_b, 6),
        "feature_names": list(FEATURE_NAMES),
    }


def predict_match_probability(features: list[float], model: dict[str, Any] | None = None) -> float:
    """Predict `[0.01..0.99]` match probability from `extract_numeric_features`."""
    weights = (model or {}).get("weights") or _PRIOR_WEIGHTS
    bias = float((model or {}).get("bias", _PRIOR_BIAS))
    z = sum(float(w) * float(x) for w, x in zip(weights, features)) + bias
    return round(max(0.01, min(0.99, _sigmoid(z))), 3)


def index_matched_c_functions(src_dir: Path | None, max_files: int = 400) -> dict[str, tuple[str, str]]:
    """Scan `src_dir` (both single-function and multi-function `.c` files) -> `{func_name: (file_name, c_code)}`."""
    if src_dir is None or not Path(src_dir).is_dir():
        return {}
    matched: dict[str, tuple[str, str]] = {}
    for cfile in sorted(Path(src_dir).rglob("*.c"))[:max_files]:
        try:
            txt = cfile.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for fname, fdef in _extract_c_function_blocks(txt).items():
            if len(fdef) <= 2400 and fname not in matched:
                matched[fname] = (cfile.name, fdef)
    return matched


def find_similar_functions(
    target_fn: TargetFunction,
    ctx: TargetContext,
    *,
    src_dir: Path | None = None,
    incoming_callers: list[str] | None = None,
    top_k: int = 3,
) -> list[dict[str, Any]]:
    """Retrieve top-K structurally similar solved `(asm, C)` functions from `src_dir` via TF-IDF cosine similarity."""
    matched_map = index_matched_c_functions(src_dir)
    if not matched_map:
        return []

    caller_set = set(incoming_callers or [])
    docs: dict[str, Counter[str]] = {}
    target_sig = extract_asm_signature(target_fn, ctx)
    docs[target_fn.name] = target_sig

    for fname in matched_map:
        if fname == target_fn.name:
            continue
        if fname in ctx.funcs:
            try:
                peer_tf = ctx.resolve_function(fname)
                docs[fname] = extract_asm_signature(peer_tf, ctx)
            except Exception:
                continue

    results: list[dict[str, Any]] = []
    if len(docs) > 1:
        n_docs = float(len(docs))
        df: Counter[str] = Counter()
        for sig in docs.values():
            for term in sig:
                df[term] += 1
        idf = {term: math.log((n_docs + 1.0) / (cnt + 1.0)) + 1.0 for term, cnt in df.items()}

        def _tfidf_vec(sig: Counter[str]) -> tuple[dict[str, float], float]:
            total = max(1, sum(sig.values()))
            vec = {t: (c / total) * idf.get(t, 1.0) for t, c in sig.items()}
            norm = math.sqrt(sum(v * v for v in vec.values())) or 1.0
            return vec, norm

        t_vec, t_norm = _tfidf_vec(target_sig)
        scored: list[tuple[float, str]] = []
        for fname, sig in docs.items():
            if fname == target_fn.name:
                continue
            p_vec, p_norm = _tfidf_vec(sig)
            dot = sum(v * p_vec.get(t, 0.0) for t, v in t_vec.items())
            sim = dot / (t_norm * p_norm)
            scored.append((sim, fname))

        scored.sort(key=lambda item: (-item[0], item[1]))
        for sim, fname in scored[:top_k]:
            file_name, c_def = matched_map[fname]
            results.append(
                {
                    "file": file_name,
                    "function": fname,
                    "similarity": round(sim, 3),
                    "calls_target": fname in caller_set,
                    "snippet": c_def[:850],
                }
            )

    # Also append up to 2 matched incoming callers not already in `results` (shows real call-site argument types!)
    seen_fns = {r["function"] for r in results}
    for caller in incoming_callers or []:
        if caller in matched_map and caller not in seen_fns:
            file_name, c_def = matched_map[caller]
            results.append(
                {
                    "file": file_name,
                    "function": caller,
                    "similarity": 1.0 if caller in caller_set else 0.0,
                    "calls_target": True,
                    "snippet": c_def[:850],
                }
            )
            seen_fns.add(caller)
            if len(results) >= top_k + 2:
                break

    # Fallback when `src_dir` functions are standalone and not listed in `ctx.funcs`
    if not results:
        for fname, (file_name, c_def) in list(matched_map.items())[: min(2, top_k)]:
            if fname != target_fn.name:
                results.append(
                    {
                        "file": file_name,
                        "function": fname,
                        "similarity": 0.0,
                        "calls_target": fname in caller_set,
                        "snippet": c_def[:700],
                    }
                )
    return results
