"""Reproducible dev + held-out A/B benchmark runner and empirical prior learner (`kintoun bench`).

Allows contributors and project maintainers to evaluate engine changes, compiler flags, or strategy
mixes on explicit `dev` and `holdout` JSON manifests with strict regression checks, and to learn
compiler-specific mutation-family priors (`priors_<preset>.json`) from search & match outcomes.
"""
from __future__ import annotations

from collections import Counter
import json
from pathlib import Path
import time
from typing import Any

from kintoun.compiler import make_compiler
from kintoun.config import KintounConfig
from kintoun.search.runner import run_search
from kintoun.targets import load_target_from_config, load_target_from_object


def run_benchmark(
    cfg: KintounConfig,
    manifest_path: Path,
    *,
    budget_s: float = 20.0,
    max_candidates: int = 250,
    workers: int = 2,
    baseline_report: Path | None = None,
) -> dict[str, Any]:
    """Run Kintoun over a JSON benchmark manifest and check for regressions against `baseline_report`."""
    entries = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
    if isinstance(entries, dict):
        entries = entries.get("functions") or entries.get("items") or []
    if not isinstance(entries, list):
        raise ValueError("benchmark manifest must be a JSON list or {'functions': [...]}")

    cache_dir = cfg.resolve_path(cfg.search.cache_dir)
    priors_path = cfg.resolve_path(cfg.search.priors_file)
    ctx_cfg = None
    rows: list[dict[str, Any]] = []
    t0 = time.monotonic()

    for item in entries:
        func_name = str(item.get("func") or item.get("name") or "")
        src_text = item.get("code")
        if src_text is None and item.get("source"):
            sp = Path(item["source"])
            if not sp.is_absolute():
                sp = cfg.root / sp
            src_text = sp.read_text(encoding="utf-8")
        if not src_text:
            continue

        if item.get("target"):
            tp = Path(item["target"])
            if not tp.is_absolute():
                tp = cfg.root / tp
            ctx, tf = load_target_from_object(tp, func_name or None)
        else:
            if ctx_cfg is None:
                ctx_cfg = load_target_from_config(cfg)
            ctx = ctx_cfg
            tf = ctx.resolve_function(func_name)

        compiler = make_compiler(cfg, va=tf.va)

        res = run_search(
            source=src_text,
            target_fn=tf,
            ctx=ctx,
            compiler=compiler,
            budget_s=budget_s,
            max_candidates=max_candidates,
            strategies=cfg.search.strategies,
            workers=workers,
            cache_dir=cache_dir,
            priors_path=priors_path,
            forbid_asm=cfg.search.forbid_asm,
            seed=0,
        )
        best = res.get("best") or {}
        aligned = float((best.get("search") or {}).get("aligned_pct") or 0.0)
        rows.append(
            {
                "name": tf.name,
                "addr": f"0x{tf.va:08X}",
                "verified": bool(res.get("verified")),
                "status": best.get("status", "error"),
                "aligned_pct": round(aligned, 2),
                "different_bytes": best.get("different_bytes"),
                "winning_strategy": best.get("strategy"),
                "evaluated": res.get("evaluated"),
                "elapsed_s": res.get("elapsed_s"),
            }
        )

    n = max(1, len(rows))
    verified_count = sum(1 for r in rows if r["verified"])
    compiled_count = sum(1 for r in rows if r["status"] in ("verified", "mismatch", "unresolved"))
    mean_aligned = round(sum(r["aligned_pct"] for r in rows) / n, 2) if rows else 0.0

    regressions: list[str] = []
    if baseline_report and Path(baseline_report).is_file():
        base_doc = json.loads(Path(baseline_report).read_text(encoding="utf-8"))
        base_by_name = {r["name"]: r for r in (base_doc.get("results") or [])}
        for r in rows:
            b = base_by_name.get(r["name"])
            if b and b.get("verified") and not r["verified"]:
                regressions.append(f"{r['name']}: lost VERIFIED match")

    return {
        "manifest": str(manifest_path),
        "functions": len(rows),
        "compiled": compiled_count,
        "verified": verified_count,
        "verified_pct": round(100.0 * verified_count / n, 2) if rows else 0.0,
        "mean_aligned_pct": mean_aligned,
        "regressions": regressions,
        "promotion_eligible": len(regressions) == 0,
        "elapsed_s": round(time.monotonic() - t0, 3),
        "results": rows,
    }


def learn_priors(notes_jsonl: Path, bench_reports: list[Path] | None = None, out_path: Path | None = None) -> dict[str, float]:
    """Compute empirical `[0.5, 5.0]` mutation-family prior weights from `notes.jsonl` and bench wins."""
    wins: Counter[str] = Counter()
    if notes_jsonl.is_file():
        for line in notes_jsonl.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                rec = json.loads(line)
            except ValueError:
                continue
            cat = str(rec.get("fix_category") or "").strip()
            if cat and cat not in ("input", "hand"):
                wins[cat] += 1

    for rep in bench_reports or []:
        if Path(rep).is_file():
            doc = json.loads(Path(rep).read_text(encoding="utf-8"))
            for row in doc.get("results") or []:
                strat = str(row.get("winning_strategy") or "").strip()
                if row.get("verified") and strat and strat != "input":
                    wins[strat] += 2

    priors: dict[str, float] = {}
    if wins:
        peak = max(wins.values())
        for fam, count in sorted(wins.items()):
            priors[fam] = round(1.0 + 3.0 * (count / max(1, peak)), 3)

    if out_path is not None:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(priors, indent=2), encoding="utf-8")
    return priors
