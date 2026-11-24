"""Optional single-user and multi-agent MCP server for Kintoun."""
from __future__ import annotations

import json
import os
from pathlib import Path

from kintoun import __version__
from kintoun.candidates import CandidateStore
from kintoun.closer import close_near_miss
from kintoun.compiler import make_compiler
from kintoun.config import SEARCH_MODES, load_config, parse_duration_s
from kintoun.inspect_fn import build_context_pack, check_function
from kintoun.queue import WorkQueue
from kintoun.search.runner import run_search
from kintoun.targets import load_target_from_config, load_target_from_object
from kintoun.verify import verify_source


def run_mcp(config_path: Path | None = None) -> None:
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError as exc:
        raise RuntimeError("MCP support requires optional dependency: pip install 'kintoun[mcp]'") from exc

    cfg = load_config(config_path)
    cache_dir = cfg.resolve_path(cfg.search.cache_dir) or (cfg.root / ".kintoun" / "cache")
    kintoun_dir = cache_dir.parent
    store = CandidateStore(cache_dir)
    queue = WorkQueue(kintoun_dir)
    default_agent = os.environ.get("KINTOUN_AGENT", f"mcp-{os.getpid()}")
    mcp = FastMCP("kintoun")

    def _load(func: str, target_obj: str):
        if target_obj:
            return load_target_from_object(Path(target_obj), func or None)
        ctx = load_target_from_config(cfg)
        return ctx, ctx.resolve_function(func)

    @mcp.tool()
    def kintoun_verify(source_path: str, func: str = "", target_obj: str = "", lines: int = 24) -> str:
        """Compile a C file and strictly verify it against a target function or .o file."""
        ctx, tf = _load(func, target_obj)
        compiler = make_compiler(cfg)
        res = verify_source(
            Path(source_path).read_text(encoding="utf-8"),
            tf,
            ctx,
            compiler,
            lines=lines,
            forbid_asm=cfg.search.forbid_asm,
        )
        return json.dumps(res, indent=2)

    @mcp.tool()
    def kintoun_permute(
        source_path: str,
        func: str = "",
        target_obj: str = "",
        budget_s: float | str = 180.0,
        max_candidates: int = 2500,
        mode: str = "",
        plateau: int = 0,
        governed: bool = True,
    ) -> str:
        """Run Kintoun real-C mutation and register-permutation search against a target function."""
        ctx, tf = _load(func, target_obj)
        compiler = make_compiler(cfg)
        mkey = mode.strip().lower()
        if mkey in SEARCH_MODES:
            eff_budget, eff_cands = SEARCH_MODES[mkey]
        else:
            eff_budget = parse_duration_s(budget_s, cfg.search.budget_s)
            eff_cands = max_candidates
        res = run_search(
            source=Path(source_path).read_text(encoding="utf-8"),
            target_fn=tf,
            ctx=ctx,
            compiler=compiler,
            budget_s=eff_budget,
            max_candidates=eff_cands,
            strategies=cfg.search.strategies,
            workers=cfg.search.workers,
            cache_dir=cache_dir,
            priors_path=cfg.resolve_path(cfg.search.priors_file),
            forbid_asm=cfg.search.forbid_asm,
            plateau=plateau,
            governed=governed,
        )
        best = res.get("best") or {}
        if best.get("code"):
            res["best_candidate_id"] = store.put(tf.name, tf.va, best["code"], best, strategy=best.get("strategy", "permute"))
            aligned = float((best.get("search") or {}).get("aligned_pct") or 0.0)
            queue.record_progress(tf.name, aligned)
        return json.dumps(res, indent=2)

    @mcp.tool()
    def kintoun_info() -> str:
        """Return active Kintoun version and project configuration."""
        return json.dumps(
            {
                "version": __version__,
                "project": cfg.project_name,
                "root": str(cfg.root),
                "compiler_preset": cfg.compiler.preset,
                "target_arch": cfg.target.arch,
            },
            indent=2,
        )

    @mcp.tool()
    def kintoun_check(func: str = "", target_obj: str = "") -> str:
        """Fast structural check for non-plain-C instructions (paired-single, COP0/VFPU, MCR/SWI, traps)."""
        ctx, tf = _load(func, target_obj)
        return json.dumps(check_function(tf, ctx), indent=2)

    @mcp.tool()
    def kintoun_context_pack(func: str = "", target_obj: str = "", max_disasm_lines: int = 64) -> str:
        """Build a compact ~1.5k-token one-call brief (disassembly, difficulty, callees, globals, hints)."""
        ctx, tf = _load(func, target_obj)
        return json.dumps(build_context_pack(tf, ctx, cfg, max_disasm_lines=max_disasm_lines), indent=2)

    @mcp.tool()
    def kintoun_score_candidate(
        code: str,
        func: str = "",
        target_obj: str = "",
        lines: int = 24,
        include_code: bool = False,
    ) -> str:
        """Score inline C code (using shared cache & governor) and return a `candidate_id` for surgical edits."""
        ctx, tf = _load(func, target_obj)
        compiler = make_compiler(cfg)
        res = store.score_one(
            code,
            tf,
            ctx,
            compiler,
            lines=lines,
            forbid_asm=cfg.search.forbid_asm,
            include_code=include_code,
        )
        aligned = float(((res.get("search") or {}).get("aligned_pct")) or 0.0)
        queue.record_progress(tf.name, aligned)
        return json.dumps(res, indent=2)

    @mcp.tool()
    def kintoun_revise_candidate(
        candidate_id: str,
        edits: list[dict[str, str]],
        func: str = "",
        target_obj: str = "",
        lines: int = 24,
        include_code: bool = False,
    ) -> str:
        """Apply exact single-match `[{'old': ..., 'new': ...}]` surgical edits to `candidate_id` and re-score."""
        ctx, tf = _load(func, target_obj)
        compiler = make_compiler(cfg)
        res = store.revise(
            candidate_id,
            edits,
            tf,
            ctx,
            compiler,
            lines=lines,
            forbid_asm=cfg.search.forbid_asm,
            include_code=include_code,
        )
        aligned = float(((res.get("search") or {}).get("aligned_pct")) or 0.0)
        queue.record_progress(tf.name, aligned)
        return json.dumps(res, indent=2)

    @mcp.tool()
    def kintoun_score_candidates(codes: list[str], func: str = "", target_obj: str = "") -> str:
        """Compile and score 2..16 candidate C formulations in parallel and return them ranked best-first."""
        ctx, tf = _load(func, target_obj)
        compiler = make_compiler(cfg)
        return json.dumps(store.score_batch(codes, tf, ctx, compiler, forbid_asm=cfg.search.forbid_asm), indent=2)

    @mcp.tool()
    def kintoun_close_near_miss(
        code: str = "",
        candidate_id: str = "",
        func: str = "",
        target_obj: str = "",
        budget_s: float = 60.0,
    ) -> str:
        """Classify a strict asm diff and run targeted 1-to-2-pass zero-LLM near-miss closing."""
        ctx, tf = _load(func, target_obj)
        compiler = make_compiler(cfg)
        seed = code
        if not seed and candidate_id:
            rec = store.get(candidate_id)
            if rec:
                seed = rec["code"]
        res = close_near_miss(
            seed,
            tf,
            ctx,
            compiler,
            budget_s=budget_s,
            cache_dir=cache_dir,
            priors_path=cfg.resolve_path(cfg.search.priors_file),
            forbid_asm=cfg.search.forbid_asm,
        )
        return json.dumps(res, indent=2)

    @mcp.tool()
    def kintoun_claim_next(agent_id: str = "", prefer_tier: str = "", max_difficulty: int = 100) -> str:
        """Claim the next pending function from `.kintoun/queue.sqlite3` with its independent chess clock."""
        ctx = load_target_from_config(cfg)
        if queue.status()["counts"]["pending"] == 0 and queue.status()["counts"]["done"] == 0:
            queue.sync_from_context(ctx)
        aid = agent_id.strip() or default_agent
        return json.dumps(queue.claim_next(aid, prefer_tier=prefer_tier, max_difficulty=max_difficulty), indent=2)

    @mcp.tool()
    def kintoun_clock(agent_id: str = "") -> str:
        """Check active function claims and remaining chess-clock seconds for `agent_id`."""
        return json.dumps(queue.clock(agent_id.strip() or default_agent), indent=2)

    @mcp.tool()
    def kintoun_submit_match(
        func_or_addr: str,
        code: str = "",
        candidate_id: str = "",
        src_path: str = "",
        engine_note: str = "",
        fix_category: str = "",
        agent_id: str = "",
    ) -> str:
        """Strictly re-verify a byte-exact match, write `src_path`, record `engine_note`, and mark `done`."""
        src = code
        if not src and candidate_id:
            rec = store.get(candidate_id)
            if rec:
                src = rec["code"]
        ctx = load_target_from_config(cfg)
        compiler = make_compiler(cfg)
        aid = agent_id.strip() or default_agent
        res = queue.submit_match(
            aid,
            func_or_addr,
            src,
            ctx,
            compiler,
            project_root=cfg.root,
            src_path=src_path,
            engine_note=engine_note,
            fix_category=fix_category,
            forbid_asm=cfg.search.forbid_asm,
        )
        return json.dumps(res, indent=2)

    @mcp.tool()
    def kintoun_fail_claim(
        func_or_addr: str,
        reason: str,
        note: str = "",
        best_pct: float = 0.0,
        agent_id: str = "",
    ) -> str:
        """Fail an active claim. Refused before clock expiry unless `reason` is a structural blocker."""
        aid = agent_id.strip() or default_agent
        return json.dumps(queue.fail_claim(aid, func_or_addr, reason, note=note, best_pct=best_pct), indent=2)

    @mcp.tool()
    def kintoun_queue_status() -> str:
        """Return multi-agent queue counts, difficulty breakdown, active claims, and top near misses."""
        return json.dumps(queue.status(), indent=2)

    mcp.run()
