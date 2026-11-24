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

    def _load(func: str, target_obj: str, source_path: str = ""):
        if target_obj:
            return load_target_from_object(Path(target_obj), func or None)
        if not (cfg.target.dol or cfg.target.binary):
            from kintoun.autoconfig import resolve_objdiff_target_object

            od_obj = resolve_objdiff_target_object(
                cfg.root,
                source_file=Path(source_path) if source_path else None,
                func_name=func or None,
            )
            if od_obj is not None:
                return load_target_from_object(od_obj, func or None)
        ctx = load_target_from_config(cfg)
        return ctx, ctx.resolve_function(func)

    @mcp.tool()
    def kintoun_verify(source_path: str, func: str = "", target_obj: str = "", lines: int = 24) -> str:
        """Compile a C file and strictly verify it against a target function or .o file."""
        ctx, tf = _load(func, target_obj)
        compiler = make_compiler(cfg, va=tf.va)
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
        compiler = make_compiler(cfg, va=tf.va)
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
        """Fast structural check for non-plain-C instructions and wrong-compiler codegen tells."""
        ctx, tf = _load(func, target_obj)
        return json.dumps(check_function(tf, ctx, configured_preset=cfg.compiler_for(tf.va).preset), indent=2)

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
        abort_if_done: bool = True,
    ) -> str:
        """Score inline C code (using shared cache & governor) and return a `candidate_id` for surgical edits."""
        ctx, tf = _load(func, target_obj)
        compiler = make_compiler(cfg, va=tf.va)
        res = store.score_one(
            code,
            tf,
            ctx,
            compiler,
            lines=lines,
            forbid_asm=cfg.search.forbid_asm,
            include_code=include_code,
            abort_if_done=abort_if_done,
        )
        if not res.get("already_verified"):
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
        abort_if_done: bool = True,
    ) -> str:
        """Apply exact single-match `[{'old': ..., 'new': ...}]` surgical edits to `candidate_id` and re-score."""
        ctx, tf = _load(func, target_obj)
        compiler = make_compiler(cfg, va=tf.va)
        res = store.revise(
            candidate_id,
            edits,
            tf,
            ctx,
            compiler,
            lines=lines,
            forbid_asm=cfg.search.forbid_asm,
            include_code=include_code,
            abort_if_done=abort_if_done,
        )
        if not res.get("already_verified"):
            aligned = float(((res.get("search") or {}).get("aligned_pct")) or 0.0)
            queue.record_progress(tf.name, aligned)
        return json.dumps(res, indent=2)

    @mcp.tool()
    def kintoun_score_candidates(codes: list[str], func: str = "", target_obj: str = "") -> str:
        """Compile and score 2..16 candidate C formulations in parallel and return them ranked best-first."""
        ctx, tf = _load(func, target_obj)
        compiler = make_compiler(cfg, va=tf.va)
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
        compiler = make_compiler(cfg, va=tf.va)
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
        tf_sub = ctx.resolve_function(func_or_addr)
        compiler = make_compiler(cfg, va=tf_sub.va)
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

    @mcp.tool()
    def kintoun_probe_flags(code: str, func: str = "", target_obj: str = "") -> str:
        """Compile `code` across candidate flag sets for the active preset and rank by alignment %."""
        from kintoun.prober import probe_compiler_flags

        ctx, tf = _load(func, target_obj)
        return json.dumps(probe_compiler_flags(code, tf, ctx, cfg), indent=2)

    @mcp.tool()
    def kintoun_scratch(
        slug_or_url: str,
        budget_s: float = 60.0,
        max_candidates: int = 800,
        compiler_dir: str = "",
    ) -> str:
        """Import a `decomp.me` scratch by slug or URL and run Kintoun search + near-miss closer locally."""
        from kintoun.scratch import run_scratch

        return json.dumps(
            run_scratch(
                slug_or_url,
                cfg,
                compiler_dir=compiler_dir,
                budget_s=budget_s,
                max_candidates=max_candidates,
            ),
            indent=2,
        )

    @mcp.tool()
    def kintoun_import_function(
        func: str,
        c_file: str = "",
        map_file: str = "",
        out_candidate: str = "",
    ) -> str:
        """Extract a standalone compilable candidate `.c` + TU flags from an `INCLUDE_ASM`/`GLOBAL_ASM` repo."""
        from kintoun.project_io import import_project_function

        return json.dumps(
            import_project_function(
                cfg.root,
                func,
                c_file=Path(c_file) if c_file else None,
                map_file=Path(map_file) if map_file else None,
                out_candidate=Path(out_candidate) if out_candidate else None,
            ),
            indent=2,
        )

    @mcp.tool()
    def kintoun_integrate_match(
        func: str,
        project_c_file: str,
        code: str = "",
        candidate_id: str = "",
        target_obj: str = "",
        verify: bool = True,
    ) -> str:
        """Splice a verified C match into a multi-function `INCLUDE_ASM`/`GLOBAL_ASM` `.c` file and verify the TU."""
        from kintoun.project_io import integrate_matched_function

        src = code
        if not src and candidate_id:
            rec = store.get(candidate_id)
            if rec:
                src = rec["code"]
        ctx = None
        tf = None
        compiler = None
        if verify:
            ctx, tf = _load(func, target_obj)
            compiler = make_compiler(cfg, va=tf.va)
        return json.dumps(
            integrate_matched_function(
                src,
                Path(project_c_file) if Path(project_c_file).is_absolute() else (cfg.root / project_c_file),
                func,
                verify=verify,
                target_fn=tf,
                ctx=ctx,
                compiler=compiler,
                forbid_asm=cfg.search.forbid_asm,
            ),
            indent=2,
        )

    @mcp.tool()
    def kintoun_atlas(output_html: str = "atlas.html", src_dir: str = "") -> str:
        """Generate a self-contained single-file HTML Decomp Atlas & Run Report for the project."""
        from kintoun.atlas import write_atlas_report

        ctx = load_target_from_config(cfg)
        out_p = Path(output_html) if Path(output_html).is_absolute() else (cfg.root / output_html)
        sdir = (Path(src_dir) if Path(src_dir).is_absolute() else (cfg.root / src_dir)) if src_dir else None
        return json.dumps(write_atlas_report(out_p, ctx, cfg, src_dir=sdir), indent=2)

    @mcp.tool()
    def kintoun_clean_match(
        func: str = "",
        code: str = "",
        candidate_id: str = "",
        target_obj: str = "",
    ) -> str:
        """Simplify a verified C match (restructure gotos, prune unused locals/casts) while keeping 0 diff bytes."""
        from kintoun.cleaner import clean_matched_source

        src = code
        if not src and candidate_id:
            rec = store.get(candidate_id)
            if rec:
                src = rec["code"]
        ctx, tf = _load(func, target_obj)
        compiler = make_compiler(cfg, va=tf.va)
        return json.dumps(
            clean_matched_source(src, tf, ctx, compiler, forbid_asm=cfg.search.forbid_asm),
            indent=2,
        )

    @mcp.tool()
    def kintoun_synth_headers(class_name: str = "", output_header: str = "") -> str:
        """Synthesize factual C struct layouts, vtables, and debug-string hints from the target binary."""
        from kintoun.synth import synthesize_project_headers

        ctx = load_target_from_config(cfg)
        out_h = (Path(output_header) if Path(output_header).is_absolute() else (cfg.root / output_header)) if output_header else None
        return json.dumps(
            synthesize_project_headers(ctx, class_filter=class_name, out_header=out_h),
            indent=2,
        )

    @mcp.tool()
    def kintoun_doctor(scan_dir: str = "") -> str:
        """Run end-to-end setup diagnostics (config, Wine/wibo, 2-line C compile smoke test, target symbols)."""
        from kintoun.doctor import run_doctor

        sdir = (Path(scan_dir) if Path(scan_dir).is_absolute() else (cfg.root / scan_dir)) if scan_dir else None
        return json.dumps(run_doctor(cfg, scan_dir=sdir), indent=2)

    @mcp.tool()
    def kintoun_export_dataset(output_jsonl: str = "dataset.jsonl", src_dir: str = "") -> str:
        """Export verifiable SFT and DPO fine-tuning JSONL pairs from Kintoun's project history."""
        from kintoun.dataset import export_dataset

        try:
            ctx = load_target_from_config(cfg)
        except Exception:
            ctx = None
        out_p = Path(output_jsonl) if Path(output_jsonl).is_absolute() else (cfg.root / output_jsonl)
        sdir = (Path(src_dir) if Path(src_dir).is_absolute() else (cfg.root / src_dir)) if src_dir else (cfg.root / "src")
        return json.dumps(export_dataset(cache_dir, ctx, src_dir=sdir, out_path=out_p), indent=2)

    @mcp.tool()
    def kintoun_engine_status() -> str:
        """Inspect `.kintoun/engine_lab/` side trees, combined commits, findings, and unseen gate ledger."""
        from kintoun.engine_lab import EngineLab

        return json.dumps(EngineLab(cfg).status(), indent=2)

    @mcp.tool()
    def kintoun_engine_gate(
        candidate_arm: str = "combined",
        count: int = 40,
        budget_s: float = 20.0,
        max_candidates: int = 250,
        confirm_runs: int = 1,
        ablate: bool = True,
        promote: bool = False,
    ) -> str:
        """Run `live` vs `candidate_arm` on a fresh blind unseen function draw, ablate commits, and optionally promote."""
        from kintoun.engine_lab import EngineLab

        lab = EngineLab(cfg)
        return json.dumps(
            lab.run_unseen_gate(
                candidate_arm=candidate_arm,
                count=count,
                budget_s=budget_s,
                max_candidates=max_candidates,
                confirm_runs=confirm_runs,
                ablate=ablate,
                promote=promote,
            ),
            indent=2,
        )

    mcp.run()
