"""Optional single-user tool server exposing verify, permute and info."""
from __future__ import annotations

import json
from pathlib import Path

from kintoun import __version__
from kintoun.compiler import make_compiler
from kintoun.config import SEARCH_MODES, load_config, parse_duration_s
from kintoun.search.runner import run_search
from kintoun.targets import load_target_from_config, load_target_from_object
from kintoun.verify import verify_source


def run_mcp(config_path: Path | None = None) -> None:
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError as exc:
        raise RuntimeError("MCP support requires optional dependency: pip install 'kintoun[mcp]'") from exc

    cfg = load_config(config_path)
    mcp = FastMCP("kintoun")

    @mcp.tool()
    def kintoun_verify(source_path: str, func: str = "", target_obj: str = "", lines: int = 24) -> str:
        """Compile a C file and strictly verify it against a target function or .o file."""
        ctx, tf = (
            load_target_from_object(Path(target_obj), func or None)
            if target_obj
            else (load_target_from_config(cfg), load_target_from_config(cfg).resolve_function(func))
        )
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
    ) -> str:
        """Run Kintoun real-C mutation and register-permutation search against a target function."""
        ctx, tf = (
            load_target_from_object(Path(target_obj), func or None)
            if target_obj
            else (load_target_from_config(cfg), load_target_from_config(cfg).resolve_function(func))
        )
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
            cache_dir=cfg.resolve_path(cfg.search.cache_dir),
            priors_path=cfg.resolve_path(cfg.search.priors_file),
            forbid_asm=cfg.search.forbid_asm,
            plateau=plateau,
        )
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

    mcp.run()
