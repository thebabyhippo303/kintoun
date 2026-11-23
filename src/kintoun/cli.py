"""Command-line interface for Kintoun."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from kintoun import __version__
from kintoun.compiler import make_compiler
from kintoun.config import load_config
from kintoun.search.runner import STRATEGIES, run_search
from kintoun.targets import load_target_from_config, load_target_from_object
from kintoun.verify import verify_source

_PRESET_TEMPLATES = {
    "prodg-wine": """[project]
name = "my-gc-decomp"

[compiler]
preset = "prodg-wine"
compiler_dir = "${PRODG_DIR}"
wine = "wine"
flags = ["-O2", "-c"]
timeout_s = 30.0

[target]
arch = "ppc_elf"
dol = "orig/GAMEID/sys/main.dol"
symbols = "config/GAMEID/symbols.txt"
sda_r13 = "0x80000000"
sda_r2 = "0x80000000"

[search]
budget_s = 60.0
max_candidates = 600
workers = 0
strategies = ["systematic", "register_focus", "random"]
cache_dir = ".kintoun/cache"
forbid_asm = true
""",
    "mwcc-wine": """[project]
name = "my-gc-decomp"

[compiler]
preset = "mwcc-wine"
compiler_dir = "${MWCC_DIR}"
wine = "wine"
flags = ["-O4,p", "-nodefaults", "-proc", "gekko", "-fp", "hardware", "-c"]
timeout_s = 30.0

[target]
arch = "ppc_elf"
dol = "orig/GAMEID/sys/main.dol"
symbols = "config/GAMEID/symbols.txt"
sda_r13 = "0x80000000"
sda_r2 = "0x80000000"

[search]
budget_s = 60.0
max_candidates = 600
workers = 0
strategies = ["systematic", "register_focus", "random"]
cache_dir = ".kintoun/cache"
forbid_asm = true
""",
    "custom": """[project]
name = "my-decomp"

[compiler]
preset = "custom"
command = ["powerpc-eabi-gcc", "{flags}", "-o", "{out}", "{in}"]
flags = ["-O2", "-c"]
timeout_s = 30.0

[target]
arch = "ppc_elf"
dol = ""
symbols = ""
sda_r13 = "0x0"
sda_r2 = "0x0"

[search]
budget_s = 60.0
max_candidates = 600
workers = 0
strategies = ["systematic", "register_focus", "random"]
cache_dir = ".kintoun/cache"
forbid_asm = true
""",
}


def _resolve_target(args: argparse.Namespace, cfg):
    if getattr(args, "target", None):
        return load_target_from_object(Path(args.target), getattr(args, "func", None))
    ctx = load_target_from_config(cfg)
    fn_spec = getattr(args, "func", None)
    if not fn_spec:
        raise ValueError("Provide --func <name|0xADDR> (with dol+symbols in kintoun.toml) or --target <file.o>.")
    return ctx, ctx.resolve_function(fn_spec)


def cmd_init(args: argparse.Namespace) -> int:
    out = Path(args.output)
    if out.exists() and not args.force:
        print(f"Error: {out} already exists (pass --force to overwrite).", file=sys.stderr)
        return 1
    out.write_text(_PRESET_TEMPLATES[args.preset], encoding="utf-8")
    print(f"Wrote {out} (preset: {args.preset}).")
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    cfg = load_config(Path(args.config) if args.config else None)
    ctx, target_fn = _resolve_target(args, cfg)
    compiler = make_compiler(cfg)
    source = Path(args.source).read_text(encoding="utf-8")
    res = verify_source(
        source,
        target_fn,
        ctx,
        compiler,
        lines=args.lines,
        forbid_asm=cfg.search.forbid_asm,
    )
    if args.json:
        print(json.dumps(res, indent=2))
    else:
        status = res.get("status", "unknown")
        sc = res.get("search", {})
        print(f"[{status.upper()}] {res.get('name')} ({res.get('addr')})")
        if sc:
            print(f"  normalized: {sc.get('normalized_pct', 0):.2f}%  aligned: {sc.get('aligned_pct', 0):.2f}%  score: {sc.get('total')}")
        if "different_bytes" in res:
            print(f"  different bytes: {res['different_bytes']} / {res['target_bytes']}  (insns: {res['instruction_mismatches']})")
        if res.get("error"):
            print(f"  error: {res['error']}")
        for hint in (sc.get("hints") or [])[:6]:
            print(f"  hint: {hint}")
        if sc.get("diff") and not res.get("verified"):
            print(sc["diff"])
    return 0 if res.get("verified") else 1


def cmd_permute(args: argparse.Namespace) -> int:
    cfg = load_config(Path(args.config) if args.config else None)
    ctx, target_fn = _resolve_target(args, cfg)
    compiler = make_compiler(cfg)
    src_path = Path(args.source)
    source = src_path.read_text(encoding="utf-8")
    cache_dir = cfg.resolve_path(cfg.search.cache_dir)
    priors_path = cfg.resolve_path(cfg.search.priors_file)
    strategies = args.strategies.split(",") if args.strategies else cfg.search.strategies
    res = run_search(
        source=source,
        target_fn=target_fn,
        ctx=ctx,
        compiler=compiler,
        budget_s=args.budget if args.budget is not None else cfg.search.budget_s,
        max_candidates=args.max_candidates if args.max_candidates is not None else cfg.search.max_candidates,
        strategies=strategies,
        workers=args.workers if args.workers is not None else cfg.search.workers,
        cache_dir=cache_dir,
        priors_path=priors_path,
        forbid_asm=cfg.search.forbid_asm,
        seed=args.seed,
    )
    best = res.get("best") or {}
    if args.write and best.get("code") and (best.get("verified") or args.write_best):
        src_path.write_text(best["code"], encoding="utf-8")
    if args.json:
        print(json.dumps(res, indent=2))
    else:
        print(
            f"[{'MATCH' if res.get('verified') else best.get('status', 'DONE').upper()}] "
            f"{res.get('name')} ({res.get('addr')}) in {res.get('elapsed_s')}s"
        )
        print(
            f"  evaluated={res.get('evaluated')} compiled={res.get('compiled')} "
            f"cache_hits={res.get('cache_hits')} improvements={res.get('improvements')} "
            f"stopped={res.get('stopped')}"
        )
        if best:
            print(
                f"  best strategy={best.get('strategy')} "
                f"diff_bytes={best.get('different_bytes')} "
                f"score={best.get('search', {}).get('total')}"
            )
    return 0 if res.get("verified") else 1


def cmd_info(args: argparse.Namespace) -> int:
    cfg = load_config(Path(args.config) if args.config else None)
    payload = {
        "version": __version__,
        "project": cfg.project_name,
        "root": str(cfg.root),
        "compiler_preset": cfg.compiler.preset,
        "target_arch": cfg.target.arch,
        "strategies": list(STRATEGIES),
    }
    print(json.dumps(payload, indent=2))
    return 0


def cmd_mcp(args: argparse.Namespace) -> int:
    from kintoun.mcp_server import run_mcp

    run_mcp(Path(args.config) if args.config else None)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="kintoun", description="Kintoun matching-C decompilation permuter & verifier.")
    p.add_argument("--version", action="version", version=f"kintoun {__version__}")
    p.add_argument("-c", "--config", help="Path to kintoun.toml (auto-discovered upward if omitted).")
    sub = p.add_subparsers(dest="cmd", required=True)

    p_init = sub.add_parser("init", help="Create a starter kintoun.toml in the current directory.")
    p_init.add_argument("--preset", choices=sorted(_PRESET_TEMPLATES), default="prodg-wine")
    p_init.add_argument("-o", "--output", default="kintoun.toml")
    p_init.add_argument("--force", action="store_true")
    p_init.set_defaults(func_cb=cmd_init)

    p_ver = sub.add_parser("verify", help="Compile and strictly verify a C file against a target.")
    p_ver.add_argument("source", help="Path to candidate .c file.")
    p_ver.add_argument("--func", help="Function name or 0xADDRESS (from kintoun.toml DOL+symbols).")
    p_ver.add_argument("--target", help="Standalone target .o file (alternative to DOL+symbols).")
    p_ver.add_argument("--lines", type=int, default=24, help="Max diff lines to show.")
    p_ver.add_argument("--json", action="store_true", help="Emit full JSON output.")
    p_ver.set_defaults(func_cb=cmd_verify)

    p_perm = sub.add_parser("permute", help="Run parallel real-C mutation & register-permutation search.")
    p_perm.add_argument("source", help="Path to candidate .c file.")
    p_perm.add_argument("--func", help="Function name or 0xADDRESS (from kintoun.toml DOL+symbols).")
    p_perm.add_argument("--target", help="Standalone target .o file (alternative to DOL+symbols).")
    p_perm.add_argument("--budget", type=float, default=None, help="Search time budget in seconds.")
    p_perm.add_argument("--max-candidates", type=int, default=None, help="Max candidates to evaluate.")
    p_perm.add_argument("--workers", type=int, default=None, help="Parallel compiler worker count.")
    p_perm.add_argument("--strategies", help="Comma-separated strategies (" + ",".join(STRATEGIES) + ").")
    p_perm.add_argument("--seed", type=int, default=0, help="RNG seed for random strategy.")
    p_perm.add_argument("--write", action="store_true", help="Write back source file if a byte-exact match is found.")
    p_perm.add_argument("--write-best", action="store_true", help="With --write, also write best non-matching improvement.")
    p_perm.add_argument("--json", action="store_true", help="Emit full JSON output.")
    p_perm.set_defaults(func_cb=cmd_permute)

    p_info = sub.add_parser("info", help="Show resolved Kintoun configuration and available strategies.")
    p_info.set_defaults(func_cb=cmd_info)

    p_mcp = sub.add_parser("mcp", help="Start the optional single-user MCP server (requires `pip install kintoun[mcp]`).")
    p_mcp.set_defaults(func_cb=cmd_mcp)
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func_cb(args)
    except Exception as exc:
        print(f"kintoun error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
