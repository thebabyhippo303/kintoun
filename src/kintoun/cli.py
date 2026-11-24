"""Command-line interface for Kintoun."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from kintoun import __version__
from kintoun.compiler import make_compiler
from kintoun.config import SEARCH_MODES, load_config, parse_duration_s
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
budget_s = 180.0
max_candidates = 2500
mode = "standard"
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
budget_s = 180.0
max_candidates = 2500
mode = "standard"
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
budget_s = 180.0
max_candidates = 2500
mode = "standard"
workers = 0
strategies = ["systematic", "register_focus", "random"]
cache_dir = ".kintoun/cache"
forbid_asm = true
""",
    "ee-gcc": """[project]
name = "my-ps2-decomp"

[compiler]
preset = "ee-gcc"
compiler_dir = "${PS2DEV}/ee"
flags = ["-O2", "-mno-abicalls", "-fno-pic", "-G8", "-c"]
timeout_s = 30.0

[target]
arch = "mips_elf"
binary = ""
symbols = ""
gp = "0x0"

[search]
budget_s = 180.0
max_candidates = 2500
mode = "standard"
workers = 0
strategies = ["systematic", "register_focus", "random"]
cache_dir = ".kintoun/cache"
forbid_asm = true
""",
    "mwccps2": """[project]
name = "my-ps2-mwcc-decomp"

[compiler]
preset = "mwccps2"
compiler_dir = "${MWCCPS2_DIR}"
wine = "wibo"
flags = ["-O4,p", "-nodefaults", "-c"]
timeout_s = 30.0

[target]
arch = "mips_elf"
binary = ""
symbols = ""
gp = "0x0"

[search]
budget_s = 180.0
max_candidates = 2500
mode = "standard"
workers = 0
strategies = ["systematic", "register_focus", "random"]
cache_dir = ".kintoun/cache"
forbid_asm = true
""",
    "psp-gcc": """[project]
name = "my-psp-decomp"

[compiler]
preset = "psp-gcc"
compiler_dir = "${PSPDEV}"
flags = ["-O2", "-mno-abicalls", "-fno-pic", "-G8", "-c"]
timeout_s = 30.0

[target]
arch = "mips_elf"
binary = ""
symbols = ""
gp = "0x0"

[search]
budget_s = 180.0
max_candidates = 2500
mode = "standard"
workers = 0
strategies = ["systematic", "register_focus", "random"]
cache_dir = ".kintoun/cache"
forbid_asm = true
""",
    "mwccpsp": """[project]
name = "my-psp-mwcc-decomp"

[compiler]
preset = "mwccpsp"
compiler_dir = "${MWCCPSP_DIR}"
wine = "wibo"
flags = ["-O4,p", "-nodefaults", "-c"]
timeout_s = 30.0

[target]
arch = "mips_elf"
binary = ""
symbols = ""
gp = "0x0"

[search]
budget_s = 180.0
max_candidates = 2500
mode = "standard"
workers = 0
strategies = ["systematic", "register_focus", "random"]
cache_dir = ".kintoun/cache"
forbid_asm = true
""",
    "pspsnc": """[project]
name = "my-psp-snc-decomp"

[compiler]
preset = "pspsnc"
compiler_dir = "${PSPSNC_DIR}"
wine = "wibo"
flags = ["-O2", "-c"]
timeout_s = 30.0

[target]
arch = "mips_elf"
binary = ""
symbols = ""
gp = "0x0"

[search]
budget_s = 180.0
max_candidates = 2500
mode = "standard"
workers = 0
strategies = ["systematic", "register_focus", "random"]
cache_dir = ".kintoun/cache"
forbid_asm = true
""",
    "mips-gcc": """[project]
name = "my-mips-decomp"

[compiler]
preset = "mips-gcc"
compiler_dir = ""
flags = ["-O2", "-mno-abicalls", "-fno-pic", "-c"]
timeout_s = 30.0

[target]
arch = "mips_elf"
binary = ""
symbols = ""
gp = "0x0"

[search]
budget_s = 180.0
max_candidates = 2500
mode = "standard"
workers = 0
strategies = ["systematic", "register_focus", "random"]
cache_dir = ".kintoun/cache"
forbid_asm = true
""",
    "arm-none-eabi-gcc": """[project]
name = "my-arm-decomp"

[compiler]
preset = "arm-none-eabi-gcc"
compiler_dir = ""
flags = ["-O2", "-mcpu=arm7tdmi", "-mthumb", "-c"]
timeout_s = 30.0

[target]
arch = "arm_elf"
binary = ""
base_addr = "0x08000000"
symbols = ""
thumb = true

[search]
budget_s = 180.0
max_candidates = 2500
mode = "standard"
workers = 0
strategies = ["systematic", "register_focus", "random"]
cache_dir = ".kintoun/cache"
forbid_asm = true
""",
    "agbcc": """[project]
name = "my-gba-decomp"

[compiler]
preset = "agbcc"
compiler_dir = "${AGBCC_DIR}"
flags = ["-O2"]
assembler = ["arm-none-eabi-as", "-mcpu=arm7tdmi", "-mthumb-interwork"]
timeout_s = 30.0

[target]
arch = "arm_elf"
binary = ""
base_addr = "0x08000000"
symbols = ""
thumb = true

[search]
budget_s = 180.0
max_candidates = 2500
mode = "standard"
workers = 0
strategies = ["systematic", "register_focus", "random"]
cache_dir = ".kintoun/cache"
forbid_asm = true
""",
    "mwccarm": """[project]
name = "my-nds-decomp"

[compiler]
preset = "mwccarm"
compiler_dir = "${MWCCARM_DIR}"
flags = ["-O4,p", "-proc", "arm946e", "-c"]
timeout_s = 30.0

[target]
arch = "arm_elf"
binary = ""
base_addr = "0x02000000"
symbols = ""

[search]
budget_s = 180.0
max_candidates = 2500
mode = "standard"
workers = 0
strategies = ["systematic", "register_focus", "random"]
cache_dir = ".kintoun/cache"
forbid_asm = true
""",
    "armcc": """[project]
name = "my-armcc-decomp"

[compiler]
preset = "armcc"
compiler_dir = "${ARMCC_DIR}"
wine = "wibo"
flags = ["--thumb", "-O2", "-c"]
timeout_s = 30.0

[target]
arch = "arm_elf"
binary = ""
base_addr = "0x08000000"
symbols = ""
thumb = true

[search]
budget_s = 180.0
max_candidates = 2500
mode = "standard"
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


def _resolve_search_limits(args: argparse.Namespace, cfg) -> tuple[float, int, int]:
    mode = getattr(args, "mode", None)
    if getattr(args, "until_match", False):
        mode = "unlimited"
    elif getattr(args, "deep", False):
        mode = "deep"
    elif getattr(args, "thorough", False):
        mode = "thorough"
    elif getattr(args, "quick", False):
        mode = "quick"

    if mode:
        budget_s, max_cands = SEARCH_MODES[mode]
    else:
        budget_s, max_cands = cfg.search.budget_s, cfg.search.max_candidates

    raw_budget = args.budget if args.budget is not None else getattr(args, "time", None)
    if raw_budget is not None:
        budget_s = parse_duration_s(raw_budget, budget_s)
    if args.max_candidates is not None:
        max_cands = args.max_candidates
    plateau = args.plateau if getattr(args, "plateau", None) is not None else cfg.search.plateau
    return budget_s, max_cands, plateau


def cmd_permute(args: argparse.Namespace) -> int:
    cfg = load_config(Path(args.config) if args.config else None)
    ctx, target_fn = _resolve_target(args, cfg)
    compiler = make_compiler(cfg)
    src_path = Path(args.source)
    source = src_path.read_text(encoding="utf-8")
    cache_dir = cfg.resolve_path(cfg.search.cache_dir)
    priors_path = cfg.resolve_path(cfg.search.priors_file)
    strategies = args.strategies.split(",") if args.strategies else cfg.search.strategies
    budget_s, max_cands, plateau = _resolve_search_limits(args, cfg)
    res = run_search(
        source=source,
        target_fn=target_fn,
        ctx=ctx,
        compiler=compiler,
        budget_s=budget_s,
        max_candidates=max_cands,
        strategies=strategies,
        workers=args.workers if args.workers is not None else cfg.search.workers,
        cache_dir=cache_dir,
        priors_path=priors_path,
        forbid_asm=cfg.search.forbid_asm,
        seed=args.seed,
        plateau=plateau,
        governed=bool(getattr(args, "governed", False) or cfg.search.shared_governor),
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
                f"aligned={best.get('search', {}).get('aligned_pct', 0.0):.2f}% "
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
        "search_mode": cfg.search.mode,
        "budget_s": cfg.search.budget_s,
        "max_candidates": cfg.search.max_candidates,
        "search_modes": {k: {"budget_s": b, "max_candidates": c} for k, (b, c) in SEARCH_MODES.items()},
    }
    print(json.dumps(payload, indent=2))
    return 0


def cmd_mcp(args: argparse.Namespace) -> int:
    from kintoun.mcp_server import run_mcp

    run_mcp(Path(args.config) if args.config else None)
    return 0


def cmd_check(args: argparse.Namespace) -> int:
    from kintoun.inspect_fn import check_function, score_difficulty

    cfg = load_config(Path(args.config) if args.config else None)
    ctx, target_fn = _resolve_target(args, cfg)
    chk = check_function(target_fn, ctx)
    diff = score_difficulty(target_fn, ctx)
    payload = {**chk, "difficulty": diff["score"], "tier": diff["tier"], "tags": diff["tags"]}
    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        print(
            f"[{payload['verdict'].upper()}] {payload['name']} ({payload['addr']}) "
            f"size={payload['size_bytes']}B tier={payload['tier']} ({payload['difficulty']}/100)"
        )
        if payload["tags"]:
            print(f"  tags: {', '.join(payload['tags'])}")
        for blk in payload["blockers"]:
            print(f"  blocker: {blk}")
    return 0 if payload["plain_c"] else 1


def cmd_context(args: argparse.Namespace) -> int:
    from kintoun.inspect_fn import build_context_pack

    cfg = load_config(Path(args.config) if args.config else None)
    ctx, target_fn = _resolve_target(args, cfg)
    pack = build_context_pack(
        target_fn,
        ctx,
        cfg,
        src_dir=Path(args.src_dir) if args.src_dir else None,
        max_disasm_lines=args.lines,
    )
    if args.json:
        print(json.dumps(pack, indent=2))
    else:
        diff = pack["difficulty"]
        print(f"# {pack['name']} ({pack['addr']}) [{pack['arch']}, {pack['size_bytes']}B]")
        print(f"Verdict: {pack['verdict']}  Difficulty: {diff['tier']} ({diff['score']}/100)  Tags: {', '.join(diff['tags'])}")
        if pack["blockers"]:
            print("Blockers: " + "; ".join(pack["blockers"]))
        if pack["callees"]:
            print("Callees: " + ", ".join(pack["callees"]))
        if pack["globals"]:
            print("Globals: " + ", ".join(pack["globals"]))
        if pack["callee_prototypes"]:
            print("\n## Matched Prototypes\n" + "\n".join(pack["callee_prototypes"]))
        print("\n## Target Disassembly\n" + pack["disassembly"])
    return 0


def cmd_close(args: argparse.Namespace) -> int:
    from kintoun.closer import close_near_miss

    cfg = load_config(Path(args.config) if args.config else None)
    ctx, target_fn = _resolve_target(args, cfg)
    compiler = make_compiler(cfg)
    src_path = Path(args.source)
    source = src_path.read_text(encoding="utf-8")
    res = close_near_miss(
        source,
        target_fn,
        ctx,
        compiler,
        budget_s=parse_duration_s(args.budget, 60.0),
        max_candidates=args.max_candidates,
        workers=args.workers,
        cache_dir=cfg.resolve_path(cfg.search.cache_dir),
        priors_path=cfg.resolve_path(cfg.search.priors_file),
        forbid_asm=cfg.search.forbid_asm,
    )
    best = res.get("best") or {}
    if args.write and best.get("code") and (res.get("verified") or args.write_best):
        src_path.write_text(best["code"], encoding="utf-8")
    if args.json:
        print(json.dumps(res, indent=2))
    else:
        cls_name = (res.get("classification") or {}).get("primary_class", "unknown")
        print(
            f"[{'MATCH' if res.get('verified') else 'NEAR-MISS'}] {res.get('name')} ({res.get('addr')}) "
            f"class={cls_name} passes={res.get('passes')} in {res.get('elapsed_s')}s"
        )
        if best:
            print(
                f"  aligned={(best.get('search') or {}).get('aligned_pct', 0.0):.2f}% "
                f"diff_bytes={best.get('different_bytes')}"
            )
    return 0 if res.get("verified") else 1


def cmd_queue(args: argparse.Namespace) -> int:
    from kintoun.queue import WorkQueue

    cfg = load_config(Path(args.config) if args.config else None)
    cache_dir = cfg.resolve_path(cfg.search.cache_dir) or (cfg.root / ".kintoun" / "cache")
    wq = WorkQueue(cache_dir.parent)
    act = args.action
    if act == "init":
        ctx = load_target_from_config(cfg)
        out = wq.sync_from_context(ctx)
    elif act == "status":
        out = wq.status()
    elif act == "claim":
        out = wq.claim_next(args.agent, prefer_tier=args.tier or "")
    elif act == "clock":
        out = wq.clock(args.agent)
    elif act == "unquarantine":
        out = {"released": wq.unquarantine(limit=args.limit)}
    elif act == "fail":
        if not args.func or not args.reason:
            raise ValueError("queue fail requires --func and --reason")
        out = wq.fail_claim(args.agent, args.func, args.reason, note=args.note or "")
    elif act == "submit":
        if not args.func or not args.source:
            raise ValueError("queue submit requires --func and --source")
        ctx = load_target_from_config(cfg)
        compiler = make_compiler(cfg)
        code = Path(args.source).read_text(encoding="utf-8")
        out = wq.submit_match(
            args.agent,
            args.func,
            code,
            ctx,
            compiler,
            project_root=cfg.root,
            src_path=args.source,
            engine_note=args.note or "",
            fix_category=args.category or "",
            forbid_asm=cfg.search.forbid_asm,
        )
    else:
        raise ValueError(f"unknown queue action: {act}")
    print(json.dumps(out, indent=2))
    return 0 if out.get("ok", True) and out.get("claimed", True) else 1


def cmd_overseer(args: argparse.Namespace) -> int:
    import time as _time
    from kintoun.overseer import Overseer, settings_from_toml

    cfg = load_config(Path(args.config) if args.config else None)
    st = settings_from_toml(cfg)
    if args.brain:
        st.brain_mode = args.brain
    if args.provider:
        st.main_brain.provider = args.provider
    if args.model:
        st.main_brain.model = args.model
    if args.api_key_env:
        st.main_brain.api_key_env = args.api_key_env
    if args.base_url:
        st.main_brain.base_url = args.base_url
    if args.budget_usd is not None:
        st.daily_budget_usd = args.budget_usd

    sup = Overseer(cfg, st)
    if args.action == "status":
        print(json.dumps(sup.status(), indent=2))
        return 0
    if args.action == "once":
        print(json.dumps(sup.run_cycle(dry_run=args.dry_run), indent=2))
        return 0
    while True:
        res = sup.run_cycle(dry_run=args.dry_run)
        print(json.dumps(res))
        _time.sleep(max(5.0, st.cycle_s))


def cmd_warm_wine(args: argparse.Namespace) -> int:
    from kintoun.governor import CompileGovernor, ensure_warm_wine, stop_warm_wine

    cfg = load_config(Path(args.config) if args.config else None)
    cache_dir = cfg.resolve_path(cfg.search.cache_dir) or (cfg.root / ".kintoun" / "cache")
    if args.status:
        gov = CompileGovernor(cache_dir)
        print(json.dumps(gov.status(), indent=2))
        return 0
    wprefix = cfg.resolve_path(cfg.compiler.wineprefix) if cfg.compiler.wineprefix else None
    out = (
        stop_warm_wine(wprefix, wine_bin=cfg.compiler.wine)
        if args.stop
        else ensure_warm_wine(wprefix, persist_s=args.persist, wine_bin=cfg.compiler.wine)
    )
    print(json.dumps(out, indent=2))
    return 0 if out.get("ok") else 1


def cmd_bench(args: argparse.Namespace) -> int:
    from kintoun.lab import learn_priors, run_benchmark

    cfg = load_config(Path(args.config) if args.config else None)
    rep = run_benchmark(
        cfg,
        Path(args.manifest),
        budget_s=parse_duration_s(args.budget, 20.0),
        max_candidates=args.max_candidates,
        workers=args.workers,
        baseline_report=Path(args.baseline) if args.baseline else None,
    )
    if args.out:
        Path(args.out).write_text(json.dumps(rep, indent=2), encoding="utf-8")
    if args.learn_priors:
        cache_dir = cfg.resolve_path(cfg.search.cache_dir) or (cfg.root / ".kintoun" / "cache")
        notes = cache_dir.parent / "research" / "notes.jsonl"
        learn_priors(notes, [Path(args.out)] if args.out else [], out_path=Path(args.learn_priors))
    print(json.dumps(rep, indent=2))
    return 0 if rep.get("promotion_eligible", True) else 1


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
    p_perm.add_argument(
        "--budget",
        type=str,
        default=None,
        help="Search time budget (seconds like 180, or duration like 30s, 5m, 1h, unlimited).",
    )
    p_perm.add_argument(
        "-t",
        "--time",
        type=str,
        default=None,
        help="Alias for --budget (e.g. --time 30s, --time 10m, --time 1h).",
    )
    p_perm.add_argument("--max-candidates", type=int, default=None, help="Max candidates to evaluate.")
    p_perm.add_argument(
        "--mode",
        choices=sorted(SEARCH_MODES),
        default=None,
        help="Search effort preset: quick (15s/250), standard (3m/2500), thorough (10m/10k), deep (30m/50k), unlimited.",
    )
    p_perm.add_argument("--quick", action="store_true", help="Shorthand for --mode quick (15s / 250 candidates).")
    p_perm.add_argument("--thorough", action="store_true", help="Shorthand for --mode thorough (10m / 10000 candidates).")
    p_perm.add_argument("--deep", action="store_true", help="Shorthand for --mode deep (30m / 50000 candidates).")
    p_perm.add_argument("--until-match", action="store_true", help="Search without early stop until VERIFIED or interrupted.")
    p_perm.add_argument(
        "--plateau",
        type=int,
        default=None,
        help="Optional early-stop threshold after N non-improving evals (0 = disabled, default 0).",
    )
    p_perm.add_argument("--workers", type=int, default=None, help="Parallel compiler worker count.")
    p_perm.add_argument("--strategies", help="Comma-separated strategies (" + ",".join(STRATEGIES) + ").")
    p_perm.add_argument("--seed", type=int, default=0, help="RNG seed for random strategy.")
    p_perm.add_argument("--governed", action="store_true", help="Coordinate compile slots across processes via shared governor.")
    p_perm.add_argument("--write", action="store_true", help="Write back source file if a byte-exact match is found.")
    p_perm.add_argument("--write-best", action="store_true", help="With --write, also write best non-matching improvement.")
    p_perm.add_argument("--json", action="store_true", help="Emit full JSON output.")
    p_perm.set_defaults(func_cb=cmd_permute)

    p_info = sub.add_parser("info", help="Show resolved Kintoun configuration and available strategies.")
    p_info.set_defaults(func_cb=cmd_info)

    p_mcp = sub.add_parser("mcp", help="Start the optional MCP server (requires `pip install kintoun[mcp]`).")
    p_mcp.set_defaults(func_cb=cmd_mcp)

    p_chk = sub.add_parser("check", help="Fast structural plain-C blocker and static difficulty check.")
    p_chk.add_argument("--func", help="Function name or 0xADDRESS.")
    p_chk.add_argument("--target", help="Standalone target .o file.")
    p_chk.add_argument("--json", action="store_true", help="Emit JSON output.")
    p_chk.set_defaults(func_cb=cmd_check)

    p_ctx = sub.add_parser("context", help="Build a compact one-call function context pack (disassembly, callees, hints).")
    p_ctx.add_argument("--func", help="Function name or 0xADDRESS.")
    p_ctx.add_argument("--target", help="Standalone target .o file.")
    p_ctx.add_argument("--src-dir", help="Matched C directory to scan for prototypes (defaults to ./src).")
    p_ctx.add_argument("--lines", type=int, default=64, help="Max disassembly lines.")
    p_ctx.add_argument("--json", action="store_true", help="Emit JSON output.")
    p_ctx.set_defaults(func_cb=cmd_context)

    p_close = sub.add_parser("close", help="Zero-LLM diff-classified near-miss finisher (1-to-2 targeted passes).")
    p_close.add_argument("source", help="Path to near-miss candidate .c file.")
    p_close.add_argument("--func", help="Function name or 0xADDRESS.")
    p_close.add_argument("--target", help="Standalone target .o file.")
    p_close.add_argument("--budget", type=str, default="60s", help="Pass-1 search budget (default 60s).")
    p_close.add_argument("--max-candidates", type=int, default=160, help="Max candidates per pass.")
    p_close.add_argument("--workers", type=int, default=2, help="Compiler workers.")
    p_close.add_argument("--write", action="store_true", help="Write back on exact match.")
    p_close.add_argument("--write-best", action="store_true", help="With --write, also write improved near miss.")
    p_close.add_argument("--json", action="store_true", help="Emit JSON output.")
    p_close.set_defaults(func_cb=cmd_close)

    p_q = sub.add_parser("queue", help="Multi-agent work queue with chess-clock enforcement and quarantine.")
    p_q.add_argument("action", choices=["init", "status", "claim", "clock", "submit", "fail", "unquarantine"])
    p_q.add_argument("--agent", default="local", help="Agent or developer identifier.")
    p_q.add_argument("--func", help="Function name or 0xADDRESS (for submit/fail).")
    p_q.add_argument("--source", help="Candidate .c path (for submit).")
    p_q.add_argument("--reason", help="Failure reason (structural blockers allowed early).")
    p_q.add_argument("--note", help="Engine note or failure note.")
    p_q.add_argument("--category", help="Winning fix category for prior learning.")
    p_q.add_argument("--tier", choices=["easy", "medium", "hard", "brutal"], help="Preferred difficulty tier on claim.")
    p_q.add_argument("--limit", type=int, default=50, help="Max items for unquarantine.")
    p_q.set_defaults(func_cb=cmd_queue)

    p_ov = sub.add_parser("overseer", help="Out-of-the-box supervisor (code-only $0, single-brain, or dual-brain).")
    p_ov.add_argument("action", nargs="?", choices=["status", "once", "loop"], default="once")
    p_ov.add_argument("--brain", choices=["none", "single", "dual"], help="Brain mode: none ($0 code-only), single (1 API), dual (2 APIs/models).")
    p_ov.add_argument("--provider", choices=["openai", "openai-compatible", "anthropic", "gemini"], help="Provider for single/main brain.")
    p_ov.add_argument("--model", help="Model name for single/main brain.")
    p_ov.add_argument("--api-key-env", help="Env var holding API key (e.g. OPENAI_API_KEY).")
    p_ov.add_argument("--base-url", help="Custom endpoint URL (e.g. http://localhost:11434/v1 for Ollama).")
    p_ov.add_argument("--budget-usd", type=float, default=None, help="Daily API spend cap in USD.")
    p_ov.add_argument("--dry-run", action="store_true", help="Preview supervisor cycle without mutating queue or workers.")
    p_ov.set_defaults(func_cb=cmd_overseer)

    p_ww = sub.add_parser("warm-wine", help="Manage persistent wineserver and inspect single-machine governor.")
    p_ww.add_argument("--status", action="store_true", help="Print live governor slots and memory pressure auto-tuner.")
    p_ww.add_argument("--stop", action="store_true", help="Stop persistent wineserver.")
    p_ww.add_argument("--persist", type=int, default=900, help="Wineserver persistence timeout in seconds (default 900).")
    p_ww.set_defaults(func_cb=cmd_warm_wine)

    p_bn = sub.add_parser("bench", help="Run reproducible benchmark manifest with regression checks.")
    p_bn.add_argument("manifest", help="Path to JSON benchmark manifest.")
    p_bn.add_argument("--budget", type=str, default="20s", help="Per-function search budget.")
    p_bn.add_argument("--max-candidates", type=int, default=250, help="Max candidates per function.")
    p_bn.add_argument("--workers", type=int, default=2, help="Compiler workers.")
    p_bn.add_argument("--baseline", help="Optional baseline benchmark JSON to check for lost exact matches.")
    p_bn.add_argument("--out", help="Write benchmark report JSON to path.")
    p_bn.add_argument("--learn-priors", help="Write updated mutation-family priors JSON to path.")
    p_bn.set_defaults(func_cb=cmd_bench)
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
