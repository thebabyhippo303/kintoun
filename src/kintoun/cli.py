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
    if not (cfg.target.dol or cfg.target.binary):
        from kintoun.autoconfig import resolve_objdiff_target_object

        raw_src = getattr(args, "source", None)
        od_obj = resolve_objdiff_target_object(
            cfg.root,
            source_file=Path(raw_src) if raw_src else None,
            func_name=getattr(args, "func", None),
        )
        if od_obj is not None:
            return load_target_from_object(od_obj, getattr(args, "func", None))
    ctx = load_target_from_config(cfg)
    fn_spec = getattr(args, "func", None)
    if not fn_spec:
        raise ValueError("Provide --func <name|0xADDR> (with dol+symbols in kintoun.toml) or --target <file.o>.")
    return ctx, ctx.resolve_function(fn_spec)


def cmd_init(args: argparse.Namespace) -> int:
    from kintoun.autoconfig import detect_repo_layout, export_objdiff_config, render_detected_toml

    if getattr(args, "export_objdiff", None):
        cfg = load_config(Path(args.config) if args.config else None)
        doc = export_objdiff_config(cfg.root, cfg.target.arch, out_path=Path(args.export_objdiff))
        print(f"Wrote {args.export_objdiff} ({len(doc['units'])} unit(s), arch: {doc['arch']}).")
        return 0

    out = Path(args.output)
    if out.exists() and not args.force:
        print(f"Error: {out} already exists (pass --force to overwrite).", file=sys.stderr)
        return 1

    if getattr(args, "auto", False) or args.preset is None:
        detected = detect_repo_layout(out.resolve().parent)
        if detected is not None:
            out.write_text(render_detected_toml(detected), encoding="utf-8")
            print(f"Wrote {out} (auto-detected from {', '.join(detected['sources'])}, preset: {detected['preset']}).")
            return 0
        if getattr(args, "auto", False):
            print("Error: no objdiff.json, dtk config.yml, or splat.yaml found to auto-detect.", file=sys.stderr)
            return 1

    preset = args.preset or "prodg-wine"
    out.write_text(_PRESET_TEMPLATES[preset], encoding="utf-8")
    print(f"Wrote {out} (preset: {preset}).")
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    cfg = load_config(Path(args.config) if args.config else None)
    ctx, target_fn = _resolve_target(args, cfg)
    compiler = make_compiler(cfg, va=target_fn.va)
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
    compiler = make_compiler(cfg, va=target_fn.va)
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
    if getattr(args, "clean", False) and best.get("code") and best.get("verified"):
        from kintoun.cleaner import clean_matched_source

        cln = clean_matched_source(best["code"], target_fn, ctx, compiler, forbid_asm=cfg.search.forbid_asm)
        if cln.get("verified") and cln.get("cleaned_code"):
            best["code"] = cln["cleaned_code"]
            res["cleaned_steps"] = cln["applied_steps"]
    if args.write and best.get("code") and (best.get("verified") or args.write_best):
        src_path.write_text(best["code"], encoding="utf-8")
    if getattr(args, "integrate", None) and best.get("code") and best.get("verified"):
        from kintoun.project_io import integrate_matched_function

        res["integration"] = integrate_matched_function(
            best["code"],
            Path(args.integrate),
            target_fn.name,
            verify=True,
            target_fn=target_fn,
            ctx=ctx,
            compiler=compiler,
            forbid_asm=cfg.search.forbid_asm,
        )
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
    from kintoun.engine_lab import active_overlay_src_dir

    cfg = load_config(Path(args.config) if args.config else None)
    overlay = active_overlay_src_dir(cfg.root)
    payload = {
        "version": __version__,
        "project": cfg.project_name,
        "root": str(cfg.root),
        "compiler_preset": cfg.compiler.preset,
        "target_arch": cfg.target.arch,
        "local_engine_overlay": str(overlay) if overlay else None,
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
    active_preset = cfg.compiler_for(target_fn.va).preset
    chk = check_function(target_fn, ctx, configured_preset=active_preset)
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
        comp_fp = payload.get("compiler_fingerprint") or {}
        if comp_fp.get("warning"):
            print(f"  compiler warning: {comp_fp['warning']}")
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
        comp_fp = pack.get("compiler_fingerprint") or {}
        if comp_fp.get("warning"):
            print(f"Compiler Warning: {comp_fp['warning']}")
        if pack["blockers"]:
            print("Blockers: " + "; ".join(pack["blockers"]))
        if pack.get("incoming_callers"):
            print("Incoming Callers: " + ", ".join(pack["incoming_callers"]))
        if pack.get("vtable_or_data_refs"):
            print("Vtable/Data Refs: " + ", ".join(pack["vtable_or_data_refs"]))
        if pack["callees"]:
            print("Callees: " + ", ".join(pack["callees"]))
        if pack["globals"]:
            print("Globals: " + ", ".join(pack["globals"]))
        if pack.get("field_offset_consensus"):
            fields_s = ", ".join(f"{k}: {v}" for k, v in pack["field_offset_consensus"].items())
            print("Field Consensus: " + fields_s)
        if pack.get("exact_floats"):
            fl_s = ", ".join(f"{f['hex']} -> {f['exact_expr']}" for f in pack["exact_floats"][:6])
            print("Exact Floats: " + fl_s)
        if pack.get("magic_divisions"):
            md_s = ", ".join(f"{m['hex']} -> {m['c_hint']}" for m in pack["magic_divisions"][:6])
            print("Magic Divisions: " + md_s)
        if pack.get("inlined_helper_candidates"):
            inl_s = "; ".join(
                f"insns {c['insn_index_range']} shared by {c['shared_by_functions']} fns"
                for c in pack["inlined_helper_candidates"]
            )
            print("Inlined Helper Candidates: " + inl_s)
        if pack["callee_prototypes"]:
            print("\n## Matched Prototypes\n" + "\n".join(pack["callee_prototypes"]))
        print("\n## Target Disassembly\n" + pack["disassembly"])
    return 0


def cmd_close(args: argparse.Namespace) -> int:
    from kintoun.closer import close_near_miss

    cfg = load_config(Path(args.config) if args.config else None)
    ctx, target_fn = _resolve_target(args, cfg)
    compiler = make_compiler(cfg, va=target_fn.va)
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
    if getattr(args, "integrate", None) and best.get("code") and res.get("verified"):
        from kintoun.project_io import integrate_matched_function

        res["integration"] = integrate_matched_function(
            best["code"],
            Path(args.integrate),
            target_fn.name,
            verify=True,
            target_fn=target_fn,
            ctx=ctx,
            compiler=compiler,
            forbid_asm=cfg.search.forbid_asm,
        )
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
        tf_sub = ctx.resolve_function(args.func)
        compiler = make_compiler(cfg, va=tf_sub.va)
        code = Path(args.source).read_text(encoding="utf-8")
        out = wq.submit_match(
            args.agent,
            args.func,
            code,
            ctx,
            compiler,
            project_root=cfg.root,
            src_path=args.source,
            integrate_into=getattr(args, "integrate", None) or "",
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


def cmd_agent_bench(args: argparse.Namespace) -> int:
    from kintoun.agent_bench import (
        load_results_jsonl,
        render_agent_bench_markdown,
        run_agent_benchmark,
        select_agent_benchmark,
        summarize_agent_benchmark,
    )

    if args.action == "select":
        cfg = load_config(Path(args.config) if args.config else None)
        ctx = load_target_from_config(cfg)
        va_min = int(args.va_min, 0) if args.va_min else 0
        va_max = int(args.va_max, 0) if args.va_max else 0xFFFFFFFF
        doc = select_agent_benchmark(
            ctx,
            count=args.count,
            seed=args.seed,
            configured_preset=cfg.compiler.preset,
            va_min=va_min,
            va_max=va_max,
            exclude_switches=not args.include_switches,
        )
        out_p = Path(args.output or "bench_manifest_60.json")
        out_p.parent.mkdir(parents=True, exist_ok=True)
        out_p.write_text(json.dumps(doc, indent=2), encoding="utf-8")
        if args.json:
            print(json.dumps(doc, indent=2))
        else:
            print(
                f"Selected {doc['selected_count']} stratified plain-C functions -> {out_p}\n"
                f"  By size tier: {doc['by_size_tier']}\n"
                f"  By family:    {doc['by_family']}"
            )
        return 0

    if args.action == "run":
        if not args.manifest:
            raise ValueError("`kintoun agent-bench run` requires --manifest <manifest.json>")
        cfg = load_config(Path(args.config) if args.config else None)
        out_dir = Path(args.out_dir or ".kintoun/agent_bench")
        only = {s.strip() for s in args.only.split(",") if s.strip()} if args.only else None
        if args.whole_set:
            from kintoun.agent_bench import run_whole_set_agent_benchmark

            summary = run_whole_set_agent_benchmark(
                cfg,
                Path(args.manifest),
                out_dir,
                runner=args.runner,
                model=args.model,
                effort=args.effort,
                agent_bin=args.agent_bin or "",
                custom_template=args.agent_cmd or "",
                total_timeout_s=parse_duration_s(args.timeout, 1800.0),
                concurrency=args.concurrency,
                with_headless_baseline=not args.no_headless_baseline,
                headless_budget_s=parse_duration_s(args.headless_budget, 30.0),
                headless_max_candidates=args.headless_max_candidates,
                limit=args.limit,
                only_funcs=only,
                kintoun_cmd=args.kintoun_cmd or "",
            )
            md = render_agent_bench_markdown(summary, title=args.title)
            (out_dir / "REPORT.md").write_text(md, encoding="utf-8")
            if args.output:
                Path(args.output).write_text(md, encoding="utf-8")
            if args.json:
                print(json.dumps(summary, indent=2))
            return 0
        summary = run_agent_benchmark(
            cfg,
            Path(args.manifest),
            out_dir,
            runner=args.runner,
            model=args.model,
            effort=args.effort,
            agent_bin=args.agent_bin or "",
            custom_template=args.agent_cmd or "",
            per_func_timeout_s=parse_duration_s(args.timeout, 1800.0),
            concurrency=args.concurrency,
            with_headless_baseline=not args.no_headless_baseline,
            headless_budget_s=parse_duration_s(args.headless_budget, 30.0),
            headless_max_candidates=args.headless_max_candidates,
            limit=args.limit,
            only_funcs=only,
            resume=not args.no_resume,
            kintoun_cmd=args.kintoun_cmd or "",
        )
        md = render_agent_bench_markdown(summary, title=args.title)
        (out_dir / "REPORT.md").write_text(md, encoding="utf-8")
        if args.output:
            Path(args.output).write_text(md, encoding="utf-8")
        if args.json:
            print(json.dumps(summary, indent=2))
        else:
            print(md)
        return 0

    # `report`: render Markdown/JSON summary from an existing `results.jsonl` or `summary.json`
    src_p = Path(args.results or (Path(args.out_dir or ".kintoun/agent_bench") / "results.jsonl"))
    if src_p.suffix == ".json":
        summary = json.loads(src_p.read_text(encoding="utf-8"))
    else:
        rows = load_results_jsonl(src_p)
        summary = summarize_agent_benchmark(
            rows,
            runner=args.runner,
            model=args.model,
            effort=args.effort,
            per_func_timeout_s=parse_duration_s(args.timeout, 1800.0),
        )
    md = render_agent_bench_markdown(summary, title=args.title)
    if args.output:
        Path(args.output).write_text(md, encoding="utf-8")
    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print(md)
    return 0


def cmd_probe_flags(args: argparse.Namespace) -> int:
    from kintoun.prober import probe_compiler_flags

    cfg = load_config(Path(args.config) if args.config else None)
    ctx, target_fn = _resolve_target(args, cfg)
    source = Path(args.source).read_text(encoding="utf-8")
    rep = probe_compiler_flags(source, target_fn, ctx, cfg, workers=args.workers)
    if args.json:
        print(json.dumps(rep, indent=2))
    else:
        print(f"Flag probe for {rep['name']} ({rep['addr']}) [{rep['preset']}] in {rep['elapsed_s']}s:")
        for row in rep["results"]:
            tag = "MATCH" if row["verified"] else row["status"]
            print(f"  [{tag:<13}] aligned={row['aligned_pct']:6.2f}%  diff={str(row['different_bytes']):<5}  flags={row['flags']}")
        if rep["toml_snippet"]:
            print(f"\nBest kintoun.toml setting:\n  {rep['toml_snippet']}")
    return 0


def cmd_scratch(args: argparse.Namespace) -> int:
    from kintoun.scratch import run_scratch

    cfg = load_config(Path(args.config) if args.config else None)
    res = run_scratch(
        args.slug_or_url,
        cfg,
        from_json=Path(args.from_json) if args.from_json else None,
        compiler_dir=args.compiler_dir or "",
        budget_s=parse_duration_s(args.budget, 60.0),
        max_candidates=args.max_candidates,
        workers=args.workers,
        save_dir=Path(args.save_dir) if args.save_dir else None,
        out_source=Path(args.out) if args.out else None,
    )
    if args.json:
        print(json.dumps(res, indent=2))
    else:
        best = res.get("best") or {}
        print(
            f"[{'MATCH' if res.get('verified') else 'BEST'}] {res.get('function')} "
            f"(scratch={res.get('slug')}, arch={res.get('arch')}, preset={res.get('preset')})"
        )
        print(
            f"  aligned={(best.get('search') or {}).get('aligned_pct', 0.0):.2f}% "
            f"diff_bytes={best.get('different_bytes')}"
        )
    return 0 if res.get("verified") else 1


def cmd_import(args: argparse.Namespace) -> int:
    from kintoun.project_io import import_project_function

    cfg = load_config(Path(args.config) if args.config else None)
    res = import_project_function(
        cfg.root,
        args.func,
        c_file=Path(args.source) if args.source else None,
        map_file=Path(args.map) if args.map else None,
        out_candidate=Path(args.out) if args.out else None,
    )
    if args.json:
        print(json.dumps(res, indent=2))
    else:
        print(f"[IMPORTED] {res['function']} from {res['c_file']} (stub={res['stub_kind']})")
        if res["tu_flags"]["raw_flags"]:
            print(f"  discovered TU flags: {' '.join(res['tu_flags']['raw_flags'])}")
        if res["map_symbol"]:
            ms = res["map_symbol"]
            print(f"  map symbol: 0x{ms['va']:08X} ({ms['size']}B, {ms['section']})")
        if res["candidate_path"]:
            print(f"  wrote candidate: {res['candidate_path']}")
        else:
            print("\n" + res["candidate_code"].rstrip())
    return 0


def cmd_integrate(args: argparse.Namespace) -> int:
    from kintoun.project_io import integrate_matched_function

    cfg = load_config(Path(args.config) if args.config else None)
    matched_code = Path(args.source).read_text(encoding="utf-8")
    do_verify = not args.no_verify
    ctx = None
    target_fn = None
    compiler = None
    if do_verify:
        ctx, target_fn = _resolve_target(args, cfg)
        compiler = make_compiler(cfg, va=target_fn.va)
    res = integrate_matched_function(
        matched_code,
        Path(args.into),
        args.func,
        verify=do_verify,
        target_fn=target_fn,
        ctx=ctx,
        compiler=compiler,
        forbid_asm=cfg.search.forbid_asm,
        write=True,
    )
    if args.json:
        print(json.dumps(res, indent=2))
    else:
        if res.get("ok"):
            print(f"[INTEGRATED] {res['function']} -> {res['c_file']} (replaced {res['replaced']})")
        else:
            print(f"[FAILED] {res.get('error')}", file=sys.stderr)
    return 0 if res.get("ok") else 1


def cmd_atlas(args: argparse.Namespace) -> int:
    from kintoun.atlas import build_atlas_data, write_atlas_report

    cfg = load_config(Path(args.config) if args.config else None)
    if getattr(args, "target", None):
        ctx, _ = load_target_from_object(Path(args.target), None)
    else:
        ctx = load_target_from_config(cfg)
    src_dir = Path(args.src_dir) if args.src_dir else None
    if args.json and not args.output:
        print(json.dumps(build_atlas_data(ctx, cfg, src_dir=src_dir), indent=2))
        return 0
    out_html = Path(args.output or "atlas.html")
    rep = write_atlas_report(out_html, ctx, cfg, src_dir=src_dir)
    if args.json:
        print(json.dumps(rep, indent=2))
    else:
        print(
            f"Wrote {rep['output_html']} ({rep['total_functions']} functions, "
            f"{rep['matched_bytes_pct']}% bytes matched)."
        )
    return 0


def cmd_clean(args: argparse.Namespace) -> int:
    from kintoun.cleaner import clean_matched_source

    cfg = load_config(Path(args.config) if args.config else None)
    ctx, target_fn = _resolve_target(args, cfg)
    compiler = make_compiler(cfg, va=target_fn.va)
    src_path = Path(args.source)
    source = src_path.read_text(encoding="utf-8")
    res = clean_matched_source(source, target_fn, ctx, compiler, forbid_asm=cfg.search.forbid_asm)
    if args.write and res.get("verified") and res.get("changed"):
        src_path.write_text(res["cleaned_code"], encoding="utf-8")
    if args.json:
        print(json.dumps(res, indent=2))
    else:
        if not res.get("ok"):
            print(f"[FAILED] {res.get('error')}", file=sys.stderr)
        else:
            steps_s = ", ".join(res["applied_steps"]) if res["applied_steps"] else "none needed"
            print(
                f"[CLEANED] {res['name']} ({res['addr']}) saved={res['lines_saved']} line(s) "
                f"steps={len(res['applied_steps'])} ({steps_s})"
            )
            if not args.write and res["changed"]:
                print("\n" + res["cleaned_code"].rstrip())
    return 0 if res.get("ok") else 1


def cmd_watch(args: argparse.Namespace) -> int:
    from kintoun.watch import WatchSession, format_watch_panel, run_watch_loop

    cfg = load_config(Path(args.config) if args.config else None)
    ctx, target_fn = _resolve_target(args, cfg)
    compiler = make_compiler(cfg, va=target_fn.va)
    cache_dir = cfg.resolve_path(cfg.search.cache_dir) or (cfg.root / ".kintoun" / "cache")
    sess = WatchSession(
        source_path=Path(args.source),
        target_fn=target_fn,
        ctx=ctx,
        compiler=compiler,
        cache_dir=cache_dir,
        forbid_asm=cfg.search.forbid_asm,
        auto_close_pct=args.auto_close_at,
        write_on_match=args.write,
    )
    if args.once:
        ev = sess.evaluate_current()
        if args.json:
            print(json.dumps(ev, indent=2))
        else:
            print(format_watch_panel(ev))
        return 0 if ev["verified"] else 1
    run_watch_loop(sess, interval_s=args.interval, stop_on_verified=not args.keep_running)
    return 0


def cmd_synth_headers(args: argparse.Namespace) -> int:
    from kintoun.synth import synthesize_project_headers

    cfg = load_config(Path(args.config) if args.config else None)
    if getattr(args, "target", None):
        ctx, _ = load_target_from_object(Path(args.target), None)
    else:
        ctx = load_target_from_config(cfg)
    out_h = Path(args.out) if args.out else None
    res = synthesize_project_headers(ctx, class_filter=args.class_name or "", out_header=out_h)
    if args.json:
        print(json.dumps(res, indent=2))
    elif out_h:
        print(
            f"Wrote {out_h} ({len(res['structs'])} struct(s), {len(res['vtables'])} vtable(s), "
            f"{len(res['debug_strings'])} debug string(s))."
        )
    else:
        print(res["header_code"].rstrip())
    return 0


def cmd_doctor(args: argparse.Namespace) -> int:
    from kintoun.doctor import run_doctor

    cfg = load_config(Path(args.config) if args.config else None)
    rep = run_doctor(cfg, scan_dir=Path(args.scan_dir) if args.scan_dir else None)
    if args.json:
        print(json.dumps(rep, indent=2))
    else:
        print(f"Kintoun Doctor - {rep['project']} (arch={rep['arch']}, preset={rep['preset']})")
        for chk in rep["checks"]:
            tag = "OK" if chk["ok"] else "WARN"
            print(f"  [{tag:<4}] {chk['check']}: {chk['detail']}")
        for dc in rep["discovered_compilers"]:
            print(f"  [FOUND] {dc['preset']} ({dc['arch']}) -> {dc['compiler_dir']}")
    return 0 if rep["ok"] else 1


def cmd_export_dataset(args: argparse.Namespace) -> int:
    from kintoun.dataset import export_dataset

    cfg = load_config(Path(args.config) if args.config else None)
    cache_dir = cfg.resolve_path(cfg.search.cache_dir) or (cfg.root / ".kintoun" / "cache")
    try:
        ctx = load_target_from_config(cfg) if (cfg.target.dol or cfg.target.binary) else None
    except Exception:
        ctx = None
    src_dir = Path(args.src_dir) if args.src_dir else (cfg.root / "src")
    kinds = tuple(k.strip() for k in args.kinds.split(",") if k.strip())
    rep = export_dataset(cache_dir, ctx, src_dir=src_dir, out_path=Path(args.output), kinds=kinds)
    if args.json:
        print(json.dumps(rep, indent=2))
    else:
        print(f"Wrote {rep['output_path']} ({rep['total_records']} record(s): {rep['counts']}).")
    return 0


def cmd_engine(args: argparse.Namespace) -> int:
    from kintoun.engine_lab import EngineLab

    cfg = load_config(Path(args.config) if args.config else None)
    lab = EngineLab(cfg)
    act = args.action

    if act == "init":
        out = lab.init_lab(builders=args.builders)
    elif act == "status":
        out = lab.status()
    elif act == "sync":
        if not args.builder:
            raise ValueError("engine sync requires --builder <id>")
        out = lab.sync_builder(args.builder, force=args.force)
    elif act == "commit":
        if not args.builder or not args.claim:
            raise ValueError("engine commit requires --builder <id> and --claim <description>")
        out = lab.commit_builder(args.builder, args.claim)
    elif act == "findings":
        sub_act = args.findings_action or "show"
        if sub_act == "show":
            out = lab.findings_show(limit=args.limit)
        elif sub_act == "start":
            if not args.builder or not args.change:
                raise ValueError("engine findings start requires --builder and --change")
            out = lab.findings_start(args.builder, args.change, what=args.what or "")
        elif sub_act == "log":
            if not args.builder or not args.change:
                raise ValueError("engine findings log requires --builder and --change")
            out = lab.findings_log(
                args.builder,
                args.change,
                dev_summary=args.dev or "",
                verdict=args.verdict or "tested",
                lesson=args.lesson or "",
            )
        elif sub_act == "done":
            if not args.builder:
                raise ValueError("engine findings done requires --builder")
            out = lab.findings_done(args.builder)
        else:
            raise ValueError(f"unknown findings action: {sub_act}")
    elif act == "make-dev":
        ctx = load_target_from_config(cfg)
        out = lab.make_dev_set(
            ctx,
            out_path=Path(args.output) if args.output else None,
            count=args.count,
            seed=args.seed,
            seeds_dir=Path(args.seeds_dir) if args.seeds_dir else None,
        )
    elif act == "bench":
        if not args.set:
            raise ValueError("engine bench requires --set <manifest.json>")
        out = lab.run_isolated_arm(
            args.arm,
            Path(args.set),
            budget_s=parse_duration_s(args.budget, 15.0),
            max_candidates=args.max_candidates,
            workers=args.workers,
            mark_builder_seen=True,
        )
    elif act == "gate":
        out = lab.run_unseen_gate(
            candidate_arm=args.candidate,
            count=args.count,
            budget_s=parse_duration_s(args.budget, 20.0),
            max_candidates=args.max_candidates,
            workers=args.workers,
            min_functions=args.min_functions,
            confirm_runs=args.confirm_runs,
            ablate=not args.no_ablate,
            promote=args.promote,
            seeds_dir=Path(args.seeds_dir) if args.seeds_dir else None,
            pool_manifest=Path(args.pool_manifest) if args.pool_manifest else None,
        )
    elif act == "rollback":
        bdir = Path(args.backup) if (args.backup and args.backup != "LATEST") else None
        out = lab.rollback(bdir, disable_overlay=args.disable)
    else:
        raise ValueError(f"unknown engine action: {act}")

    print(json.dumps(out, indent=2))
    if act == "gate":
        return 0 if out.get("win") else 1
    return 0 if out.get("ok", True) else 1


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="kintoun", description="Kintoun matching-C decompilation permuter & verifier.")
    p.add_argument("--version", action="version", version=f"kintoun {__version__}")
    p.add_argument("-c", "--config", help="Path to kintoun.toml (auto-discovered upward if omitted).")
    sub = p.add_subparsers(dest="cmd", required=True)

    p_init = sub.add_parser("init", help="Create a starter kintoun.toml (auto-detects objdiff.json, dtk, or splat.yaml).")
    p_init.add_argument("--preset", choices=sorted(_PRESET_TEMPLATES), default=None)
    p_init.add_argument("--auto", action="store_true", help="Require auto-detection from objdiff.json, dtk config.yml, or splat.yaml.")
    p_init.add_argument("--export-objdiff", help="Export an objdiff.json unit manifest from src/*.c to path.")
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
    p_perm.add_argument("--clean", action="store_true", help="On byte-exact match, run byte-verified de-goto & temp cleanup.")
    p_perm.add_argument("--integrate", help="On byte-exact match, splice into multi-function .c file and verify full TU.")
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
    p_close.add_argument("--integrate", help="On exact match, splice into multi-function .c file and verify full TU.")
    p_close.add_argument("--json", action="store_true", help="Emit JSON output.")
    p_close.set_defaults(func_cb=cmd_close)

    p_q = sub.add_parser("queue", help="Multi-agent work queue with chess-clock enforcement and quarantine.")
    p_q.add_argument("action", choices=["init", "status", "claim", "clock", "submit", "fail", "unquarantine"])
    p_q.add_argument("--agent", default="local", help="Agent or developer identifier.")
    p_q.add_argument("--func", help="Function name or 0xADDRESS (for submit/fail).")
    p_q.add_argument("--source", help="Candidate .c path (for submit).")
    p_q.add_argument("--integrate", help="Multi-function project .c path to splice and verify on submit.")
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

    p_ab = sub.add_parser(
        "agent-bench",
        help="Stratified 60-function zero-prior-context CLI agent benchmark (select, run, report).",
    )
    p_ab.add_argument("action", choices=["select", "run", "report"], help="Benchmark action.")
    p_ab.add_argument("--manifest", help="Path to stratified JSON manifest (for `run`).")
    p_ab.add_argument("--out-dir", help="Output directory for `results.jsonl`, `logs/`, and `best/`.")
    p_ab.add_argument("--results", help="Path to `results.jsonl` or `summary.json` (for `report`).")
    p_ab.add_argument("-o", "--output", help="Output path (`manifest.json` for `select`, `REPORT.md` for `run`/`report`).")
    p_ab.add_argument("--count", type=int, default=60, help="Number of stratified functions to select (default 60).")
    p_ab.add_argument("--seed", type=int, default=20261124, help="Deterministic RNG seed for `select`.")
    p_ab.add_argument("--va-min", help="Optional minimum virtual address (hex) for `select`.")
    p_ab.add_argument("--va-max", help="Optional maximum virtual address (hex) for `select`.")
    p_ab.add_argument("--include-switches", action="store_true", help="Include jump-table switch functions in `select`.")
    p_ab.add_argument("--runner", choices=["agy", "claude", "codex", "custom"], default="agy", help="Agent CLI runner.")
    p_ab.add_argument("--model", default="gemini-4-neon-high", help="Agent model identifier (default gemini-4-neon-high).")
    p_ab.add_argument("--effort", default="high", help="Reasoning effort level (default high).")
    p_ab.add_argument("--agent-bin", help="Override path to agent CLI binary.")
    p_ab.add_argument("--agent-cmd", help="Custom command template with {prompt}, {func}, {addr}, {workspace}, {timeout_s}.")
    p_ab.add_argument("--kintoun-cmd", help="Override kintoun CLI command advertised inside zero-context prompt.")
    p_ab.add_argument("--timeout", default="30m", help="Wall-clock time limit: per function, or for the whole set with --whole-set (default 30m).")
    p_ab.add_argument(
        "--whole-set",
        action="store_true",
        help="One agent session works every function on one shared clock (--timeout) and decides how to split its time.",
    )
    p_ab.add_argument("--concurrency", type=int, default=1, help="Number of isolated functions to benchmark concurrently.")
    p_ab.add_argument("--no-headless-baseline", action="store_true", help="Skip 30s headless `kintoun permute` baseline pass.")
    p_ab.add_argument("--headless-budget", default="30s", help="Headless baseline budget per function (default 30s).")
    p_ab.add_argument("--headless-max-candidates", type=int, default=300, help="Headless baseline max candidates (default 300).")
    p_ab.add_argument("--limit", type=int, default=0, help="Evaluate only the first N manifest entries (0 = all).")
    p_ab.add_argument("--only", help="Comma-separated function names to run.")
    p_ab.add_argument("--no-resume", action="store_true", help="Ignore existing `results.jsonl` entries.")
    p_ab.add_argument("--title", default="Zero-Context Agent Benchmark", help="Markdown report title.")
    p_ab.add_argument("--json", action="store_true", help="Emit JSON output.")
    p_ab.set_defaults(func_cb=cmd_agent_bench)
    __import__("kintoun.overseer_bench", fromlist=["add_parser"]).add_parser(sub)
    __import__("kintoun.overseer_course", fromlist=["add_parser"]).add_parser(sub)

    p_pf = sub.add_parser("probe-flags", help="Test a candidate C file across compiler flag matrices to find optimal TU flags.")
    p_pf.add_argument("source", help="Path to candidate .c file.")
    p_pf.add_argument("--func", help="Function name or 0xADDRESS.")
    p_pf.add_argument("--target", help="Standalone target .o file.")
    p_pf.add_argument("--workers", type=int, default=4, help="Parallel compiler workers.")
    p_pf.add_argument("--json", action="store_true", help="Emit JSON output.")
    p_pf.set_defaults(func_cb=cmd_probe_flags)

    p_sc = sub.add_parser("scratch", help="Import a decomp.me scratch by slug/URL (or offline JSON) and run Kintoun locally.")
    p_sc.add_argument("slug_or_url", help="decomp.me scratch slug or URL (or label when using --from-json).")
    p_sc.add_argument("--from-json", help="Offline scratch JSON path (for local/air-gapped bundles).")
    p_sc.add_argument("--compiler-dir", help="Override compiler_dir for the imported scratch.")
    p_sc.add_argument("--budget", type=str, default="60s", help="Search time budget (default 60s).")
    p_sc.add_argument("--max-candidates", type=int, default=800, help="Max candidates to evaluate.")
    p_sc.add_argument("--workers", type=int, default=0, help="Parallel compiler workers (0 = auto).")
    p_sc.add_argument("--save-dir", help="Directory to save downloaded target.o, candidate.c, and scratch.json.")
    p_sc.add_argument("--out", help="Write best/verified C source to path.")
    p_sc.add_argument("--json", action="store_true", help="Emit JSON output.")
    p_sc.set_defaults(func_cb=cmd_scratch)

    p_imp = sub.add_parser("import", help="Extract a standalone compilable candidate .c from an INCLUDE_ASM/GLOBAL_ASM repo.")
    p_imp.add_argument("source", nargs="?", help="Optional multi-function .c file (auto-searched under src/ if omitted).")
    p_imp.add_argument("--func", required=True, help="Target function name.")
    p_imp.add_argument("--map", help="Optional GNU ld / mwld / dtk .map file to resolve symbol VA and size.")
    p_imp.add_argument("-o", "--out", help="Output path for extracted candidate .c file.")
    p_imp.add_argument("--json", action="store_true", help="Emit JSON output.")
    p_imp.set_defaults(func_cb=cmd_import)

    p_int = sub.add_parser("integrate", help="Splice a matched C function back into an INCLUDE_ASM/GLOBAL_ASM .c file and verify.")
    p_int.add_argument("source", help="Path to matched standalone .c file.")
    p_int.add_argument("--into", required=True, help="Target multi-function project .c file.")
    p_int.add_argument("--func", required=True, help="Function name to splice.")
    p_int.add_argument("--target", help="Optional standalone target .o file for verification.")
    p_int.add_argument("--no-verify", action="store_true", help="Skip full-TU compilation & verification check.")
    p_int.add_argument("--json", action="store_true", help="Emit JSON output.")
    p_int.set_defaults(func_cb=cmd_integrate)

    p_atl = sub.add_parser("atlas", help="Generate a self-contained single-file HTML Decomp Atlas & Run Report.")
    p_atl.add_argument("-o", "--output", default="atlas.html", help="Output HTML file path (default: atlas.html).")
    p_atl.add_argument("--target", help="Optional standalone .o file (alternative to kintoun.toml binary).")
    p_atl.add_argument("--src-dir", help="Matched C directory (defaults to ./src).")
    p_atl.add_argument("--json", action="store_true", help="Emit JSON summary.")
    p_atl.set_defaults(func_cb=cmd_atlas)

    p_cln = sub.add_parser("clean", help="Simplify a verified C match (de-goto, unused locals, casts) while keeping 0 diff bytes.")
    p_cln.add_argument("source", help="Path to matched .c file.")
    p_cln.add_argument("--func", help="Function name or 0xADDRESS.")
    p_cln.add_argument("--target", help="Standalone target .o file.")
    p_cln.add_argument("--write", action="store_true", help="Write cleaned C back to source file.")
    p_cln.add_argument("--json", action="store_true", help="Emit JSON output.")
    p_cln.set_defaults(func_cb=cmd_clean)

    p_wt = sub.add_parser("watch", help="Watch a .c file on save with live aligned diffs, deltas, and optional auto-close.")
    p_wt.add_argument("source", help="Path to candidate .c file.")
    p_wt.add_argument("--func", help="Function name or 0xADDRESS.")
    p_wt.add_argument("--target", help="Standalone target .o file.")
    p_wt.add_argument("--interval", type=float, default=0.25, help="File poll interval in seconds (default 0.25).")
    p_wt.add_argument("--auto-close-at", type=float, default=0.0, help="Auto-run targeted close when aligned %% >= threshold (e.g. 90).")
    p_wt.add_argument("--write", action="store_true", help="Write back winning C if auto-close verifies.")
    p_wt.add_argument("--once", action="store_true", help="Evaluate once and exit.")
    p_wt.add_argument("--keep-running", action="store_true", help="Keep watching even after VERIFIED.")
    p_wt.add_argument("--json", action="store_true", help="With --once, emit JSON output.")
    p_wt.set_defaults(func_cb=cmd_watch)

    p_syn = sub.add_parser("synth-headers", help="Synthesize factual C structs, vtables, and debug-string hints from the binary.")
    p_syn.add_argument("-o", "--out", help="Output .h file path (prints to stdout if omitted).")
    p_syn.add_argument("--class-name", help="Filter synthesis to a single class/module prefix.")
    p_syn.add_argument("--target", help="Optional standalone .o file.")
    p_syn.add_argument("--json", action="store_true", help="Emit JSON output.")
    p_syn.set_defaults(func_cb=cmd_synth_headers)

    p_doc = sub.add_parser("doctor", help="Validate config, Wine/wibo, compiler smoke test, and scan local compiler directories.")
    p_doc.add_argument("--scan-dir", help="Optional directory (e.g. tools/) to scan for known compiler binaries.")
    p_doc.add_argument("--json", action="store_true", help="Emit JSON output.")
    p_doc.set_defaults(func_cb=cmd_doctor)

    p_exp = sub.add_parser("export-dataset", help="Export verifiable SFT and DPO fine-tuning JSONL datasets from project history.")
    p_exp.add_argument("-o", "--output", default="dataset.jsonl", help="Output .jsonl path (default: dataset.jsonl).")
    p_exp.add_argument("--src-dir", help="Matched C directory (defaults to ./src).")
    p_exp.add_argument("--kinds", default="sft_decomp,sft_repair,dpo_pair", help="Comma-separated record kinds to export.")
    p_exp.add_argument("--json", action="store_true", help="Emit JSON summary.")
    p_exp.set_defaults(func_cb=cmd_export_dataset)

    p_eng = sub.add_parser(
        "engine",
        help="Self-learning side-tree Engine Lab with blind unseen promotion gate, ablation, and rollback.",
    )
    p_eng.add_argument(
        "action",
        choices=["init", "status", "sync", "commit", "findings", "make-dev", "bench", "gate", "rollback"],
    )
    p_eng.add_argument("findings_action", nargs="?", choices=["show", "start", "log", "done"], help="Sub-action for `findings`.")
    p_eng.add_argument("--builders", type=int, default=4, help="Number of builder side trees on `init` (default 4).")
    p_eng.add_argument("--builder", help="Builder identifier (e.g. b1, b2, b3, b4).")
    p_eng.add_argument("--claim", help="One-line description of improvement for `commit`.")
    p_eng.add_argument("--force", action="store_true", help="Discard uncommitted builder edits on `sync`.")
    p_eng.add_argument("--change", help="Short slug for `findings start/log`.")
    p_eng.add_argument("--what", help="Hypothesis summary for `findings start`.")
    p_eng.add_argument("--dev", help="Dev benchmark summary for `findings log`.")
    p_eng.add_argument("--verdict", help="Verdict label (`committed`, `reverted`, `tested`) for `findings log`.")
    p_eng.add_argument("--lesson", help="One-line takeaway for `findings log`.")
    p_eng.add_argument("--limit", type=int, default=15, help="Max entries for `findings show`.")
    p_eng.add_argument("-o", "--output", help="Output manifest path for `make-dev`.")
    p_eng.add_argument("--set", help="Dev manifest path for `bench`.")
    p_eng.add_argument("--arm", default="live", help="Engine arm for `bench` (`live`, `combined`, `b1`..`b4`, or path).")
    p_eng.add_argument("--candidate", default="combined", help="Candidate arm for `gate` (default `combined`).")
    p_eng.add_argument("--count", type=int, default=40, help="Number of functions to sample (`make-dev` or unseen `gate`).")
    p_eng.add_argument("--min-functions", type=int, default=4, help="Minimum unseen sample size required by `gate`.")
    p_eng.add_argument("--seed", type=int, default=1, help="RNG seed for `make-dev`.")
    p_eng.add_argument("--budget", type=str, default="20s", help="Per-function search budget.")
    p_eng.add_argument("--max-candidates", type=int, default=250, help="Max candidates per function.")
    p_eng.add_argument("--workers", type=int, default=1, help="Worker count inside isolated arm benchmark.")
    p_eng.add_argument("--confirm-runs", type=int, default=1, help="Independent unseen gate draws required before win (1..3).")
    p_eng.add_argument("--no-ablate", action="store_true", help="Skip per-commit ablation on `combined` during `gate`.")
    p_eng.add_argument("--promote", action="store_true", help="Promote candidate into `live/` and enable overlay if gate wins.")
    p_eng.add_argument("--seeds-dir", help="Optional directory of initial `<func>.c` seeds.")
    p_eng.add_argument("--pool-manifest", help="Optional JSON manifest pool for unseen gate sampling.")
    p_eng.add_argument("--backup", default="LATEST", help="Backup directory (or LATEST) for `rollback`.")
    p_eng.add_argument("--disable", action="store_true", help="Disable project-local engine overlay (`rollback --disable`).")
    p_eng.add_argument("--json", action="store_true", help="Emit JSON output.")
    p_eng.set_defaults(func_cb=cmd_engine)
    return p


def _maybe_reexec_into_local_overlay(argv: list[str] | None) -> int | None:
    """When invoked from CLI (`argv is None`) in a project with a promoted `live/` engine, delegate to it."""
    if argv is not None:
        return None
    import os
    import subprocess

    if os.environ.get("KINTOUN_OVERLAY_ACTIVE") == "1" or os.environ.get("KINTOUN_DISABLE_LOCAL_ENGINE") == "1":
        return None
    raw_args = sys.argv[1:]
    # Never delegate `engine` management/rollback commands so `engine rollback` is always immune to side-tree bugs.
    non_flag = [a for i, a in enumerate(raw_args) if not a.startswith("-") and (i == 0 or raw_args[i - 1] not in ("-c", "--config"))]
    if not non_flag or non_flag[0] in ("engine", "init"):
        return None

    cfg_arg: Path | None = None
    for i, a in enumerate(raw_args):
        if a in ("-c", "--config") and i + 1 < len(raw_args):
            cfg_arg = Path(raw_args[i + 1])
            break
    try:
        cfg = load_config(cfg_arg)
    except Exception:
        return None

    from kintoun.engine_lab import active_overlay_src_dir

    overlay_src = active_overlay_src_dir(cfg.root)
    if overlay_src is None:
        return None

    existing_pp = os.environ.get("PYTHONPATH", "")
    pp = f"{overlay_src}{os.pathsep}{existing_pp}" if existing_pp else str(overlay_src)
    env = {**os.environ, "PYTHONPATH": pp, "KINTOUN_OVERLAY_ACTIVE": "1", "PYTHONDONTWRITEBYTECODE": "1"}
    proc = subprocess.run([sys.executable, "-B", "-m", "kintoun.cli", *raw_args], env=env)
    return int(proc.returncode)


def main(argv: list[str] | None = None) -> int:
    delegated_rc = _maybe_reexec_into_local_overlay(argv)
    if delegated_rc is not None:
        return delegated_rc
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func_cb(args)
    except Exception as exc:
        print(f"kintoun error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
