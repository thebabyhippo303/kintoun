"""Overseer course (`kintoun overseer-course run.toml`): an overseer team runs a fixed course of phases unattended.

Each phase has its own clock and kind:
  - `match`: the overseer and its workers match functions (as in `kintoun overseer-bench`).
  - `engine`: workers switch to building the team's own engine in a Kintoun Engine Lab shared by every game
    folder, and the overseer adjusts its strategy for the next pass. Function files are frozen: anything
    changed in them during an engine phase is discarded when the phase ends.

The overseer is started fresh for every phase with that phase's brief (templates `phase_<kind>_overseer.md` and
`phase_<kind>_worker.md`, filled in from the run file) and keeps its own notes in `OVERSEER-NOTES.md`. Nobody
intervenes between phases. The function files are scored after every matching phase and at the end, each time
re-verified outside the workspace.

Run file: the same `[set]`, `[overseer]`, `[workers]` and `[machine]` tables as `overseer-bench`, plus
`[[phases]]` rows with `name`, `kind` and `duration` (see `templates/overseer/course.example.toml`).
"""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import tomllib
from typing import Any

from kintoun.agent_bench import FAMILIES, SIZE_TIERS, _agg_arm, _recover_best_cached_source, build_agent_command, summarize_agent_benchmark
from kintoun.compiler import make_compiler
from kintoun.config import load_config, parse_duration_s
from kintoun.overseer_bench import _TEAM_SCRIPT, TEMPLATE_DIR, TeamBroker, _killpg, _peak, fill_template, machine_note
from kintoun.search.runner import rank_result
from kintoun.targets import load_target_from_config
from kintoun.verify import verify_source

KINDS = ("match", "engine")


def _snapshot(ws: Path, games: list[str], dst: Path) -> None:
    """Copy every game's function files and Kintoun cache (the scored state) to `dst/games/<game>/`."""
    for g in games:
        src = ws / "games" / g
        d = dst / "games" / g
        shutil.copytree(src / "funcs", d / "funcs", dirs_exist_ok=True)
        cache = src / ".kintoun" / "cache"
        if cache.is_dir():
            shutil.copytree(cache, d / ".kintoun" / "cache", dirs_exist_ok=True)


def _restore(ws: Path, games: list[str], snap: Path) -> None:
    """Put back the function files and caches of `snap` (discards an engine phase's function edits)."""
    for g in games:
        gws = ws / "games" / g
        shutil.rmtree(gws / "funcs", ignore_errors=True)
        shutil.copytree(snap / "games" / g / "funcs", gws / "funcs")
        shutil.rmtree(gws / ".kintoun" / "cache", ignore_errors=True)
        sc = snap / "games" / g / ".kintoun" / "cache"
        if sc.is_dir():
            shutil.copytree(sc, gws / ".kintoun" / "cache")


def _score_state(state: Path, funcs: list[dict[str, Any]], set_root: Path, ctxs: dict[str, Any],
                 headless: dict[str, Any], out_best: Path | None, concurrency: int) -> list[dict[str, Any]]:
    def one(f: dict[str, Any]) -> dict[str, Any]:
        cfg, ctx = ctxs[f["game"]]
        tf = ctx.resolve_function(f["func"])
        comp = make_compiler(cfg, va=tf.va)
        gws = state / "games" / f["game"]
        seed = (set_root / f["source"]).read_text(encoding="utf-8")
        fp = gws / "funcs" / f"{f['func']}.c"
        cands = ([fp.read_text(encoding="utf-8", errors="replace")] if fp.is_file() else []) + _recover_best_cached_source(gws, f["func"]) + [seed]
        best, best_src = None, seed
        for src in cands:
            v = verify_source(src, tf, ctx, comp, lines=24, forbid_asm=True)
            if best is None or rank_result(v) < rank_result(best):
                best, best_src = v, src
                if v.get("verified"):
                    break
        if out_best is not None:
            (out_best / f"{f['game']}_{f['func']}.c").write_text(best_src, encoding="utf-8")
        cached = headless.get(f"{f['game']}/{f['func']}") or {}
        ac = best.get("status") in ("verified", "mismatch", "unresolved")
        return {
            "game": f["game"], "func": f["func"], "addr": f["addr"], "size_bytes": f["size_bytes"],
            "size_tier": f.get("size_tier", "other"), "family": f.get("family", "other"), "mode": "overseer_course",
            "seed": cached.get("seed") or {"compiled": False, "verified": False, "aligned_pct": 0.0},
            "headless": cached.get("headless"),
            "agent": {"compiled": ac, "verified": bool(best.get("verified")), "status": best.get("status", "error"),
                      "aligned_pct": round(float((best.get("search") or {}).get("aligned_pct") or 0.0), 2) if ac else 0.0,
                      "different_bytes": best.get("different_bytes"), "timed_out": False},
        }
    with ThreadPoolExecutor(max_workers=max(1, concurrency)) as pool:
        return list(pool.map(one, funcs))


def _phase_context(i: int, phases: list[dict[str, Any]]) -> str:
    if i == 0:
        return "This is the first phase."
    done = ", ".join(f"{p['name']}" for p in phases[:i])
    text = (f"Already over: {done}. Read `OVERSEER-NOTES.md` first (your own notes from earlier phases); "
            f"`kintoun engine status` shows whether the builders promoted a new engine.")
    if any(p["kind"] == "engine" for p in phases[:i]):
        text += " Function files hold the results of the matching passes so far; edits made during engine building were discarded."
    return text


def run_overseer_course(run_path: Path, out_dir: Path, *, concurrency: int = 4, kintoun_cmd: str = "kintoun") -> dict[str, Any]:
    run = tomllib.loads(Path(run_path).read_text(encoding="utf-8"))
    base = Path(run_path).resolve().parent
    man_path = (base / run["set"]["manifest"]).resolve()
    set_root = man_path.parent
    manifest = json.loads(man_path.read_text(encoding="utf-8"))
    funcs: list[dict[str, Any]] = manifest["functions"]
    games = sorted({f["game"] for f in funcs})
    phases = [dict(p) for p in run["phases"]]
    for p in phases:
        if p.get("kind") not in KINDS:
            raise ValueError(f"phase kind must be one of {KINDS}: {p}")
        p["seconds"] = parse_duration_s(str(p.get("duration", "30m")), 1800.0)
    out_dir = Path(out_dir)
    for sub in ("logs", "workers", "snapshots", "best"):
        (out_dir / sub).mkdir(parents=True, exist_ok=True)
    (out_dir / "RUN.toml").write_text(Path(run_path).read_text(encoding="utf-8"), encoding="utf-8")

    ctxs: dict[str, Any] = {}
    for g in games:
        cfg = load_config(set_root / "games" / g / "kintoun.toml")
        ctxs[g] = (cfg, load_target_from_config(cfg))
    src_pkg_dir = Path(__file__).resolve().parent.parent
    skills_root = src_pkg_dir.parent / "skills"
    ov, wk = run["overseer"], run["workers"]
    phase_rows: list[dict[str, Any]] = []
    t_wall0 = time.monotonic()

    with tempfile.TemporaryDirectory(prefix="kintoun_ovcourse_") as tmp_ws:
        ws = Path(tmp_ws)
        lab = ws / ".engine_lab"
        lab.mkdir()
        rows_md = ["| Game | Function | Address | Size | File |", "|---|---|---|---|---|"]
        game_desc = []
        for g in games:
            gsrc, gdst = set_root / "games" / g, ws / "games" / g
            (gdst / "funcs").mkdir(parents=True)
            (gdst / ".kintoun").mkdir()
            os.symlink(lab, gdst / ".kintoun" / "engine_lab")
            shutil.copytree(gsrc / "orig", gdst / "orig")
            shutil.copy2(gsrc / "kintoun.toml", gdst / "kintoun.toml")
            game_desc.append(f"`{g}` ({ctxs[g][1].arch}, {ctxs[g][0].compiler.preset})")
        for f in funcs:
            shutil.copy2(set_root / f["source"], ws / "games" / f["game"] / "funcs" / f"{f['func']}.c")
            rows_md.append(f"| `{f['game']}` | `{f['func']}` | `{f['addr']}` | {f['size_bytes']} | `games/{f['game']}/funcs/{f['func']}.c` |")
        (ws / "FUNCTIONS.md").write_text("\n".join(rows_md) + "\n", encoding="utf-8")
        (ws / "OVERSEER-NOTES.md").write_text("", encoding="utf-8")
        (ws / "workers").mkdir()
        for sk in ("kintoun-match", "ENGINE-BUILDER"):
            if (skills_root / sk).is_dir():
                shutil.copytree(skills_root / sk, ws / "skills" / sk)

        env = dict(os.environ)
        pp = env.get("PYTHONPATH", "")
        env["PYTHONPATH"] = f"{src_pkg_dir}{os.pathsep}{pp}" if pp else str(src_pkg_dir)
        env["ORIG_PATH"] = env.get("PATH", "")
        shim = ws / ".kintoun_bin"
        shim.mkdir()
        kcfg = ws / ".kintoun_config"
        kcfg.mkdir()
        # Kintoun's engine trust record lives in the workspace, so an engine promoted by any agent is used by all
        (shim / "kintoun").write_text(
            f"#!/bin/sh\nXDG_CONFIG_HOME={shlex.quote(str(kcfg))} PYTHONPATH={shlex.quote(env['PYTHONPATH'])} "
            f"exec {shlex.quote(sys.executable)} -m kintoun.cli \"$@\"\n", encoding="utf-8")
        (shim / "kintoun").chmod(0o755)
        team = ws / ".team_bin"
        team.mkdir()
        (team / "team.py").write_text(_TEAM_SCRIPT.replace("__WS__", repr(str(ws))), encoding="utf-8")
        for name in ("spawn-worker", "worker-status", "worker-log", "stop-worker"):
            (team / name).symlink_to("team.py")
        (team / "team.py").chmod(0o755)
        oenv = dict(env)
        oenv["PATH"] = f"{shim}{os.pathsep}{team}{os.pathsep}{env.get('PATH', '')}"

        mx = int(wk.get("max", 0) or 0)
        plan = "; ".join(f"phase {i + 1}, {p['name']} ({int(round(p['seconds'] / 60))} min)" for i, p in enumerate(phases)) + "; then the final score."
        values = {
            "worker_label": wk.get("label", wk["model"]), "overseer_label": ov.get("label", ov["model"]),
            "max_workers_note": f" (at most {mx} at a time)" if mx else "", "n_functions": len(funcs), "n_games": len(games),
            "game_list": ", ".join(game_desc), "machine": run.get("machine", {}).get("note") or machine_note(),
            "kintoun_cmd": kintoun_cmd, "course_plan": plan, "phase_count": len(phases),
        }
        broker: TeamBroker | None = None
        last_match_snap: Path | None = None
        for i, p in enumerate(phases):
            total_s = p["seconds"]
            pv = {**values, "phase_index": i + 1, "phase_name": p["name"], "phase_s": int(total_s),
                  "phase_min": max(1, int(round(total_s / 60))), "phase_context": _phase_context(i, phases),
                  "clock_s": int(total_s), "clock_min": max(1, int(round(total_s / 60)))}
            otpl = Path(p["overseer_template"]) if p.get("overseer_template") else TEMPLATE_DIR / f"phase_{p['kind']}_overseer.md"
            wtpl = Path(p["worker_template"]) if p.get("worker_template") else TEMPLATE_DIR / f"phase_{p['kind']}_worker.md"
            prompt = fill_template(otpl, pv)
            (out_dir / f"PROMPT.phase{i + 1}.md").write_text(prompt, encoding="utf-8")
            (ws / "PHASE_START").write_text(time.strftime("%Y-%m-%d %H:%M:%S %Z") + f" (phase {i + 1}: {p['name']})\n", encoding="utf-8")
            t0 = time.monotonic()
            deadline = t0 + total_s
            if broker is None:
                broker = TeamBroker(ws, run, env, deadline, t0, pv)
            broker.deadline, broker.t0, broker.values, broker.tpl = deadline, t0, pv, wtpl
            first_worker = len(broker.workers)
            cmd = build_agent_command("custom", prompt=prompt, model=ov["model"], effort=ov.get("effort", "high"),
                                      timeout_s=total_s, custom_template=ov["cmd"], workspace=ws)
            olog = (out_dir / "logs" / f"overseer.phase{i + 1}.log").open("w", encoding="utf-8")
            oproc = subprocess.Popen(cmd, cwd=str(ws), env=oenv, stdin=subprocess.DEVNULL, stdout=olog,
                                     stderr=subprocess.STDOUT, start_new_session=True)
            oend = None
            while True:
                broker.poll()
                now = time.monotonic()
                if oproc.poll() is not None and oend is None:
                    oend = now
                if now >= deadline or (oend is not None and broker.running() == 0):
                    break
                time.sleep(0.5)
            timed_out = time.monotonic() >= deadline
            _killpg(oproc)
            oend = oend or time.monotonic()
            broker.stop_all()
            olog.close()
            phase_end = time.monotonic()
            team_rows = []
            for wid in list(broker.workers)[first_worker:]:
                w = broker.workers[wid]
                shutil.copy2(ws / ".overseer" / "workers" / wid / "log", out_dir / "workers" / f"{wid}.log")
                shutil.copy2(ws / ".overseer" / "workers" / wid / "PROMPT.md", out_dir / "workers" / f"{wid}.PROMPT.md")
                team_rows.append({"id": wid, "brief": w["brief"], "started_at_s": round(w["start"] - t0, 1),
                                  "elapsed_s": round(w["end"] - w["start"], 1), "exit_code": w["proc"].returncode,
                                  "stopped_by_overseer": bool(w.get("stopped"))})
            snap = out_dir / "snapshots" / f"phase{i + 1}"
            _snapshot(ws, games, snap)
            if p["kind"] == "match":
                last_match_snap = snap
            elif last_match_snap is not None:
                _restore(ws, games, last_match_snap)
            else:  # an engine phase before any matching pass: function files go back to the seeds
                for f in funcs:
                    shutil.copy2(set_root / f["source"], ws / "games" / f["game"] / "funcs" / f"{f['func']}.c")
            phase_rows.append({"index": i + 1, "name": p["name"], "kind": p["kind"], "seconds": total_s,
                               "overseer_session_s": round(oend - t0, 1), "phase_s": round(phase_end - t0, 1),
                               "timed_out": timed_out, "workers": team_rows, "spawned": len(team_rows),
                               "peak_running": _peak(team_rows),
                               "worker_minutes": round(sum(t["elapsed_s"] for t in team_rows) / 60, 1),
                               "stopped_by_overseer": sum(t["stopped_by_overseer"] for t in team_rows)})
        if (ws / "workers").is_dir():
            shutil.copytree(ws / "workers", out_dir / "workers" / "briefs", dirs_exist_ok=True)
        shutil.copy2(ws / "OVERSEER-NOTES.md", out_dir / "OVERSEER-NOTES.md")
        engine = {"initialised": (lab / "lab_state.json").is_file()}
        for name in ("findings.md", "lab_state.json"):
            if (lab / name).is_file():
                shutil.copy2(lab / name, out_dir / f"engine_{name}")
        act = lab / "active_engine.json"
        engine["promoted"] = bool(act.is_file() and json.loads(act.read_text() or "{}").get("enabled"))
        manifests = sorted(lab.rglob("PROMOTION_MANIFEST.json")) if lab.is_dir() else []
        engine["promotions"] = len(manifests)
        if (lab / "combined" / ".git").is_dir():
            log = subprocess.run(["git", "-C", str(lab / "combined"), "log", "--oneline", "--all"], capture_output=True, text=True)
            (out_dir / "engine_commits.txt").write_text(log.stdout, encoding="utf-8")
            engine["commits"] = len([ln for ln in log.stdout.splitlines() if ln.strip()])
        if (lab / "live").is_dir():
            shutil.copytree(lab / "live", out_dir / "engine_live", dirs_exist_ok=True, ignore=shutil.ignore_patterns("__pycache__"))

    headless: dict[str, Any] = {}
    hp = run.get("set", {}).get("headless")
    if hp and (base / hp).is_file():
        headless = json.loads((base / hp).read_text(encoding="utf-8"))
    scores: list[dict[str, Any]] = []
    for row in phase_rows:
        if row["kind"] != "match":
            continue
        last = row is [r for r in phase_rows if r["kind"] == "match"][-1]
        res = _score_state(out_dir / "snapshots" / f"phase{row['index']}", funcs, set_root, ctxs, headless,
                           out_dir / "best" if last else None, concurrency)
        with (out_dir / f"results.phase{row['index']}.jsonl").open("w", encoding="utf-8") as fh:
            for r in res:
                fh.write(json.dumps(r) + "\n")
        summ = summarize_agent_benchmark(res, runner="custom", model=ov["model"], effort=ov.get("effort", "high"),
                                         per_func_timeout_s=row["seconds"])
        summ.pop("results", None)
        summ["by_game"] = {g: _agg_arm([r for r in res if r["game"] == g], "agent") for g in games}
        scores.append({"after_phase": row["index"], "name": row["name"], "summary": summ})
    final = scores[-1]["summary"] if scores else {}
    summary = {
        "protocol": "kintoun-overseer-course-v1", "mode": "overseer_course", "functions": len(funcs), "games": len(games),
        "overseer": {"label": values["overseer_label"], "model": ov["model"], "effort": ov.get("effort", "high")},
        "workers": {"label": values["worker_label"], "model": wk["model"], "effort": wk.get("effort", "high"), "max": mx},
        "phases": phase_rows, "scores": scores, "engine": engine, "final": final,
        "wall_elapsed_s": round(time.monotonic() - t_wall0, 1),
    }
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    (out_dir / "REPORT.md").write_text(render_course_markdown(summary), encoding="utf-8")
    return summary


def render_course_markdown(s: dict[str, Any], title: str = "Kintoun Overseer Course") -> str:
    def row(label: str, a: dict[str, Any], bold: bool = False) -> str:
        c = [label, a.get("functions", 0), a.get("compiles", 0), a.get("verified", 0), f"{a.get('verified_pct', 0.0)}%",
             f"{a.get('mean_aligned_pct', 0.0)}%", f"{a.get('median_aligned_pct', 0.0)}%", a.get("ge_80", 0), a.get("ge_95", 0)]
        return "| " + " | ".join(f"**{x}**" if bold else str(x) for x in c) + " |"
    o, w = s["overseer"], s["workers"]
    plan = ", then ".join(f"{p['name']} ({int(round(p['seconds'] / 60))} min)" for p in s["phases"])
    lines = [f"# {title}", "", f"Overseer {o['label']} leading {w['label']} workers over {s['functions']} functions from {s['games']} games: {plan}. No intervention between phases.", "",
             "## Score", "", "| Stage | Functions | Compiles | Exact | Exact % | Mean aligned | Median aligned | >= 80% | >= 95% |",
             "|---|---|---|---|---|---|---|---|---|"]
    if s["scores"]:
        ov0 = s["scores"][0]["summary"]["overall"]
        lines += [row("Raw `m2c` seed", ov0["seed"]), row("Kintoun alone (headless `permute`, 30 s per function)", ov0.get("headless") or {})]
        for sc in s["scores"]:
            lines.append(row(f"Team after phase {sc['after_phase']} ({sc['name']})", sc["summary"]["overall"]["agent"], sc is s["scores"][-1]))
    lines += ["", "## Phases", "", "| Phase | Kind | Workers started | Most at once | Worker minutes | Stopped by overseer | Overseer session | Ended |", "|---|---|---|---|---|---|---|---|"]
    for p in s["phases"]:
        lines.append(f"| {p['index']}. {p['name']} | {p['kind']} | {p['spawned']} | {p['peak_running']} | {p['worker_minutes']} | {p['stopped_by_overseer']} | {p['overseer_session_s']} s | {'clock' if p['timed_out'] else 'early'} |")
    e = s["engine"]
    lines += ["", "## Engine", "", f"Lab initialised: {'yes' if e.get('initialised') else 'no'}; engine commits: {e.get('commits', 0)}; promotions: {e.get('promotions', 0)}; promoted engine active at the end: {'yes' if e.get('promoted') else 'no'}."]
    if s["scores"]:
        fin = s["scores"][-1]["summary"]
        first = s["scores"][0]["summary"]
        for name, key, order in (("size tier", "by_size_tier", [t[0] for t in SIZE_TIERS]), ("structural family", "by_family", list(FAMILIES))):
            lines += ["", f"## By {name}", "", "| Group | Functions | Kintoun alone exact | Kintoun alone mean | First pass exact | First pass mean | Final exact | Final mean |", "|---|---|---|---|---|---|---|---|"]
            for k in order:
                d = (fin.get(key) or {}).get(k)
                if not d:
                    continue
                h, a, a1 = d.get("headless") or {}, d["agent"], first[key][k]["agent"]
                lines.append(f"| `{k}` | {a['functions']} | {h.get('verified', 0)} | {h.get('mean_aligned_pct', 0.0)}% | {a1['verified']} | {a1['mean_aligned_pct']}% | {a['verified']} | {a['mean_aligned_pct']}% |")
    return "\n".join(lines) + "\n"


def cmd_overseer_course(args: argparse.Namespace) -> int:
    s = run_overseer_course(Path(args.run), Path(args.out_dir), concurrency=args.concurrency, kintoun_cmd=args.kintoun_cmd)
    print(render_course_markdown(s))
    return 0


def add_parser(sub: Any) -> None:
    p = sub.add_parser("overseer-course", help="Overseer team runs a course of matching and engine building phases unattended (run file).")
    p.add_argument("run", help="Run file with [[phases]] (see templates/overseer/course.example.toml).")
    p.add_argument("--out-dir", required=True, help="Output directory (prompts, logs, workers, snapshots, results per pass, summary.json, REPORT.md).")
    p.add_argument("--concurrency", type=int, default=4, help="Parallel re-verification after the course (default 4).")
    p.add_argument("--kintoun-cmd", default="kintoun", help="Kintoun command named in the briefs.")
    p.set_defaults(func_cb=cmd_overseer_course)
