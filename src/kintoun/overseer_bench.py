"""Overseer benchmark (`kintoun overseer-bench run.toml`): one overseer agent leads worker agents on one clock.

The overseer gets a multi-game function set in one workspace and a small set of team commands (`spawn-worker`,
`worker-status`, `worker-log`, `stop-worker`). It decides how many workers to start, what each one does and how
to move work around. Workers are started outside the overseer's own process by a broker in this harness (each
through its own command template, so overseer and workers can run under different agent CLIs or sandboxes), and
the harness stops everyone when the shared clock runs out. Every function is then re-verified outside the
workspace exactly as in the per-function and whole-set protocols.

Every run is described by a run file (see `templates/overseer/run.example.toml`); the overseer and worker briefs
are filled in from templates (`templates/overseer/overseer.md`, `worker.md`) so every overseer test uses the same
generic briefs with its own parameters.
"""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import shlex
import shutil
import signal
import string
import subprocess
import sys
import tempfile
import time
import tomllib
from typing import Any

from kintoun.agent_bench import (
    FAMILIES,
    SIZE_TIERS,
    _agg_arm,
    _recover_best_cached_source,
    build_agent_command,
    summarize_agent_benchmark,
)
from kintoun.compiler import make_compiler
from kintoun.config import load_config, parse_duration_s
from kintoun.search.runner import rank_result, run_search
from kintoun.targets import load_target_from_config
from kintoun.verify import verify_source

TEMPLATE_DIR = Path(__file__).resolve().parent / "templates" / "overseer"

_TEAM_SCRIPT = r'''#!/usr/bin/env python3
"""Team commands for the overseer: spawn-worker, worker-status, worker-log, stop-worker."""
import json, os, sys, time
from pathlib import Path
WS = Path(__WS__)
OV = WS / ".overseer"
cmd = Path(sys.argv[0]).name
args = sys.argv[1:]

def workers():
    out = []
    for d in sorted((OV / "workers").glob("*"), key=lambda p: (len(p.name), p.name)):
        try:
            out.append(json.loads((d / "status.json").read_text()))
        except Exception:
            pass
    return out

if cmd == "spawn-worker":
    if len(args) != 1:
        sys.exit("usage: spawn-worker <brief file>")
    brief = Path(args[0]).resolve()
    if not brief.is_file():
        sys.exit(f"no such brief file: {args[0]}")
    n = f"{time.time_ns()}"
    req = OV / "requests" / f"{n}.json"
    tmp = req.with_suffix(".tmp")
    tmp.write_text(json.dumps({"brief": str(brief)}))
    tmp.rename(req)
    rep = OV / "replies" / f"{n}.json"
    for _ in range(1200):
        if rep.is_file():
            r = json.loads(rep.read_text())
            print(r["message"])
            sys.exit(0 if r.get("ok") else 1)
        time.sleep(0.05)
    sys.exit("spawn-worker: no reply from the team broker")
elif cmd == "worker-status":
    ws = workers()
    if not ws:
        print("no workers yet")
    for w in ws:
        print(f"{w['id']}: {w['state']}, {w['elapsed_s']:.0f}s, brief {w['brief']}" + (f", exit {w['exit_code']}" if w.get("exit_code") is not None else ""))
        log = OV / "workers" / w["id"] / "log"
        if log.is_file():
            for line in log.read_text(errors="replace").splitlines()[-5:]:
                print("    " + line[:200])
elif cmd == "worker-log":
    if len(args) != 1:
        sys.exit("usage: worker-log <id>")
    log = OV / "workers" / args[0] / "log"
    print(log.read_text(errors="replace") if log.is_file() else f"no worker {args[0]}")
elif cmd == "stop-worker":
    if len(args) != 1:
        sys.exit("usage: stop-worker <id>")
    d = OV / "workers" / args[0]
    if not d.is_dir():
        sys.exit(f"no worker {args[0]}")
    (d / "stop").write_text("stop")
    print(f"stopping {args[0]}")
'''


def fill_template(path: Path, values: dict[str, Any]) -> str:
    """Fill a `$name` template; unknown `$` text is left as it is."""
    return string.Template(path.read_text(encoding="utf-8")).safe_substitute({k: str(v) for k, v in values.items()})


def _meminfo_gb(key: str) -> float:
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            if line.startswith(key + ":"):
                return int(line.split()[1]) / (1024 * 1024)
    except OSError:
        pass
    return 0.0


def machine_note() -> str:
    return f"{os.cpu_count() or 1} CPU threads and {_meminfo_gb('MemTotal'):.0f} GB of memory"


def _killpg(proc: subprocess.Popen) -> None:
    for sig, wait in ((signal.SIGTERM, 3.0), (signal.SIGKILL, 2.0)):
        if proc.poll() is not None:
            return
        try:
            os.killpg(proc.pid, sig)
        except ProcessLookupError:
            return
        try:
            proc.wait(timeout=wait)
        except subprocess.TimeoutExpired:
            pass


class TeamBroker:
    """Starts, watches and stops workers on the overseer's requests, inside the shared clock."""

    def __init__(self, ws: Path, run: dict[str, Any], env: dict[str, str], deadline: float, t0: float, values: dict[str, Any]):
        self.ws, self.run, self.env, self.deadline, self.t0, self.values = ws, run, env, deadline, t0, values
        self.ov = ws / ".overseer"
        for sub in ("requests", "replies", "workers"):
            (self.ov / sub).mkdir(parents=True, exist_ok=True)
        self.workers: dict[str, dict[str, Any]] = {}
        w = run.get("workers", {})
        self.max = int(w.get("max", 0) or 0)
        self.min_free = float(w.get("min_free_mem_gb", 0) or 0)
        tpl = w.get("brief_template") or ""
        self.tpl = Path(tpl) if tpl else TEMPLATE_DIR / "worker.md"

    def running(self) -> int:
        return sum(1 for w in self.workers.values() if w["proc"].poll() is None)

    def _reply(self, n: str, ok: bool, message: str) -> None:
        p = self.ov / "replies" / f"{n}.json"
        p.with_suffix(".tmp").write_text(json.dumps({"ok": ok, "message": message}))
        p.with_suffix(".tmp").rename(p)

    def _spawn(self, n: str, brief_path: Path) -> None:
        try:
            brief_path.resolve().relative_to(self.ws.resolve())
        except ValueError:
            return self._reply(n, False, "refused: the brief file must be inside the workspace")
        remaining = self.deadline - time.monotonic()
        if remaining < 30:
            return self._reply(n, False, "refused: less than 30 s left on the clock")
        if self.max and self.running() >= self.max:
            return self._reply(n, False, f"refused: {self.max} workers already running (the run's limit)")
        if self.min_free and _meminfo_gb("MemAvailable") < self.min_free:
            return self._reply(n, False, f"refused: the machine has less than {self.min_free} GB of free memory; wait for a worker to finish or stop one")
        wid = f"w{len(self.workers) + 1}"
        wdir = self.ov / "workers" / wid
        wdir.mkdir(parents=True, exist_ok=True)
        assignment = brief_path.read_text(encoding="utf-8", errors="replace").strip()
        prompt = fill_template(self.tpl, {**self.values, "worker_id": wid, "assignment": assignment,
                                          "remaining_s": int(remaining), "remaining_min": max(1, int(remaining // 60))})
        (wdir / "PROMPT.md").write_text(prompt, encoding="utf-8")
        w = self.run["workers"]
        cmd = build_agent_command("custom", prompt=prompt, model=w["model"], effort=w.get("effort", "high"),
                                  timeout_s=remaining, custom_template=w["cmd"], workspace=self.ws)
        log = (wdir / "log").open("w", encoding="utf-8")
        wenv = dict(self.env)
        wenv["PATH"] = f"{self.ws / '.kintoun_bin'}{os.pathsep}{self.env.get('ORIG_PATH', '')}"
        proc = subprocess.Popen(cmd, cwd=str(self.ws), env=wenv, stdin=subprocess.DEVNULL, stdout=log,
                                stderr=subprocess.STDOUT, start_new_session=True)
        rel = str(brief_path.resolve().relative_to(self.ws.resolve()))
        self.workers[wid] = {"proc": proc, "log": log, "start": time.monotonic(), "brief": rel, "assignment": assignment}
        self._status(wid)
        self._reply(n, True, f"started {wid} ({int(remaining)} s left on the clock)")

    def _status(self, wid: str) -> None:
        w = self.workers[wid]
        rc = w["proc"].poll()
        end = w.get("end") or time.monotonic()
        st = {"id": wid, "state": "running" if rc is None else ("stopped" if w.get("stopped") else "finished"),
              "elapsed_s": round(end - w["start"], 1), "started_at_s": round(w["start"] - self.t0, 1),
              "exit_code": rc, "brief": w["brief"]}
        p = self.ov / "workers" / wid / "status.json"
        p.with_suffix(".tmp").write_text(json.dumps(st))
        p.with_suffix(".tmp").rename(p)

    def poll(self) -> None:
        for req in sorted((self.ov / "requests").glob("*.json")):
            n = req.stem
            try:
                brief = Path(json.loads(req.read_text())["brief"])
                req.unlink()
                self._spawn(n, brief)
            except Exception as exc:  # a bad request must never stop the run
                req.unlink(missing_ok=True)
                self._reply(n, False, f"refused: {exc}")
        for wid, w in self.workers.items():
            if w["proc"].poll() is None and (self.ov / "workers" / wid / "stop").is_file():
                w["stopped"] = True
                _killpg(w["proc"])
            if w["proc"].poll() is not None and "end" not in w:
                w["end"] = time.monotonic()
            self._status(wid)

    def stop_all(self) -> None:
        for wid, w in self.workers.items():
            if w["proc"].poll() is None:
                _killpg(w["proc"])
            w.setdefault("end", time.monotonic())
            w["log"].close()
            self._status(wid)


def run_overseer_benchmark(run_path: Path, out_dir: Path, *, concurrency: int = 4, kintoun_cmd: str = "kintoun") -> dict[str, Any]:
    run = tomllib.loads(Path(run_path).read_text(encoding="utf-8"))
    base = Path(run_path).resolve().parent
    man_path = (base / run["set"]["manifest"]).resolve()
    set_root = man_path.parent
    manifest = json.loads(man_path.read_text(encoding="utf-8"))
    funcs: list[dict[str, Any]] = manifest["functions"]
    games = sorted({f["game"] for f in funcs})
    total_s = parse_duration_s(str(run.get("clock", {}).get("total", "30m")), 1800.0)
    out_dir = Path(out_dir)
    for sub in ("best", "logs", "workers"):
        (out_dir / sub).mkdir(parents=True, exist_ok=True)

    ctxs: dict[str, Any] = {}
    for g in games:
        cfg = load_config(set_root / "games" / g / "kintoun.toml")
        ctxs[g] = (cfg, load_target_from_config(cfg))

    src_pkg_dir = Path(__file__).resolve().parent.parent
    repo_skills = src_pkg_dir.parent / "skills" / "kintoun-match"
    ov = run["overseer"]
    wk = run["workers"]
    t_wall0 = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="kintoun_ovset_") as tmp_ws:
        ws = Path(tmp_ws)
        rows_md = ["| Game | Function | Address | Size | File |", "|---|---|---|---|---|"]
        game_desc = []
        for g in games:
            gsrc, gdst = set_root / "games" / g, ws / "games" / g
            (gdst / "funcs").mkdir(parents=True)
            shutil.copytree(gsrc / "orig", gdst / "orig")
            shutil.copy2(gsrc / "kintoun.toml", gdst / "kintoun.toml")
            cfg = ctxs[g][0]
            game_desc.append(f"`{g}` ({ctxs[g][1].arch}, {cfg.compiler.preset})")
        for f in funcs:
            shutil.copy2(set_root / f["source"], ws / "games" / f["game"] / "funcs" / f"{f['func']}.c")
            rows_md.append(f"| `{f['game']}` | `{f['func']}` | `{f['addr']}` | {f['size_bytes']} | `games/{f['game']}/funcs/{f['func']}.c` |")
        (ws / "FUNCTIONS.md").write_text("\n".join(rows_md) + "\n", encoding="utf-8")
        (ws / "workers").mkdir()
        if repo_skills.is_dir():
            shutil.copytree(repo_skills, ws / "skills" / "kintoun-match")
        (ws / "START_TIME").write_text(time.strftime("%Y-%m-%d %H:%M:%S %Z") + "\n", encoding="utf-8")

        env = dict(os.environ)
        pp = env.get("PYTHONPATH", "")
        env["PYTHONPATH"] = f"{src_pkg_dir}{os.pathsep}{pp}" if pp else str(src_pkg_dir)
        env["ORIG_PATH"] = env.get("PATH", "")
        shim = ws / ".kintoun_bin"
        shim.mkdir()
        (shim / "kintoun").write_text(
            f"#!/bin/sh\nPYTHONPATH={shlex.quote(env['PYTHONPATH'])} exec {shlex.quote(sys.executable)} -m kintoun.cli \"$@\"\n",
            encoding="utf-8")
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
        values = {
            "worker_label": wk.get("label", wk["model"]),
            "overseer_label": ov.get("label", ov["model"]),
            "max_workers_note": f" (at most {mx} at a time)" if mx else "",
            "n_functions": len(funcs),
            "n_games": len(games),
            "game_list": ", ".join(game_desc),
            "clock_s": int(total_s),
            "clock_min": max(1, int(round(total_s / 60))),
            "machine": run.get("machine", {}).get("note") or machine_note(),
            "kintoun_cmd": kintoun_cmd,
        }
        otpl = Path(ov["brief_template"]) if ov.get("brief_template") else TEMPLATE_DIR / "overseer.md"
        prompt = fill_template(otpl, values)
        (out_dir / "PROMPT.md").write_text(prompt, encoding="utf-8")
        (out_dir / "RUN.toml").write_text(Path(run_path).read_text(encoding="utf-8"), encoding="utf-8")
        cmd = build_agent_command("custom", prompt=prompt, model=ov["model"], effort=ov.get("effort", "high"),
                                  timeout_s=total_s, custom_template=ov["cmd"], workspace=ws)

        t0 = time.monotonic()
        deadline = t0 + total_s
        broker = TeamBroker(ws, run, env, deadline, t0, values)
        olog = (out_dir / "logs" / "overseer.log").open("w", encoding="utf-8")
        oproc = subprocess.Popen(cmd, cwd=str(ws), env=oenv, stdin=subprocess.DEVNULL, stdout=olog,
                                 stderr=subprocess.STDOUT, start_new_session=True)
        overseer_end = None
        while True:
            broker.poll()
            now = time.monotonic()
            if oproc.poll() is not None and overseer_end is None:
                overseer_end = now
            if now >= deadline or (overseer_end is not None and broker.running() == 0):
                break
            time.sleep(0.5)
        timed_out = time.monotonic() >= deadline
        _killpg(oproc)
        overseer_end = overseer_end or time.monotonic()
        broker.stop_all()
        olog.close()
        session_s = round(time.monotonic() - t0, 1)

        team_rows = []
        for wid, w in broker.workers.items():
            shutil.copy2(ws / ".overseer" / "workers" / wid / "log", out_dir / "workers" / f"{wid}.log")
            shutil.copy2(ws / ".overseer" / "workers" / wid / "PROMPT.md", out_dir / "workers" / f"{wid}.PROMPT.md")
            team_rows.append({"id": wid, "brief": w["brief"], "started_at_s": round(w["start"] - t0, 1),
                              "elapsed_s": round(w["end"] - w["start"], 1), "exit_code": w["proc"].returncode,
                              "stopped_by_overseer": bool(w.get("stopped"))})
        if (ws / "workers").is_dir():
            shutil.copytree(ws / "workers", out_dir / "workers" / "briefs", dirs_exist_ok=True)

        items = []
        for f in funcs:
            gws = ws / "games" / f["game"]
            fp = gws / "funcs" / f"{f['func']}.c"
            seed = (set_root / f["source"]).read_text(encoding="utf-8")
            cands = [fp.read_text(encoding="utf-8", errors="replace")] if fp.is_file() else []
            cands += _recover_best_cached_source(gws, f["func"])
            cands.append(seed)
            items.append({"f": f, "seed": seed, "cands": cands})

    headless: dict[str, Any] = {}
    hp = run.get("set", {}).get("headless")
    hpath = (base / hp).resolve() if hp else None
    if hpath and hpath.is_file():
        headless = json.loads(hpath.read_text(encoding="utf-8"))

    def _score(it: dict[str, Any]) -> dict[str, Any]:
        f = it["f"]
        cfg, ctx = ctxs[f["game"]]
        tf = ctx.resolve_function(f["func"])
        comp = make_compiler(cfg, va=tf.va)
        key = f"{f['game']}/{f['func']}"
        cached = headless.get(key)
        if cached:
            seed_info, hl = cached["seed"], cached["headless"]
        else:
            sres = verify_source(it["seed"], tf, ctx, comp, lines=0, forbid_asm=True)
            sc = sres.get("status") in ("verified", "mismatch", "unresolved")
            seed_info = {"compiled": sc, "verified": bool(sres.get("verified")),
                         "aligned_pct": round(float((sres.get("search") or {}).get("aligned_pct") or 0.0), 2) if sc else 0.0}
            with tempfile.TemporaryDirectory(prefix="kintoun_hl_") as t:
                r = run_search(source=it["seed"], target_fn=tf, ctx=ctx, compiler=comp, budget_s=30.0, max_candidates=300,
                               workers=1, cache_dir=Path(t) / "cache", forbid_asm=True, seed=0, governed=True)
            b = r.get("best") or {}
            hc = b.get("status") in ("verified", "mismatch", "unresolved")
            hl = {"compiled": hc, "verified": bool(r.get("verified")), "status": b.get("status", "error"),
                  "aligned_pct": round(float((b.get("search") or {}).get("aligned_pct") or 0.0), 2) if hc else 0.0}
        best, best_src = None, it["seed"]
        for src in it["cands"]:
            v = verify_source(src, tf, ctx, comp, lines=24, forbid_asm=True)
            if best is None or rank_result(v) < rank_result(best):
                best, best_src = v, src
                if v.get("verified"):
                    break
        (out_dir / "best" / f"{f['game']}_{f['func']}.c").write_text(best_src, encoding="utf-8")
        ac = best.get("status") in ("verified", "mismatch", "unresolved")
        return {
            "game": f["game"], "func": f["func"], "addr": f["addr"], "size_bytes": f["size_bytes"],
            "size_tier": f.get("size_tier", "other"), "family": f.get("family", "other"), "mode": "overseer",
            "model": ov["model"], "worker_model": wk["model"], "time_limit_s": total_s,
            "seed": seed_info, "headless": hl,
            "agent": {"compiled": ac, "verified": bool(best.get("verified")), "status": best.get("status", "error"),
                      "aligned_pct": round(float((best.get("search") or {}).get("aligned_pct") or 0.0), 2) if ac else 0.0,
                      "different_bytes": best.get("different_bytes"), "timed_out": timed_out},
        }

    with ThreadPoolExecutor(max_workers=max(1, concurrency)) as pool:
        results = list(pool.map(_score, items))
    with (out_dir / "results.jsonl").open("w", encoding="utf-8") as fh:
        for r in results:
            fh.write(json.dumps(r) + "\n")

    summary = summarize_agent_benchmark(results, runner="custom", model=ov["model"], effort=ov.get("effort", "high"),
                                        per_func_timeout_s=total_s, wall_elapsed_s=round(time.monotonic() - t_wall0, 3))
    summary.update({
        "mode": "overseer",
        "overseer": {"label": values["overseer_label"], "model": ov["model"], "effort": ov.get("effort", "high"),
                     "session_s": round(overseer_end - t0, 1)},
        "workers": {"label": values["worker_label"], "model": wk["model"], "effort": wk.get("effort", "high"),
                    "spawned": len(team_rows), "max": mx, "team": team_rows,
                    "peak_running": _peak(team_rows)},
        "total_time_limit_s": total_s, "session_s": session_s, "timed_out": timed_out,
        "by_game": {g: {"headless": _agg_arm([r for r in results if r["game"] == g], "headless"),
                        "agent": _agg_arm([r for r in results if r["game"] == g], "agent")} for g in games},
    })
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    (out_dir / "REPORT.md").write_text(render_overseer_markdown(summary), encoding="utf-8")
    return summary


def _peak(team: list[dict[str, Any]]) -> int:
    ev = sorted([(t["started_at_s"], 1) for t in team] + [(t["started_at_s"] + t["elapsed_s"], -1) for t in team])
    cur = peak = 0
    for _t, d in ev:
        cur += d
        peak = max(peak, cur)
    return peak


def render_overseer_markdown(s: dict[str, Any], title: str = "Kintoun Overseer Benchmark") -> str:
    def row(label: str, a: dict[str, Any], bold: bool = False) -> str:
        cells = [label, a.get("functions", 0), a.get("compiles", 0), a.get("verified", 0), f"{a.get('verified_pct', 0.0)}%",
                 f"{a.get('mean_aligned_pct', 0.0)}%", f"{a.get('median_aligned_pct', 0.0)}%", a.get("ge_80", 0), a.get("ge_95", 0)]
        return "| " + " | ".join(f"**{c}**" if bold else str(c) for c in cells) + " |"

    o, w = s["overseer"], s["workers"]
    mins = int(round(s["total_time_limit_s"] / 60))
    head = "| Stage | Functions | Compiles | Exact | Exact % | Mean aligned | Median aligned | >= 80% | >= 95% |\n|---|---|---|---|---|---|---|---|---|"
    ov = s.get("overall") or {}
    lines = [
        f"# {title}", "",
        f"Overseer {o['label']} leading {w['label']} workers, {mins} minutes on one clock for the whole team, "
        f"{ov.get('agent', {}).get('functions', 0)} functions from {len(s['by_game'])} games.", "",
        f"Team: {w['spawned']} workers started, at most {w['peak_running']} at once; overseer session {o['session_s']} s; "
        f"run ended {'when the clock ran out' if s['timed_out'] else 'before the clock ran out'} ({s['session_s']} s).", "",
        "## Overall", "", head,
        row("Raw `m2c` seed", ov.get("seed", {})),
        row("Kintoun alone (headless `permute`, 30 s per function)", ov.get("headless", {})),
        row(f"{o['label']} overseer + {w['label']} workers + Kintoun", ov.get("agent", {}), True), "",
        "## By game", "", "| Game | Functions | Kintoun alone exact | Kintoun alone mean | Team exact | Team mean | Team median |",
        "|---|---|---|---|---|---|---|",
    ]
    for g, d in s["by_game"].items():
        h, a = d["headless"], d["agent"]
        lines.append(f"| `{g}` | {a['functions']} | {h['verified']} | {h['mean_aligned_pct']}% | {a['verified']} | {a['mean_aligned_pct']}% | {a['median_aligned_pct']}% |")
    for name, key, order in (("size tier", "by_size_tier", [t[0] for t in SIZE_TIERS]), ("structural family", "by_family", list(FAMILIES))):
        lines += ["", f"## By {name}", "", "| Group | Functions | Kintoun alone exact | Kintoun alone mean | Team exact | Team mean | Team median |", "|---|---|---|---|---|---|---|"]
        for k in order + ["other"]:
            d = (s.get(key) or {}).get(k)
            if not d:
                continue
            h, a = d.get("headless") or {}, d["agent"]
            lines.append(f"| `{k}` | {a['functions']} | {h.get('verified', 0)} | {h.get('mean_aligned_pct', 0.0)}% | {a['verified']} | {a['mean_aligned_pct']}% | {a['median_aligned_pct']}% |")
    lines += ["", "## Team", "", "| Worker | Brief | Started at | Ran for | Stopped by overseer |", "|---|---|---|---|---|"]
    for t in w["team"]:
        lines.append(f"| {t['id']} | `{t['brief']}` | {t['started_at_s']} s | {t['elapsed_s']} s | {'yes' if t['stopped_by_overseer'] else 'no'} |")
    return "\n".join(lines) + "\n"


def cmd_overseer_bench(args: argparse.Namespace) -> int:
    s = run_overseer_benchmark(Path(args.run), Path(args.out_dir), concurrency=args.concurrency, kintoun_cmd=args.kintoun_cmd)
    print(render_overseer_markdown(s))
    return 0


def add_parser(sub: Any) -> None:
    p = sub.add_parser("overseer-bench", help="Overseer agent leads worker agents over a multi-game set on one clock (run file).")
    p.add_argument("run", help="Run file (see templates/overseer/run.example.toml).")
    p.add_argument("--out-dir", required=True, help="Output directory (PROMPT.md, logs/, workers/, best/, results.jsonl, summary.json, REPORT.md).")
    p.add_argument("--concurrency", type=int, default=4, help="Parallel re-verification after the session (default 4).")
    p.add_argument("--kintoun-cmd", default="kintoun", help="Kintoun command named in the briefs.")
    p.set_defaults(func_cb=cmd_overseer_bench)
