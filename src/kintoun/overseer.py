"""Lean, stdlib-only Kintoun Fleet Supervisor (`overseer`) with Code-Only, Single-Brain, & Dual-Brain modes.

Designed to work right out of the box with zero third-party SDK dependencies:
  - `mode = "none"` (default when no API key is configured, `$0.00` cost):
    Runs all deterministic reflexes: chess-clock reaping, timeout quarantine, machine pressure
    auto-tuning, zero-LLM near-miss closing on `>=85%` functions, optional `tmux` worker health
    checks/nudges, and durable SQLite action journaling.
  - `mode = "single"` (one API key, one provider):
    Uses a single LLM endpoint (`openai`, `openai-compatible` e.g. Ollama/vLLM/OpenRouter,
    `anthropic`, or `gemini`) for state-fingerprint-gated triage, standing-rule `action_check`,
    and fleet steering under one daily `budget_usd` cap.
  - `mode = "dual"` (two models or two providers):
    Routes cheap triage & rule checks to `fast_brain` and high-level fleet steering to `main_brain`
    under the same shared daily `budget_usd` cap, with automatic fallback if either endpoint errors.

The LLM never receives raw shell or arbitrary file-write tools—only a small allowlist of typed
queue/fleet control tools checked against standing rules.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, field
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import time
from typing import Any
import urllib.error
import urllib.request

from kintoun.closer import close_near_miss
from kintoun.compiler import make_compiler
from kintoun.config import KintounConfig
from kintoun.governor import AutoTuner
from kintoun.queue import WorkQueue
from kintoun.targets import load_target_from_config

DEFAULT_STANDING_RULES = (
    "1. Real C only: never introduce inline assembly or raw byte directives.\n"
    "2. Never pause all agents simultaneously when pending work remains and machine memory is healthy.\n"
    "3. Only unquarantine functions when pending work is low (< 5) or explicitly requested.\n"
    "4. Respect daily_budget_usd and machine memory headroom."
)


@dataclass
class BrainEndpoint:
    provider: str = "openai"  # openai | openai-compatible | anthropic | gemini
    model: str = "gpt-4o-mini"
    api_key_env: str = "OPENAI_API_KEY"
    base_url: str = ""
    price_in_per_m: float = 0.15
    price_out_per_m: float = 0.60

    def api_key(self) -> str:
        if self.provider == "openai-compatible" and not self.api_key_env:
            return "local"
        return os.environ.get(self.api_key_env, "").strip()


@dataclass
class OverseerSettings:
    brain_mode: str = "none"  # none | single | dual
    daily_budget_usd: float = 2.0
    cycle_s: float = 60.0
    auto_close_near_misses: bool = True
    standing_rules: str = DEFAULT_STANDING_RULES
    tmux_sessions: list[str] = field(default_factory=list)
    main_brain: BrainEndpoint = field(default_factory=BrainEndpoint)
    fast_brain: BrainEndpoint | None = None


def settings_from_toml(cfg: KintounConfig) -> OverseerSettings:
    """Load optional `[overseer]` and `[overseer.main_brain]` / `[overseer.fast_brain]` from `kintoun.toml`."""
    toml_path = cfg.root / "kintoun.toml"
    if not toml_path.is_file():
        return OverseerSettings()
    import tomllib

    raw = tomllib.loads(toml_path.read_text(encoding="utf-8")).get("overseer", {})
    if not isinstance(raw, dict):
        return OverseerSettings()

    def _ep(d: dict[str, Any], default_model: str = "gpt-4o-mini") -> BrainEndpoint:
        prov = str(d.get("provider", "openai")).strip().lower()
        default_env = {
            "openai": "OPENAI_API_KEY",
            "openai-compatible": "OPENAI_API_KEY",
            "anthropic": "ANTHROPIC_API_KEY",
            "gemini": "GEMINI_API_KEY",
        }.get(prov, "OPENAI_API_KEY")
        return BrainEndpoint(
            provider=prov,
            model=str(d.get("model", default_model)),
            api_key_env=str(d.get("api_key_env", default_env)),
            base_url=str(d.get("base_url", "")),
            price_in_per_m=float(d.get("price_in_per_m", 0.15)),
            price_out_per_m=float(d.get("price_out_per_m", 0.60)),
        )

    main_raw = raw.get("main_brain") or raw.get("brain") or {}
    fast_raw = raw.get("fast_brain")
    return OverseerSettings(
        brain_mode=str(raw.get("brain_mode", "none")).strip().lower(),
        daily_budget_usd=float(raw.get("daily_budget_usd", 2.0)),
        cycle_s=float(raw.get("cycle_s", 60.0)),
        auto_close_near_misses=bool(raw.get("auto_close_near_misses", True)),
        standing_rules=str(raw.get("standing_rules", DEFAULT_STANDING_RULES)),
        tmux_sessions=[str(x) for x in raw.get("tmux_sessions", [])],
        main_brain=_ep(main_raw if isinstance(main_raw, dict) else {}),
        fast_brain=_ep(fast_raw) if isinstance(fast_raw, dict) else None,
    )


def call_llm_json(
    ep: BrainEndpoint,
    system_prompt: str,
    user_payload: str,
    *,
    max_tokens: int = 600,
    timeout_s: float = 30.0,
) -> tuple[dict[str, Any] | None, float]:
    """Stdlib HTTPS JSON call supporting OpenAI/compatible, Anthropic, and Gemini APIs."""
    key = ep.api_key()
    if not key and ep.provider != "openai-compatible":
        raise RuntimeError(f"missing API key in env var '{ep.api_key_env}' for provider '{ep.provider}'")

    if ep.provider in ("openai", "openai-compatible"):
        base = (ep.base_url or "https://api.openai.com/v1").rstrip("/")
        url = f"{base}/chat/completions"
        body = json.dumps(
            {
                "model": ep.model,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_payload},
                ],
                "max_tokens": max_tokens,
                "temperature": 0.1,
            }
        ).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if key:
            headers["Authorization"] = f"Bearer {key}"
        req = urllib.request.Request(url, data=body, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        text = (((data.get("choices") or [{}])[0].get("message") or {}).get("content")) or ""
        usage = data.get("usage") or {}
        tok_in = int(usage.get("prompt_tokens", 0))
        tok_out = int(usage.get("completion_tokens", 0))
    elif ep.provider == "anthropic":
        base = (ep.base_url or "https://api.anthropic.com/v1").rstrip("/")
        url = f"{base}/messages"
        body = json.dumps(
            {
                "model": ep.model,
                "max_tokens": max_tokens,
                "system": system_prompt,
                "messages": [{"role": "user", "content": user_payload}],
            }
        ).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "x-api-key": key,
            "anthropic-version": "2023-06-01",
        }
        req = urllib.request.Request(url, data=body, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        text = " ".join(b.get("text", "") for b in (data.get("content") or []) if b.get("type") == "text")
        usage = data.get("usage") or {}
        tok_in = int(usage.get("input_tokens", 0))
        tok_out = int(usage.get("output_tokens", 0))
    elif ep.provider == "gemini":
        base = (ep.base_url or "https://generativelanguage.googleapis.com/v1beta").rstrip("/")
        url = f"{base}/models/{ep.model}:generateContent?key={key}"
        body = json.dumps(
            {
                "systemInstruction": {"parts": [{"text": system_prompt}]},
                "contents": [{"role": "user", "parts": [{"text": user_payload}]}],
                "generationConfig": {"maxOutputTokens": max_tokens, "temperature": 0.1},
            }
        ).encode("utf-8")
        req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        cands = data.get("candidates") or [{}]
        parts = ((cands[0].get("content") or {}).get("parts")) or []
        text = " ".join(p.get("text", "") for p in parts)
        usage = data.get("usageMetadata") or {}
        tok_in = int(usage.get("promptTokenCount", 0))
        tok_out = int(usage.get("candidatesTokenCount", 0))
    else:
        raise ValueError(f"unsupported brain provider: {ep.provider}")

    cost = (tok_in / 1_000_000.0) * ep.price_in_per_m + (tok_out / 1_000_000.0) * ep.price_out_per_m
    start = text.find("{")
    end = text.rfind("}")
    parsed: dict[str, Any] | None = None
    if start >= 0 and end > start:
        try:
            obj = json.loads(text[start : end + 1])
            if isinstance(obj, dict):
                parsed = obj
        except ValueError:
            parsed = None
    return parsed, round(cost, 6)


class BrainRouter:
    """Unified router supporting `none`, `single` (one API), and `dual` (fast + main) brain modes."""

    def __init__(self, settings: OverseerSettings, kintoun_dir: Path, caller=call_llm_json) -> None:
        self.settings = settings
        self.kintoun_dir = Path(kintoun_dir)
        self.db_path = self.kintoun_dir / "overseer.sqlite3"
        self._caller = caller
        self._init_db()

    @contextmanager
    def _connect(self):
        conn = sqlite3.connect(self.db_path, timeout=10.0)
        conn.execute("PRAGMA journal_mode=WAL")
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    def _init_db(self) -> None:
        self.kintoun_dir.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS spend (
                    day TEXT PRIMARY KEY,
                    usd REAL NOT NULL DEFAULT 0,
                    calls INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS journal (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts REAL NOT NULL,
                    kind TEXT NOT NULL,
                    detail TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS router_state (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                """
            )

    def log_event(self, kind: str, detail: Any) -> None:
        txt = detail if isinstance(detail, str) else json.dumps(detail)
        with self._connect() as conn:
            conn.execute("INSERT INTO journal (ts, kind, detail) VALUES (?, ?, ?)", (time.time(), kind, txt[:2000]))

    def today_spend(self) -> float:
        day = dt.date.today().isoformat()
        with self._connect() as conn:
            row = conn.execute("SELECT usd FROM spend WHERE day = ?", (day,)).fetchone()
        return float(row[0]) if row else 0.0

    def _record_spend(self, cost: float) -> None:
        day = dt.date.today().isoformat()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO spend (day, usd, calls) VALUES (?, ?, 1)
                ON CONFLICT(day) DO UPDATE SET usd = usd + excluded.usd, calls = calls + 1
                """,
                (day, max(0.0, cost)),
            )

    def budget_ok(self) -> bool:
        return self.today_spend() < self.settings.daily_budget_usd

    def _endpoint_for(self, role: str) -> tuple[BrainEndpoint, BrainEndpoint | None]:
        """Return `(primary, fallback)` endpoints for `role` (`fast` vs `main`)."""
        if self.settings.brain_mode == "dual" and self.settings.fast_brain is not None:
            if role == "fast":
                return self.settings.fast_brain, self.settings.main_brain
            return self.settings.main_brain, self.settings.fast_brain
        # `single` mode: one provider & API key handles both fast triage/checks and main turns!
        return self.settings.main_brain, None

    def _invoke(self, role: str, system_prompt: str, payload: str, max_tokens: int) -> tuple[dict[str, Any] | None, float]:
        if self.settings.brain_mode == "none" or not self.budget_ok():
            return None, 0.0
        primary, fallback = self._endpoint_for(role)
        try:
            out, cost = self._caller(primary, system_prompt, payload, max_tokens=max_tokens)
            self._record_spend(cost)
            return out, cost
        except Exception as exc:
            self.log_event("llm_error", {"role": role, "provider": primary.provider, "error": str(exc)[:240]})
            if fallback is not None:
                out, cost = self._caller(fallback, system_prompt, payload, max_tokens=max_tokens)
                self._record_spend(cost)
                return out, cost
            return None, 0.0

    @staticmethod
    def _view_of(snapshot: dict[str, Any]) -> dict[str, Any]:
        return {
            "counts": snapshot.get("queue", {}).get("counts"),
            "near_misses": len(snapshot.get("queue", {}).get("near_misses") or []),
            "idle_workers": [w["session"] for w in (snapshot.get("tmux_workers") or []) if w.get("idle")],
            "pressure_level": (snapshot.get("autotune") or {}).get("level"),
        }

    @classmethod
    def fingerprint_of(cls, snapshot: dict[str, Any]) -> str:
        view = cls._view_of(snapshot)
        return hashlib.sha1(json.dumps(view, sort_keys=True).encode("utf-8")).hexdigest()[:16]

    def save_fingerprint(self, snapshot: dict[str, Any]) -> str:
        fp = self.fingerprint_of(snapshot)
        with self._connect() as conn:
            conn.execute("INSERT OR REPLACE INTO router_state (key, value) VALUES ('last_fp', ?)", (fp,))
        return fp

    def should_wake_main(self, snapshot: dict[str, Any]) -> tuple[bool, str]:
        """State-fingerprint gate + fast triage check (works identically in `single` and `dual` modes)."""
        if self.settings.brain_mode == "none":
            return False, "brain_mode=none"
        if not self.budget_ok():
            return False, f"daily budget cap (${self.settings.daily_budget_usd:.2f}) reached"

        view = self._view_of(snapshot)
        fp = self.fingerprint_of(snapshot)
        with self._connect() as conn:
            row = conn.execute("SELECT value FROM router_state WHERE key = 'last_fp'").fetchone()
            last_fp = row[0] if row else ""
            if fp == last_fp:
                return False, "state fingerprint unchanged ($0 skip)"
            conn.execute("INSERT OR REPLACE INTO router_state (key, value) VALUES ('last_fp', ?)", (fp,))

        triage_sys = (
            "You are the fast triage gate for the Kintoun decompilation supervisor. "
            "Decide if the main supervisor turn is needed now (e.g. quarantined pile with 0 pending, "
            "stalled workers, or routing adjustments needed). Routine progress needs no intervention. "
            'Reply ONLY JSON: {"wake": true|false, "why": "<= 15 words"}'
        )
        verdict, _cost = self._invoke("fast", triage_sys, json.dumps(view), max_tokens=200)
        if verdict is None:
            return False, "triage unavailable"
        return bool(verdict.get("wake")), str(verdict.get("why", "triage"))

    def check_action(self, action: dict[str, Any]) -> tuple[bool, str]:
        """Audit a proposed mutating action against `standing_rules` before executing."""
        check_sys = (
            "Check ONE supervisor action against the standing rules below. "
            'Reply ONLY JSON: {"ok": true|false, "why": "<= 20 words"}\n\n'
            f"STANDING RULES:\n{self.settings.standing_rules}"
        )
        verdict, _cost = self._invoke("fast", check_sys, json.dumps(action), max_tokens=200)
        if verdict is None:
            return True, "check skipped (fail-open)"
        return bool(verdict.get("ok", True)), str(verdict.get("why", ""))

    def plan_actions(self, snapshot: dict[str, Any]) -> list[dict[str, Any]]:
        """Run main supervisor reasoning turn returning 0..3 guarded actions."""
        sys_prompt = (
            "You are the Kintoun Fleet Supervisor. Given the live queue, pressure, and worker snapshot, "
            "choose 0 to 3 safe actions from ONLY this allowlist:\n"
            '  - {"tool": "unquarantine", "limit": 20}\n'
            '  - {"tool": "set_claim_limit", "agent_id": "<id>", "max_claims": 1..6, "note": "<why>"}\n'
            '  - {"tool": "pause_agent", "agent_id": "<id>", "minutes": 5..60, "note": "<why>"}\n'
            '  - {"tool": "resume_agent", "agent_id": "<id>"}\n'
            '  - {"tool": "nudge_tmux", "session": "<name>"}\n'
            'Reply ONLY JSON: {"summary": "<1 sentence>", "actions": [ ... ]}'
        )
        out, _cost = self._invoke("main", sys_prompt, json.dumps(snapshot)[:10000], max_tokens=500)
        if not out:
            return []
        self.log_event("main_turn", {"summary": out.get("summary", ""), "actions": out.get("actions", [])})
        raw_actions = out.get("actions") or []
        return [a for a in raw_actions if isinstance(a, dict) and isinstance(a.get("tool"), str)][:3]


class Overseer:
    """Out-of-the-box deterministic + optional single/dual-LLM supervisor."""

    def __init__(self, cfg: KintounConfig, settings: OverseerSettings | None = None) -> None:
        self.cfg = cfg
        self.settings = settings or settings_from_toml(cfg)
        cache_dir = cfg.resolve_path(cfg.search.cache_dir) or (cfg.root / ".kintoun" / "cache")
        self.kintoun_dir = cache_dir.parent
        self.queue = WorkQueue(self.kintoun_dir)
        self.tuner = AutoTuner(cache_dir)
        self.router = BrainRouter(self.settings, self.kintoun_dir)

    def _scan_tmux_workers(self) -> list[dict[str, Any]]:
        workers: list[dict[str, Any]] = []
        for sess in self.settings.tmux_sessions:
            try:
                proc = subprocess.run(
                    ["tmux", "capture-pane", "-p", "-t", sess],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=4,
                )
                if proc.returncode != 0:
                    workers.append({"session": sess, "alive": False, "idle": False})
                    continue
                tail = [ln.strip() for ln in proc.stdout.splitlines() if ln.strip()][-6:]
                joined = "\n".join(tail).lower()
                busy = any(tok in joined for tok in ("working", "thinking", "running", "esc to interrupt"))
                workers.append({"session": sess, "alive": True, "idle": not busy, "tail": tail[-2:]})
            except Exception:
                workers.append({"session": sess, "alive": False, "idle": False})
        return workers

    def _nudge_tmux(self, session: str, dry_run: bool = False) -> dict[str, Any]:
        msg = "Overseer: continue claiming and refining functions until verified or clock expiry."
        if dry_run:
            return {"tool": "nudge_tmux", "session": session, "dry_run": True}
        subprocess.run(["tmux", "send-keys", "-t", session, "-l", msg], capture_output=True, timeout=4)
        subprocess.run(["tmux", "send-keys", "-t", session, "Enter"], capture_output=True, timeout=4)
        return {"tool": "nudge_tmux", "session": session, "sent": True}

    def _run_code_closer_once(self, dry_run: bool = False) -> dict[str, Any] | None:
        """Zero-LLM reflex: pick top pending `>=85%` near-miss and run `close_near_miss` if headroom is clear."""
        if not self.settings.auto_close_near_misses:
            return None
        tune = self.tuner.evaluate()
        if tune["level"] == 0:
            return {"skipped": True, "reason": "autotune paused on memory pressure"}
        top = self.queue.top_near_misses(limit=1)
        if not top:
            return None
        item = top[0]
        src_cand = self.cfg.root / item["src_path"]
        hint_cand = self.kintoun_dir / "hints" / f"{item['name']}.c"
        seeds = [p.read_text(encoding="utf-8") for p in (hint_cand, src_cand) if p.is_file()]
        if not seeds:
            return None
        if dry_run:
            return {"dry_run": True, "would_close": item["name"], "best_pct": item["best_pct"]}
        ctx = load_target_from_config(self.cfg)
        tf = ctx.resolve_function(item["name"])
        compiler = make_compiler(self.cfg, va=tf.va)
        cache_dir = self.cfg.resolve_path(self.cfg.search.cache_dir)
        priors_path = self.cfg.resolve_path(self.cfg.search.priors_file)
        budget = min(60.0, float(tune["params"]["budget_s"] or 45))
        res = close_near_miss(
            seeds,
            tf,
            ctx,
            compiler,
            budget_s=budget,
            max_candidates=int(tune["params"]["max_candidates"] or 120),
            cache_dir=cache_dir,
            priors_path=priors_path,
            forbid_asm=self.cfg.search.forbid_asm,
        )
        if res.get("verified") and (res.get("best") or {}).get("code"):
            self.queue.submit_match(
                "overseer-closer",
                item["addr"],
                res["best"]["code"],
                ctx,
                compiler,
                project_root=self.cfg.root,
                src_path=item["src_path"],
                fix_category=res.get("classification", {}).get("primary_class", "closer"),
                engine_note="Auto-closed from near-miss seed by Kintoun zero-LLM diff-classified closer.",
                forbid_asm=self.cfg.search.forbid_asm,
            )
        return {"function": item["name"], "verified": res.get("verified"), "improved": res.get("improved")}

    def execute_action(self, action: dict[str, Any], *, dry_run: bool = False) -> dict[str, Any]:
        tool = action.get("tool", "")
        ok, why = self.router.check_action(action)
        if not ok:
            blocked = {"tool": tool, "blocked": True, "why": why}
            self.router.log_event("action_blocked", blocked)
            return blocked

        if tool == "unquarantine":
            lim = int(action.get("limit", 20))
            n = 0 if dry_run else self.queue.unquarantine(limit=lim)
            res = {"tool": tool, "released": n, "dry_run": dry_run}
        elif tool == "set_claim_limit":
            aid = str(action.get("agent_id", ""))
            mc = max(1, min(int(action.get("max_claims", 4)), 8))
            res = (
                {"tool": tool, "agent_id": aid, "max_claims": mc, "dry_run": True}
                if dry_run
                else self.queue.set_agent_control(aid, max_claims=mc, note=str(action.get("note", "overseer")))
            )
        elif tool == "pause_agent":
            aid = str(action.get("agent_id", ""))
            mins = max(1.0, min(float(action.get("minutes", 15.0)), 120.0))
            res = (
                {"tool": tool, "agent_id": aid, "minutes": mins, "dry_run": True}
                if dry_run
                else self.queue.set_agent_control(aid, pause_minutes=mins, note=str(action.get("note", "overseer")))
            )
        elif tool == "resume_agent":
            aid = str(action.get("agent_id", ""))
            res = (
                {"tool": tool, "agent_id": aid, "dry_run": True}
                if dry_run
                else self.queue.set_agent_control(aid, pause_minutes=0.0, note="resumed")
            )
        elif tool == "nudge_tmux":
            sess = str(action.get("session", ""))
            res = self._nudge_tmux(sess, dry_run=dry_run) if sess in self.settings.tmux_sessions else {"error": "unknown session"}
        else:
            res = {"tool": tool, "error": "tool not in allowlist"}

        self.router.log_event("action_executed", res)
        return res

    def run_cycle(self, *, dry_run: bool = False) -> dict[str, Any]:
        """Execute one full supervisor cycle: `$0` code reflexes first, then optional single/dual brain."""
        reaped = [] if dry_run else self.queue.reap_expired()
        closer_res = self._run_code_closer_once(dry_run=dry_run)
        q_status = self.queue.status()
        tune = self.tuner.evaluate()
        workers = self._scan_tmux_workers()

        snapshot = {
            "brain_mode": self.settings.brain_mode,
            "spend_today_usd": round(self.router.today_spend(), 5),
            "daily_budget_usd": self.settings.daily_budget_usd,
            "reaped_expired": reaped,
            "closer": closer_res,
            "queue": q_status,
            "autotune": {"level": tune["level"], "params": tune["params"], "reasons": tune["reasons"]},
            "tmux_workers": workers,
        }

        wake, wake_why = self.router.should_wake_main(snapshot)
        executed: list[dict[str, Any]] = []
        if wake:
            for act in self.router.plan_actions(snapshot):
                executed.append(self.execute_action(act, dry_run=dry_run))
            if executed and not dry_run:
                # Refresh queue snapshot and store post-action fingerprint so the Overseer's
                # own steady-state change does not trigger a redundant wake on the next cycle.
                q_status = self.queue.status()
                snapshot["queue"] = q_status
                self.router.save_fingerprint(snapshot)

        out = {
            **snapshot,
            "brain_woke": wake,
            "brain_reason": wake_why,
            "actions": executed,
        }
        self.router.log_event("cycle", {"woke": wake, "why": wake_why, "actions": len(executed)})
        return out

    def status(self) -> dict[str, Any]:
        with self.router._connect() as conn:
            recent = [
                {"ts": r[0], "kind": r[1], "detail": r[2]}
                for r in conn.execute("SELECT ts, kind, detail FROM journal ORDER BY id DESC LIMIT 8").fetchall()
            ]
        return {
            "brain_mode": self.settings.brain_mode,
            "main_brain": {
                "provider": self.settings.main_brain.provider,
                "model": self.settings.main_brain.model,
            },
            "fast_brain": (
                {
                    "provider": self.settings.fast_brain.provider,
                    "model": self.settings.fast_brain.model,
                }
                if self.settings.fast_brain
                else None
            ),
            "spend_today_usd": round(self.router.today_spend(), 5),
            "daily_budget_usd": self.settings.daily_budget_usd,
            "queue": self.queue.status(),
            "autotune": self.tuner.evaluate(),
            "recent_journal": recent,
        }
