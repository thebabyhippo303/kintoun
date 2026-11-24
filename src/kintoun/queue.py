"""Multi-agent work queue, server-enforced chess clock, difficulty routing, and quarantine.

Provides a zero-dependency SQLite WAL queue (`.kintoun/queue.sqlite3`) so a single developer or
a fleet of concurrent AI agents can coordinate cleanly out of the box:
  - **Multi-claim multiplexing (`max_claims`):** Each agent can hold multiple functions at once,
    each with its own independent per-function chess clock (`limit_s`, scaled automatically for
    `hard` and `brutal` functions).
  - **Server-enforced chess clock:** `fail_claim` is refused before clock expiry unless `reason`
    is a structural blocker (`not-plain-c`, `needs-asm`, `data-only`, `toolchain-error`, `bad-symbol`).
  - **Timeout quarantine & near-miss routing:** Functions timing out `>= 2` times below `85%` are
    parked as `quarantined` (`unquarantine` releases them); timeouts at `>= 85%` stay eligible for
    `kintoun close` / near-miss sweeps.
  - **Strict submit + research corpus:** `submit_match` checks `real_c_violation`, freshly runs
    `verify_source`, writes `src_path`, and logs optional `engine_note` / `fix_category` to
    `.kintoun/research/notes.jsonl`.
"""
from __future__ import annotations

from contextlib import contextmanager
import json
from pathlib import Path
import sqlite3
import threading
import time
from typing import Any

from kintoun.compiler import CompilerBackend
from kintoun.inspect_fn import score_difficulty
from kintoun.targets import TargetContext
from kintoun.verify import real_c_violation, verify_source

STRUCTURAL_REASONS: frozenset[str] = frozenset(
    {
        "not-plain-c",
        "needs-asm",
        "data-only",
        "not-code",
        "bad-symbol",
        "toolchain-error",
        "duplicate",
    }
)


class WorkQueue:
    """SQLite WAL multi-agent claim queue with chess-clock enforcement and quarantine."""

    def __init__(
        self,
        kintoun_dir: Path,
        *,
        default_limit_s: float = 450.0,
        max_claims_per_agent: int = 4,
        quarantine_after_timeouts: int = 2,
        near_miss_pct: float = 85.0,
        require_engine_note: bool = False,
    ) -> None:
        self.kintoun_dir = Path(kintoun_dir)
        self.kintoun_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = self.kintoun_dir / "queue.sqlite3"
        self.notes_path = self.kintoun_dir / "research" / "notes.jsonl"
        self.default_limit_s = default_limit_s
        self.max_claims_per_agent = max_claims_per_agent
        self.quarantine_after_timeouts = quarantine_after_timeouts
        self.near_miss_pct = near_miss_pct
        self.require_engine_note = require_engine_note
        self._lock = threading.Lock()
        self._init_db()

    @contextmanager
    def _connect(self):
        conn = sqlite3.connect(self.db_path, timeout=15.0)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.row_factory = sqlite3.Row
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    def _init_db(self) -> None:
        with self._lock, self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS queue (
                    addr TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    size_bytes INTEGER NOT NULL,
                    status TEXT NOT NULL DEFAULT 'pending',
                    claimed_by TEXT NOT NULL DEFAULT '',
                    claimed_at REAL NOT NULL DEFAULT 0,
                    limit_s REAL NOT NULL DEFAULT 450,
                    difficulty INTEGER NOT NULL DEFAULT 25,
                    tier TEXT NOT NULL DEFAULT 'medium',
                    tags_json TEXT NOT NULL DEFAULT '[]',
                    plain_c INTEGER NOT NULL DEFAULT 1,
                    tries INTEGER NOT NULL DEFAULT 0,
                    timeouts INTEGER NOT NULL DEFAULT 0,
                    best_pct REAL NOT NULL DEFAULT 0,
                    src_path TEXT NOT NULL DEFAULT '',
                    note TEXT NOT NULL DEFAULT '',
                    updated_at REAL NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS agent_controls (
                    agent_id TEXT PRIMARY KEY,
                    max_claims INTEGER,
                    paused_until REAL NOT NULL DEFAULT 0,
                    note TEXT NOT NULL DEFAULT ''
                );
                """
            )

    def sync_from_context(self, ctx: TargetContext, default_src_dir: str = "src") -> dict[str, int]:
        """Populate new target functions from `ctx` with static difficulty scores."""
        added = 0
        skipped = 0
        now = time.time()
        rows_to_insert: list[tuple[Any, ...]] = []
        with self._lock, self._connect() as conn:
            existing = {r["addr"] for r in conn.execute("SELECT addr FROM queue").fetchall()}
            for name, (va, size) in sorted(ctx.funcs.items(), key=lambda kv: kv[1][0]):
                if size <= 0:
                    continue
                addr_s = f"0x{va:08X}"
                if addr_s in existing:
                    skipped += 1
                    continue
                try:
                    tf = ctx.resolve_function(name)
                    diff = score_difficulty(tf, ctx)
                except Exception:
                    diff = {
                        "score": 30,
                        "tier": "medium",
                        "tags": [],
                        "recommended_time_multiplier": 1.0,
                        "plain_c": True,
                    }
                lim = round(self.default_limit_s * float(diff["recommended_time_multiplier"]), 1)
                cls_part, sep, meth_part = name.partition("__")
                rel_src = f"{default_src_dir}/{cls_part}/{meth_part}.c" if sep else f"{default_src_dir}/{name}.c"
                rows_to_insert.append(
                    (
                        addr_s,
                        name,
                        size,
                        "pending" if diff["plain_c"] else "blocked",
                        lim,
                        int(diff["score"]),
                        str(diff["tier"]),
                        json.dumps(diff["tags"]),
                        int(bool(diff["plain_c"])),
                        rel_src,
                        "" if diff["plain_c"] else "auto-flagged not-plain-c",
                        now,
                    )
                )
            if rows_to_insert:
                conn.executemany(
                    """
                    INSERT OR IGNORE INTO queue
                    (addr, name, size_bytes, status, limit_s, difficulty, tier, tags_json, plain_c, src_path, note, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    rows_to_insert,
                )
                added = len(rows_to_insert)
        return {"added": added, "existing": skipped, "total": added + skipped}

    def reap_expired(self, now: float | None = None) -> list[dict[str, Any]]:
        """Auto-expire claims past their chess clock, quarantining repeated low-% timeouts."""
        t_now = time.time() if now is None else now
        expired: list[dict[str, Any]] = []
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM queue WHERE status = 'claimed' AND (claimed_at + limit_s) <= ?",
                (t_now,),
            ).fetchall()
            for r in rows:
                timeouts = int(r["timeouts"]) + 1
                tries = int(r["tries"]) + 1
                best_pct = float(r["best_pct"])
                if timeouts >= self.quarantine_after_timeouts and best_pct < self.near_miss_pct:
                    new_status = "quarantined"
                    note = f"quarantined after {timeouts} timeouts (best {best_pct:.1f}%)"
                else:
                    new_status = "pending"
                    note = f"timeout #{timeouts} by {r['claimed_by']} (best {best_pct:.1f}%)"
                conn.execute(
                    """
                    UPDATE queue
                    SET status = ?, claimed_by = '', claimed_at = 0, tries = ?, timeouts = ?, note = ?, updated_at = ?
                    WHERE addr = ?
                    """,
                    (new_status, tries, timeouts, note, t_now, r["addr"]),
                )
                expired.append(
                    {
                        "addr": r["addr"],
                        "name": r["name"],
                        "agent": r["claimed_by"],
                        "new_status": new_status,
                        "best_pct": best_pct,
                        "timeouts": timeouts,
                    }
                )
        return expired

    def _agent_allowance(self, conn: sqlite3.Connection, agent_id: str, now: float) -> tuple[int, str | None]:
        row = conn.execute("SELECT * FROM agent_controls WHERE agent_id = ?", (agent_id,)).fetchone()
        if row is not None:
            if float(row["paused_until"]) > now:
                left = int(round(float(row["paused_until"]) - now))
                return 0, f"claiming paused for {agent_id} ({left}s remaining: {row['note']})"
            if row["max_claims"] is not None:
                return int(row["max_claims"]), None
        return self.max_claims_per_agent, None

    def clock(self, agent_id: str, now: float | None = None) -> dict[str, Any]:
        """Return active claims and remaining chess-clock time for `agent_id`."""
        t_now = time.time() if now is None else now
        self.reap_expired(now=t_now)
        with self._lock, self._connect() as conn:
            cap, pause_msg = self._agent_allowance(conn, agent_id, t_now)
            rows = conn.execute(
                "SELECT * FROM queue WHERE status = 'claimed' AND claimed_by = ? ORDER BY claimed_at ASC",
                (agent_id,),
            ).fetchall()
        claims = []
        parts = []
        for r in rows:
            used = max(0.0, t_now - float(r["claimed_at"]))
            left = max(0.0, float(r["limit_s"]) - used)
            claims.append(
                {
                    "addr": r["addr"],
                    "name": r["name"],
                    "tier": r["tier"],
                    "src_path": r["src_path"],
                    "used_s": round(used, 1),
                    "left_s": round(left, 1),
                    "limit_s": float(r["limit_s"]),
                    "best_pct": float(r["best_pct"]),
                }
            )
            parts.append(f"{r['addr']} {r['name']} {int(used)}s used / {int(left)}s left")
        summary = (
            f"clock: {' | '.join(parts)} ({len(claims)}/{cap} claims)"
            if parts
            else f"clock: idle (0/{cap} claims)"
        )
        out: dict[str, Any] = {
            "agent_id": agent_id,
            "active_claims": len(claims),
            "max_claims": cap,
            "claims": claims,
            "clock_line": summary,
        }
        if pause_msg:
            out["paused"] = pause_msg
        return out

    def claim_next(
        self,
        agent_id: str,
        *,
        prefer_tier: str = "",
        max_difficulty: int = 100,
        now: float | None = None,
    ) -> dict[str, Any]:
        """Claim the next pending function for `agent_id`, respecting `max_claims` and difficulty routing."""
        t_now = time.time() if now is None else now
        self.reap_expired(now=t_now)
        with self._lock, self._connect() as conn:
            cap, pause_msg = self._agent_allowance(conn, agent_id, t_now)
            if pause_msg:
                return {"claimed": False, "error": pause_msg}
            held = conn.execute(
                "SELECT COUNT(*) AS n FROM queue WHERE status = 'claimed' AND claimed_by = ?",
                (agent_id,),
            ).fetchone()["n"]
            if held >= cap:
                return {
                    "claimed": False,
                    "error": f"agent '{agent_id}' already holds {held}/{cap} active claims",
                    **self.clock(agent_id, now=t_now),
                }

            rows = conn.execute(
                """
                SELECT * FROM queue
                WHERE status = 'pending' AND difficulty <= ?
                ORDER BY
                    CASE WHEN ? != '' AND tier = ? THEN 0 ELSE 1 END ASC,
                    CASE WHEN best_pct >= ? THEN 0 ELSE 1 END ASC,
                    difficulty ASC,
                    size_bytes ASC,
                    addr ASC
                LIMIT 1
                """,
                (max_difficulty, prefer_tier, prefer_tier, self.near_miss_pct),
            ).fetchall()
            if not rows:
                return {"claimed": False, "error": "no pending functions match filter"}
            r = rows[0]
            conn.execute(
                """
                UPDATE queue
                SET status = 'claimed', claimed_by = ?, claimed_at = ?, updated_at = ?
                WHERE addr = ?
                """,
                (agent_id, t_now, t_now, r["addr"]),
            )
        clk = self.clock(agent_id, now=t_now)
        return {
            "claimed": True,
            "addr": r["addr"],
            "name": r["name"],
            "size_bytes": int(r["size_bytes"]),
            "difficulty": int(r["difficulty"]),
            "tier": r["tier"],
            "tags": json.loads(r["tags_json"]),
            "src_path": r["src_path"],
            "limit_s": float(r["limit_s"]),
            "best_pct": float(r["best_pct"]),
            "prior_note": r["note"],
            "clock_line": clk["clock_line"],
        }

    def verified_info(self, func_or_addr: str) -> dict[str, Any] | None:
        """Return match info if `func_or_addr` is already marked `done` (for early-abort race coordination)."""
        key = self._norm_key(func_or_addr)
        with self._lock, self._connect() as conn:
            r = conn.execute(
                "SELECT addr, name, src_path, note, updated_at FROM queue WHERE (addr = ? OR name = ?) AND status = 'done'",
                (key, func_or_addr),
            ).fetchone()
        if r is None:
            return None
        return {
            "already_verified": True,
            "addr": r["addr"],
            "name": r["name"],
            "verified_src_path": r["src_path"],
            "note": r["note"],
            "abort_hint": (
                f"{r['name']} ({r['addr']}) is already VERIFIED ({r['note']}). "
                "Stop iterating on this function and claim your next function."
            ),
        }

    def record_progress(self, func_or_addr: str, best_pct: float) -> None:
        """Update `best_pct` watermark on a function as search/scoring progresses."""
        key = self._norm_key(func_or_addr)
        with self._lock, self._connect() as conn:
            conn.execute(
                "UPDATE queue SET best_pct = MAX(best_pct, ?), updated_at = ? WHERE addr = ? OR name = ?",
                (float(best_pct), time.time(), key, func_or_addr),
            )

    @staticmethod
    def _norm_key(func_or_addr: str) -> str:
        s = func_or_addr.strip()
        try:
            return f"0x{int(s, 16):08X}" if s.lower().startswith("0x") else s
        except ValueError:
            return s

    def fail_claim(
        self,
        agent_id: str,
        func_or_addr: str,
        reason: str,
        *,
        note: str = "",
        best_pct: float | None = None,
        now: float | None = None,
    ) -> dict[str, Any]:
        """Fail an active claim. Refused before clock expiry unless `reason` is structural."""
        t_now = time.time() if now is None else now
        norm_reason = reason.strip().lower()
        key = self._norm_key(func_or_addr)
        with self._lock, self._connect() as conn:
            r = conn.execute(
                "SELECT * FROM queue WHERE (addr = ? OR name = ?) AND status = 'claimed'",
                (key, func_or_addr),
            ).fetchone()
            if r is None:
                return {"ok": False, "error": f"no active claim found for '{func_or_addr}'"}
            if r["claimed_by"] != agent_id:
                return {"ok": False, "error": f"claim belongs to '{r['claimed_by']}', not '{agent_id}'"}

            elapsed = t_now - float(r["claimed_at"])
            remaining = float(r["limit_s"]) - elapsed
            if remaining > 0 and norm_reason not in STRUCTURAL_REASONS:
                return {
                    "ok": False,
                    "refused": True,
                    "error": (
                        f"CHESS CLOCK: {int(remaining)}s remaining on {r['name']} ({r['addr']}). "
                        f"Early fail_claim is only allowed for structural blockers "
                        f"({', '.join(sorted(STRUCTURAL_REASONS))}). Keep refining C or run permute/close."
                    ),
                }

            eff_best = max(float(r["best_pct"]), float(best_pct or 0.0))
            tries = int(r["tries"]) + 1
            if norm_reason in STRUCTURAL_REASONS:
                new_status = "blocked"
                timeouts = int(r["timeouts"])
            else:
                timeouts = int(r["timeouts"]) + 1
                new_status = (
                    "quarantined"
                    if (timeouts >= self.quarantine_after_timeouts and eff_best < self.near_miss_pct)
                    else "pending"
                )
            full_note = f"{norm_reason}: {note}".strip(": ")
            conn.execute(
                """
                UPDATE queue
                SET status = ?, claimed_by = '', claimed_at = 0, tries = ?, timeouts = ?,
                    best_pct = ?, note = ?, updated_at = ?
                WHERE addr = ?
                """,
                (new_status, tries, timeouts, eff_best, full_note, t_now, r["addr"]),
            )
        return {
            "ok": True,
            "addr": r["addr"],
            "name": r["name"],
            "new_status": new_status,
            "reason": norm_reason,
            "best_pct": eff_best,
            "clock_line": self.clock(agent_id, now=t_now)["clock_line"],
        }

    def submit_match(
        self,
        agent_id: str,
        func_or_addr: str,
        source_code: str,
        ctx: TargetContext,
        compiler: CompilerBackend,
        *,
        project_root: Path,
        src_path: str = "",
        integrate_into: str = "",
        engine_note: str = "",
        fix_category: str = "",
        forbid_asm: bool = True,
    ) -> dict[str, Any]:
        """Strictly re-verify `source_code`, write `src_path` (or splice `integrate_into`), log `engine_note`, and mark `done`."""
        if forbid_asm:
            bad = real_c_violation(source_code)
            if bad:
                return {"ok": False, "error": f"REAL C ONLY: rejected '{bad}'"}

        if self.require_engine_note and len(engine_note.split()) < 15:
            return {
                "ok": False,
                "error": "engine_note requires at least 15 words describing what the seed/permuter missed",
            }

        key = self._norm_key(func_or_addr)
        with self._lock, self._connect() as conn:
            r = conn.execute(
                "SELECT * FROM queue WHERE addr = ? OR name = ?",
                (key, func_or_addr),
            ).fetchone()
            if r is not None and r["status"] == "claimed" and r["claimed_by"] not in ("", agent_id):
                return {"ok": False, "error": f"function is claimed by '{r['claimed_by']}'"}
            fn_name = r["name"] if r is not None else func_or_addr
            rel_out = src_path or (r["src_path"] if r is not None else f"src/{fn_name}.c")

        target_fn = ctx.resolve_function(fn_name)
        ver = verify_source(source_code, target_fn, ctx, compiler, lines=16, forbid_asm=forbid_asm)
        if not ver.get("verified"):
            return {
                "ok": False,
                "error": f"strict verification failed ({ver.get('status')}): {ver.get('different_bytes')} bytes differ",
                "verification": ver,
            }

        integration_res: dict[str, Any] | None = None
        if integrate_into:
            from kintoun.project_io import integrate_matched_function

            int_path = Path(integrate_into) if Path(integrate_into).is_absolute() else (Path(project_root) / integrate_into)
            integration_res = integrate_matched_function(
                source_code,
                int_path,
                target_fn.name,
                verify=True,
                target_fn=target_fn,
                ctx=ctx,
                compiler=compiler,
                forbid_asm=forbid_asm,
                write=True,
            )
            if not integration_res.get("ok"):
                return integration_res
            out_file = int_path
            rel_out = integrate_into
        else:
            out_file = Path(rel_out) if Path(rel_out).is_absolute() else (Path(project_root) / rel_out)
            out_file.parent.mkdir(parents=True, exist_ok=True)
            out_file.write_text(source_code, encoding="utf-8")

        now = time.time()
        with self._lock, self._connect() as conn:
            if r is not None:
                conn.execute(
                    """
                    UPDATE queue
                    SET status = 'done', claimed_by = '', claimed_at = 0, tries = tries + 1,
                        best_pct = 100.0, src_path = ?, note = ?, updated_at = ?
                    WHERE addr = ?
                    """,
                    (str(rel_out), f"matched by {agent_id}", now, r["addr"]),
                )

        if engine_note.strip() or fix_category.strip():
            self.notes_path.parent.mkdir(parents=True, exist_ok=True)
            entry = {
                "ts": now,
                "addr": f"0x{target_fn.va:08X}",
                "name": target_fn.name,
                "agent": agent_id,
                "fix_category": fix_category.strip(),
                "engine_note": engine_note.strip(),
            }
            with self.notes_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(entry) + "\n")

        return {
            "ok": True,
            "verified": True,
            "addr": f"0x{target_fn.va:08X}",
            "name": target_fn.name,
            "written_to": str(out_file),
            "clock_line": self.clock(agent_id, now=now)["clock_line"],
        }

    def unquarantine(self, limit: int = 50) -> int:
        """Release quarantined functions back to `pending` for a fresh agent/strategy pass."""
        now = time.time()
        with self._lock, self._connect() as conn:
            cur = conn.execute(
                """
                UPDATE queue
                SET status = 'pending', timeouts = 0, note = 'unquarantined', updated_at = ?
                WHERE addr IN (SELECT addr FROM queue WHERE status = 'quarantined' LIMIT ?)
                """,
                (now, max(1, limit)),
            )
            return int(cur.rowcount or 0)

    def set_agent_control(
        self,
        agent_id: str,
        *,
        max_claims: int | None = None,
        pause_minutes: float = 0.0,
        note: str = "",
    ) -> dict[str, Any]:
        paused_until = (time.time() + pause_minutes * 60.0) if pause_minutes > 0 else 0.0
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO agent_controls (agent_id, max_claims, paused_until, note)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(agent_id) DO UPDATE SET
                    max_claims = COALESCE(excluded.max_claims, agent_controls.max_claims),
                    paused_until = excluded.paused_until,
                    note = excluded.note
                """,
                (agent_id, max_claims, paused_until, note),
            )
        return {"agent_id": agent_id, "max_claims": max_claims, "paused_until": paused_until, "note": note}

    def top_near_misses(self, min_pct: float | None = None, limit: int = 10) -> list[dict[str, Any]]:
        floor = self.near_miss_pct if min_pct is None else min_pct
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                """
                SELECT addr, name, size_bytes, best_pct, tries, timeouts, src_path, note
                FROM queue
                WHERE status = 'pending' AND best_pct >= ? AND best_pct < 100.0
                ORDER BY best_pct DESC, size_bytes ASC
                LIMIT ?
                """,
                (floor, max(1, limit)),
            ).fetchall()
        return [dict(r) for r in rows]

    def status(self) -> dict[str, Any]:
        self.reap_expired()
        with self._lock, self._connect() as conn:
            counts = {
                r["status"]: int(r["n"])
                for r in conn.execute("SELECT status, COUNT(*) AS n FROM queue GROUP BY status").fetchall()
            }
            tiers = {
                r["tier"]: int(r["n"])
                for r in conn.execute(
                    "SELECT tier, COUNT(*) AS n FROM queue WHERE status = 'pending' GROUP BY tier"
                ).fetchall()
            }
            active = [
                dict(r)
                for r in conn.execute(
                    "SELECT addr, name, claimed_by, claimed_at, limit_s, best_pct FROM queue WHERE status = 'claimed'"
                ).fetchall()
            ]
        return {
            "counts": {
                "pending": counts.get("pending", 0),
                "claimed": counts.get("claimed", 0),
                "done": counts.get("done", 0),
                "quarantined": counts.get("quarantined", 0),
                "blocked": counts.get("blocked", 0),
            },
            "pending_by_tier": tiers,
            "active_claims": active,
            "near_misses": self.top_near_misses(limit=5),
        }
