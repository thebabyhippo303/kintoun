"""Content-addressed candidate store, surgical `revise_candidate`, and batch `score_candidates`.

Lets humans and AI agents iterate on C candidates using compact `cand_<12hex>` IDs and exact
`old -> new` diff patches (~150 tokens/turn) instead of rewriting entire source files on each edit,
while caching both valid strict scores and deterministic compile errors across calls.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import hashlib
import json
from pathlib import Path
import sqlite3
import threading
import time
from typing import Any

from kintoun.cache import ResultCache, source_key
from kintoun.compiler import CompilerBackend
from kintoun.governor import CompileDeduper, CompileGovernor
from kintoun.search.runner import rank_result
from kintoun.targets import TargetContext, TargetFunction
from kintoun.verify import verify_source


class CandidateStore:
    """SQLite-backed immutable candidate store keyed by `cand_<12hex>` IDs."""

    def __init__(self, cache_dir: Path, max_entries: int = 10000) -> None:
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = self.cache_dir / "candidates.sqlite3"
        self.max_entries = max_entries
        self._lock = threading.Lock()
        self._result_cache = ResultCache(self.cache_dir)
        self._deduper = CompileDeduper(self.cache_dir)
        self._governor = CompileGovernor(self.cache_dir, caller_id="candidates")
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
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS candidates (
                    cand_id TEXT PRIMARY KEY,
                    func_name TEXT NOT NULL,
                    func_addr TEXT NOT NULL,
                    source TEXT NOT NULL,
                    result_json TEXT NOT NULL,
                    strategy TEXT NOT NULL,
                    parent_id TEXT NOT NULL,
                    created REAL NOT NULL
                )
                """
            )

    @staticmethod
    def make_id(func_name: str, addr: int, source: str) -> str:
        digest = hashlib.sha256(f"{func_name}@0x{addr:08X}\n{source}".encode("utf-8")).hexdigest()[:12]
        return f"cand_{digest}"

    def put(
        self,
        func_name: str,
        addr: int,
        source: str,
        result: dict[str, Any],
        strategy: str = "hand",
        parent_id: str = "",
    ) -> str:
        cand_id = self.make_id(func_name, addr, source)
        clean_res = {k: v for k, v in result.items() if not k.startswith("_")}
        now = time.time()
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO candidates
                (cand_id, func_name, func_addr, source, result_json, strategy, parent_id, created)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    cand_id,
                    func_name,
                    f"0x{addr:08X}",
                    source,
                    json.dumps(clean_res),
                    strategy,
                    parent_id,
                    now,
                ),
            )
            count = conn.execute("SELECT COUNT(*) FROM candidates").fetchone()[0]
            if count > self.max_entries:
                excess = count - self.max_entries
                conn.execute(
                    "DELETE FROM candidates WHERE cand_id IN "
                    "(SELECT cand_id FROM candidates ORDER BY created ASC LIMIT ?)",
                    (excess,),
                )
        return cand_id

    def get(self, cand_id: str) -> dict[str, Any] | None:
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT cand_id, func_name, func_addr, source, result_json, strategy, parent_id, created "
                "FROM candidates WHERE cand_id = ?",
                (cand_id,),
            ).fetchone()
        if row is None:
            return None
        return {
            "candidate_id": row[0],
            "name": row[1],
            "addr": row[2],
            "code": row[3],
            "result": json.loads(row[4]),
            "strategy": row[5],
            "parent_id": row[6],
            "created": row[7],
        }

    def score_one(
        self,
        source: str,
        target_fn: TargetFunction,
        ctx: TargetContext,
        compiler: CompilerBackend,
        *,
        lines: int = 24,
        forbid_asm: bool = True,
        strategy: str = "hand",
        parent_id: str = "",
        include_code: bool = False,
        tier: str = "interactive",
        abort_if_done: bool = False,
    ) -> dict[str, Any]:
        """Compile (or hit shared cache, including cached compile errors) and register `candidate_id`."""
        done_meta: dict[str, Any] | None = None
        q_db = self.cache_dir.parent / "queue.sqlite3"
        if q_db.is_file():
            from kintoun.queue import WorkQueue

            done_meta = WorkQueue(self.cache_dir.parent).verified_info(target_fn.name)
            if done_meta and abort_if_done:
                cand_id = self.make_id(target_fn.name, target_fn.va, source)
                return {
                    "status": "already_verified",
                    "verified": True,
                    "name": target_fn.name,
                    "addr": f"0x{target_fn.va:08X}",
                    "candidate_id": cand_id,
                    "cache_hit": True,
                    **done_meta,
                }

        target_id = f"{target_fn.name}@0x{target_fn.va:08X}:{hashlib.sha256(target_fn.data).hexdigest()[:16]}"
        ckey = source_key(source, target_id, compiler.flags, compiler.compiler_id)

        with self._deduper.lock_key(ckey):
            cached = self._result_cache.get(ckey)
            if cached is not None and lines <= 24:
                res = dict(cached)
                res["cache_hit"] = True
            else:
                with self._governor.acquire(tier=tier, timeout_s=30.0):
                    res = verify_source(
                        source,
                        target_fn,
                        ctx,
                        compiler,
                        lines=lines,
                        forbid_asm=forbid_asm,
                    )
                res["cache_hit"] = False
                self._result_cache.put(ckey, res)

        cand_id = self.put(target_fn.name, target_fn.va, source, res, strategy=strategy, parent_id=parent_id)
        out = dict(res)
        out["candidate_id"] = cand_id
        if done_meta:
            out.update(done_meta)
        if parent_id:
            out["parent_id"] = parent_id
        if include_code:
            out["code"] = source
        return out

    def revise(
        self,
        cand_id: str,
        edits: list[dict[str, str]],
        target_fn: TargetFunction,
        ctx: TargetContext,
        compiler: CompilerBackend,
        *,
        lines: int = 24,
        forbid_asm: bool = True,
        include_code: bool = False,
        abort_if_done: bool = False,
    ) -> dict[str, Any]:
        """Apply exact single-match `old -> new` edits to `cand_id`, re-score strictly, and compute deltas."""
        if abort_if_done and (self.cache_dir.parent / "queue.sqlite3").is_file():
            from kintoun.queue import WorkQueue

            done_meta = WorkQueue(self.cache_dir.parent).verified_info(target_fn.name)
            if done_meta:
                return {
                    "status": "already_verified",
                    "verified": True,
                    "name": target_fn.name,
                    "addr": f"0x{target_fn.va:08X}",
                    "candidate_id": cand_id,
                    "cache_hit": True,
                    **done_meta,
                }
        base = self.get(cand_id)
        if base is None:
            raise ValueError(f"unknown candidate_id: {cand_id}")
        text = base["code"]
        if not edits:
            out = dict(base["result"])
            out["candidate_id"] = cand_id
            if include_code:
                out["code"] = text
            return out

        for idx, edit in enumerate(edits):
            old = edit.get("old", "")
            new = edit.get("new", "")
            if not old:
                raise ValueError(f"edit[{idx}] 'old' string must be non-empty")
            matches = text.count(old)
            if matches == 0:
                raise ValueError(f"edit[{idx}] 'old' snippet not found in {cand_id}")
            if matches > 1:
                raise ValueError(f"edit[{idx}] 'old' snippet matched {matches} times; include more surrounding context")
            text = text.replace(old, new, 1)

        scored = self.score_one(
            text,
            target_fn,
            ctx,
            compiler,
            lines=lines,
            forbid_asm=forbid_asm,
            strategy="revise",
            parent_id=cand_id,
            include_code=include_code,
        )
        prev = base["result"]
        prev_sc = prev.get("search") or {}
        cur_sc = scored.get("search") or {}
        scored["delta"] = {
            "aligned_pct": (
                round(float(cur_sc["aligned_pct"]) - float(prev_sc["aligned_pct"]), 2)
                if "aligned_pct" in cur_sc and "aligned_pct" in prev_sc
                else None
            ),
            "different_bytes": (
                int(scored["different_bytes"]) - int(prev["different_bytes"])
                if isinstance(scored.get("different_bytes"), int) and isinstance(prev.get("different_bytes"), int)
                else None
            ),
            "score_total": (
                int(cur_sc["total"]) - int(prev_sc["total"])
                if isinstance(cur_sc.get("total"), int) and isinstance(prev_sc.get("total"), int)
                else None
            ),
            "improved": rank_result({**scored, "_source": text}) < rank_result({**prev, "_source": base["code"]}),
        }
        return scored

    def score_batch(
        self,
        sources: list[str],
        target_fn: TargetFunction,
        ctx: TargetContext,
        compiler: CompilerBackend,
        *,
        forbid_asm: bool = True,
        workers: int = 4,
    ) -> dict[str, Any]:
        """Compile and score 2..16 candidate C formulations in parallel and return them ranked best-first."""
        if not 1 <= len(sources) <= 16:
            raise ValueError("score_batch accepts between 1 and 16 candidate C strings")

        def _one(item: tuple[int, str]) -> dict[str, Any]:
            idx, src = item
            res = self.score_one(
                src,
                target_fn,
                ctx,
                compiler,
                lines=16,
                forbid_asm=forbid_asm,
                strategy=f"batch_{idx}",
                tier="search",
            )
            res["index"] = idx
            res["_source"] = src
            return res

        max_w = max(1, min(workers, len(sources), 8))
        with ThreadPoolExecutor(max_workers=max_w) as pool:
            raw_results = list(pool.map(_one, enumerate(sources)))

        ranked = sorted(raw_results, key=rank_result)
        cleaned = [{k: v for k, v in r.items() if not k.startswith("_")} for r in ranked]
        return {
            "name": target_fn.name,
            "addr": f"0x{target_fn.va:08X}",
            "evaluated": len(cleaned),
            "verified": any(bool(r.get("verified")) for r in cleaned),
            "best": cleaned[0] if cleaned else None,
            "results": cleaned,
        }
