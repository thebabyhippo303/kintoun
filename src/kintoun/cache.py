"""Local SQLite content-addressed verification cache (stdlib only)."""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import json
from pathlib import Path
import sqlite3
import threading
import time
from typing import Any


def source_key(source: str, target_id: str, flags: tuple[str, ...], compiler_id: str) -> str:
    payload = json.dumps(
        {
            "source_sha256": hashlib.sha256(source.encode("utf-8")).hexdigest(),
            "target_id": target_id,
            "flags": list(flags),
            "compiler": compiler_id,
        },
        sort_keys=True,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class ResultCache:
    """Thread-safe local SQLite cache for strict verification results."""

    def __init__(self, cache_dir: Path, max_entries: int = 20000) -> None:
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = self.cache_dir / "results.sqlite3"
        self.max_entries = max_entries
        self._lock = threading.Lock()
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
                CREATE TABLE IF NOT EXISTS results (
                    key TEXT PRIMARY KEY,
                    payload TEXT NOT NULL,
                    touched REAL NOT NULL
                )
                """
            )

    def get(self, key: str) -> dict[str, Any] | None:
        with self._lock, self._connect() as conn:
            row = conn.execute("SELECT payload FROM results WHERE key = ?", (key,)).fetchone()
            if row is None:
                return None
            conn.execute("UPDATE results SET touched = ? WHERE key = ?", (time.time(), key))
        try:
            return json.loads(row[0])
        except ValueError:
            return None

    def put(self, key: str, result: dict[str, Any]) -> None:
        clean = {k: v for k, v in result.items() if not k.startswith("_")}
        payload = json.dumps(clean)
        now = time.time()
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO results (key, payload, touched) VALUES (?, ?, ?)",
                (key, payload, now),
            )
            count = conn.execute("SELECT COUNT(*) FROM results").fetchone()[0]
            if count > self.max_entries:
                excess = count - self.max_entries
                conn.execute(
                    "DELETE FROM results WHERE key IN (SELECT key FROM results ORDER BY touched ASC LIMIT ?)",
                    (excess,),
                )
