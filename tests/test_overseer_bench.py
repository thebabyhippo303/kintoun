"""Unit tests for the overseer benchmark's templates and team broker (no compiler or agent needed)."""
from __future__ import annotations

import json
from pathlib import Path
import re
import sys
import tempfile
import time
import unittest

from kintoun.overseer_bench import TEMPLATE_DIR, TeamBroker, _peak, fill_template


def _values() -> dict:
    return {
        "worker_label": "W", "overseer_label": "O", "max_workers_note": "", "n_functions": 3, "n_games": 2,
        "game_list": "`g01`, `g02`", "clock_s": 60, "clock_min": 1, "machine": "2 CPU threads", "kintoun_cmd": "kintoun",
    }


class TemplateTests(unittest.TestCase):
    def test_overseer_and_worker_templates_fill_every_parameter(self) -> None:
        o = fill_template(TEMPLATE_DIR / "overseer.md", _values())
        w = fill_template(TEMPLATE_DIR / "worker.md", {**_values(), "worker_id": "w1", "assignment": "own g01",
                                                         "remaining_s": 50, "remaining_min": 1})
        for text in (o, w):
            self.assertIsNone(re.search(r"\$[a-z_]+", text), text)
        self.assertIn("spawn-worker", o)
        self.assertIn("own g01", w)
        self.assertNotIn("spawn-worker", w)

    def test_example_run_file_parses(self) -> None:
        import tomllib

        run = tomllib.loads((TEMPLATE_DIR / "run.example.toml").read_text())
        for side in ("overseer", "workers"):
            self.assertIn("{prompt}", run[side]["cmd"])
            self.assertTrue(run[side]["model"])


class BrokerTests(unittest.TestCase):
    def _broker(self, ws: Path, max_workers: int = 0) -> TeamBroker:
        run = {"workers": {"model": "m", "effort": "high", "max": max_workers, "min_free_mem_gb": 0,
                           "cmd": f"{sys.executable} -c \"import time; print('worker up'); time.sleep(5)\" {{prompt}}"}}
        return TeamBroker(ws, run, {"PATH": "/usr/bin:/bin", "ORIG_PATH": "/usr/bin:/bin"}, time.monotonic() + 120,
                          time.monotonic(), _values())

    def _request(self, ws: Path, n: str, brief: Path) -> dict:
        (ws / ".overseer" / "requests" / f"{n}.json").write_text(json.dumps({"brief": str(brief)}))
        return n

    def test_spawn_limit_outside_brief_and_stop(self) -> None:
        with tempfile.TemporaryDirectory() as t:
            ws = Path(t)
            b = self._broker(ws, max_workers=1)
            (ws / "workers").mkdir()
            brief = ws / "workers" / "a.md"
            brief.write_text("own g01")
            self._request(ws, "1", brief)
            self._request(ws, "2", brief)
            self._request(ws, "3", Path("/etc/hostname"))
            b.poll()
            replies = {p.stem: json.loads(p.read_text()) for p in (ws / ".overseer" / "replies").glob("*.json")}
            self.assertTrue(replies["1"]["ok"])
            self.assertIn("workers already running", replies["2"]["message"])
            self.assertIn("inside the workspace", replies["3"]["message"])
            self.assertEqual(b.running(), 1)
            (ws / ".overseer" / "workers" / "w1" / "stop").write_text("stop")
            b.poll()
            st = json.loads((ws / ".overseer" / "workers" / "w1" / "status.json").read_text())
            self.assertEqual(st["state"], "stopped")
            self.assertIn("own g01", (ws / ".overseer" / "workers" / "w1" / "PROMPT.md").read_text())
            b.stop_all()

    def test_peak_running(self) -> None:
        team = [{"started_at_s": 0, "elapsed_s": 10}, {"started_at_s": 5, "elapsed_s": 10}, {"started_at_s": 20, "elapsed_s": 1}]
        self.assertEqual(_peak(team), 2)


if __name__ == "__main__":
    unittest.main()
