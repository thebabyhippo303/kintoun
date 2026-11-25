"""Unit tests for the overseer course: phase templates, phase context, and the engine phase freeze."""
from __future__ import annotations

from pathlib import Path
import re
import tempfile
import tomllib
import unittest

from kintoun.overseer_bench import TEMPLATE_DIR, fill_template
from kintoun.overseer_course import KINDS, _phase_context, _restore, _snapshot


class CourseTemplateTests(unittest.TestCase):
    def test_phase_templates_fill_every_parameter(self) -> None:
        values = {"worker_label": "W", "overseer_label": "O", "max_workers_note": "", "n_functions": 3, "n_games": 2,
                  "game_list": "`g01`", "machine": "2 CPU threads", "kintoun_cmd": "kintoun", "course_plan": "plan.",
                  "phase_count": 3, "phase_index": 2, "phase_name": "Engine building", "phase_s": 60, "phase_min": 1,
                  "phase_context": "ctx", "worker_id": "w1", "assignment": "do it", "remaining_s": 50, "remaining_min": 1}
        for kind in KINDS:
            for who in ("overseer", "worker"):
                text = fill_template(TEMPLATE_DIR / f"phase_{kind}_{who}.md", values)
                self.assertIsNone(re.search(r"\$[a-z_]+", text), (kind, who))
        self.assertIn("discarded", fill_template(TEMPLATE_DIR / "phase_engine_overseer.md", values))

    def test_course_example_parses(self) -> None:
        run = tomllib.loads((TEMPLATE_DIR / "course.example.toml").read_text())
        self.assertEqual([p["kind"] for p in run["phases"]], ["match", "engine", "match"])

    def test_phase_context(self) -> None:
        phases = [{"name": "A", "kind": "match"}, {"name": "B", "kind": "engine"}, {"name": "C", "kind": "match"}]
        self.assertEqual(_phase_context(0, phases), "This is the first phase.")
        self.assertIn("discarded", _phase_context(2, phases))
        self.assertNotIn("discarded", _phase_context(1, phases))


class FreezeTests(unittest.TestCase):
    def test_engine_phase_edits_are_discarded(self) -> None:
        with tempfile.TemporaryDirectory() as t:
            ws, snap = Path(t) / "ws", Path(t) / "snap"
            f = ws / "games" / "g01" / "funcs" / "fn_1.c"
            f.parent.mkdir(parents=True)
            (ws / "games" / "g01" / ".kintoun" / "cache").mkdir(parents=True)
            f.write_text("pass one")
            _snapshot(ws, ["g01"], snap)
            f.write_text("engine phase edit")
            (ws / "games" / "g01" / "funcs" / "fn_new.c").write_text("x")
            _restore(ws, ["g01"], snap)
            self.assertEqual(f.read_text(), "pass one")
            self.assertFalse((ws / "games" / "g01" / "funcs" / "fn_new.c").exists())


if __name__ == "__main__":
    unittest.main()
