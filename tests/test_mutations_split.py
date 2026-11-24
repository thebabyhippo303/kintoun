"""Tests for the readable `mutations.py` module split and baseline inventory preservation."""
from __future__ import annotations

import unittest

from kintoun.config import KintounConfig
from kintoun.search import (
    base_mutations,
    guidance,
    mutations,
    mutations_directed,
    mutations_float,
    mutations_mem,
    mutations_order_reg,
    mutations_order_stmt,
    mutations_recovery,
    mutations_switch,
    permuter,
    repairs,
    runner,
    score,
    seeds,
)


class MutationsSplitAndInventoryTests(unittest.TestCase):
    def test_split_modules_and_reexports_intact(self) -> None:
        self.assertEqual(len(mutations.__all__), 383)
        for name in mutations.__all__:
            self.assertTrue(hasattr(mutations, name), msg=f"Missing re-export: {name}")

        # Verify themed submodules carry docstrings and expected lead symbols
        for mod in (
            mutations_recovery,
            mutations_float,
            mutations_order_reg,
            mutations_order_stmt,
            mutations_mem,
            mutations_switch,
            mutations_directed,
        ):
            self.assertTrue(mod.__doc__ and len(mod.__doc__.strip()) > 15)

        self.assertIs(mutations.m_index_address, mutations_recovery.m_index_address)
        self.assertIs(mutations.m_fma_negate, mutations_float.m_fma_negate)
        self.assertIs(mutations.m_init_order, mutations_order_reg.m_init_order)
        self.assertIs(mutations.m_mixed_order, mutations_order_stmt.m_mixed_order)
        self.assertIs(mutations.m_globalcache, mutations_mem.m_globalcache)
        self.assertIs(mutations.m_case_order, mutations_switch.m_case_order)
        self.assertIs(mutations.directed, mutations_directed.directed)

    def test_baseline_ppc_inventory_defaults_preserved(self) -> None:
        from pathlib import Path

        cfg = KintounConfig(root=Path("."))
        self.assertEqual(cfg.project_name, "decomp-project")
        self.assertEqual(cfg.compiler.preset, "custom")
        self.assertEqual(cfg.compiler.wine, "wine")
        self.assertEqual(cfg.compiler.timeout_s, 30.0)
        self.assertEqual(cfg.target.arch, "ppc_elf")
        self.assertEqual(cfg.target.sda_r13, 0)
        self.assertEqual(cfg.target.sda_r2, 0)
        self.assertEqual(cfg.search.budget_s, 180.0)
        self.assertEqual(cfg.search.max_candidates, 2500)
        self.assertEqual(cfg.search.mode, "standard")
        self.assertEqual(cfg.search.plateau, 0)
        self.assertEqual(cfg.search.workers, 0)
        self.assertEqual(cfg.search.strategies, ["systematic", "register_focus", "random"])
        self.assertEqual(cfg.search.cache_dir, ".kintoun/cache")
        self.assertTrue(cfg.search.forbid_asm)
        self.assertEqual(len(base_mutations.FAMILIES), 30)
        self.assertEqual(
            runner.STRATEGIES,
            ("systematic", "random", "statement", "types", "temps", "control", "regalloc", "register_focus"),
        )
        self.assertTrue(callable(score.score))
        self.assertTrue(callable(repairs.hypotheses))
        self.assertTrue(callable(permuter.variants))
        self.assertTrue(callable(seeds.repair_seed))
        self.assertTrue(callable(guidance.priorities))

    def test_search_modes_duration_parser_and_monotonic_rank_result(self) -> None:
        from kintoun import cli
        from kintoun.config import KintounConfig, parse_duration_s
        from kintoun.search import ppc_seeds
        from pathlib import Path

        self.assertEqual(parse_duration_s("30s"), 30.0)
        self.assertEqual(parse_duration_s("5m"), 300.0)
        self.assertEqual(parse_duration_s("2h"), 7200.0)
        self.assertEqual(parse_duration_s("unlimited"), 86400.0)

        p = cli.build_parser()
        cfg = KintounConfig(root=Path("."))
        a_thorough = p.parse_args(["permute", "foo.c", "--thorough"])
        self.assertEqual(cli._resolve_search_limits(a_thorough, cfg), (600.0, 10000, 0))
        a_custom = p.parse_args(["permute", "foo.c", "--deep", "--time", "45s", "--plateau", "128"])
        self.assertEqual(cli._resolve_search_limits(a_custom, cfg), (45.0, 50000, 128))

        # Monotonic alignment ranking: higher aligned_pct always beats lower aligned_pct even if positional diff_bytes collided
        r_start = {"verified": False, "status": "mismatch", "different_bytes": 70, "instruction_mismatches": 18, "search": {"aligned_pct": 65.0, "total": 40}}
        r_worse = {"verified": False, "status": "mismatch", "different_bytes": 62, "instruction_mismatches": 16, "search": {"aligned_pct": 63.0, "total": 38}}
        self.assertLess(runner.rank_result(r_start), runner.rank_result(r_worse))

        # PowerPC raw DOL address + SDA rebasing
        raw_ppc = "s32 fn_80010000(void *p) {\n    M2C_FIELD(saved_reg_r13, s32 *, -0x7F00) = *(s32 *)0x80241A10;\n    return 0;\n}\n"
        rep = ppc_seeds.repair_ppc_seed(raw_ppc, "fn_80010000", 0x80010000, sda_r13=0x803E8000)
        self.assertIn("lbl_803E0100", rep)
        # lis r3, 0x8024 (0x3C608024); lwz r3, 0x1A10(r3) (0x80631A10)
        reb = ppc_seeds.ppc_raw_addr_rebase(rep, [0x3C608024, 0x80631A10], sda_r13=0x803E8000)
        self.assertIsNotNone(reb)
        self.assertIn("lbl_80241A10", reb or "")


if __name__ == "__main__":
    unittest.main()
