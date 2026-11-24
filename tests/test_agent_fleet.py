"""Comprehensive self-contained tests for Kintoun's open-source governor, candidates, inspect,
closer, multi-agent chess-clock queue, single/dual/code-only overseer, and lab modules."""
from __future__ import annotations

import json
from pathlib import Path
import struct
import tempfile
import unittest

from kintoun.arch.ppc_disasm import disasm_ppc_word
from kintoun.candidates import CandidateStore
from kintoun.cli import main as cli_main
from kintoun.closer import classify_mismatch, close_near_miss
from kintoun.compiler import CompileResult
from kintoun.config import KintounConfig
from kintoun.governor import AutoTuner, CompileDeduper, CompileGovernor
from kintoun.inspect_fn import build_context_pack, check_function, score_difficulty
from kintoun.lab import learn_priors
from kintoun.overseer import BrainEndpoint, Overseer, OverseerSettings
from kintoun.queue import WorkQueue
from kintoun.search.runner import run_search
from kintoun.targets import TargetContext, TargetFunction
from tests.test_kintoun import _MockCompiler, _build_ppc_elf32


class AgentFleetTests(unittest.TestCase):
    def _sample_ppc_target(self) -> tuple[TargetContext, TargetFunction, _MockCompiler]:
        # Target: cmplwi r3, 10 (0x2803000A); blr (0x4E800020)
        # Wrong:  cmpwi  r3, 10 (0x2C03000A); blr (0x4E800020)
        target_bytes = struct.pack(">II", 0x2803000A, 0x4E800020)
        wrong_bytes = struct.pack(">II", 0x2C03000A, 0x4E800020)
        ctx = TargetContext(
            arch="ppc_elf",
            funcs={"TestFunc": (0x80001000, 8)},
            by_addr={0x80001000: "TestFunc"},
            external={"TestFunc": 0x80001000},
            _regions=[(0, 0x80001000, 8, True)],
            _image=target_bytes,
        )
        tf = TargetFunction("TestFunc", 0x80001000, 8, target_bytes)
        return ctx, tf, _MockCompiler(target_bytes, wrong_bytes)

    def test_ppc_stdlib_disassembler(self) -> None:
        self.assertEqual(disasm_ppc_word(0x9421FFE0)[0], "stwu")
        self.assertEqual(disasm_ppc_word(0x7C0802A6), ("mflr", "r0"))
        self.assertEqual(disasm_ppc_word(0x2C03000A), ("cmpwi", "r3, 0xa"))
        self.assertEqual(disasm_ppc_word(0x4E800020), ("blr", ""))
        self.assertEqual(disasm_ppc_word(0x4E800420), ("bctr", ""))

    def test_governor_tiers_autotuner_and_governed_search(self) -> None:
        ctx, tf, compiler = self._sample_ppc_target()
        with tempfile.TemporaryDirectory() as tmp:
            cdir = Path(tmp) / "cache"
            gov = CompileGovernor(cdir, caller_id="test-agent")
            st = gov.status()
            self.assertGreaterEqual(st["total_slots"], 2)
            self.assertIn(st["autotune"]["level"], (0, 1, 2, 3))

            with gov.acquire(tier="interactive", timeout_s=2.0) as ok_int:
                self.assertTrue(ok_int)
                with gov.acquire(tier="search", timeout_s=2.0) as ok_srch:
                    self.assertTrue(ok_srch)

            dedup = CompileDeduper(cdir)
            with dedup.lock_key("abc123"):
                pass

            res = run_search(
                source="s32 TestFunc(s32 a) {\n    s32 x;\n    x = a;\n    return x;\n}\n",
                target_fn=tf,
                ctx=ctx,
                compiler=compiler,
                budget_s=5.0,
                max_candidates=40,
                workers=2,
                cache_dir=cdir,
                governed=True,
            )
            self.assertTrue(res["verified"])

    def test_candidate_store_revise_batch_and_negative_cache(self) -> None:
        ctx, tf, compiler = self._sample_ppc_target()
        with tempfile.TemporaryDirectory() as tmp:
            store = CandidateStore(Path(tmp) / "cache")

            # Deterministic compile error is cached across calls
            err1 = store.score_one("SYNTAX_ERROR\n", tf, ctx, compiler)
            self.assertEqual(err1["status"], "compile_error")
            self.assertFalse(err1["cache_hit"])
            err2 = store.score_one("SYNTAX_ERROR\n", tf, ctx, compiler)
            self.assertEqual(err2["status"], "compile_error")
            self.assertTrue(err2["cache_hit"])

            # Surgical `revise` from `s32 x` -> `u32 x` reaches VERIFIED with strict deltas
            c1 = store.score_one("s32 TestFunc(s32 a) {\n    s32 x = a;\n    return x;\n}\n", tf, ctx, compiler)
            self.assertFalse(c1["verified"])
            c2 = store.revise(
                c1["candidate_id"],
                [{"old": "s32 x = a;", "new": "u32 x = a;"}],
                tf,
                ctx,
                compiler,
                include_code=True,
            )
            self.assertTrue(c2["verified"])
            self.assertTrue(c2["delta"]["improved"])
            self.assertIn("u32 x = a;", c2["code"])

            # Batch scoring ranks exact match first
            batch = store.score_batch(
                [
                    "s32 TestFunc(s32 a) {\n    s32 x = a;\n    return x;\n}\n",
                    "s32 TestFunc(s32 a) {\n    u32 x = a;\n    return x;\n}\n",
                ],
                tf,
                ctx,
                compiler,
            )
            self.assertTrue(batch["verified"])
            self.assertTrue(batch["best"]["verified"])

    def test_multiarch_check_difficulty_and_context_pack(self) -> None:
        # 1. PPC plain-C vs paired-single blocker
        ctx_ppc, tf_ppc, _ = self._sample_ppc_target()
        chk_ok = check_function(tf_ppc, ctx_ppc)
        self.assertTrue(chk_ok["plain_c"])

        ps_fn = TargetFunction("VecPs", 0x80002000, 8, struct.pack(">II", (4 << 26) | 0x20, 0x4E800020))
        chk_ps = check_function(ps_fn, ctx_ppc)
        self.assertFalse(chk_ps["plain_c"])
        self.assertEqual(chk_ps["verdict"], "not-plain-c")

        # 2. MIPS COP0 blocker vs plain-C
        ctx_mips = TargetContext(arch="mips_elf", endian="little")
        mips_ok = TargetFunction("MipsAdd", 0x00100000, 8, struct.pack("<II", 0x03E00008, 0x00851021))
        mips_cop0 = TargetFunction("MipsCop0", 0x00100010, 8, struct.pack("<II", (16 << 26), 0x03E00008))
        self.assertTrue(check_function(mips_ok, ctx_mips)["plain_c"])
        self.assertFalse(check_function(mips_cop0, ctx_mips)["plain_c"])

        # 3. ARM Thumb SWI blocker vs plain-C
        ctx_arm = TargetContext(arch="arm_elf", thumb=True)
        arm_ok = TargetFunction("ThumbLeaf", 0x08000100, 4, struct.pack("<HH", 0x2001, 0x4770), is_thumb=True)
        arm_swi = TargetFunction("ThumbSwi", 0x08000110, 4, struct.pack("<HH", 0xDF05, 0x4770), is_thumb=True)
        self.assertTrue(check_function(arm_ok, ctx_arm)["plain_c"])
        self.assertFalse(check_function(arm_swi, ctx_arm)["plain_c"])

        diff = score_difficulty(tf_ppc, ctx_ppc)
        self.assertIn(diff["tier"], ("easy", "medium", "hard", "brutal"))
        pack = build_context_pack(tf_ppc, ctx_ppc)
        self.assertIn("cmp", pack["disassembly"])

    def test_zero_llm_near_miss_classifier_and_closer(self) -> None:
        ctx, tf, compiler = self._sample_ppc_target()
        fake_res = {
            "status": "mismatch",
            "different_bytes": 4,
            "search": {
                "aligned_pct": 92.0,
                "hints": ["compare signedness (`cmpwi` vs `cmplwi`)"],
                "diff": "- cmpwi r3, 10\n+ cmplwi r3, 10",
            },
            "repairs": [],
        }
        cls_info = classify_mismatch(fake_res, arch="ppc_elf")
        self.assertEqual(cls_info["primary_class"], "missing_cast")

        with tempfile.TemporaryDirectory() as tmp:
            closed = close_near_miss(
                "s32 TestFunc(s32 a) {\n    s32 x;\n    x = a;\n    return x;\n}\n",
                tf,
                ctx,
                compiler,
                budget_s=5.0,
                max_candidates=40,
                cache_dir=Path(tmp) / "cache",
            )
            self.assertTrue(closed["verified"])

    def test_queue_chess_clock_quarantine_and_submit(self) -> None:
        ctx, tf, compiler = self._sample_ppc_target()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            wq = WorkQueue(root / ".kintoun", default_limit_s=300.0, max_claims_per_agent=2, quarantine_after_timeouts=2)
            sync = wq.sync_from_context(ctx)
            self.assertEqual(sync["added"], 1)

            c1 = wq.claim_next("agent-a", now=1000.0)
            self.assertTrue(c1["claimed"])
            self.assertEqual(c1["name"], "TestFunc")

            # Early give-up before clock expiry is REFUSED for non-structural reasons!
            early = wq.fail_claim("agent-a", "TestFunc", "stuck-plateau", now=1050.0)
            self.assertFalse(early["ok"])
            self.assertTrue(early.get("refused"))

            # Simulate 2 clock expiries -> quarantined, then unquarantine
            wq.reap_expired(now=1400.0)
            wq.claim_next("agent-a", now=1401.0)
            wq.reap_expired(now=1800.0)
            self.assertEqual(wq.status()["counts"]["quarantined"], 1)
            self.assertEqual(wq.unquarantine(), 1)

            # Re-claim and submit a verified match (and verify inline asm is rejected)
            wq.claim_next("agent-a", now=2000.0)
            bad = wq.submit_match(
                "agent-a",
                "TestFunc",
                'void TestFunc(void) { __asm__("nop"); }\n',
                ctx,
                compiler,
                project_root=root,
            )
            self.assertFalse(bad["ok"])

            good = wq.submit_match(
                "agent-a",
                "TestFunc",
                "s32 TestFunc(s32 a) {\n    u32 x = a;\n    return x;\n}\n",
                ctx,
                compiler,
                project_root=root,
                fix_category="local_type",
                engine_note="Flipped local x from s32 to u32 so comparison emits cmplwi.",
            )
            self.assertTrue(good["ok"])
            self.assertEqual(wq.status()["counts"]["done"], 1)
            priors = learn_priors(root / ".kintoun" / "research" / "notes.jsonl")
            self.assertIn("local_type", priors)

    def test_overseer_none_single_and_dual_brain_modes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cfg = KintounConfig(root=root)

            # 1. Code-only (`none`) mode runs cleanly with zero API keys
            sup_none = Overseer(cfg, OverseerSettings(brain_mode="none", auto_close_near_misses=False))
            with sup_none.queue._connect() as conn:
                conn.execute(
                    "INSERT INTO queue (addr, name, size_bytes, status) VALUES ('0x80001000', 'FnA', 16, 'quarantined')"
                )
            cyc0 = sup_none.run_cycle()
            self.assertFalse(cyc0["brain_woke"])

            # 2. Single-brain (`single`) mode: one API handles triage, rule check, and main action
            calls: list[str] = []

            def fake_single_llm(ep: BrainEndpoint, sys_p: str, payload: str, *, max_tokens: int = 600, timeout_s: float = 30.0):
                calls.append(f"{ep.provider}:{ep.model}:{max_tokens}")
                if "triage gate" in sys_p:
                    return {"wake": True, "why": "quarantined function with 0 pending"}, 0.001
                if "STANDING RULES" in sys_p:
                    return {"ok": True, "why": "pending is 0 so unquarantine is allowed"}, 0.001
                return {"summary": "unquarantine FnA", "actions": [{"tool": "unquarantine", "limit": 5}]}, 0.002

            st_single = OverseerSettings(
                brain_mode="single",
                auto_close_near_misses=False,
                daily_budget_usd=1.0,
                main_brain=BrainEndpoint(provider="openai-compatible", model="single-model", api_key_env=""),
            )
            sup_single = Overseer(cfg, st_single)
            sup_single.router._caller = fake_single_llm
            # Re-park FnA so pending=0, quarantined=1
            with sup_single.queue._connect() as conn:
                conn.execute("DELETE FROM queue")
                conn.execute(
                    "INSERT INTO queue (addr, name, size_bytes, status) VALUES ('0x80001000', 'FnA', 16, 'quarantined')"
                )
            cyc1 = sup_single.run_cycle()
            self.assertTrue(cyc1["brain_woke"])
            self.assertEqual(cyc1["actions"][0]["released"], 1)
            self.assertTrue(all("single-model" in c for c in calls))

            # Second identical cycle hits state-fingerprint skip ($0, zero new LLM calls!)
            before_n = len(calls)
            cyc1_repeat = sup_single.run_cycle()
            self.assertFalse(cyc1_repeat["brain_woke"])
            self.assertEqual(len(calls), before_n)

            # External state change wakes single-brain again
            with sup_single.queue._connect() as conn:
                conn.execute(
                    "INSERT INTO queue (addr, name, size_bytes, status) VALUES ('0x80001010', 'FnB', 16, 'quarantined')"
                )
            cyc1_changed = sup_single.run_cycle()
            self.assertTrue(cyc1_changed["brain_woke"])
            self.assertGreater(len(calls), before_n)

            # 3. Dual-brain (`dual`) mode: fast_brain handles triage/checks, main_brain handles planning
            dual_models: list[str] = []

            def fake_dual_llm(ep: BrainEndpoint, sys_p: str, payload: str, *, max_tokens: int = 600, timeout_s: float = 30.0):
                dual_models.append(ep.model)
                if "triage gate" in sys_p:
                    return {"wake": True, "why": "adjust claim limit"}, 0.0005
                if "STANDING RULES" in sys_p:
                    return {"ok": True, "why": "allowed"}, 0.0005
                return {
                    "summary": "pin agent-x claim limit",
                    "actions": [{"tool": "set_claim_limit", "agent_id": "agent-x", "max_claims": 3, "note": "test"}],
                }, 0.003

            st_dual = OverseerSettings(
                brain_mode="dual",
                auto_close_near_misses=False,
                main_brain=BrainEndpoint(provider="openai-compatible", model="deep-main", api_key_env=""),
                fast_brain=BrainEndpoint(provider="openai-compatible", model="cheap-fast", api_key_env=""),
            )
            sup_dual = Overseer(cfg, st_dual)
            sup_dual.router._caller = fake_dual_llm
            with sup_dual.queue._connect() as conn:
                conn.execute("UPDATE queue SET status = 'quarantined'")
            cyc2 = sup_dual.run_cycle()
            self.assertTrue(cyc2["brain_woke"])
            self.assertIn("cheap-fast", dual_models)
            self.assertIn("deep-main", dual_models)

            # Repeat dual cycle with no external change also skips ($0)
            dual_before = len(dual_models)
            cyc2_repeat = sup_dual.run_cycle()
            self.assertFalse(cyc2_repeat["brain_woke"])
            self.assertEqual(len(dual_models), dual_before)

    def test_cli_check_context_overseer_and_skills_present(self) -> None:
        repo_root = Path(__file__).resolve().parent.parent
        self.assertTrue((repo_root / "skills" / "CLI-OVERSEER" / "SKILL.md").is_file())
        self.assertTrue((repo_root / "skills" / "CLI-OVERSEER" / "references" / "subagent-briefs.md").is_file())
        self.assertTrue((repo_root / "skills" / "kintoun-match" / "SKILL.md").is_file())

        target_obj = _build_ppc_elf32("CliCheckFn", struct.pack(">II", 0x38600001, 0x4E800020))
        with tempfile.TemporaryDirectory() as tmp:
            obj_p = Path(tmp) / "fn.o"
            obj_p.write_bytes(target_obj)
            self.assertEqual(cli_main(["check", "--target", str(obj_p), "--json"]), 0)
            self.assertEqual(cli_main(["context", "--target", str(obj_p), "--json"]), 0)
            self.assertEqual(cli_main(["warm-wine", "--status"]), 0)
            self.assertEqual(cli_main(["overseer", "status", "--brain", "none"]), 0)


if __name__ == "__main__":
    unittest.main()
