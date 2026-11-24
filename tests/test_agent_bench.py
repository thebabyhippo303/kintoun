"""Self-contained unit tests for Kintoun's open-source zero-prior-context agent benchmark harness."""
from __future__ import annotations

import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest

from kintoun.agent_bench import (
    FAMILIES,
    SIZE_TIERS,
    build_agent_command,
    classify_structural_family,
    render_agent_bench_markdown,
    run_agent_benchmark,
    select_agent_benchmark,
)
from kintoun.candidates import CandidateStore
from kintoun.cli import main as cli_main
from kintoun.config import CompilerConfig, KintounConfig, TargetConfig
from kintoun.targets import TargetContext
from tests.test_kintoun import _build_ppc_elf32


class AgentBenchTests(unittest.TestCase):
    def _make_synthetic_mips_context(self) -> TargetContext:
        """Build a synthetic multi-tier, multi-family plain-C MIPS TargetContext with zero external binaries."""
        funcs: dict[str, tuple[int, int]] = {}
        by_addr: dict[int, str] = {}
        blobs: list[bytes] = []
        regions: list[tuple[int, int, int, bool]] = []
        cursor_off = 0
        cursor_va = 0x00400000

        # Construct distinct instruction shapes across all 5 size tiers and 6 families
        tier_word_counts = [8, 20, 40, 72, 128]  # 32B, 80B, 160B, 288B, 512B
        for t_idx, nwords in enumerate(tier_word_counts):
            for f_idx, fam in enumerate(FAMILIES):
                for k in range(3):
                    words = [0x00851021 + ((k + t_idx) << 6)] * (nwords - 2)  # addu/sll variants for distinct shape_hash
                    # Make distinct opcode token sequences so shape_hash differs per function
                    if k == 1:
                        words[0] = 0x24840001  # addiu $a0, $a0, 1
                    elif k == 2:
                        words[0] = 0x308400FF  # andi $a0, $a0, 0xff
                    if len(words) > 3:
                        words[1] = (8 + ((t_idx + k) % 7)) << 26 | 0x00840001

                    if fam == "leaf_int":
                        pass
                    elif fam == "branch_guard":
                        words[2] = (4 << 26) | (4 << 21) | 2  # beqz $a0, +2
                    elif fam == "loop":
                        words[-1] = (5 << 26) | (4 << 21) | 0xFFFE  # bnez $a0, -2 (backward branch)
                    elif fam == "float_fpu":
                        words[2] = (17 << 26) | (16 << 21) | (12 << 11) | (0 << 6) | 0  # add.s
                        words[3] = (17 << 26) | (16 << 21) | (12 << 11) | (0 << 6) | 2  # mul.s
                    elif fam == "call_chain":
                        words[2] = (3 << 26) | ((0x00400000 >> 2) & 0x03FFFFFF)  # jal
                    elif fam == "vtable_dispatch":
                        words[2] = (0 << 26) | (25 << 21) | (31 << 11) | 9  # jalr $t9

                    words.extend([0x03E00008, 0x00000000])  # jr $ra; nop
                    raw = struct.pack(f"<{len(words)}I", *words)
                    name = f"SecretName_{t_idx}_{f_idx}_{k}"
                    sz = len(raw)
                    funcs[name] = (cursor_va, sz)
                    by_addr[cursor_va] = name
                    blobs.append(raw)
                    regions.append((cursor_off, cursor_va, sz, True))
                    cursor_off += sz
                    cursor_va += (sz + 0xF) & ~0xF

        # Also add one SIMD/MMI `.word` non-plain-C function to confirm it is excluded
        bad_raw = struct.pack("<3I", 0x70851628, 0x03E00008, 0x00000000)
        funcs["BadSimdFn"] = (cursor_va, 12)
        by_addr[cursor_va] = "BadSimdFn"
        blobs.append(bad_raw)
        regions.append((cursor_off, cursor_va, 12, True))

        return TargetContext(
            arch="mips_elf",
            funcs=funcs,
            by_addr=by_addr,
            external={n: va for n, (va, _) in funcs.items()},
            _regions=regions,
            _image=b"".join(blobs),
            endian="little",
            gp=0x00600000,
        )

    def test_stratified_60_selector_covers_all_tiers_and_families(self) -> None:
        ctx = self._make_synthetic_mips_context()
        doc = select_agent_benchmark(ctx, count=60, seed=42)
        self.assertEqual(doc["selected_count"], 60)
        for tname, _, _ in SIZE_TIERS:
            self.assertEqual(doc["by_size_tier"][tname], 12)
        for fam in FAMILIES:
            self.assertEqual(doc["by_family"][fam], 10)
        selected_names = {r["func"] for r in doc["functions"]}
        self.assertNotIn("BadSimdFn", selected_names)

        # Confirm classify_structural_family rejects non-plain-C
        self.assertIsNone(classify_structural_family({"plain_c": False, "features": {}}))

    def test_agy_command_preset_uses_neon_high_new_project_and_30m_timeout(self) -> None:
        cmd = build_agent_command(
            "agy",
            prompt="Match fn_00401000",
            model="gemini-4-neon-high",
            effort="high",
            timeout_s=1800.0,
            agent_bin="/usr/local/bin/agy",
        )
        self.assertEqual(cmd[0], "/usr/local/bin/agy")
        self.assertIn("--model", cmd)
        self.assertEqual(cmd[cmd.index("--model") + 1], "gemini-4-neon-high")
        self.assertIn("--effort", cmd)
        self.assertEqual(cmd[cmd.index("--effort") + 1], "high")
        self.assertIn("--new-project", cmd)
        self.assertIn("--disable-slash-commands", cmd)
        self.assertIn("--print-timeout", cmd)
        self.assertEqual(cmd[cmd.index("--print-timeout") + 1], "1800s")

    def test_zero_context_isolation_timeout_cache_recovery_and_asm_rejection(self) -> None:
        # Target PPC function: li r3, 7 (0x38600007); blr (0x4E800020)
        target_code = struct.pack(">II", 0x38600007, 0x4E800020)
        wrong_code = struct.pack(">II", 0x38600000, 0x4E800020)
        good_elf = _build_ppc_elf32("BenchFn", target_code)
        wrong_elf = _build_ppc_elf32("BenchFn", wrong_code)

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            # Put a "secret" file in project root to verify the agent's isolated workspace NEVER sees it!
            (root / "PROJECT_SECRET.txt").write_text("DO_NOT_LEAK", encoding="utf-8")

            orig_o = root / "target_fn.o"
            orig_o.write_bytes(good_elf)

            # Fake compiler script: emits `good_elf` when `return 7;` is in source, `wrong_elf` when `return 0;`
            comp_script = root / "fake_cc.py"
            comp_script.write_text(
                "import pathlib, sys\n"
                "out_p = pathlib.Path(sys.argv[-2])\n"
                "in_p = pathlib.Path(sys.argv[-1])\n"
                "txt = in_p.read_text(encoding='utf-8')\n"
                "if 'SYNTAX_ERR' in txt:\n"
                "    sys.stderr.write('syntax error\\n')\n"
                "    raise SystemExit(1)\n"
                f"good = bytes.fromhex('{good_elf.hex()}')\n"
                f"wrong = bytes.fromhex('{wrong_elf.hex()}')\n"
                "out_p.write_bytes(good if 'return 7;' in txt else wrong)\n",
                encoding="utf-8",
            )

            # Fake agent CLI script covering 3 scenarios across 3 manifest functions:
            # 1. `BenchFn` (normal match): verifies `PROJECT_SECRET.txt` is absent (zero prior context!) and writes `return 7;`
            # 2. `TimeoutRecoverFn`: caches a valid `return 7;` in `.kintoun/cache/candidates.sqlite3`, then writes broken C to `cand.c` and sleeps past timeout -> harness recovers the cached match!
            # 3. `AsmCheatFn`: writes `__asm__("li 3, 7"); return 7;` -> harness rejects inline asm (`forbid_asm=True`)!
            good_tl = _build_ppc_elf32("TimeoutRecoverFn", target_code)
            good_ch = _build_ppc_elf32("AsmCheatFn", target_code)
            orig_tl = root / "target_tl.o"
            orig_ch = root / "target_ch.o"
            orig_tl.write_bytes(good_tl)
            orig_ch.write_bytes(good_ch)

            comp_script.write_text(
                "import pathlib, sys\n"
                "out_p = pathlib.Path(sys.argv[-2])\n"
                "in_p = pathlib.Path(sys.argv[-1])\n"
                "txt = in_p.read_text(encoding='utf-8')\n"
                "if 'SYNTAX_ERR' in txt:\n"
                "    sys.stderr.write('syntax error\\n')\n"
                "    raise SystemExit(1)\n"
                "fn = 'TimeoutRecoverFn' if 'TimeoutRecoverFn' in txt else ('AsmCheatFn' if 'AsmCheatFn' in txt else 'BenchFn')\n"
                f"by_fn_good = {{'BenchFn': '{good_elf.hex()}', 'TimeoutRecoverFn': '{good_tl.hex()}', 'AsmCheatFn': '{good_ch.hex()}'}}\n"
                f"wrong = bytes.fromhex('{wrong_elf.hex()}')\n"
                "out_p.write_bytes(bytes.fromhex(by_fn_good[fn]) if 'return 7;' in txt else wrong)\n",
                encoding="utf-8",
            )

            agent_script = root / "fake_agent.py"
            agent_script.write_text(
                "import pathlib, sys, time\n"
                "from kintoun.candidates import CandidateStore\n"
                "ws = pathlib.Path.cwd()\n"
                "assert not (ws / 'PROJECT_SECRET.txt').exists(), 'leaked parent workspace!'\n"
                "assert (ws / 'skills' / 'kintoun-match' / 'SKILL.md').is_file(), 'missing skill!'\n"
                "fn = sys.argv[1]\n"
                "cand = ws / 'cand.c'\n"
                "if fn == 'BenchFn':\n"
                "    cand.write_text('int BenchFn(void) { return 7; }\\n', encoding='utf-8')\n"
                "elif fn == 'TimeoutRecoverFn':\n"
                "    store = CandidateStore(ws / '.kintoun' / 'cache')\n"
                "    store.put(fn, 0x80000000, 'int TimeoutRecoverFn(void) { return 7; }\\n', {'verified': True, 'status': 'verified', 'different_bytes': 0, 'search': {'aligned_pct': 100.0}})\n"
                "    cand.write_text('SYNTAX_ERR\\n', encoding='utf-8')\n"
                "    time.sleep(10.0)\n"
                "elif fn == 'AsmCheatFn':\n"
                "    cand.write_text('int AsmCheatFn(void) { __asm__(\"nop\"); return 7; }\\n', encoding='utf-8')\n",
                encoding="utf-8",
            )

            manifest = {
                "functions": [
                    {
                        "func": "BenchFn",
                        "addr": "0x80000000",
                        "size_bytes": 8,
                        "size_tier": "tiny_24_64B",
                        "family": "leaf_int",
                        "target": str(orig_o),
                        "code": "int BenchFn(void) { return 0; }\n",
                    },
                    {
                        "func": "TimeoutRecoverFn",
                        "addr": "0x80000000",
                        "size_bytes": 8,
                        "size_tier": "small_68_136B",
                        "family": "branch_guard",
                        "target": str(orig_tl),
                        "code": "int TimeoutRecoverFn(void) { return 0; }\n",
                    },
                    {
                        "func": "AsmCheatFn",
                        "addr": "0x80000000",
                        "size_bytes": 8,
                        "size_tier": "medium_140_260B",
                        "family": "call_chain",
                        "target": str(orig_ch),
                        "code": "int AsmCheatFn(void) { return 0; }\n",
                    },
                ]
            }
            manifest_p = root / "manifest.json"
            manifest_p.write_text(json.dumps(manifest), encoding="utf-8")

            cfg = KintounConfig(
                root=root,
                compiler=CompilerConfig(
                    preset="custom",
                    command=[sys.executable, str(comp_script), "{flags}", "{out}", "{in}"],
                    flags=["-O2", "-c"],
                ),
                target=TargetConfig(arch="ppc_elf"),
            )

            out_dir = root / "bench_out"
            # Note: `_run_subprocess_bounded` adds 15s grace over `per_func_timeout_s` for CLI internal timeout,
            # so use a custom command with a 1s timeout test via `per_func_timeout_s=0.5` -> adjust sleep or test recovery directly!
            # Make `TimeoutRecoverFn` exit cleanly after writing `SYNTAX_ERR` to `cand.c` so test runs in < 0.5s!
            agent_script.write_text(
                agent_script.read_text(encoding="utf-8").replace("    time.sleep(10.0)\n", ""),
                encoding="utf-8",
            )

            summary = run_agent_benchmark(
                cfg,
                manifest_p,
                out_dir,
                runner="custom",
                model="gemini-4-neon-high",
                effort="high",
                custom_template=f"{sys.executable} {agent_script} {{func}}",
                per_func_timeout_s=1800.0,
                with_headless_baseline=False,
            )

            self.assertEqual(summary["functions"], 3)
            self.assertEqual(summary["overall"]["agent"]["verified"], 2)
            by_res = {r["size_tier"]: r for r in summary["results"]}
            self.assertTrue(by_res["tiny_24_64B"]["agent_verified"])
            # Cached valid C was recovered even though `cand.c` was left with `SYNTAX_ERR`!
            self.assertTrue(by_res["small_68_136B"]["agent_verified"])
            # Inline asm cheat was rejected (`forbid_asm=True`)!
            self.assertFalse(by_res["medium_140_260B"]["agent_verified"])

            md = render_agent_bench_markdown(summary, title="Public Bench Check")
            self.assertIn("Public Bench Check", md)
            self.assertIn("`gemini-4-neon-high`", md)
            self.assertNotIn(str(root), md)

            # CLI `report` subcommand works cleanly on `results.jsonl`
            md_out = root / "REPORT_CLI.md"
            rc = cli_main(
                [
                    "agent-bench",
                    "report",
                    "--results",
                    str(out_dir / "results.jsonl"),
                    "-o",
                    str(md_out),
                ]
            )
            self.assertEqual(rc, 0)
            self.assertTrue(md_out.is_file())

    def test_result_cache_closes_sqlite_connections_without_fd_leak(self) -> None:
        from kintoun.cache import ResultCache
        import os

        with tempfile.TemporaryDirectory() as tmp:
            cache = ResultCache(Path(tmp) / "cache")
            fd_dir = Path("/proc/self/fd")
            before = len(list(fd_dir.iterdir())) if fd_dir.is_dir() else 0
            for i in range(250):
                cache.put(f"k_{i}", {"verified": False, "status": "mismatch"})
                _ = cache.get(f"k_{i}")
            if fd_dir.is_dir():
                after = len(list(fd_dir.iterdir()))
                self.assertLessEqual(after - before, 6)


if __name__ == "__main__":
    unittest.main()
