"""End-to-end tests for Kintoun 0.7.0 Self-Learning Engine Lab & ENGINE-BUILDER skill:
  1. `EngineLab.init_lab`, shared `findings` board, and `inflight` duplicate-work lock
  2. Stratified `make_dev_set` + permanent `seen_by_builders` tainting so unseen `gate` never draws dev rows
  3. Real side-tree mutation commit (`b1`) + dead-weight commit (`b2`) -> 3-way stacked `combined` branch
  4. Per-commit git worktree ablation auto-reverting `b2` while keeping `b1`
  5. Strict dual-metric blind unseen gate (`% close to matched` AND `exact matches` up, zero regressions)
  6. Atomic backup (`PROMOTION_MANIFEST.json`), `live/` promotion, active CLI overlay routing, negative gate rejection, & 1-command rollback
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import textwrap
import unittest

from kintoun.cli import main as cli_main
from kintoun.config import load_config
from kintoun.engine_lab import EngineLab, active_overlay_src_dir, tree_digest
from kintoun.targets import load_target_from_config


class V070EngineBuilderTests(unittest.TestCase):
    def _create_mock_project(self, root: Path) -> Path:
        """Create a self-contained PowerPC project with 7 functions (`Dev_01..03` + `Unseen_01..04`)."""
        # Target instruction sequence for all 7 functions: `rlwinm r3, r3, 0, 16, 31; blr` (8 bytes)
        fn_words = struct.pack(">II", 0x5463043E, 0x4E800020)
        names = [f"Dev_{i:02d}" for i in range(1, 4)] + [f"Unseen_{i:02d}" for i in range(1, 5)]

        # Build valid GameCube DOL at `0x80004000` containing all 10 functions (80 bytes `.text`)
        text_blob = fn_words * len(names)
        dol_hdr = bytearray(0x100)
        struct.pack_into(">I", dol_hdr, 0x00, 0x100)            # text[0] file offset
        struct.pack_into(">I", dol_hdr, 0x48, 0x80004000)       # text[0] virtual addr
        struct.pack_into(">I", dol_hdr, 0x90, len(text_blob))   # text[0] size
        dol_path = root / "main.dol"
        dol_path.write_bytes(bytes(dol_hdr) + text_blob)

        sym_lines = [
            f"{name} = .text:0x{0x80004000 + idx * 8:08X}; // type:function size:0x8"
            for idx, name in enumerate(names)
        ]
        (root / "symbols.txt").write_text("\n".join(sym_lines) + "\n", encoding="utf-8")

        # Standalone Python custom compiler simulating a project-specific unsigned-mask idiom (`& 0xFFFFu`):
        # - Baseline seeds emit 3 wrong instructions (33.33% aligned, 0 exact matches)
        # -Project idiom `& 0xFFFFu` emits exact `0x5463043E, 0x4E800020` (100% VERIFIED!)
        mock_cc = root / "mock_cc.py"
        mock_cc.write_text(
            textwrap.dedent(
                """\
                import pathlib, re, struct, sys

                src_p = pathlib.Path(sys.argv[1])
                out_p = pathlib.Path(sys.argv[2])
                txt = src_p.read_text(encoding="utf-8")
                m = re.search(r"\\bs32\\s+([A-Za-z_]\\w*)\\s*\\(", txt)
                fn_name = m.group(1) if m else "UnknownFn"

                if "& 0xFFFFu" in txt:
                    code_bytes = struct.pack(">II", 0x5463043E, 0x4E800020)
                else:
                    code_bytes = struct.pack(">III", 0x38630007, 0x38840009, 0x4E800020)

                shstrtab = b"\\x00.shstrtab\\x00.text\\x00.symtab\\x00.strtab\\x00"
                strtab = b"\\x00" + fn_name.encode("utf-8") + b"\\x00"
                symtab = struct.pack(">IIIBBH", 0, 0, 0, 0, 0, 0) + struct.pack(">IIIBBH", 1, 0, len(code_bytes), 0x12, 0, 2)
                off_shstr = 52
                off_text = off_shstr + len(shstrtab)
                off_sym = off_text + len(code_bytes)
                off_str = off_sym + len(symtab)
                shoff = off_str + len(strtab)
                ehdr = struct.pack(
                    ">16sHHIIIIIHHHHHH",
                    b"\\x7fELF\\x01\\x02\\x01" + b"\\x00" * 9,
                    1, 20, 1, 0, 0, shoff, 0, 52, 0, 0, 40, 5, 1
                )
                def sh(n, t, f, o, s, lk=0, inf=0, al=1, es=0):
                    return struct.pack(">10I", n, t, f, 0, o, s, lk, inf, al, es)
                shdrs = b"".join([
                    sh(0, 0, 0, 0, 0),
                    sh(shstrtab.index(b".shstrtab"), 3, 0, off_shstr, len(shstrtab)),
                    sh(shstrtab.index(b".text"), 1, 6, off_text, len(code_bytes), al=4),
                    sh(shstrtab.index(b".symtab"), 2, 0, off_sym, len(symtab), lk=4, inf=1, al=4, es=16),
                    sh(shstrtab.index(b".strtab"), 3, 0, off_str, len(strtab)),
                ])
                out_p.write_bytes(ehdr + shstrtab + code_bytes + symtab + strtab + shdrs)
                """
            ),
            encoding="utf-8",
        )

        toml_p = root / "kintoun.toml"
        toml_p.write_text(
            textwrap.dedent(
                f"""\
                [project]
                name = "self-learning-demo"

                [compiler]
                preset = "custom"
                command = [{json.dumps(sys.executable)}, {json.dumps(str(mock_cc))}, "{{in}}", "{{out}}"]
                flags = ["-O2"]

                [target]
                arch = "ppc_elf"
                dol = "main.dol"
                symbols = "symbols.txt"
                """
            ),
            encoding="utf-8",
        )
        return toml_p

    def test_skill_files_present_and_cli_engine_commands(self) -> None:
        repo_root = Path(__file__).resolve().parent.parent
        self.assertTrue((repo_root / "skills" / "ENGINE-BUILDER" / "SKILL.md").is_file())
        self.assertTrue((repo_root / "skills" / "ENGINE-BUILDER" / "references" / "builder-briefs.md").is_file())

    def test_end_to_end_side_tree_ablation_blind_unseen_gate_overlay_and_rollback(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            toml_p = self._create_mock_project(root)
            cfg = load_config(toml_p)
            ctx = load_target_from_config(cfg)
            lab = EngineLab(cfg)

            # 1. Initialize lab with 3 builder side trees
            init_res = lab.init_lab(builders=3)
            self.assertTrue(init_res["ok"])
            self.assertEqual(init_res["builders"], ["b1", "b2", "b3"])
            orig_live_hash = tree_digest(lab.live_dir / "src")

            # 2. Shared findings board & in-flight duplicate-work lock
            s1 = lab.findings_start("b1", "u16-mask-idiom", what="emit & 0xFFFFu mask on accumulator")
            self.assertTrue(s1["ok"])
            s_dup = lab.findings_start("b2", "u16_mask_idiom", what="duplicate attempt")
            self.assertFalse(s_dup["ok"])
            self.assertTrue(s_dup.get("refused"))
            s2 = lab.findings_start("b2", "inert-comment", what="harmless comment tweak")
            self.assertTrue(s2["ok"])

            # 3. Sample `dev` set of 3 functions -> permanently marks them `seen_by_builders`
            dev_res = lab.make_dev_set(ctx, count=3, seed=42)
            self.assertEqual(dev_res["count"], 3)
            dev_doc = json.loads(Path(dev_res["manifest"]).read_text(encoding="utf-8"))
            dev_names = {r["func"] for r in dev_doc["functions"]}
            self.assertEqual(len(dev_names), 3)
            self.assertTrue(dev_names.issubset(set(lab.seen_ledger()["seen_by_builders"])))

            # 4. Builder `b1` adds a real-C mutation in its isolated side tree (`builders/b1/src/kintoun/...`)
            b1_bm = lab.builders_dir / "b1" / "src" / "kintoun" / "search" / "base_mutations.py"
            bm_txt = b1_bm.read_text(encoding="utf-8")
            custom_family = (
                "\n\ndef m_project_u16_mask(t):\n"
                "    if 'acc = a0;' in t and '& 0xFFFFu' not in t:\n"
                "        yield 'project_u16_mask', t.replace('acc = a0;', 'acc = (s32)((u32)a0 & 0xFFFFu);', 1)\n"
            )
            bm_txt = bm_txt.replace("FAMILIES = [", custom_family + "\nFAMILIES = [\n    m_project_u16_mask,")
            b1_bm.write_text(bm_txt, encoding="utf-8")

            c1 = lab.commit_builder("b1", "add project_u16_mask mutation family")
            self.assertTrue(c1["ok"])
            lab.findings_log("b1", "u16-mask-idiom", dev_summary="33% -> 100%", verdict="committed", lesson="mask needed")
            lab.findings_done("b1")

            # 5. Builder `b2` syncs to `combined` and commits an inert change on a separate file (to test ablation!)
            self.assertTrue(lab.sync_builder("b2")["ok"])
            b2_const = lab.builders_dir / "b2" / "src" / "kintoun" / "constants.py"
            b2_const.write_text(b2_const.read_text(encoding="utf-8") + "\n# inert builder-2 note\n", encoding="utf-8")
            c2 = lab.commit_builder("b2", "inert comment that contributes 0 matches")
            self.assertTrue(c2["ok"])
            lab.findings_done("b2")
            self.assertEqual(len(lab.commits_since_live()), 2)

            # 6. Run Blind Unseen Promotion Gate (`ablate=True`, `promote=True`)
            gate = lab.run_unseen_gate(
                candidate_arm="combined",
                ctx=ctx,
                count=4,
                budget_s=5.0,
                max_candidates=15,
                workers=1,
                min_functions=4,
                ablate=True,
                promote=True,
            )
            self.assertTrue(gate["win"], msg=json.dumps(gate, indent=2))
            self.assertTrue(gate["promoted"])

            # Verify 0% overlap between dev functions and unseen gate functions:
            # 3 dev functions + 4 remaining unseen functions = all 7 functions accounted for with zero overlap!
            ledger_after = lab.seen_ledger()
            gate_names = {x for x in ledger_after["seen_in_gates"] if not x.startswith("0x")}
            self.assertEqual(len(gate_names), 4)
            self.assertTrue(dev_names.isdisjoint(gate_names))

            # Verify ablation kept `b1` (+4 exact matches) and auto-reverted `b2` (0 contribution)!
            actions = {a["subject"]: a["action"] for a in gate["ablations"]}
            self.assertTrue(any("b1" in k and v == "kept" for k, v in actions.items()))
            self.assertTrue(any("b2" in k and v.startswith("reverted") for k, v in actions.items()))

            # Verify dual-metric improvement (`live` 0/4 exact -> `candidate` 4/4 exact, 33.33% -> 100.0% aligned)
            rnd = gate["rounds"][0]
            self.assertEqual(rnd["live"]["verified"], 0)
            self.assertEqual(rnd["candidate"]["verified"], 4)
            self.assertGreater(rnd["candidate"]["mean_aligned_pct"], rnd["live"]["mean_aligned_pct"])

            # 7. Confirm project-local overlay is active and CLI `kintoun permute` routes through promoted `live/`!
            self.assertIsNotNone(active_overlay_src_dir(root))
            cand_c = root / "try_unseen.c"
            cand_c.write_text("typedef int s32;\ntypedef unsigned int u32;\ns32 Unseen_01(s32 a0) {\n    s32 acc;\n    acc = a0;\n    return acc;\n}\n", encoding="utf-8")
            repo_src = str(Path(__file__).resolve().parent.parent / "src")
            cli_proc = subprocess.run(
                [sys.executable, "-m", "kintoun", "-c", str(toml_p), "permute", str(cand_c), "--func", "Unseen_01", "--max-candidates", "15", "--json"],
                cwd=str(root),
                env={**os.environ, "PYTHONPATH": repo_src},
                capture_output=True,
                text=True,
                timeout=20.0,
            )
            self.assertEqual(cli_proc.returncode, 0, msg=cli_proc.stderr + cli_proc.stdout)
            perm_out = json.loads(cli_proc.stdout)
            self.assertTrue(perm_out["verified"])
            self.assertIn("& 0xFFFFu", perm_out["best"]["code"])

            # 8. Negative Gate Check: a candidate (`b3`) that does NOT beat the newly promoted `live` is REJECTED!
            self.assertTrue(lab.sync_builder("b3", force=True)["ok"])
            no_win_gate = lab.run_unseen_gate(
                candidate_arm="b3",
                ctx=ctx,
                count=4,
                budget_s=5.0,
                max_candidates=6,
                min_functions=4,
                ablate=False,
                promote=True,
            )
            self.assertFalse(no_win_gate["win"])
            self.assertFalse(no_win_gate["promoted"])

            # 9. One-command `rollback` restores the exact pre-promotion `live/` bytes!
            self.assertEqual(cli_main(["-c", str(toml_p), "engine", "rollback"]), 0)
            self.assertEqual(tree_digest(lab.live_dir / "src"), orig_live_hash)


if __name__ == "__main__":
    unittest.main()
