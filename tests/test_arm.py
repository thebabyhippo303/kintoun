"""Comprehensive unit and real-object fixture tests for dedicated ARM / Thumb support."""
from __future__ import annotations

from pathlib import Path
import struct
import tempfile
import unittest

from kintoun.arch.arm_disasm import disasm_a32, disasm_thumb16, disasm_thumb32
from kintoun.arch.arm_elf import (
    ArmObject,
    PreparedArmReloc,
    compare_arm_bytes,
    relocate_arm,
)
from kintoun.cli import main as cli_main
from kintoun.compiler import CompileResult
from kintoun.config import load_config
from kintoun.search import arm_guidance, arm_permuter, arm_repairs, arm_score, arm_seeds, base_mutations
from kintoun.search.runner import run_search
from kintoun.targets import load_target_from_object
from kintoun.verify import verify_source

FIXTURES = Path(__file__).resolve().parent / "fixtures"
ARM_SUITES = ("a32", "thumb", "thumb2", "agbcc", "mwccarm")


class _FixedArmCompiler:
    compiler_id = "fixture-arm"
    flags = ("-O2",)

    def __init__(self, rules: list[tuple[str, bytes]], default_bytes: bytes) -> None:
        self.rules = rules
        self.default_bytes = default_bytes

    def compile_c(self, src: Path, out_obj: Path) -> CompileResult:
        text = src.read_text(encoding="utf-8")
        for needle, blob in self.rules:
            if needle in text:
                out_obj.write_bytes(blob)
                return CompileResult(0, "", "", out_obj)
        out_obj.write_bytes(self.default_bytes)
        return CompileResult(0, "", "", out_obj)


class ArmTests(unittest.TestCase):
    def test_real_arm_fixtures_match_mismatch_literal_pools_and_relocations(self) -> None:
        target_src = (FIXTURES / "target.c").read_text(encoding="utf-8")
        mismatch_src = (FIXTURES / "mismatch.c").read_text(encoding="utf-8")
        wrong_callee_src = (FIXTURES / "wrong_callee.c").read_text(encoding="utf-8")

        for suite in ARM_SUITES:
            with self.subTest(suite=suite):
                fdir = FIXTURES / "arm" / suite
                target_o = fdir / "target.o"
                shifted_o = fdir / "shifted.o"
                mismatch_o = fdir / "mismatch.o"
                wrong_callee_o = fdir / "wrong_callee.o"

                ctx, tf = load_target_from_object(target_o, "compute_reading")
                self.assertEqual(ctx.arch, "arm_elf")
                self.assertEqual(tf.is_thumb, suite != "a32")

                # Verify `$a`/`$t`/`$d` mapping intervals parsed properly
                modes = {m for _, _, m in tf.intervals}
                if suite == "a32":
                    self.assertIn("a", modes)
                else:
                    self.assertIn("t", modes)
                if suite in ("a32", "thumb", "agbcc", "mwccarm"):
                    self.assertIn("d", modes)

                # 1. Exact byte match
                comp_exact = _FixedArmCompiler([], target_o.read_bytes())
                res_exact = verify_source(target_src, tf, ctx, comp_exact)
                self.assertTrue(res_exact["verified"], msg=res_exact)
                self.assertEqual(res_exact["different_bytes"], 0)
                self.assertEqual(res_exact["search"]["normalized_pct"], 100.0)

                # 2. Relocation masking & strict linking on `shifted.o`
                shifted_elf = ArmObject(shifted_o.read_bytes())
                shifted_sym = shifted_elf.function("compute_reading")
                self.assertEqual(len(shifted_elf.defined_functions()), 2)
                if suite != "mwccarm":
                    self.assertGreater(shifted_sym.offset, 0)
                comp_shifted = _FixedArmCompiler([], shifted_o.read_bytes())
                res_shifted = verify_source(target_src, tf, ctx, comp_shifted)
                self.assertTrue(res_shifted["verified"], msg=res_shifted)
                self.assertEqual(res_shifted["different_bytes"], 0)
                self.assertEqual(res_shifted["search"]["normalized_pct"], 100.0)

                # 3. Deliberate mismatch (`cfg->base` vs `cfg->scale`, `99` vs `42`)
                comp_mism = _FixedArmCompiler([], mismatch_o.read_bytes())
                res_mism = verify_source(mismatch_src, tf, ctx, comp_mism)
                # Must be 100% JSON-serializable for `kintoun verify --json`, SQLite cache, and MCP
                self.assertTrue(len(__import__("json").dumps(res_mism)) > 20)
                self.assertFalse(res_mism["verified"])
                self.assertEqual(res_mism["status"], "mismatch")
                self.assertGreater(res_mism["different_bytes"], 0)
                self.assertTrue(res_mism["search"]["hints"])
                self.assertTrue(res_mism["search"]["diff"])
                cats = {r["category"] for r in res_mism["repairs"]}
                self.assertTrue(cats & {"literal", "field_offset"}, msg=res_mism["repairs"])

                # 4. Wrong callee (`ext_other` vs `ext_clamp`): caught strictly after relocation!
                comp_callee = _FixedArmCompiler([], wrong_callee_o.read_bytes())
                res_unres = verify_source(wrong_callee_src, tf, ctx, comp_callee)
                self.assertFalse(res_unres["verified"])
                self.assertEqual(res_unres["status"], "unresolved")

                callee_va = 0x08050000
                ctx.external["ext_other"] = (callee_va | 1) if tf.is_thumb else callee_va
                ctx.by_addr[callee_va] = "ext_other"
                if tf.is_thumb:
                    ctx.thumb_addrs.add(callee_va)
                res_callee = verify_source(wrong_callee_src, tf, ctx, comp_callee)
                self.assertFalse(res_callee["verified"])
                self.assertEqual(res_callee["status"], "mismatch")
                self.assertTrue(
                    any(
                        r["category"] == "callee" and r["ours"] == "ext_other" and r["target"] == "ext_clamp"
                        for r in res_callee["repairs"]
                    ),
                    msg=res_callee["repairs"],
                )

    def test_arm_interworking_movw_movt_and_thumb_relocations(self) -> None:
        # 1. A32 `BL` converted to `BLX` when T=1 on R_ARM_CALL
        raw_a32 = (0xEBFFFFFE).to_bytes(4, "little")
        linked_blx = relocate_arm(
            raw_a32,
            [PreparedArmReloc(0, "CALL", "thumb_fn#0", -8)],
            {"thumb_fn#0": (0x08000102, 1)},
            text_base=0x08000000,
        )
        w = int.from_bytes(linked_blx, "little")
        self.assertEqual(disasm_a32(w, 0x08000000), ("blx", "0x8000102"))

        # 2. Thumb `BL` converted to `BLX` at 2-byte-misaligned P=0x08000002 targeting A32 0x08000100 (T=0)
        raw_thm = b"\x00\x00" + (0xF7FF).to_bytes(2, "little") + (0xFFFE).to_bytes(2, "little")
        linked_thm_blx = relocate_arm(
            raw_thm,
            [PreparedArmReloc(2, "THM_CALL", "arm_fn#0", -4)],
            {"arm_fn#0": (0x08000100, 0)},
            text_base=0x08000000,
        )
        hw1 = int.from_bytes(linked_thm_blx[2:4], "little")
        hw2 = int.from_bytes(linked_thm_blx[4:6], "little")
        self.assertEqual(disasm_thumb32(hw1, hw2, 0x08000002), ("blx", "0x8000100"))

        # 3. Thumb-2 MOVW + MOVT relocation
        movw_t2 = (0xF240).to_bytes(2, "little") + (0x0000).to_bytes(2, "little")
        movt_t2 = (0xF2C0).to_bytes(2, "little") + (0x0000).to_bytes(2, "little")
        linked_mov = relocate_arm(
            movw_t2 + movt_t2,
            [
                PreparedArmReloc(0, "THM_MOVW_ABS_NC", "sym#0", 0),
                PreparedArmReloc(4, "THM_MOVT_ABS", "sym#1", 0),
            ],
            {"sym#0": (0x0201ABCD, 0), "sym#1": (0x0201ABCD, 0)},
            text_base=0x08000000,
        )
        self.assertEqual(
            disasm_thumb32(int.from_bytes(linked_mov[0:2], "little"), int.from_bytes(linked_mov[2:4], "little")),
            ("movw", "r0, #0xabcd"),
        )
        self.assertEqual(
            disasm_thumb32(int.from_bytes(linked_mov[4:6], "little"), int.from_bytes(linked_mov[6:8], "little")),
            ("movt", "r0, #0x201"),
        )

    def test_literal_pool_inference_and_pool_constant_repair(self) -> None:
        # Thumb function without mapping symbols:
        # 0x00: ldr r0, [pc, #4]  (0x4801 -> loads from Align(0x04, 4) + 4 = 0x08)
        # 0x02: bx lr             (0x4770)
        # 0x04: nop pad           (0x0000)
        # 0x06: nop pad           (0x0000)
        # 0x08: .word 0x12345678
        ours_bytes = struct.pack("<HHHHI", 0x4801, 0x4770, 0x0000, 0x0000, 0x12345678)
        targ_bytes = struct.pack("<HHHHI", 0x4801, 0x4770, 0x0000, 0x0000, 0x12345699)

        ours_items = arm_score.tokenize_arm(ours_bytes, intervals=None, default_thumb=True)
        targ_items = arm_score.tokenize_arm(targ_bytes, intervals=None, default_thumb=True)
        self.assertEqual(ours_items[-1].mode, "d")
        self.assertEqual(ours_items[-1].raw, 0x12345678)

        src = "unsigned int get_magic(void) {\n    return 0x12345678u;\n}\n"
        sc = arm_score.score_arm(ours_items, targ_items)
        reps = arm_repairs.hypotheses(ours_items, targ_items, src, 0x08000000, {}, {}, ops=sc.ops)
        self.assertEqual(len(reps), 1)
        self.assertEqual(reps[0]["category"], "literal")
        self.assertEqual(reps[0]["target"], 0x12345699)
        self.assertIn("0x12345699u", reps[0]["suggested_edit"]["new"])

    def test_arm_permuter_seeds_cli_presets_and_end_to_end_search(self) -> None:
        src = "int f(int a, int b) {\n    int x;\n    int y;\n    x = a + 1;\n    y = b + 2;\n    x += 1;\n    return ((u32)(x << 24)) >> 24;\n}\n"
        pvars = list(arm_permuter.variants(src, base_mutations, limit=12))
        self.assertTrue(any(fam == "arm_reg_kw" for fam, _ in pvars))
        svars = list(arm_seeds.arm_seed_variants(src))
        self.assertTrue(any(fam == "arm_shift_cast" for fam, _ in svars))

        # Test CLI init for all new MIPS & ARM presets
        with tempfile.TemporaryDirectory() as tmp:
            for preset in ("ee-gcc", "psp-gcc", "mips-gcc", "agbcc", "arm-none-eabi-gcc", "mwccarm"):
                cfg_p = Path(tmp) / f"{preset}.toml"
                self.assertEqual(cli_main(["init", "--preset", preset, "-o", str(cfg_p)]), 0)
                cfg = load_config(cfg_p)
                self.assertEqual(cfg.compiler.preset, preset)

        # End-to-end search on `agbcc` fixture
        fdir = FIXTURES / "arm" / "agbcc"
        ctx, tf = load_target_from_object(fdir / "target.o", "compute_reading")
        single_mism = (FIXTURES / "mismatch.c").read_text(encoding="utf-8").replace("cfg->base", "cfg->scale")
        comp = _FixedArmCompiler([("42", (fdir / "target.o").read_bytes())], (fdir / "mismatch.o").read_bytes())
        res = run_search(
            source=single_mism,
            target_fn=tf,
            ctx=ctx,
            compiler=comp,
            budget_s=10.0,
            max_candidates=60,
            workers=1,
        )
        self.assertTrue(res["verified"], msg=res)
        self.assertIn("42", res["best"]["code"])

    def test_arm_thumb_width_frame_repairs_and_flat_binary_config(self) -> None:
        from kintoun.config import load_config
        from kintoun.targets import load_target_from_config

        # Thumb-16 `movs r0, #5` (0x2005) vs Thumb-32 `mov.w r0, #5` (0xF04F, 0x0005)
        ours_w = [arm_score.ArmItem(0, 2, "t16", 0x2005), arm_score.ArmItem(2, 2, "t16", 0x4770)]
        targ_w = [arm_score.ArmItem(0, 4, "t32", 0xF04F, 0x0005), arm_score.ArmItem(4, 2, "t16", 0x4770)]
        sc_w = arm_score.score_arm(ours_w, targ_w)
        reps_w = arm_repairs.hypotheses(ours_w, targ_w, "int f(void){return 5;}\n", 0x08000000, {}, {}, ops=sc_w.ops)
        self.assertTrue(any(r["category"] == "thumb_width" for r in reps_w))

        # Thumb `push {r4, lr}` (0xB510) vs `push {r4, r5, lr}` (0xB530) -> `frame` repair
        ours_f = [arm_score.ArmItem(0, 2, "t16", 0xB510), arm_score.ArmItem(2, 2, "t16", 0xBD10)]
        targ_f = [arm_score.ArmItem(0, 2, "t16", 0xB530), arm_score.ArmItem(2, 2, "t16", 0xBD30)]
        sc_f = arm_score.score_arm(ours_f, targ_f)
        reps_f = arm_repairs.hypotheses(ours_f, targ_f, "void g(void){}\n", 0x08000000, {}, {}, ops=sc_f.ops)
        self.assertTrue(any(r["category"] == "frame" for r in reps_f))

        # Test `load_target_from_config` with a GBA flat binary + odd-VA Thumb symbols.txt
        fdir = FIXTURES / "arm" / "agbcc"
        _, ref_tf = load_target_from_object(fdir / "target.o", "compute_reading")
        with tempfile.TemporaryDirectory() as tmp:
            tpath = Path(tmp)
            (tpath / "baserom.gba").write_bytes(b"\x00" * 0x200 + ref_tf.data + b"\x00" * 0x100)
            (tpath / "symbols.txt").write_text(
                f"compute_reading = .text:0x08000201; // type:function size:0x{ref_tf.size:X}\n"
                "ext_clamp = .text:0x08040081; // type:function size:0x8\n",
                encoding="utf-8",
            )
            (tpath / "kintoun.toml").write_text(
                '[project]\nname = "gba-bin-test"\n'
                '[target]\narch = "arm_elf"\nbinary = "baserom.gba"\n'
                'base_addr = "0x08000000"\nsymbols = "symbols.txt"\nthumb = true\n',
                encoding="utf-8",
            )
            cfg = load_config(tpath / "kintoun.toml")
            bctx = load_target_from_config(cfg)
            btf = bctx.resolve_function("0x08000201")
            self.assertEqual(btf.va, 0x08000200)
            self.assertTrue(btf.is_thumb)
            self.assertEqual(btf.data, ref_tf.data)

    def test_real_arm_multiblock_engine_step_across_five_toolchains(self) -> None:
        step_src = (FIXTURES / "engine_step.c").read_text(encoding="utf-8")
        mism_src = (FIXTURES / "engine_step_mismatch.c").read_text(encoding="utf-8")
        for suite in ARM_SUITES:
            with self.subTest(suite=suite):
                fdir = FIXTURES / "arm" / suite
                ctx, tf = load_target_from_object(fdir / "engine_step.o", "step_channel_block")
                self.assertGreaterEqual(tf.size, 64)

                res_ok = verify_source(step_src, tf, ctx, _FixedArmCompiler([], (fdir / "engine_step.o").read_bytes()))
                self.assertTrue(res_ok["verified"], msg=res_ok)

                res_sh = verify_source(step_src, tf, ctx, _FixedArmCompiler([], (fdir / "engine_step_shifted.o").read_bytes()))
                self.assertTrue(res_sh["verified"], msg=res_sh)

                res_mm = verify_source(mism_src, tf, ctx, _FixedArmCompiler([], (fdir / "engine_step_mismatch.o").read_bytes()))
                self.assertFalse(res_mm["verified"])
                self.assertEqual(res_mm["status"], "mismatch")
                self.assertGreater(res_mm["different_bytes"], 0)

    def test_arm_pool_rebase_widen_param_pool_order_and_dma_flush(self) -> None:
        from kintoun.arch.arm_elf import _probe_target_thumb
        from kintoun.search import arm_mutations

        # 1. `arm_raw_pool_rebase` (struct base + indexed ROM LUT) & `m_arm_widen_thumb_narrow`
        raw_gba = (
            "M2C_UNK fn_08047A58(u16);\n"
            "void fn_080014A0(u16 arg0) {\n"
            "    if (*(u8 *)0x030018C0 == 0) {\n"
            "        *(u16 *)0x030018E8 = *(u16 *)(0x08700400 + (arg0 * 2));\n"
            "        fn_08047A58(arg0);\n"
            "    }\n"
            "}\n"
        )
        rep = arm_seeds.repair_arm_seed(raw_gba, "fn_080014A0", 0x080014A0)
        pool_items = [
            arm_score.ArmItem(0, 2, "t16", 0xB510),
            arm_score.ArmItem(2, 2, "t16", 0x1C04),
            arm_score.ArmItem(16, 4, "d", 0x03001890),
            arm_score.ArmItem(20, 4, "d", 0x08700400),
        ]
        rebased = arm_seeds.arm_raw_pool_rebase(rep, pool_items)
        self.assertIsNotNone(rebased)
        self.assertIn("lbl_03001890.f_30", rebased)
        self.assertIn("lbl_03001890.f_58", rebased)
        self.assertIn("lbl_08700400[arg0]", rebased)

        ours_narrow = [
            arm_score.ArmItem(0, 2, "t16", 0xB510),
            arm_score.ArmItem(2, 2, "t16", 0x0400),
            arm_score.ArmItem(4, 2, "t16", 0x0C04),
        ]
        widened = list(arm_mutations.m_arm_widen_thumb_narrow(rebased, pool_items, ours_narrow))
        self.assertTrue(any(fam == "arm_widen_param" and "void fn_080014A0(s32 arg0)" in c for fam, c in widened))

        # 2. `m_arm_pool_order` flips independent statements to match target `$d` pool `.word` order
        pool_src = "int f(void) {\n    int a;\n    int b;\n    a = 0x11112222;\n    b = 0x33334444;\n    return a ^ b;\n}\n"
        o_p = [arm_score.ArmItem(8, 4, "d", 0x11112222), arm_score.ArmItem(12, 4, "d", 0x33334444)]
        t_p = [arm_score.ArmItem(8, 4, "d", 0x33334444), arm_score.ArmItem(12, 4, "d", 0x11112222)]
        reordered = list(arm_mutations.m_arm_pool_order(pool_src, t_p, o_p))
        self.assertEqual(len(reordered), 1)
        self.assertLess(reordered[0][1].index("0x33334444"), reordered[0][1].index("0x11112222"))

        # 3. AGB DMA3 pipeline-flush dummy read & stripped-ROM Thumb vs A32 prologue probe
        dma_c = "void d(void) {\n    M2C_FIELD((void *)0x040000D4, volatile s32 *, 8) = 0x84000010;\n}\n"
        dma_items = [arm_score.ArmItem(0, 2, "t16", 0x6093), arm_score.ArmItem(2, 2, "t16", 0x6893)]
        flushed = arm_seeds.arm_dma_flush_reads(dma_c, dma_items)
        self.assertIsNotNone(flushed)
        self.assertIn("(void)M2C_FIELD((void *)0x040000D4, volatile s32 *, 8);", flushed)

        mem = {0x08001000: b"\x10\xb5\x04\x1c", 0x08002000: b"\x10\x40\x2d\xe9"}
        probe_read = lambda a, n: mem[a][:n]
        self.assertEqual(_probe_target_thumb(0x08001000, probe_read, default_thumb_callee=False), 1)
        self.assertEqual(_probe_target_thumb(0x08002000, probe_read, default_thumb_callee=True), 0)

        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(cli_main(["init", "--preset", "armcc", "-o", str(Path(tmp) / "armcc.toml")]), 0)


if __name__ == "__main__":
    unittest.main()
