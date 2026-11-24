"""Comprehensive unit and real-object fixture tests for dedicated MIPS support."""
from __future__ import annotations

from pathlib import Path
import struct
import unittest

from kintoun.arch.mips_disasm import disasm_mips_word
from kintoun.arch.mips_elf import (
    MipsObject,
    PreparedMipsReloc,
    compare_mips_bytes,
    gp_references,
    link_mips_function,
    relocate_mips,
)
from kintoun.compiler import CompileResult
from kintoun.search import base_mutations, mips_guidance, mips_permuter, mips_repairs, mips_score, mips_seeds
from kintoun.search.runner import run_search
from kintoun.targets import load_target_from_object
from kintoun.verify import verify_source

FIXTURES = Path(__file__).resolve().parent / "fixtures"
MIPS_SUITES = ("ee_gcc", "psp_gcc", "mips_le", "mips_be")


class _FixedObjCompiler:
    """Compiler stub returning prebuilt real-toolchain `.o` fixture bytes."""

    compiler_id = "fixture-mips"
    flags = ("-O2",)

    def __init__(self, obj_bytes_by_substr: list[tuple[str, bytes]], default_bytes: bytes) -> None:
        self.rules = obj_bytes_by_substr
        self.default_bytes = default_bytes

    def compile_c(self, src: Path, out_obj: Path) -> CompileResult:
        text = src.read_text(encoding="utf-8")
        for needle, blob in self.rules:
            if needle in text:
                out_obj.write_bytes(blob)
                return CompileResult(0, "", "", out_obj)
        out_obj.write_bytes(self.default_bytes)
        return CompileResult(0, "", "", out_obj)


class MipsTests(unittest.TestCase):
    def test_real_mips_fixtures_match_mismatch_and_relocation_masking(self) -> None:
        target_src = (FIXTURES / "target.c").read_text(encoding="utf-8")
        mismatch_src = (FIXTURES / "mismatch.c").read_text(encoding="utf-8")
        wrong_callee_src = (FIXTURES / "wrong_callee.c").read_text(encoding="utf-8")

        for suite in MIPS_SUITES:
            with self.subTest(suite=suite):
                fdir = FIXTURES / "mips" / suite
                target_o = fdir / "target.o"
                shifted_o = fdir / "shifted.o"
                mismatch_o = fdir / "mismatch.o"
                wrong_callee_o = fdir / "wrong_callee.o"

                ctx, tf = load_target_from_object(target_o, "compute_reading")
                self.assertEqual(ctx.arch, "mips_elf")
                expected_endian = "big" if suite == "mips_be" else "little"
                self.assertEqual(ctx.endian, expected_endian)

                # 1. Exact byte match
                comp_exact = _FixedObjCompiler([], target_o.read_bytes())
                res_exact = verify_source(target_src, tf, ctx, comp_exact)
                self.assertTrue(res_exact["verified"], msg=res_exact)
                self.assertEqual(res_exact["different_bytes"], 0)
                self.assertEqual(res_exact["search"]["normalized_pct"], 100.0)

                # 2. Relocation masking & strict linking on `shifted.o` (function at non-zero .text offset)
                shifted_elf = MipsObject(shifted_o.read_bytes())
                shifted_sym = shifted_elf.function("compute_reading")
                self.assertGreater(shifted_sym.value, 0)
                comp_shifted = _FixedObjCompiler([], shifted_o.read_bytes())
                res_shifted = verify_source(target_src, tf, ctx, comp_shifted)
                self.assertTrue(res_shifted["verified"], msg=res_shifted)
                self.assertEqual(res_shifted["different_bytes"], 0)
                self.assertEqual(res_shifted["search"]["normalized_pct"], 100.0)

                # 3. Deliberate mismatch (`cfg->base` vs `cfg->scale`, `99` vs `42`)
                comp_mism = _FixedObjCompiler([], mismatch_o.read_bytes())
                res_mism = verify_source(mismatch_src, tf, ctx, comp_mism)
                self.assertTrue(len(__import__("json").dumps(res_mism)) > 20)
                self.assertFalse(res_mism["verified"])
                self.assertEqual(res_mism["status"], "mismatch")
                self.assertGreater(res_mism["different_bytes"], 0)
                self.assertTrue(res_mism["search"]["hints"])
                self.assertTrue(res_mism["search"]["diff"])
                cats = {r["category"] for r in res_mism["repairs"]}
                self.assertIn("literal", cats)
                self.assertIn("field_offset", cats)
                lit_rep = next(r for r in res_mism["repairs"] if r["category"] == "literal" and r.get("target") == 42)
                self.assertIn("suggested_edit", lit_rep)

                # 4. Wrong callee (`ext_other` vs `ext_clamp`): caught strictly after relocation!
                comp_callee = _FixedObjCompiler([], wrong_callee_o.read_bytes())
                res_unres = verify_source(wrong_callee_src, tf, ctx, comp_callee)
                self.assertFalse(res_unres["verified"])
                self.assertEqual(res_unres["status"], "unresolved")

                # When `ext_other` is mapped at a distinct address, verifier reports `callee` hypothesis
                ctx.external["ext_other"] = 0x00490000
                ctx.by_addr[0x00490000] = "ext_other"
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

    def test_mips_relocations_rel_rela_gp_disp_and_orphaned_lo16(self) -> None:
        # Test _gp_disp HI16 + LO16, GPREL16 (with gp0), R_MIPS_26, PC16, GPREL32, PC32
        # 0x00: lui $gp, 0        (0x3C1C0000)
        # 0x04: addiu $gp, $gp, 0 (0x279C0000)
        # 0x08: lw $v0, 0($gp)    (0x8F820000)
        # 0x0C: jal 0             (0x0C000000)
        # 0x10: beq $v0, $0, 0    (0x10400000)
        # 0x14: nop               (0x00000000)
        words = [0x3C1C0000, 0x279C0000, 0x8F820000, 0x0C000000, 0x10400000, 0x00000000]
        raw_le = b"".join(w.to_bytes(4, "little") for w in words)
        recs = [
            PreparedMipsReloc(0, "HI16", "_gp_disp#0", 0, False, True),
            PreparedMipsReloc(4, "LO16", "_gp_disp#1", 0, False, True),
            PreparedMipsReloc(8, "GPREL16", "sdata_var#2", 0x10, True, False),
            PreparedMipsReloc(12, "26", "callee#3", 0, False, False),
            PreparedMipsReloc(16, "PC16", "label#4", -4, False, False),
        ]
        syms = {
            "sdata_var#2": 0x10004000,
            "callee#3": 0x00402000,
            "label#4": 0x00401020,
        }
        linked = relocate_mips(
            raw_le,
            recs,
            syms,
            text_base=0x00401000,
            endian="little",
            gp=0x10008000,
            gp0=0x00001000,
            use_gp0_for_local=True,
        )
        out_w = mips_score.words_mips(linked, "little")
        # _gp_disp = 0x10008000 - 0x00401000 = 0x0FC07000 => hi=0x0FC0, lo=0x7000
        self.assertEqual(out_w[0], 0x3C1C0FC0)
        self.assertEqual(out_w[1], 0x279C7000)
        # local GPREL16: 0x10004000 + 0x10 + 0x1000 - 0x10008000 = -0x2FF0 => 0xD010
        self.assertEqual(out_w[2] & 0xFFFF, (-0x2FF0) & 0xFFFF)
        # jal 0x00402000 => target >> 2 = 0x00100800
        self.assertEqual(out_w[3], 0x0C100800)
        # PC16 at 0x00401010 -> label 0x00401020 + (-4) - 0x00401010 = +12 bytes => +3 words
        self.assertEqual(out_w[4] & 0xFFFF, 3)

        # Decode gp_references on relocated stream
        refs = gp_references(out_w, {0x10005010: ("g_LocalSdata", 4)}, 0x10008000)
        self.assertEqual(len(refs), 1)
        self.assertEqual(refs[0]["symbol"], "g_LocalSdata")

    def test_delay_slot_alignment_disasm_and_repairs(self) -> None:
        # Target fills return delay slot: `jr $ra; li $v0, 7`
        # Ours leaves delay slot unfilled: `li $v0, 7; jr $ra; nop`
        li_v0_7 = 0x24020007
        jr_ra = 0x03E00008
        nop = 0x00000000
        ours = [li_v0_7, jr_ra, nop]
        target = [jr_ra, li_v0_7]

        self.assertEqual(disasm_mips_word(li_v0_7), ("li", "$v0, 7"))
        self.assertEqual(disasm_mips_word(jr_ra), ("jr", "$ra"))
        self.assertEqual(disasm_mips_word(nop), ("nop", ""))
        # R5900 lq & Allegrex seb/wsbh & COP1 add.s
        self.assertEqual(disasm_mips_word((30 << 26) | (4 << 21) | (2 << 16) | 0x10)[0], "lq")
        self.assertEqual(disasm_mips_word((31 << 26) | (4 << 16) | (2 << 11) | (16 << 6) | 32), ("seb", "$v0, $a0"))
        self.assertEqual(disasm_mips_word((17 << 26) | (16 << 21) | (2 << 16) | (0 << 11) | (4 << 6) | 0), ("add.s", "$f4, $f0, $f2"))

        sc = mips_score.score_mips(ours, target)
        self.assertTrue(sc.delay_swaps)
        self.assertTrue(any("delay-slot" in h for h in sc.hints))
        reps = mips_repairs.hypotheses(ours, target, "int f(void) { return 7; }\n", 0x00400000, {}, {}, ops=sc.ops, delay_swaps=sc.delay_swaps)
        self.assertTrue(any(r["category"] == "delay_slot" for r in reps))

    def test_mips_permuter_seeds_guidance_and_end_to_end_search(self) -> None:
        fdir = FIXTURES / "mips" / "mips_le"
        ctx, tf = load_target_from_object(fdir / "target.o", "compute_reading")
        mismatch_src = (FIXTURES / "mismatch.c").read_text(encoding="utf-8")
        target_bytes = (fdir / "target.o").read_bytes()
        mismatch_bytes = (fdir / "mismatch.o").read_bytes()

        # Mock compiler transitions mismatch -> partial -> exact match when both repairs (`cfg->scale` and `42`) apply
        comp = _FixedObjCompiler(
            [("cfg->scale", target_bytes)],
            mismatch_bytes,
        )
        # Verify permuter & seeds produce valid C candidates
        divmod_src = "int dm(int a, int b) {\n    int q;\n    int r;\n    q = a / b;\n    r = a % b;\n    return q + r;\n}\n"
        pvars = list(mips_permuter.variants(divmod_src, base_mutations, limit=12))
        self.assertTrue(any(fam == "mips_hilo_order" for fam, _ in pvars))
        self.assertIsNotNone(mips_seeds.narrow_shift_casts("int f(int x) { return ((s32)(x << 16)) >> 16; }\n"))

        # End-to-end search repairs field offset (`cfg->base` -> `cfg->scale`) via MIPS guidance!
        single_mism = mismatch_src.replace("99", "42")
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
        self.assertIn("cfg->scale", res["best"]["code"])

    def test_mips_multi_hi16_orphaned_lo16_and_binary_config_target(self) -> None:
        from kintoun.arch.mips_elf import MipsRelocation, MipsSymbol, prepare_section_relocs
        from kintoun.config import load_config
        from kintoun.targets import load_target_from_config
        import tempfile

        # Two HI16s, an intervening GPREL16, then two LO16s (second LO16 is orphaned!)
        # 0x00: lui $v0, 0x0001
        # 0x04: lui $v1, 0x0001
        # 0x08: lw  $a0, 8($gp)
        # 0x0C: lw  $v0, 0x0010($v0)
        # 0x10: lw  $v1, 0x0014($v1)  <-- orphaned LO16 reusing hi=0x0001!
        sec_bytes = b"".join(
            w.to_bytes(4, "little")
            for w in (0x3C020001, 0x3C030001, 0x8F840008, 0x8C420010, 0x8C630014)
        )
        sym_arr = MipsSymbol(2, "g_arr", 0, 0, 0x10, 0, 0)
        sym_gp = MipsSymbol(3, "g_small", 0, 0, 0x10, 0, 0xFF04)
        rels = [
            MipsRelocation(0x00, "HI16", sym_arr, 0, is_rela=False),
            MipsRelocation(0x04, "HI16", sym_arr, 0, is_rela=False),
            MipsRelocation(0x08, "GPREL16", sym_gp, 0, is_rela=False),
            MipsRelocation(0x0C, "LO16", sym_arr, 0, is_rela=False),
            MipsRelocation(0x10, "LO16", sym_arr, 0, is_rela=False),
        ]
        prepared = prepare_section_relocs(sec_bytes, rels, "little")
        self.assertEqual([a for _, a in prepared], [0x00010010, 0x00010010, 8, 0x00010010, 0x00010014])

        # Test `load_target_from_config` with a flat MIPS binary + symbols.txt + gp
        fdir = FIXTURES / "mips" / "ee_gcc"
        _, ref_tf = load_target_from_object(fdir / "target.o", "compute_reading")
        with tempfile.TemporaryDirectory() as tmp:
            tpath = Path(tmp)
            (tpath / "rom.bin").write_bytes(b"\x00" * 0x100 + ref_tf.data + b"\x00" * 0x100)
            (tpath / "symbols.txt").write_text(
                f"compute_reading = .text:0x00400100; // type:function size:0x{ref_tf.size:X}\n"
                "ext_clamp = .text:0x004800C0; // type:function size:0x8\n"
                "g_step = .sdata:0x10008120; // size:0x4\n"
                "g_table = .data:0x00580200; // size:0x40\n",
                encoding="utf-8",
            )
            (tpath / "kintoun.toml").write_text(
                '[project]\nname = "mips-bin-test"\n'
                '[target]\narch = "mips_elf"\nbinary = "rom.bin"\n'
                'base_addr = "0x00400000"\nsymbols = "symbols.txt"\ngp = "0x10008000"\n',
                encoding="utf-8",
            )
            cfg = load_config(tpath / "kintoun.toml")
            bctx = load_target_from_config(cfg)
            btf = bctx.resolve_function("compute_reading")
            self.assertEqual(btf.va, 0x00400100)
            self.assertEqual(btf.data, ref_tf.data)

    def test_real_mips_multiblock_engine_step_across_six_toolchains(self) -> None:
        step_src = (FIXTURES / "engine_step.c").read_text(encoding="utf-8")
        mism_src = (FIXTURES / "engine_step_mismatch.c").read_text(encoding="utf-8")
        for suite in ("ee_gcc", "mwccps2", "psp_gcc", "mwccpsp", "mips_le", "mips_be"):
            with self.subTest(suite=suite):
                fdir = FIXTURES / "mips" / suite
                ctx, tf = load_target_from_object(fdir / "engine_step.o", "step_channel_block")
                self.assertGreaterEqual(tf.size, 80)

                res_ok = verify_source(step_src, tf, ctx, _FixedObjCompiler([], (fdir / "engine_step.o").read_bytes()))
                self.assertTrue(res_ok["verified"], msg=res_ok)

                res_sh = verify_source(step_src, tf, ctx, _FixedObjCompiler([], (fdir / "engine_step_shifted.o").read_bytes()))
                self.assertTrue(res_sh["verified"], msg=res_sh)

                res_mm = verify_source(mism_src, tf, ctx, _FixedObjCompiler([], (fdir / "engine_step_mismatch.o").read_bytes()))
                self.assertFalse(res_mm["verified"])
                self.assertEqual(res_mm["status"], "mismatch")
                self.assertGreater(res_mm["different_bytes"], 0)
                self.assertTrue(res_mm["repairs"])

    def test_psp_prx_relocation_r5900_sq_and_mips_target_guided_mutations(self) -> None:
        from kintoun.arch.mips_elf import relocate_psp_prx_image
        from kintoun.cli import main as cli_main
        from kintoun.search import mips_mutations
        from kintoun.targets import parse_arch_symbols
        import tempfile

        # 1. R5900 `sq $ra, 0($sp)` (`0x7FBF0000`) & `sq $s0, 0x10($sp)` vs Allegrex `ext $v0, $a0, 4, 8`
        self.assertEqual(disasm_mips_word(0x7FBF0000), ("sq", "$ra, 0($sp)"))
        self.assertEqual(disasm_mips_word(0x7FB00010), ("sq", "$s0, 0x10($sp)"))
        self.assertEqual(disasm_mips_word((31 << 26) | (4 << 21) | (2 << 16) | (7 << 11) | (4 << 6) | 0), ("ext", "$v0, $a0, 4, 8"))

        # 2. Synthetic PSP `ET_SCE_PSP_PRX` (`0xFFA0`) with `PT_LOAD` + `PT_PRXRELOC` (`0x700000A0`) + `SceModuleInfo`
        # Segment 0 at file_off=0x100, size=0x80:
        #   +0x00: jal +0x10 (`0x0C000004`) -> relocated to `0x08804010`
        #   +0x04: lui $a0, 0 (`0x3C040000`) + +0x08: addiu $a0, $a0, 0x40 (`0x24840040`) -> `0x08804040`
        #   +0x40: SceModuleInfo (`gp_value = 0x00018000` -> relocated to `0x0881C000`)
        ehdr = struct.pack(
            "<16sHHIIIIIHHHHHH",
            b"\x7fELF\x01\x01\x01" + b"\x00" * 9,
            0xFFA0, 8, 1, 0, 52, 0, 0x00A20000, 52, 32, 2, 40, 0, 0,
        )
        ph0 = struct.pack("<8I", 1, 0x100, 0, 0x140, 0x80, 0x80, 5, 16)
        ph1 = struct.pack("<8I", 0x700000A0, 0x180, 0, 0, 24, 0, 0, 4)
        seg = bytearray(0x80)
        struct.pack_into("<III", seg, 0, 0x0C000004, 0x3C040000, 0x24840040)
        struct.pack_into("<HH28sI", seg, 0x40, 0, 0x0101, b"TESTMOD\x00" + b"\x00" * 20, 0x00018000)
        relocs = struct.pack("<6I", 0x00, 4, 0x04, 5, 0x08, 6)
        prx = ehdr + ph0 + ph1 + b"\x00" * (0x100 - len(ehdr) - 64) + bytes(seg) + relocs
        rel_img, regs, prx_gp = relocate_psp_prx_image(prx, 0x08804000)
        self.assertEqual(prx_gp, 0x0881C000)
        self.assertEqual(regs[0][1], 0x08804000)
        w0, w1, w2 = struct.unpack_from("<III", rel_img, 0x100)
        self.assertEqual(w0, 0x0C000000 | (0x08804010 >> 2))
        self.assertEqual(w1, 0x3C040880)
        self.assertEqual(w2, 0x24844040)

        # 3. `mips_seeds` (`saved_reg_gp`, `lui+addiu` rebase, `synthesize_m2c_structs`, `single_float`)
        raw_m2c = (
            "M2C_UNK fn_00102000(M2C_UNK);\n"
            "void fn_00101000(void *arg0) {\n"
            "    M2C_FIELD(arg0, s32 *, 4) = M2C_FIELD(saved_reg_gp, s32 *, -0x100);\n"
            "    M2C_FIELD(arg0, s16 *, 0) = 2;\n"
            "    fn_00102000(0x005030D0);\n"
            "}\n"
        )
        rep = mips_seeds.repair_mips_seed(raw_m2c, "fn_00101000", 0x00101000, gp=0x00500000)
        self.assertIn("lbl_004FFF00", rep)
        self.assertIn('section(".sdata")', rep)
        # Target builds `0x005030D0` via `lui $a0, 0x50; addiu $a0, $a0, 0x30d0` (`0x3C040050`, `0x248430D0`)
        rebased = mips_seeds.mips_raw_addr_rebase(rep, [0x3C040050, 0x248430D0], gp=0x00500000)
        self.assertIsNotNone(rebased)
        self.assertIn("&lbl_005030D0", rebased)
        synth = mips_seeds.synthesize_m2c_structs(rebased)
        self.assertIsNotNone(synth)
        self.assertIn("arg0->f_4", synth)

        # 4. `mips_mutations` (`store_tgtorder`, `ptrstep_rescale`, `regcopy`) & CLI presets + splat symbols
        sw_src = "typedef struct { int a; int b; } P;\nvoid f(P *p) {\n    p->a = 1;\n    p->b = 2;\n}\n"
        # Target stores offset 4 (`sw $v0, 4($a0)` = `0xAC820004`) BEFORE offset 0 (`sw $v1, 0($a0)` = `0xAC830000`)
        sw_cands = list(mips_mutations.m_mips_store_tgtorder(sw_src, [0xAC820004, 0xAC830000]))
        self.assertEqual(len(sw_cands), 1)
        self.assertLess(sw_cands[0][1].index("p->b = 2;"), sw_cands[0][1].index("p->a = 1;"))

        step_cands = list(mips_mutations.m_mips_ptrstep_rescale("void g(short *p) {\n    p += 0x104;\n}\n", [0x26100104]))
        self.assertTrue(any("p += 130;" in c for _, c in step_cands))

        with tempfile.TemporaryDirectory() as tmp:
            for preset in ("mwccps2", "mwccpsp", "pspsnc"):
                self.assertEqual(cli_main(["init", "--preset", preset, "-o", str(Path(tmp) / f"{preset}.toml")]), 0)
            splat_p = Path(tmp) / "symbol_addrs.txt"
            splat_p.write_text("step_channel_block = 0x00120000; // type:func size:0x90\nD_00501000 = 0x00501000; // size:0x10\n")
            fn_map, _, obj_map = parse_arch_symbols(splat_p)
            self.assertEqual(fn_map["step_channel_block"], (0x00120000, 0x90))
            self.assertIn(0x00501000, obj_map)


if __name__ == "__main__":
    unittest.main()
