"""Unit and end-to-end tests for Kintoun 0.4.0 features:
  1. Binary xrefs (incoming callers + vtable refs), struct-offset consensus, and inlined-helper detection.
  2. Bit-exact IEEE-754 `.rodata` float solver & magic-division inverter + search repair.
  3. Wrong-compiler codegen fingerprinter (`prodg` vs `mwcc`, `agbcc` vs Thumb-2) + `[[compiler_bands]]`.
  4. Parallel compiler flag prober (`kintoun probe-flags`).
  5. `decomp.me` scratch importer & runner (`kintoun scratch --from-json`).
"""
from __future__ import annotations

import base64
import json
from pathlib import Path
import struct
import tempfile
import unittest

from kintoun.cli import main as cli_main
from kintoun.compiler import CompileResult, make_compiler
from kintoun.compiler_id import fingerprint_compiler
from kintoun.config import load_config
from kintoun.constants import constant_repair_variants, invert_magic_div32, scan_target_constants, solve_float32
from kintoun.inspect_fn import build_context_pack, check_function
from kintoun.prober import probe_compiler_flags
from kintoun.scratch import map_decompme_compiler, parse_scratch_slug, run_scratch
from kintoun.targets import TargetContext, TargetFunction
from tests.test_kintoun import _MockCompiler, _build_ppc_elf32


class V040FeatureTests(unittest.TestCase):
    def test_exact_float_solver_and_magic_division_inverter(self) -> None:
        # 0x3C8EFA35 == 3.1415927f / 180.0f (deg2rad)
        deg2rad = solve_float32(0x3C8EFA35)
        self.assertIsNotNone(deg2rad)
        packed = struct.unpack(">I", struct.pack(">f", float(deg2rad["c_literal"].rstrip("f"))))[0]
        self.assertEqual(packed, 0x3C8EFA35)
        self.assertIn("180.0f", deg2rad["exact_expr"])

        # Magic division constants: 0x55555556 -> x / 3, 0x66666667 -> x / 5
        div3 = invert_magic_div32(0x55555556)
        self.assertTrue(any(d["divisor"] == 3 for d in div3))
        div5 = invert_magic_div32(0x66666667)
        self.assertTrue(any(d["divisor"] == 5 for d in div5))

        # Target PPC function loading `lfs f1, 0(r2)` from `.sdata2` at 0x803F0000 containing 0x3C8EFA35,
        # plus `lis r4, 0x5555; ori r4, r4, 0x5556`
        fn_words = struct.pack(
            ">IIII",
            (48 << 26) | (1 << 21) | (2 << 16) | 0,       # lfs f1, 0(r2)
            (15 << 26) | (4 << 21) | 0x5555,              # lis r4, 0x5555
            (24 << 26) | (4 << 21) | (4 << 16) | 0x5556,  # ori r4, r4, 0x5556
            0x4E800020,                                   # blr
        )
        rodata = struct.pack(">I", 0x3C8EFA35)
        image = fn_words + rodata
        ctx = TargetContext(
            arch="ppc_elf",
            sda_r2=0x803F0000,
            _regions=[(0, 0x80001000, len(fn_words), True), (len(fn_words), 0x803F0000, 4, False)],
            _image=image,
        )
        tf = TargetFunction("AngleFn", 0x80001000, len(fn_words), fn_words)
        scanned = scan_target_constants(tf, ctx)
        self.assertEqual(scanned["floats"][0]["hex"], "0x3C8EFA35")
        self.assertEqual(scanned["magic_divisions"][0]["divisor"], 3)

        # Verify 1-ULP rounded float `0.0174533f` is snapped to bit-exact `0x3C8EFA35`
        repaired = constant_repair_variants("float AngleFn(float x) { return x * 0.0174533f; }\n", tf, ctx)
        self.assertEqual(len(repaired), 1)
        self.assertEqual(repaired[0][0], "exact_rodata_float")
        self.assertIn(deg2rad["c_literal"], repaired[0][1])

    def test_xrefs_vtable_struct_consensus_and_inlined_helper_detector(self) -> None:
        # Build 3 functions sharing a 5-instruction body + CallerA/CallerB calling TargetFn + vtable slot
        shared_seq = [
            0x80630004,  # lwz r3, 4(r3)
            0x38630001,  # addi r3, r3, 1
            0x5463083C,  # rlwinm r3, r3, 1, 0, 30
            0x9064001C,  # stw r3, 0x1c(r4)
            0x38600000,  # li r3, 0
        ]
        target_code = struct.pack(">7I", 0x9421FFE0, *shared_seq, 0x4E800020)
        peer1_code = struct.pack(">7I", 0x9421FFD0, *shared_seq, 0x4E800020)
        # Peer2 (`0x80001100`) also calls `TargetFn` (`0x80001000`) via `bl -0x100` at offset 0!
        bl_to_target = (18 << 26) | ((-0x100) & 0x03FFFFFC) | 1
        peer2_code = struct.pack(">8I", bl_to_target, 0x9421FFC0, *shared_seq, 0x4E800020)
        vtable_bytes = struct.pack(">II", 0x80001000, 0x80001080)

        blob = target_code.ljust(0x80, b"\x00") + peer1_code.ljust(0x80, b"\x00") + peer2_code + vtable_bytes
        vt_off = 0x100 + len(peer2_code)
        ctx = TargetContext(
            arch="ppc_elf",
            funcs={
                "Actor__Target": (0x80001000, len(target_code)),
                "Actor__Peer1": (0x80001080, len(peer1_code)),
                "Actor__Peer2": (0x80001100, len(peer2_code)),
            },
            by_addr={
                0x80001000: "Actor__Target",
                0x80001080: "Actor__Peer1",
                0x80001100: "Actor__Peer2",
            },
            objs={0x80200000: ("Actor__vtbl", 8)},
            data_segments=[(0x80200000, vtable_bytes)],
            _regions=[(0, 0x80001000, vt_off, True), (vt_off, 0x80200000, 8, False)],
            _image=blob,
        )
        tf = ctx.resolve_function("Actor__Target")

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            actor_dir = root / "src" / "Actor"
            actor_dir.mkdir(parents=True)
            (actor_dir / "Peer1.c").write_text(
                "static inline void HelperStep(void *a, void *b) { M2C_FIELD(b, s32 *, 0x1C) = 0; }\n"
                "s32 Actor__Peer1(void *self, void *other) {\n"
                "    M2C_FIELD(other, s32 *, 0x1C) = 1;\n"
                "    return 0;\n"
                "}\n",
                encoding="utf-8",
            )
            pack = build_context_pack(tf, ctx, src_dir=root / "src")
            self.assertIn("Actor__Peer2", pack["incoming_callers"])
            self.assertIn("Actor__vtbl", pack["vtable_or_data_refs"])
            self.assertIn("+0x1C", pack["field_offset_consensus"])
            self.assertGreaterEqual(len(pack["inlined_helper_candidates"]), 1)
            self.assertEqual(pack["corpus_inline_defs"][0]["name"], "HelperStep")

    def test_wrong_compiler_fingerprinter_and_compiler_bands(self) -> None:
        # MWCC PPC prologue + `addi r3, r4, 0` register move idiom
        mwcc_words = struct.pack(
            ">5I",
            0x9421FFE0,  # stwu r1, -0x20(r1)
            0x7C0802A6,  # mflr r0
            0x90010024,  # stw r0, 0x24(r1)
            0xBF810010,  # stmw r28, 0x10(r1)
            0x38640000,  # addi r3, r4, 0
        )
        ctx = TargetContext(arch="ppc_elf")
        tf = TargetFunction("SdkFn", 0x80170000, len(mwcc_words), mwcc_words)
        fp = fingerprint_compiler(tf, ctx, configured_preset="prodg-wine")
        self.assertEqual(fp["detected_family"], "mwcc")
        self.assertTrue(fp["mismatch"])
        self.assertIn("compiler_bands", fp["warning"])

        chk = check_function(tf, ctx, configured_preset="prodg-wine")
        self.assertTrue(chk["compiler_fingerprint"]["mismatch"])

        # ARM `agbcc` vs Thumb-2 `push.w` mismatch
        ctx_arm = TargetContext(arch="arm_elf", thumb=True)
        t2_fn = TargetFunction("Thumb2Fn", 0x08001000, 8, struct.pack("<HHHH", 0xE92D, 0x41F0, 0x4770, 0x0000), is_thumb=True)
        fp_arm = fingerprint_compiler(t2_fn, ctx_arm, configured_preset="agbcc")
        self.assertTrue(fp_arm["mismatch"])

        # Test `[[compiler_bands]]` selection in `kintoun.toml` + `make_compiler(cfg, va=...)`
        with tempfile.TemporaryDirectory() as tmp:
            toml_p = Path(tmp) / "kintoun.toml"
            toml_p.write_text(
                '[project]\nname = "mixed"\n'
                '[compiler]\npreset = "custom"\ncommand = ["echo", "game", "{out}", "{in}"]\nflags = ["-O2"]\n'
                '[[compiler_bands]]\nname = "sdk"\nstart = "0x80160000"\nend = "0x80180000"\n'
                'preset = "custom"\ncommand = ["echo", "sdk", "{out}", "{in}"]\nflags = ["-O4,p"]\n',
                encoding="utf-8",
            )
            cfg = load_config(toml_p)
            cc_game = make_compiler(cfg, va=0x80004000)
            cc_sdk = make_compiler(cfg, va=0x80170000)
            self.assertEqual(cc_game.flags, ("-O2",))
            self.assertEqual(cc_sdk.flags, ("-O4,p",))

    def test_probe_flags_and_decompme_scratch_runner(self) -> None:
        self.assertEqual(map_decompme_compiler("mwcc_233_163"), "mwcc-wine")
        self.assertEqual(map_decompme_compiler("ee-gcc2.96"), "ee-gcc")
        self.assertEqual(map_decompme_compiler("agbcc"), "agbcc")
        self.assertEqual(parse_scratch_slug("https://decomp.me/scratch/xYz12"), ("https://decomp.me", "xYz12"))

        target_bytes = struct.pack(">II", 0x38600001, 0x4E800020)
        wrong_bytes = struct.pack(">II", 0x38600000, 0x4E800020)

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            # 1. Test `probe-flags` via a small Python mock compiler script where `-O3` emits `target_bytes`
            mock_cc_py = root / "mock_cc.py"
            obj_match = root / "match.o"
            obj_wrong = root / "wrong.o"
            obj_match.write_bytes(_build_ppc_elf32("ProbeFn", target_bytes))
            obj_wrong.write_bytes(_build_ppc_elf32("ProbeFn", wrong_bytes))
            mock_cc_py.write_text(
                "import shutil, sys\n"
                "args = sys.argv[1:]\n"
                "out = args[args.index('-o') + 1]\n"
                f"src = {str(obj_match)!r} if '-O3' in args else {str(obj_wrong)!r}\n"
                "shutil.copyfile(src, out)\n",
                encoding="utf-8",
            )
            toml_p = root / "kintoun.toml"
            toml_p.write_text(
                '[compiler]\npreset = "custom"\n'
                f'command = ["python3", "{mock_cc_py}", "{{flags}}", "-o", "{{out}}", "{{in}}"]\n'
                'flags = ["-O2", "-c"]\n',
                encoding="utf-8",
            )
            cand_c = root / "cand.c"
            cand_c.write_text("int ProbeFn(void) { return 1; }\n", encoding="utf-8")
            cfg = load_config(toml_p)
            ctx = TargetContext(arch="ppc_elf")
            tf = TargetFunction("ProbeFn", 0x80001000, 8, target_bytes)
            rep = probe_compiler_flags("int ProbeFn(void) { return 1; }\n", tf, ctx, cfg, workers=2)
            self.assertTrue(rep["best"]["verified"])
            self.assertIn("-O3", rep["best"]["flags"])
            self.assertEqual(
                cli_main(["-c", str(toml_p), "probe-flags", str(cand_c), "--target", str(obj_match), "--json"]),
                0,
            )

            # 2. Test `kintoun scratch --from-json` end-to-end solving a scratch locally
            scratch_target = _build_ppc_elf32("TestFunc", target_bytes)
            scratch_json = root / "scratch_bundle.json"
            out_c = root / "solved.c"
            scratch_json.write_text(
                json.dumps(
                    {
                        "slug": "demo1",
                        "diff_label": "TestFunc",
                        "compiler": "mwcc_247_92",
                        "compiler_flags": "-O4,p",
                        "context": "typedef int s32;\ntypedef unsigned int u32;",
                        "source_code": "s32 TestFunc(void) {\n    s32 x;\n    x = 1;\n    return x;\n}",
                        "target_obj_b64": base64.b64encode(scratch_target).decode("ascii"),
                    }
                ),
                encoding="utf-8",
            )
            res = run_scratch(
                "demo1",
                cfg,
                from_json=scratch_json,
                budget_s=5.0,
                max_candidates=60,
                out_source=out_c,
                compiler_override=_MockCompiler(target_bytes, wrong_bytes),
            )
            self.assertTrue(res["verified"])
            self.assertTrue(out_c.is_file())
            self.assertIn("u32 x", out_c.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
