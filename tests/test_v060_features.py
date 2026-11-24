"""End-to-end tests for Kintoun 0.6.0 features:
  1. Zero-config repo ingestion (`objdiff.json`, `dtk` `config.yml`, `splat.yaml`) & two-way `objdiff.json` export
  2. Byte-verified post-match C cleaner & `goto` restructurer (`cleaner.py`, `kintoun clean`)
  3. Live file-save watch mode with score deltas & auto-close trigger (`watch.py`, `kintoun watch`)
  4. Factual binary struct, vtable, & debug-string header synthesizer (`synth.py`, `kintoun synth-headers`)
  5. End-to-end `kintoun doctor` + verifiable SFT/DPO fine-tuning dataset exporter (`doctor.py`, `dataset.py`)
"""
from __future__ import annotations

import io
import json
from pathlib import Path
import struct
import tempfile
import unittest

from kintoun.autoconfig import (
    detect_repo_layout,
    export_objdiff_config,
    parse_objdiff_config,
    resolve_objdiff_target_object,
)
from kintoun.candidates import CandidateStore
from kintoun.cleaner import clean_matched_source
from kintoun.cli import main as cli_main
from kintoun.compiler import CompileResult, CompilerBackend
from kintoun.config import KintounConfig, load_config
from kintoun.dataset import export_dataset
from kintoun.doctor import run_doctor, scan_local_compilers
from kintoun.search.runner import run_search
from kintoun.synth import synthesize_project_headers
from kintoun.targets import TargetContext, TargetFunction
from kintoun.watch import WatchSession, run_watch_loop
from tests.test_kintoun import _MockCompiler, _build_ppc_elf32


class _CleanerMockCompiler:
    """Mock compiler where removing `needed_stack_pad` breaks byte match, while de-goto & other cleanups stay exact."""

    compiler_id = "mock-clean-v1"
    flags = ("-O2", "-c")

    def __init__(self, target_bytes: bytes, broken_bytes: bytes) -> None:
        self._good = _build_ppc_elf32("CleanFn", target_bytes)
        self._bad = _build_ppc_elf32("CleanFn", broken_bytes)

    def compile_c(self, src: Path, out_obj: Path) -> CompileResult:
        source = src.read_text(encoding="utf-8")
        if "SYNTAX_ERROR" in source:
            return CompileResult(1, "", "syntax error", out_obj)
        # Simulate real compiler sensitivity: `needed_stack_pad` MUST remain to preserve stack layout,
        # whereas `unused_dead`, `goto skip_blk`, `do { ... } while (0)`, `(s32)(s32)`, and `temp_ret` can be cleaned!
        out_obj.write_bytes(self._good if "needed_stack_pad" in source else self._bad)
        return CompileResult(0, "", "", out_obj)


class V060FeatureTests(unittest.TestCase):
    def _sample_ppc(self) -> tuple[TargetContext, TargetFunction, _MockCompiler]:
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

    def test_autoconfig_objdiff_dtk_and_splat_ingestion(self) -> None:
        # 1. `splat.yaml` auto-detection -> `kintoun init` writes PS2 `ee-gcc` config automatically
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "splat.yaml").write_text(
                "name: DemoPs2\n"
                "options:\n"
                "  platform: ps2\n"
                "  compiler: EEGCC\n"
                "  target_path: disc/SLUS_999.99\n"
                "  symbol_addrs_path: config/symbol_addrs.txt\n"
                "  gp_value: 0x00345670\n",
                encoding="utf-8",
            )
            det = detect_repo_layout(root)
            self.assertIsNotNone(det)
            self.assertEqual(det["arch"], "mips_elf")
            self.assertEqual(det["preset"], "ee-gcc")
            self.assertEqual(det["binary"], "disc/SLUS_999.99")

            out_toml = root / "kintoun.toml"
            self.assertEqual(cli_main(["init", "--auto", "-o", str(out_toml)]), 0)
            cfg = load_config(out_toml)
            self.assertEqual(cfg.target.arch, "mips_elf")
            self.assertEqual(cfg.compiler.preset, "ee-gcc")
            self.assertEqual(cfg.target.gp, 0x00345670)

        # 2. `dtk` `config/GALE01/config.yml` + `objdiff.json` unit target `.o` resolution + two-way export
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "config" / "GM8E01").mkdir(parents=True)
            (root / "config" / "GM8E01" / "config.yml").write_text(
                "object: orig/GM8E01/sys/main.dol\nsymbols: config/GM8E01/symbols.txt\n",
                encoding="utf-8",
            )
            (root / "build" / "orig").mkdir(parents=True)
            (root / "src").mkdir()
            c_path = root / "src" / "actor.c"
            c_path.write_text("int Actor_Step(int x) { return x; }\n", encoding="utf-8")
            obj_path = root / "build" / "orig" / "actor.o"
            obj_path.write_bytes(_build_ppc_elf32("Actor_Step", struct.pack(">II", 0x38630001, 0x4E800020)))

            exported_od = root / "objdiff.json"
            doc = export_objdiff_config(root, "ppc_elf", out_path=exported_od)
            self.assertEqual(doc["arch"], "ppc")
            self.assertEqual(len(doc["units"]), 1)

            parsed_od = parse_objdiff_config(exported_od)
            self.assertEqual(parsed_od["arch"], "ppc_elf")
            resolved_o = resolve_objdiff_target_object(root, source_file=c_path)
            self.assertEqual(resolved_o, obj_path)

            det_gc = detect_repo_layout(root)
            self.assertEqual(det_gc["dol"], "orig/GM8E01/sys/main.dol")
            self.assertEqual(det_gc["preset"], "mwcc-wine")

    def test_byte_verified_post_match_cleaner_and_degoto(self) -> None:
        target_bytes = struct.pack(">II", 0x38630001, 0x4E800020)
        broken_bytes = struct.pack(">II", 0x38630002, 0x4E800020)
        ctx = TargetContext(arch="ppc_elf")
        tf = TargetFunction("CleanFn", 0x80002000, 8, target_bytes)
        compiler = _CleanerMockCompiler(target_bytes, broken_bytes)

        ugly_matched_c = """\
s32 CleanFn(s32 a) {
    s32 needed_stack_pad;
    s32 unused_dead;
    s32 temp_ret;
    a = a;
    do {
        a = (s32)(s32)a + 1;
    } while (0);
    if (a == 0) {
        goto skip_blk;
    }
    a += 2;
skip_blk:
    temp_ret = a;
    return (temp_ret);
}
"""
        res = clean_matched_source(ugly_matched_c, tf, ctx, compiler)
        self.assertTrue(res["ok"])
        self.assertTrue(res["verified"])
        self.assertTrue(res["changed"])
        cleaned = res["cleaned_code"]

        # `needed_stack_pad` was kept because removing it broke byte-exact verification (`reverted_steps >= 1`)!
        self.assertIn("needed_stack_pad;", cleaned)
        self.assertGreaterEqual(res["reverted_steps"], 1)

        # Meanwhile, all byte-safe ugly artifacts were cleaned automatically!
        self.assertNotIn("unused_dead", cleaned)
        self.assertNotIn("goto skip_blk", cleaned)
        self.assertIn("if (a != 0)", cleaned)
        self.assertNotIn("while (0)", cleaned)
        self.assertNotIn("(s32)(s32)", cleaned)
        self.assertNotIn("temp_ret", cleaned)
        self.assertIn("return a;", cleaned)

    def test_live_watch_mode_deltas_and_auto_close(self) -> None:
        ctx, tf, compiler = self._sample_ppc()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cand_p = root / "watch_me.c"
            cand_p.write_text("s32 TestFunc(s32 a) {\n    s32 x = a;\n    return x;\n}\n", encoding="utf-8")

            # 1. First save without auto-close -> mismatch recorded; second save with `u32 x` -> +delta & VERIFIED!
            sess = WatchSession(
                source_path=cand_p,
                target_fn=tf,
                ctx=ctx,
                compiler=compiler,
                cache_dir=root / "cache",
            )
            ev1 = sess.evaluate_current()
            self.assertFalse(ev1["verified"])
            self.assertEqual(ev1["save_number"], 1)

            cand_p.write_text("s32 TestFunc(s32 a) {\n    u32 x = a;\n    return x;\n}\n", encoding="utf-8")
            buf = io.StringIO()
            events = run_watch_loop(sess, interval_s=0.05, max_events=1, stream=buf)
            self.assertEqual(len(events), 1)
            self.assertTrue(events[0]["verified"])
            self.assertEqual(events[0]["different_bytes"], 0)
            self.assertLess(events[0]["delta_different_bytes"], 0)

            # 2. Auto-close trigger (`auto_close_pct=50.0`, `write_on_match=True`) closes mismatch automatically!
            cand_p.write_text("s32 TestFunc(s32 a) {\n    s32 x;\n    x = a;\n    return x;\n}\n", encoding="utf-8")
            sess_auto = WatchSession(
                source_path=cand_p,
                target_fn=tf,
                ctx=ctx,
                compiler=compiler,
                cache_dir=root / "cache2",
                auto_close_pct=50.0,
                write_on_match=True,
            )
            ev_auto = sess_auto.evaluate_current()
            self.assertTrue(ev_auto["verified"])
            self.assertTrue(ev_auto["auto_close"]["verified"])
            self.assertIn("u32 x", cand_p.read_text(encoding="utf-8"))

    def test_binary_struct_vtable_and_debug_string_synthesizer(self) -> None:
        # Build two PowerPC methods `Actor__Init` and `Actor__Step` touching `r3+0x00` (vtable),
        # `r3+0x08` (`s32`: lwz r4, 8(r3)), `r3+0x0C` (`u16`: lhz r5, 12(r3)), `r3+0x10` (`f32`: lfs f1, 16(r3))
        fn_init = struct.pack(
            ">IIII",
            (32 << 26) | (4 << 21) | (3 << 16) | 0x0008,  # lwz r4, 0x8(r3)
            (40 << 26) | (5 << 21) | (3 << 16) | 0x000C,  # lhz r5, 0xC(r3)
            (48 << 26) | (1 << 21) | (3 << 16) | 0x0010,  # lfs f1, 0x10(r3)
            0x4E800020,                                   # blr
        )
        fn_step = struct.pack(
            ">III",
            (36 << 26) | (4 << 21) | (3 << 16) | 0x0008,  # stw r4, 0x8(r3)
            (52 << 26) | (1 << 21) | (3 << 16) | 0x0010,  # stfs f1, 0x10(r3)
            0x4E800020,                                   # blr
        )
        code_blob = fn_init + fn_step
        # `.rodata` with 2-slot vtable `[0x80001000, 0x80001010]` + debug assert string `"src/actor_ctrl.cpp\0"`
        rodata_blob = struct.pack(">II", 0x80001000, 0x80001010) + b"ASSERT(p != NULL) in src/actor_ctrl.cpp\x00"
        ctx = TargetContext(
            arch="ppc_elf",
            funcs={
                "Actor__Init": (0x80001000, len(fn_init)),
                "Actor__Step": (0x80001010, len(fn_step)),
            },
            by_addr={0x80001000: "Actor__Init", 0x80001010: "Actor__Step"},
            data_segments=[(0x80020000, rodata_blob)],
            _regions=[(0, 0x80001000, len(code_blob), True)],
            _image=code_blob,
        )
        with tempfile.TemporaryDirectory() as tmp:
            out_h = Path(tmp) / "synth.h"
            syn = synthesize_project_headers(ctx, out_header=out_h)
            self.assertTrue(out_h.is_file())
            self.assertEqual(len(syn["vtables"]), 1)
            self.assertEqual(syn["vtables"][0]["slot_count"], 2)
            self.assertEqual(len(syn["structs"]), 1)
            st = syn["structs"][0]
            self.assertEqual(st["name"], "Actor")
            self.assertTrue(st["has_vtable"])
            hdr = syn["header_code"]
            self.assertIn("typedef struct Actor_vtable", hdr)
            self.assertIn("/* +0x00 */ void* vtable;", hdr)
            self.assertIn("/* +0x04 */ u8 _pad_0x04[0x4];", hdr)
            self.assertIn("/* +0x08 */ s32 unk_0x08;", hdr)
            self.assertIn("/* +0x0C */ u16 unk_0x0C;", hdr)
            self.assertIn("/* +0x10 */ f32 unk_0x10;", hdr)
            self.assertIn("src/actor_ctrl.cpp", hdr)

    def test_doctor_and_verifiable_dataset_exporter(self) -> None:
        ctx, tf, compiler = self._sample_ppc()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cfg = KintounConfig(root=root)

            # 1. `scan_local_compilers` + `run_doctor` with live ELF32 smoke test
            tools_dir = root / "tools" / "agbcc_bin"
            tools_dir.mkdir(parents=True)
            (tools_dir / "agbcc").write_text("", encoding="utf-8")
            found_comps = scan_local_compilers(root / "tools")
            self.assertEqual(len(found_comps), 1)
            self.assertEqual(found_comps[0]["preset"], "agbcc")

            doc_rep = run_doctor(cfg, compiler_override=compiler, scan_dir=root / "tools")
            self.assertTrue(doc_rep["ok"])

            # 2. Run `run_search` (records trajectory milestone) + `CandidateStore` -> export SFT & DPO JSONL
            cdir = root / ".kintoun" / "cache"
            res = run_search(
                source="s32 TestFunc(s32 a) {\n    s32 x;\n    x = a;\n    return x;\n}\n",
                target_fn=tf,
                ctx=ctx,
                compiler=compiler,
                budget_s=5.0,
                max_candidates=40,
                cache_dir=cdir,
            )
            self.assertTrue(res["verified"])
            self.assertTrue((cdir / "trajectories.jsonl").is_file())

            store = CandidateStore(cdir)
            store.score_one("s32 TestFunc(s32 a) {\n    s32 x = a;\n    return x;\n}\n", tf, ctx, compiler)
            store.score_one("s32 TestFunc(s32 a) {\n    u32 x = a;\n    return x;\n}\n", tf, ctx, compiler)

            out_jsonl = root / "train.jsonl"
            ds = export_dataset(cdir, ctx, out_path=out_jsonl)
            self.assertTrue(out_jsonl.is_file())
            self.assertGreaterEqual(ds["counts"]["sft_decomp"], 1)
            self.assertGreaterEqual(ds["counts"]["sft_repair"], 1)
            self.assertGreaterEqual(ds["counts"]["dpo_pair"], 1)

            rows = [json.loads(ln) for ln in out_jsonl.read_text(encoding="utf-8").splitlines() if ln.strip()]
            self.assertTrue(any(r["kind"] == "dpo_pair" and "u32 x" in r["chosen"] for r in rows))


if __name__ == "__main__":
    unittest.main()
