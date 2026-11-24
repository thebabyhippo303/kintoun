"""End-to-end tests for Kintoun 0.5.0 moat-widening features:
  1. Pure-stdlib `PERM_*` / `KINTOUN_*` parametric macro DSL + beam-search hybrid (`macros.py`, `runner.py`)
  2. Linker `.map` parser, `compile_commands.json`/`build.ninja` flag discovery, header slicer,
     `INCLUDE_ASM`/`GLOBAL_ASM` importer, and atomic full-TU verified integrator (`project_io.py`)
  3. Per-ISA opcode-bigram TF-IDF similarity + L2 logistic match model (`similarity.py`, `inspect_fn.py`)
  4. Single-file zero-dependency HTML Decomp Atlas & Run Report (`atlas.py`)
  5. Background-solved early-abort race coordination (`queue.py`, `candidates.py`)
"""
from __future__ import annotations

import json
from pathlib import Path
import struct
import tempfile
import unittest

from kintoun.atlas import build_atlas_data, write_atlas_report
from kintoun.candidates import CandidateStore
from kintoun.cli import main as cli_main
from kintoun.config import KintounConfig
from kintoun.inspect_fn import build_context_pack
from kintoun.macros import count_perm_combinations, expand_perm_macros, has_perm_macros
from kintoun.project_io import (
    discover_tu_compile_flags,
    import_project_function,
    integrate_matched_function,
    parse_linker_map,
    slice_project_types_and_decls,
)
from kintoun.queue import WorkQueue
from kintoun.search.runner import run_search
from kintoun.similarity import (
    extract_numeric_features,
    find_similar_functions,
    fit_project_difficulty_model,
    predict_match_probability,
)
from kintoun.targets import TargetContext, TargetFunction
from tests.test_kintoun import _MockCompiler, _build_ppc_elf32


class V050MoatTests(unittest.TestCase):
    def _sample_ppc(self) -> tuple[TargetContext, TargetFunction, _MockCompiler]:
        # `_MockCompiler` emits `target_bytes` when `"u32 x"` appears in source and `wrong_bytes` otherwise.
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

    def test_perm_macro_dsl_and_hybrid_beam_search(self) -> None:
        raw_c = """\
s32 Compute(s32 a, s32 b) {
    PERM_VAR(T, PERM_GENERAL(s32, u32))
    PERM_VAR(T) x;
    PERM_ONCE(init, x = 0;)
    PERM_LINESWAP(
        a += PERM_INT(1, 2);
        b += fn_call(a(,) b);
    )
    PERM_SAMELINE(
        if (a > b)
            x = a;
    )
    PERM_ONCE(init, x = 0;)
    return PERM_RANDOMIZE(x + b);
}
"""
        self.assertTrue(has_perm_macros(raw_c))
        total = count_perm_combinations(raw_c)
        # 2 (`T`) * 2 (`PERM_ONCE`) * 2 (`LINESWAP`) * 2 (`PERM_INT(1,2)`) = 16 combinations
        self.assertEqual(total, 16)
        exp = expand_perm_macros(raw_c, max_variants=64, seed=42)
        self.assertTrue(exp["has_macros"])
        self.assertTrue(exp["exhaustive"])
        self.assertEqual(len(exp["variants"]), 16)
        for v in exp["variants"]:
            self.assertFalse(has_perm_macros(v))
            self.assertIn("fn_call(a, b);", v)
            self.assertIn("if (a > b) x = a;", v)
            self.assertEqual(v.count("x = 0;"), 1)

        # Verify `run_search` expands `PERM_*` macros AND chains into Kintoun's beam search to hit VERIFIED!
        # Notice the macro choices only test `s16 x` vs `s8 x`, so NEITHER macro variant matches directly;
        # Kintoun expands the macros so they compile cleanly, then its own `local_type` beam mutation
        # mutates `s16 x` -> `u32 x` to achieve `verified == True`!
        ctx, tf, compiler = self._sample_ppc()
        hybrid_seed = """\
s32 TestFunc(s32 a) {
    PERM_GENERAL(s16 x;, s32 x;)
    x = a;
    return x;
}
"""
        res = run_search(
            source=hybrid_seed,
            target_fn=tf,
            ctx=ctx,
            compiler=compiler,
            budget_s=5.0,
            max_candidates=60,
            workers=2,
        )
        self.assertTrue(res["verified"])
        self.assertEqual(res["macro_variants"], 2)
        self.assertIn("u32 x", res["best"]["code"])

    def test_linker_map_tu_flags_import_and_verified_integrate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "include").mkdir()
            (root / "src").mkdir()
            (root / "asm" / "nonmatchings" / "player").mkdir(parents=True)

            # 1. GNU ld + mwld map parsing (including .NON_MATCHING & Thumb bit)
            map_file = root / "game.map"
            map_file.write_text(
                ".text           0x08001000       0x40 build/src/player.o\n"
                "                0x08001001                ThumbFn\n"
                "                0x08001021                ThumbFn.NON_MATCHING\n"
                "                0x08001021                NextThumb\n"
                "  00000000 000008 80001000  4 TestFunc   player.o\n",
                encoding="utf-8",
            )
            parsed = parse_linker_map(map_file)
            self.assertEqual(parsed["ThumbFn"]["va"], 0x08001000)
            self.assertTrue(parsed["ThumbFn"]["thumb"])
            self.assertEqual(parsed["ThumbFn"]["size"], 0x20)
            self.assertEqual(parsed["TestFunc"]["va"], 0x80001000)
            self.assertEqual(parsed["TestFunc"]["size"], 8)

            # 2. Header + multi-function INCLUDE_ASM source + compile_commands.json
            (root / "include" / "player.h").write_text(
                "typedef struct PlayerState {\n    int hp;\n    int mp;\n} PlayerState;\n"
                "int Helper_Clamp(int v);\n"
                "int TestFunc(int a);\n",
                encoding="utf-8",
            )
            c_file = root / "src" / "player.c"
            c_file.write_text(
                '#include "player.h"\n\n'
                "int AlreadyMatched(int z) {\n    return z + 1;\n}\n\n"
                'INCLUDE_ASM("asm/nonmatchings/player", TestFunc);\n\n'
                'INCLUDE_ASM("asm/nonmatchings/player", UnfinishedPeer);\n',
                encoding="utf-8",
            )
            (root / "asm" / "nonmatchings" / "player" / "TestFunc.s").write_text(
                "glabel TestFunc\n    bl Helper_Clamp\n    blr\n",
                encoding="utf-8",
            )
            (root / "compile_commands.json").write_text(
                json.dumps(
                    [
                        {
                            "directory": str(root),
                            "file": "src/player.c",
                            "command": "cc -O2 -Iinclude -DGAME_REV=1 -c src/player.c -o build/player.o",
                        }
                    ]
                ),
                encoding="utf-8",
            )

            tu_flags = discover_tu_compile_flags(root, c_file)
            self.assertIn("-O2", tu_flags["opt_flags"])
            self.assertIn("GAME_REV=1", tu_flags["defines"])

            sliced = slice_project_types_and_decls(c_file, root, target_func="TestFunc")
            self.assertTrue(any("PlayerState" in td for td in sliced["type_definitions"]))
            self.assertIn("TestFunc", sliced["target_declaration"])

            out_cand = root / "cand.c"
            imp = import_project_function(root, "TestFunc", map_file=map_file, out_candidate=out_cand)
            self.assertEqual(imp["stub_kind"], "INCLUDE_ASM")
            self.assertIn("Helper_Clamp", imp["asm_callees"])
            self.assertTrue(out_cand.is_file())
            self.assertIn("PlayerState", imp["candidate_code"])

            # 3. Atomic Verified Integration: wrong match is rejected WITHOUT modifying `src/player.c`!
            ctx, tf, compiler = self._sample_ppc()
            bad_cand = "int Helper_Clamp(int v);\ns32 TestFunc(s32 a) {\n    s32 x = a;\n    return x;\n}\n"
            bad_int = integrate_matched_function(
                bad_cand,
                c_file,
                "TestFunc",
                verify=True,
                target_fn=tf,
                ctx=ctx,
                compiler=compiler,
            )
            self.assertFalse(bad_int["ok"])
            self.assertIn('INCLUDE_ASM("asm/nonmatchings/player", TestFunc);', c_file.read_text(encoding="utf-8"))

            # Verified match splices cleanly, strips duplicate `AlreadyMatched` / `Helper_Clamp` collisions,
            # and leaves neighbor `INCLUDE_ASM(..., UnfinishedPeer)` untouched!
            good_cand = (
                "int AlreadyMatched(int z);\n"
                "int NewExternalCall(int q);\n"
                "s32 TestFunc(s32 a) {\n    u32 x = a;\n    return NewExternalCall(x);\n}\n"
            )
            good_int = integrate_matched_function(
                good_cand,
                c_file,
                "TestFunc",
                verify=True,
                target_fn=tf,
                ctx=ctx,
                compiler=compiler,
            )
            self.assertTrue(good_int["ok"])
            self.assertTrue(good_int["verified"])
            updated_tu = c_file.read_text(encoding="utf-8")
            self.assertNotIn("TestFunc);", updated_tu)
            self.assertIn("u32 x = a;", updated_tu)
            self.assertIn("extern int NewExternalCall(int q);", updated_tu)
            self.assertEqual(updated_tu.count("AlreadyMatched"), 1)
            self.assertIn('INCLUDE_ASM("asm/nonmatchings/player", UnfinishedPeer);', updated_tu)

    def test_tfidf_opcode_similarity_and_logistic_calibration(self) -> None:
        # FnTarget and FnTwin share identical float+add+return opcode sequences; FnUnrelated is branch/store heavy.
        twin_bytes = struct.pack(">IIII", 0xC0230000, 0xEC01082A, 0xD0030004, 0x4E800020)  # lfs, fadds, stfs, blr
        other_bytes = struct.pack(">IIII", 0x2C030000, 0x4182000C, 0x90830000, 0x4E800020)  # cmpwi, beq, stw, blr
        image = twin_bytes + twin_bytes + other_bytes
        ctx = TargetContext(
            arch="ppc_elf",
            funcs={
                "FnTarget": (0x80001000, 16),
                "FnTwin": (0x80001010, 16),
                "FnUnrelated": (0x80001020, 16),
            },
            by_addr={0x80001000: "FnTarget", 0x80001010: "FnTwin", 0x80001020: "FnUnrelated"},
            _regions=[(0, 0x80001000, len(image), True)],
            _image=image,
        )
        tf_target = ctx.resolve_function("FnTarget")
        with tempfile.TemporaryDirectory() as tmp:
            sdir = Path(tmp) / "src"
            sdir.mkdir()
            (sdir / "math.c").write_text(
                "void FnTwin(float* p, float b) {\n    p[1] = p[0] + b;\n}\n\n"
                "void FnUnrelated(int* p, int v) {\n    if (p) *p = v;\n}\n",
                encoding="utf-8",
            )
            sims = find_similar_functions(tf_target, ctx, src_dir=sdir, top_k=2)
            self.assertEqual(len(sims), 2)
            self.assertEqual(sims[0]["function"], "FnTwin")
            self.assertGreater(sims[0]["similarity"], sims[1]["similarity"])

            pack = build_context_pack(tf_target, ctx, src_dir=sdir)
            self.assertEqual(pack["similar_examples"][0]["function"], "FnTwin")
            self.assertIn("estimated_match_prob", pack["difficulty"])

        # Train project-calibrated L2 logistic model on 8 synthetic functions (4 easy leaves = 1, 4 complex = 0)
        easy_f = extract_numeric_features(tf_target, ctx)
        hard_f = [7.5, 0.35, 3.0, 1.0, 0.2, 1.0, 0.4, 2.0, 0.0, 0.0]
        samples = [(easy_f, 1)] * 4 + [(hard_f, 0)] * 4
        model = fit_project_difficulty_model(samples)
        self.assertTrue(model["trained"])
        self.assertGreater(predict_match_probability(easy_f, model), predict_match_probability(hard_f, model))

    def test_html_atlas_and_background_solved_early_abort(self) -> None:
        ctx, tf, compiler = self._sample_ppc()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cfg = KintounConfig(root=root)
            wq = WorkQueue(root / ".kintoun")
            wq.sync_from_context(ctx)

            store = CandidateStore(root / ".kintoun" / "cache")
            c1 = store.score_one("s32 TestFunc(s32 a) {\n    s32 x = a;\n    return x;\n}\n", tf, ctx, compiler)
            self.assertFalse(c1.get("already_verified", False))

            # Background closer / peer submits the match -> marks TestFunc `done` in `.kintoun/queue.sqlite3`
            sub = wq.submit_match(
                "bg-closer",
                "TestFunc",
                "s32 TestFunc(s32 a) {\n    u32 x = a;\n    return x;\n}\n",
                ctx,
                compiler,
                project_root=root,
            )
            self.assertTrue(sub["ok"])

            # Foreground agent calling `revise` or `score_one` with `abort_if_done=True` gets instant early-abort!
            aborted = store.revise(
                c1["candidate_id"],
                [{"old": "s32 x = a;", "new": "s16 x = a;"}],
                tf,
                ctx,
                compiler,
                abort_if_done=True,
            )
            self.assertEqual(aborted["status"], "already_verified")
            self.assertTrue(aborted["already_verified"])
            self.assertIn("already VERIFIED", aborted["abort_hint"])

            # Generate self-contained HTML Decomp Atlas
            atlas_data = build_atlas_data(ctx, cfg)
            self.assertEqual(atlas_data["counts"]["done"], 1)
            self.assertEqual(atlas_data["matched_bytes_pct"], 100.0)

            out_html = root / "atlas.html"
            rep = write_atlas_report(out_html, ctx, cfg)
            self.assertTrue(out_html.is_file())
            self.assertGreater(rep["bytes_written"], 1000)
            html_txt = out_html.read_text(encoding="utf-8")
            self.assertIn("Kintoun Decomp Atlas", html_txt)
            self.assertIn("TestFunc", html_txt)

            # CLI smoke test for `atlas` and `import`
            obj_p = root / "fn.o"
            obj_p.write_bytes(_build_ppc_elf32("CliAtlasFn", struct.pack(">II", 0x38600001, 0x4E800020)))
            cli_html = root / "cli_atlas.html"
            self.assertEqual(cli_main(["atlas", "--target", str(obj_p), "-o", str(cli_html), "--json"]), 0)
            self.assertTrue(cli_html.is_file())


if __name__ == "__main__":
    unittest.main()


class KintounMacroNameTests(unittest.TestCase):
    def test_every_perm_name_has_a_kintoun_name(self):
        from kintoun import macros

        for perm in [n for n in macros._MACRO_NAMES if n.startswith("PERM_")]:
            own = "KINTOUN_" + perm[len("PERM_"):]
            if perm == "PERM_GENERAL":
                own = "KINTOUN_ALT"
            self.assertIn(own, macros._MACRO_NAMES, perm)

    def test_kintoun_wrappers_unwrap_like_perm(self):
        from kintoun import macros

        for a, b in (("PERM_RANDOMIZE", "KINTOUN_RANDOMIZE"), ("PERM_FORCE_SAMELINE", "KINTOUN_FORCE_SAMELINE")):
            src = "int f(void) {\n    %s(return\n 1;)\n}\n"
            self.assertEqual(macros._preprocess_deterministic_wrappers(src % a), macros._preprocess_deterministic_wrappers(src % b))
            self.assertNotIn(b, macros._preprocess_deterministic_wrappers(src % b))
