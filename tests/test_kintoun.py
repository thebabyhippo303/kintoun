"""Self-contained unit and end-to-end tests for Kintoun (no external compilers or ROMs required)."""
from __future__ import annotations

from pathlib import Path
import struct
import tempfile
import unittest

from kintoun.arch.elf import Object
from kintoun.arch.ppc_elf import compare_bytes, relocate_ppc, sda_references, symbol_name
from kintoun.cache import ResultCache, source_key
from kintoun.cli import main as cli_main
from kintoun.compiler import CompileResult
from kintoun.config import load_config
from kintoun.search import base_mutations, guidance, mutations, permuter, repairs, score
from kintoun.search.runner import run_search
from kintoun.targets import TargetContext, TargetFunction, load_target_from_object
from kintoun.verify import real_c_violation, verify_source


def _build_ppc_elf32(func_name: str, code_bytes: bytes, relocs: list[tuple[int, int, str, int]] | None = None) -> bytes:
    """Build a minimal valid ELF32 big-endian PowerPC relocatable object in memory."""
    relocs = relocs or []
    shstrtab = b"\x00.shstrtab\x00.text\x00.symtab\x00.strtab\x00.rela.text\x00"
    strtab_parts = [b"\x00", func_name.encode("utf-8") + b"\x00"]
    ext_names: dict[str, int] = {}
    str_off = len(b"".join(strtab_parts))
    for _off, _kind, sym_name, _add in relocs:
        if sym_name not in ext_names:
            ext_names[sym_name] = str_off
            bname = sym_name.encode("utf-8") + b"\x00"
            strtab_parts.append(bname)
            str_off += len(bname)
    strtab = b"".join(strtab_parts)

    # Symbols: 0=NULL, 1=func_name (STT_FUNC=2, STB_GLOBAL=1 => 0x12, section=2), 2..=externals (section=0)
    sym_entries = [
        struct.pack(">IIIBBH", 0, 0, 0, 0, 0, 0),
        struct.pack(">IIIBBH", 1, 0, len(code_bytes), 0x12, 0, 2),
    ]
    sym_idx: dict[str, int] = {}
    for name, off in ext_names.items():
        sym_idx[name] = len(sym_entries)
        sym_entries.append(struct.pack(">IIIBBH", off, 0, 0, 0x10, 0, 0))
    symtab = b"".join(sym_entries)

    rela_entries = [
        struct.pack(">IIi", off, (sym_idx[sym_name] << 8) | (kind & 0xFF), addend)
        for off, kind, sym_name, addend in relocs
    ]
    rela_text = b"".join(rela_entries)

    # Section layout: 0=NULL, 1=.shstrtab, 2=.text, 3=.symtab, 4=.strtab, 5=.rela.text
    ehdr_size = 52
    off_shstr = ehdr_size
    off_text = off_shstr + len(shstrtab)
    off_sym = off_text + len(code_bytes)
    off_str = off_sym + len(symtab)
    off_rela = off_str + len(strtab)
    shoff = off_rela + len(rela_text)

    sh_count = 6 if rela_text else 5
    ehdr = struct.pack(
        ">16sHHIIIIIHHHHHH",
        b"\x7fELF\x01\x02\x01" + b"\x00" * 9,
        1,        # ET_REL
        20,       # EM_PPC
        1,        # EV_CURRENT
        0,        # entry
        0,        # phoff
        shoff,
        0,        # flags
        52,       # ehsize
        0,        # phentsize
        0,        # phnum
        40,       # shentsize
        sh_count,
        1,        # shstrndx
    )

    def sh(name_off, sh_type, flags, offset, size, link=0, info=0, align=1, entsize=0):
        return struct.pack(">10I", name_off, sh_type, flags, 0, offset, size, link, info, align, entsize)

    shdrs = [
        sh(0, 0, 0, 0, 0),
        sh(shstrtab.index(b".shstrtab"), 3, 0, off_shstr, len(shstrtab)),
        sh(shstrtab.index(b".text"), 1, 6, off_text, len(code_bytes), align=4),
        sh(shstrtab.index(b".symtab"), 2, 0, off_sym, len(symtab), link=4, info=1, align=4, entsize=16),
        sh(shstrtab.index(b".strtab"), 3, 0, off_str, len(strtab)),
    ]
    if rela_text:
        shdrs.append(
            sh(shstrtab.index(b".rela.text"), 4, 0, off_rela, len(rela_text), link=3, info=2, align=4, entsize=12)
        )
    return ehdr + shstrtab + code_bytes + symtab + strtab + rela_text + b"".join(shdrs)


class _MockCompiler:
    """Synthetic compiler that maps C patterns to deterministic PPC32 machine code."""

    compiler_id = "mock-ppc"
    flags = ("-O2",)

    def __init__(self, target_code: bytes, wrong_code: bytes) -> None:
        self.target_code = target_code
        self.wrong_code = wrong_code

    def compile_c(self, src: Path, out_obj: Path) -> CompileResult:
        text = src.read_text(encoding="utf-8")
        if "SYNTAX_ERROR" in text:
            return CompileResult(1, "", "candidate.c:1: error: syntax error", out_obj)
        # Match when `u32` (flipped from `s32` by m_local_type / m_param_type) is present
        code = self.target_code if "u32 x" in text else self.wrong_code
        out_obj.write_bytes(_build_ppc_elf32("TestFunc", code))
        return CompileResult(0, "", "", out_obj)


class KintounTests(unittest.TestCase):
    def test_elf_parse_and_relocate_ppc(self) -> None:
        # bl 0x0 (0x48000001), blr (0x4E800020)
        raw = struct.pack(">II", 0x48000001, 0x4E800020)
        obj_bytes = _build_ppc_elf32("Foo", raw, relocs=[(0, 10, "Callee", 0)])
        elf = Object(obj_bytes)
        sym = elf.function("Foo")
        self.assertEqual(sym.size, 8)
        rels = elf.relocations(sym.section)
        self.assertEqual(len(rels), 1)
        self.assertEqual(rels[0].kind, "REL24")

        relocated = relocate_ppc(raw, [(0, "REL24", "Callee", 0)], {"Callee": 0x80001020}, 0x80001000)
        self.assertEqual(struct.unpack(">II", relocated)[0], 0x48000021)
        self.assertTrue(compare_bytes(relocated, relocated)["verified"])

    def test_sda_decode_and_symbol_name(self) -> None:
        objs = {0x803E4370: ("g_Counter", 4)}
        self.assertEqual(symbol_name(objs, 0x803E4370), "g_Counter")
        self.assertEqual(symbol_name(objs, 0x803E4372), "g_Counter+0x2")
        # lwz r3, 0x10(r13) -> op=32, rd=3, ra=13, imm=0x10
        word = (32 << 26) | (3 << 21) | (13 << 16) | 0x10
        refs = sda_references([word], objs, 0x803E4360, 0x803F4360)
        self.assertEqual(len(refs), 1)
        self.assertEqual(refs[0]["symbol"], "g_Counter")

    def test_real_c_guard(self) -> None:
        self.assertIsNone(real_c_violation("/* asm comment */\ns32 f(s32 a) { return a + 1; }\n"))
        self.assertIsNotNone(real_c_violation("void f(void) { __asm__(\"nop\"); }\n"))
        self.assertIsNotNone(real_c_violation("GLOBAL_ASM(\"foo.s\")\n"))

    def test_score_and_repairs(self) -> None:
        # li r3, 5 (0x38600005), blr (0x4E800020) vs li r3, 7 (0x38600007), blr
        ours = [0x38600005, 0x4E800020]
        target = [0x38600007, 0x4E800020]
        sc = score.score(ours, target)
        self.assertGreater(sc.pct, 0.0)
        src = "s32 Foo(void) {\n    return 5;\n}\n"
        reps = repairs.hypotheses(ours, target, src, 0x80001000, {}, {}, 0, 0)
        self.assertTrue(any(r["category"] == "literal" and r["target"] == 7 for r in reps))

    def test_mutations_and_permuter_generate_variants(self) -> None:
        src = (
            "s32 TestFunc(s32 a, s32 b) {\n"
            "    s32 x;\n"
            "    s32 y;\n"
            "    x = a + 1;\n"
            "    y = b + 2;\n"
            "    return x + y;\n"
            "}\n"
        )
        base_vars = list(base_mutations.mutations(src))
        self.assertGreater(len(base_vars), 3)
        perm_vars = list(permuter.variants(src, base_mutations, limit=12))
        self.assertGreater(len(perm_vars), 2)
        self.assertTrue(hasattr(mutations, "m_index_address"))
        self.assertTrue(callable(guidance.priorities))

    def test_end_to_end_verify_and_permute_with_cache(self) -> None:
        target_code = struct.pack(">II", 0x38600001, 0x4E800020)  # li r3, 1; blr
        wrong_code = struct.pack(">II", 0x38600000, 0x4E800020)   # li r3, 0; blr
        compiler = _MockCompiler(target_code, wrong_code)

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            target_o = tmp_path / "target.o"
            target_o.write_bytes(_build_ppc_elf32("TestFunc", target_code))
            ctx, tf = load_target_from_object(target_o)

            src_mismatch = "s32 TestFunc(void) {\n    s32 x;\n    x = 1;\n    return x;\n}\n"
            v1 = verify_source(src_mismatch, tf, ctx, compiler)
            self.assertFalse(v1["verified"])
            self.assertEqual(v1["status"], "mismatch")

            res = run_search(
                source=src_mismatch,
                target_fn=tf,
                ctx=ctx,
                compiler=compiler,
                budget_s=10.0,
                max_candidates=100,
                strategies=["systematic", "register_focus"],
                workers=2,
                cache_dir=tmp_path / "cache",
            )
            self.assertTrue(res["verified"])
            self.assertIn("u32 x", res["best"]["code"])

            # Second run hits SQLite cache
            cache = ResultCache(tmp_path / "cache")
            k = source_key(res["best"]["code"], f"{tf.name}@0x{tf.va:08X}:" + __import__("hashlib").sha256(tf.data).hexdigest()[:16], compiler.flags, compiler.compiler_id)
            self.assertIsNotNone(cache.get(k))

    def test_cli_init_and_info(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cfg_file = Path(tmp) / "kintoun.toml"
            rc = cli_main(["init", "--preset", "prodg-wine", "-o", str(cfg_file)])
            self.assertEqual(rc, 0)
            cfg = load_config(cfg_file)
            self.assertEqual(cfg.compiler.preset, "prodg-wine")
            self.assertEqual(cli_main(["-c", str(cfg_file), "info"]), 0)


if __name__ == "__main__":
    unittest.main()
