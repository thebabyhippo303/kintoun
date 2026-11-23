# NIM-DTK

**Compiler-agnostic matching-C decompilation permuter, beam-search engine, and strict ELF verifier.**

NIM-DTK is a standalone, zero-dependency (Python 3.11+ stdlib) matching-C search tool originally developed to match thousands of PowerPC functions for GameCube decompilation (including [dbzsagas-decomp](https://github.com/thebabyhippo303/dbzsagas-decomp)) and now open-sourced for any decompilation project.

## What makes NIM-DTK different
* **Real C only:** Rejects inline assembly, `GLOBAL_ASM`, naked functions, and raw `.long`/`.4byte` directives.
* **Strict relocation-exact verification:** Parses ELF32 relocations directly (`REL24`, `REL14`, `ADDR16_HA`/`LO`, `EMB_SDA21`, `SDAREL16`) and compares relocated machine-code bytes 1:1 against the target binary.
* **Score-guided real-C mutations + live-range register permuter:** Combines 30+ compiler-codegen mutation families (declaration order, variable splitting, temp merging, branch polarity, loop shapes, type/cast flips, load splitting, evaluation order) with instruction-backed repair hypotheses (`callee`, `global`, `literal`, `field_offset`, `frame`, `block_layout`).
* **Compiler-agnostic:** Works with SN ProDG (under Wine), Metrowerks CodeWarrior / MWCC (under Wine), `powerpc-eabi-gcc`, or any custom command template via `nim-dtk.toml`.
* **Local SQLite cache & parallel workers:** Zero external daemon, zero fleet/server setup — runs locally on any contributor's machine.

## Quickstart

```bash
# Install from source (Python 3.11+, stdlib only)
pip install -e .

# Create a starter nim-dtk.toml in your decomp repo
nim-dtk init --preset prodg-wine   # or: mwcc-wine, custom

# Verify a single C file against a target function from your DOL + symbols.txt
nim-dtk verify src/MyClass/MyFunc.c --func MyClass__MyFunc

# Or verify against a standalone target .o file (e.g. from decomp.me)
nim-dtk verify candidate.c --target target.o

# Run parallel real-C permutation search (writes back on exact match with --write)
nim-dtk permute src/MyClass/MyFunc.c --func MyClass__MyFunc --budget 60 --write
```

## Plugging into `dbzsagas-decomp`

Copy [examples/dbzsagas-decomp/nim-dtk.toml](examples/dbzsagas-decomp/nim-dtk.toml) into your `dbzsagas-decomp` checkout, point `PRODG_DIR` to your SN ProDG 3.9.3 directory, and place your legally owned `main.dol` at `orig/GZEE70/sys/main.dol`:

```bash
export PRODG_DIR=/path/to/prodg_393
nim-dtk verify src/global/Assert_Fail.c --func Assert_Fail
nim-dtk permute src/MyClass/MyFunc.c --func MyClass__MyFunc --budget 60 --write
```

## Documentation
* [docs/CONFIG.md](docs/CONFIG.md) — `nim-dtk.toml` schema and options
* [docs/COMPILERS.md](docs/COMPILERS.md) — Setting up SN ProDG, MWCC, and custom compilers

## License & Output Exception
NIM-DTK itself is licensed under the **GNU General Public License v3.0 or later (GPL-3.0-or-later)** — see [LICENSE](LICENSE). No copyrighted game assets, ROMs, or proprietary compilers are included.

**Output / Decompilation Exception:** Running NIM-DTK on your source files does **not** place your C source code, decompilations, or build outputs under the GPL. Any C code written, mutated, permuted, or verified using NIM-DTK is **not** a derivative work of NIM-DTK and may be licensed however its authors choose (including CC0 / Public Domain, MIT, or any other license).
