# Kintoun

**Compiler-agnostic matching-C decompilation permuter, beam-search engine, and strict ELF32 verifier for PowerPC, MIPS, and ARM.**

Kintoun is a standalone, zero-dependency (Python 3.11+ stdlib) matching-C search tool originally developed to match thousands of PowerPC functions for GameCube decompilation (including [dbzsagas-decomp](https://github.com/thebabyhippo303/dbzsagas-decomp)), expanded in **0.2.0** with dedicated first-class **MIPS** and **ARM / Thumb** engines, expanded in **0.3.0** with a single-machine governor, zero-LLM near-miss closer, multi-agent chess-clock queue, Overseer, and agent skills (`CLI-OVERSEER` and `kintoun-match`), expanded in **0.4.0** with binary xrefs, struct-field consensus, inlined-helper detection, bit-exact `.rodata` float & magic-division solving, wrong-compiler fingerprinting + `[[compiler_bands]]`, `kintoun probe-flags`, and `kintoun scratch` (`decomp.me`), and expanded in **0.5.0** with pure-stdlib `PERM_*` / `KINTOUN_*` user macros + beam-search hybrid, `INCLUDE_ASM`/`GLOBAL_ASM` + `.map` project `import` & full-TU verified `integrate`, zero-Torch TF-IDF assembly similarity + logistic match calibration, and a single-file HTML Decomp Atlas (`kintoun atlas`).

Kintoun has been trained through research and development on TNRP's 15 game codebase. On a held out benchmark of 69 real console functions it starts from raw `m2c` output and reaches 63.6% aligned on average (75% median), with 8 exact matches. See [docs/BENCHMARKS.md](docs/BENCHMARKS.md).

## What makes Kintoun different
* **Real C only:** Rejects inline assembly, `GLOBAL_ASM`, naked functions, and raw `.long`/`.4byte`/`.word` directives.
* **Dedicated per-architecture relocation-exact verification (no shallow generic layer):**
  * **PowerPC (`ppc_elf`):** Strict ELF32 big-endian verifier (`REL24`, `REL14`, `ADDR16_HA`/`LO`, `EMB_SDA21`, `SDAREL16`, DOL + `symbols.txt` and standalone `.o` linking), stdlib disassembler, `m2c` C89 seed repair + `r13`/`r2` SDA & raw `lis+addi` DOL address rebasing (`ppc_seeds`), and all 52 target-instruction-directed mutations (`mutations.directed`).
  * **MIPS (`mips_elf`):** Both `SHT_REL` and `SHT_RELA`, little- and big-endian, paired/multi-`HI16` + orphaned-`LO16` (including `_gp_disp`), `GPREL16`/`GPREL32` + `.reginfo`/`.MIPS.options`/`SceModuleInfo` `$gp` extraction, PSP `ET_SCE_PSP_PRX` (`0xFFA0`) auto-relocation, `26`, `PC16`, `LITERAL`, delay-slot-aware alignment, stdlib disassembler (MIPS I-IV, R5900 EE `lq`/`sq`, Allegrex, COP1), register-class live-range permuter (`$v`, `$a`, `$t`, `$s`, `$f`, `HI`/`LO`), target-instruction-guided mutations (`mips_mutations`), `m2c` seed repairs (`mips_seeds`), and MIPS repair hypotheses.
  * **ARM / Thumb (`arm_elf`):** `$a`/`$t`/`$d` mapping-symbol segmentation, A32 + Thumb-16 + Thumb-2 mixed-width scoring and stdlib disassembly, `SHT_REL` and `SHT_RELA` (`ABS32`, `REL32`, `PC24`, `CALL`, `JUMP24`, `THM_CALL`, `THM_JUMP*`, `MOVW`/`MOVT`, `THM_PC8`/`PC12`), relocation-aware inline literal-pool comparison, Thumb low-register (`r0-r7`) permuter, `$d` literal-pool struct-base rebasing (`arm_seeds`), target-guided ARM/Thumb mutations (`arm_mutations`), and interworking (`BL` vs `BLX`) / Thumb-width repair hypotheses.
* **Compiler-agnostic presets:** Works with SN ProDG (`prodg-wine`, `pspsnc`), Metrowerks MWCC (GameCube/Wii `mwcc-wine`, PS2 `mwccps2`, PSP `mwccpsp`, and DS `mwccarm`), `ee-gcc` (PS2), `psp-gcc` (PSP), `mips-gcc`, `agbcc` (GBA, with integrated `cpp` preprocessing), `arm-none-eabi-gcc`, `armcc`, or any custom command template in `kintoun.toml` (supports both Wine and `wibo`).
* **Out-of-the-box single-machine governor, queue, & Overseer:** Includes a 3-tier cross-process compile governor + zram-aware pressure auto-tuner, surgical `revise_candidate` cache, `$0` diff-classified near-miss closer, SQLite chess-clock multi-agent queue, `kintoun overseer` (`--brain none`, `--brain single`, or `--brain dual`), and `CLI-OVERSEER` / `kintoun-match` agent skills.

## Quickstart

```bash
# Install from source (Python 3.11+, stdlib only)
pip install -e .

# Create a starter kintoun.toml in your decomp repo
# Presets: prodg-wine, mwcc-wine, ee-gcc, mwccps2, psp-gcc, mwccpsp, pspsnc, mips-gcc, agbcc, arm-none-eabi-gcc, mwccarm, armcc, custom
kintoun init --preset prodg-wine

# Verify a single C file against a target function from your binary/DOL + symbols.txt
kintoun verify src/MyClass/MyFunc.c --func MyClass__MyFunc

# Or verify against a standalone target .o file (PowerPC, MIPS, or ARM/Thumb auto-detected)
kintoun verify candidate.c --target target.o

# Run parallel real-C permutation search (default 3m / 2500 tries; writes back on exact match with --write)
kintoun permute src/MyClass/MyFunc.c --func MyClass__MyFunc --write

# Search duration & depth presets / flags:
#   --quick (15s/250), --thorough (10m/10k), --deep (30m/50k), --until-match, or --time 5m --workers 8
kintoun permute src/MyClass/MyFunc.c --func MyClass__MyFunc --thorough --workers 8 --write

# Fast plain-C check, ~1.5k-token context pack, and zero-LLM diff-classified near-miss closer:
kintoun check --func MyClass__MyFunc
kintoun context --func MyClass__MyFunc
kintoun close src/MyClass/MyFunc.c --func MyClass__MyFunc --write

# Multi-agent queue & out-of-the-box overseer ($0 code-only, single-API, or dual-API brain):
kintoun queue init && kintoun queue status
kintoun overseer once --brain none

# Probe optimal per-file compiler flags or run a decomp.me scratch locally:
kintoun probe-flags src/MyClass/MyFunc.c --func MyClass__MyFunc
kintoun scratch https://decomp.me/scratch/abc123 --out matched.c

# Import an INCLUDE_ASM/GLOBAL_ASM function, splice a match back into its TU, or build an HTML Atlas:
kintoun import src/player.c --func Player_Update -o cand.c
kintoun integrate cand.c --into src/player.c --func Player_Update
kintoun atlas -o atlas.html
```

## Plugging into `dbzsagas-decomp`

Copy [examples/dbzsagas-decomp/kintoun.toml](examples/dbzsagas-decomp/kintoun.toml) into your `dbzsagas-decomp` checkout, point `PRODG_DIR` to your SN ProDG 3.9.3 directory, and place your legally owned `main.dol` at `orig/GZEE70/sys/main.dol`:

```bash
export PRODG_DIR=/path/to/prodg_393
kintoun verify src/global/Assert_Fail.c --func Assert_Fail
kintoun permute src/MyClass/MyFunc.c --func MyClass__MyFunc --budget 60 --write
```

## Documentation
* [AGENTS.md](AGENTS.md) - setup, workflow, and maintenance playbook for AI coding agents
* [docs/USAGE.md](docs/USAGE.md) - a full matching session: setup, verify, permute, search length, reading results, MCP
* [docs/ARCHITECTURES.md](docs/ARCHITECTURES.md) - what each engine (PowerPC, MIPS, ARM and Thumb) reads, links, scores and repairs
* [docs/BENCHMARKS.md](docs/BENCHMARKS.md) - held out benchmark results by platform and compiler
* [docs/WORKFLOWS.md](docs/WORKFLOWS.md) - single-machine governor, Wine warmer, near-miss closer, multi-agent queue, and single/dual-brain Overseer
* [CHANGELOG.md](CHANGELOG.md) - what changed in each version
* [docs/CONFIG.md](docs/CONFIG.md) - `kintoun.toml` schema, governor, and `[overseer]` options
* [docs/COMPILERS.md](docs/COMPILERS.md) - Setting up ProDG, MWCC, `ee-gcc`, `psp-gcc`, `mips-gcc`, `agbcc`, `arm-none-eabi-gcc`, and `mwccarm`
* [skills/CLI-OVERSEER/SKILL.md](skills/CLI-OVERSEER/SKILL.md) - orchestrator skill delegating to Matcher and Namer subagents
* [skills/kintoun-match/SKILL.md](skills/kintoun-match/SKILL.md) - matcher skill & PowerPC / MIPS / ARM symptom-to-C lookup tables

## MCP server
An optional MCP server exposes 19 Kintoun tools (`verify`, `permute`, `info`, `check`, `context_pack`, `probe_flags`, `scratch`, `import_function`, `integrate_match`, `atlas`, `score_candidate`, `revise_candidate`, `score_candidates`, `close_near_miss`, `claim_next`, `clock`, `submit_match`, `fail_claim`, and `queue_status`). Install the optional extra, then start the server:

```bash
pip install -e ".[mcp]"
kintoun mcp
```

## License

Kintoun's own source code is licensed under the **GNU General Public License v3.0 or later (`GPL-3.0-or-later`)**. No copyrighted game assets, ROMs, or proprietary compilers are included in this repository.

**Plain-language Output Exception:** Running Kintoun on your C files does **not** infect your decompilation project with the GPL. Under the **Kintoun Output Exception** (an additional permission under GNU GPLv3 Section 7), any C source files, mutated/permuted candidates, decompilations, or build outputs you create, modify, or verify using Kintoun are **not** derivative works of Kintoun and are **not** covered by the GPL. You may license your project's C code under any terms you choose, including CC0, public domain, MIT, BSD, or proprietary terms.

Only modifications or redistributions of Kintoun's own tool code remain under `GPL-3.0-or-later`. See [LICENSE](LICENSE) for the full GPLv3 text and the exact Kintoun Output Exception wording.
