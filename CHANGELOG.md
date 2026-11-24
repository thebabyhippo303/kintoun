# Changelog

## 0.2.0

Kintoun has been trained through research and development on TNRP's 15 game codebase.

### New architectures
* **MIPS (`mips_elf`):** PS2 (`ee-gcc`, `mwccps2`), PSP (`psp-gcc`, `mwccpsp`, `pspsnc`, including PRX modules) and generic MIPS32 in either byte order.
* **ARM and Thumb (`arm_elf`):** GBA (`agbcc`, `arm-none-eabi-gcc`) and Nintendo DS (`mwccarm`, `armcc`), with ARM, Thumb, Thumb 2 and inline literal pools.
* Each architecture has its own reader, relocation linker, scoring, disassembler, register permuter, repairs and seeds. See [docs/ARCHITECTURES.md](docs/ARCHITECTURES.md).

### Better search on every architecture
* Raw `m2c` output is repaired automatically, so a search can start from it directly (now on PowerPC too).
* Candidates are ranked by alignment first, so the best result never falls below the starting C.
* The search no longer stops early. It keeps a beam of the best candidates and chains two and three step mutations until it matches or runs out of budget.
* New search length options: `--quick`, `--thorough`, `--deep`, `--until-match`, `--time`, `--mode` and `--plateau`. The default is now 3 minutes and 2,500 candidates (was 1 minute and 600).
* PowerPC gains directed families that read the target's instructions: float, fused multiply add and compare forms, switch lowering, load and store scheduling and stack frame unions.
* On a held out benchmark of 69 functions, PowerPC went from 52.4% to 73.9% aligned from the same starting C, and from not compiling to 73.6% aligned from raw `m2c` output. See [docs/BENCHMARKS.md](docs/BENCHMARKS.md).

### Other changes
* `search/mutations.py` is split into seven themed modules. Every definition is unchanged, and `kintoun.search.mutations` still exports all of them.
* The MCP `kintoun_permute` tool accepts `mode`, duration strings and `plateau`.
* New docs: [docs/USAGE.md](docs/USAGE.md), [docs/ARCHITECTURES.md](docs/ARCHITECTURES.md), [docs/BENCHMARKS.md](docs/BENCHMARKS.md).
* 69 small test objects compiled with the real toolchains from original C, with the exact commands in `tests/fixtures/BUILD.txt`, and a GitHub Actions workflow that runs the tests.
* A plain language License section in the README.

### Unchanged
* All 0.1.0 commands, options, config keys, presets and MCP tools still work. The PowerPC reader, relocation code and original scorer are byte for byte the same as 0.1.0.

## 0.1.0

First release: PowerPC matching C permuter and strict relocation verifier for GameCube decompilation.
