# Changelog

## 0.5.0

Kintoun has been trained through research and development on TNRP's 15 game codebase.

### `KINTOUN_*` permutation macros + beam search hybrid
* **User directed permutation macros in pure stdlib (`macros.py`, `runner.py`):** Supports `KINTOUN_ALT` / `KINTOUN_GENERAL`, `KINTOUN_INT`, `KINTOUN_LINESWAP`, `KINTOUN_ONCE`, `KINTOUN_VAR`, `KINTOUN_SAMELINE` / `KINTOUN_FORCE_SAMELINE`, `KINTOUN_RANDOMIZE` and `KINTOUN_IGNORE` with `(,)` comma escapes, with no `cpp` or C parser dependency. decomp-permuter's `PERM_*` names are accepted as aliases, so existing annotated files work unchanged. Kintoun evaluates the macro space and feeds the top scoring expansions directly into its 12 parent beam search, target directed mutations and register permuter.

### `INCLUDE_ASM` / `GLOBAL_ASM` project importer, linker `.map` parser and verified post match integrator
* **Repo importer and header slicer (`project_io.py`, `kintoun import`, `kintoun_import_function`):** Parses GNU `ld`, Metrowerks `mwld` and `dtk` `.map` files, extracts per file `-I` / `-D` / optimization flags from `compile_commands.json` and `build.ninja`, transitively slices `typedef` / `struct` / `union` / `enum` definitions from local project headers without running external `cpp`, and builds standalone compilable candidate `.c` files from `INCLUDE_ASM` or `#pragma GLOBAL_ASM` stubs.
* **Atomic verified post match integrator (`project_io.py`, `kintoun integrate`, `kintoun_integrate_match`, `--integrate`):** Splices a matched C function back into its multi function `.c` file (replacing `INCLUDE_ASM` or `GLOBAL_ASM`), strips duplicate declarations and strictly verifies that the integrated translation unit still compiles and links byte exact before writing to disk.

### TF IDF assembly similarity, logistic win calibration, HTML Decomp Atlas and race abort
* **Per ISA opcode bigram TF IDF similarity and logistic model (`similarity.py`, `inspect_fn.py`):** Retrieves the top structurally similar already matched `(asm, C)` functions and solved callers in `kintoun context` across PowerPC, MIPS and ARM/Thumb in milliseconds using pure stdlib TF IDF cosine similarity, and fits an L2 logistic match probability model (`estimated_match_prob`) as projects accumulate solved and timed out functions.
* **Single file interactive HTML Decomp Atlas (`atlas.py`, `kintoun atlas`, `kintoun_atlas`):** Generates a self contained `atlas.html` dashboard (2D PCA structural scatter map, module coverage bars, searchable function table sorted by match odds or near miss %, disassembly drawer and 1 click CLI copy) that works offline and loads nothing external.
* **Background solved early abort signal (`queue.py`, `candidates.py`, `mcp_server.py`):** When background `close`, `overseer` or another worker verifies a function, subsequent `score_candidate` / `revise_candidate` calls immediately return `already_verified: true` without burning redundant compile slots.

## 0.4.0

Kintoun has been trained through research and development on TNRP's 15 game codebase.

### Binary cross references, struct consensus, inlined helpers and exact constants
* **Incoming xrefs and struct field consensus (`xref.py`, `kintoun context`):** Indexes incoming direct callers (`bl`, `jal`, `bl`/`blx`), vtable and jump table pointer slots, and struct offset type consensus (`+0x1C -> s16`, `+0x44 -> f32`) mined from matched `src/` files.
* **Inlined helper detector (`xref.py`):** Hashes normalized 5 instruction sliding windows across the target binary to flag repeated `static inline` helper sequences inside target functions and link matched peers.
* **Bit exact `.rodata` float and magic division solver (`constants.py`, `runner.py`):** Decodes 32/64 bit IEEE 754 words into shortest bit exact round trip C float literals (recognizing `1.0f / N` and trig ratios), snaps 1 to 3 ULP rounded float candidates during `permute`, and inverts reciprocal magic multiply constants (`0x55555556` -> `x / 3`, `0x66666667` -> `x / 5`, etc.).

### Wrong compiler detection, `[[compiler_bands]]`, flag prober and `decomp.me` scratches
* **Wrong compiler fingerprinter and per range overrides (`compiler_id.py`, `config.py`, `compiler.py`):** Fingerprints compiler codegen idioms across PowerPC (`prodg` vs `mwcc`), MIPS (`ee-gcc`/`psp-gcc` vs `mwcc`/`snc`) and ARM/Thumb (`agbcc` vs EABI/`mwccarm`), warns in `kintoun check` on mismatches, and adds `[[compiler_bands]]` in `kintoun.toml` so mixed compiler binaries route SDK/middleware address ranges to their own compiler preset automatically.
* **Per file compiler flag prober (`prober.py`, `kintoun probe-flags`, `kintoun_probe_flags`):** Compiles a rough C draft across preset flag matrices (`-O1/-O2/-O3/-Os`, `-O4,p/-O4,s`, `-G0/-G8`, `-fp hardware/fmadd`, `-inline auto/deferred/off`) in parallel and ranks them by alignment %.
* **One command `decomp.me` scratch runner (`scratch.py`, `kintoun scratch`, `kintoun_scratch`):** Pulls a `decomp.me` scratch by slug or URL (or offline JSON bundle), maps compiler and flags onto Kintoun presets, and runs local multi core beam search plus near miss closing.

## 0.3.0

Kintoun has been trained through research and development on TNRP's 15 game codebase.

### Single machine resource governor and candidate store
* **3 tier compile governor (`governor.py`, `kintoun warm-wine`, `--governed`):** Coordinates concurrent compiles across processes on one machine (`interactive`, `search` and `background` priority tiers), deduplicates identical concurrent compiles across 64 lock stripes, auto tunes duty cycle from active working set memory, Linux PSI and swap in rate, and manages persistent `wineserver` sessions for Windows compilers under Wine.
* **Surgical candidate revisions (`candidates.py`):** Content addressed `cand_<12hex>` store that caches both strict verification scores and deterministic compiler errors, with single match `revise_candidate` patches and parallel `score_candidates` batch scoring.

### Inspection, near miss closer and benchmark lab
* **Blocker check and context packs (`inspect_fn.py`, `ppc_disasm.py`, `kintoun check`, `kintoun context`):** Per architecture non plain C instruction checks (paired single, COP0/VU0/VFPU, MCR/MRC/SWI, cache ops and trap words), `0..100` static difficulty scoring (`easy`, `medium`, `hard`, `brutal`), a pure stdlib PowerPC disassembler alongside MIPS and ARM, and one call ~1.5k token function briefs.
* **Zero AI near miss closer (`closer.py`, `kintoun close`):** Classifies strict assembly diffs across PowerPC, MIPS and ARM into seven mismatch classes (`register_allocation`, `instruction_order`, `missing_cast`, `stack_layout`, `constant_literal`, `branch_shape`, `float_shape`) and runs 1 to 2 targeted search passes, saving `.kintoun/hints/` when improved.
* **Benchmark runner and prior learner (`lab.py`, `kintoun bench`):** Runs JSON benchmark manifests with zero regression checks against a baseline report and learns empirical mutation family priors (`--learn-priors`).

### Multi agent queue, Overseer and agent skills
* **Work queue with time limits (`queue.py`, `kintoun queue`, 14 MCP tools):** SQLite WAL multi agent queue supporting simultaneous claims per agent, enforced per function time clocks (refusing early non structural give ups), timeout quarantine and `unquarantine`, strict re verification on submit and research note logging.
* **Out of the box Overseer (`overseer.py`, `kintoun overseer`):** Runs with `--brain none` ($0 code only reflexes, no API key needed), `--brain single` (one API key or local OpenAI compatible Ollama/vLLM endpoint for state gated triage, rule checks and steering under a daily USD cap) or `--brain dual` (separate fast triage/check brain and main brain with fallback).
* **Agent skill packs and `AGENTS.md` (`AGENTS.md`, `skills/CLI-OVERSEER/`, `skills/kintoun-match/`):** Adds root `AGENTS.md` (version synced onboarding and setup guide for AI coding agents), `CLI-OVERSEER` for standard CLI coding agents to orchestrate Matcher and Namer subagents (standalone or alongside `kintoun overseer`), and `kintoun-match` with PowerPC, MIPS and ARM/Thumb symptom to C lookup tables. See [docs/WORKFLOWS.md](docs/WORKFLOWS.md).

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
