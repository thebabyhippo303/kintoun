⁹# Kintoun

**Matching C decompilation for PowerPC, MIPS and ARM. One AI agent with Kintoun and 30 minutes took 60 raw `m2c` functions from a PS2 game it had never seen to 60 of 60 compiling, 13 exact matches and 83.5% aligned on average.**

Kintoun 0.8.0 is a standalone permuter, beam search engine and strict ELF32 verifier that needs nothing beyond the Python 3.11 standard library. It was built to match thousands of PowerPC functions for GameCube decompilation, including [dbzsagas-decomp](https://github.com/thebabyhippo303/dbzsagas-decomp), and now covers PowerPC, MIPS and ARM / Thumb, with a benchmark you can run on any command line agent, agent skills and an MCP server.

Kintoun is like a sister of [TNRP](https://nimbusrecomp.org), and sometimes they work together.

## Benchmark: 60 functions from a PS2 game Kintoun had never seen

60 functions from a commercial PS2 game outside the 15 game development set, built with Metrowerks for PS2. Every function starts from raw `m2c` output, which never compiles as is. Each agent got all 60 in one fresh, empty workspace with a single 30 minute clock for the whole set, the same brief and no earlier attempts. Every result was verified again outside the agent's workspace. Every run used Kintoun v0.8.0.

| Stage | Functions | Compiles | Exact (`VERIFIED`) | Exact % | Mean aligned | Median aligned | 80% or better | 95% or better |
|---|---|---|---|---|---|---|---|---|
| Raw `m2c` seed | 60 | 0 | 0 | 0.0% | 0.0% | 0.0% | 0 | 0 |
| Headless `kintoun permute` (30s per function) | 60 | 38 | 9 | 15.0% | 47.1% | 49.3% | 22 | 9 |
| **Gemini 4 Neon (high) + Kintoun, 30 min whole set** | **60** | **60** | **13** | **21.7%** | **83.5%** | **88.6%** | **46** | **20** |
| **Claude Fable 5.2 (high) + Kintoun, 30 min whole set*** | **60** | **60** | **13** | **21.7%** | **81.6%** | **88.0%** | **43** | **22** |
| **Claude Opus 5.5 (high) + Kintoun, 30 min whole set**** | **60** | **60** | **12** | **20.0%** | **79.3%** | **87.6%** | **41** | **18** |
| **Gemini 4 Carbon (high) + Kintoun, 30 min whole set** | **60** | **60** | **12** | **20.0%** | **78.2%** | **85.6%** | **38** | **19** |
| **Gemini 4 Hydrogen (high) + Kintoun, 30 min whole set***** | **60** | **60** | **12** | **20.0%** | **75.6%** | **85.2%** | **34** | **18** |
| **Muse Spark 1.3 (high) + Kintoun, 30 min whole set****** | **60** | **60** | **11** | **18.3%** | **71.7%** | **77.4%** | **28** | **14** |
| **Muse Wonder 1.0 (high) + Kintoun, 30 min whole set******* | **60** | **60** | **13** | **21.7%** | **70.0%** | **74.8%** | **28** | **17** |
| **Muse Wonder Full 1.0 (high) + Kintoun, 30 min whole set******** | **60** | **60** | **12** | **20.0%** | **69.4%** | **71.9%** | **28** | **15** |
| **Claude Sonnet 5.5 (high) + Kintoun, 30 min whole set********* | **60** | **60** | **12** | **20.0%** | **65.9%** | **78.8%** | **29** | **15** |
| **Claude Haiku 5.5 (high) + Kintoun, 30 min whole set********** | **60** | **60** | **10** | **16.7%** | **63.2%** | **70.1%** | **25** | **10** |
| **Grok 4.7 (high) + Kintoun, 30 min whole set** | **60** | **60** | **12** | **20.0%** | **58.5%** | **52.1%** | **24** | **14** |

\* Claude Fable 5.2 (high): session ended on its own after 23.1 of the 30 minutes.

\*\* Claude Opus 5.5 (high): session ended at 27.8 of the 30 minutes when the service's usage limit was reached.

\*\*\* Gemini 4 Hydrogen (high): session ended on its own after 26.4 of the 30 minutes.

\*\*\*\* Muse Spark 1.3 (high): session ended on its own after 22.8 of the 30 minutes.

\*\*\*\*\* Muse Wonder 1.0 (high): session ended on its own after 18.8 of the 30 minutes.

\*\*\*\*\*\* Muse Wonder Full 1.0 (high): session ended on its own after 27.2 of the 30 minutes.

\*\*\*\*\*\*\* Claude Sonnet 5.5 (high): session ended on its own after 17.1 of the 30 minutes.

\*\*\*\*\*\*\*\* Claude Haiku 5.5 (high): session ended on its own after 18.6 of the 30 minutes.

### By size

| Size tier | Functions | Headless mean | Headless exact | Gemini 4 Neon exact | Gemini 4 Neon mean | Claude Fable 5.2 exact | Claude Fable 5.2 mean | Claude Opus 5.5 exact | Claude Opus 5.5 mean | Gemini 4 Carbon exact | Gemini 4 Carbon mean | Gemini 4 Hydrogen exact | Gemini 4 Hydrogen mean | Muse Spark 1.3 exact | Muse Spark 1.3 mean | Muse Wonder 1.0 exact | Muse Wonder 1.0 mean | Muse Wonder Full 1.0 exact | Muse Wonder Full 1.0 mean | Claude Sonnet 5.5 exact | Claude Sonnet 5.5 mean | Claude Haiku 5.5 exact | Claude Haiku 5.5 mean | Grok 4.7 exact | Grok 4.7 mean |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| `tiny_24_64B` | 12 | 85.8% | 7 | 10 | 96.4% | 9 | 92.4% | 9 | 92.4% | 9 | 91.2% | 9 | 92.4% | 9 | 92.4% | 9 | 91.2% | 9 | 91.2% | 9 | 92.4% | 8 | 86.6% | 9 | 92.4% |
| `small_68_136B` | 12 | 45.6% | 2 | 3 | 79.5% | 4 | 83.1% | 3 | 79.5% | 3 | 78.8% | 3 | 77.4% | 2 | 76.5% | 4 | 75.6% | 3 | 74.4% | 3 | 75.2% | 2 | 65.1% | 3 | 71.0% |
| `medium_140_260B` | 12 | 36.3% | 0 | 0 | 73.2% | 0 | 69.3% | 0 | 68.6% | 0 | 75.9% | 0 | 70.7% | 0 | 65.8% | 0 | 67.0% | 0 | 65.1% | 0 | 63.0% | 0 | 64.3% | 0 | 53.1% |
| `large_264_480B` | 12 | 39.6% | 0 | 0 | 89.5% | 0 | 87.3% | 0 | 83.8% | 0 | 76.4% | 0 | 72.6% | 0 | 67.5% | 0 | 66.9% | 0 | 66.5% | 0 | 58.4% | 0 | 60.7% | 0 | 50.0% |
| `xlarge_484_960B` | 12 | 28.2% | 0 | 0 | 78.8% | 0 | 75.8% | 0 | 72.4% | 0 | 68.5% | 0 | 65.0% | 0 | 56.2% | 0 | 49.4% | 0 | 49.7% | 0 | 40.4% | 0 | 39.4% | 0 | 26.1% |

### By kind of function

| Family | Functions | Headless mean | Headless exact | Gemini 4 Neon exact | Gemini 4 Neon mean | Claude Fable 5.2 exact | Claude Fable 5.2 mean | Claude Opus 5.5 exact | Claude Opus 5.5 mean | Gemini 4 Carbon exact | Gemini 4 Carbon mean | Gemini 4 Hydrogen exact | Gemini 4 Hydrogen mean | Muse Spark 1.3 exact | Muse Spark 1.3 mean | Muse Wonder 1.0 exact | Muse Wonder 1.0 mean | Muse Wonder Full 1.0 exact | Muse Wonder Full 1.0 mean | Claude Sonnet 5.5 exact | Claude Sonnet 5.5 mean | Claude Haiku 5.5 exact | Claude Haiku 5.5 mean | Grok 4.7 exact | Grok 4.7 mean |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| `leaf_int` | 10 | 89.9% | 7 | 10 | 100.0% | 9 | 97.9% | 9 | 97.9% | 9 | 96.4% | 9 | 97.9% | 9 | 97.9% | 9 | 96.4% | 9 | 96.4% | 9 | 97.9% | 8 | 90.9% | 9 | 97.9% |
| `branch_guard` | 10 | 43.0% | 0 | 0 | 76.5% | 0 | 82.2% | 0 | 76.8% | 0 | 76.4% | 0 | 78.1% | 0 | 70.3% | 0 | 72.7% | 0 | 70.8% | 0 | 67.6% | 0 | 69.5% | 0 | 65.9% |
| `loop` | 10 | 45.7% | 0 | 1 | 74.6% | 1 | 69.6% | 1 | 68.1% | 1 | 63.0% | 1 | 65.1% | 0 | 68.3% | 1 | 62.8% | 1 | 68.5% | 1 | 67.0% | 0 | 62.1% | 1 | 53.0% |
| `float_fpu` | 10 | 19.2% | 0 | 0 | 89.6% | 0 | 88.0% | 0 | 84.6% | 0 | 78.7% | 0 | 70.8% | 0 | 58.9% | 0 | 53.0% | 0 | 51.5% | 0 | 40.0% | 0 | 37.1% | 0 | 27.8% |
| `call_chain` | 10 | 59.7% | 2 | 2 | 87.1% | 3 | 82.4% | 2 | 83.3% | 2 | 83.0% | 2 | 76.3% | 2 | 79.1% | 3 | 79.6% | 2 | 74.8% | 2 | 75.6% | 2 | 69.6% | 2 | 70.3% |
| `vtable_dispatch` | 10 | 25.2% | 0 | 0 | 73.1% | 0 | 69.4% | 0 | 65.4% | 0 | 71.5% | 0 | 65.7% | 0 | 55.5% | 0 | 55.6% | 0 | 54.2% | 0 | 47.2% | 0 | 50.0% | 0 | 36.3% |

Every agent compiles all 60 functions (22 did not with headless search alone).


• Timeline & Improvement: Collected between mid-October and October 25th before TNRP started; PowerPC starting alignment has since grown by roughly 40% following the open-source GPL release.

Dragon Ball Z: Sagas
• Functions Named: 9,281 out of 9,961 (93.17%)
• Functions Matched (Pure C): 6,636 out of 9,961 (66.62%)
• Code Bytes Matched: 991,716 out of 3,161,132

Kintoun has been trained through research and development on TNRP's 15 game codebase. On a held out benchmark of 69 real console functions it starts from raw `m2c` output and reaches 63.6% aligned on average (75% median), with 8 exact matches.

## Overseer benchmark: 500 functions from 16 games, one team, 30 minutes

500 functions from 16 commercial console games (PS2, PSP, GameCube and GBA), about 31 from each, built with eight compilers across GCC, SN Systems, Metrowerks and agbcc. None of them is in the 60 function benchmark or matched in any of our decompilation projects. Every function starts from raw `m2c` output.

One overseer agent gets all 500 in one fresh, empty workspace and a single 30 minute clock for the whole team. It starts as many worker agents as it sees fit, writes each one its own brief, follows their progress and moves work around; every worker stops when the clock runs out. Every team gets the same generic briefs, filled in from its run file. Neither side can see earlier attempts. Every result was verified again outside the workspace.

| Stage | Functions | Compiles | Exact (`VERIFIED`) | Exact % | Mean aligned | Median aligned | 80% or better | 95% or better |
|---|---|---|---|---|---|---|---|---|
| Raw `m2c` seed | 500 | 0 | 0 | 0.0% | 0.0% | 0.0% | 0 | 0 |
| Headless `kintoun permute` (30s per function) | 500 | 358 | 44 | 8.8% | 39.2% | 33.3% | 101 | 50 |
| **Gemini 4 Neon (high) overseer + Gemini 4 Hydrogen (high) workers + Kintoun, 30 min** | **500** | **500** | **198** | **39.6%** | **69.1%** | **84.4%** | **261** | **209** |
| **Claude Fable 5.2 (high) overseer + Claude Sonnet 5.5 (high) workers + Kintoun, 30 min** | **500** | **500** | **168** | **33.6%** | **67.4%** | **81.1%** | **254** | **192** |
| **Muse Wonder Full 1.0 (high) overseer + Muse Spark 1.3 (high) workers + Kintoun, 30 min** | **500** | **500** | **73** | **14.6%** | **51.5%** | **50.0%** | **132** | **77** |
| **Grok 4.7 (high) overseer + Grok 4.7 (high) workers + Kintoun, 30 min** | **500** | **500** | **64** | **12.8%** | **43.0%** | **33.9%** | **109** | **68** |

How each overseer ran its team:

| Overseer | Workers | Workers started | Most at once | Worker minutes | Workers it stopped | How it split the work |
|---|---|---|---|---|---|---|
| Gemini 4 Neon (high) | Gemini 4 Hydrogen (high) | 57 | 32 | 732 | 15 | a Kintoun triage of all 500 first, then two workers per game, then smaller rounds aimed at near misses |
| Claude Fable 5.2 (high) | Claude Sonnet 5.5 (high) | 101 | 40 | 895 | 16 | two workers per game, then a fresh worker for a share whenever one stopped, and merged shares late in the clock |
| Muse Wonder Full 1.0 (high) | Muse Spark 1.3 (high) | 16 | 16 | 428 | 0 | one worker per game for the whole clock |
| Grok 4.7 (high) | Grok 4.7 (high) | 4 | 4 | 76 | 0 | a breadth first Kintoun permute script over every function, smallest first, for the whole clock; at minute 10, four workers on groups of games fixing near misses by hand |

Full tables by size and kind are in [docs/BENCHMARKS.md](docs/BENCHMARKS.md). The overseer and worker briefs are generic templates (`src/kintoun/templates/overseer/`): a new overseer test only needs a run file with its models, effort, clock and worker limit.

## Beyond game development

Outside of game development, the same concept could be applied to the use of AI models to help adapt aging infrastructure and defense systems, restore lost manufacturing pipelines and tool chains, and allow modern and aging low and high level systems to natively speak to each other.

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

# Clean goto/temp artifacts on a verified match, watch edits live, synthesize headers, or export datasets:
kintoun clean src/player.c --func Player_Update --write
kintoun watch src/player.c --func Player_Update --auto-close-at 90
kintoun synth-headers -o include/synth_types.h
kintoun doctor --scan-dir tools
kintoun export-dataset -o dataset.jsonl

# Self-learning side-tree Engine Lab (for ENGINE-BUILDER subagents; promotes only on blind unseen wins):
kintoun engine init --builders 4
kintoun engine gate --candidate combined --count 40 --confirm-runs 2 --ablate --promote

# Reproducible 60-function zero-prior-context agent benchmark (30m per-function limit):
kintoun agent-bench select --count 60 -o manifest_60.json
kintoun agent-bench run --manifest manifest_60.json --whole-set --runner agy --model gemini-4-neon-high --effort high --timeout 30m -o REPORT.md

# Overseer benchmark: one overseer agent leads worker agents on one clock (run file from templates/overseer/run.example.toml):
kintoun overseer-bench run.toml --out-dir runs/overseer
```

## Plugging into `dbzsagas-decomp`

Copy [examples/dbzsagas-decomp/kintoun.toml](examples/dbzsagas-decomp/kintoun.toml) into your `dbzsagas-decomp` checkout, point `PRODG_DIR` to your SN ProDG 3.9.3 directory, and place your legally owned `main.dol` at `orig/GZEE70/sys/main.dol`:

```bash
export PRODG_DIR=/path/to/prodg_393
kintoun verify src/global/Assert_Fail.c --func Assert_Fail
kintoun permute src/MyClass/MyFunc.c --func MyClass__MyFunc --budget 60 --write
```

## What each version added

* **0.1.0**: built to match thousands of PowerPC functions for GameCube decompilation (including [dbzsagas-decomp](https://github.com/thebabyhippo303/dbzsagas-decomp))
* **0.2.0**: dedicated first-class **MIPS** and **ARM / Thumb** engines
* **0.3.0**: a single-machine governor, zero-LLM near-miss closer, multi-agent chess-clock queue, Overseer, and agent skills (`CLI-OVERSEER` and `kintoun-match`)
* **0.4.0**: binary xrefs, struct-field consensus, inlined-helper detection, bit-exact `.rodata` float & magic-division solving, wrong-compiler fingerprinting + `[[compiler_bands]]`, `kintoun probe-flags`, and `kintoun scratch` (`decomp.me`)
* **0.5.0**: pure-stdlib `KINTOUN_*` permutation macros (decomp-permuter `PERM_*` names accepted) + beam-search hybrid, `INCLUDE_ASM`/`GLOBAL_ASM` + `.map` project `import` & full-TU verified `integrate`, TF-IDF assembly similarity + logistic match calibration, and a single-file HTML Decomp Atlas (`kintoun atlas`)
* **0.6.0**: zero-config `objdiff.json` / `dtk` / `splat.yaml` ingestion, byte-verified post-match C cleanup (`kintoun clean`), live editor `kintoun watch`, factual binary struct/vtable header synthesis (`kintoun synth-headers`), `kintoun doctor`, and verifiable SFT/DPO dataset export (`kintoun export-dataset`)
* **0.7.0**: a self-learning side-tree Engine Lab (`kintoun engine`) and `ENGINE-BUILDER` subagent skill gated on blind unseen functions
* **0.8.0**: a stratified 60-function zero-prior-context CLI agent benchmark harness (`kintoun agent-bench`) and target-evidenced MIPS readonly/small-data constant pool verification

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
* [skills/ENGINE-BUILDER/SKILL.md](skills/ENGINE-BUILDER/SKILL.md) - side-tree engine evolution skill gated on blind unseen functions
* [skills/kintoun-match/SKILL.md](skills/kintoun-match/SKILL.md) - matcher skill & PowerPC / MIPS / ARM symptom-to-C lookup tables

## MCP server
An optional MCP server exposes 25 Kintoun tools (`verify`, `permute`, `info`, `doctor`, `check`, `context_pack`, `probe_flags`, `scratch`, `import_function`, `integrate_match`, `clean_match`, `synth_headers`, `atlas`, `export_dataset`, `score_candidate`, `revise_candidate`, `score_candidates`, `close_near_miss`, `claim_next`, `clock`, `submit_match`, `fail_claim`, `queue_status`, `engine_status`, and `engine_gate`). Install the optional extra, then start the server:

```bash
pip install -e ".[mcp]"
kintoun mcp
```


• Full tables by size and kind are in docs/BENCHMARKS.md.

## License

Kintoun's own source code is licensed under the **GNU General Public License v3.0 or later (`GPL-3.0-or-later`)**. No copyrighted game assets, ROMs, or proprietary compilers are included in this repository.

**Plain-language Output Exception:** Running Kintoun on your C files does **not** infect your decompilation project with the GPL. Under the **Kintoun Output Exception** (an additional permission under GNU GPLv3 Section 7), any C source files, mutated/permuted candidates, decompilations, or build outputs you create, modify, or verify using Kintoun are **not** derivative works of Kintoun and are **not** covered by the GPL. You may license your project's C code under any terms you choose, including CC0, public domain, MIT, BSD, or proprietary terms.

Only modifications or redistributions of Kintoun's own tool code remain under `GPL-3.0-or-later`. See [LICENSE](LICENSE) for the full GPLv3 text and the exact Kintoun Output Exception wording.
