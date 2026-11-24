# Benchmarks

Kintoun has been trained through research and development on TNRP's 15 game codebase.

The numbers below come from a held out set: functions that were never used while Kintoun was developed or tuned, so the search could not have learned them.

## The test

* **Functions:** 69 real compiled functions from 14 commercial console titles, 24 to 164 bytes each (median 82). They come from four platforms and nine compiler setups.
* **Starting point:** the raw output of the `m2c` decompiler for each function, exactly as `m2c` prints it. Raw `m2c` output almost never compiles, so every function starts at 0% aligned.
* **Search:** `kintoun permute` with the same settings for every function: 30 seconds, at most 300 candidates, 1 worker, seed 0.
* **Measure:** the share of the target's instructions that the best candidate lines up with (aligned %), and how many functions reach a byte exact, relocation verified match.

Most matching decompilation work is about getting close, then finishing by hand. Aligned % is the number that shows how much of that work Kintoun does for you.

## Results by compiler (0.2.0, raw `m2c` start)

| Platform and compiler | Functions | Compiles | Exact | Mean aligned | Median aligned | 80% or better |
|---|---|---|---|---|---|---|
| GameCube, SN ProDG 3.9.3 | 5 | 5 | 0 | 85.9% | 85.2% | 4 |
| GameCube, MWCC GC 2.0 | 5 | 5 | 1 | 79.3% | 87.5% | 3 |
| GameCube, MWCC GC 1.2.5n | 5 | 5 | 0 | 55.7% | 50.0% | 1 |
| GBA, agbcc | 10 | 9 | 2 | 78.0% | 89.0% | 8 |
| PS2, ee-gcc 2.96 | 15 | 15 | 2 | 72.1% | 74.1% | 5 |
| PS2, MWCC PS2 3.0 | 5 | 4 | 0 | 15.2% | 15.4% | 0 |
| PSP, MWCC PSP 3.0.1 | 5 | 4 | 1 | 72.5% | 87.5% | 4 |
| PSP, psp-gcc 3.3.3 | 10 | 10 | 1 | 48.3% | 40.2% | 1 |
| PSP PRX modules, psp-gcc 3.3.3 | 9 | 8 | 1 | 55.4% | 57.1% | 3 |
| **All** | **69** | **65** | **8** | **63.6%** | **75.0%** | **29** |

## PowerPC: 0.2.0 against 0.1.0

The same 15 GameCube functions, run through both versions.

| Start | Version | Compiles | Exact | Start aligned | Best aligned | Median | Ended below start |
|---|---|---|---|---|---|---|---|
| Raw `m2c` output | 0.1.0 | 0 of 15 | 0 | 0% | 0% | 0% | none |
| Raw `m2c` output | **0.2.0** | **15 of 15** | **1** | 0% | **73.6%** | | none |
| Cleaned C (types and declarations added) | 0.1.0 | 11 of 15 | 0 | 53.3% | 52.4% | 65.7% | 3 |
| Cleaned C (types and declarations added) | **0.2.0** | **15 of 15** | **1** | 53.3% | **73.9%** | **83.3%** | **none** |

0.1.0 could not take raw `m2c` output at all, and from cleaned C it ended below its starting point on 3 of 15 functions. 0.2.0 repairs raw output on its own, adds about 20 points of alignment, and never ranks a candidate below the starting C.

## Notes

* These runs were capped at 300 candidates to keep the comparison equal. The 0.2.0 default is 3 minutes and 2,500 candidates, and `--thorough`, `--deep` and `--until-match` go further, so real runs usually end closer than this table.
* The weakest setup is PS2 MWCC 3.0. Its raw `m2c` output needs the most manual cleanup before the search has something to work with.
* No game code, decompiled game C or game data is part of this repository. The test fixtures in `tests/fixtures` are compiled from small original C files.

## Unseen 60-function stratified PS2 MWCC 3.0 benchmark (0.8.0)

In 0.2.0 above, PS2 MWCC 3.0 was Kintoun's hardest setup (5 functions, 15.2% mean aligned, 0 exact matches). To test 0.8.0 at full project scale without touching any of the 15 games used during development, `kintoun agent-bench select --count 60` sampled **60 unseen plain-C functions** (24 to 888 bytes) from a 16th commercial PS2 title compiled with `mwccps2` 3.0 (`-O4,p -nodefaults -c`):

* **5 byte-size tiers (12 functions each):** `tiny_24_64B`, `small_68_136B`, `medium_140_260B`, `large_264_480B`, `xlarge_484_960B`.
* **6 structural families (10 functions each):** `leaf_int`, `branch_guard`, `loop`, `float_fpu`, `call_chain`, `vtable_dispatch` (deduplicated by `shape_hash`).
* **Starting point:** raw `m2c` (`-t mipsee-mwcc-c --valid-syntax`) output for each function (0 of 60 compile out of the box).

### Headless `kintoun permute` (30s, 300 candidates, 1 worker, seed 0, zero AI)

| Slice | Functions | Compiles | Exact (`VERIFIED`) | Exact % | Mean aligned | Median aligned | 80% or better |
|---|---|---|---|---|---|---|---|
| **All 60 unseen functions** | **60** | **38** | **9** | **15.0%** | **47.1%** | **49.3%** | **22** |
| `tiny_24_64B` | 12 | 12 | 7 | 58.3% | 85.8% | 100.0% | 9 |
| `small_68_136B` | 12 | 8 | 2 | 16.7% | 45.6% | 46.3% | 4 |
| `medium_140_260B` | 12 | 7 | 0 | 0.0% | 36.3% | 20.8% | 4 |
| `large_264_480B` | 12 | 6 | 0 | 0.0% | 39.6% | 27.0% | 4 |
| `xlarge_484_960B` | 12 | 5 | 0 | 0.0% | 28.2% | 0.0% | 1 |
| Family: `leaf_int` | 10 | 10 | 7 | 70.0% | 89.9% | 100.0% | 8 |
| Family: `call_chain` | 10 | 8 | 2 | 20.0% | 59.7% | 66.6% | 4 |
| Family: `loop` | 10 | 6 | 0 | 0.0% | 45.7% | 48.4% | 4 |
| Family: `branch_guard` | 10 | 6 | 0 | 0.0% | 43.0% | 47.0% | 4 |
| Family: `vtable_dispatch` | 10 | 5 | 0 | 0.0% | 25.2% | 7.1% | 1 |
| Family: `float_fpu` | 10 | 3 | 0 | 0.0% | 19.2% | 0.0% | 1 |

### Zero-prior-context AI agent benchmark protocol (`kintoun agent-bench`)

Headless search is designed to seed and accelerate human or AI matching, especially on medium-to-xlarge C++ vtable, loop, and FPU functions. `kintoun agent-bench` provides a standardized, zero-leakage end-to-end benchmark for pairing any CLI coding agent with Kintoun:

1. **Stratified selection (`kintoun agent-bench select`):** Picks 60 plain-C functions balanced across all 5 byte-size tiers and 6 structural families (`shape_hash` deduplicated).
2. **Strict zero prior context (`kintoun agent-bench run`):** Each function runs in a fresh isolated temporary workspace (`--new-project`) containing only `kintoun.toml`, anonymous hex symbols (`fn_XXXXXXXX` / `D_XXXXXXXX`), `skills/kintoun-match/`, and `cand.c` (no project history, no cross-function memory, no game metadata).
3. **30-minute per-function ceiling (`--timeout 30m`):** Easy functions finish in under a minute while complex functions can iterate with `kintoun context`, hand edits, `KINTOUN_*` macros, `kintoun permute`, and `kintoun close` for up to 30 minutes (`1800s`). If a session hits the 30-minute limit mid-edit, the harness recovers the highest-ranked valid real-C candidate from `candidates.sqlite3` / `trajectories.jsonl`.
4. **Independent ground-truth audit:** Every output is re-verified outside the agent workspace with `verify_source(..., forbid_asm=True)`.

#### Whole set: one zero-prior-context agent, 30 minutes for all 60 functions

Each agent session received all 60 functions in one fresh workspace with a single 30-minute clock for the whole set (`kintoun agent-bench run --whole-set --timeout 30m`) and decided by itself how to split its time. Every agent got the same brief, the same raw `m2c` starting C and no access to any earlier attempt. Every function was then re-verified outside the workspace with `verify_source(..., forbid_asm=True)`.

| Stage | Functions | Compiles | Exact (`VERIFIED`) | Exact % | Mean aligned | Median aligned | 80% or better | 95% or better |
|---|---|---|---|---|---|---|---|---|
| Raw `m2c` seed | 60 | 0 | 0 | 0.0% | 0.0% | 0.0% | 0 | 0 |
| Headless `kintoun permute` (30s per function) | 60 | 38 | 9 | 15.0% | 47.1% | 49.3% | 22 | 9 |
| **Gemini 4 Neon (high) + Kintoun, 30 min whole set** | **60** | **60** | **13** | **21.7%** | **83.5%** | **88.6%** | **46** | **20** |
| **Claude Opus 5.5 (high) + Kintoun, 30 min whole set*** | **60** | **60** | **12** | **20.0%** | **79.3%** | **87.6%** | **41** | **18** |

\* Claude Opus 5.5 (high): session ended at 27.8 of the 30 minutes when the service's usage limit was reached.

| Size tier | Functions | Headless mean | Headless exact | Gemini 4 Neon exact | Gemini 4 Neon mean | Claude Opus 5.5 exact | Claude Opus 5.5 mean |
|---|---|---|---|---|---|---|---|
| `tiny_24_64B` | 12 | 85.8% | 7 | 10 | 96.4% | 9 | 92.4% |
| `small_68_136B` | 12 | 45.6% | 2 | 3 | 79.5% | 3 | 79.5% |
| `medium_140_260B` | 12 | 36.3% | 0 | 0 | 73.2% | 0 | 68.6% |
| `large_264_480B` | 12 | 39.6% | 0 | 0 | 89.5% | 0 | 83.8% |
| `xlarge_484_960B` | 12 | 28.2% | 0 | 0 | 78.8% | 0 | 72.4% |

| Family | Functions | Headless mean | Headless exact | Gemini 4 Neon exact | Gemini 4 Neon mean | Claude Opus 5.5 exact | Claude Opus 5.5 mean |
|---|---|---|---|---|---|---|---|
| `leaf_int` | 10 | 89.9% | 7 | 10 | 100.0% | 9 | 97.9% |
| `branch_guard` | 10 | 43.0% | 0 | 0 | 76.5% | 0 | 76.8% |
| `loop` | 10 | 45.7% | 0 | 1 | 74.6% | 1 | 68.1% |
| `float_fpu` | 10 | 19.2% | 0 | 0 | 89.6% | 0 | 84.6% |
| `call_chain` | 10 | 59.7% | 2 | 2 | 87.1% | 2 | 83.3% |
| `vtable_dispatch` | 10 | 25.2% | 0 | 0 | 73.1% | 0 | 65.4% |

All agents compile every function (22 did not with headless search alone). Exact matches come from the small functions; the 140 to 888 byte functions end roughly 65% to 90% aligned on average, a starting point for finishing by hand.

## Reproducing

### 1. Headless 30s baseline

Pick functions from a binary you own, decompile them with `m2c`, then for each one:

```bash
kintoun permute fn_80001234.c --func fn_80001234 --budget 30s --max-candidates 300 --workers 1 --seed 0 --json
```

The JSON output reports the input and best candidate, including `search.aligned_pct` and `different_bytes`.

### 2. Zero-prior-context 60-function agent benchmark

```bash
# 1. Deterministically select 60 stratified plain-C functions (12 per size tier, 10 per family)
kintoun agent-bench select --count 60 --seed 20261124 -o manifest_60.json

# 2a. One agent session for the whole set on one shared 30-minute clock (the agent splits its own time)
kintoun agent-bench run \
  --manifest manifest_60.json \
  --out-dir .kintoun/agent_bench_set \
  --whole-set \
  --runner agy \
  --model gemini-4-neon-high \
  --effort high \
  --timeout 30m \
  --concurrency 3 \
  -o REPORT.md

# 2b. Or one fresh agent per function with a 30-minute per-function limit (resumable via results.jsonl)
kintoun agent-bench run \
  --manifest manifest_60.json \
  --out-dir .kintoun/agent_bench \
  --runner agy \
  --model gemini-4-neon-high \
  --effort high \
  --timeout 30m \
  --concurrency 3 \
  -o REPORT.md
```
