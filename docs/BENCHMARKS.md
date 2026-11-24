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

#### 6-family zero-prior-context `gemini-4-neon-high` calibration sample (1 function per family, `<= 30m/fn`)

On a 6-function calibration draw spanning all 6 structural families (`leaf_int` 60B, `call_chain` 76B, `branch_guard` 160B, `vtable_dispatch` 172B, `loop` 204B, `float_fpu` 296B) from the unseen 60-function MWCC PS2 3.0 manifest:

| Stage | Functions | Compiles | Exact (`VERIFIED`) | Mean aligned | Median aligned | 80% or better | 95% or better |
|---|---|---|---|---|---|---|---|
| Raw `m2c` seed | 6 | 0 | 0 | 0.0% | 0.0% | 0 | 0 |
| Headless `kintoun permute` (30s) | 6 | 4 | 2 | 62.7% | 88.0% | 4 | 2 |
| **Zero-context `gemini-4-neon-high` (high, `<= 30m/fn`) + Kintoun** | **6** | **6** | **2** | **94.9%** | **97.1%** | **6** | **3** |

Notably, on the two C++/control-flow functions where 30-second headless search could not compile raw `m2c` (`0.0%`), zero-context `gemini-4-neon-high` paired with Kintoun raised `vtable_dispatch` (172B) from `0.0%` to `93.0%` aligned and `branch_guard` (160B) from `0.0%` to `82.5%` aligned, while bringing the 296B `float_fpu` function to `100.0%` instruction alignment (`2 / 296` bytes remaining).

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

# 2. Run a zero-prior-context CLI agent with a 30-minute per-function limit (resumable via results.jsonl)
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
