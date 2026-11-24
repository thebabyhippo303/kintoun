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

## Reproducing

Pick functions from a binary you own, decompile them with `m2c`, then for each one:

```bash
kintoun permute fn_80001234.c --func fn_80001234 --budget 30s --max-candidates 300 --workers 1 --seed 0 --json
```

The JSON output reports the input and best candidate, including `search.aligned_pct` and `different_bytes`.
