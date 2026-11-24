# Using Kintoun

This guide walks through a full matching session: set up a project, check a function, search for a closer or exact match, and read the results. For every `kintoun.toml` key see [CONFIG.md](CONFIG.md); for compiler setup see [COMPILERS.md](COMPILERS.md).

## 1. Install

```bash
git clone https://github.com/thebabyhippo303/kintoun.git
cd kintoun
pip install -e .            # Python 3.11 or newer, no other dependencies
pip install -e ".[mcp]"     # optional: the MCP server
```

You can also run it without installing: `PYTHONPATH=src python3 -m pytest -q tests` runs the test suite, and the `kintoun` command is `kintoun.cli:main`.

## 2. Create a project

Run `kintoun init` in the root of your decompilation project and pick the preset for your compiler:

```bash
kintoun init --preset prodg-wine     # GameCube, SN ProDG under Wine
kintoun init --preset mwcc-wine      # GameCube / Wii, Metrowerks under Wine
kintoun init --preset ee-gcc         # PS2, Sony ee-gcc
kintoun init --preset mwccps2        # PS2, Metrowerks
kintoun init --preset psp-gcc        # PSP, psp-gcc (Allegrex)
kintoun init --preset mwccpsp        # PSP, Metrowerks
kintoun init --preset pspsnc         # PSP, SN SNC
kintoun init --preset mips-gcc       # generic MIPS32, either byte order
kintoun init --preset agbcc          # GBA, agbcc
kintoun init --preset arm-none-eabi-gcc
kintoun init --preset mwccarm        # Nintendo DS, Metrowerks
kintoun init --preset armcc          # ARM RealView / ADS
kintoun init --preset custom         # any compiler, through a command template
```

This writes `kintoun.toml`. Point it at your compiler and at the target: a GameCube DOL plus `symbols.txt`, a MIPS or ARM binary (flat image, ELF executable or PSP PRX) plus symbols, or nothing at all if you compare against single `.o` files. `kintoun info` prints the configuration Kintoun resolved.

## 3. Check a function

```bash
kintoun verify fn_80012345.c --func fn_80012345
kintoun verify my_func.c --target expected/my_func.o
```

`--func` takes a symbol name or a `0xADDRESS` from your symbols file. `--target` compares against a standalone object instead. On MIPS and ARM binaries without symbols you can also give an address and size directly, as `0xADDR:0xSIZE`.

Kintoun compiles the C, links it the way the target was linked (relocations, small data bases, literal pools, call targets), and compares the result byte for byte. You get one of:

| Status | Meaning |
|---|---|
| `VERIFIED` | Byte exact after relocation. The function matches. |
| `MISMATCH` | It compiles, but some instructions differ. A side by side diff shows where. |
| `UNRESOLVED` | It compiles, but a symbol or call could not be linked to the target. |
| `COMPILE_ERROR` | The compiler rejected the C. The error is shown. |

`--lines N` sets how many diff lines to print and `--json` prints everything, including `search.aligned_pct` (how much of the target the candidate lines up with) and `different_bytes`.

Only real C is accepted. Inline assembly, `GLOBAL_ASM`, naked functions and raw data directives are rejected, so a `VERIFIED` result is always a real decompilation.

## 4. Search

```bash
kintoun permute fn_80012345.c --func fn_80012345 --write
```

`permute` mutates the C (statement order, temporaries, types, casts, branch shapes, loop forms, register lifetimes and many more) and keeps the candidates that line up better with the target. It also reads the target's instructions to propose direct repairs: the right callee, global, constant, struct offset or stack frame. Candidates are ranked by alignment first, so the best result is never worse than the C you started from.

You can start from raw `m2c` output. Kintoun repairs the common problems (missing types, `M2C_ERROR` markers, pointer arithmetic, C89 declaration order, small data and absolute addresses) before it searches.

### How long to search

| Option | Time | Candidates |
|---|---|---|
| `--quick` | 15 s | 250 |
| default (`--mode standard`) | 3 min | 2,500 |
| `--thorough` | 10 min | 10,000 |
| `--deep` | 30 min | 50,000 |
| `--until-match` | until `VERIFIED` or you stop it | no limit |

`--time 90s`, `--time 20m` or `--budget 1h` set the time directly, and `--max-candidates N` sets the candidate limit. The search uses its whole budget unless you add `--plateau N`, which stops after N candidates in a row without an improvement.

### Other options

* `--workers N` runs N compiles in parallel.
* `--strategies` limits the search to some families: `systematic`, `random`, `statement`, `types`, `temps`, `control`, `regalloc`, `register_focus`.
* `--seed N` makes the random strategy repeatable.
* `--write` writes the source back when an exact match is found. Add `--write-best` to also write the best close match.
* `--json` prints the full result.

Results are cached in a local SQLite database, so repeated candidates are not compiled twice.

## 5. Reading the output

A search ends with a line like:

```
[MISMATCH] fn_80012345 (0x80012345) in 42.1s
  evaluated=2500 compiled=1830 cache_hits=670 improvements=9
  best strategy=directed diff_bytes=4 score=6
```

followed by the remaining differences and hints about what to change next, for example callee saved registers that differ or a constant that does not match. Those hints are where to look when you finish a function by hand.

## 6. MCP server

`kintoun mcp` starts a local MCP server (install the `mcp` extra first). It offers three tools:

* `kintoun_verify(source_path, func, target_obj, lines)`
* `kintoun_permute(source_path, func, target_obj, budget_s, max_candidates, mode, plateau, ...)`
* `kintoun_info()`

An assistant can then check and search functions in your project directly. `budget_s` accepts the same duration strings as `--time`, and `mode` the same presets as `--mode`.
