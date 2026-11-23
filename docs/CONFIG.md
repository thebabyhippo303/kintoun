# `nim-dtk.toml` Configuration Reference

`nim-dtk` automatically discovers `nim-dtk.toml` by walking upward from the current working directory (or pass `-c path/to/nim-dtk.toml`). Environment variables (`${VAR}`) and `~` are expanded in all path fields.

```toml
[project]
name = "my-decomp"

[compiler]
# Built-in presets: "prodg-wine", "mwcc-wine", "gcc", or "custom"
preset = "prodg-wine"
compiler_dir = "${PRODG_DIR}"
wine = "wine"
wineprefix = ""          # optional WINEPREFIX path
flags = ["-O2", "-c"]
timeout_s = 30.0

# Optional: override the exact invocation template for any compiler
# Placeholders: {in}, {out}, {flags}, {compiler_dir}
# command = ["powerpc-eabi-gcc", "{flags}", "-o", "{out}", "{in}"]

[compiler.env]
WINEDEBUG = "-all"

[target]
arch = "ppc_elf"
dol = "orig/GAMEID/sys/main.dol"
symbols = "config/GAMEID/symbols.txt"
sda_r13 = "0x803E4360"
sda_r2 = "0x803F4360"
link_layout = ""         # optional JSON file for ambiguous rodata placements

[search]
budget_s = 60.0
max_candidates = 600
workers = 0              # 0 = auto (half of CPU cores, capped at 8)
strategies = ["systematic", "register_focus", "random"]
cache_dir = ".nim-dtk/cache"
priors_file = ""         # optional JSON file mapping mutation family -> weight
forbid_asm = true        # enforce pure C (reject inline asm / raw data)
```

## Strategies
* `systematic` — all real-C mutation families prioritized by score hints
* `register_focus` — live-range register permuter (`decl_rot`, `var_split`, `temp_merge`, `alias_make`, composed pairs) activated on near misses (>=80% normalized match)
* `random` — randomized 1-step and 2-step mutation compositions
* Focused subsets: `statement`, `types`, `temps`, `control`, `regalloc`
