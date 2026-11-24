# `kintoun.toml` Configuration Reference

`kintoun` automatically discovers `kintoun.toml` by walking upward from the current working directory (or pass `-c path/to/kintoun.toml`). Environment variables (`${VAR}`) and `~` are expanded in all path fields.

```toml
[project]
name = "my-decomp"

[compiler]
# Built-in presets:
#   PowerPC: "prodg-wine", "mwcc-wine"
#   MIPS:    "ee-gcc", "mwccps2", "psp-gcc", "mwccpsp", "pspsnc", "mips-gcc"
#   ARM:     "agbcc", "arm-none-eabi-gcc", "mwccarm", "armcc"
#   Generic: "gcc", "custom"
preset = "prodg-wine"
compiler_dir = "${PRODG_DIR}"
wine = "wine"
wineprefix = ""          # optional WINEPREFIX path
flags = ["-O2", "-c"]
assembler = []           # optional assembler command list for preset = "agbcc"
timeout_s = 30.0

# Optional: override the exact invocation template for any compiler
# Placeholders: {in}, {out}, {flags}, {compiler_dir}
# command = ["powerpc-eabi-gcc", "{flags}", "-o", "{out}", "{in}"]

[compiler.env]
WINEDEBUG = "-all"

[target]
# Architecture: "ppc_elf" (default), "mips_elf" (or "mips"), "arm_elf" (or "arm")
arch = "ppc_elf"

# PowerPC DOL target:
dol = "orig/GAMEID/sys/main.dol"
sda_r13 = "0x803E4360"
sda_r2 = "0x803F4360"

# MIPS / ARM flat binary, ELF32 executable, or PSP PRX (`0xFFA0`) target:
binary = ""              # e.g. "baserom.gba", "SLUS_000.00", "EBOOT.BIN" (ET_EXEC or PRX), "arm9.bin"
base_addr = "0x0"        # load address for flat ROMs (defaults to 0x08000000 for .gba and 0x08804000 for PSP PRX)
gp = "0x0"               # MIPS $gp small-data base (auto-detected from .reginfo / .MIPS.options / SceModuleInfo if 0x0)
sb = "0x0"               # ARM R9 static-base address (for R_ARM_SBREL32)
thumb = false            # default Thumb mode for ARM flat-binary functions (auto-enabled for .gba)
endian = ""              # optional "little" or "big" check for MIPS/ARM

symbols = "config/GAMEID/symbols.txt"   # supports dtk symbols.txt, splat symbol_addrs.txt, or GNU nm output
link_layout = ""         # optional JSON file for ambiguous rodata placements

[search]
mode = "standard"        # "quick" (15s/250), "standard" (180s/2500), "thorough" (10m/10k), "deep" (30m/50k), "unlimited"
budget_s = 180.0         # seconds or duration string ("30s", "10m", "1h", "unlimited")
max_candidates = 2500    # max candidates to evaluate (up to 1000000)
plateau = 0              # 0 = never stop early on plateau (runs full budget/candidates unless VERIFIED)
workers = 0              # 0 = auto (half of CPU cores, capped at 8)
strategies = ["systematic", "register_focus", "random"]
cache_dir = ".kintoun/cache"
priors_file = ""         # optional JSON file mapping mutation family -> weight
forbid_asm = true        # enforce pure C (reject inline asm / raw data)
```

## Strategies
* `systematic` - all real-C mutation families prioritized by architecture-specific score hints
* `register_focus` - live-range register permuter activated on near misses (>=80% normalized match)
* `random` - randomized 1-step and 2-step mutation compositions
* Focused subsets: `statement`, `types`, `temps`, `control`, `regalloc`
