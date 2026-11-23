# Compiler Setup Guide

NIM-DTK does not bundle any proprietary console compilers. Point `nim-dtk.toml` at your own toolchain installation.

## SN ProDG (GameCube, under Wine)
```toml
[compiler]
preset = "prodg-wine"
compiler_dir = "${PRODG_DIR}"   # directory containing ngccc.exe
wine = "wine"
flags = ["-O2", "-c"]
```
Tip: On Linux, starting a persistent `wineserver -p` in your `WINEPREFIX` avoids per-compile Wine cold-start overhead (~300 ms per candidate).

## Metrowerks CodeWarrior / MWCC (GameCube/Wii, under Wine)
```toml
[compiler]
preset = "mwcc-wine"
compiler_dir = "${MWCC_DIR}"    # directory containing mwcceppc.exe
wine = "wine"
flags = ["-O4,p", "-nodefaults", "-proc", "gekko", "-fp", "hardware", "-c"]
```

## Custom Compiler Command
Any compiler that takes a `.c` file and writes a big-endian PPC ELF32 `.o` object works via `command`:
```toml
[compiler]
preset = "custom"
command = ["powerpc-eabi-gcc", "{flags}", "-o", "{out}", "{in}"]
flags = ["-O2", "-mbig", "-mregnames", "-c"]
```
