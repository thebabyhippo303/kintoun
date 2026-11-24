# Compiler Setup Guide

Kintoun does not bundle any proprietary console compilers. Point `kintoun.toml` at your own toolchain installation.

## PowerPC (GameCube / Wii)

### SN ProDG (under Wine)
```toml
[compiler]
preset = "prodg-wine"
compiler_dir = "${PRODG_DIR}"   # directory containing ngccc.exe
wine = "wine"
flags = ["-O2", "-c"]
```
Tip: On Linux, starting a persistent `wineserver -p` in your `WINEPREFIX` avoids per-compile Wine cold-start overhead (~300 ms per candidate).

### Metrowerks CodeWarrior / MWCC (under Wine)
```toml
[compiler]
preset = "mwcc-wine"
compiler_dir = "${MWCC_DIR}"    # directory containing mwcceppc.exe
wine = "wine"
flags = ["-O4,p", "-nodefaults", "-proc", "gekko", "-fp", "hardware", "-c"]
```

## MIPS (PS2, PSP, MIPS32)

### PS2 Emotion Engine (`ee-gcc` and `mwccps2`)
Supports both historic Sony `ee-gcc` (2.95, 2.96, 3.2) and modern PS2DEV `mips64r5900el-ps2-elf-gcc`, plus Metrowerks CodeWarrior for PS2 (`mwccps2.exe` via `wibo` or `wine`):
```toml
[compiler]
preset = "ee-gcc"
compiler_dir = "${PS2DEV}/ee"
flags = ["-O2", "-mno-abicalls", "-fno-pic", "-G8", "-c"]
```
```toml
[compiler]
preset = "mwccps2"
compiler_dir = "${MWCCPS2_DIR}"
wine = "wibo"
flags = ["-O4,p", "-nodefaults", "-c"]
```

### PSP Allegrex (`psp-gcc`, `mwccpsp`, and `pspsnc`)
Supports Sony/PSPDEV `psp-gcc`, Metrowerks CodeWarrior for PSP (`mwccpsp.exe`), and SN Systems ProDG/SNC for PSP (`pspsnc.exe`):
```toml
[compiler]
preset = "psp-gcc"
compiler_dir = "${PSPDEV}"
flags = ["-O2", "-mno-abicalls", "-fno-pic", "-G8", "-c"]
```
```toml
[compiler]
preset = "mwccpsp"
compiler_dir = "${MWCCPSP_DIR}"
wine = "wibo"
flags = ["-O4,p", "-nodefaults", "-c"]
```

### Generic MIPS32 Little- or Big-Endian (`mips-gcc`)
```toml
[compiler]
preset = "mips-gcc"
compiler_dir = "${MIPS_TOOLCHAIN_DIR}"
# Pass "-EL" for little-endian or "-EB" for big-endian
flags = ["-O2", "-EL", "-mno-abicalls", "-fno-pic", "-G8", "-c"]
```

## ARM / Thumb (GBA and Nintendo DS)

### GBA `agbcc` (two-stage `agbcc` + `arm-none-eabi-as`)
```toml
[compiler]
preset = "agbcc"
compiler_dir = "${AGBCC_DIR}"
flags = ["-O2"]
assembler = ["arm-none-eabi-as", "-mcpu=arm7tdmi", "-mthumb-interwork"]
```

### Arm GNU Toolchain (`arm-none-eabi-gcc`)
```toml
[compiler]
preset = "arm-none-eabi-gcc"
compiler_dir = "${ARM_GNU_DIR}"
# A32: ["-O2", "-mcpu=arm7tdmi", "-marm", "-c"]
# Thumb-1: ["-O2", "-mcpu=arm7tdmi", "-mthumb", "-c"]
# Thumb-2: ["-O2", "-march=armv7-m", "-mthumb", "-c"]
flags = ["-O2", "-mcpu=arm7tdmi", "-mthumb", "-c"]
```

### Metrowerks MWCC for ARM / Nintendo DS (`mwccarm`)
Supports both native Linux wrappers (such as `metroskrew`'s `mwccarm`) and `mwccarm.exe` under Wine:
```toml
[compiler]
preset = "mwccarm"
compiler_dir = "${MWCCARM_DIR}"   # directory containing mwccarm or mwccarm.exe
flags = ["-O4,p", "-proc", "arm946e", "-c"]   # add "-thumb" for Thumb targets
```

## Custom Compiler Command
Any compiler that takes a `.c` file and writes a PowerPC, MIPS, or ARM ELF32 `.o` object works via `command`:
```toml
[compiler]
preset = "custom"
command = ["powerpc-eabi-gcc", "{flags}", "-o", "{out}", "{in}"]
flags = ["-O2", "-mbig", "-mregnames", "-c"]
```
