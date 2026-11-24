# How Kintoun handles each architecture

Kintoun has three engines, chosen by `[target] arch` in `kintoun.toml`. Each one has its own object reader, relocation linker, instruction scoring, disassembler for diffs, register permuter, repair hypotheses and decompiler seed repairs. They share the C mutation families and the search loop, nothing else.

## PowerPC (`ppc_elf`, the default)

**Targets:** GameCube and Wii DOL executables with a `dtk` style `symbols.txt`, or single ELF32 big endian `.o` files.

**Compilers:** SN ProDG (`prodg-wine`) and Metrowerks CodeWarrior (`mwcc-wine`), both run under Wine, plus any PowerPC GCC through a command template.

**Linking and verification:** relocations `REL24`, `REL14`, `ADDR16_HA`, `ADDR16_LO`, `ADDR16_HI`, `ADDR32`, `REL32`, `SDAREL16` and `EMB_SDA21` are applied against the real target addresses, with both small data bases (`r13` for `_SDA_BASE_`, `r2` for `_SDA2_BASE_`). Read only data is placed where the target expects it. A standalone target `.o` is linked the same way as the candidate, so relocated bytes compare exactly. Symbols named after their address (`fn_80012345`, `lbl_80012345`) bind to that address.

**Seed repairs for `m2c` output:** a C89 prelude of fixed width types, repair of `M2C_ERROR` markers, unknown types, pointer arithmetic and declaration order, `saved_reg_r13` and `saved_reg_r2` small data references turned into named globals, raw `0x80xxxxxx` addresses rebuilt as globals and struct offsets from the target's `lis` and `addi` pairs, struct layout synthesis, single precision float literals where the target uses single precision, and the integer to float conversion constant.

**Search:** the original mutation families, plus directed families that read the target's instructions (float, fused multiply add and compare forms, switch lowering, load and store scheduling, stack frame unions).

## MIPS (`mips_elf`)

**Targets:** flat binaries at a load address, ELF32 executables in either byte order, PSP PRX modules (`ET_SCE_PSP_PRX`, type `0xFFA0`, relocated at load), and single `.o` files.

**Compilers:** PS2 `ee-gcc` (2.96, 3.2 and PS2DEV) and Metrowerks PS2 (`mwccps2`); PSP `psp-gcc` (Allegrex), Metrowerks PSP (`mwccpsp`) and SN SNC (`pspsnc`); generic MIPS32 GCC (`mips-gcc`, either byte order).

**Linking and verification:** `SHT_REL` and `SHT_RELA` relocations, including paired `HI16` and `LO16` (several `HI16` per `LO16`, and orphaned `LO16`), `GPREL16`, `GPREL32`, `LITERAL`, `26`, `PC16`, `16`, `32`, `REL32`, `PC32` and `JALR`. The `$gp` base is read from `.reginfo`, `.MIPS.options` or the PSP module info.

**Scoring and diffs:** alignment that keeps each branch together with its delay slot, normalisation of relocated immediates and `$gp` relative offsets, and a disassembler that knows the R5900 (`lq`, `sq` and the multimedia instructions) and Allegrex extensions.

**Register permuter:** live range permutation within register classes: `$v`, `$a`, `$t`, `$s`, floating point registers, and `HI` and `LO`.

**Repairs and seeds:** the right callee, global, `lui` and `ori` or `li` constant, struct field offset and stack frame, read from the target's instructions; repair of raw `m2c` output for MIPS, R5900 and Allegrex; symbolisation of absolute addresses; short circuit condition merging; and target guided C transforms.

## ARM and Thumb (`arm_elf`)

**Targets:** GBA ROMs and other flat images at a load address, ELF32 little endian executables, and single `.o` files. Functions may be ARM or Thumb; a symbol with the low bit set, `mode:thumb` in the symbols file or `thumb = true` marks Thumb.

**Compilers:** GBA `agbcc` (compile, then assemble with `arm-none-eabi-as`), the Arm GNU toolchain (`arm-none-eabi-gcc`, ARM, Thumb and Thumb 2), Metrowerks for Nintendo DS (`mwccarm`) and ARM RealView or ADS (`armcc`).

**Linking and verification:** mapping symbols `$a`, `$t` and `$d` decide how each byte range is decoded, so mixed 16 and 32 bit Thumb code and inline literal pools are handled. Relocations cover `ABS32`, `REL32`, `CALL`, `JUMP24`, the Thumb call and jump family (`THM_CALL`, `THM_JUMP6`, `THM_JUMP8`, `THM_JUMP11`, `THM_JUMP19`), `MOVW` and `MOVT`, `SBREL32`, `PREL31` and the small immediate forms. Calls between ARM and Thumb are linked the way the target was linked, as `BL` or `BLX`. Literal pool words are compared after relocation.

**Scoring and diffs:** a disassembler for ARM, Thumb 16, Thumb 2 and data, scoring that understands literal pools, and PC relative load inference for flat ROMs.

**Register permuter:** `r0` to `r12`, and the low registers `r0` to `r7` in Thumb code.

**Repairs and seeds:** the right callee, global, literal pool constant, field offset and push and pop frame; Thumb width and `BL` or `BLX` interworking; literal pool rebasing for constants, structs and lookup tables; recovery of the SDK's DMA flush reads that `m2c` drops; and target guided C transforms.

## Not supported

* 64 bit ELF.
* Big endian ARM.
* Position independent MIPS code (compile with `-mno-abicalls -fno-pic`, as the presets do).
* A few rare ARM relocation types.
