# MIPS (`mips_elf`) Symptom-to-C Lookup (PS2 `ee-gcc`, PSP `psp-gcc`, MWCC, MIPS32)

| Assembly Diff Symptom | Exact C Edit |
|---|---|
| `slt` / `slti` vs `sltu` / `sltiu` | Signed vs unsigned comparison: change operand types between `s32` and `u32`. |
| `sll 16` + `sra 16` (or `seh`) vs `andi 0xffff` | `s16` sign-extension vs `u16` zero-extension (or `sll 24` + `sra 24` / `seb` vs `andi 0xff` for `s8` vs `u8`). |
| `lw $reg, off($gp)` vs `lui + addiu/lw` | Small-data (`.sdata`/`.sbss`, `-G8`) vs far `.data`: scalar externs `<= 8` bytes use `$gp`-relative `GPREL16`; arrays/structs `> 8` bytes (`extern s32 sym[4];`) force `HI16/LO16` (`lui + addiu`). |
| `lui + addiu` vs `lui + ori` constant load | Signed 16-bit addend (symbol address or signed literal) vs unsigned 32-bit bitmask (`0xUUUU0000 | 0xLLLL` with `u32` hex literal). |
| Branch delay slot filled with wrong instruction | Move independent assignment above or below the `if` condition, or toggle simple assignment vs compound expression so GCC's delay-slot filler picks the target instruction. |
| `beql` / `bnel` (branch-likely) vs `beq` / `bne` | Controlled by single-statement `if` body vs `if`/`else` merge block: rewrite ternary `x = cond ? a : b;` <-> `if (cond) x = a; else x = b;` or hoist the default initialization `x = b; if (cond) x = a;`. |
| `movz` / `movn` vs branch | Conditional move on MIPS IV / R5900 / Allegrex: write as clean ternary `cond ? a : b` without side effects (or expand to `if` if target uses a branch). |
| `madd.s` / `msub.s` vs `mul.s` + `add.s` | Fused multiply-add on R5900 / Allegrex: group `a * b + c` in one `float` expression vs splitting `float prod = a * b; return prod + c;`. |
| `cvt.d.s` + `add.d` + `cvt.s.d` | Accidental `double` promotion: add `f` suffix to float literals (`0.5f` instead of `0.5`) and ensure math callees are `sinf`/`cosf`/`sqrtf`. |
| Extra `$s0..$s7` saved on `$sp` | Too many values live across `jal`: recompute `p->field` or `base + offset` after the call instead of caching it in a local before the call. |
| `sd`/`ld $ra` + `sq`/`lq $s0..$s7` on `$sp` (`mwccps2`) | Normal MWCC PS2 `-O4,p` prologue/epilogue for functions calling callees: `mwccps2` saves `$ra` with 64-bit `sd`/`ld` and `$s0..$s7` with 128-bit `sq`/`lq` automatically when C locals stay live across a call. |
| `daddu $rd, $rs, $zero` (`move`) vs `addu` (`mwccps2`) | MWCC PS2 emits `daddu` (`0x00..002d`) for register-to-register `move` and 64-bit `long` math, while 32-bit `int`/`u32` addition emits `addu`/`addiu`. Keep standard 32-bit ints as `s32`/`u32` (`int`/`unsigned int`), not `long` (which is 64-bit on PS2 EABI64/ILP32). |
| `mula.s` + `madd.s` / `msub.s` (`mwccps2` R5900 FPU) | R5900 COP1 accumulator multiply-add: write `a * b + c` or `a * b + c * d` as a single `f32` expression so `mwccps2` emits `mula.s` + `madd.s`; split into a separate `f32 tmp = a * b;` statement if target uses `mul.s` + `add.s`. |
| C++ virtual call (`lw vtbl` -> `lh delta; daddu $a0` -> `lw fn; jalr`) | MWCC PS2 C++ vtable entries can be 8-byte descriptors `struct { s16 delta; s16 voff; void *fn; }` (or direct function pointers in C callback tables): model the vtable struct matching the exact `lh` + `lw` offsets seen in disassembly. |
| Swapped `$v0/$v1/$a0..$a3/$t0..$t7` | Reorder local variable declarations (C89 top-of-block), split or inline single-use temps, or run `kintoun close` (`register_focus`). |
| `mfc0`/`mtc0`, `qmfc2`/`vadd` (VU0), `lv.q` (VFPU), MMI `.word 0x70...` | Coprocessor / SIMD vector instructions: run `kintoun check` and mark `not-plain-c`. |
