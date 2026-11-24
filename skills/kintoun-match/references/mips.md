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
| Swapped `$v0/$v1/$a0..$a3/$t0..$t7` | Reorder local variable declarations (C89 top-of-block), split or inline single-use temps, or run `kintoun close` (`register_focus`). |
| `mfc0`/`mtc0`, `qmfc2`/`vadd` (VU0), `lv.q` (VFPU) | Coprocessor / vector instructions: run `kintoun check` and mark `not-plain-c`. |
