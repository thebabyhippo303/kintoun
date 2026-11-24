# PowerPC (`ppc_elf`) Symptom-to-C Lookup (SN ProDG & Metrowerks MWCC)

| Assembly Diff Symptom | Exact C Edit |
|---|---|
| `cmpw` vs `cmplw` / `cmpwi` vs `cmplwi` | Signedness mismatch: make both operands `s32` (signed) or both `u32` (unsigned) on the local, parameter, or struct field. |
| `extsh` / `extsb` vs `clrlwi 16` / `clrlwi 24` | Narrow integer signedness: flip `s16` <-> `u16` or `s8` <-> `u8` on the struct member or cast. |
| `srawi` + `addze` vs `srwi` | Signed division by `2^k` (`s32 / 8`) vs unsigned shift/division (`u32 >> 3`). |
| `lfs` / `fadds` vs `lfd` / `fadd` + `frsp` | Float vs double promotion: use `1.0f` instead of `1.0`, keep temps `f32`, and check callee return prototypes (`float` vs `double`). |
| `cror` before branch on float compare | ProDG emits `cror` for `<=` / `>=` or negated `<` / `>`: flip comparison polarity (`!(a >= b)` <-> `a < b`) and swap `if`/`else` bodies. |
| `lis 0x4330` magic constant in `.rodata` | Integer-to-float conversion (`(f32)val`): `s32 -> f32` flips sign bit (`^ 0x80000000`), `u32 -> f32` does not. Fix signedness of `val`. |
| `lwz rX, off(r13)` vs `lis + addi/lwz` | Global SDA vs far data: `<= 8`-byte scalar externs (`extern s32 sym;`) use `r13`/`r2` SDA; `> 8`-byte arrays/structs (`extern u8 sym[16];`) use `lis + addi`. |
| `stmw rN` count differs in prologue | Number of values live across a function call: inline/recompute a temp after the call to free a non-volatile `r31..rN`, or hoist an expression into a local before the call to add one. |
| `stwu r1, -N(r1)` frame size differs | Stack-allocated locals: check local arrays, address-taken variables (`&x`), spilled temps, or by-value struct copies (`Vec3 tmp = src->v;`). |
| `!` same shape, swapped GPRs (`r3..r12`, `r28..r31`) | GCC/ProDG assigns temps in first-use order (declaration order breaks ties); MWCC assigns by declaration/lifetime order. Reorder local declarations, inline a single-use temp, or run `kintoun close`. |
| `lwz`/`stw` 3-word copy vs `lfs`/`stfs` | Struct assignment `*(Vec3 *)dst = *(Vec3 *)src;` (`struct { s32 x, y, z; }` vs `float` field-by-field copy). |
| `li rN, K` before `b` to shared epilogue | Cross-jumping / tail merge: duplicate the tail (`call(); return K;`) in each branch instead of sharing a single `return ret;`. |
| `.long 0x1`, `psq_l`, `dcbz`, `mfmsr`, `mtspr GQR` | Not expressible in standard C: verify with `kintoun check` and mark `not-plain-c`. |
