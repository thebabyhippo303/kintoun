# ARM / Thumb (`arm_elf`) Symptom-to-C Lookup (`agbcc`, `arm-none-eabi-gcc`, `mwccarm`)

| Assembly Diff Symptom | Exact C Edit |
|---|---|
| `lsl rX, rY, #16` + `asr rX, rX, #16` vs `lsr #16` | Thumb-1 `s16` sign-extension (`asr`) vs `u16` zero-extension (`lsr`); `#24` is `s8` vs `u8`. Change local/field/cast type. |
| Extra `lsl #16; lsr #16` after arithmetic in `agbcc` | Local variable declared as `u16`/`s16` forces Thumb narrowing after every step; widen the local temp to `u32`/`s32` and cast only on store, or narrow `int` to `u16` if target has the shifts. |
| `$d` literal pool entries in wrong order | GCC/agbcc emits literal-pool constants and global pointers in first-reference order within the function: reorder independent initializations or helper checks to match target pool order (or run `m_arm_pool_order` via `kintoun permute`). |
| Two `ldr rX, [pc, #imm]` globals vs one base + offset | Adjacent globals came from the same struct/array in original C: group them into one `struct` or rebase off `(u8 *)&base_sym + offset`. |
| High-register spills (`mov r8, r4` / `[sp, #off]`) | Thumb-1 only directly addresses `r0..r7` in most ALU/load/store ops (>5 live values spill to `r8..r11` or stack): shorten temp lifetimes by moving loads next to their use and inlining single-use locals. |
| `push {r4-r6, lr}` vs `push {r4-r5, lr}` | One extra variable survives across `bl`: move computation after the call or re-read from struct pointer instead of keeping a local temp. |
| `bl` vs `blx` interworking mismatch | Target callee Thumb/ARM state differs: check `symbols.txt` (`type:thumb` / LSB=1) or function pointer typedef attribute. |
| `bcs`/`bcc`/`bhi`/`bls` vs `bge`/`blt`/`bgt`/`ble` | Unsigned (`cs`/`cc`/`hi`/`ls`) vs signed (`ge`/`lt`/`gt`/`le`) comparison: align operand signedness (`u32` vs `s32`). |
| Redundant `ldr` after `str` to volatile hardware reg | GBA/NDS MMIO (`REG_DMA*`, `REG_DISPCNT`): ensure pointer uses `volatile u16 *` / `volatile u32 *` (or remove `volatile` if target caches the value in a register). |
| `swi` / `svc`, `mcr` / `mrc` (`cp15`), `mrs` / `msr`, `bx pc` | Supervisor trap, coprocessor control, or inline ARM/Thumb veneer: run `kintoun check` and mark `not-plain-c`. |
