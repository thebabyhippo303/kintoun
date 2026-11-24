---
name: kintoun-match
description: Byte-exact matching-C decompilation workflow using Kintoun across PowerPC (GameCube/Wii), MIPS (PS2/PSP/MIPS32), and ARM/Thumb (GBA/NDS). Activate whenever matching functions, fixing assembly diffs, running Kintoun MCP/CLI tools, or coordinating multi-agent decomp queues.
---

# Skill: Byte-Exact Matching C with Kintoun

## Core Rules
1. **Hand-Write Rule:** Kintoun search (`kintoun permute` / `kintoun_permute` / `kintoun close`) is a **starting point and force multiplier**, never an excuse to give up early. Inspect the aligned diff and repair hypotheses, hand-edit real C, score repeatedly, and combine hand edits with targeted `permute` / `close` passes until `VERIFIED` (`100%` relocation-resolved byte match) or the function's chess clock expires.
2. **Real C Only:** Never emit `asm`, `__asm__`, `GLOBAL_ASM`, `register ... __asm__("...")` pins, naked functions, `.long` / `.4byte` / `.word` / `.byte`, or constant-pool padding. Kintoun's strict verifier rejects them.
3. **Token Discipline:**
   - Start with **one** `kintoun_context_pack` (or `kintoun context --func NAME`) instead of dumping whole binaries or scanning dozens of files.
   - Iterate with `kintoun_score_candidate` -> `kintoun_revise_candidate` (`edits=[{"old": ..., "new": ...}]`) or batch-compare hypotheses with `kintoun_score_candidates` (`2..8` variants in one call).
   - Read only the mismatching rows in the aligned diff (`-` extra, `+` missing, `!` same shape / swapped registers).

## Fast Loop (Single Agent or Multi-Claim Fleet)
1. **Claim & Check:**
   - If using the queue: `kintoun_claim_next` (keep your allowed claims full; switch claims while a search runs instead of idling).
   - Run `kintoun_check` (`kintoun check --func NAME`). If `verdict == "not-plain-c"`, call `kintoun_fail_claim(..., reason="not-plain-c")` immediately and move on.
2. **One-Screen Brief:**
   - Call `kintoun_context_pack(func=NAME)` to inspect target disassembly, callees, matched prototypes, globals, difficulty tags, and any prior near-miss hint.
3. **Initial Seed & Search:**
   - Score your initial C draft with `kintoun_score_candidate` (or run `kintoun_permute` in `quick` / `standard` mode to auto-repair raw `m2c` output, rebase globals/literal pools, and search 1-to-3-step mutations).
4. **Hand-Refine + Near-Miss Closer:**
   - Load the architecture reference below matching `target_arch`:
     - PowerPC (`ppc_elf`, ProDG / MWCC): `references/powerpc.md`
     - MIPS (`mips_elf`, `ee-gcc` / `psp-gcc` / MWCC): `references/mips.md`
     - ARM / Thumb (`arm_elf`, `agbcc` / `arm-none-eabi-gcc` / `mwccarm`): `references/arm.md`
   - Apply surgical `kintoun_revise_candidate` edits addressing the top mismatch symptom (if `already_verified: true` is returned, another worker or background closer already solved it - stop immediately and claim your next function).
   - When multiple C sites interact (e.g. local declaration order + loop condition + cast), annotate `PERM_GENERAL(...)`, `PERM_LINESWAP(...)`, `PERM_INT(lo, hi)`, `PERM_ONCE(key, stmt)`, or `PERM_SAMELINE(...)` directly in C and run `kintoun_permute` so Kintoun searches the joint macro space + beam mutations together.
   - At `>= 85%` aligned, run `kintoun_close_near_miss` (or `kintoun close`) to classify the remaining diff (`register_allocation`, `instruction_order`, `missing_cast`, `stack_layout`, `constant_literal`, `branch_shape`, `float_shape`) and run targeted 1-to-2-pass permutation.
5. **Strict Verify, Integrate & Submit:**
   - Confirm `verified == true` via `kintoun_verify` (`kintoun verify`), optionally splice into multi-function `INCLUDE_ASM` / `GLOBAL_ASM` files via `kintoun_integrate_match` (`kintoun integrate`), and call `kintoun_submit_match` with a short `fix_category` and `engine_note` recording what C construct closed the final diff so `kintoun bench --learn-priors` improves future searches.
