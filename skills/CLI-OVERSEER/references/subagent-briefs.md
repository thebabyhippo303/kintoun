# Subagent Brief Templates for `CLI-OVERSEER`

Copy and fill `<AGENT_ID>`, `<TIER>`, or `<ADDR_RANGE>` when spawning subagents.

---

## 1. Matcher Subagent Brief

```text
Role: Kintoun Matcher (<AGENT_ID>, tier: <TIER>)
Read `skills/kintoun-match/SKILL.md` and the reference for this project's `target.arch` (`powerpc.md`, `mips.md`, or `arm.md`) before starting.

Assignment:
Match <COUNT> functions in plain C to 100% strict byte-exact verification (`VERIFIED`).

Loop for each function:
1. Claim: `kintoun queue claim --agent <AGENT_ID> --tier <TIER>` (stop if no pending functions remain).
2. Blocker check: `kintoun check --func <NAME>`. If `not-plain-c`, run `kintoun queue fail --agent <AGENT_ID> --func <NAME> --reason not-plain-c` and claim the next function.
3. Brief: `kintoun context --func <NAME>` to read target disassembly, callees, matched prototypes, globals, and any prior near-miss hint.
4. Seed & governed search: write or load initial C at `<SRC_PATH>`, then run `kintoun permute <SRC_PATH> --func <NAME> --governed --write --write-best` (or use `kintoun_score_candidate` / `kintoun_revise_candidate` if Kintoun MCP is attached).
5. Hand-refine + close: do NOT give up if `permute` plateaus. Read the aligned diff, apply targeted C edits from the architecture symptom table, verify with `kintoun verify <SRC_PATH> --func <NAME>`, and run `kintoun close <SRC_PATH> --func <NAME> --write --write-best` when >= 85% aligned.
6. Submit or expire:
   - At 100% (`VERIFIED`): run `kintoun queue submit --agent <AGENT_ID> --func <NAME> --source <SRC_PATH> --category <FIX_CATEGORY> --note "<what C change solved the final diff>"`.
   - Check remaining time with `kintoun queue clock --agent <AGENT_ID>`; only call `fail` after the function's chess clock expires.

Hard rules:
- Real C only (no `asm`, `__asm__`, `GLOBAL_ASM`, register pins, naked functions, or `.long`/`.word`/`.byte`).
- Never edit other agents' claimed `src/` files and never run `git add -A` or `git push`.
- Report back: list of `VERIFIED` functions submitted, plus best aligned % and remaining diff symptom on any function that timed out.
```

---

## 2. Namer Subagent Brief

```text
Role: Kintoun Namer (<AGENT_ID>, band: <ADDR_START>..<ADDR_END>)

Assignment:
Assign accurate, evidence-backed function names to unnamed `fn_XXXXXXXX` / `sub_XXXXXXXX` symbols strictly inside address range `<ADDR_START>..<ADDR_END>` in `<SYMBOLS_PATH>`.

Workflow:
1. Find unnamed function symbols in `<ADDR_START>..<ADDR_END>` from `<SYMBOLS_PATH>`.
2. For each candidate, run `kintoun check --func <SYM>` and `kintoun context --func <SYM>` to inspect disassembly, direct callees, referenced globals, struct field access patterns, and nearby named functions.
3. Naming standard:
   - Use `Class__Method` or `Module_VerbNoun` matching the existing project naming convention.
   - Require concrete evidence (debug/assert strings, known callee cluster, vtable slot layout, or unambiguous hardware register usage).
   - If the subsystem is clear but exact behavior is uncertain, use an honest `<Module>_Unk_<ADDR>` name rather than guessing.
4. Update only the symbol lines inside `<ADDR_START>..<ADDR_END>` in `<SYMBOLS_PATH>`. Never edit `src/*.c` or touch symbols outside your assigned address band.

Report back: count of functions named, key subsystem discoveries, and the exact `<ADDR> -> <NewName> (evidence)` table so the orchestrator can run `kintoun queue init`.
```

---

## 3. Near-Miss Finisher Subagent Brief (`90..99%` Pile)

```text
Role: Kintoun Near-Miss Finisher (<AGENT_ID>)
Read `skills/kintoun-match/SKILL.md` and the architecture symptom reference (`powerpc.md`, `mips.md`, or `arm.md`).

Assignment:
Close `<FUNC_NAME>` (`<ADDR>`), currently at `<BEST_PCT>%` aligned, starting from `<SEED_PATH>`.

Steps:
1. Run `kintoun verify <SEED_PATH> --func <FUNC_NAME> --lines 48` and `kintoun context --func <FUNC_NAME>` to inspect every remaining mismatching instruction.
2. Identify the exact mismatch class (register allocation, instruction order, signed/unsigned or narrow cast, stack layout, constant/pool literal, branch polarity, or float promotion).
3. Test 2 to 6 targeted hand-written C hypotheses directly addressing those lines, scoring each with `kintoun verify` (or `kintoun_score_candidates`), then run `kintoun close <SEED_PATH> --func <FUNC_NAME> --budget 90s --write --write-best`.
4. If `VERIFIED`, submit via `kintoun queue submit --agent <AGENT_ID> --func <FUNC_NAME> --source <SRC_PATH> --category <CLASS> --note "<exact fix>"`.
```
