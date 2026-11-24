---
name: ENGINE-BUILDER
description: Iterative side-tree engine evolution skill for personal decompilation projects. Delegates 1 to 4 ENGINE-BUILDER subagents to improve a project-local Kintoun engine copy on dev sets and promotes a new engine ONLY when it beats the current live engine on a wide, blind unseen function gate (both % close to matched and exact matches, zero regressions).
---

# Skill: ENGINE-BUILDER (Self-Learning Side-Tree Engine Evolution)

`ENGINE-BUILDER` lets any personal decompilation project **self-learn its own compiler and codebase idioms** as the project develops. Instead of editing the live matching engine blindly or overfitting to a fixed benchmark, 1 to 4 `ENGINE-BUILDER` subagents iterate rapidly in isolated side trees under `.kintoun/engine_lab/`, stack their commits into a local `combined` branch, and face a **blind unseen promotion gate** (`kintoun engine gate`) that neither engine has ever seen before.

---

## 1. Core Architecture & Anti-Overfitting Law

All engine evolution lives inside `.kintoun/engine_lab/` (never touching `src/`, `symbols.txt`, or `.kintoun/queue.sqlite3` claims):

1. **`live/` (Current Project Engine):** Seeded from Kintoun's `src/kintoun/`. When promoted, `active_engine.json` routes future `permute`, `close`, `overseer`, and `mcp` runs in this repo through `live/src` automatically.
2. **`builders/b1` .. `builders/b4` (Isolated Side Trees):** Each `ENGINE-BUILDER` subagent edits **only** its assigned side tree (`builders/b1/src/kintoun/...`).
3. **`combined/` (Stacked Candidate Git Repo):** Builders commit discrete improvements (`kintoun engine commit --builder b1 --claim "..."`) onto `combined` via 3-way merge so wins from multiple builders compound into one stronger engine.
4. **`seen_functions.json` (Strict Blind Unseen Gate Ledger):**
   - Every function placed into any `dev` manifest (`make-dev`) or run through `kintoun engine bench` is permanently marked **`seen_by_builders`**.
   - When `kintoun engine gate` evaluates `live` vs `combined`, it **dynamically draws a fresh, size-stratified wide array of plain-C functions** from the binary while strictly excluding every `seen_by_builders` function (and rotating past prior gate draws). Builders **cannot** tune heuristics or hardcode patterns to game the gate.
5. **Dual-Metric Promotion Gate + Ablation + 1-Command Rollback:**
   - When `combined` has 2+ commits above `live`, `gate` ablates each commit (`HEAD` vs `HEAD-without-commit`) and auto-reverts commits that do not help.
   - `combined` replaces `live` **only** when on the fresh unseen set:
     1. **Exact matches strictly increase** (`cand.verified > live.verified`),
     2. **`%` close to matched strictly improves** (`cand.mean_aligned_pct > live.mean_aligned_pct` and `>= 85%` close rate does not drop), and
     3. **Zero exact matches are lost** (`lost_exact == []` on unseen functions and solved guards).
   - Every promotion writes a full backup + `PROMOTION_MANIFEST.json` so `kintoun engine rollback` restores the previous engine in one command.

---

## 2. Initializing the Project Engine Lab

Run once per repository before spawning `ENGINE-BUILDER` subagents:

```bash
# 1. Initialize .kintoun/engine_lab/ with 1 builder (solo) or 4 builders (parallel fleet)
kintoun engine init --builders 4

# 2. Sample an initial stratified dev set for rapid builder iteration (marks rows seen_by_builders)
kintoun engine make-dev -o .kintoun/engine_lab/sets/dev_r1.json --count 24 --seed 1

# 3. Inspect lab status & shared findings board
kintoun engine status
kintoun engine findings show
```

---

## 3. Orthogonal Focus Lanes (1 Builder or 4 Parallel Builders)

Read [references/builder-briefs.md](references/builder-briefs.md) for copy-ready subagent prompts.

* **Solo Mode (1 Subagent):** Assign `b1` across the highest-frequency failure class seen in `.kintoun/hints/*.json` and `.kintoun/research/notes.jsonl`.
* **4-Builder Fleet Mode (`b1`..`b4`):** Partition by orthogonal engine subsystem so builders never collide on the same files or hypotheses:
  - **`b1` (Scorer, Repair Guidance & Beam Search):** `search/runner.py`, `search/*_guidance.py`, `closer.py` (beam diversity, repair priorities, wasted-budget pruning).
  - **`b2` (Float, Switch & Constant/Rodata Directed Moves):** `constants.py`, `search/mutations_float.py`, `search/mutations_switch.py`, `search/*_mutations.py` (FPU/FMA idioms, jump-table/if-chain lowering, literal pools).
  - **`b3` (Register Allocation & Instruction Scheduling):** `search/*_permuter.py`, `search/mutations_order_*.py`, `search/base_mutations.py` (`85..99%` register swaps, temp hoisting/inlining, load/store scheduling).
  - **`b4` (Seed Recovery, Struct/Prototype Context & Control Flow):** `search/*_seeds.py`, `search/mutations_recovery.py`, `inspect_fn.py` (compile-error recovery on raw seeds, loop/guard shapes, missing casts/prototypes).

---

## 4. The Builder Iteration Cycle

Every `ENGINE-BUILDER` subagent follows this exact loop:

1. **Read Shared Findings & Sync Side Tree:**
   ```bash
   kintoun engine findings show -n 15
   kintoun engine sync --builder b1
   ```
2. **Mine Real Project Mismatches (Not Blind Guessing):**
   - Inspect `.kintoun/hints/*.json` (saved near-miss diffs from Matcher waves), `.kintoun/research/notes.jsonl` (what human/Matcher hand-edits actually solved functions in this game!), and `dev` benchmark failure rows.
3. **Register Hypothesis Lock (No Duplicate Work):**
   ```bash
   kintoun engine findings start --builder b1 --change hoist-loop-bound --what "hoist invariant pointer load above countdown loop"
   ```
   If `REFUSED` (another builder holds it), pick a different hypothesis.
4. **Edit Only Your Side Tree & Dev-Bench Head-to-Head:**
   - Edit files strictly under `.kintoun/engine_lab/builders/b1/src/kintoun/`.
   - Run `live` vs `b1` on the `dev` manifest:
     ```bash
     kintoun engine bench --arm live --set .kintoun/engine_lab/sets/dev_r1.json --budget 15s --workers 1
     kintoun engine bench --arm b1   --set .kintoun/engine_lab/sets/dev_r1.json --budget 15s --workers 1
     ```
5. **Commit Dev Winners to `combined` (or Revert Duds) & Log Lesson:**
   - If `b1` improves `dev` with zero lost `dev` matches:
     ```bash
     kintoun engine commit --builder b1 --claim "hoist invariant pointer load above countdown loop"
     kintoun engine findings log --builder b1 --change hoist-loop-bound --dev "62.4% -> 66.1% (3->5 exact)" --verdict committed --lesson "countdown loops in this compiler spill base ptr unless hoisted"
     kintoun engine findings done --builder b1
     ```
   - If `b1` ties or regresses on `dev`: discard via `kintoun engine sync --builder b1 --force`, log the negative finding (`--verdict reverted`) so nobody repeats it, and clear `findings done`.
   - Periodically rotate `dev` (`kintoun engine make-dev -o .kintoun/engine_lab/sets/dev_r2.json --seed 2`) so builders don't overfit even to `dev`.

---

## 5. Running the Unseen Promotion Gate (Coordinator / Gatekeeper)

After 1 or more builder commits land on `combined`, the coordinator runs the **blind unseen gate**:

```bash
# Test live vs combined on 40 brand-new unseen functions, ablate commits, confirm on 2 draws, and promote on strict win:
kintoun engine gate --candidate combined --count 40 --budget 20s --workers 1 --confirm-runs 2 --ablate --promote
```

* If `win == true`: `combined` is backed up, promoted into `.kintoun/engine_lab/live/`, and activated (`active_engine.json`) for all future `CLI-OVERSEER` Matcher waves!
* If `win == false`: `live` stays untouched; builders read the gate report, sync to `combined`, and keep iterating.
* **Instant Emergency Rollback:**
  ```bash
  kintoun engine rollback
  # Or return to stock installed Kintoun without deleting lab history:
  kintoun engine rollback --disable
  ```

---

## 6. Pairing `CLI-OVERSEER` + `ENGINE-BUILDER` (The Self-Learning Flywheel)

On a long-running personal decomp project:
1. Run a **`CLI-OVERSEER`** wave of Namers + Matchers (`--governed`). Every solved match logs a `fix_category` + `engine_note` to `.kintoun/research/notes.jsonl`, and every `85..99%` near-miss saves its diff to `.kintoun/hints/`.
2. Run an **`ENGINE-BUILDER`** wave reading those exact `notes.jsonl` + `hints/` patterns to teach the project's side-tree engine the C-to-assembly transforms Matchers had to do by hand.
3. Run `kintoun engine gate --promote` on a wide unseen slice of the binary. Each promoted generation makes the next `CLI-OVERSEER` Matcher wave faster, cheaper, and higher-yield.
