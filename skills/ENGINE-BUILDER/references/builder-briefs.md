# Subagent Brief Templates for `ENGINE-BUILDER`

Copy and fill `<BUILDER_ID>`, `<FOCUS_LANE>`, and `<DEV_SET_PATH>` when spawning subagents.

---

## 1. Solo `ENGINE-BUILDER` Subagent Brief (Personal Project Rapid Iteration)

```text
Role: Kintoun Engine Builder (<BUILDER_ID>)
Read `skills/ENGINE-BUILDER/SKILL.md` before making any edits.

Assignment:
Complete <CYCLES> rapid side-tree improvement cycles on `.kintoun/engine_lab/builders/<BUILDER_ID>/src/kintoun/` for this project's target architecture and compiler.

Rules & Boundaries:
- Edit ONLY files inside `.kintoun/engine_lab/builders/<BUILDER_ID>/src/kintoun/`.
- NEVER edit `.kintoun/engine_lab/live/`, the main Kintoun installation, `src/*.c`, `symbols.txt`, or `.kintoun/queue.sqlite3`.
- Keep all candidate C generations 100% real C (no inline `asm`, `GLOBAL_ASM`, register pins, or raw `.word`/`.long` directives) and Python 3.11+ stdlib only.

Cycle steps:
1. Inspect context: run `kintoun engine status`, `kintoun engine findings show -n 15`, and read `.kintoun/research/notes.jsonl` + `.kintoun/hints/*.json` to identify the top recurring mismatch pattern in this codebase.
2. Sync your side tree: `kintoun engine sync --builder <BUILDER_ID>`.
3. Lock your hypothesis: `kintoun engine findings start --builder <BUILDER_ID> --change <SLUG> --what "<1-line hypothesis>"`.
4. Implement ONE clean, general C-mutation, seed-repair, or guidance improvement in `.kintoun/engine_lab/builders/<BUILDER_ID>/src/kintoun/`.
5. Benchmark head-to-head on the dev set (never on unseen gate sets):
   - `kintoun engine bench --arm live --set <DEV_SET_PATH> --budget 15s --workers 1 --json`
   - `kintoun engine bench --arm <BUILDER_ID> --set <DEV_SET_PATH> --budget 15s --workers 1 --json`
6. Commit or revert:
   - If `<BUILDER_ID>` beats `live` on dev (more exact matches or higher mean aligned % with 0 lost exact matches): run `kintoun engine commit --builder <BUILDER_ID> --claim "<what & why>"`.
   - Otherwise revert cleanly: `kintoun engine sync --builder <BUILDER_ID> --force`.
7. Log & release lock:
   - `kintoun engine findings log --builder <BUILDER_ID> --change <SLUG> --dev "<live>% -> <cand>% (<live_exact>-><cand_exact> exact)" --verdict <committed|reverted> --lesson "<1-line takeaway>"`
   - `kintoun engine findings done --builder <BUILDER_ID>`

Report back: commits added to `combined`, dev score deltas, and reverted hypotheses so the coordinator can run `kintoun engine gate`.
```

---

## 2. Parallel 4-Lane `ENGINE-BUILDER` Subagent Brief (`b1`..`b4`)

```text
Role: Kintoun Engine Builder (<BUILDER_ID> - Focus Lane: <FOCUS_LANE>)
Read `skills/ENGINE-BUILDER/SKILL.md` before starting.

Your Assigned Focus Lane (stay strictly inside your lane so builders do not conflict):
- If `b1`: Scorer, alignment hints, beam diversity & wasted-budget pruning (`runner.py`, `*_guidance.py`, `closer.py`).
- If `b2`: Float/FPU/FMA casts, switch/jump-table lowering & constant/rodata repairs (`constants.py`, `mutations_float.py`, `mutations_switch.py`, `*_mutations.py`).
- If `b3`: Register allocation, live-range permuter & load/store/temp scheduling (`*_permuter.py`, `mutations_order_*.py`, `base_mutations.py`).
- If `b4`: Raw seed compile-error recovery, struct/prototype inference & loop/guard shapes (`*_seeds.py`, `mutations_recovery.py`, `inspect_fn.py`).

Loop (<CYCLES> iterations):
1. Run `kintoun engine findings show -n 20` (never repeat a reverted idea without a new mechanism) and `kintoun engine sync --builder <BUILDER_ID>`.
2. Claim your hypothesis with `kintoun engine findings start --builder <BUILDER_ID> --change <SLUG> --what "<hypothesis>"`. If REFUSED, choose another idea in your lane.
3. Edit ONLY `.kintoun/engine_lab/builders/<BUILDER_ID>/src/kintoun/` within your lane's modules.
4. Run `kintoun engine bench` for `live` and `<BUILDER_ID>` on `<DEV_SET_PATH>` (`--workers 1`).
5. Commit dev wins (`kintoun engine commit --builder <BUILDER_ID> --claim "..."`) or discard duds (`kintoun engine sync --builder <BUILDER_ID> --force`), log via `kintoun engine findings log`, and clear `kintoun engine findings done`.
6. Never run `kintoun engine gate --promote` yourself; the coordinator judges `combined` on blind unseen functions.
```

---

## 3. Unseen Gatekeeper Subagent Brief

```text
Role: Kintoun Engine Gatekeeper
Read `skills/ENGINE-BUILDER/SKILL.md`.

Assignment:
Evaluate `combined` against `live` on a fresh, wide unseen function draw and promote ONLY if it passes the strict dual-metric gate.

Steps:
1. Check `kintoun engine status`. Confirm `commits_above_live` is non-empty and no builder has broken syntax.
2. Run the blind unseen gate with per-commit ablation and confirmation:
   `kintoun engine gate --candidate combined --count <COUNT> --budget 20s --workers 1 --confirm-runs 2 --ablate --promote --json`
3. Report back:
   - Which commits survived ablation vs were auto-reverted,
   - Unseen `live` vs `combined` exact match count and mean aligned % across confirmation rounds,
   - Whether `combined` was promoted to `live` (and the backup path in `.kintoun/engine_lab/backups/`).
```
