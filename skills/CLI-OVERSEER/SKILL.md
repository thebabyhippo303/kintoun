---
name: CLI-OVERSEER
description: Project-level decompilation orchestrator skill that delegates to subagents as Matchers and Namers over Kintoun's queue, chess clock, governor, and near-miss closer, and interoperates with the kintoun overseer daemon (code-only, single-brain, or dual-brain).
---

# Skill: CLI-OVERSEER (Subagent & Hybrid Decompilation Orchestrator)

`CLI-OVERSEER` turns any standard CLI coding agent (Claude Code, Codex CLI, Gemini CLI, OpenCode, Cursor, etc.) into a full decompilation project orchestrator. It delegates parallel function **Naming** and **Matching** to subagents while sharing `.kintoun/queue.sqlite3`, `.kintoun/cache/`, and `CompileGovernor` with `kintoun overseer` (whether `kintoun overseer` runs in `$0` code-only mode, single-API mode, or dual-API mode).

---

## 1. Two Operating Modes (Use Either or Both Together)

1. **Standard CLI Subagent Mode (No separate API keys needed):**
   - Your main CLI agent runs this `CLI-OVERSEER` skill and spawns **Namer** and **Matcher** subagents using its built-in subagent / task tool.
   - Between waves (or in a background terminal), run `kintoun overseer once --brain none` (or `kintoun overseer loop --brain none`) so `$0` deterministic housekeeping runs automatically: expiring stale chess clocks, quarantining repeated low-% duds, auto-tuning machine pressure, and closing `>= 85%` near-misses with zero LLM tokens.
2. **Hybrid Mode with the API `kintoun overseer` (`--brain single` or `--brain dual`):**
   - Run `kintoun overseer loop --brain single` (one cloud API or local Ollama/vLLM endpoint) or `--brain dual` to supervise `tmux` workers and queue health unattended.
   - Use `CLI-OVERSEER` interactively to launch targeted Namer/Matcher subagent waves, inspect hard blockers, unquarantine parked functions with fresh strategies, and update compiler priors (`kintoun bench --learn-priors`).

Both modes read and write the exact same SQLite WAL queue (`.kintoun/queue.sqlite3`) and cross-process compile governor (`.kintoun/cache/governor_state.json`), so they never step on each other.

---

## 2. Pre-Flight Checklist (Run Once per Session)

1. **Sync the work queue & static difficulty tiers (`easy`, `medium`, `hard`, `brutal`):**
   ```bash
   kintoun queue init
   kintoun queue status
   ```
2. **Check single-machine compile slots & warm Wine (if using `prodg-wine` or `mwcc-wine`):**
   ```bash
   kintoun warm-wine --status
   # Only for Wine-hosted Windows compilers:
   kintoun warm-wine --persist 900
   ```
3. **Read queue balance before spawning subagents:**
   - If unnamed `fn_XXXXXXXX` / `sub_XXXXXXXX` symbols dominate and `pending` named functions are low (`< 15`), spawn **1 to 2 Namer subagents** alongside **Matchers**.
   - If `pending` has plenty of functions, focus subagent capacity on **Matchers** split by difficulty tier.

---

## 3. Delegating to Subagents

Read [references/subagent-briefs.md](references/subagent-briefs.md) for ready-to-send prompt templates for each role.

### Role A: NAMER Subagents (Evidence-Backed Symbol Naming)
- **Partition by non-overlapping address bands or modules** (for example `0x80010000..0x8002FFFF` for `namer-1`, `0x80030000..0x8004FFFF` for `namer-2`) so two Namers never edit the same symbols.
- **Required evidence:** Namers inspect `kintoun context --func 0xADDR` (disassembly, direct callees, callers, string references, globals, struct offsets). Every name (`Class__Method` or `Module_VerbNoun`) must cite concrete evidence; uncertain functions keep an honest `_Unk` suffix rather than guessed names.
- **Boundary:** Namers update only the symbol map (`symbols.txt`) and never edit `src/*.c` or claim functions from the match queue. After a Namer finishes a batch, run `kintoun queue init` to pull the newly named functions into `pending`.

### Role B: MATCHER Subagents (Byte-Exact Real-C Matching)
- **Equip every Matcher with `skills/kintoun-match/SKILL.md`** and a unique agent ID (`matcher-1`, `matcher-2`, ...).
- **Route by difficulty tier:**
  - Fast / lightweight subagents -> `kintoun queue claim --agent matcher-1 --tier easy` (and `medium`).
  - Stronger reasoning subagents -> `kintoun queue claim --agent matcher-2 --tier hard` (and `brutal` / `float` / `switch`).
- **Enforce the Four Matcher Laws:**
  1. **Always pass `--governed`** on `kintoun permute` (or set `shared_governor = true` in `kintoun.toml`) so concurrent subagents share CPU/RAM cleanly without starving `kintoun verify`.
  2. **Fast `check` first:** Run `kintoun check --func NAME` right after claiming; immediately fail `not-plain-c` functions (`kintoun queue fail --agent ID --func NAME --reason not-plain-c`) so zero time is wasted on assembly/coprocessor routines.
  3. **Hand-Write Rule + Chess Clock:** `permute` is a seed, not a stopping point. Subagents must inspect the aligned diff, apply surgical C edits (using the PowerPC / MIPS / ARM lookup tables in `skills/kintoun-match/references/`), and run `kintoun close` on `>= 85%` near-misses until `VERIFIED` or clock expiry.
  4. **Real C Only + `submit` Note:** Submit only via `kintoun queue submit --agent ID --func NAME --source PATH --category CAT --note "..."` (or `kintoun_submit_match` over MCP), which rejects inline assembly and freshly re-verifies `different_bytes == 0`.

---

## 4. Orchestrator Wave Loop

Run this loop as the `CLI-OVERSEER` coordinator:

1. **Dispatch Wave:** Launch 2 to 6 subagents (Matchers + optional Namers) with distinct `--agent` IDs and non-overlapping assignments. Wait for their completion notifications rather than polling in tight shell loops.
2. **Housekeeping & `$0` Near-Miss Closing:** After each wave (or continuously via `kintoun overseer loop`), run:
   ```bash
   kintoun overseer once --brain none
   kintoun queue status
   ```
   This reaps expired claims, quarantines 2x low-% timeouts, and runs targeted zero-LLM `close_near_miss` passes on `>= 85%` functions.
3. **Handle Near-Misses & Quarantined Functions:**
   - Check `.kintoun/hints/*.json` or `queue status`'s `near_misses` list: assign stubborn `90..99%` functions to a strong Matcher subagent seeded from `.kintoun/hints/<func>.c`.
   - When `pending` runs low and `quarantined > 0`, release a batch (`kintoun queue unquarantine --limit 20`) and assign them to a **different** model family or deeper budget (`--thorough`).
4. **Compound Wins into Priors:** Periodically convert recorded match notes into updated search weights:
   ```bash
   kintoun bench bench_manifest.json --out bench_latest.json --learn-priors .kintoun/priors.json
   ```

---

## 5. Standing Guardrails for the Orchestrator
- **Never commit or push unverified C:** Every matched file must pass `kintoun verify` (`rc == 0`, `verified == true`, zero `real_c_violation`).
- **Stage paths explicitly in git:** When committing completed matches, stage specific files (`git add src/Foo/Bar.c`) rather than `git add -A` so parallel subagent scratch files are never swept in.
- **Respect machine memory:** Check `kintoun warm-wine --status`; if `autotune.level` drops to `0` or `1`, reduce concurrent Matcher subagents rather than overriding memory guards.
