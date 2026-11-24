# Kintoun Workflows: Single-Machine Brute Force, Multi-Agent Queue, and Overseer

Kintoun works right out of the box as a lean single-command CLI (`verify` / `permute` / `close`), and scales cleanly to multi-agent MCP setups and autonomous supervision with zero external runtime dependencies.

---

## 1. Fast Function Triage, Context Packs, and Near-Miss Closing

```bash
# 1. Fast non-plain-C blocker & static difficulty check (0..100: easy/medium/hard/brutal)
kintoun check --func Player__Update

# 2. Compact ~1.5k-token one-call brief (stdlib disassembly, callees, globals, prototypes, hints)
kintoun context --func Player__Update

# 3. Zero-LLM diff-classified near-miss closer ($0 API cost)
#    Classifies diff into register_allocation, instruction_order, missing_cast, stack_layout,
#    constant_literal, branch_shape, or float_shape and runs 1-to-2 targeted passes:
kintoun close src/Player/Update.c --func Player__Update --write
```

---

## 2. Single-Machine Brute-Force Governor & Persistent Wine

When running multiple terminals, batch sweeps, or AI agents on one machine, Kintoun's shared governor (`CompileGovernor`) prevents CPU/RAM thrashing and keeps interactive `verify` calls fast:
* **3-tier admission (`governor_state.json`):** Reserves fast slots for interactive `verify`/`revise_candidate`, shares spare cores fairly across `permute --governed` searches, and runs background `close` sweeps at lowest priority (`<= 2` slots, yielding whenever interactive/search callers wait).
* **Zram- & cgroup-aware `AutoTuner`:**Monitors active working set (`memory.current - inactive_file`), Linux memory PSI, and real swap-in rate (`pswpin` pages/s) so cold zram swap never causes false pauses.
* **Persistent Wine (`warm-wine`):** Starts `wineserver -p` so Win32 compilers (`prodg-wine`, `mwcc-wine`) skip the ~300ms Wine startup overhead on every candidate.

```bash
# Start persistent wineserver (15m idle persistence)
kintoun warm-wine --persist 900

# Inspect live governor slots and memory auto-tuner level (0=paused .. 3=full)
kintoun warm-wine --status

# Run governed search (or set `shared_governor = true` under [search] in kintoun.toml)
kintoun permute src/Player/Update.c --func Player__Update --governed --thorough --write
```

---

## 3. Multi-Agent Work Queue & Chess Clock (`kintoun queue` & `kintoun mcp`)

Coordinate multiple developers or AI agents against `.kintoun/queue.sqlite3` with server-enforced chess clocks, multi-claim multiplexing, and automatic timeout quarantine:

```bash
# Populate queue from kintoun.toml with static difficulty tiers
kintoun queue init
kintoun queue status

# Claim next function, check chess clock, and submit a verified match
kintoun queue claim --agent agent-1 --tier easy
kintoun queue clock --agent agent-1
kintoun queue submit --agent agent-1 --func Player__Update --source src/Player/Update.c \
  --category missing_cast --note "Changed count field from s16 to u16 to replace extsh with clrlwi"
```

When running `kintoun mcp`, agents get 14 structured MCP tools out of the box:
* **Inspection:** `kintoun_info`, `kintoun_check`, `kintoun_context_pack`
* **Surgical Iteration & Search:** `kintoun_verify`, `kintoun_score_candidate`, `kintoun_revise_candidate`, `kintoun_score_candidates`, `kintoun_permute`, `kintoun_close_near_miss`
* **Queue & Chess Clock:** `kintoun_claim_next`, `kintoun_clock`, `kintoun_submit_match`, `kintoun_fail_claim`, `kintoun_queue_status`

---

## 4. Out-of-the-Box Overseer (`none`, `single`, or `dual` Brain)

`kintoun overseer` supervises the queue, reaps expired chess clocks, quarantines multi-timeout duds, auto-closes `>=85%` near-misses using `closer.py`, and optionally steers `tmux` workers. Pick the brain mode that fits your setup:

### Option A: Zero-API Code-Only Mode (`--brain none`, default, `$0.00`)
Needs no API keys at all. Runs all deterministic reflexes (clock reaping, quarantine, auto-tuned zero-LLM near-miss closing, journal):
```bash
kintoun overseer once --brain none
kintoun overseer loop --brain none
```

### Option B: Single-Brain Mode (`--brain single`, one API key or local Ollama)
Uses **one** provider (`openai`, `openai-compatible`, `anthropic`, or `gemini`) for both fast state-gated triage/rule-checks and supervisor decisions under one daily USD cap:
```bash
# Single cloud API (e.g. OpenAI, Anthropic, or Gemini)
export OPENAI_API_KEY="sk-..."
kintoun overseer once --brain single --provider openai --model gpt-4o-mini --budget-usd 1.50

# Or local zero-cost Ollama / vLLM endpoint (OpenAI-compatible)
kintoun overseer once --brain single --provider openai-compatible \
  --base-url http://localhost:11434/v1 --model qwen2.5-coder:14b
```

### Option C: Dual-Brain Mode (`--brain dual`, fast triage + deep main model)
Configure `[overseer]`, `[overseer.fast_brain]`, and `[overseer.main_brain]` in `kintoun.toml` so cheap triage/standing-rule checks hit a fast/cheap endpoint while strategic routing uses a deeper reasoning model, with automatic fallback between them.

---

## 5. Reproducible Benchmarking & Prior Learning (`kintoun bench`)

```bash
# Run a benchmark manifest, verify zero lost exact matches vs baseline, and learn priors
kintoun bench bench_dev.json --budget 20s --out report_dev.json \
  --baseline report_base.json --learn-priors .kintoun/priors.json
```

---

## 6. Portable Agent Skills (`skills/CLI-OVERSEER/` and `skills/kintoun-match/`)

* **`skills/CLI-OVERSEER/SKILL.md`:** Orchestrator skill enabling any standard CLI coding agent to delegate parallel **Namer** and **Matcher** subagents over Kintoun's queue and governor (standalone or alongside `kintoun overseer`). Includes copy-ready subagent brief templates in `skills/CLI-OVERSEER/references/subagent-briefs.md`.
* **`skills/kintoun-match/SKILL.md`:** Matcher workflow skill with dedicated symptom-to-C lookup tables for PowerPC (`powerpc.md`), MIPS (`mips.md`), and ARM/Thumb (`arm.md`).

Copy or symlink either skill folder into your agent's skill directory (`.claude/skills/`, `.codex/skills/`, `.gemini/skills/`, or Cursor rules).
