# AGENTS.md - Kintoun Setup, Workflow, and Maintenance Guide for AI Agents

**Current Version:** `0.3.0` (keep this file updated alongside `pyproject.toml`, `src/kintoun/__init__.py`, and `CHANGELOG.md` on every release).

This guide is written for AI coding agents (Claude Code, Codex CLI, Gemini CLI, OpenCode, Cursor, etc.) when a user asks you to **set up Kintoun on their decompilation repository**, **match or name functions**, or **extend Kintoun itself**.

---

## 1. Quick Setup Playbook (Setting Kintoun Up on a User's Project)

Kintoun requires **Python 3.11+** and uses **only the Python standard library** (`dependencies = []`). No external system libraries, Capstone, or database servers are needed.

### Step 1: Install Kintoun
```bash
# Core CLI + verifier + permuter + queue + overseer (stdlib only):
python3 -m pip install -e /path/to/kintoun

# Optional: add MCP server support (`kintoun mcp`) if the host client uses MCP:
python3 -m pip install -e "/path/to/kintoun[mcp]"
```

### Step 2: Pick the Matching Preset & Generate `kintoun.toml`
Inspect the user's project to identify the target console/ISA and compiler, then run `kintoun init` in the project root:

| Platform / ISA | `target.arch` | Presets (`kintoun init --preset <name>`) |
|---|---|---|
| GameCube / Wii (PowerPC) | `ppc_elf` | `prodg-wine`, `mwcc-wine`, `custom` |
| PlayStation 2 (MIPS R5900 EE) | `mips_elf` | `ee-gcc`, `mwccps2`, `mips-gcc` |
| PSP (MIPS Allegrex / PRX) | `mips_elf` | `psp-gcc`, `mwccpsp`, `pspsnc` |
| Generic MIPS32 (LE or BE) | `mips_elf` | `mips-gcc`, `custom` |
| Game Boy Advance (ARM7TDMI) | `arm_elf` | `agbcc`, `arm-none-eabi-gcc` |
| Nintendo DS (ARM946E / ARM7) | `arm_elf` | `mwccarm`, `armcc`, `arm-none-eabi-gcc` |

```bash
cd /path/to/user-decomp-repo
kintoun init --preset prodg-wine
```

### Step 3: Wire Paths in `kintoun.toml`
Edit `kintoun.toml` so paths match the user's repo layout (all paths expand `~` and `${ENV_VAR}`):
- **`[compiler]`:** Set `compiler_dir` (and `wine = "wibo"` or `"wine"` for Windows console compilers), plus exact project optimization `flags` (for example `["-O2", "-c"]` or `["-O4,p", "-nodefaults", "-proc", "gekko", "-fp", "hardware", "-c"]`).
- **`[target]`:**
  - **PowerPC DOL:** Set `dol`, `symbols`, `sda_r13`, and `sda_r2`.
  - **MIPS ELF / PRX / binary:** Set `binary` (ELF32 `ET_EXEC`, PSP `0xFFA0` PRX, or flat binary), `symbols` (dtk `symbols.txt`, splat `symbol_addrs.txt`, or `nm` map), and `gp` (`"0x0"` auto-detects `$gp` from `.reginfo` / `.MIPS.options` / `SceModuleInfo`).
  - **ARM / Thumb ROM or ELF:** Set `binary` (e.g. `"baserom.gba"`), `base_addr` (`"0x08000000"` for GBA), `symbols`, and `thumb = true` for Thumb targets.
  - **Standalone `.o` mode:** Even without a full ROM/DOL, `kintoun verify cand.c --target orig.o` and `kintoun permute cand.c --target orig.o` work immediately.

### Step 4: Smoke-Test the Setup
```bash
# 1. Confirm config resolution
kintoun info

# 2. If using Wine-hosted Windows compilers, start persistent wineserver + check governor slots
kintoun warm-wine --persist 900
kintoun warm-wine --status

# 3. Check a target function for non-plain-C blockers and view its ~1.5k-token context brief
kintoun check --func <FuncNameOr0xAddr>
kintoun context --func <FuncNameOr0xAddr>
```

---

## 2. Installing Kintoun's Built-In Agent Skills (`skills/`)

Kintoun ships two portable skill folders under `skills/`:
1. **`skills/kintoun-match/`** - Byte-exact C matching workflow plus PowerPC (`powerpc.md`), MIPS (`mips.md`), and ARM/Thumb (`arm.md`) assembly-diff-to-C lookup tables.
2. **`skills/CLI-OVERSEER/`** - Project orchestrator skill enabling standard CLI coding models to delegate parallel **Matcher** and **Namer** subagents over Kintoun's queue and governor (standalone or alongside `kintoun overseer`).

Copy or symlink them into whichever agent skill directory the user's CLI reads:
```bash
# Examples (pick the directory used by your CLI environment):
mkdir -p .claude/skills && cp -r /path/to/kintoun/skills/* .claude/skills/
mkdir -p .codex/skills  && cp -r /path/to/kintoun/skills/* .codex/skills/
mkdir -p .gemini/skills && cp -r /path/to/kintoun/skills/* .gemini/skills/
```

If the user's client supports MCP, register `kintoun mcp` (run from the decomp repo root, or `kintoun -c /path/to/kintoun.toml mcp`) to expose all **14 MCP tools**:
- **Inspection:** `kintoun_info`, `kintoun_check`, `kintoun_context_pack`
- **Scoring & Search:** `kintoun_verify`, `kintoun_score_candidate`, `kintoun_revise_candidate`, `kintoun_score_candidates`, `kintoun_permute`, `kintoun_close_near_miss`
- **Multi-Agent Queue & Clock:** `kintoun_claim_next`, `kintoun_clock`, `kintoun_submit_match`, `kintoun_fail_claim`, `kintoun_queue_status`

---

## 3. Choosing the Right Operating Mode

| User Goal | Recommended Setup |
|---|---|
| **Match one function interactively** | `kintoun check` -> `kintoun context` -> `kintoun permute cand.c --func F --write --write-best` -> hand-refine C -> `kintoun close cand.c --func F --write` -> `kintoun verify` |
| **CLI agent orchestrating subagents (no extra API keys)** | Load `skills/CLI-OVERSEER/SKILL.md`, run `kintoun queue init`, spawn Namer + Matcher subagents (`--governed`), and run `kintoun overseer once --brain none` between waves |
| **Unattended supervisor with $0 API cost** | `kintoun overseer loop --brain none` (reaps expired clocks, quarantines 2x low-% duds, auto-tunes pressure, runs zero-AI `close` on `>= 85%` near-misses) |
| **Unattended supervisor with 1 API or local Ollama** | `kintoun overseer loop --brain single --provider openai --model gpt-4o-mini --budget-usd 1.50` (or `--provider openai-compatible --base-url http://localhost:11434/v1 --model qwen2.5-coder:14b`) |
| **Unattended supervisor with 2 models/APIs** | Configure `[overseer]` (`brain_mode = "dual"`), `[overseer.fast_brain]`, and `[overseer.main_brain]` in `kintoun.toml`, then run `kintoun overseer loop` |

---

## 4. Non-Negotiable Matching Rules for Agents

1. **Real C Only:** Never emit `asm`, `__asm__`, `GLOBAL_ASM`, `register ... __asm__("...")` pins, naked functions, `.long` / `.4byte` / `.word` / `.byte`, or constant-pool padding. `kintoun verify` and `kintoun queue submit` reject them.
2. **Hand-Write Rule:** Automated search (`permute` / `close`) is a seed and force multiplier, not a reason to give up on plateau. Read the aligned diff (`-` extra, `+` missing, `!` swapped registers), edit real C using `skills/kintoun-match/references/{powerpc,mips,arm}.md`, and iterate until `VERIFIED` (`different_bytes == 0`) or clock expiry.
3. **Token Discipline:** Use `kintoun context` (or `kintoun_context_pack`) instead of reading whole binaries, and use `kintoun_revise_candidate` (`old -> new` patches) instead of rewriting entire files on each attempt.
4. **Single-Machine Courtesy:** Pass `--governed` on parallel `permute` runs (or set `shared_governor = true` under `[search]` in `kintoun.toml`) so interactive `verify` slots stay fast and RAM headroom is respected.

---

## 5. Repository Map & Maintenance Checklist (Updating Kintoun)

- `src/kintoun/arch/` - Dedicated ELF32 readers, relocators, and stdlib disassemblers (`elf.py` + `ppc_elf.py` + `ppc_disasm.py`, `mips_elf.py` + `mips_disasm.py`, `arm_elf.py` + `arm_disasm.py`).
- `src/kintoun/search/` - Per-ISA scorers, live-range permuters, repair hypotheses, raw `m2c` seed recovery (`ppc_seeds.py`, `mips_seeds.py`, `arm_seeds.py`), 7 themed `mutations_*.py` modules, and beam-search `runner.py`.
- `src/kintoun/verify.py`, `verify_mips.py`, `verify_arm.py` - Strict relocation-exact verifiers.
- `src/kintoun/governor.py` - 3-tier cross-process compile governor, zram/cgroup `AutoTuner`, 64-stripe deduper, and persistent Wine helper.
- `src/kintoun/candidates.py` - `cand_<12hex>` candidate store, negative compile-error cache, `revise`, and `score_batch`.
- `src/kintoun/inspect_fn.py` & `closer.py` - Blocker `check`, static difficulty scorer, `context_pack`, and 7-class zero-AI near-miss closer.
- `src/kintoun/queue.py`, `overseer.py`, `lab.py` - SQLite WAL chess-clock work queue, `none`/`single`/`dual`-brain Overseer, and benchmark/prior runner.
- `skills/` & `docs/` - Portable `CLI-OVERSEER` and `kintoun-match` skills plus user documentation.

### Version Bump Checklist
Whenever shipping a new Kintoun version:
1. Keep core `dependencies = []` (Python 3.11+ stdlib only) and preserve dedicated per-architecture implementations (no shallow generic arch layer).
2. Update the version together in `pyproject.toml`, `src/kintoun/__init__.py`, `CHANGELOG.md`, and the **`Current Version:`** header at the top of `AGENTS.md` (enforced by `tests/test_agent_fleet.py`).
3. Run the full test suite (`PYTHONPATH=src python3 -m unittest discover -s tests -v`) and ensure 100% pass before packaging.
