"""Configuration loader for nim-dtk.toml (stdlib tomllib, Python 3.11+)."""
from __future__ import annotations

from dataclasses import dataclass, field
import os
from pathlib import Path
import tomllib
from typing import Any


@dataclass
class CompilerConfig:
    preset: str = "custom"
    command: list[str] = field(default_factory=list)
    flags: list[str] = field(default_factory=list)
    compiler_dir: str = ""
    wine: str = "wine"
    wineprefix: str = ""
    timeout_s: float = 30.0
    env: dict[str, str] = field(default_factory=dict)


@dataclass
class TargetConfig:
    arch: str = "ppc_elf"
    dol: str = ""
    symbols: str = ""
    sda_r13: int = 0
    sda_r2: int = 0
    link_layout: str = ""


@dataclass
class SearchConfig:
    budget_s: float = 60.0
    max_candidates: int = 600
    workers: int = 0
    strategies: list[str] = field(default_factory=lambda: ["systematic", "register_focus", "random"])
    cache_dir: str = ".nim-dtk/cache"
    priors_file: str = ""
    forbid_asm: bool = True


@dataclass
class NimDtkConfig:
    root: Path
    project_name: str = "decomp-project"
    compiler: CompilerConfig = field(default_factory=CompilerConfig)
    target: TargetConfig = field(default_factory=TargetConfig)
    search: SearchConfig = field(default_factory=SearchConfig)

    def resolve_path(self, raw: str) -> Path | None:
        if not raw:
            return None
        expanded = os.path.expandvars(os.path.expanduser(raw))
        p = Path(expanded)
        return p if p.is_absolute() else (self.root / p).resolve()


def _parse_int(val: Any, default: int = 0) -> int:
    if val is None or val == "":
        return default
    if isinstance(val, int):
        return val
    return int(str(val), 0)


def find_config(start: Path | None = None) -> Path | None:
    cur = (start or Path.cwd()).resolve()
    for parent in (cur, *cur.parents):
        cand = parent / "nim-dtk.toml"
        if cand.is_file():
            return cand
    return None


def load_config(path: Path | None = None) -> NimDtkConfig:
    """Load nim-dtk.toml if found, otherwise return sensible defaults rooted at cwd."""
    cfg_path = path or find_config()
    if cfg_path is None or not cfg_path.is_file():
        return NimDtkConfig(root=Path.cwd().resolve())

    data = tomllib.loads(cfg_path.read_text(encoding="utf-8"))
    root = cfg_path.resolve().parent

    proj = data.get("project", {})
    comp_raw = data.get("compiler", {})
    tgt_raw = data.get("target", {})
    srch_raw = data.get("search", {})

    compiler = CompilerConfig(
        preset=str(comp_raw.get("preset", "custom")),
        command=list(comp_raw.get("command", [])),
        flags=list(comp_raw.get("flags", [])),
        compiler_dir=str(comp_raw.get("compiler_dir", "")),
        wine=str(comp_raw.get("wine", "wine")),
        wineprefix=str(comp_raw.get("wineprefix", "")),
        timeout_s=float(comp_raw.get("timeout_s", 30.0)),
        env={str(k): str(v) for k, v in comp_raw.get("env", {}).items()},
    )
    target = TargetConfig(
        arch=str(tgt_raw.get("arch", "ppc_elf")),
        dol=str(tgt_raw.get("dol", "")),
        symbols=str(tgt_raw.get("symbols", "")),
        sda_r13=_parse_int(tgt_raw.get("sda_r13"), 0),
        sda_r2=_parse_int(tgt_raw.get("sda_r2"), 0),
        link_layout=str(tgt_raw.get("link_layout", "")),
    )
    search = SearchConfig(
        budget_s=float(srch_raw.get("budget_s", 60.0)),
        max_candidates=int(srch_raw.get("max_candidates", 600)),
        workers=int(srch_raw.get("workers", 0)),
        strategies=list(srch_raw.get("strategies", ["systematic", "register_focus", "random"])),
        cache_dir=str(srch_raw.get("cache_dir", ".nim-dtk/cache")),
        priors_file=str(srch_raw.get("priors_file", "")),
        forbid_asm=bool(srch_raw.get("forbid_asm", True)),
    )
    return NimDtkConfig(
        root=root,
        project_name=str(proj.get("name", root.name)),
        compiler=compiler,
        target=target,
        search=search,
    )
