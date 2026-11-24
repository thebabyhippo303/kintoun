"""Configuration loader for kintoun.toml (stdlib tomllib, Python 3.11+)."""
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
    assembler: list[str] = field(default_factory=list)


@dataclass
class TargetConfig:
    arch: str = "ppc_elf"
    dol: str = ""
    symbols: str = ""
    sda_r13: int = 0
    sda_r2: int = 0
    link_layout: str = ""
    binary: str = ""
    base_addr: int = 0
    gp: int = 0
    sb: int = 0
    thumb: bool = False
    endian: str = ""


SEARCH_MODES: dict[str, tuple[float, int]] = {
    "quick": (15.0, 250),
    "fast": (15.0, 250),
    "standard": (180.0, 2500),
    "thorough": (600.0, 10000),
    "deep": (1800.0, 50000),
    "unlimited": (86400.0, 1000000),
}


def parse_duration_s(val: Any, default: float = 180.0) -> float:
    """Parse seconds or human duration strings (`20`, `30s`, `5m`, `2h`, `unlimited`)."""
    if val is None or val == "":
        return default
    if isinstance(val, (int, float)):
        return float(val)
    s = str(val).strip().lower()
    if s in ("unlimited", "inf", "until-match", "max"):
        return 86400.0
    if s.endswith("ms"):
        return max(0.1, float(s[:-2]) / 1000.0)
    if s.endswith("s"):
        return float(s[:-1])
    if s.endswith("m"):
        return float(s[:-1]) * 60.0
    if s.endswith("h"):
        return float(s[:-1]) * 3600.0
    return float(s)


@dataclass
class SearchConfig:
    budget_s: float = 180.0
    max_candidates: int = 2500
    workers: int = 0
    strategies: list[str] = field(default_factory=lambda: ["systematic", "register_focus", "random"])
    cache_dir: str = ".kintoun/cache"
    priors_file: str = ""
    forbid_asm: bool = True
    mode: str = "standard"
    plateau: int = 0
    shared_governor: bool = False


@dataclass
class CompilerBand:
    """Optional address-range compiler override (`[[compiler_bands]]` in `kintoun.toml`)."""

    name: str
    start: int
    end: int
    compiler: CompilerConfig


@dataclass
class KintounConfig:
    root: Path
    project_name: str = "decomp-project"
    compiler: CompilerConfig = field(default_factory=CompilerConfig)
    target: TargetConfig = field(default_factory=TargetConfig)
    search: SearchConfig = field(default_factory=SearchConfig)
    compiler_bands: list[CompilerBand] = field(default_factory=list)

    def resolve_path(self, raw: str) -> Path | None:
        if not raw:
            return None
        expanded = os.path.expandvars(os.path.expanduser(raw))
        p = Path(expanded)
        return p if p.is_absolute() else (self.root / p).resolve()

    def compiler_for(self, va: int | None = None) -> CompilerConfig:
        """Return the matching `[[compiler_bands]]` config for `va`, or default `self.compiler`."""
        if va is not None:
            for band in self.compiler_bands:
                if band.start <= va < band.end:
                    return band.compiler
        return self.compiler


def _parse_int(val: Any, default: int = 0) -> int:
    if val is None or val == "":
        return default
    if isinstance(val, int):
        return val
    return int(str(val), 0)


def find_config(start: Path | None = None) -> Path | None:
    cur = (start or Path.cwd()).resolve()
    for parent in (cur, *cur.parents):
        cand = parent / "kintoun.toml"
        if cand.is_file():
            return cand
    return None


def load_config(path: Path | None = None) -> KintounConfig:
    """Load kintoun.toml if found, otherwise return sensible defaults rooted at cwd."""
    cfg_path = path or find_config()
    if cfg_path is None or not cfg_path.is_file():
        return KintounConfig(root=Path.cwd().resolve())

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
        assembler=list(comp_raw.get("assembler", [])),
    )
    target = TargetConfig(
        arch=str(tgt_raw.get("arch", "ppc_elf")),
        dol=str(tgt_raw.get("dol", "")),
        symbols=str(tgt_raw.get("symbols", "")),
        sda_r13=_parse_int(tgt_raw.get("sda_r13"), 0),
        sda_r2=_parse_int(tgt_raw.get("sda_r2"), 0),
        link_layout=str(tgt_raw.get("link_layout", "")),
        binary=str(tgt_raw.get("binary", "")),
        base_addr=_parse_int(tgt_raw.get("base_addr"), 0),
        gp=_parse_int(tgt_raw.get("gp"), 0),
        sb=_parse_int(tgt_raw.get("sb"), 0),
        thumb=bool(tgt_raw.get("thumb", False)),
        endian=str(tgt_raw.get("endian", "")),
    )
    mode_name = str(srch_raw.get("mode", "standard")).strip().lower() or "standard"
    mode_budget, mode_max_cands = SEARCH_MODES.get(mode_name, (180.0, 2500))
    search = SearchConfig(
        budget_s=parse_duration_s(srch_raw.get("budget_s"), mode_budget),
        max_candidates=int(srch_raw.get("max_candidates", mode_max_cands)),
        workers=int(srch_raw.get("workers", 0)),
        strategies=list(srch_raw.get("strategies", ["systematic", "register_focus", "random"])),
        cache_dir=str(srch_raw.get("cache_dir", ".kintoun/cache")),
        priors_file=str(srch_raw.get("priors_file", "")),
        forbid_asm=bool(srch_raw.get("forbid_asm", True)),
        mode=mode_name,
        plateau=int(srch_raw.get("plateau", 0)),
        shared_governor=bool(srch_raw.get("shared_governor", False)),
    )
    bands_raw = data.get("compiler_bands", [])
    compiler_bands: list[CompilerBand] = []
    if isinstance(bands_raw, list):
        for idx, b in enumerate(bands_raw):
            if not isinstance(b, dict):
                continue
            b_cc = CompilerConfig(
                preset=str(b.get("preset", compiler.preset)),
                command=list(b.get("command", [])),
                flags=list(b.get("flags", [])),
                compiler_dir=str(b.get("compiler_dir", compiler.compiler_dir)),
                wine=str(b.get("wine", compiler.wine)),
                wineprefix=str(b.get("wineprefix", compiler.wineprefix)),
                timeout_s=float(b.get("timeout_s", compiler.timeout_s)),
                env={**compiler.env, **{str(k): str(v) for k, v in b.get("env", {}).items()}},
                assembler=list(b.get("assembler", compiler.assembler)),
            )
            compiler_bands.append(
                CompilerBand(
                    name=str(b.get("name", f"band_{idx}")),
                    start=_parse_int(b.get("start"), 0),
                    end=_parse_int(b.get("end"), 0),
                    compiler=b_cc,
                )
            )

    return KintounConfig(
        root=root,
        project_name=str(proj.get("name", root.name)),
        compiler=compiler,
        target=target,
        search=search,
        compiler_bands=compiler_bands,
    )
