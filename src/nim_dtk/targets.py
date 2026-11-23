"""Target binary, DOL, ELF object, and dtk symbol-map loaders for NIM-DTK."""
from __future__ import annotations

from dataclasses import dataclass, field
import json
from pathlib import Path
import re
import struct
from typing import Any

from nim_dtk.arch.elf import Object
from nim_dtk.config import NimDtkConfig

_SYM_RE = re.compile(r"^(\S+)\s*=\s*\.([^:]+):(0x[0-9A-Fa-f]+);(.*)$")
_SIZE_RE = re.compile(r"size:(0x[0-9A-Fa-f]+)")


@dataclass(frozen=True)
class TargetFunction:
    name: str
    va: int
    size: int
    data: bytes
    section: str = ".text"


@dataclass
class TargetContext:
    """Everything needed to verify and relocate a compiled function against a target."""

    arch: str = "ppc_elf"
    sda_r13: int = 0
    sda_r2: int = 0
    funcs: dict[str, tuple[int, int]] = field(default_factory=dict)
    by_addr: dict[int, str] = field(default_factory=dict)
    objs: dict[int, tuple[str, int]] = field(default_factory=dict)
    external: dict[str, int] = field(default_factory=dict)
    data_segments: list[tuple[int, bytes]] = field(default_factory=list)
    _regions: list[tuple[int, int, int, bool]] = field(default_factory=list)
    _image: bytes = b""
    explicit_layouts: dict[str, dict[str, int]] = field(default_factory=dict)

    def read(self, va: int, size: int) -> bytes:
        for file_off, addr, length, _is_code in self._regions:
            if addr <= va and va + size <= addr + length:
                rel = va - addr
                return self._image[file_off + rel : file_off + rel + size]
        raise ValueError(f"address range 0x{va:08X}+0x{size:X} not mapped in target binary")

    def resolve_function(self, spec: str) -> TargetFunction:
        if spec in self.funcs:
            va, size = self.funcs[spec]
            return TargetFunction(spec, va, size, self.read(va, size))
        try:
            va = int(spec, 0)
        except ValueError:
            raise ValueError(f"unknown target function: {spec}") from None
        if va in self.by_addr:
            name = self.by_addr[va]
            _, size = self.funcs[name]
            return TargetFunction(name, va, size, self.read(va, size))
        raise ValueError(f"no function symbol at 0x{va:08X}")

    def layout_for(self, name: str) -> dict[str, int]:
        return self.explicit_layouts.get(name, {})


def parse_dol(path: Path) -> tuple[bytes, list[tuple[int, int, int, bool]]]:
    """Parse a GameCube/Wii DOL executable into (raw_bytes, [(file_off, va, size, is_code)])."""
    image = path.read_bytes()
    if len(image) < 0x100:
        raise ValueError(f"DOL too small: {path}")
    offsets = struct.unpack_from(">18I", image, 0x00)
    addrs = struct.unpack_from(">18I", image, 0x48)
    sizes = struct.unpack_from(">18I", image, 0x90)
    regions: list[tuple[int, int, int, bool]] = []
    for i in range(18):
        if sizes[i] > 0 and addrs[i] != 0:
            regions.append((offsets[i], addrs[i], sizes[i], i < 7))
    return image, regions


def parse_dtk_symbols(path: Path) -> tuple[dict[str, tuple[int, int]], dict[int, str], dict[int, tuple[str, int]]]:
    """Parse a dtk-format symbols.txt into (funcs, by_addr, objs)."""
    funcs: dict[str, tuple[int, int]] = {}
    by_addr: dict[int, str] = {}
    objs: dict[int, tuple[str, int]] = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        m = _SYM_RE.match(line.strip())
        if not m:
            continue
        name, _sec, addr_s, rest = m.groups()
        va = int(addr_s, 16)
        sm = _SIZE_RE.search(rest)
        size = int(sm.group(1), 16) if sm else 0
        if "type:function" in rest:
            funcs[name] = (va, size)
            by_addr[va] = name
        else:
            objs[va] = (name, size)
    return funcs, by_addr, objs


def load_link_layout(path: Path | None) -> dict[str, dict[str, int]]:
    if path is None or not path.is_file():
        return {}
    doc = json.loads(path.read_text(encoding="utf-8"))
    out: dict[str, dict[str, int]] = {}
    for fn_name, entry in doc.get("functions", {}).items():
        sections = entry.get("sections", {})
        out[fn_name] = {k: int(v, 0) if isinstance(v, str) else int(v) for k, v in sections.items()}
    return out


def load_target_from_config(cfg: NimDtkConfig) -> TargetContext:
    """Build a TargetContext from nim-dtk.toml (DOL + dtk symbols.txt)."""
    dol_path = cfg.resolve_path(cfg.target.dol)
    sym_path = cfg.resolve_path(cfg.target.symbols)
    layout_path = cfg.resolve_path(cfg.target.link_layout)

    image, regions = parse_dol(dol_path) if dol_path and dol_path.is_file() else (b"", [])
    funcs, by_addr, objs = parse_dtk_symbols(sym_path) if sym_path and sym_path.is_file() else ({}, {}, {})
    external: dict[str, int] = {name: va for name, (va, _sz) in funcs.items()}
    external.update({row[0]: va for va, row in objs.items()})
    data_segments = [(addr, image[off : off + sz]) for off, addr, sz, is_code in regions if not is_code]

    return TargetContext(
        arch=cfg.target.arch,
        sda_r13=cfg.target.sda_r13,
        sda_r2=cfg.target.sda_r2,
        funcs=funcs,
        by_addr=by_addr,
        objs=objs,
        external=external,
        data_segments=data_segments,
        _regions=regions,
        _image=image,
        explicit_layouts=load_link_layout(layout_path),
    )


def load_target_from_object(obj_path: Path, func_name: str | None = None) -> tuple[TargetContext, TargetFunction]:
    """Load a standalone target ELF32 .o file (e.g. from decomp.me or a single-function build)."""
    elf = Object(obj_path.read_bytes())
    defined = [
        sym
        for table in elf.tables.values()
        for sym in table
        if (sym.info & 15) == 2 and 0 < sym.section < len(elf.sections) and sym.size > 0
    ]
    if func_name:
        matches = [s for s in defined if s.name == func_name]
        if len(matches) != 1:
            raise ValueError(f"expected one function '{func_name}' in {obj_path}; found {[s.name for s in defined]}")
        sym = matches[0]
    else:
        if len(defined) != 1:
            raise ValueError(f"specify --func; found {len(defined)} functions in {obj_path}: {[s.name for s in defined]}")
        sym = defined[0]

    sec = elf.sections[sym.section]
    raw = sec.data[sym.value : sym.value + sym.size]
    va = 0x80000000
    tf = TargetFunction(sym.name, va, sym.size, raw, sec.name)
    ctx = TargetContext(
        arch="ppc_elf",
        funcs={sym.name: (va, sym.size)},
        by_addr={va: sym.name},
        external={sym.name: va},
        _regions=[(0, va, len(raw), True)],
        _image=raw,
    )
    return ctx, tf
