"""Target binary, DOL, ELF/PRX executable, object, and symbol-map loaders for Kintoun."""
from __future__ import annotations

from dataclasses import dataclass, field
import json
from pathlib import Path
import re
import struct
from typing import Any

from kintoun.arch.elf import Object
from kintoun.config import KintounConfig

_SYM_RE = re.compile(r"^(\S+)\s*=\s*\.([^:]+):(0x[0-9A-Fa-f]+);(.*)$")
_SPLAT_SYM_RE = re.compile(r"^([A-Za-z_.$][\w.$]*)\s*=\s*(0x[0-9A-Fa-f]+)\s*;(.*)$")
_NM_SYM_RE = re.compile(r"^(?:0x)?([0-9A-Fa-f]{6,8})\s+(?:([0-9A-Fa-f]{1,8})\s+)?([TtDdBbRrSsGgCcWwVv])\s+(\S+)$")
_SIZE_RE = re.compile(r"size:(0x[0-9A-Fa-f]+|\d+)")


@dataclass(frozen=True)
class TargetFunction:
    name: str
    va: int
    size: int
    data: bytes
    section: str = ".text"
    is_thumb: bool = False
    intervals: tuple[tuple[int, int, str], ...] = ()
    reloc_offsets: frozenset[int] = frozenset()


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
    gp: int = 0
    sb: int = 0
    endian: str = ""
    thumb: bool = False
    thumb_addrs: set[int] = field(default_factory=set)
    allow_hex_fallback: bool = False

    def read(self, va: int, size: int) -> bytes:
        for file_off, addr, length, _is_code in self._regions:
            if addr <= va and va + size <= addr + length:
                rel = va - addr
                return self._image[file_off + rel : file_off + rel + size]
        raise ValueError(f"address range 0x{va:08X}+0x{size:X} not mapped in target binary")

    def resolve_function(self, spec: str) -> TargetFunction:
        if spec in self.funcs:
            va, size = self.funcs[spec]
            is_th = self.thumb or (va in self.thumb_addrs)
            return TargetFunction(spec, va, size, self.read(va, size), is_thumb=is_th)
        # Support `0xADDR:0xSIZE` or `0xADDR+0xSIZE` direct slice syntax on stripped binaries.
        if ":" in spec or "+" in spec:
            sep = ":" if ":" in spec else "+"
            left, right = spec.split(sep, 1)
            try:
                raw_va = int(left, 0)
                sz = int(right, 0)
                lookup_va = (raw_va & ~1) if self.arch in ("arm", "arm_elf") else raw_va
                is_th = self.thumb or bool(raw_va & 1) or (lookup_va in self.thumb_addrs)
                name = self.by_addr.get(lookup_va, f"fn_{lookup_va:08X}")
                return TargetFunction(name, lookup_va, sz, self.read(lookup_va, sz), is_thumb=is_th)
            except ValueError:
                pass
        try:
            va = int(spec, 0)
        except ValueError:
            raise ValueError(f"unknown target function: {spec}") from None
        lookup_va = (va & ~1) if self.arch in ("arm", "arm_elf") else va
        if lookup_va in self.by_addr:
            name = self.by_addr[lookup_va]
            _, size = self.funcs[name]
            is_th = self.thumb or bool(va & 1) or (lookup_va in self.thumb_addrs)
            return TargetFunction(name, lookup_va, size, self.read(lookup_va, size), is_thumb=is_th)
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


def parse_arch_symbols(path: Path) -> tuple[dict[str, tuple[int, int]], dict[int, str], dict[int, tuple[str, int]]]:
    """Parse dtk `symbols.txt`, splat `symbol_addrs.txt`, or GNU `nm` maps for MIPS/ARM projects."""
    funcs: dict[str, tuple[int, int]] = {}
    by_addr: dict[int, str] = {}
    objs: dict[int, tuple[str, int]] = {}
    for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw_line.strip()
        if not line or line.startswith(("#", "//", "/*")):
            continue
        m = _SYM_RE.match(line)
        if m:
            name, sec, addr_s, rest = m.groups()
            va = int(addr_s, 16)
            sm = _SIZE_RE.search(rest)
            size = int(sm.group(1), 0) if sm else 0
            if "type:function" in rest or "type:func" in rest or (sec in ("text", "init", "iwram", "ewram_code") and "type:object" not in rest and "type:data" not in rest):
                funcs[name] = (va, size)
                by_addr[va] = name
            else:
                objs[va] = (name, size)
            continue
        ms = _SPLAT_SYM_RE.match(line)
        if ms:
            name, addr_s, rest = ms.groups()
            va = int(addr_s, 16)
            sm = _SIZE_RE.search(rest)
            size = int(sm.group(1), 0) if sm else 0
            is_fn = (
                "type:func" in rest
                or "type:thumb" in rest
                or ("type:" not in rest and not name.startswith(("D_", "lbl_", "g_", "s_")))
            )
            if "type:thumb" in rest and not (va & 1):
                va |= 1
            if is_fn and "type:data" not in rest and "type:rodata" not in rest and "type:object" not in rest:
                funcs[name] = (va, size)
                by_addr[va] = name
            else:
                objs[va] = (name, size)
            continue
        mn = _NM_SYM_RE.match(line)
        if mn:
            addr_s, sz_s, sym_t, name = mn.groups()
            va = int(addr_s, 16)
            size = int(sz_s, 16) if sz_s else 0
            if sym_t in ("T", "t", "W", "w"):
                funcs[name] = (va, size)
                by_addr[va] = name
            else:
                objs[va] = (name, size)
    return funcs, by_addr, objs


def _extract_elf_exec_symbols(image: bytes) -> tuple[dict[str, tuple[int, int]], dict[int, tuple[str, int]]]:
    """Ingest `.symtab` function and object symbols from an unstripped `ET_EXEC` ELF32 image."""
    funcs: dict[str, tuple[int, int]] = {}
    objs: dict[int, tuple[str, int]] = {}
    if len(image) < 52 or image[:4] != b"\x7fELF" or image[4] != 1 or image[5] not in (1, 2):
        return funcs, objs
    pfx = "<" if image[5] == 1 else ">"
    _phoff, shoff, _flags, _ehsz, _phentsz, _phnum, shentsz, shnum, _shstr = struct.unpack_from(
        pfx + "IIIHHHHHH", image, 28
    )
    if not shoff or not shnum or shentsz < 40 or shoff + shnum * shentsz > len(image):
        return funcs, objs
    shdrs = [struct.unpack_from(pfx + "10I", image, shoff + i * shentsz) for i in range(shnum)]
    for sh in shdrs:
        if sh[1] != 2 or sh[9] != 16 or sh[6] >= shnum:
            continue
        sym_off, sym_sz, link = sh[4], sh[5], sh[6]
        str_off, str_sz = shdrs[link][4], shdrs[link][5]
        if sym_off + sym_sz > len(image) or str_off + str_sz > len(image):
            continue
        strtab = image[str_off : str_off + str_sz]
        for pos in range(sym_off, sym_off + sym_sz, 16):
            st_name, st_val, st_size, st_info, _st_other, st_shndx = struct.unpack_from(pfx + "IIIBBH", image, pos)
            if st_shndx == 0 or st_shndx >= 0xFF00 or st_val == 0 or st_name >= len(strtab):
                continue
            end = strtab.find(b"\0", st_name)
            if end <= st_name:
                continue
            name = strtab[st_name:end].decode("utf-8", errors="replace")
            if name.startswith(("$", ".")):
                continue
            stt = st_info & 0xF
            if stt in (2, 13):  # STT_FUNC / STT_ARM_TFUNC
                if stt == 13 and not (st_val & 1):
                    st_val |= 1
                funcs[name] = (st_val, st_size)
            elif stt == 1:  # STT_OBJECT
                objs[st_val] = (name, st_size)
    return funcs, objs


def load_link_layout(path: Path | None) -> dict[str, dict[str, int]]:
    if path is None or not path.is_file():
        return {}
    doc = json.loads(path.read_text(encoding="utf-8"))
    out: dict[str, dict[str, int]] = {}
    for fn_name, entry in doc.get("functions", {}).items():
        sections = entry.get("sections", {})
        out[fn_name] = {k: int(v, 0) if isinstance(v, str) else int(v) for k, v in sections.items()}
    return out


def _parse_binary_or_elf_exec(path: Path, base_addr: int, is_mips: bool = False) -> tuple[bytes, list[tuple[int, int, int, bool]], str, int]:
    """Parse an ELF32 executable (`PT_LOAD`), PSP PRX (`0xFFA0`), or flat ROM/binary image."""
    image = path.read_bytes()
    if len(image) >= 52 and image[:4] == b"\x7fELF" and image[4] == 1 and image[5] in (1, 2):
        endian = "little" if image[5] == 1 else "big"
        pfx = "<" if endian == "little" else ">"
        e_type = struct.unpack_from(pfx + "H", image, 16)[0]
        if is_mips and e_type == 0xFFA0:
            from kintoun.arch.mips_elf import relocate_psp_prx_image

            rel_img, regions, prx_gp = relocate_psp_prx_image(image, base_addr or 0x08804000)
            return rel_img, regions, endian, prx_gp

        phoff, _shoff, _flags, _ehsize, phentsize, phnum = struct.unpack_from(pfx + "IIIHHH", image, 28)
        det_gp = 0
        if is_mips:
            from kintoun.arch.mips_elf import extract_mips_exec_gp

            det_gp = extract_mips_exec_gp(image)
        if phoff and phnum and phentsize >= 32:
            regions: list[tuple[int, int, int, bool]] = []
            for i in range(phnum):
                p_type, p_offset, p_vaddr, _p_paddr, p_filesz, _p_memsz, p_flags, _p_align = struct.unpack_from(
                    pfx + "8I", image, phoff + i * phentsize
                )
                if p_type == 1 and p_filesz > 0:  # PT_LOAD
                    regions.append((p_offset, p_vaddr, p_filesz, bool(p_flags & 1)))
            if regions:
                return image, regions, endian, det_gp
    eff_base = base_addr
    if eff_base == 0 and path.suffix.lower() == ".gba":
        eff_base = 0x08000000
    return image, [(0, eff_base, len(image), True)], "", 0


def load_target_from_config(cfg: KintounConfig) -> TargetContext:
    """Build a TargetContext from kintoun.toml (DOL or MIPS/ARM binary/ELF/PRX + symbols.txt)."""
    if cfg.target.arch in ("mips", "mips_elf", "arm", "arm_elf"):
        is_mips = cfg.target.arch in ("mips", "mips_elf")
        is_arm = not is_mips
        bin_path = cfg.resolve_path(cfg.target.binary or cfg.target.dol)
        sym_path = cfg.resolve_path(cfg.target.symbols)
        layout_path = cfg.resolve_path(cfg.target.link_layout)
        image, regions, detected_endian, detected_gp = (
            _parse_binary_or_elf_exec(bin_path, cfg.target.base_addr, is_mips=is_mips)
            if bin_path and bin_path.is_file()
            else (b"", [], "", 0)
        )
        elf_funcs, elf_objs = _extract_elf_exec_symbols(image) if image else ({}, {})
        file_funcs, _file_by_addr, file_objs = (
            parse_arch_symbols(sym_path) if sym_path and sym_path.is_file() else ({}, {}, {})
        )
        raw_funcs = {**elf_funcs, **file_funcs}
        objs = {**elf_objs, **file_objs}

        funcs: dict[str, tuple[int, int]] = {}
        by_addr: dict[int, str] = {}
        thumb_addrs: set[int] = set()
        external: dict[str, int] = {}
        for name, (va, sz) in raw_funcs.items():
            if is_arm and (va & 1):
                even_va = va & ~1
                funcs[name] = (even_va, sz)
                by_addr[even_va] = name
                thumb_addrs.add(even_va)
                external[name] = va
            else:
                funcs[name] = (va, sz)
                by_addr[va] = name
                if is_arm and cfg.target.thumb:
                    thumb_addrs.add(va)
                external[name] = (va | 1) if (is_arm and cfg.target.thumb) else va

        # Infer missing function sizes (`sz == 0`) from next symbol address in the same region
        if any(sz == 0 for _v, sz in funcs.values()) and regions:
            sorted_addrs = sorted(by_addr)
            for idx, addr in enumerate(sorted_addrs):
                fname = by_addr[addr]
                fva, fsz = funcs[fname]
                if fsz > 0:
                    continue
                reg_end = next((r_a + r_l for _fo, r_a, r_l, _ic in regions if r_a <= fva < r_a + r_l), fva)
                next_addr = sorted_addrs[idx + 1] if idx + 1 < len(sorted_addrs) else reg_end
                inferred = max(0, min(next_addr, reg_end) - fva)
                if inferred > 0:
                    funcs[fname] = (fva, inferred)

        external.update({row[0]: va for va, row in objs.items()})
        data_segments = [(addr, image[off : off + sz]) for off, addr, sz, is_code in regions if not is_code]
        if image and regions:
            # On GBA ROMs and single-PT_LOAD PS2/PSP ELFs, `.rodata` sits inside the executable PT_LOAD segment!
            code_addrs = {a for a, _ in data_segments}
            for off, addr, sz, _ in regions:
                if addr not in code_addrs:
                    data_segments.append((addr, image[off : off + sz]))
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
            gp=cfg.target.gp or detected_gp,
            sb=cfg.target.sb,
            endian=cfg.target.endian or detected_endian,
            thumb=cfg.target.thumb or (bin_path is not None and bin_path.suffix.lower() == ".gba"),
            thumb_addrs=thumb_addrs,
            allow_hex_fallback=bool(image),
        )

    dol_path = cfg.resolve_path(cfg.target.dol)
    sym_path = cfg.resolve_path(cfg.target.symbols)
    layout_path = cfg.resolve_path(cfg.target.link_layout)

    image, regions = parse_dol(dol_path) if dol_path and dol_path.is_file() else (b"", [])
    funcs, by_addr, objs = parse_dtk_symbols(sym_path) if sym_path and sym_path.is_file() else ({}, {}, {})
    external = {name: va for name, (va, _sz) in funcs.items()}
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


def _load_mips_target_from_object(raw_obj: bytes, obj_path: Path, func_name: str | None) -> tuple[TargetContext, TargetFunction]:
    from kintoun.arch.mips_elf import MipsObject, _EXTERNAL_SHNDX, link_mips_function

    elf = MipsObject(raw_obj)
    defined = elf.defined_functions()
    if func_name:
        matches = [s for s in defined if s.name == func_name]
        if len(matches) != 1:
            raise ValueError(f"expected one function '{func_name}' in {obj_path}; found {[s.name for s in defined]}")
        sym = matches[0]
    else:
        if len(defined) != 1:
            raise ValueError(f"specify --func; found {len(defined)} functions in {obj_path}: {[s.name for s in defined]}")
        sym = defined[0]

    va = 0x00400000
    gp = elf.gp0 if elf.gp0 else 0x10008000
    funcs: dict[str, tuple[int, int]] = {}
    by_addr: dict[int, str] = {}
    objs: dict[int, tuple[str, int]] = {}
    external: dict[str, int] = {}
    explicit_sec: dict[str, int] = {}

    for fn in defined:
        fn_va = va + (fn.value - sym.value) if fn.section == sym.section else (0x00440000 + fn.value)
        funcs[fn.name] = (fn_va, fn.size)
        by_addr[fn_va] = fn.name
        external[fn.name] = fn_va

    mem_blobs: list[bytes] = []
    regions: list[tuple[int, int, int, bool]] = []
    data_segments: list[tuple[int, bytes]] = []
    cur_ro = 0x00500000
    cur_gp = (gp - 0x4000) & 0xFFFFFFFF
    file_cursor = 0

    for sec in elf.sections:
        if sec.index in (0, sym.section) or not (sec.flags & 2) or sec.size == 0:
            continue
        align = max(4, sec.align)
        is_small = sec.name.startswith((".sdata", ".sbss", ".lit4", ".lit8"))
        if is_small:
            if cur_gp % align:
                cur_gp += align - (cur_gp % align)
            base = cur_gp
            cur_gp += sec.size + 16
        else:
            if cur_ro % align:
                cur_ro += align - (cur_ro % align)
            base = cur_ro
            cur_ro += sec.size + 16
        body = sec.data if sec.data else (b"\x00" * sec.size)
        mem_blobs.append(body)
        regions.append((file_cursor, base, len(body), False))
        file_cursor += len(body)
        if not (sec.flags & 1):
            data_segments.append((base, body))
        explicit_sec[sec.name] = base
        for tab in elf.tables.values():
            for s in tab:
                if s.section == sec.index and s.name and not s.name.startswith("."):
                    s_addr = base + s.value
                    objs[s_addr] = (s.name, max(s.size, 4))
                    external[s.name] = s_addr

    gp_syms: set[str] = set()
    call_syms: set[str] = set()
    for rel in elf.relocations(sym.section):
        if rel.kind in ("GPREL16", "GPREL32", "LITERAL"):
            gp_syms.add(rel.symbol.name)
        elif rel.kind in ("26", "PC16", "CALL16", "CALL_HI16", "CALL_LO16"):
            call_syms.add(rel.symbol.name)

    ext_idx = 0
    for tab in elf.tables.values():
        for s in tab:
            if not s.name or s.name == "_gp_disp" or s.name in external:
                continue
            if s.section in _EXTERNAL_SHNDX:
                ext_idx += 1
                if s.name in call_syms or s.st_type == 2:
                    addr = 0x00480000 + ext_idx * 0x40
                    funcs[s.name] = (addr, 4)
                    by_addr[addr] = s.name
                    external[s.name] = addr
                elif s.name in gp_syms or s.section in (0xFF03, 0xFF04):
                    addr = (gp + 0x100 + ext_idx * 0x20) & 0xFFFFFFFF
                    objs[addr] = (s.name, max(s.size, 4))
                    external[s.name] = addr
                else:
                    addr = 0x00580000 + ext_idx * 0x100
                    objs[addr] = (s.name, max(s.size, 16))
                    external[s.name] = addr

    temp_image = b"".join(mem_blobs)

    def _tmp_read(rva: int, rsz: int) -> bytes:
        for foff, raddr, rlen, _ in regions:
            if raddr <= rva and rva + rsz <= raddr + rlen:
                rel_o = rva - raddr
                return temp_image[foff + rel_o : foff + rel_o + rsz]
        raise ValueError("unmapped")

    linked_target, _, _ = link_mips_function(
        elf=elf,
        function=sym,
        va=va,
        target_bytes=b"",
        external=external,
        function_addresses=by_addr,
        object_addresses=objs,
        data_segments=data_segments,
        read_mem=_tmp_read,
        gp=gp,
        explicit_layout=explicit_sec,
        partial=False,
    )
    code_off = len(temp_image)
    full_image = temp_image + linked_target
    regions.append((code_off, va, len(linked_target), True))
    reloc_offs = frozenset(
        rel.offset - sym.value
        for rel in elf.relocations(sym.section)
        if sym.value <= rel.offset < sym.value + sym.size
    )
    tf = TargetFunction(sym.name, va, sym.size, linked_target, elf.sections[sym.section].name, reloc_offsets=reloc_offs)
    ctx = TargetContext(
        arch="mips_elf",
        funcs=funcs,
        by_addr=by_addr,
        objs=objs,
        external=external,
        data_segments=data_segments,
        _regions=regions,
        _image=full_image,
        explicit_layouts={sym.name: explicit_sec} if explicit_sec else {},
        gp=gp,
        endian=elf.endian,
    )
    return ctx, tf


def _load_arm_target_from_object(raw_obj: bytes, obj_path: Path, func_name: str | None) -> tuple[TargetContext, TargetFunction]:
    from kintoun.arch.arm_elf import ArmObject, SHN_COMMON, SHN_UNDEF, is_mapping_symbol_name, link_arm_function

    elf = ArmObject(raw_obj)
    defined = elf.defined_functions()
    if func_name:
        matches = [s for s in defined if s.name == func_name]
        if len(matches) != 1:
            raise ValueError(f"expected one function '{func_name}' in {obj_path}; found {[s.name for s in defined]}")
        sym = matches[0]
    else:
        if len(defined) != 1:
            raise ValueError(f"specify --func; found {len(defined)} functions in {obj_path}: {[s.name for s in defined]}")
        sym = defined[0]

    va = 0x08000000
    sb = 0x02000000
    funcs: dict[str, tuple[int, int]] = {}
    by_addr: dict[int, str] = {}
    objs: dict[int, tuple[str, int]] = {}
    external: dict[str, int] = {}
    thumb_addrs: set[int] = set()
    explicit_sec: dict[str, int] = {}

    for fn in defined:
        fn_va = va + (fn.offset - sym.offset) if fn.section == sym.section else (0x08020000 + fn.offset)
        funcs[fn.name] = (fn_va, fn.size)
        by_addr[fn_va] = fn.name
        if fn.is_thumb:
            thumb_addrs.add(fn_va)
            external[fn.name] = fn_va | 1
        else:
            external[fn.name] = fn_va

    mem_blobs: list[bytes] = []
    regions: list[tuple[int, int, int, bool]] = []
    data_segments: list[tuple[int, bytes]] = []
    cur_ro = 0x08100000
    file_cursor = 0

    for sec in elf.sections:
        if sec.index in (0, sym.section) or not (sec.flags & 2) or sec.size == 0:
            continue
        align = max(4, sec.align)
        if cur_ro % align:
            cur_ro += align - (cur_ro % align)
        base = cur_ro
        cur_ro += sec.size + 16
        body = sec.data if sec.data else (b"\x00" * sec.size)
        mem_blobs.append(body)
        regions.append((file_cursor, base, len(body), False))
        file_cursor += len(body)
        if not (sec.flags & 1):
            data_segments.append((base, body))
        explicit_sec[sec.name] = base
        for tab in elf.tables.values():
            for s in tab:
                if s.section == sec.index and s.name and not s.name.startswith((".", "$")):
                    s_addr = base + s.value
                    objs[s_addr] = (s.name, max(s.size, 4))
                    external[s.name] = s_addr

    sec_data = elf.sections[sym.section].data
    thm_call_syms: set[str] = set()
    arm_call_syms: set[str] = set()
    pool_reloc_by_off = {rel.offset: rel.symbol.name for rel in elf.relocations(sym.section) if rel.kind == "ABS32"}
    if sym.is_thumb and pool_reloc_by_off:
        pos = sym.offset
        loaded_pool_sym: dict[int, str] = {}
        while pos + 2 <= sym.offset + sym.size:
            hw = int.from_bytes(sec_data[pos : pos + 2], elf.insn_endian)
            if (hw & 0xF800) in (0xE800, 0xF000, 0xF800) and pos + 4 <= sym.offset + sym.size:
                pos += 4
                continue
            if (hw >> 11) == 9:
                rd = (hw >> 8) & 7
                poff = ((pos + 4) & ~3) + (hw & 0xFF) * 4
                if poff in pool_reloc_by_off:
                    loaded_pool_sym[rd] = pool_reloc_by_off[poff]
            elif (hw & 0xFF00) == 0x4700:
                rm = (hw >> 3) & 0xF
                if rm in loaded_pool_sym:
                    thm_call_syms.add(loaded_pool_sym[rm])
            pos += 2
    for rel in elf.relocations(sym.section):
        if rel.kind in ("THM_CALL", "THM_JUMP24", "THM_JUMP19", "THM_JUMP11", "THM_JUMP8"):
            if rel.kind == "THM_CALL" and rel.offset + 4 <= len(sec_data):
                hw2 = int.from_bytes(sec_data[rel.offset + 2 : rel.offset + 4], elf.insn_endian)
                if (hw2 & 0x1000) == 0:
                    arm_call_syms.add(rel.symbol.name)
                else:
                    thm_call_syms.add(rel.symbol.name)
            else:
                thm_call_syms.add(rel.symbol.name)
        elif rel.kind in ("PC24", "PLT32", "CALL", "JUMP24"):
            if rel.kind == "CALL" and rel.offset + 4 <= len(sec_data):
                w = int.from_bytes(sec_data[rel.offset : rel.offset + 4], elf.insn_endian)
                if ((w >> 28) & 0xF) == 0xF:
                    thm_call_syms.add(rel.symbol.name)
                else:
                    arm_call_syms.add(rel.symbol.name)
            else:
                arm_call_syms.add(rel.symbol.name)

    ext_idx = 0
    for tab in elf.tables.values():
        for s in tab:
            if not s.name or is_mapping_symbol_name(s.name) or s.name in external:
                continue
            if s.section in (SHN_UNDEF, SHN_COMMON):
                ext_idx += 1
                if s.name in thm_call_syms or (s.st_type in (2, 13) and sym.is_thumb and s.name not in arm_call_syms):
                    addr = 0x08040000 + ext_idx * 0x40
                    funcs[s.name] = (addr, 4)
                    by_addr[addr] = s.name
                    thumb_addrs.add(addr)
                    external[s.name] = addr | 1
                elif s.name in arm_call_syms or s.st_type == 2:
                    addr = 0x08040000 + ext_idx * 0x40
                    funcs[s.name] = (addr, 4)
                    by_addr[addr] = s.name
                    external[s.name] = addr
                else:
                    addr = 0x02010000 + ext_idx * 0x100
                    objs[addr] = (s.name, max(s.size, 16))
                    external[s.name] = addr

    temp_image = b"".join(mem_blobs)

    def _tmp_read(rva: int, rsz: int) -> bytes:
        for foff, raddr, rlen, _ in regions:
            if raddr <= rva and rva + rsz <= raddr + rlen:
                rel_o = rva - raddr
                return temp_image[foff + rel_o : foff + rel_o + rsz]
        raise ValueError("unmapped")

    linked_target, _, _ = link_arm_function(
        elf=elf,
        function=sym,
        va=va,
        target_bytes=b"",
        external=external,
        function_addresses=by_addr,
        object_addresses=objs,
        data_segments=data_segments,
        read_mem=_tmp_read,
        thumb_addrs=thumb_addrs,
        sb=sb,
        explicit_layout=explicit_sec,
        partial=False,
    )
    code_off = len(temp_image)
    full_image = temp_image + linked_target
    regions.append((code_off, va, len(linked_target), True))

    intervals = tuple(
        elf.mapping_intervals(sym.section, sym.offset, sym.offset + sym.size, default_mode="t" if sym.is_thumb else "a")
    )
    reloc_offs = frozenset(
        rel.offset - sym.offset
        for rel in elf.relocations(sym.section)
        if sym.offset <= rel.offset < sym.offset + sym.size
    )
    tf = TargetFunction(
        sym.name,
        va,
        sym.size,
        linked_target,
        elf.sections[sym.section].name,
        is_thumb=sym.is_thumb,
        intervals=intervals,
        reloc_offsets=reloc_offs,
    )
    ctx = TargetContext(
        arch="arm_elf",
        funcs=funcs,
        by_addr=by_addr,
        objs=objs,
        external=external,
        data_segments=data_segments,
        _regions=regions,
        _image=full_image,
        explicit_layouts={sym.name: explicit_sec} if explicit_sec else {},
        sb=sb,
        endian=elf.endian,
        thumb=sym.is_thumb,
        thumb_addrs=thumb_addrs,
    )
    return ctx, tf


def load_target_from_object(obj_path: Path, func_name: str | None = None) -> tuple[TargetContext, TargetFunction]:
    """Load a standalone target ELF32 .o file (PowerPC, MIPS, or ARM/Thumb)."""
    raw_obj = obj_path.read_bytes()
    if len(raw_obj) >= 20 and raw_obj[:4] == b"\x7fELF" and raw_obj[4] == 1 and raw_obj[5] in (1, 2):
        e_machine = struct.unpack_from("<H" if raw_obj[5] == 1 else ">H", raw_obj, 18)[0]
        if e_machine in (8, 10):
            return _load_mips_target_from_object(raw_obj, obj_path, func_name)
        if e_machine == 40:
            return _load_arm_target_from_object(raw_obj, obj_path, func_name)
    elf = Object(raw_obj)
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

    # If the standalone PowerPC `.o` has relocations (e.g. ProDG/MWCC local `R_PPC_REL14` branches,
    # `.rodata` float constants, or external calls/globals), link it cleanly like MIPS/ARM!
    sec_relocs = [
        rel
        for rel in elf.relocations(sym.section)
        if sym.value <= rel.offset < sym.value + sym.size and rel.kind != "NONE"
    ]
    if not sec_relocs:
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

    from kintoun.arch.ppc_elf import link_function as link_ppc_fn

    funcs: dict[str, tuple[int, int]] = {}
    by_addr: dict[int, str] = {}
    objs: dict[int, tuple[str, int]] = {}
    external: dict[str, int] = {}
    explicit_sec: dict[str, int] = {}
    sda_r13 = 0x80200000
    sda_r2 = 0x80210000

    for fn in defined:
        fn_va = va + (fn.value - sym.value) if fn.section == sym.section else (0x80020000 + fn.value)
        funcs[fn.name] = (fn_va, fn.size)
        by_addr[fn_va] = fn.name
        external[fn.name] = fn_va

    mem_blobs: list[bytes] = []
    regions: list[tuple[int, int, int, bool]] = []
    data_segments: list[tuple[int, bytes]] = []
    cur_ro = 0x80100000
    cur_sda = sda_r13 - 0x4000
    cur_sda2 = sda_r2 - 0x4000
    file_cursor = 0

    for osec in elf.sections:
        if osec.index in (0, sym.section) or not (osec.flags & 2) or osec.size == 0:
            continue
        align = max(4, osec.align)
        if osec.name in (".sdata", ".sbss"):
            if cur_sda % align:
                cur_sda += align - (cur_sda % align)
            base = cur_sda
            cur_sda += osec.size + 16
        elif osec.name in (".sdata2", ".sbss2"):
            if cur_sda2 % align:
                cur_sda2 += align - (cur_sda2 % align)
            base = cur_sda2
            cur_sda2 += osec.size + 16
        else:
            if cur_ro % align:
                cur_ro += align - (cur_ro % align)
            base = cur_ro
            cur_ro += osec.size + 16
        body = osec.data if osec.data else (b"\x00" * osec.size)
        mem_blobs.append(body)
        regions.append((file_cursor, base, len(body), False))
        file_cursor += len(body)
        if not (osec.flags & 4):
            data_segments.append((base, body))
        explicit_sec[osec.name] = base
        for tab in elf.tables.values():
            for s in tab:
                if s.section == osec.index and s.name and not s.name.startswith("."):
                    s_addr = base + s.value
                    objs[s_addr] = (s.name, max(s.size, 4))
                    external[s.name] = s_addr

    call_syms = {rel.symbol.name for rel in sec_relocs if rel.kind == "REL24" and rel.symbol.name}
    sda_syms = {rel.symbol.name for rel in sec_relocs if rel.kind in ("SDAREL16", "EMB_SDA21") and rel.symbol.name}
    ext_idx = 0
    for tab in elf.tables.values():
        for s in tab:
            if not s.name or s.name.startswith(".") or s.name in external:
                continue
            if s.section in (0, 0xFFF2):
                ext_idx += 1
                if s.name in call_syms or (s.info & 15) == 2:
                    addr = 0x80040000 + ext_idx * 0x40
                    funcs[s.name] = (addr, 4)
                    by_addr[addr] = s.name
                    external[s.name] = addr
                elif s.name in sda_syms:
                    addr = sda_r13 + ext_idx * 0x10
                    objs[addr] = (s.name, max(s.size, 4))
                    external[s.name] = addr
                else:
                    addr = 0x80180000 + ext_idx * 0x40
                    objs[addr] = (s.name, max(s.size, 4))
                    external[s.name] = addr

    temp_image = b"".join(mem_blobs)

    def _tmp_read(addr: int, n: int) -> bytes | None:
        for foff, rva, rlen, _ in regions:
            if rva <= addr and addr + n <= rva + rlen:
                off = foff + (addr - rva)
                return temp_image[off : off + n]
        return None

    linked_target, _, _ = link_ppc_fn(
        elf=elf,
        function=sym,
        va=va,
        target_bytes=None,
        external=external,
        function_addresses=by_addr,
        object_addresses=objs,
        data_segments=data_segments,
        read_mem=_tmp_read,
        sda_r13=sda_r13,
        sda_r2=sda_r2,
        explicit_layout=explicit_sec,
        partial=False,
    )
    code_off = len(temp_image)
    full_image = temp_image + linked_target
    regions.append((code_off, va, len(linked_target), True))

    tf = TargetFunction(sym.name, va, len(linked_target), linked_target, sec.name)
    ctx = TargetContext(
        arch="ppc_elf",
        funcs=funcs,
        by_addr=by_addr,
        objs=objs,
        external=external,
        data_segments=data_segments,
        _regions=regions,
        _image=full_image,
        sda_r13=sda_r13,
        sda_r2=sda_r2,
        explicit_layouts={sym.name: explicit_sec} if explicit_sec else {},
    )
    return ctx, tf
