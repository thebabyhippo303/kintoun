"""Dedicated MIPS ELF32 (o32/EABI/n32, LE and BE) reader, relocator, and strict byte verifier.

Built directly from the System V ABI MIPS RISC Processor Supplement (3rd Ed.)
and GNU binutils `include/elf/mips.h` for PS2 Emotion Engine (`ee-gcc`),
PSP Allegrex (`psp-gcc`), and MIPS32 (`mips-gcc` little- and big-endian).
"""
from __future__ import annotations

from bisect import bisect_right
from dataclasses import dataclass
import hashlib
import re
import struct
from typing import Any

# ELF constants for MIPS
EM_MIPS = 8
EM_MIPS_RS3_LE = 10
SHT_PROGBITS = 1
SHT_SYMTAB = 2
SHT_STRTAB = 3
SHT_RELA = 4
SHT_NOBITS = 8
SHT_REL = 9
SHT_MIPS_REGINFO = 0x70000006
SHT_MIPS_OPTIONS = 0x7000000D

SHN_UNDEF = 0
SHN_LORESERVE = 0xFF00
SHN_MIPS_ACOMMON = 0xFF00
SHN_MIPS_TEXT = 0xFF01
SHN_MIPS_DATA = 0xFF02
SHN_MIPS_SCOMMON = 0xFF03
SHN_MIPS_SUNDEFINED = 0xFF04
SHN_ABS = 0xFFF1
SHN_COMMON = 0xFFF2

EF_MIPS_NOREORDER = 0x00000001
EF_MIPS_PIC = 0x00000002
EF_MIPS_CPIC = 0x00000004
EF_MIPS_ABI2 = 0x00000020
EF_MIPS_ABI_MASK = 0x0000F000
EF_MIPS_MACH_MASK = 0x00FF0000

MIPS_RELOCATIONS: dict[int, str] = {
    0: "NONE",
    1: "16",
    2: "32",
    3: "REL32",
    4: "26",
    5: "HI16",
    6: "LO16",
    7: "GPREL16",
    8: "LITERAL",
    9: "GOT16",
    10: "PC16",
    11: "CALL16",
    12: "GPREL32",
    22: "GOT_HI16",
    23: "GOT_LO16",
    30: "CALL_HI16",
    31: "CALL_LO16",
    37: "JALR",
    248: "PC32",
}

_HI16_KINDS = {"HI16", "GOT_HI16", "CALL_HI16"}
_LO16_KINDS = {"LO16", "GOT_LO16", "CALL_LO16"}
_HI_TO_LO = {
    "HI16": "LO16",
    "GOT_HI16": "GOT_LO16",
    "CALL_HI16": "CALL_LO16",
}
_EXTERNAL_SHNDX = {SHN_UNDEF, SHN_MIPS_SUNDEFINED, SHN_MIPS_SCOMMON, SHN_MIPS_ACOMMON, SHN_COMMON}


def _s16(val: int) -> int:
    val &= 0xFFFF
    return val - 0x10000 if val & 0x8000 else val


def _s28(val: int) -> int:
    val &= 0x0FFFFFFF
    return val - 0x10000000 if val & 0x08000000 else val


def _s32(val: int) -> int:
    val &= 0xFFFFFFFF
    return val - 0x100000000 if val & 0x80000000 else val


@dataclass(frozen=True)
class MipsSection:
    index: int
    name: str
    type: int
    flags: int
    data: bytes
    size: int
    link: int
    info: int
    align: int
    entsize: int


@dataclass(frozen=True)
class MipsSymbol:
    index: int
    name: str
    value: int
    size: int
    info: int
    other: int
    section: int

    @property
    def binding(self) -> int:
        return self.info >> 4

    @property
    def st_type(self) -> int:
        return self.info & 0xF

    @property
    def is_local(self) -> bool:
        return self.binding == 0


@dataclass(frozen=True)
class MipsRelocation:
    offset: int
    kind: str
    symbol: MipsSymbol
    addend: int
    is_rela: bool


class MipsObject:
    """Bounds-checked ELF32 reader for little- and big-endian MIPS relocatable objects."""

    def __init__(self, data: bytes) -> None:
        self.data = data
        if len(data) < 52 or data[:4] != b"\x7fELF":
            raise ValueError("expected an ELF32 MIPS relocatable object")
        ei_class, ei_data, ei_version = data[4], data[5], data[6]
        if ei_class != 1 or ei_data not in (1, 2) or ei_version != 1:
            raise ValueError("expected an ELF32 (LE or BE) version-1 MIPS object")
        self.endian = "little" if ei_data == 1 else "big"
        self._fmt_prefix = "<" if ei_data == 1 else ">"

        header = self._unpack("16sHHIIIIIHHHHHH", 0)
        _ident, typ, machine, version, _entry, _phoff, shoff, flags, ehsize, _phent, _phnum, shsize, count, strings = header
        if typ != 1 or machine not in (EM_MIPS, EM_MIPS_RS3_LE) or version != 1:
            raise ValueError("expected an ELF32 MIPS relocatable object (ET_REL, EM_MIPS)")
        if ehsize != 52 or shsize != 40 or not count or strings >= count:
            raise ValueError("unsupported MIPS ELF section header table")

        self.flags = flags
        self.abi = self._decode_abi(flags)
        self.mach = self._decode_mach(flags)

        raw_headers = [self._unpack("10I", shoff + i * shsize) for i in range(count)]
        shstr_hdr = raw_headers[strings]
        shstr = self._slice(shstr_hdr[4], shstr_hdr[5])

        self.sections: list[MipsSection] = []
        for i, h in enumerate(raw_headers):
            name_off, kind, sh_flags, _addr, offset, size, link, info, align, entsize = h
            body = b"" if kind == SHT_NOBITS else self._slice(offset, size)
            self.sections.append(
                MipsSection(
                    i,
                    self._string(shstr, name_off),
                    kind,
                    sh_flags,
                    body,
                    size,
                    link,
                    info,
                    align,
                    entsize,
                )
            )

        self.gp0 = self._read_gp0()
        self.tables: dict[int, list[MipsSymbol]] = {}
        sym_fmt = self._fmt_prefix + "IIIBBH"
        for sec in self.sections:
            if sec.type != SHT_SYMTAB:
                continue
            if sec.link >= count or sec.entsize != 16 or sec.size % 16:
                raise ValueError("invalid MIPS ELF symbol table")
            strtab = self.sections[sec.link].data
            syms: list[MipsSymbol] = []
            for i in range(sec.size // 16):
                st_name, st_value, st_size, st_info, st_other, st_shndx = struct.unpack_from(
                    sym_fmt, sec.data, i * 16
                )
                if 0 < st_shndx < SHN_LORESERVE and st_shndx >= count:
                    raise ValueError("invalid MIPS symbol section index")
                sym_name = self._string(strtab, st_name)
                if not sym_name and 0 < st_shndx < count:
                    sym_name = self.sections[st_shndx].name
                syms.append(MipsSymbol(i, sym_name, st_value, st_size, st_info, st_other, st_shndx))
            self.tables[sec.index] = syms

    @staticmethod
    def _decode_abi(flags: int) -> str:
        if flags & EF_MIPS_ABI2:
            return "n32"
        abi_bits = flags & EF_MIPS_ABI_MASK
        return {
            0x0000: "o32",
            0x1000: "o32",
            0x2000: "o64",
            0x3000: "eabi32",
            0x4000: "eabi64",
        }.get(abi_bits, "o32")

    @staticmethod
    def _decode_mach(flags: int) -> str:
        mach_bits = flags & EF_MIPS_MACH_MASK
        return {
            0x00920000: "r5900",
            0x00A20000: "allegrex",
        }.get(mach_bits, "mips32")

    def _read_gp0(self) -> int:
        """Extract `ri_gp_value` from `.reginfo` or `.MIPS.options` if present."""
        for sec in self.sections:
            if sec.type == SHT_MIPS_REGINFO and len(sec.data) >= 24:
                (gp_val,) = struct.unpack_from(self._fmt_prefix + "I", sec.data, 20)
                return gp_val
            if sec.type == SHT_MIPS_OPTIONS and len(sec.data) >= 32:
                pos = 0
                while pos + 8 <= len(sec.data):
                    kind, size = struct.unpack_from(self._fmt_prefix + "BB", sec.data, pos)[:2]
                    if size < 8 or pos + size > len(sec.data):
                        break
                    if kind == 1 and size >= 32:  # ODK_REGINFO: 8-byte header + 24-byte Elf32_RegInfo
                        (gp_val,) = struct.unpack_from(self._fmt_prefix + "I", sec.data, pos + 28)
                        return gp_val
                    pos += size
        return 0

    def _slice(self, offset: int, size: int) -> bytes:
        if offset < 0 or size < 0 or offset + size > len(self.data):
            raise ValueError("truncated MIPS ELF object")
        return self.data[offset : offset + size]

    def _unpack(self, fmt: str, offset: int) -> tuple[Any, ...]:
        full = self._fmt_prefix + fmt
        return struct.unpack(full, self._slice(offset, struct.calcsize(full)))

    @staticmethod
    def _string(data: bytes, offset: int) -> str:
        end = data.find(b"\x00", offset)
        if offset < 0 or offset >= len(data) or end < 0:
            raise ValueError("invalid MIPS ELF string offset")
        return data[offset:end].decode("utf-8", errors="strict")

    def defined_functions(self) -> list[MipsSymbol]:
        """Return defined function symbols with inferred size when `.size` was omitted."""
        raw_syms = [
            s
            for table in self.tables.values()
            for s in table
            if s.st_type == 2 and 0 < s.section < len(self.sections) and (self.sections[s.section].flags & 4)
        ]
        if not raw_syms:
            return []
        by_sec: dict[int, list[MipsSymbol]] = {}
        for s in raw_syms:
            by_sec.setdefault(s.section, []).append(s)
        out: list[MipsSymbol] = []
        for sec_idx, group in by_sec.items():
            sec_size = self.sections[sec_idx].size
            starts = sorted({g.value for g in group})
            next_start = {starts[i]: (starts[i + 1] if i + 1 < len(starts) else sec_size) for i in range(len(starts))}
            for s in group:
                sz = s.size if s.size > 0 else max(0, next_start[s.value] - s.value)
                if sz > 0 and s.value + sz <= sec_size:
                    out.append(MipsSymbol(s.index, s.name, s.value, sz, s.info, s.other, s.section))
        return out

    def function(self, name: str) -> MipsSymbol:
        found = [s for s in self.defined_functions() if s.name == name]
        if len(found) != 1:
            raise ValueError(f"expected one defined MIPS function: {name}")
        return found[0]

    def relocations(self, section_index: int) -> list[MipsRelocation]:
        out: list[MipsRelocation] = []
        for sec in self.sections:
            if sec.info != section_index or sec.type not in (SHT_REL, SHT_RELA):
                continue
            if sec.link not in self.tables:
                raise ValueError("invalid MIPS relocation symbol table link")
            symbols = self.tables[sec.link]
            is_rela = sec.type == SHT_RELA
            expected_ent = 12 if is_rela else 8
            if sec.entsize != expected_ent or sec.size % expected_ent:
                raise ValueError("invalid MIPS relocation entry size")
            fmt = self._fmt_prefix + ("IIi" if is_rela else "II")
            for pos in range(0, sec.size, expected_ent):
                unpacked = struct.unpack_from(fmt, sec.data, pos)
                r_offset, r_info = unpacked[0], unpacked[1]
                r_addend = unpacked[2] if is_rela else 0
                sym_idx = r_info >> 8
                r_type = r_info & 0xFF
                if sym_idx >= len(symbols):
                    raise ValueError("invalid MIPS relocation symbol index")
                kind = MIPS_RELOCATIONS.get(r_type, f"UNKNOWN_{r_type}")
                if kind == "NONE":
                    continue
                out.append(MipsRelocation(r_offset, kind, symbols[sym_idx], r_addend, is_rela))
        return out


def symbol_name_mips(objects: dict[int, tuple[str, int]], address: int) -> str:
    """Resolve an address to its nearest MIPS object symbol or fallback lbl_XXXXXXXX."""
    if address in objects:
        return objects[address][0]
    addresses = sorted(objects)
    i = bisect_right(addresses, address) - 1
    if i >= 0:
        start = addresses[i]
        row = objects[start]
        if start <= address < start + max(row[1], 1):
            return row[0] if address == start else f"{row[0]}+0x{address - start:X}"
    return f"lbl_{address:08X}"


def gp_references(
    words: list[int],
    objects: dict[int, tuple[str, int]],
    gp: int,
) -> list[dict[str, Any]]:
    """Decode `$gp`-relative (`$28`) loads, stores, and `addiu` in a MIPS instruction stream."""
    if not gp:
        return []
    out: list[dict[str, Any]] = []
    for i, word in enumerate(words):
        op = (word >> 26) & 0x3F
        rs = (word >> 21) & 0x1F
        rt = (word >> 16) & 0x1F
        if rs != 28 or (op == 9 and rt == 28):
            continue
        if op != 9 and not (32 <= op <= 63):
            continue
        imm = _s16(word & 0xFFFF)
        address = (gp + imm) & 0xFFFFFFFF
        out.append(
            {
                "offset": 4 * i,
                "register": "$gp",
                "address": f"0x{address:08X}",
                "symbol": symbol_name_mips(objects, address),
            }
        )
    return out


@dataclass(frozen=True)
class PreparedMipsReloc:
    offset: int
    kind: str
    key: str
    addend: int
    is_local: bool
    is_gp_disp: bool


def prepare_section_relocs(
    section_data: bytes,
    relocs: list[MipsRelocation],
    endian: str,
) -> list[tuple[MipsRelocation, int]]:
    """Compute effective signed addends for every relocation in a MIPS section.

    Handles `SHT_RELA` explicit addends and `SHT_REL` implicit in-place addends,
    including SysV MIPS ABI paired/multi-`HI16` and orphaned-`LO16` sequences.
    """
    result: list[tuple[MipsRelocation, int]] = []
    last_hi_imm: dict[tuple[int, str], int] = {}

    def read_u32(off: int) -> int:
        if off < 0 or off + 4 > len(section_data):
            raise ValueError("MIPS relocation outside section bounds")
        return int.from_bytes(section_data[off : off + 4], endian)

    def read_u16(off: int) -> int:
        if off < 0 or off + 2 > len(section_data):
            raise ValueError("MIPS 16-bit relocation outside section bounds")
        return int.from_bytes(section_data[off : off + 2], endian)

    for idx, rel in enumerate(relocs):
        if rel.is_rela:
            result.append((rel, rel.addend))
            continue

        kind = rel.kind
        if kind == "JALR":
            result.append((rel, 0))
        elif kind == "16":
            # Halfword or low-16 immediate depending on alignment
            if rel.offset % 4 == 0 and rel.offset + 4 <= len(section_data):
                imm = _s16(read_u32(rel.offset) & 0xFFFF)
            else:
                imm = _s16(read_u16(rel.offset))
            result.append((rel, imm))
        elif kind in ("32", "REL32", "GPREL32", "PC32"):
            result.append((rel, _s32(read_u32(rel.offset))))
        elif kind == "26":
            raw_targ = (read_u32(rel.offset) & 0x03FFFFFF) << 2
            addend = raw_targ if rel.symbol.is_local else _s28(raw_targ)
            result.append((rel, addend))
        elif kind in _HI16_KINDS:
            hi_imm = read_u32(rel.offset) & 0xFFFF
            want_lo = _HI_TO_LO[kind]
            last_hi_imm[(rel.symbol.index, want_lo)] = hi_imm
            paired_lo = None
            for nxt in relocs[idx + 1 :]:
                if nxt.symbol.index == rel.symbol.index and nxt.kind == want_lo:
                    paired_lo = nxt
                    break
            if paired_lo is None:
                raise ValueError(f"unpaired MIPS {kind} relocation for '{rel.symbol.name}' at +0x{rel.offset:X}")
            lo_imm = _s16(read_u32(paired_lo.offset) & 0xFFFF)
            ahl = _s32((hi_imm << 16) + lo_imm)
            result.append((rel, ahl))
        elif kind in _LO16_KINDS:
            lo_imm = _s16(read_u32(rel.offset) & 0xFFFF)
            hi_imm = last_hi_imm.get((rel.symbol.index, kind), 0)
            ahl = _s32((hi_imm << 16) + lo_imm)
            result.append((rel, ahl))
        elif kind in ("GPREL16", "LITERAL", "GOT16", "CALL16"):
            imm = _s16(read_u32(rel.offset) & 0xFFFF)
            result.append((rel, imm))
        elif kind == "PC16":
            imm = _s16(read_u32(rel.offset) & 0xFFFF) << 2
            result.append((rel, imm))
        else:
            raise ValueError(f"unsupported MIPS relocation: {kind}")

    return result


def relocate_mips(
    data: bytes,
    records: list[PreparedMipsReloc],
    symbols: dict[str, int],
    text_base: int,
    endian: str = "little",
    gp: int = 0,
    gp0: int = 0,
    use_gp0_for_local: bool = True,
) -> bytes:
    """Apply strict MIPS ELF32 relocations to function bytes."""
    buf = bytearray(data)
    for rec in records:
        offset, kind, sym_key, addend = rec.offset, rec.kind, rec.key, rec.addend
        if kind == "JALR":
            continue
        if rec.is_gp_disp:
            if not gp:
                raise ValueError("_gp_disp relocation requires target.gp")
            pc = (text_base + offset) & 0xFFFFFFFF
            if kind == "HI16":
                val = (gp - pc + addend) & 0xFFFFFFFF
                imm16 = ((val + 0x8000) >> 16) & 0xFFFF
            elif kind == "LO16":
                val = (gp - pc + 4 + addend) & 0xFFFFFFFF
                imm16 = val & 0xFFFF
            else:
                raise ValueError(f"unsupported _gp_disp relocation kind: {kind}")
            if offset < 0 or offset + 4 > len(buf):
                raise ValueError("relocation outside MIPS function")
            word = int.from_bytes(buf[offset : offset + 4], endian)
            word = (word & 0xFFFF0000) | imm16
            buf[offset : offset + 4] = word.to_bytes(4, endian)
            continue

        if sym_key not in symbols:
            raise ValueError(f"unresolved MIPS relocation: {kind} {sym_key}")
        sym_addr = symbols[sym_key]
        value = (sym_addr + addend) & 0xFFFFFFFF
        pc = (text_base + offset) & 0xFFFFFFFF

        if kind == "16":
            sval = sym_addr + addend
            if not -0x8000 <= sval <= 0xFFFF:
                raise ValueError("R_MIPS_16 overflow")
            if offset % 4 == 0 and offset + 4 <= len(buf):
                word = int.from_bytes(buf[offset : offset + 4], endian)
                word = (word & 0xFFFF0000) | (sval & 0xFFFF)
                buf[offset : offset + 4] = word.to_bytes(4, endian)
            elif 0 <= offset and offset + 2 <= len(buf):
                buf[offset : offset + 2] = (sval & 0xFFFF).to_bytes(2, endian)
            else:
                raise ValueError("relocation outside MIPS function")
            continue

        if offset < 0 or offset + 4 > len(buf):
            raise ValueError("relocation outside MIPS function")
        word = int.from_bytes(buf[offset : offset + 4], endian)

        if kind == "32":
            word = value
        elif kind in ("REL32", "PC32"):
            word = (value - pc) & 0xFFFFFFFF
        elif kind == "26":
            if value % 4:
                raise ValueError("unaligned R_MIPS_26 jump target")
            if (value & 0xF0000000) != ((pc + 4) & 0xF0000000):
                raise ValueError(
                    f"R_MIPS_26 target 0x{value:08X} outside 256MB region of PC+4 0x{(pc + 4) & 0xFFFFFFFF:08X}"
                )
            word = (word & 0xFC000000) | ((value >> 2) & 0x03FFFFFF)
        elif kind in _HI16_KINDS:
            imm16 = ((value + 0x8000) >> 16) & 0xFFFF
            word = (word & 0xFFFF0000) | imm16
        elif kind in _LO16_KINDS:
            word = (word & 0xFFFF0000) | (value & 0xFFFF)
        elif kind in ("GPREL16", "LITERAL", "GOT16", "CALL16"):
            if not gp:
                raise ValueError(f"R_MIPS_{kind} relocation requires target.gp")
            gp_adj = gp0 if (rec.is_local and use_gp0_for_local and kind in ("GPREL16", "LITERAL")) else 0
            disp = _s32((sym_addr + addend + gp_adj - gp) & 0xFFFFFFFF)
            if not -32768 <= disp <= 32767:
                raise ValueError(
                    f"R_MIPS_{kind} displacement {disp} out of signed 16-bit range from gp=0x{gp:08X}"
                )
            word = (word & 0xFFFF0000) | (disp & 0xFFFF)
        elif kind == "GPREL32":
            if not gp:
                raise ValueError("R_MIPS_GPREL32 relocation requires target.gp")
            gp_adj = gp0 if (rec.is_local and use_gp0_for_local) else 0
            word = (sym_addr + addend + gp_adj - gp) & 0xFFFFFFFF
        elif kind == "PC16":
            disp = _s32((value - pc) & 0xFFFFFFFF)
            if disp % 4 or not -0x20000 <= disp <= 0x1FFFC:
                raise ValueError("R_MIPS_PC16 branch relocation out of range")
            word = (word & 0xFFFF0000) | ((disp >> 2) & 0xFFFF)
        else:
            raise ValueError(f"unsupported MIPS relocation: {kind}")

        buf[offset : offset + 4] = word.to_bytes(4, endian)

    return bytes(buf)


def compare_mips_bytes(ours: bytes, target: bytes) -> dict[str, Any]:
    """Byte-exact comparison between relocated MIPS candidate bytes and target bytes."""
    offsets = [
        i
        for i in range(max(len(ours), len(target)))
        if i >= len(ours) or i >= len(target) or ours[i] != target[i]
    ]
    return {
        "verified": bool(target) and not offsets,
        "ours_bytes": len(ours),
        "target_bytes": len(target),
        "different_bytes": len(offsets),
        "first_offsets": offsets[:24],
        "instruction_mismatches": len({offset // 4 for offset in offsets}),
    }


def _locate_readonly_all(section: MipsSection, segments: list[tuple[int, bytes]], cap: int | None = None) -> list[int]:
    if section.flags & 5 or not section.flags & 2 or section.type != SHT_PROGBITS:
        raise ValueError(f"{section.name}: automatic placement requires readonly data")
    data = section.data
    if len(data) < 4 or not any(data):
        raise ValueError(f"{section.name}: insufficient distinctive constant data")
    matches: list[int] = []
    align = max(1, section.align)
    for address, body in segments:
        cursor = 0
        while True:
            found = body.find(data, cursor)
            if found < 0:
                break
            candidate = address + found
            if candidate % align == 0:
                matches.append(candidate)
            if cap is not None and len(matches) > cap:
                raise ValueError(f"{section.name}: too many constant placements; supply link_layout")
            cursor = found + 1
    return sorted(set(matches))


def _locate_readonly(section: MipsSection, segments: list[tuple[int, bytes]]) -> int:
    matches = _locate_readonly_all(section, segments)
    if len(matches) > 1:
        raise ValueError(f"{section.name}: ambiguous constant placement; supply link_layout")
    if len(matches) != 1:
        raise ValueError(f"{section.name}: no exact constant placement; supply link_layout")
    return matches[0]


def _external_address(
    symbol: str,
    external: dict[str, int],
    function_addresses: dict[int, str],
    object_addresses: dict[int, tuple[str, int]],
    allow_hex_fallback: bool = False,
) -> int:
    if symbol in external:
        return external[symbol]
    match = re.fullmatch(r"(fn|func|lbl|D)_([0-9A-Fa-f]{6,8})", symbol)
    if match:
        address = int(match[2], 16)
        known = function_addresses if match[1] in ("fn", "func") else object_addresses
        if address in known or allow_hex_fallback:
            return address
    raise ValueError(f"unresolved external: {symbol}")


def extract_mips_exec_gp(data: bytes) -> int:
    """Extract `$gp` value from a MIPS ELF32 `ET_EXEC` (`.reginfo`, `.MIPS.options`, `.rodata.sceModuleInfo`, `PHDR[0]`, or `_gp`)."""
    if len(data) < 52 or data[:4] != b"\x7fELF" or data[4] != 1 or data[5] not in (1, 2):
        return 0
    pfx = "<" if data[5] == 1 else ">"
    phoff, shoff, _flags, _ehsz, phentsz, phnum, shentsz, shnum, shstrndx = struct.unpack_from(
        pfx + "IIIHHHHHH", data, 28
    )
    if shoff and shnum and shentsz >= 40 and shoff + shnum * shentsz <= len(data):
        shdrs = [struct.unpack_from(pfx + "10I", data, shoff + i * shentsz) for i in range(shnum)]
        shstr = b""
        if shstrndx < shnum:
            so, ssz = shdrs[shstrndx][4], shdrs[shstrndx][5]
            if so + ssz <= len(data):
                shstr = data[so : so + ssz]

        for sh in shdrs:
            name_off, sh_type, _sh_flags, _sh_addr, sh_off, sh_sz = sh[:6]
            if sh_type == SHT_MIPS_REGINFO and sh_sz >= 24 and sh_off + 24 <= len(data):
                gp = struct.unpack_from(pfx + "I", data, sh_off + 20)[0]
                if gp:
                    return gp
            if sh_type == SHT_MIPS_OPTIONS and sh_sz >= 32 and sh_off + sh_sz <= len(data):
                pos = sh_off
                while pos + 8 <= sh_off + sh_sz:
                    kind, sz = struct.unpack_from(pfx + "BB", data, pos)[:2]
                    if sz < 8 or pos + sz > sh_off + sh_sz:
                        break
                    if kind == 1 and sz >= 32:
                        gp = struct.unpack_from(pfx + "I", data, pos + 28)[0]
                        if gp:
                            return gp
                    pos += sz
            if shstr and name_off < len(shstr):
                end = shstr.find(b"\0", name_off)
                sname = shstr[name_off:end].decode("latin-1") if end >= 0 else ""
                if sname == ".rodata.sceModuleInfo" and sh_sz >= 0x24 and sh_off + 0x24 <= len(data):
                    gp = struct.unpack_from(pfx + "I", data, sh_off + 0x20)[0]
                    if gp:
                        return gp

        # Fallback 1: `_gp` symbol in `.symtab`
        for sh in shdrs:
            if sh[1] == SHT_SYMTAB and sh[9] == 16 and sh[6] < shnum:
                sym_off, sym_sz, link = sh[4], sh[5], sh[6]
                str_off, str_sz = shdrs[link][4], shdrs[link][5]
                if sym_off + sym_sz <= len(data) and str_off + str_sz <= len(data):
                    strtab = data[str_off : str_off + str_sz]
                    for pos in range(sym_off, sym_off + sym_sz, 16):
                        st_name, st_val = struct.unpack_from(pfx + "II", data, pos)
                        if st_name < len(strtab):
                            end = strtab.find(b"\0", st_name)
                            if end >= 0 and strtab[st_name:end] in (b"_gp", b"_gp_disp") and st_val:
                                return st_val

    # Fallback 2: PSP `SceModuleInfo` pointed to by `PHDR[0].p_paddr & 0x7FFFFFFF` in stripped `ET_EXEC` EBOOTs
    if phoff and phnum and phentsz >= 32 and phoff + 32 <= len(data) and pfx == "<":
        p_type, _p_off, p_vaddr, p_paddr = struct.unpack_from("<4I", data, phoff)
        if p_type == 1 and 0x08800000 <= p_vaddr < 0x0C000000 and p_paddr:
            mod_off = p_paddr & 0x7FFFFFFF
            if 0 < mod_off and mod_off + 0x24 <= len(data):
                ver = struct.unpack_from("<H", data, mod_off + 2)[0]
                gp = struct.unpack_from("<I", data, mod_off + 0x20)[0]
                if ver in (0x0100, 0x0101) and 0x08800000 <= gp < 0x0C000000:
                    return gp
    return 0


def relocate_psp_prx_image(
    data: bytes, base_addr: int = 0x08804000
) -> tuple[bytes, list[tuple[int, int, int, bool]], int]:
    """Relocate a PSP `ET_SCE_PSP_PRX` (`e_type == 0xFFA0`) image to `base_addr` using `PT_PRXRELOC` (`0x700000A0`).

    Returns `(relocated_image_bytes, regions, relocated_gp)`.
    """
    if len(data) < 52 or data[:4] != b"\x7fELF" or data[4] != 1 or data[5] != 1:
        raise ValueError("expected a little-endian ELF32 PSP PRX")
    phoff, shoff, _flags, _ehsz, phentsz, phnum, shentsz, shnum, shstrndx = struct.unpack_from("<IIIHHHHHH", data, 28)
    if not phoff or not phnum or phentsz < 32:
        raise ValueError("PSP PRX missing program headers")

    buf = bytearray(data)
    load_phdrs: list[tuple[int, int, int, int, int]] = []  # (p_offset, p_vaddr, p_filesz, p_memsz, p_flags)
    reloc_blobs: list[tuple[int, int]] = []
    for i in range(phnum):
        p_type, p_off, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, _p_align = struct.unpack_from(
            "<8I", data, phoff + i * phentsz
        )
        if p_type == 1:  # PT_LOAD
            load_phdrs.append((p_off, p_vaddr, p_filesz, p_memsz, p_flags))
        elif p_type == 0x700000A0 and p_filesz > 0 and p_off + p_filesz <= len(data):  # PT_PRXRELOC (Type A)
            reloc_blobs.append((p_off, p_filesz))

    if not reloc_blobs and shoff and shnum and shoff + shnum * shentsz <= len(data):
        for i in range(shnum):
            sh = struct.unpack_from("<10I", data, shoff + i * shentsz)
            if sh[1] == 0x700000A0 and sh[5] > 0 and sh[4] + sh[5] <= len(data):
                reloc_blobs.append((sh[4], sh[5]))

    eff_base = base_addr or 0x08804000
    seg_bases = [(eff_base + pv) & 0xFFFFFFFF for _po, pv, _pf, _pm, _pfl in load_phdrs]

    for roff, rsz in reloc_blobs:
        entries = [struct.unpack_from("<II", data, roff + pos) for pos in range(0, rsz - (rsz % 8), 8)]
        pending_hi: list[tuple[int, int]] = []  # (file_pos, raw_word)
        for idx, (r_offset, r_info) in enumerate(entries):
            rtype = r_info & 0xFF
            o_ph = (r_info >> 8) & 0xFF
            a_ph = (r_info >> 16) & 0xFF
            if rtype == 0 or o_ph >= len(load_phdrs) or a_ph >= len(load_phdrs):
                continue
            p_off, _pv, p_filesz, _pm, _pfl = load_phdrs[o_ph]
            if r_offset + 4 > p_filesz:
                continue
            fpos = p_off + r_offset
            w = struct.unpack_from("<I", buf, fpos)[0]
            addr_base = seg_bases[a_ph]

            if rtype == 2:  # R_MIPS_32
                w = (w + addr_base) & 0xFFFFFFFF
                struct.pack_into("<I", buf, fpos, w)
            elif rtype == 4:  # R_MIPS_26
                targ = (((w & 0x03FFFFFF) << 2) + addr_base) & 0xFFFFFFFF
                w = (w & 0xFC000000) | ((targ >> 2) & 0x03FFFFFF)
                struct.pack_into("<I", buf, fpos, w)
            elif rtype == 5:  # R_MIPS_HI16 (may chain multiple HI16 before one LO16!)
                pending_hi.append((fpos, w))
            elif rtype == 6:  # R_MIPS_LO16
                lo_s = _s16(w & 0xFFFF)
                if pending_hi:
                    for hi_pos, hi_w in pending_hi:
                        ahl = (((hi_w & 0xFFFF) << 16) + lo_s + addr_base) & 0xFFFFFFFF
                        new_hi = ((ahl + 0x8000) >> 16) & 0xFFFF
                        struct.pack_into("<I", buf, hi_pos, (hi_w & 0xFFFF0000) | new_hi)
                    last_hi_w = pending_hi[-1][1]
                    ahl_lo = (((last_hi_w & 0xFFFF) << 16) + lo_s + addr_base) & 0xFFFFFFFF
                    pending_hi.clear()
                else:
                    ahl_lo = (lo_s + addr_base) & 0xFFFFFFFF
                struct.pack_into("<I", buf, fpos, (w & 0xFFFF0000) | (ahl_lo & 0xFFFF))

    regions: list[tuple[int, int, int, bool]] = []
    for idx, (p_off, _pv, p_filesz, _pm, p_flags) in enumerate(load_phdrs):
        if p_filesz > 0:
            regions.append((p_off, seg_bases[idx], p_filesz, bool(p_flags & 1)))

    # Relocate `SceModuleInfo.gp_value` (`p_paddr & 0x7FFFFFFF` in PHDR[0] or `.rodata.sceModuleInfo` section)
    gp = 0
    if shoff and shnum and shstrndx < shnum and shoff + shnum * shentsz <= len(buf):
        shdrs = [struct.unpack_from("<10I", buf, shoff + i * shentsz) for i in range(shnum)]
        shstr = bytes(buf[shdrs[shstrndx][4] : shdrs[shstrndx][4] + shdrs[shstrndx][5]])
        for sh in shdrs:
            end = shstr.find(b"\0", sh[0])
            sname = shstr[sh[0] : end].decode("latin-1") if end >= 0 else ""
            if sname == ".rodata.sceModuleInfo" and sh[5] >= 0x24 and sh[4] + 0x24 <= len(buf):
                raw_gp = struct.unpack_from("<I", buf, sh[4] + 0x20)[0]
                if raw_gp:
                    gp = (raw_gp + eff_base) & 0xFFFFFFFF if raw_gp < eff_base else raw_gp
                break
    if not gp and load_phdrs:
        p0 = struct.unpack_from("<8I", data, phoff)
        mod_off = p0[3] & 0x7FFFFFFF  # p_paddr in PSP PRX points to SceModuleInfo file offset!
        if 0 < mod_off and mod_off + 0x24 <= len(buf):
            raw_gp = struct.unpack_from("<I", buf, mod_off + 0x20)[0]
            if raw_gp:
                gp = (raw_gp + eff_base) & 0xFFFFFFFF if raw_gp < eff_base else raw_gp

    return bytes(buf), regions, gp


def _cache_key(section: MipsSection) -> tuple[str, str, int, int]:
    return (section.name, hashlib.sha256(section.data).hexdigest(), section.align, section.flags)


def link_mips_function(
    elf: MipsObject,
    function: MipsSymbol,
    va: int,
    target_bytes: bytes,
    external: dict[str, int],
    function_addresses: dict[int, str],
    object_addresses: dict[int, tuple[str, int]],
    data_segments: list[tuple[int, bytes]],
    read_mem: Any,
    gp: int = 0,
    explicit_layout: dict[str, int] | None = None,
    partial: bool = False,
    placement_cache: dict[Any, Any] | None = None,
    allow_hex_fallback: bool = False,
) -> tuple[bytes, dict[str, Any], dict[int, str]]:
    """Relocate a compiled MIPS function against the target symbol map and readonly segments."""
    start, length = function.value, function.size
    sec_obj = elf.sections[function.section]
    raw = sec_obj.data[start : start + length]
    explicit = explicit_layout or {}

    all_sec_relocs = elf.relocations(function.section)
    prepared_all = prepare_section_relocs(sec_obj.data, all_sec_relocs, elf.endian)
    fn_relocs = [(rel, eff_add) for rel, eff_add in prepared_all if start <= rel.offset < start + length]

    def resolve_section(section: MipsSection, idx: int) -> tuple[int, str]:
        if elf.relocations(idx):
            raise ValueError(f"{section.name}: relocated local data requires full linker support")
        if section.name in explicit:
            base = explicit[section.name]
            if base % max(1, section.align) or read_mem(base, section.size) != section.data:
                raise ValueError(f"{section.name}: explicit placement does not match target bytes/alignment")
            return base, "explicit layout, content verified"
        key = _cache_key(section)
        cached = placement_cache.get(key) if placement_cache is not None else None
        if isinstance(cached, str):
            raise ValueError(cached)
        if cached is None:
            try:
                base = _locate_readonly(section, data_segments)
            except ValueError as error:
                if placement_cache is not None:
                    placement_cache[key] = str(error)
                raise
            if placement_cache is not None:
                placement_cache[key] = base
        else:
            base = cached
        return base, "unique readonly content"

    def build(forced: dict[int, tuple[int, str]] | None = None):
        placements: dict[int, int] = {function.section: va - start}
        evidence: dict[str, Any] = {}
        records: list[PreparedMipsReloc] = []
        values: dict[str, int] = {}
        unknown: dict[int, str] = {}
        ambiguous: dict[int, MipsSection] = {}
        has_rela = False

        for rel, eff_addend in fn_relocs:
            has_rela = has_rela or rel.is_rela
            key = f"{rel.symbol.name}#{len(records)}"
            symbol = rel.symbol
            if symbol.name == "_gp_disp":
                records.append(PreparedMipsReloc(rel.offset - start, rel.kind, key, eff_addend, False, True))
                continue
            try:
                if symbol.section in _EXTERNAL_SHNDX:
                    address = _external_address(
                        symbol.name,
                        external,
                        function_addresses,
                        object_addresses,
                        allow_hex_fallback=allow_hex_fallback,
                    )
                elif symbol.section == SHN_ABS:
                    address = symbol.value
                elif 0 < symbol.section < len(elf.sections):
                    section = elf.sections[symbol.section]
                    if symbol.section not in placements:
                        if forced is not None and symbol.section in forced:
                            base, method = forced[symbol.section]
                        else:
                            try:
                                base, method = resolve_section(section, symbol.section)
                            except ValueError as error:
                                if "ambiguous constant placement" in str(error):
                                    ambiguous[symbol.section] = section
                                raise
                        placements[symbol.section] = base
                        evidence[section.name] = {
                            "address": f"0x{base:08X}",
                            "method": method,
                            "bytes": section.size,
                        }
                    address = placements[symbol.section] + symbol.value
                else:
                    raise ValueError(f"unsupported MIPS symbol section 0x{symbol.section:X} for '{symbol.name}'")
                records.append(
                    PreparedMipsReloc(rel.offset - start, rel.kind, key, eff_addend, symbol.is_local, False)
                )
                values[key] = address
            except ValueError as error:
                if not partial:
                    raise
                unknown[(rel.offset - start) // 4] = str(error)
        return placements, evidence, records, values, unknown, ambiguous, has_rela

    def finish(records: list[PreparedMipsReloc], values: dict[str, int], has_rela: bool):
        linked = raw
        unknown: dict[int, str] = {}
        for rec in records:
            try:
                linked = relocate_mips(
                    linked,
                    [rec],
                    values,
                    va,
                    endian=elf.endian,
                    gp=gp,
                    gp0=elf.gp0,
                    use_gp0_for_local=not has_rela,
                )
            except ValueError as error:
                if not partial:
                    raise
                unknown[rec.offset // 4] = str(error)
        return linked, unknown

    _placements, evidence, records, values, unknown, ambiguous, has_rela = build()
    if partial and len(ambiguous) == 1 and target_bytes:
        (idx, section), = ambiguous.items()
        try:
            bases = _locate_readonly_all(section, data_segments, cap=128)
        except ValueError:
            bases = []
        if len(bases) >= 2:
            key = _cache_key(section)
            best = None
            for base in bases:
                forced = {idx: (base, f"target-agreement {len(bases)} candidates")}
                try:
                    _, evidence2, records2, values2, unknown2, _, has_rela2 = build(forced)
                    if any("ambiguous constant placement" in str(m) for m in unknown2.values()):
                        continue
                    linked2, relocate_unknown = finish(records2, values2, has_rela2)
                except ValueError:
                    continue
                diffs = compare_mips_bytes(linked2, target_bytes)["different_bytes"]
                if best is None or diffs < best[0]:
                    unknown2.update(relocate_unknown)
                    best = (diffs, base, linked2, evidence2, unknown2)
                    if diffs == 0:
                        break
            if best is not None:
                _, base, linked, evidence, unknown = best
                if placement_cache is not None:
                    placement_cache[key] = base
                return linked, evidence, unknown

    linked, relocate_unknown = finish(records, values, has_rela)
    unknown.update(relocate_unknown)
    return linked, evidence, unknown
