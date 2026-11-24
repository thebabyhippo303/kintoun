"""Dedicated ARM/Thumb ELF32 (ARMv4T, ARMv5TE, Thumb-2; LE and BE) reader, mapping-symbol parser, relocator, and strict verifier.

Built directly from the Arm 32-bit ELF ABI (`aaelf32`), Procedure Call Standard
(`aapcs32`), and ARM Architecture Reference Manuals for GBA (`agbcc`,
`arm-none-eabi-gcc`) and Nintendo DS (`mwccarm`, `arm-none-eabi-gcc`).
"""
from __future__ import annotations

from bisect import bisect_right
from dataclasses import dataclass
import hashlib
import re
import struct
from typing import Any

EM_ARM = 40
SHT_PROGBITS = 1
SHT_SYMTAB = 2
SHT_STRTAB = 3
SHT_RELA = 4
SHT_NOBITS = 8
SHT_REL = 9
SHT_ARM_ATTRIBUTES = 0x70000003

SHN_UNDEF = 0
SHN_LORESERVE = 0xFF00
SHN_ABS = 0xFFF1
SHN_COMMON = 0xFFF2

STT_NOTYPE = 0
STT_OBJECT = 1
STT_FUNC = 2
STT_SECTION = 3
STT_ARM_TFUNC = 13

EF_ARM_BE8 = 0x00800000
EF_ARM_EABIMASK = 0xFF000000

ARM_RELOCATIONS: dict[int, str] = {
    0: "NONE",
    1: "PC24",
    2: "ABS32",
    3: "REL32",
    4: "LDR_PC_G0",
    5: "ABS16",
    6: "ABS12",
    7: "THM_ABS5",
    8: "ABS8",
    9: "SBREL32",
    10: "THM_CALL",
    11: "THM_PC8",
    27: "PLT32",
    28: "CALL",
    29: "JUMP24",
    30: "THM_JUMP24",
    38: "TARGET1",
    40: "V4BX",
    42: "PREL31",
    43: "MOVW_ABS_NC",
    44: "MOVT_ABS",
    45: "MOVW_PREL_NC",
    46: "MOVT_PREL",
    47: "THM_MOVW_ABS_NC",
    48: "THM_MOVT_ABS",
    49: "THM_MOVW_PREL_NC",
    50: "THM_MOVT_PREL",
    51: "THM_JUMP19",
    52: "THM_JUMP6",
    53: "THM_ALU_PREL_11_0",
    54: "THM_PC12",
    55: "ABS32_NOI",
    56: "REL32_NOI",
    57: "ALU_PC_G0_NC",
    58: "ALU_PC_G0",
    102: "THM_JUMP11",
    103: "THM_JUMP8",
}

_MAP_SYM_RE = re.compile(r"^\$([atd])(?:\..*|$)")


def _sext(val: int, bits: int) -> int:
    mask = (1 << bits) - 1
    val &= mask
    return val - (1 << bits) if val & (1 << (bits - 1)) else val


def _s32(val: int) -> int:
    return _sext(val, 32)


def is_mapping_symbol_name(name: str) -> str | None:
    """Return `'a'`, `'t'`, or `'d'` if `name` is an AAELF32 mapping symbol (`$a`, `$t.x`, `$d`, ...)."""
    m = _MAP_SYM_RE.match(name)
    return m.group(1) if m else None


@dataclass(frozen=True)
class ArmSection:
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
class ArmSymbol:
    index: int
    name: str
    value: int
    size: int
    info: int
    other: int
    section: int
    is_thumb: bool = False

    @property
    def binding(self) -> int:
        return self.info >> 4

    @property
    def st_type(self) -> int:
        return self.info & 0xF

    @property
    def is_local(self) -> bool:
        return self.binding == 0

    @property
    def offset(self) -> int:
        return self.value & ~1 if (self.st_type in (STT_FUNC, STT_ARM_TFUNC) or self.is_thumb) else self.value


@dataclass(frozen=True)
class ArmRelocation:
    offset: int
    kind: str
    symbol: ArmSymbol
    addend: int
    is_rela: bool


class ArmObject:
    """Bounds-checked ELF32 reader for ARM/Thumb relocatable objects (`agbcc`, GNU EABI, `mwccarm`)."""

    def __init__(self, data: bytes) -> None:
        self.data = data
        if len(data) < 52 or data[:4] != b"\x7fELF":
            raise ValueError("expected an ELF32 ARM relocatable object")
        ei_class, ei_data, ei_version = data[4], data[5], data[6]
        if ei_class != 1 or ei_data not in (1, 2) or ei_version != 1:
            raise ValueError("expected an ELF32 (LE or BE) version-1 ARM object")
        self.endian = "little" if ei_data == 1 else "big"
        self._fmt_prefix = "<" if ei_data == 1 else ">"

        header = self._unpack("16sHHIIIIIHHHHHH", 0)
        _ident, typ, machine, version, _entry, _phoff, shoff, flags, ehsize, _phent, _phnum, shsize, count, strings = header
        if typ != 1 or machine != EM_ARM or version != 1:
            raise ValueError("expected an ELF32 ARM relocatable object (ET_REL, EM_ARM)")
        if ehsize != 52 or shsize != 40 or not count or strings >= count:
            raise ValueError("unsupported ARM ELF section header table")

        self.flags = flags
        self.eabiv = (flags & EF_ARM_EABIMASK) >> 24
        self.insn_endian = "little" if (ei_data == 1 or (flags & EF_ARM_BE8)) else "big"

        raw_headers = [self._unpack("10I", shoff + i * shsize) for i in range(count)]
        shstr_hdr = raw_headers[strings]
        shstr = self._slice(shstr_hdr[4], shstr_hdr[5])

        self.sections: list[ArmSection] = []
        for i, h in enumerate(raw_headers):
            name_off, kind, sh_flags, _addr, offset, size, link, info, align, entsize = h
            body = b"" if kind == SHT_NOBITS else self._slice(offset, size)
            self.sections.append(
                ArmSection(
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

        # First pass: parse raw symbols and mapping symbols per section
        raw_tables: dict[int, list[ArmSymbol]] = {}
        self._map_by_sec: dict[int, list[tuple[int, str]]] = {}
        sym_fmt = self._fmt_prefix + "IIIBBH"
        for sec in self.sections:
            if sec.type != SHT_SYMTAB:
                continue
            if sec.link >= count or sec.entsize != 16 or sec.size % 16:
                raise ValueError("invalid ARM ELF symbol table")
            strtab = self.sections[sec.link].data
            syms: list[ArmSymbol] = []
            for i in range(sec.size // 16):
                st_name, st_value, st_size, st_info, st_other, st_shndx = struct.unpack_from(
                    sym_fmt, sec.data, i * 16
                )
                if 0 < st_shndx < SHN_LORESERVE and st_shndx >= count:
                    raise ValueError("invalid ARM symbol section index")
                sym_name = self._string(strtab, st_name)
                if not sym_name and 0 < st_shndx < count:
                    sym_name = self.sections[st_shndx].name
                mtag = is_mapping_symbol_name(sym_name)
                if mtag and (st_info >> 4) == 0 and 0 < st_shndx < count:
                    self._map_by_sec.setdefault(st_shndx, []).append((st_value & ~1, mtag))
                thumb_bit = bool(
                    mtag is None
                    and ((st_info & 0xF) == STT_ARM_TFUNC or ((st_info & 0xF) == STT_FUNC and (st_value & 1)))
                )
                syms.append(ArmSymbol(i, sym_name, st_value, st_size, st_info, st_other, st_shndx, thumb_bit))
            raw_tables[sec.index] = syms

        # Normalize mapping lists per section (keep last tag at identical offset, sorted ascending)
        for sec_idx, pairs in list(self._map_by_sec.items()):
            dedup: dict[int, str] = {}
            for off, tag in pairs:
                dedup[off] = tag
            self._map_by_sec[sec_idx] = sorted(dedup.items())

        # Second pass: enrich defined function symbols with `$t` mapping-symbol Thumb detection (`mwccarm -thumb`)
        self.tables: dict[int, list[ArmSymbol]] = {}
        for tab_idx, syms in raw_tables.items():
            enriched: list[ArmSymbol] = []
            for s in syms:
                if (
                    not s.is_thumb
                    and is_mapping_symbol_name(s.name) is None
                    and s.st_type in (STT_FUNC, STT_ARM_TFUNC)
                    and 0 < s.section < len(self.sections)
                ):
                    if self.mode_at(s.section, s.value & ~1) == "t":
                        s = ArmSymbol(s.index, s.name, s.value, s.size, s.info, s.other, s.section, True)
                enriched.append(s)
            self.tables[tab_idx] = enriched

    def _slice(self, offset: int, size: int) -> bytes:
        if offset < 0 or size < 0 or offset + size > len(self.data):
            raise ValueError("truncated ARM ELF object")
        return self.data[offset : offset + size]

    def _unpack(self, fmt: str, offset: int) -> tuple[Any, ...]:
        full = self._fmt_prefix + fmt
        return struct.unpack(full, self._slice(offset, struct.calcsize(full)))

    @staticmethod
    def _string(data: bytes, offset: int) -> str:
        end = data.find(b"\x00", offset)
        if offset < 0 or offset >= len(data) or end < 0:
            raise ValueError("invalid ARM ELF string offset")
        return data[offset:end].decode("utf-8", errors="strict")

    def mode_at(self, section_index: int, byte_offset: int, default: str = "a") -> str:
        """Return `'a'`, `'t'`, or `'d'` at `byte_offset` in `section_index` from mapping symbols."""
        pts = self._map_by_sec.get(section_index)
        if not pts:
            # mwccarm sets 0x00100000 in e_flags for Thumb objects even if mapping symbols are absent
            return "t" if (self.flags & 0x00100000) else default
        offs = [p[0] for p in pts]
        idx = bisect_right(offs, byte_offset) - 1
        if idx >= 0:
            return pts[idx][1]
        return pts[0][1]

    def mapping_intervals(
        self,
        section_index: int,
        start: int = 0,
        end: int | None = None,
        default_mode: str = "a",
    ) -> list[tuple[int, int, str]]:
        """Return relative `(rel_start, rel_end, mode)` intervals covering `[start, end)`."""
        sec_size = self.sections[section_index].size
        stop = sec_size if end is None else min(end, sec_size)
        if stop <= start:
            return []
        pts = self._map_by_sec.get(section_index)
        if not pts:
            mode = "t" if (self.flags & 0x00100000) else default_mode
            return [(0, stop - start, mode)]

        cur_mode = self.mode_at(section_index, start, default=default_mode)
        cuts: list[tuple[int, str]] = [(start, cur_mode)]
        for off, tag in pts:
            if start < off < stop:
                if cuts[-1][1] != tag:
                    cuts.append((off, tag))
        intervals: list[tuple[int, int, str]] = []
        for i, (seg_s, mode) in enumerate(cuts):
            seg_e = cuts[i + 1][0] if i + 1 < len(cuts) else stop
            if seg_e > seg_s:
                intervals.append((seg_s - start, seg_e - start, mode))
        return intervals

    def defined_functions(self) -> list[ArmSymbol]:
        """Return non-mapping defined function symbols, inferring size when `.size` was 0."""
        candidates = [
            s
            for table in self.tables.values()
            for s in table
            if is_mapping_symbol_name(s.name) is None
            and s.name
            and 0 < s.section < len(self.sections)
            and (self.sections[s.section].flags & 4)
            and (s.st_type in (STT_FUNC, STT_ARM_TFUNC) or (s.st_type == STT_NOTYPE and s.binding in (1, 2)))
        ]
        if not candidates:
            return []
        by_sec: dict[int, list[ArmSymbol]] = {}
        for s in candidates:
            by_sec.setdefault(s.section, []).append(s)
        out: list[ArmSymbol] = []
        for sec_idx, group in by_sec.items():
            sec_size = self.sections[sec_idx].size
            starts = sorted({g.value & ~1 for g in group})
            next_start = {starts[i]: (starts[i + 1] if i + 1 < len(starts) else sec_size) for i in range(len(starts))}
            for s in group:
                off = s.value & ~1
                sz = s.size if s.size > 0 else max(0, next_start[off] - off)
                is_th = bool(s.is_thumb or (s.value & 1) or self.mode_at(sec_idx, off) == "t")
                if sz > 0 and off + sz <= sec_size:
                    # Normalize value to byte offset while preserving Thumb state in `is_thumb`
                    out.append(ArmSymbol(s.index, s.name, off, sz, s.info, s.other, s.section, is_th))
        return out

    def function(self, name: str) -> ArmSymbol:
        found = [s for s in self.defined_functions() if s.name == name]
        if len(found) != 1:
            raise ValueError(f"expected one defined ARM function: {name}")
        return found[0]

    def relocations(self, section_index: int) -> list[ArmRelocation]:
        out: list[ArmRelocation] = []
        for sec in self.sections:
            if sec.info != section_index or sec.type not in (SHT_REL, SHT_RELA):
                continue
            if sec.link not in self.tables:
                raise ValueError("invalid ARM relocation symbol table link")
            symbols = self.tables[sec.link]
            is_rela = sec.type == SHT_RELA
            expected_ent = 12 if is_rela else 8
            if sec.entsize != expected_ent or sec.size % expected_ent:
                raise ValueError("invalid ARM relocation entry size")
            fmt = self._fmt_prefix + ("IIi" if is_rela else "II")
            for pos in range(0, sec.size, expected_ent):
                unpacked = struct.unpack_from(fmt, sec.data, pos)
                r_offset, r_info = unpacked[0], unpacked[1]
                r_addend = unpacked[2] if is_rela else 0
                sym_idx = r_info >> 8
                r_type = r_info & 0xFF
                if sym_idx >= len(symbols):
                    raise ValueError("invalid ARM relocation symbol index")
                kind = ARM_RELOCATIONS.get(r_type, f"UNKNOWN_{r_type}")
                if kind == "NONE":
                    continue
                out.append(ArmRelocation(r_offset, kind, symbols[sym_idx], r_addend, is_rela))
        return out


def symbol_name_arm(objects: dict[int, tuple[str, int]], address: int) -> str:
    """Resolve an address to its nearest ARM object symbol or fallback lbl_XXXXXXXX."""
    clean = address & 0xFFFFFFFF
    if clean in objects:
        return objects[clean][0]
    addresses = sorted(objects)
    i = bisect_right(addresses, clean) - 1
    if i >= 0:
        start = addresses[i]
        row = objects[start]
        if start <= clean < start + max(row[1], 1):
            return row[0] if clean == start else f"{row[0]}+0x{clean - start:X}"
    return f"lbl_{clean:08X}"


@dataclass(frozen=True)
class PreparedArmReloc:
    offset: int
    kind: str
    key: str
    addend: int


def _decode_thm_call_addend(hw1: int, hw2: int) -> int:
    s = (hw1 >> 10) & 1
    imm10 = hw1 & 0x3FF
    j1 = (hw2 >> 13) & 1
    j2 = (hw2 >> 11) & 1
    imm11 = hw2 & 0x7FF
    i1 = (~(j1 ^ s)) & 1
    i2 = (~(j2 ^ s)) & 1
    raw25 = (s << 24) | (i1 << 23) | (i2 << 22) | (imm10 << 12) | (imm11 << 1)
    return _sext(raw25, 25)


def _decode_thm_jump19_addend(hw1: int, hw2: int) -> int:
    s = (hw1 >> 10) & 1
    imm6 = hw1 & 0x3F
    j1 = (hw2 >> 13) & 1
    j2 = (hw2 >> 11) & 1
    imm11 = hw2 & 0x7FF
    raw21 = (s << 20) | (j2 << 19) | (j1 << 18) | (imm6 << 12) | (imm11 << 1)
    return _sext(raw21, 21)


def _decode_thm_mov_imm16(hw1: int, hw2: int) -> int:
    i = (hw1 >> 10) & 1
    imm4 = hw1 & 0xF
    imm3 = (hw2 >> 12) & 0x7
    imm8 = hw2 & 0xFF
    return _sext((imm4 << 12) | (i << 11) | (imm3 << 8) | imm8, 16)


def prepare_arm_relocs(
    section_data: bytes,
    relocs: list[ArmRelocation],
    data_endian: str = "little",
    insn_endian: str = "little",
) -> list[tuple[ArmRelocation, int]]:
    """Extract signed initial addends `A` for ARM/Thumb `SHT_REL` and `SHT_RELA` relocations."""
    out: list[tuple[ArmRelocation, int]] = []

    def ru32_data(off: int) -> int:
        if off < 0 or off + 4 > len(section_data):
            raise ValueError("ARM data relocation outside section")
        return int.from_bytes(section_data[off : off + 4], data_endian)

    def ru32_insn(off: int) -> int:
        if off < 0 or off + 4 > len(section_data):
            raise ValueError("ARM instruction relocation outside section")
        return int.from_bytes(section_data[off : off + 4], insn_endian)

    def ru16_insn(off: int) -> int:
        if off < 0 or off + 2 > len(section_data):
            raise ValueError("Thumb instruction relocation outside section")
        return int.from_bytes(section_data[off : off + 2], insn_endian)

    for rel in relocs:
        if rel.is_rela:
            out.append((rel, rel.addend))
            continue

        k = rel.kind
        off = rel.offset
        if k == "V4BX":
            out.append((rel, 0))
        elif k in ("ABS32", "REL32", "TARGET1", "SBREL32", "ABS32_NOI", "REL32_NOI"):
            out.append((rel, _s32(ru32_data(off))))
        elif k == "PREL31":
            out.append((rel, _sext(ru32_data(off) & 0x7FFFFFFF, 31)))
        elif k == "ABS16":
            if off < 0 or off + 2 > len(section_data):
                raise ValueError("ABS16 outside section")
            out.append((rel, _sext(int.from_bytes(section_data[off : off + 2], data_endian), 16)))
        elif k == "ABS8":
            if off < 0 or off + 1 > len(section_data):
                raise ValueError("ABS8 outside section")
            out.append((rel, _sext(section_data[off], 8)))
        elif k in ("PC24", "PLT32", "CALL", "JUMP24"):
            w = ru32_insn(off)
            out.append((rel, _sext((w & 0x00FFFFFF) << 2, 26)))
        elif k in ("LDR_PC_G0", "ABS12"):
            w = ru32_insn(off)
            u = (w >> 23) & 1
            imm12 = w & 0xFFF
            out.append((rel, imm12 if (u or k == "ABS12") else -imm12))
        elif k in ("ALU_PC_G0_NC", "ALU_PC_G0"):
            w = ru32_insn(off)
            rot = ((w >> 8) & 0xF) * 2
            imm8 = w & 0xFF
            val = ((imm8 >> rot) | ((imm8 << (32 - rot)) & 0xFFFFFFFF)) if rot else imm8
            sub_op = ((w >> 21) & 0xF) == 2  # SUB vs ADD
            out.append((rel, -val if sub_op else val))
        elif k in ("MOVW_ABS_NC", "MOVT_ABS", "MOVW_PREL_NC", "MOVT_PREL"):
            w = ru32_insn(off)
            imm16 = ((w >> 4) & 0xF000) | (w & 0xFFF)
            out.append((rel, _sext(imm16, 16)))
        elif k in ("THM_CALL", "THM_JUMP24"):
            hw1, hw2 = ru16_insn(off), ru16_insn(off + 2)
            out.append((rel, _decode_thm_call_addend(hw1, hw2)))
        elif k == "THM_JUMP19":
            hw1, hw2 = ru16_insn(off), ru16_insn(off + 2)
            out.append((rel, _decode_thm_jump19_addend(hw1, hw2)))
        elif k in ("THM_MOVW_ABS_NC", "THM_MOVT_ABS", "THM_MOVW_PREL_NC", "THM_MOVT_PREL"):
            hw1, hw2 = ru16_insn(off), ru16_insn(off + 2)
            out.append((rel, _decode_thm_mov_imm16(hw1, hw2)))
        elif k in ("THM_PC12", "THM_ALU_PREL_11_0"):
            hw1, hw2 = ru16_insn(off), ru16_insn(off + 2)
            if k == "THM_PC12":
                u = (hw1 >> 7) & 1
                imm12 = hw2 & 0xFFF
                out.append((rel, imm12 if u else -imm12))
            else:
                i = (hw1 >> 10) & 1
                imm3 = (hw2 >> 12) & 0x7
                imm8 = hw2 & 0xFF
                mag = (i << 11) | (imm3 << 8) | imm8
                is_sub = (hw1 & 0x00A0) == 0x00A0
                out.append((rel, -mag if is_sub else mag))
        elif k == "THM_JUMP11":
            hw = ru16_insn(off)
            out.append((rel, _sext((hw & 0x7FF) << 1, 12)))
        elif k == "THM_JUMP8":
            hw = ru16_insn(off)
            out.append((rel, _sext((hw & 0xFF) << 1, 9)))
        elif k == "THM_JUMP6":
            hw = ru16_insn(off)
            mag = ((((hw >> 9) & 1) << 6) | (((hw >> 3) & 0x1F) << 1)) - 4
            out.append((rel, mag))
        elif k == "THM_PC8":
            hw = ru16_insn(off)
            # Standard GNU assembler encodes 0xFF (-4 bytes in signed 10-bit word offset) or 0
            raw_off = (hw & 0xFF) << 2
            # In AAELF32 REL, imm8 is unsigned words added to Align(PC,4), with -4 encoded as 0x3FC -> -4
            add = -4 if (hw & 0xFF) == 0xFF else raw_off
            out.append((rel, add))
        elif k == "THM_ABS5":
            hw = ru16_insn(off)
            out.append((rel, ((hw >> 6) & 0x1F) << 2))
        else:
            raise ValueError(f"unsupported ARM relocation: {k}")
    return out


def relocate_arm(
    data: bytes,
    records: list[PreparedArmReloc],
    symbols: dict[str, tuple[int, int]],  # key -> (S_addr_even_or_exact, T_bit)
    text_base: int,
    data_endian: str = "little",
    insn_endian: str = "little",
    sb: int = 0,
) -> bytes:
    """Apply strict AAELF32 relocations to ARM/Thumb function bytes."""
    buf = bytearray(data)
    base_pc = text_base & ~1

    def r_u32_d(off: int) -> int:
        if off < 0 or off + 4 > len(buf):
            raise ValueError("relocation outside ARM function")
        return int.from_bytes(buf[off : off + 4], data_endian)

    def w_u32_d(off: int, val: int) -> None:
        buf[off : off + 4] = (val & 0xFFFFFFFF).to_bytes(4, data_endian)

    def r_u32_i(off: int) -> int:
        if off < 0 or off + 4 > len(buf):
            raise ValueError("relocation outside ARM function")
        return int.from_bytes(buf[off : off + 4], insn_endian)

    def w_u32_i(off: int, val: int) -> None:
        buf[off : off + 4] = (val & 0xFFFFFFFF).to_bytes(4, insn_endian)

    def r_u16_i(off: int) -> int:
        if off < 0 or off + 2 > len(buf):
            raise ValueError("relocation outside Thumb function")
        return int.from_bytes(buf[off : off + 2], insn_endian)

    def w_u16_i(off: int, val: int) -> None:
        buf[off : off + 2] = (val & 0xFFFF).to_bytes(2, insn_endian)

    for rec in records:
        off, k, sym_key, A = rec.offset, rec.kind, rec.key, rec.addend
        if k == "V4BX":
            continue
        if sym_key not in symbols:
            raise ValueError(f"unresolved ARM relocation: {k} {sym_key}")
        S, T = symbols[sym_key]
        P = (base_pc + off) & 0xFFFFFFFF

        if k in ("ABS32", "TARGET1"):
            if off < 0 or off + 4 > len(buf):
                raise ValueError("relocation outside ARM function")
            w_u32_d(off, ((S + A) | T) & 0xFFFFFFFF)
        elif k == "ABS32_NOI":
            if off < 0 or off + 4 > len(buf):
                raise ValueError("relocation outside ARM function")
            w_u32_d(off, (S + A) & 0xFFFFFFFF)
        elif k == "REL32":
            if off < 0 or off + 4 > len(buf):
                raise ValueError("relocation outside ARM function")
            w_u32_d(off, (((S + A) | T) - P) & 0xFFFFFFFF)
        elif k == "REL32_NOI":
            if off < 0 or off + 4 > len(buf):
                raise ValueError("relocation outside ARM function")
            w_u32_d(off, ((S + A) - P) & 0xFFFFFFFF)
        elif k == "PREL31":
            w = r_u32_d(off)
            disp = _s32((((S + A) | T) - P) & 0xFFFFFFFF)
            if not -(1 << 30) <= disp < (1 << 30):
                raise ValueError("R_ARM_PREL31 out of range")
            w_u32_d(off, (w & 0x80000000) | (disp & 0x7FFFFFFF))
        elif k == "SBREL32":
            if not sb:
                raise ValueError("R_ARM_SBREL32 requires target.sb")
            w_u32_d(off, (((S + A) | T) - sb) & 0xFFFFFFFF)
        elif k == "ABS16":
            val = S + A
            if not -0x8000 <= val <= 0xFFFF or off < 0 or off + 2 > len(buf):
                raise ValueError("R_ARM_ABS16 overflow or out of bounds")
            buf[off : off + 2] = (val & 0xFFFF).to_bytes(2, data_endian)
        elif k == "ABS8":
            val = S + A
            if not -0x80 <= val <= 0xFF or off < 0 or off + 1 > len(buf):
                raise ValueError("R_ARM_ABS8 overflow or out of bounds")
            buf[off] = val & 0xFF
        elif k in ("PC24", "PLT32", "CALL", "JUMP24"):
            w = r_u32_i(off)
            disp = _s32(((S + A) - P) & 0xFFFFFFFF)
            if not -0x02000000 <= disp <= 0x01FFFFFC:
                raise ValueError(f"R_ARM_{k} branch relocation out of 32MB range")
            if T == 1 and k == "CALL" and ((w >> 28) & 0xF) == 0xE:
                # Interworking A32 BL -> BLX <thumb_target>
                if disp % 2:
                    raise ValueError("unaligned Thumb target for A32 BLX")
                h_bit = (disp >> 1) & 1
                w = 0xFA000000 | (h_bit << 24) | ((disp >> 2) & 0x00FFFFFF)
            else:
                if disp % 4:
                    raise ValueError(f"unaligned A32 branch target for R_ARM_{k}")
                w = (w & 0xFF000000) | ((disp >> 2) & 0x00FFFFFF)
            w_u32_i(off, w)
        elif k == "LDR_PC_G0":
            w = r_u32_i(off)
            disp = _s32(((S + A) - P) & 0xFFFFFFFF)
            if not -4095 <= disp <= 4095:
                raise ValueError("R_ARM_LDR_PC_G0 out of +-4095 range")
            u = 1 if disp >= 0 else 0
            w = (w & 0xFF7FF000) | (u << 23) | (abs(disp) & 0xFFF)
            w_u32_i(off, w)
        elif k == "ABS12":
            w = r_u32_i(off)
            val = S + A
            if not 0 <= val <= 4095:
                raise ValueError("R_ARM_ABS12 out of 12-bit range")
            w_u32_i(off, (w & 0xFFFFF000) | (val & 0xFFF))
        elif k in ("ALU_PC_G0_NC", "ALU_PC_G0"):
            w = r_u32_i(off)
            disp = _s32((((S + A) | T) - P) & 0xFFFFFFFF)
            mag = abs(disp)
            if mag > 0xFF and k == "ALU_PC_G0":
                raise ValueError("R_ARM_ALU_PC_G0 immediate out of 8-bit group-0 range")
            opc = 4 if disp >= 0 else 2  # ADD=4, SUB=2
            w_u32_i(off, (w & 0xFE1FF000) | (opc << 21) | (mag & 0xFF))
        elif k in ("MOVW_ABS_NC", "MOVT_ABS", "MOVW_PREL_NC", "MOVT_PREL"):
            w = r_u32_i(off)
            if k == "MOVW_ABS_NC":
                v = ((S + A) | T) & 0xFFFF
            elif k == "MOVT_ABS":
                v = ((S + A) >> 16) & 0xFFFF
            elif k == "MOVW_PREL_NC":
                v = (((S + A) | T) - P) & 0xFFFF
            else:
                v = (((S + A) - P) >> 16) & 0xFFFF
            w_u32_i(off, (w & 0xFFF0F000) | (((v >> 12) & 0xF) << 16) | (v & 0xFFF))
        elif k in ("THM_CALL", "THM_JUMP24"):
            hw1, hw2 = r_u16_i(off), r_u16_i(off + 2)
            is_blx = (k == "THM_CALL" and T == 0)
            eff_p = (P & ~3) if is_blx else P
            disp = _s32(((S + A) - eff_p) & 0xFFFFFFFF)
            if not -(1 << 24) <= disp < (1 << 24):
                raise ValueError(f"R_ARM_{k} out of 16MB Thumb branch range")
            if is_blx and (disp % 4):
                raise ValueError("unaligned ARM target for Thumb BLX")
            if not is_blx and (disp % 2):
                raise ValueError("unaligned Thumb target for Thumb BL/B.W")
            s_bit = (disp >> 24) & 1
            i1 = (disp >> 23) & 1
            i2 = (disp >> 22) & 1
            j1 = (~i1 ^ s_bit) & 1
            j2 = (~i2 ^ s_bit) & 1
            imm10 = (disp >> 12) & 0x3FF
            imm11 = (disp >> 1) & 0x7FF
            if is_blx:
                imm11 &= ~1
                hw2_op = 0xC000
            elif k == "THM_CALL":
                hw2_op = 0xD000
            else:
                hw2_op = 0x9000
            w_u16_i(off, 0xF000 | (s_bit << 10) | imm10)
            w_u16_i(off + 2, hw2_op | (j1 << 13) | (j2 << 11) | imm11)
        elif k == "THM_JUMP19":
            hw1, hw2 = r_u16_i(off), r_u16_i(off + 2)
            disp = _s32(((S + A) - P) & 0xFFFFFFFF)
            if disp % 2 or not -(1 << 20) <= disp < (1 << 20):
                raise ValueError("R_ARM_THM_JUMP19 out of 1MB range")
            s_bit = (disp >> 20) & 1
            j2 = (disp >> 19) & 1
            j1 = (disp >> 18) & 1
            imm6 = (disp >> 12) & 0x3F
            imm11 = (disp >> 1) & 0x7FF
            w_u16_i(off, (hw1 & 0xFBC0) | (s_bit << 10) | imm6)
            w_u16_i(off + 2, 0x8000 | (j1 << 13) | (j2 << 11) | imm11)
        elif k in ("THM_MOVW_ABS_NC", "THM_MOVT_ABS", "THM_MOVW_PREL_NC", "THM_MOVT_PREL"):
            hw1, hw2 = r_u16_i(off), r_u16_i(off + 2)
            if k == "THM_MOVW_ABS_NC":
                v = ((S + A) | T) & 0xFFFF
            elif k == "THM_MOVT_ABS":
                v = ((S + A) >> 16) & 0xFFFF
            elif k == "THM_MOVW_PREL_NC":
                v = (((S + A) | T) - P) & 0xFFFF
            else:
                v = (((S + A) - P) >> 16) & 0xFFFF
            w_u16_i(off, (hw1 & 0xFBF0) | (((v >> 11) & 1) << 10) | ((v >> 12) & 0xF))
            w_u16_i(off + 2, (hw2 & 0x8F00) | (((v >> 8) & 0x7) << 12) | (v & 0xFF))
        elif k == "THM_PC12":
            hw1, hw2 = r_u16_i(off), r_u16_i(off + 2)
            disp = _s32(((S + A) - (P & ~3)) & 0xFFFFFFFF)
            if not -4095 <= disp <= 4095:
                raise ValueError("R_ARM_THM_PC12 out of +-4095 range")
            u = 1 if disp >= 0 else 0
            w_u16_i(off, (hw1 & 0xFF7F) | (u << 7))
            w_u16_i(off + 2, (hw2 & 0xF000) | (abs(disp) & 0xFFF))
        elif k == "THM_ALU_PREL_11_0":
            hw1, hw2 = r_u16_i(off), r_u16_i(off + 2)
            disp = _s32((((S + A) | T) - (P & ~3)) & 0xFFFFFFFF)
            if not -4095 <= disp <= 4095:
                raise ValueError("R_ARM_THM_ALU_PREL_11_0 out of +-4095 range")
            mag = abs(disp)
            # ADR.W: F20F (ADD) vs F2AF (SUB)
            hw1_base = (hw1 & 0xFB5F) | (0x0000 if disp >= 0 else 0x00A0)
            w_u16_i(off, hw1_base | (((mag >> 11) & 1) << 10))
            w_u16_i(off + 2, (hw2 & 0x8F00) | (((mag >> 8) & 0x7) << 12) | (mag & 0xFF))
        elif k == "THM_JUMP11":
            hw = r_u16_i(off)
            disp = _s32(((S + A) - P) & 0xFFFFFFFF)
            if disp % 2 or not -2048 <= disp <= 2046:
                raise ValueError("R_ARM_THM_JUMP11 out of 2KB range")
            w_u16_i(off, (hw & 0xF800) | ((disp >> 1) & 0x7FF))
        elif k == "THM_JUMP8":
            hw = r_u16_i(off)
            disp = _s32(((S + A) - P) & 0xFFFFFFFF)
            if disp % 2 or not -256 <= disp <= 254:
                raise ValueError("R_ARM_THM_JUMP8 out of 256B range")
            w_u16_i(off, (hw & 0xFF00) | ((disp >> 1) & 0xFF))
        elif k == "THM_JUMP6":
            hw = r_u16_i(off)
            disp = _s32(((S + A) - P) & 0xFFFFFFFF)
            if disp % 2 or not 0 <= disp <= 126:
                raise ValueError("R_ARM_THM_JUMP6 (CBZ/CBNZ) out of 0..126 range")
            w_u16_i(off, (hw & 0xFD07) | (((disp >> 6) & 1) << 9) | (((disp >> 1) & 0x1F) << 3))
        elif k == "THM_PC8":
            hw = r_u16_i(off)
            disp = _s32((((S + A) & ~3) - (P & ~3)) & 0xFFFFFFFF)
            if disp % 4 or not 0 <= disp <= 1020:
                raise ValueError("R_ARM_THM_PC8 literal-pool/ADR offset out of 0..1020 range")
            w_u16_i(off, (hw & 0xFF00) | ((disp >> 2) & 0xFF))
        elif k == "THM_ABS5":
            hw = r_u16_i(off)
            val = S + A
            if val % 4 or not 0 <= val <= 124:
                raise ValueError("R_ARM_THM_ABS5 out of 0..124 word-aligned range")
            w_u16_i(off, (hw & 0xF83F) | (((val >> 2) & 0x1F) << 6))
        else:
            raise ValueError(f"unsupported ARM relocation: {k}")

    return bytes(buf)


def compare_arm_bytes(
    ours: bytes,
    target: bytes,
    unit_offsets: list[int] | None = None,
) -> dict[str, Any]:
    """Byte-exact comparison between relocated ARM/Thumb candidate bytes and target bytes."""
    offsets = [
        i
        for i in range(max(len(ours), len(target)))
        if i >= len(ours) or i >= len(target) or ours[i] != target[i]
    ]
    if unit_offsets:
        starts = sorted(unit_offsets)
        insn_mism = len({bisect_right(starts, off) - 1 for off in offsets})
    else:
        insn_mism = len({off // 2 for off in offsets}) if (len(target) % 4) else len({off // 4 for off in offsets})
    return {
        "verified": bool(target) and not offsets,
        "ours_bytes": len(ours),
        "target_bytes": len(target),
        "different_bytes": len(offsets),
        "first_offsets": offsets[:24],
        "instruction_mismatches": insn_mism,
    }


def _locate_readonly_all(section: ArmSection, segments: list[tuple[int, bytes]], cap: int | None = None) -> list[int]:
    if section.flags & 5 or not section.flags & 2 or section.type != SHT_PROGBITS:
        raise ValueError(f"{section.name}: automatic placement requires readonly data")
    data = section.data
    if len(data) < 2 or not any(data):
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


def _locate_readonly(section: ArmSection, segments: list[tuple[int, bytes]]) -> int:
    matches = _locate_readonly_all(section, segments)
    if len(matches) > 1:
        raise ValueError(f"{section.name}: ambiguous constant placement; supply link_layout")
    if len(matches) != 1:
        raise ValueError(f"{section.name}: no exact constant placement; supply link_layout")
    return matches[0]


def _probe_target_thumb(address: int, read_mem: Any, default_thumb_callee: bool = False) -> int:
    """Infer Thumb (`1`) vs ARM (`0`) bit for an unnamed `fn_XXXXXXXX` callee in target memory."""
    if address & 1:
        return 1
    if read_mem is not None:
        try:
            head = read_mem(address & ~1, 4)
            if len(head) == 4:
                hw0 = int.from_bytes(head[:2], "little")
                w0 = int.from_bytes(head, "little")
                if (w0 >> 28) == 0xE and ((w0 & 0xFFFF0000) in (0xE92D0000, 0xE52D0000) or w0 == 0xE12FFF1E):
                    return 0
                if (hw0 & 0xFE00) == 0xB400 or hw0 == 0x4770 or (hw0 & 0xFF80) == 0xB080:
                    return 1
        except Exception:
            pass
    return int(default_thumb_callee)


def _resolve_external_arm(
    symbol: str,
    external: dict[str, int],
    function_addresses: dict[int, str],
    object_addresses: dict[int, tuple[str, int]],
    thumb_addrs: set[int],
    default_thumb_callee: bool = False,
    allow_hex_fallback: bool = False,
    read_mem: Any = None,
) -> tuple[int, int]:
    """Return `(S_even_or_exact, T_bit)` for an external ARM/Thumb symbol."""
    if symbol in external:
        raw_addr = external[symbol]
        if raw_addr in object_addresses and (raw_addr & ~1) not in function_addresses:
            return raw_addr, 0
        is_th = bool((raw_addr & 1) or ((raw_addr & ~1) in thumb_addrs))
        if not is_th and (raw_addr & ~1) in function_addresses and default_thumb_callee:
            is_th = True
        return (raw_addr & ~1 if (raw_addr & ~1) in function_addresses or is_th else raw_addr), int(is_th)

    match = re.fullmatch(r"(fn|func|lbl|D)_([0-9A-Fa-f]{6,8})", symbol)
    if match:
        addr = int(match.group(2), 16)
        if match.group(1) in ("fn", "func"):
            even = addr & ~1
            if even in function_addresses:
                t = int(bool((addr & 1) or (even in thumb_addrs) or default_thumb_callee))
                return even, t
            if allow_hex_fallback:
                return even, _probe_target_thumb(addr, read_mem, default_thumb_callee=default_thumb_callee)
        elif addr in object_addresses or allow_hex_fallback:
            return addr, 0
    raise ValueError(f"unresolved external: {symbol}")


def _cache_key(section: ArmSection) -> tuple[str, str, int, int]:
    return (section.name, hashlib.sha256(section.data).hexdigest(), section.align, section.flags)


def link_arm_function(
    elf: ArmObject,
    function: ArmSymbol,
    va: int,
    target_bytes: bytes,
    external: dict[str, int],
    function_addresses: dict[int, str],
    object_addresses: dict[int, tuple[str, int]],
    data_segments: list[tuple[int, bytes]],
    read_mem: Any,
    thumb_addrs: set[int] | None = None,
    sb: int = 0,
    explicit_layout: dict[str, int] | None = None,
    partial: bool = False,
    placement_cache: dict[Any, Any] | None = None,
    allow_hex_fallback: bool = False,
) -> tuple[bytes, dict[str, Any], dict[int, str]]:
    """Relocate a compiled ARM/Thumb function (including inline `$d` literal pools) against target symbols."""
    start, length = function.offset, function.size
    sec_obj = elf.sections[function.section]
    raw = sec_obj.data[start : start + length]
    explicit = explicit_layout or {}
    tset = thumb_addrs or set()
    even_va = va & ~1

    all_sec_relocs = elf.relocations(function.section)
    prepared_all = prepare_arm_relocs(sec_obj.data, all_sec_relocs, elf.endian, elf.insn_endian)
    fn_relocs = [(rel, eff_add) for rel, eff_add in prepared_all if start <= rel.offset < start + length]

    def resolve_section(section: ArmSection, idx: int) -> tuple[int, str]:
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
        placements: dict[int, int] = {function.section: even_va - start}
        evidence: dict[str, Any] = {}
        records: list[PreparedArmReloc] = []
        values: dict[str, tuple[int, int]] = {}
        unknown: dict[int, str] = {}
        ambiguous: dict[int, ArmSection] = {}

        for rel, eff_add in fn_relocs:
            key = f"{rel.symbol.name}#{len(records)}"
            symbol = rel.symbol
            try:
                if symbol.section in (SHN_UNDEF, SHN_COMMON):
                    s_addr, t_bit = _resolve_external_arm(
                        symbol.name,
                        external,
                        function_addresses,
                        object_addresses,
                        tset,
                        default_thumb_callee=function.is_thumb and rel.kind == "THM_CALL",
                        allow_hex_fallback=allow_hex_fallback,
                        read_mem=read_mem,
                    )
                elif symbol.section == SHN_ABS:
                    s_addr, t_bit = symbol.value & ~1, int(bool(symbol.value & 1))
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
                    if symbol.st_type in (STT_FUNC, STT_ARM_TFUNC):
                        s_addr = placements[symbol.section] + (symbol.value & ~1)
                        t_bit = int(symbol.is_thumb or bool(symbol.value & 1))
                    else:
                        s_addr = placements[symbol.section] + symbol.value
                        t_bit = 0
                else:
                    raise ValueError(f"unsupported ARM symbol section 0x{symbol.section:X} for '{symbol.name}'")
                records.append(PreparedArmReloc(rel.offset - start, rel.kind, key, eff_add))
                values[key] = (s_addr, t_bit)
            except ValueError as error:
                if not partial:
                    raise
                unknown[(rel.offset - start) // 2] = str(error)
        return placements, evidence, records, values, unknown, ambiguous

    def finish(records: list[PreparedArmReloc], values: dict[str, tuple[int, int]]):
        linked = raw
        unknown: dict[int, str] = {}
        for rec in records:
            try:
                linked = relocate_arm(
                    linked,
                    [rec],
                    values,
                    even_va,
                    data_endian=elf.endian,
                    insn_endian=elf.insn_endian,
                    sb=sb,
                )
            except ValueError as error:
                if not partial:
                    raise
                unknown[rec.offset // 2] = str(error)
        return linked, unknown

    _placements, evidence, records, values, unknown, ambiguous = build()
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
                    _, evidence2, records2, values2, unknown2, _ = build(forced)
                    if any("ambiguous constant placement" in str(m) for m in unknown2.values()):
                        continue
                    linked2, relocate_unknown = finish(records2, values2)
                except ValueError:
                    continue
                diffs = compare_arm_bytes(linked2, target_bytes)["different_bytes"]
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

    linked, relocate_unknown = finish(records, values)
    unknown.update(relocate_unknown)
    return linked, evidence, unknown
