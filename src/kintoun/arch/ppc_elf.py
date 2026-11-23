"""Strict PowerPC ELF32 relocation, SDA lookup, readonly placement, and byte comparison."""
from __future__ import annotations

from bisect import bisect_right
import hashlib
import re
from typing import Any

from kintoun.arch.elf import Object


def symbol_name(objects: dict[int, tuple[str, int]], address: int) -> str:
    """Resolve an address to its nearest object symbol name or fallback lbl_XXXXXXXX."""
    if address in objects:
        return objects[address][0]
    addresses = sorted(objects)
    i = bisect_right(addresses, address) - 1
    if i >= 0:
        start = addresses[i]
        row = objects[start]
        if start <= address < start + row[1]:
            return f"{row[0]}+0x{address - start:X}"
    return f"lbl_{address:08X}"


def sda_references(
    words: list[int],
    objects: dict[int, tuple[str, int]],
    r13: int,
    r2: int,
) -> list[dict[str, Any]]:
    """Decode r13/r2 small-data accesses in a big-endian PPC instruction stream."""
    out = []
    for i, word in enumerate(words):
        op, ra = word >> 26, (word >> 16) & 31
        if (op != 14 and not 32 <= op <= 55) or ra not in (2, 13):
            continue
        imm = word & 0xFFFF
        imm = imm - 0x10000 if imm & 0x8000 else imm
        address = ((r13 if ra == 13 else r2) + imm) & 0xFFFFFFFF
        out.append(
            {
                "offset": 4 * i,
                "register": f"r{ra}",
                "address": f"0x{address:08X}",
                "symbol": symbol_name(objects, address),
            }
        )
    return out


def relocate_ppc(
    data: bytes,
    records: list[tuple[int, str, str, int]],
    symbols: dict[str, int],
    text_base: int,
    sda_r13: int = 0,
    sda_r2: int = 0,
) -> bytes:
    """Apply actual PPC ELF32 relocations to function bytes. Refuses out-of-range/unknown relocs."""
    buf = bytearray(data)
    widths = {
        "ADDR32": 4,
        "REL32": 4,
        "REL24": 4,
        "REL14": 4,
        "ADDR16": 2,
        "ADDR16_LO": 2,
        "ADDR16_HI": 2,
        "ADDR16_HA": 2,
        "SDAREL16": 2,
        "EMB_SDA21": 4,
    }
    for offset, kind, symbol, addend in records:
        if symbol not in symbols:
            raise ValueError(f"unresolved relocation: {kind} {symbol}")
        value = (symbols[symbol] + addend) & 0xFFFFFFFF
        if kind not in widths:
            raise ValueError(f"unsupported relocation: {kind}")
        width = widths[kind]
        if offset < 0 or offset + width > len(buf):
            raise ValueError("relocation outside function")
        word = int.from_bytes(buf[offset : offset + width], "big")
        if kind == "ADDR32":
            word = value
        elif kind == "REL32":
            word = (value - text_base - offset) & 0xFFFFFFFF
        elif kind == "ADDR16":
            if value > 0xFFFF:
                raise ValueError("ADDR16 overflow")
            word = value
        elif kind.startswith("ADDR16_"):
            word = {
                "ADDR16_LO": value,
                "ADDR16_HI": value >> 16,
                "ADDR16_HA": (value + 0x8000) >> 16,
            }[kind] & 0xFFFF
        elif kind in ("EMB_SDA21", "SDAREL16"):
            if kind == "SDAREL16":
                disp = value - sda_r13
                if not -32768 <= disp <= 32767:
                    raise ValueError("SDA displacement out of range")
                word = disp & 0xFFFF
            else:
                choices = [
                    (register, value - base)
                    for register, base in ((13, sda_r13), (2, sda_r2))
                    if base and -32768 <= value - base <= 32767
                ]
                if len(choices) != 1:
                    raise ValueError(
                        f"{symbol}: SDA21 address 0x{value:08X} is ambiguous or outside "
                        f"r13=0x{sda_r13:08X}/r2=0x{sda_r2:08X} range"
                    )
                register, disp = choices[0]
                if word >> 26 not in (14, *range(32, 56)):
                    raise ValueError("unsupported SDA21 instruction")
                word = (word & 0xFFE00000) | (register << 16) | (disp & 0xFFFF)
        else:
            expected = 18 if kind == "REL24" else 16
            if word >> 26 != expected or word & 2:
                raise ValueError("invalid relative branch instruction")
            disp = (value - text_base - offset + 0x80000000) % 0x100000000 - 0x80000000
            bits = 26 if kind == "REL24" else 16
            if disp % 4 or not -(1 << (bits - 1)) <= disp < (1 << (bits - 1)):
                raise ValueError("branch relocation out of range")
            mask = 0x03FFFFFC if kind == "REL24" else 0xFFFC
            word = (word & ~mask) | (disp & mask)
        buf[offset : offset + width] = word.to_bytes(width, "big")
    return bytes(buf)


def compare_bytes(ours: bytes, target: bytes) -> dict[str, Any]:
    """Byte-exact comparison between relocated candidate bytes and target bytes."""
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


def locate_readonly_all(section: Any, segments: list[tuple[int, bytes]], cap: int | None = None) -> list[int]:
    """Find every aligned full-content occurrence of a readonly section in data segments."""
    if section.flags & 5 or not section.flags & 2 or section.type != 1:
        raise ValueError(f"{section.name}: automatic placement requires readonly data")
    data = section.data
    if len(data) < 4 or not any(data):
        raise ValueError(f"{section.name}: insufficient distinctive constant data")
    matches = []
    for address, body in segments:
        cursor = 0
        while True:
            found = body.find(data, cursor)
            if found < 0:
                break
            candidate = address + found
            if candidate % max(1, section.align) == 0:
                matches.append(candidate)
            if cap is not None and len(matches) > cap:
                raise ValueError(f"{section.name}: too many constant placements; supply link_layout")
            cursor = found + 1
    return sorted(set(matches))


def locate_readonly(section: Any, segments: list[tuple[int, bytes]]) -> int:
    """Infer a local constant section only from a single unique aligned occurrence."""
    matches = locate_readonly_all(section, segments)
    if len(matches) > 1:
        raise ValueError(f"{section.name}: ambiguous constant placement; supply link_layout")
    if len(matches) != 1:
        raise ValueError(f"{section.name}: no exact constant placement; supply link_layout")
    return matches[0]


def external_address(
    symbol: str,
    external: dict[str, int],
    function_addresses: dict[int, str],
    object_addresses: dict[int, tuple[str, int]],
) -> int:
    """Resolve an external symbol name to its target address."""
    if symbol in external:
        return external[symbol]
    match = re.fullmatch(r"(fn|lbl)_([0-9A-Fa-f]{8})", symbol)
    if match:
        address = int(match[2], 16)
        known = function_addresses if match[1] == "fn" else object_addresses
        if address in known:
            return address
    raise ValueError(f"unresolved external: {symbol}")


def _cache_key(section: Any) -> tuple[str, str, int, int]:
    return (section.name, hashlib.sha256(section.data).hexdigest(), section.align, section.flags)


def link_function(
    elf: Object,
    function: Any,
    va: int,
    target_bytes: bytes,
    external: dict[str, int],
    function_addresses: dict[int, str],
    object_addresses: dict[int, tuple[str, int]],
    data_segments: list[tuple[int, bytes]],
    read_mem: Any,
    sda_r13: int = 0,
    sda_r2: int = 0,
    explicit_layout: dict[str, int] | None = None,
    partial: bool = False,
    placement_cache: dict[Any, Any] | None = None,
) -> tuple[bytes, dict[str, Any], dict[int, str]]:
    """Relocate a compiled PPC function against the target symbol map and readonly segments."""
    start, length = function.value, function.size
    raw = elf.sections[function.section].data[start : start + length]
    explicit = explicit_layout or {}

    def resolve(section: Any, idx: int) -> tuple[int, str]:
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
                base = locate_readonly(section, data_segments)
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
        records: list[tuple[int, str, str, int]] = []
        values: dict[str, int] = {}
        unknown: dict[int, str] = {}
        ambiguous: dict[int, Any] = {}
        for rel in elf.relocations(function.section):
            if not start <= rel.offset < start + length:
                continue
            key = f"{rel.symbol.name}#{len(records)}"
            symbol = rel.symbol
            try:
                if symbol.section == 0:
                    address = external_address(symbol.name, external, function_addresses, object_addresses)
                elif symbol.section == 0xFFF1:
                    address = symbol.value
                elif 0 < symbol.section < len(elf.sections):
                    section = elf.sections[symbol.section]
                    if symbol.section not in placements:
                        if forced is not None and symbol.section in forced:
                            base, method = forced[symbol.section]
                        else:
                            try:
                                base, method = resolve(section, symbol.section)
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
                    raise ValueError(f"unsupported symbol section: {symbol.name}")
                records.append((rel.offset - start, rel.kind, key, rel.addend))
                values[key] = address
            except ValueError as error:
                if not partial:
                    raise
                unknown[(rel.offset - start) // 4] = str(error)
        return placements, evidence, records, values, unknown, ambiguous

    def finish(records: list[tuple[int, str, str, int]], values: dict[str, int]):
        linked = raw
        unknown: dict[int, str] = {}
        for record in records:
            try:
                linked = relocate_ppc(linked, [record], values, va, sda_r13, sda_r2)
            except ValueError as error:
                if not partial:
                    raise
                unknown[record[0] // 4] = str(error)
        return linked, unknown

    placements, evidence, records, values, unknown, ambiguous = build()
    if partial and len(ambiguous) == 1 and target_bytes:
        (idx, section), = ambiguous.items()
        try:
            bases = locate_readonly_all(section, data_segments, cap=128)
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
                diffs = compare_bytes(linked2, target_bytes)["different_bytes"]
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
