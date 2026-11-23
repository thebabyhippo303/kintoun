"""Small, bounds-checked reader for ProDG's ELF32 big-endian PowerPC objects."""
from dataclasses import dataclass
import struct

RELOCATIONS = {0: 'NONE', 1: 'ADDR32', 3: 'ADDR16', 4: 'ADDR16_LO', 5: 'ADDR16_HI',
               6: 'ADDR16_HA', 10: 'REL24', 11: 'REL14', 26: 'REL32',
               32: 'SDAREL16', 109: 'EMB_SDA21'}


@dataclass(frozen=True)
class Section:
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
class Symbol:
    index: int
    name: str
    value: int
    size: int
    info: int
    section: int


@dataclass(frozen=True)
class Relocation:
    offset: int
    kind: str
    symbol: Symbol
    addend: int


class Object:
    def __init__(self, data):
        self.data = data
        header = self.unpack('16sHHIIIIIHHHHHH', 0)
        ident, typ, machine, version = header[:4]
        if ident[:7] != b'\x7fELF\x01\x02\x01' or typ != 1 or machine != 20 or version != 1:
            raise ValueError('expected an ELF32 big-endian PowerPC relocatable object')
        shoff, ehsize, shsize, count, strings = header[6], header[8], header[11], header[12], header[13]
        if ehsize != 52 or shsize != 40 or not count or strings >= count:
            raise ValueError('unsupported ELF section table')
        headers = [self.unpack('10I', shoff + i * shsize) for i in range(count)]
        names_header = headers[strings]
        names = self.slice(names_header[4], names_header[5])
        self.sections = []
        for i, h in enumerate(headers):
            name, kind, flags, _, offset, size, link, info, align, entsize = h
            body = b'' if kind == 8 else self.slice(offset, size)
            self.sections.append(Section(i, self.string(names, name), kind, flags, body,
                                         size, link, info, align, entsize))
        self.tables = {}
        for section in self.sections:
            if section.type != 2: continue
            if section.link >= count or section.entsize != 16 or section.size % 16:
                raise ValueError('invalid ELF symbol table')
            names = self.sections[section.link].data
            symbols = []
            for i in range(section.size // 16):
                name, value, size, info, _, index = struct.unpack_from('>IIIBBH', section.data, i * 16)
                if 0 < index < 0xff00 and index >= count: raise ValueError('invalid symbol section')
                symbol_name = self.string(names, name)
                if not symbol_name and index and index < count: symbol_name = self.sections[index].name
                symbols.append(Symbol(i, symbol_name, value, size, info, index))
            self.tables[section.index] = symbols

    def slice(self, offset, size):
        if offset < 0 or size < 0 or offset + size > len(self.data):
            raise ValueError('truncated ELF object')
        return self.data[offset:offset + size]

    def unpack(self, fmt, offset):
        return struct.unpack('>' + fmt, self.slice(offset, struct.calcsize('>' + fmt)))

    @staticmethod
    def string(data, offset):
        end = data.find(b'\0', offset)
        if offset < 0 or offset >= len(data) or end < 0: raise ValueError('invalid ELF string')
        return data[offset:end].decode('utf-8', errors='strict')

    def function(self, name):
        found = [s for table in self.tables.values() for s in table
                 if s.name == name and s.info & 15 == 2 and 0 < s.section < len(self.sections)]
        if len(found) != 1: raise ValueError(f'expected one defined function: {name}')
        symbol = found[0]
        section = self.sections[symbol.section]
        if not section.flags & 4 or symbol.size <= 0 or symbol.value + symbol.size > section.size:
            raise ValueError('invalid function extent')
        return symbol

    def relocations(self, index):
        out = []
        for section in self.sections:
            if section.info != index or section.type not in (4, 9): continue
            if section.type == 9: raise ValueError('implicit-addend REL relocations are not supported')
            if section.link not in self.tables or section.entsize != 12 or section.size % 12:
                raise ValueError('invalid ELF relocation table')
            symbols = self.tables[section.link]
            for offset in range(0, section.size, 12):
                place, info, addend = struct.unpack_from('>IIi', section.data, offset)
                if info >> 8 >= len(symbols): raise ValueError('invalid relocation symbol index')
                kind = RELOCATIONS.get(info & 255, f'UNKNOWN_{info & 255}')
                if kind == 'NONE': continue
                out.append(Relocation(place, kind, symbols[info >> 8], addend))
        return out
