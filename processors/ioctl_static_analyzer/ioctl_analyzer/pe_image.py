from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pefile

from .models import ImportSymbol


IMAGE_FILE_MACHINE_I386 = 0x014C
IMAGE_FILE_MACHINE_AMD64 = 0x8664


@dataclass(slots=True)
class Section:
    name: str
    va: int
    virtual_size: int
    raw_offset: int
    raw_size: int
    characteristics: int

    @property
    def end_va(self) -> int:
        return self.va + max(self.virtual_size, self.raw_size)

    @property
    def is_executable(self) -> bool:
        return bool(self.characteristics & 0x20000000)

    @property
    def is_readable(self) -> bool:
        return bool(self.characteristics & 0x40000000)


class PEImage:
    """Thin VA-centric wrapper around pefile for kernel driver analysis."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.pe = pefile.PE(str(self.path), fast_load=False)
        self.image_base = int(self.pe.OPTIONAL_HEADER.ImageBase)
        self.entry_point_rva = int(self.pe.OPTIONAL_HEADER.AddressOfEntryPoint)
        self.entry_point_va = self.image_base + self.entry_point_rva
        self.machine = int(self.pe.FILE_HEADER.Machine)
        self.sections = [
            Section(
                name=s.Name.rstrip(b"\x00").decode("ascii", "replace"),
                va=self.image_base + int(s.VirtualAddress),
                virtual_size=int(s.Misc_VirtualSize),
                raw_offset=int(s.PointerToRawData),
                raw_size=int(s.SizeOfRawData),
                characteristics=int(s.Characteristics),
            )
            for s in self.pe.sections
        ]

    @property
    def is_64bit(self) -> bool:
        return self.machine == IMAGE_FILE_MACHINE_AMD64

    @property
    def machine_name(self) -> str:
        if self.machine == IMAGE_FILE_MACHINE_AMD64:
            return "x64"
        if self.machine == IMAGE_FILE_MACHINE_I386:
            return "x86"
        return f"unknown_0x{self.machine:x}"

    def va_to_rva(self, va: int) -> int:
        return va - self.image_base

    def rva_to_va(self, rva: int) -> int:
        return self.image_base + rva

    def section_for_va(self, va: int) -> Section | None:
        return next((s for s in self.sections if s.va <= va < s.end_va), None)

    def va_to_offset(self, va: int) -> int:
        section = self.section_for_va(va)
        if section is None:
            raise ValueError(f"VA 0x{va:x} is not inside a PE section")
        return section.raw_offset + (va - section.va)

    def read_va(self, va: int, size: int) -> bytes:
        offset = self.va_to_offset(va)
        with self.path.open("rb") as f:
            f.seek(offset)
            return f.read(size)

    def read_c_string_va(self, va: int, max_size: int = 4096) -> bytes:
        data = self.read_va(va, max_size)
        return data.split(b"\x00", 1)[0]

    def executable_ranges(self) -> list[tuple[int, int]]:
        return [(s.va, s.end_va) for s in self.sections if s.is_executable]

    def readable_ranges(self) -> list[tuple[int, int]]:
        return [(s.va, s.end_va) for s in self.sections if s.is_readable]

    def iter_executable_bytes(self) -> list[tuple[int, bytes]]:
        out: list[tuple[int, bytes]] = []
        for section in self.sections:
            if not section.is_executable or section.raw_size <= 0:
                continue
            out.append((section.va, self.read_va(section.va, section.raw_size)))
        return out

    def read_pointer(self, va: int) -> int:
        raw = self.read_va(va, 8 if self.is_64bit else 4)
        return int.from_bytes(raw, "little")

    def imports(self) -> list[ImportSymbol]:
        symbols: list[ImportSymbol] = []
        if not hasattr(self.pe, "DIRECTORY_ENTRY_IMPORT"):
            return symbols
        for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode("ascii", "replace")
            for imp in entry.imports:
                name = imp.name.decode("ascii", "replace") if imp.name else f"ordinal_{imp.ordinal}"
                symbols.append(ImportSymbol(name=name, dll=dll, iat_va=imp.address))
        return symbols

    def import_iat_va(self, name: str) -> int | None:
        lowered = name.lower()
        for sym in self.imports():
            if sym.name.lower() == lowered:
                return sym.iat_va
        return None

