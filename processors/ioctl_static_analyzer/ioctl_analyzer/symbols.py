from __future__ import annotations

import csv
import json
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(slots=True)
class SymbolResolver:
    symbols: dict[int, str] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)

    def add(self, address: int, name: str) -> None:
        if name:
            self.symbols[int(address)] = name

    def resolve(self, address: int) -> str | None:
        return self.symbols.get(int(address))

    def to_json(self) -> dict[str, str]:
        return {hex(addr): name for addr, name in sorted(self.symbols.items())}

    @classmethod
    def from_paths(cls, image_base: int, symbol_paths: list[Path] | None = None, pdb_paths: list[Path] | None = None) -> "SymbolResolver":
        resolver = cls()
        for path in symbol_paths or []:
            resolver.load_symbol_file(path, image_base=image_base)
        for path in pdb_paths or []:
            resolver.load_pdb(path, image_base=image_base)
        return resolver

    def load_symbol_file(self, path: Path, image_base: int) -> None:
        if not path.exists():
            self.warnings.append(f"Symbol file not found: {path}")
            return
        suffix = path.suffix.lower()
        try:
            if suffix == ".json":
                self._load_json(path, image_base)
            elif suffix == ".csv":
                self._load_csv(path, image_base)
            else:
                self._load_text(path, image_base)
        except Exception as exc:  # noqa: BLE001
            self.warnings.append(f"Failed to load symbol file {path}: {exc}")

    def load_pdb(self, path: Path, image_base: int) -> None:
        if not path.exists():
            self.warnings.append(f"PDB file not found: {path}")
            return
        try:
            proc = subprocess.run(
                ["llvm-pdbutil", "dump", "-symbols", str(path)],
                check=False,
                capture_output=True,
                text=True,
                timeout=60,
            )
        except FileNotFoundError:
            self.warnings.append("llvm-pdbutil was not found; install LLVM or pass a JSON/CSV/text symbol map with --symbols.")
            return
        except Exception as exc:  # noqa: BLE001
            self.warnings.append(f"Failed to invoke llvm-pdbutil for {path}: {exc}")
            return

        if proc.returncode != 0:
            self.warnings.append(f"llvm-pdbutil failed for {path}: {proc.stderr.strip()[:300]}")
            return

        count = 0
        for line in proc.stdout.splitlines():
            parsed = self._parse_pdbutil_symbol_line(line, image_base=image_base)
            if parsed is None:
                continue
            address, name = parsed
            self.add(address, name)
            count += 1
        if count == 0:
            self.warnings.append(f"No public/code symbols were parsed from {path}; try exporting a map file if names are needed.")

    def _load_json(self, path: Path, image_base: int) -> None:
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            items = data.items()
        elif isinstance(data, list):
            items = []
            for row in data:
                if isinstance(row, dict):
                    addr = row.get("address") or row.get("va") or row.get("rva")
                    name = row.get("name") or row.get("symbol")
                    items.append((addr, name))
        else:
            raise ValueError("JSON symbol file must be an object or list of objects")
        for addr, name in items:
            parsed = _parse_address(addr, image_base=image_base)
            if parsed is not None and name:
                self.add(parsed, str(name))

    def _load_csv(self, path: Path, image_base: int) -> None:
        with path.open("r", encoding="utf-8", newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                addr = row.get("address") or row.get("va") or row.get("rva")
                name = row.get("name") or row.get("symbol")
                parsed = _parse_address(addr, image_base=image_base)
                if parsed is not None and name:
                    self.add(parsed, name)

    def _load_text(self, path: Path, image_base: int) -> None:
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # Accept: "0x140001000 Dispatch", "140001000 Dispatch", "0001:00001000 _Dispatch"
            match = re.search(r"(?P<seg>[0-9a-fA-F]{4}):(?P<off>[0-9a-fA-F]{8,16})\s+(?P<name>\S+)", line)
            if match:
                self.add(image_base + int(match.group("off"), 16), match.group("name"))
                continue
            match = re.search(r"(?P<addr>0x[0-9a-fA-F]+|[0-9a-fA-F]{3,16})\s+`?(?P<name>[A-Za-z_.$?@][\w.$?@<>~`':-]*)", line)
            if match:
                parsed = _parse_address(match.group("addr"), image_base=image_base)
                if parsed is not None:
                    self.add(parsed, match.group("name").strip("`"))

    def _parse_pdbutil_symbol_line(self, line: str, image_base: int) -> tuple[int, str] | None:
        # Handles common llvm-pdbutil output fragments such as:
        #   0001:00001234 | S_GPROC32 [size = ...] `DriverEntry`
        #   0001:00004567 | S_LPROC32 ... `DeviceControl`
        if "S_GPROC32" not in line and "S_LPROC32" not in line and "S_PUB32" not in line:
            return None
        loc = re.search(r"(?P<seg>[0-9a-fA-F]{4}):(?P<off>[0-9a-fA-F]{8,16})", line)
        name = re.search(r"`(?P<name>[^`]+)`", line)
        if not loc or not name:
            return None
        return image_base + int(loc.group("off"), 16), name.group("name")


def _parse_address(value, image_base: int) -> int | None:
    if value is None:
        return None
    if isinstance(value, int):
        addr = value
    else:
        text = str(value).strip()
        if not text:
            return None
        if text.lower().startswith("rva:"):
            return image_base + int(text.split(":", 1)[1], 0)
        addr = int(text, 0 if text.lower().startswith("0x") else 16)
    if addr < image_base:
        return image_base + addr
    return addr
