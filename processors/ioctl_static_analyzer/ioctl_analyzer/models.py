from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from .ioctl import decode_ioctl


IRP_MJ_DEVICE_CONTROL = 0x0E


@dataclass(slots=True)
class ImportSymbol:
    name: str
    dll: str
    iat_va: int | None

    def to_json(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class Instruction:
    address: int
    size: int
    mnemonic: str
    op_str: str
    bytes_hex: str
    groups: tuple[str, ...] = ()

    def to_json(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class BasicBlock:
    start: int
    end: int
    instructions: list[Instruction] = field(default_factory=list)

    def to_json(self) -> dict[str, Any]:
        return {
            "start": hex(self.start),
            "end": hex(self.end),
            "instructions": [ins.to_json() for ins in self.instructions],
        }


@dataclass(slots=True)
class CFG:
    function: int
    blocks: list[BasicBlock] = field(default_factory=list)
    edges: list[tuple[int, int, str]] = field(default_factory=list)

    def to_json(self) -> dict[str, Any]:
        return {
            "function": hex(self.function),
            "blocks": [block.to_json() for block in self.blocks],
            "edges": [
                {"src": hex(src), "dst": hex(dst), "kind": kind}
                for src, dst, kind in self.edges
            ],
        }


@dataclass(slots=True)
class IoctlCase:
    ioctl_code: int | None
    handler_va: int
    source: str
    confidence: str
    handler_symbol: str | None = None
    cfg: CFG | None = None

    def to_json(self) -> dict[str, Any]:
        return {
            "ioctl_code": None if self.ioctl_code is None else hex(self.ioctl_code),
            "decoded_ioctl": None if self.ioctl_code is None else decode_ioctl(self.ioctl_code).to_json(),
            "handler_va": hex(self.handler_va),
            "handler_symbol": self.handler_symbol,
            "source": self.source,
            "confidence": self.confidence,
            "cfg": None if self.cfg is None else self.cfg.to_json(),
        }


@dataclass(slots=True)
class DispatchRoutine:
    routine_va: int
    routine_symbol: str | None = None
    evidence: list[str] = field(default_factory=list)
    ioctl_cases: list[IoctlCase] = field(default_factory=list)
    cfg: CFG | None = None

    def to_json(self) -> dict[str, Any]:
        return {
            "routine_va": hex(self.routine_va),
            "routine_symbol": self.routine_symbol,
            "evidence": self.evidence,
            "ioctl_cases": [case.to_json() for case in self.ioctl_cases],
            "cfg": None if self.cfg is None else self.cfg.to_json(),
        }


@dataclass(slots=True)
class AnalysisResult:
    image_path: str
    machine: str
    image_base: int
    entry_point_va: int
    imports: list[ImportSymbol]
    io_create_device_refs: list[int]
    io_create_symbolic_link_refs: list[int]
    io_create_device_wrapper_refs: list[dict[str, str]]
    io_create_symbolic_link_wrapper_refs: list[dict[str, str]]
    device_control_dispatches: list[DispatchRoutine]
    warnings: list[str] = field(default_factory=list)
    symbols: dict[int, str] = field(default_factory=dict)

    def to_json(self) -> dict[str, Any]:
        return {
            "image_path": self.image_path,
            "machine": self.machine,
            "image_base": hex(self.image_base),
            "entry_point_va": hex(self.entry_point_va),
            "imports": [sym.to_json() for sym in self.imports],
            "io_create_device_refs": [hex(x) for x in self.io_create_device_refs],
            "io_create_symbolic_link_refs": [hex(x) for x in self.io_create_symbolic_link_refs],
            "io_create_device_wrapper_refs": self.io_create_device_wrapper_refs,
            "io_create_symbolic_link_wrapper_refs": self.io_create_symbolic_link_wrapper_refs,
            "device_control_dispatches": [d.to_json() for d in self.device_control_dispatches],
            "warnings": self.warnings,
            "symbols": {hex(addr): name for addr, name in sorted(self.symbols.items())},
        }
