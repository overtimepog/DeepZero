from __future__ import annotations

from pathlib import Path

from .models import CFG, AnalysisResult


def cfg_to_dot(cfg: CFG, name: str | None = None) -> str:
    graph_name = _dot_id(name or f"sub_{cfg.function:x}")
    lines = [f"digraph {graph_name} {{", "  rankdir=TB;", "  node [shape=box,fontname=\"Consolas\"];"]
    for block in cfg.blocks:
        label_lines = [f"0x{block.start:x}:"]
        for ins in block.instructions:
            label_lines.append(f"0x{ins.address:x}: {ins.mnemonic} {ins.op_str}".rstrip())
        label = "\\l".join(_escape_label(x) for x in label_lines) + "\\l"
        lines.append(f"  n_{block.start:x} [label=\"{label}\"];")
    for src, dst, kind in cfg.edges:
        lines.append(f"  n_{src:x} -> n_{dst:x} [label=\"{_escape_label(kind)}\"];")
    lines.append("}")
    return "\n".join(lines) + "\n"


def write_analysis_dot(result: AnalysisResult, directory: Path) -> list[Path]:
    directory.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for dispatch in result.device_control_dispatches:
        if dispatch.cfg is not None:
            path = directory / f"dispatch_{dispatch.routine_va:x}.dot"
            path.write_text(cfg_to_dot(dispatch.cfg, f"dispatch_{dispatch.routine_va:x}"), encoding="utf-8")
            written.append(path)
        for case in dispatch.ioctl_cases:
            if case.cfg is None:
                continue
            ioctl_name = "unknown" if case.ioctl_code is None else f"{case.ioctl_code:x}"
            path = directory / f"ioctl_{ioctl_name}_handler_{case.handler_va:x}.dot"
            path.write_text(cfg_to_dot(case.cfg, f"ioctl_{ioctl_name}_{case.handler_va:x}"), encoding="utf-8")
            written.append(path)
    return written


def _dot_id(value: str) -> str:
    safe = "".join(ch if ch.isalnum() or ch == "_" else "_" for ch in value)
    if safe and safe[0].isdigit():
        safe = f"g_{safe}"
    return safe or "cfg"


def _escape_label(value: str) -> str:
    return value.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n")

