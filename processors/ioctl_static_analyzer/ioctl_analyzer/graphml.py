from __future__ import annotations

from pathlib import Path
from xml.sax.saxutils import escape

from .models import AnalysisResult, CFG


def cfg_to_graphml(cfg: CFG) -> str:
    lines = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<graphml xmlns="http://graphml.graphdrawing.org/xmlns">',
        '  <key id="label" for="node" attr.name="label" attr.type="string"/>',
        '  <key id="start" for="node" attr.name="start" attr.type="string"/>',
        '  <key id="end" for="node" attr.name="end" attr.type="string"/>',
        '  <key id="kind" for="edge" attr.name="kind" attr.type="string"/>',
        f'  <graph id="cfg_0x{cfg.function:x}" edgedefault="directed">',
    ]

    for block in cfg.blocks:
        label = "\n".join(
            [f"0x{block.start:x}:"] + [f"0x{ins.address:x}: {ins.mnemonic} {ins.op_str}".rstrip() for ins in block.instructions]
        )
        lines.extend(
            [
                f'    <node id="n_{block.start:x}">',
                f"      <data key=\"label\">{escape(label)}</data>",
                f"      <data key=\"start\">0x{block.start:x}</data>",
                f"      <data key=\"end\">0x{block.end:x}</data>",
                "    </node>",
            ]
        )

    for idx, (src, dst, kind) in enumerate(cfg.edges):
        lines.extend(
            [
                f'    <edge id="e_{idx}" source="n_{src:x}" target="n_{dst:x}">',
                f"      <data key=\"kind\">{escape(kind)}</data>",
                "    </edge>",
            ]
        )

    lines.extend(["  </graph>", "</graphml>"])
    return "\n".join(lines) + "\n"


def write_analysis_graphml(result: AnalysisResult, directory: Path) -> list[Path]:
    directory.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for dispatch in result.device_control_dispatches:
        if dispatch.cfg is not None:
            path = directory / f"dispatch_{dispatch.routine_va:x}.graphml"
            path.write_text(cfg_to_graphml(dispatch.cfg), encoding="utf-8")
            written.append(path)
        for case in dispatch.ioctl_cases:
            if case.cfg is None:
                continue
            ioctl_name = "unknown" if case.ioctl_code is None else f"{case.ioctl_code:x}"
            path = directory / f"ioctl_{ioctl_name}_handler_{case.handler_va:x}.graphml"
            path.write_text(cfg_to_graphml(case.cfg), encoding="utf-8")
            written.append(path)
    return written

