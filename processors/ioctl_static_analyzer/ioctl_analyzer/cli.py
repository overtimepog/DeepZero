from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .analysis import DriverAnalyzer
from .dot import write_analysis_dot
from .graphml import write_analysis_graphml
from .pe_image import PEImage
from .symbols import SymbolResolver


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ioctl-analyzer",
        description="Statically recover Windows kernel driver IOCTL dispatch handlers and CFGs.",
    )
    parser.add_argument("driver", type=Path, help="Path to a Windows kernel driver .sys/.dll PE image")
    parser.add_argument("-o", "--output", type=Path, help="Write JSON analysis output to this path")
    parser.add_argument("--dot-dir", type=Path, help="Write Graphviz DOT CFG files to this directory")
    parser.add_argument("--graphml-dir", type=Path, help="Write GraphML CFG files to this directory")
    parser.add_argument("--symbols", type=Path, action="append", default=[], help="Load JSON/CSV/text symbol map. May be supplied more than once")
    parser.add_argument("--pdb", type=Path, action="append", default=[], help="Load symbols from a PDB via llvm-pdbutil. May be supplied more than once")
    parser.add_argument("--no-cfg", action="store_true", help="Skip handler CFG construction for faster triage")
    parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON output")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        image = PEImage(args.driver)
        symbols = SymbolResolver.from_paths(image.image_base, symbol_paths=args.symbols, pdb_paths=args.pdb)
        result = DriverAnalyzer(image, symbols=symbols).analyze(include_cfg=not args.no_cfg)
        payload = result.to_json()
        if args.dot_dir:
            if args.no_cfg:
                payload.setdefault("warnings", []).append("--dot-dir requested with --no-cfg; no DOT files were written.")
            else:
                written = write_analysis_dot(result, args.dot_dir)
                payload["dot_files"] = [str(path) for path in written]
        if args.graphml_dir:
            if args.no_cfg:
                payload.setdefault("warnings", []).append("--graphml-dir requested with --no-cfg; no GraphML files were written.")
            else:
                written = write_analysis_graphml(result, args.graphml_dir)
                payload["graphml_files"] = [str(path) for path in written]
    except Exception as exc:  # noqa: BLE001 - CLI should return a useful error instead of a traceback by default.
        print(f"error: {exc}", file=sys.stderr)
        return 2

    text = json.dumps(payload, indent=2 if args.pretty else None, sort_keys=True)
    if args.output:
        args.output.write_text(text + "\n", encoding="utf-8")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
