# IOCTL Static Analyzer

`ioctl-static-analyzer` is a defensive static-analysis CLI for Windows kernel driver triage. It parses a PE driver image, disassembles executable sections with Capstone, locates the driver entry point, identifies common references to `IoCreateDevice` and `IoCreateSymbolicLink`, searches `DriverEntry` for `DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL]` assignments, recovers likely IOCTL switch cases, and exports per-handler control-flow graphs.

The tool is designed for manual review workflows. It reports discovered dispatch metadata and CFG structure, but it does not generate exploit payloads or vulnerability-specific exploitation steps.

## Install

```bash
python -m venv .venv
. .venv/bin/activate
pip install -e ".[dev]"
```

## Usage

```bash
ioctl-analyzer path/to/driver.sys --pretty -o analysis.json
```

To also emit Graphviz DOT CFG files:

```bash
ioctl-analyzer path/to/driver.sys --pretty -o analysis.json --dot-dir cfg-dot
dot -Tsvg cfg-dot/dispatch_140001000.dot -o dispatch.svg
```

To emit GraphML files for graph tooling:

```bash
ioctl-analyzer path/to/driver.sys --pretty -o analysis.json --graphml-dir cfg-graphml
```

To annotate functions with symbols:

```bash
ioctl-analyzer path/to/driver.sys --pretty -o analysis.json --symbols symbols.json
ioctl-analyzer path/to/driver.sys --pretty -o analysis.json --pdb driver.pdb
```

`--symbols` accepts JSON, CSV, or simple text maps with `address name` pairs. `--pdb` uses `llvm-pdbutil dump -symbols`, so LLVM must be installed and available on `PATH`.

For faster triage without per-handler CFGs:

```bash
ioctl-analyzer path/to/driver.sys --no-cfg --pretty
```

## Output shape

The JSON output includes:

- `entry_point_va`: PE entry point virtual address.
- `imports`: imported symbols and IAT virtual addresses.
- `io_create_device_refs`: call sites that reference the `IoCreateDevice` import.
- `io_create_symbolic_link_refs`: call sites that reference the `IoCreateSymbolicLink` import.
- `io_create_device_wrapper_refs` and `io_create_symbolic_link_wrapper_refs`: calls from discovered initialization routines into local wrappers that call those imports.
- `device_control_dispatches`: recovered `IRP_MJ_DEVICE_CONTROL` routines.
- `ioctl_cases`: likely IOCTL code to handler virtual-address mappings.
- `routine_symbol` and `handler_symbol`: names from supplied symbol maps or PDBs when available.
- `cfg`: basic blocks and edges for dispatch routines and handlers.
- `dot_files`: emitted Graphviz DOT paths when `--dot-dir` is supplied.
- `graphml_files`: emitted GraphML paths when `--graphml-dir` is supplied.
- `symbols`: loaded symbol table keyed by virtual address.
- `warnings`: unresolved patterns or analysis limitations.

## Recovery approach

The analyzer uses pragmatic compiler-pattern heuristics:

- Direct or RIP-relative calls through the import-address table for WDM routines.
- x64 and x86 `_DRIVER_OBJECT.MajorFunction` offset patterns.
- Conservative recursive scanning of direct `DriverEntry` helper calls to catch dispatch registration delegated to initialization wrappers.
- Immediate `cmp` plus conditional-branch IOCTL checks.
- CFG-aware fixed-point data-flow tracking from `IoGetCurrentIrpStackLocation` and `_IO_STACK_LOCATION.Parameters.DeviceIoControl.IoControlCode` loads into comparison registers.
- Stack-spill tracking for IOCTL temporaries stored in frame-pointer or stack-pointer-relative local slots.
- Basic absolute/RIP-relative jump-table reads where table entries point into executable PE sections.
- MSVC-style relative jump tables containing signed 32-bit offsets from the table base.
- CTL_CODE field decoding for recovered IOCTL values, including device type, function, method, and access names.
- Symbol annotation from JSON/CSV/text maps and optional `llvm-pdbutil` PDB extraction.
- Import-wrapper detection for local initialization helpers that call `IoCreateDevice` or `IoCreateSymbolicLink`.
- x64 dispatch-registration wrapper recovery when a helper stores an argument register into `DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL]`.

These heuristics intentionally expose confidence levels. Optimized drivers may require follow-up manual analysis, especially if dispatch registration is delegated through helper functions, the import is dynamically resolved, or the switch is lowered into arithmetic/range-normalized forms.

## Development

```bash
pytest -q
```

## Extending

Useful next improvements:

- Expand data-flow tracking to richer alias handling and indirect call target recovery.
- Add richer x86/stdcall wrapper argument recovery.
- Add PDB-assisted symbol naming when symbols are available.
