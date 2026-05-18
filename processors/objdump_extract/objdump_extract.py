from __future__ import annotations

import json
import logging
import re
import struct
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from deepzero.engine.stage import (
    MapProcessor,
    ProcessorContext,
    ProcessorEntry,
    ProcessorResult,
)

log = logging.getLogger("deepzero.processor.objdump_extract")

# Optional Capstone import — native disassembly, faster + cross-platform + jump table support
try:
    import capstone as _capstone
    _HAS_CAPSTONE = True
except ImportError:
    _HAS_CAPSTONE = False


# -- expanded IOCTL device type ranges (upper 16 bits) --
# These cover the most common BYOVD-relevant device types.
# Format: "0xNNNN" matches any IOCTL where (code >> 16) == 0xNNNN
DEFAULT_IOCTL_RANGES = [
    # FILE_DEVICE_UNKNOWN (0x22) — most common BYOVD range
    "0x22",
    # Common vendor ranges
    "0x8000",   # METHOD_BUFFERED, high function numbers
    "0x8001",   # METHOD_IN_DIRECT
    "0x8002",   # METHOD_OUT_DIRECT
    "0x8003",   # METHOD_NEITHER
    "0x9C40",   # AMD / ATI vendor range
    "0x7000",   # Intel vendor range
    "0x7300",   # Intel MEI
    "0x8500",   # Common HW vendor
    "0x8888",   # Various
    "0xA000",   # Storage controllers
    "0xB000",   # Display adapters
    # METHOD_NEITHER with FILE_DEVICE_UNKNOWN — classic BYOVD pattern
    "0x2200",   # 0x22 << 2 + METHOD_BUFFERED
    # Direct IOCTL code prefix matches from known vulnerable drivers
    "0x2236",   # Capcom / MSI Afterburner
    "0x2220",   # Various
    "0x2274",   # Various
]


# -- dangerous API string references to scan for --
DANGEROUS_APIS = [
    # Physical memory
    "MmMapIoSpace", "MmUnmapIoSpace", "MmGetPhysicalAddress",
    "MmAllocateContiguousMemory", "MmAllocatePagesForMdl",
    # Memory copy / manipulation
    "MmCopyMemory", "RtlCopyMemory", "memcpy", "memmove",
    "MmProbeAndLockPages", "MmUnlockPages",
    # MSR / IO port
    "__readmsr", "__writemsr", "READ_PORT_UCHAR", "WRITE_PORT_UCHAR",
    "READ_REGISTER_UCHAR", "WRITE_REGISTER_UCHAR",
    # Bus / hardware
    "HalGetBusDataByOffset", "HalSetBusDataByOffset",
    "HalTranslateBusAddress",
    # Process manipulation
    "PsLookupProcessByProcessId", "PsGetCurrentProcess",
    "ZwOpenProcess", "ZwTerminateProcess",
    "ZwAllocateVirtualMemory", "ZwProtectVirtualMemory",
    "ZwWriteVirtualMemory", "ZwReadVirtualMemory",
    "KeStackAttachProcess", "KeUnstackDetachProcess",
    # Token / privilege
    "PsReferencePrimaryToken", "SeSinglePrivilegeCheck",
    # Object manager
    "ObOpenObjectByPointer", "ObRegisterCallbacks",
    # Section / view mapping
    "ZwMapViewOfSection", "ZwOpenSection", "ZwCreateSection",
    # Driver loading
    "ZwLoadDriver", "ZwSetSystemInformation",
    # Device / symlink creation
    "IoCreateDevice", "IoCreateDeviceSecure", "IoCreateSymbolicLink",
    # Callbacks (rootkit indicators)
    "PsSetCreateProcessNotifyRoutine", "PsSetLoadImageNotifyRoutine",
    "CmRegisterCallback",
    # WDF
    "WdfDeviceCreate", "WdfDeviceCreateSymbolicLink",
    "EvtIoDeviceControl", "EvtIoInternalDeviceControl",
]

# IOCTL indicator APIs (confirming driver exposes IOCTL surface)
IOCTL_INDICATOR_APIS = {
    "IoCreateDevice", "IoCreateDeviceSecure", "IoCreateSymbolicLink",
    "IoCompleteRequest", "IofCompleteRequest",
    "WdfDeviceCreate", "WdfDeviceCreateSymbolicLink",
    "WdfIoQueueCreate", "WdfRequestComplete",
}


class ObjdumpExtract(MapProcessor):
    description = (
        "fast IOCTL code + device path extraction from kernel drivers "
        "using objdump and strings with multi-pattern detection "
        "(no decompiler needed, ~2s per driver). "
        "v2.0: filtering, sub/mov patterns, .rdata scan, jump table detection"
    )
    version = "3.0"

    @dataclass
    class Config:
        # -- extraction controls --
        max_ioctl_codes: int = 50
        extract_device_paths: bool = True
        extract_section_info: bool = True
        extract_dangerous_refs: bool = True
        extract_rdata_scan: bool = True

        # -- custom IOCTL ranges (overrides defaults) --
        ioctl_ranges: list[str] | None = None

        # -- priority scoring weights --
        score_per_ioctl: float = 0.5
        score_per_device_path: float = 1.0
        score_per_dangerous_ref: float = 1.5
        score_max: float = 10.0

        # -- FILTERING (new in v2.0) --
        # return filter() when criteria not met. all default to 0 (no filter)
        min_ioctl_codes: int = 0
        min_device_paths: int = 0
        require_device_path: bool = False      # must have at least one \Device\ path
        min_text_section_size: int = 0         # minimum .text section size in bytes
        require_dangerous_refs: bool = False   # must have at least one dangerous API ref

    def should_skip(self, ctx: ProcessorContext, entry: ProcessorEntry) -> str | None:
        if entry.sample_dir is None:
            return None
        cached = entry.sample_dir / "fast_extract" / "objdump_result.json"
        if cached.exists():
            try:
                json.loads(cached.read_text(encoding="utf-8"))
                return "fast extraction already cached"
            except (json.JSONDecodeError, OSError):
                pass
        return None

    def process(self, ctx: ProcessorContext, entry: ProcessorEntry) -> ProcessorResult:
        if entry.sample_dir is None:
            return ProcessorResult.fail("sample_dir not set")

        log.info("extracting %s", entry.filename)
        start_time = time.monotonic()

        output_dir = entry.sample_dir / "fast_extract"
        output_dir.mkdir(parents=True, exist_ok=True)
        result_path = output_dir / "objdump_result.json"

        # Copy binary to Linux-native tmp dir to avoid WSL DrvFs I/O bottleneck
        import shutil
        import tempfile
        tmp_dir = Path(tempfile.mkdtemp(prefix="objdump_"))
        try:
            tmp_binary = tmp_dir / entry.source_path.name
            shutil.copy2(entry.source_path, tmp_binary)

            data: dict[str, Any] = {}

            # 1. IOCTL codes — multi-pattern extraction
            ranges = self.config.ioctl_ranges or DEFAULT_IOCTL_RANGES
            ioctl_codes = self._extract_ioctl_codes_multi(tmp_binary, ranges)
            data["ioctl_codes"] = ioctl_codes
            data["ioctl_count"] = len(ioctl_codes)

            # 2. Device paths — ASCII + Unicode
            if self.config.extract_device_paths:
                device_paths = self._extract_device_paths_combined(tmp_binary)
                data["device_paths"] = device_paths
                data["device_path_count"] = len(device_paths)

            # 3. Section info
            if self.config.extract_section_info:
                section_info = self._extract_section_info(tmp_binary)
                data.update(section_info)

            # 4. Dangerous API string refs + import cross-reference
            if self.config.extract_dangerous_refs:
                dangerous_refs = self._extract_dangerous_refs(tmp_binary)
                # Also cross-reference with pe_ingest imports (catches API symbols)
                import_refs = self._extract_dangerous_refs_from_history(entry)
                # Merge, deduplicate
                all_refs = sorted(set(dangerous_refs) | set(import_refs))
                data["dangerous_string_refs"] = all_refs
                data["dangerous_ref_count"] = len(all_refs)
                data["dangerous_refs_strings"] = len(dangerous_refs)
                data["dangerous_refs_imports"] = len(import_refs)

            # 5. Priority score
            data["priority_score"] = self._compute_priority(data)

            # 6. Build IOCTL summary for quick scanning
            data["ioctl_summary"] = self._build_ioctl_summary(ioctl_codes)

            result_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)

        elapsed = time.monotonic() - start_time
        log.info(
            "extracted %s (%.1fs) ioctl=%d paths=%d refs=%d score=%.1f",
            entry.filename,
            elapsed,
            data.get("ioctl_count", 0),
            data.get("device_path_count", 0),
            data.get("dangerous_ref_count", 0),
            data.get("priority_score", 0),
        )

        # -- FILTERING logic (new in v2.0) --
        filter_reason = self._check_filters(data)
        if filter_reason:
            return ProcessorResult.filter(filter_reason, data=data)

        artifacts = {"objdump_result": "fast_extract/objdump_result.json"}
        return ProcessorResult.ok(data=data, artifacts=artifacts)

    # ── filtering ──────────────────────────────────────────────

    def _check_filters(self, data: dict[str, Any]) -> str | None:
        """Check all configured filter criteria. Returns reason string if filtered."""
        cfg = self.config

        if cfg.min_ioctl_codes > 0:
            count = data.get("ioctl_count", 0)
            if count < cfg.min_ioctl_codes:
                return f"ioctl_count={count} < min {cfg.min_ioctl_codes}"

        if cfg.min_device_paths > 0:
            count = data.get("device_path_count", 0)
            if count < cfg.min_device_paths:
                return f"device_path_count={count} < min {cfg.min_device_paths}"

        if cfg.require_device_path:
            paths = data.get("device_paths", [])
            has_device = any("\\Device\\" in p for p in paths)
            if not has_device:
                return "no \\Device\\ path found"

        if cfg.min_text_section_size > 0:
            size = data.get("text_section_size", 0)
            if size < cfg.min_text_section_size:
                return f"text_section_size={size} < min {cfg.min_text_section_size}"

        if cfg.require_dangerous_refs:
            count = data.get("dangerous_ref_count", 0)
            if count == 0:
                return "no dangerous API string refs found"

        return None

    # ── priority scoring ───────────────────────────────────────

    def _compute_priority(self, data: dict[str, Any]) -> float:
        score = 0.0
        score += data.get("ioctl_count", 0) * self.config.score_per_ioctl
        score += data.get("device_path_count", 0) * self.config.score_per_device_path
        score += data.get("dangerous_ref_count", 0) * self.config.score_per_dangerous_ref

        # Bonus for METHOD_NEITHER IOCTLs (highest risk)
        ioctl_codes = data.get("ioctl_codes", [])
        method_neither_count = sum(
            1 for c in ioctl_codes if (c.get("value", 0) & 0x3) == 3
        )
        score += method_neither_count * 1.0

        return min(self.config.score_max, score)

    def _build_ioctl_summary(self, codes: list[dict[str, Any]]) -> dict[str, Any]:
        """Build a summary of IOCTL codes by device type and method."""
        methods = {0: "METHOD_BUFFERED", 1: "METHOD_IN_DIRECT",
                   2: "METHOD_OUT_DIRECT", 3: "METHOD_NEITHER"}
        summary: dict[str, Any] = {"unique_device_types": [], "by_method": {}}

        device_types: set[int] = set()
        for c in codes:
            val = c.get("value", 0)
            dt = (val >> 16) & 0xFFFF
            method = val & 0x3
            device_types.add(dt)
            method_name = methods.get(method, f"UNKNOWN_{method}")
            summary["by_method"][method_name] = summary["by_method"].get(method_name, 0) + 1

        summary["unique_device_types"] = sorted(device_types)
        summary["total"] = len(codes)
        return summary

    # ── multi-pattern IOCTL extraction ─────────────────────────

    def _extract_ioctl_codes_multi(
        self, binary: Path, ranges: list[str]
    ) -> list[dict[str, Any]]:
        """Extract IOCTL codes using multiple detection strategies.

        Strategy 1 (preferred): Capstone native disassembly + instruction-level
          analysis with jump table reconstruction (if capstone installed).
        Strategy 2 (fallback): objdump disassembly + regex patterns.
        Strategy 3: .rdata/.text hex dump scan for CTL_CODE dword constants.
        """
        codes: list[dict[str, Any]] = []
        seen: set[int] = set()

        # -- strategy 1: Capstone native disassembly (preferred) --
        if _HAS_CAPSTONE:
            capstone_codes = self._extract_ioctl_codes_capstone(binary, ranges)
            for code_val in capstone_codes:
                if code_val not in seen and len(codes) < self.config.max_ioctl_codes:
                    seen.add(code_val)
                    codes.append(self._make_ioctl_entry("capstone", code_val))
            if codes:
                log.debug("capstone found %d IOCTL codes", len(codes))

        # -- strategy 2: objdump regex (fallback or supplement) --
        if not _HAS_CAPSTONE or len(codes) < self.config.max_ioctl_codes:
            text_disasm = self._run_objdump_disasm(binary)
            objdump_codes = self._extract_ioctl_codes_objdump(text_disasm, ranges)
            for code_val in objdump_codes:
                if code_val not in seen and len(codes) < self.config.max_ioctl_codes:
                    seen.add(code_val)
                    codes.append(self._make_ioctl_entry("objdump", code_val))

        # -- strategy 3: rdata hex scan (always runs) --
        if self.config.extract_rdata_scan and len(codes) < self.config.max_ioctl_codes:
            rdata_hex = self._run_objdump_hexdump(binary)
            rdata_codes = self._scan_rdata_for_ioctls(rdata_hex, ranges)
            for code_val in rdata_codes:
                if code_val not in seen and len(codes) < self.config.max_ioctl_codes:
                    seen.add(code_val)
                    codes.append(self._make_ioctl_entry("rdata", code_val))

        return codes

    # ── Capstone-based extraction (v3.0) ────────────────────────

    def _extract_ioctl_codes_capstone(
        self, binary: Path, ranges: list[str]
    ) -> list[int]:
        """Extract IOCTL codes using Capstone native disassembly.

        Capstone provides instruction-level analysis without subprocess overhead.
        Enables: jump table reconstruction, bitfield pattern detection,
        cross-platform support (Windows/Linux/macOS).

        Architecture auto-detected from PE header.
        """
        codes: list[int] = []
        seen: set[int] = set()

        # Read PE sections to find .text
        sections = self._read_pe_sections(binary)
        text_section = sections.get(".text")
        if not text_section:
            return codes

        text_data = text_section["data"]
        text_rva = text_section["virtual_address"]
        if not text_data:
            return codes

        # Detect architecture from PE header
        arch = self._detect_pe_arch(binary)
        if arch is None:
            return codes

        cs_mode = arch["mode"]
        md = _capstone.Cs(_capstone.CS_ARCH_X86, cs_mode)
        md.detail = True
        md.syntax = _capstone.CS_OPT_SYNTAX_INTEL

        # Track jump table candidates: {table_rva: [case_values]}
        jump_tables: dict[int, list[int]] = {}
        # Track bitfield patterns spotted
        bitfield_detected = False

        try:
            for insn in md.disasm(text_data, text_rva):
                addr = insn.address
                mnemonic = insn.mnemonic
                op_str = insn.op_str

                # -- Immediate extraction patterns --
                if mnemonic == "cmp":
                    val = self._capstone_extract_imm(insn)
                    if val is not None and self._is_valid_ioctl(val, ranges):
                        if val not in seen:
                            seen.add(val)
                            codes.append(val)

                elif mnemonic == "sub":
                    val = self._capstone_extract_imm(insn)
                    if val is not None and self._is_valid_ioctl(val, ranges):
                        if val not in seen:
                            seen.add(val)
                            codes.append(val)

                elif mnemonic == "mov":
                    # Only capture mov into register (not memory)
                    if self._capstone_is_reg_dst(insn):
                        val = self._capstone_extract_imm(insn)
                        if val is not None and self._is_valid_ioctl(val, ranges):
                            if val not in seen:
                                seen.add(val)
                                codes.append(val)

                # -- Jump table detection --
                # Pattern: lea reg, [base + index*scale] followed by jmp [reg*4/8]
                elif mnemonic == "lea":
                    table_addr = self._capstone_detect_jump_table(insn)
                    if table_addr is not None:
                        jump_tables[table_addr] = []  # will be resolved below

                # -- Bitfield decoding detection --
                elif mnemonic == "shr":
                    # shr reg, 2/14/16 — IOCTL field extraction
                    val = self._capstone_extract_imm(insn)
                    if val in (2, 14, 16):
                        bitfield_detected = True
                elif mnemonic == "and":
                    # and reg, 0xFFF/0x3/0xFFFF — field masking
                    val = self._capstone_extract_imm(insn)
                    if val in (0x3, 0xFFF, 0xFFFF, 0xFFF000, 0xFFFF0000):
                        bitfield_detected = True

                if len(codes) >= self.config.max_ioctl_codes:
                    break

        except Exception as e:
            log.debug("capstone disassembly error: %s", e)

        # -- Resolve jump tables --
        if jump_tables and len(codes) < self.config.max_ioctl_codes:
            for table_rva, _ in list(jump_tables.items()):
                table_codes = self._resolve_jump_table(
                    binary, table_rva, text_rva, len(text_data), ranges
                )
                for val in table_codes:
                    if val not in seen and len(codes) < self.config.max_ioctl_codes:
                        seen.add(val)
                        codes.append(val)

        return codes

    def _capstone_extract_imm(self, insn) -> int | None:
        """Extract immediate value from a Capstone instruction."""
        if insn.operands:
            for op in insn.operands:
                if op.type == _capstone.x86.X86_OP_IMM:
                    return op.imm
        return None

    def _capstone_is_reg_dst(self, insn) -> bool:
        """Check if the destination operand of mov is a register (not memory)."""
        if insn.operands and len(insn.operands) >= 2:
            return insn.operands[0].type == _capstone.x86.X86_OP_REG
        return False

    def _capstone_detect_jump_table(self, insn) -> int | None:
        """Detect jump table in LEA instruction.

        Pattern: lea reg, [base + index*scale]
        Used before indirect jump: jmp [reg*4 + table]

        Returns the table address (RVA) if detected.
        """
        if insn.operands and len(insn.operands) >= 2:
            mem = insn.operands[1]
            if mem.type == _capstone.x86.X86_OP_MEM:
                # Check if it has index*scale (jump table indicator)
                if mem.mem.index != 0 and mem.mem.scale in (4, 8):
                    return mem.mem.disp  # table base address
        return None

    def _resolve_jump_table(
        self, binary: Path, table_rva: int, text_rva: int,
        text_size: int, ranges: list[str]
    ) -> list[int]:
        """Read dword entries from a jump table in the binary.

        Jump tables are arrays of case values in .text or .rdata.
        Each entry is a 32-bit value — could be a code address (not IOCTL)
        or an IOCTL constant. We filter to only IOCTL-like values.
        """
        codes: list[int] = []
        seen: set[int] = set()

        try:
            raw = binary.read_bytes()
        except OSError:
            return codes

        # Convert RVA to file offset (simplistic — assumes .text starts at file offset)
        # For PE files, we need proper RVA→offset conversion
        sections = self._read_pe_sections(binary)
        text_sec = sections.get(".text")
        if not text_sec:
            return codes

        text_file_offset = text_sec.get("file_offset", 0)
        text_va = text_sec.get("virtual_address", 0)

        # The jump table RVA is relative to image base.
        # For simplicity, assume table is in .text or nearby.
        # Calculate file offset from RVA
        table_file_offset = table_rva - text_va + text_file_offset

        if table_file_offset < 0 or table_file_offset + 4 > len(raw):
            return codes

        # Read up to 256 dword entries (generous max for switch tables)
        max_entries = min(256, (len(raw) - table_file_offset) // 4)
        for i in range(max_entries):
            offset = table_file_offset + i * 4
            if offset + 4 > len(raw):
                break
            try:
                val = struct.unpack("<I", raw[offset:offset + 4])[0]
            except struct.error:
                break

            # Skip code addresses (targets within .text)
            if text_va <= val < text_va + text_size:
                continue

            if self._is_valid_ioctl(val, ranges) and val not in seen:
                seen.add(val)
                codes.append(val)

        return codes

    def _read_pe_sections(self, binary: Path) -> dict[str, dict[str, Any]]:
        """Read PE section headers and return section data.

        Returns: {section_name: {data, virtual_address, file_offset, size}}
        """
        sections: dict[str, dict[str, Any]] = {}
        try:
            raw = binary.read_bytes()
        except OSError:
            return sections

        if len(raw) < 64 or raw[:2] != b"MZ":
            return sections

        try:
            pe_offset = struct.unpack("<I", raw[0x3C:0x40])[0]
        except struct.error:
            return sections

        if pe_offset + 4 > len(raw) or raw[pe_offset:pe_offset + 4] != b"PE\0\0":
            return sections

        # COFF header
        coff = pe_offset + 4
        if coff + 20 > len(raw):
            return sections

        num_sections = struct.unpack("<H", raw[coff + 2:coff + 4])[0]
        opt_header_size = struct.unpack("<H", raw[coff + 16:coff + 18])[0]

        # Section headers start after optional header
        section_start = coff + 20 + opt_header_size

        for i in range(num_sections):
            sec_off = section_start + i * 40
            if sec_off + 40 > len(raw):
                break

            name_raw = raw[sec_off:sec_off + 8]
            name = name_raw.rstrip(b"\0").decode("ascii", errors="replace")
            virtual_size = struct.unpack("<I", raw[sec_off + 8:sec_off + 12])[0]
            virtual_addr = struct.unpack("<I", raw[sec_off + 12:sec_off + 16])[0]
            raw_size = struct.unpack("<I", raw[sec_off + 16:sec_off + 20])[0]
            raw_offset = struct.unpack("<I", raw[sec_off + 20:sec_off + 24])[0]

            data_size = min(raw_size, virtual_size) if raw_size else virtual_size
            if raw_offset > 0 and raw_offset + data_size <= len(raw):
                section_data = raw[raw_offset:raw_offset + data_size]
            else:
                section_data = b""

            sections[name] = {
                "data": section_data,
                "virtual_address": virtual_addr,
                "file_offset": raw_offset,
                "size": data_size,
            }

        return sections

    def _detect_pe_arch(self, binary: Path) -> dict[str, Any] | None:
        """Detect PE architecture from the optional header magic."""
        try:
            raw = binary.read_bytes()
        except OSError:
            return None

        if len(raw) < 64 or raw[:2] != b"MZ":
            return None

        try:
            pe_offset = struct.unpack("<I", raw[0x3C:0x40])[0]
        except struct.error:
            return None

        opt_header = pe_offset + 24  # PE sig(4) + COFF(20)
        if opt_header + 2 > len(raw):
            return None

        magic = struct.unpack("<H", raw[opt_header:opt_header + 2])[0]
        if magic == 0x10B:  # PE32
            return {"arch": _capstone.CS_ARCH_X86, "mode": _capstone.CS_MODE_32}
        elif magic == 0x20B:  # PE32+
            return {"arch": _capstone.CS_ARCH_X86, "mode": _capstone.CS_MODE_64}

        return None

    # ── objdump-based extraction (fallback) ─────────────────────

    def _extract_ioctl_codes_objdump(
        self, text_disasm: str, ranges: list[str]
    ) -> list[int]:
        """Extract IOCTL codes from objdump disassembly using regex patterns.

        Matches: cmp/sub/mov with immediate values in IOCTL ranges.
        """
        codes: list[int] = []
        seen: set[int] = set()

        cmp_patterns = [
            re.compile(
                r'\s+([0-9a-f]+):\s+\S+\s+cmp\s+\S+,\s*\$?(0x[0-9a-f]{6,8})\b',
                re.IGNORECASE,
            ),
            re.compile(
                r'\s+([0-9a-f]+):\s+\S+\s+cmp\s+\S+,\s*\$?(-0x[0-9a-f]{1,8})\b',
                re.IGNORECASE,
            ),
        ]
        sub_patterns = [
            re.compile(
                r'\s+([0-9a-f]+):\s+\S+\s+sub\s+\S+,\s*\$?(0x[0-9a-f]{6,8})\b',
                re.IGNORECASE,
            ),
        ]
        mov_patterns = [
            re.compile(
                r'\s+([0-9a-f]+):\s+\S+\s+mov\s+(?:e?[abcd]x|r\d+d?|e?[sd]i|[er]8d|[er]9d|[er]1[0-5]d),\s*\$?(0x[0-9a-f]{6,8})\b',
                re.IGNORECASE,
            ),
        ]

        for line in text_disasm.splitlines():
            for pat in cmp_patterns:
                m = pat.search(line)
                if m:
                    code_val = self._parse_hex_immediate(m.group(2))
                    if code_val is not None and self._is_valid_ioctl(code_val, ranges):
                        if code_val not in seen:
                            seen.add(code_val)
                            codes.append(code_val)
                    break

            for pat in sub_patterns:
                m = pat.search(line)
                if m:
                    code_val = self._parse_hex_immediate(m.group(2))
                    if code_val is not None and self._is_valid_ioctl(code_val, ranges):
                        if code_val not in seen:
                            seen.add(code_val)
                            codes.append(code_val)
                    break

            for pat in mov_patterns:
                m = pat.search(line)
                if m:
                    code_val = self._parse_hex_immediate(m.group(2))
                    if code_val is not None and self._is_valid_ioctl(code_val, ranges):
                        if code_val not in seen:
                            seen.add(code_val)
                            codes.append(code_val)
                    break

            if len(codes) >= self.config.max_ioctl_codes:
                break

        return codes

    def _scan_rdata_for_ioctls(
        self, hexdump: str, ranges: list[str]
    ) -> list[int]:
        """Scan .rdata/.text hex dumps for dword values matching IOCTL ranges.

        objdump -s -j .rdata -j .text output looks like:
         4a00 01020304 05060708 090a0b0c 0d0e0f10  ................
        We extract all 32-bit little-endian dwords and check against ranges.
        """
        codes: list[int] = []
        seen: set[int] = set()

        # Extract hex bytes from objdump -s output
        hex_pattern = re.compile(r'^\s*[0-9a-f]+\s+((?:[0-9a-f]{8}\s+)+)', re.IGNORECASE)

        for line in hexdump.splitlines():
            m = hex_pattern.search(line)
            if not m:
                continue

            hex_str = m.group(1).replace(" ", "")
            # Parse each 8-char (4-byte) chunk as little-endian dword
            for i in range(0, len(hex_str) - 6, 8):
                chunk = hex_str[i:i + 8]
                if len(chunk) < 8:
                    continue
                try:
                    # Parse as little-endian uint32
                    dword = struct.unpack("<I", bytes.fromhex(chunk))[0]
                except (ValueError, struct.error):
                    continue

                if dword in seen:
                    continue
                if not self._is_valid_ioctl(dword, ranges):
                    continue

                seen.add(dword)
                codes.append(dword)

        return codes

    def _parse_hex_immediate(self, s: str) -> int | None:
        """Parse a hex immediate value. Handles signed negatives like -0x222000."""
        s = s.strip().lower()
        negative = s.startswith("-")
        if negative:
            s = s[1:]
        if s.startswith("0x"):
            s = s[2:]
        try:
            val = int(s, 16)
            if negative:
                # Convert signed 32-bit negative to unsigned
                val = val & 0xFFFFFFFF if val <= 0x80000000 else (-val) & 0xFFFFFFFF
            return val
        except ValueError:
            return None

    def _is_valid_ioctl(self, value: int, ranges: list[str]) -> bool:
        """Check if a value looks like a valid IOCTL code.

        Sanity checks only — does NOT require matching known device type ranges.
        Known ranges are used for prioritization/classification, not rejection.
        This prevents filtering drivers with obscure/custom device types.
        """
        # Sanity bounds — must be a 32-bit value with plausible upper bits
        if value < 0x1000 or value > 0xFFFFFFFF:
            return False

        # Filter obvious garbage: 0x00000000, 0xFFFFFFFF, 0xCCCCCCCC, 0x90909090
        low_word = value & 0xFFFF
        if low_word in (0x0000, 0xFFFF, 0xCCCC, 0x9090, 0x0F0F):
            # Allow 0x0000 low word only if upper 16 bits are non-zero (valid device type)
            if low_word == 0x0000 and (value >> 16) == 0:
                return False
            if low_word not in (0x0000,):
                return False

        # All-zeros, all-ones, common padding patterns
        if value in (0x00000000, 0xFFFFFFFF, 0xCCCCCCCC, 0x90909090, 0x0F0F0F0F):
            return False

        # Passed all sanity checks — accept even if device type is not in known ranges
        return True

    def _match_any_range(self, value: int, ranges: list[str]) -> bool:
        for r in ranges:
            if self._match_hex_range(value, r):
                return True
        return False

    @staticmethod
    def _match_hex_range(value: int, pattern: str) -> bool:
        """Check if hex value falls within a hex prefix pattern.

        "0x22" matches 0x220000-0x22FFFF (device type in upper 16 bits)
        "0x8000" matches 0x80000000-0x8000FFFF
        "0x2236" matches 0x22360000-0x2236FFFF
        """
        p = pattern.lower().replace("0x", "")
        sig_len = len(p)
        if sig_len == 0:
            return False
        shift = max(0, (8 - sig_len)) * 4
        shifted = value >> shift
        try:
            expected = int(p, 16)
        except ValueError:
            return False
        return shifted == expected

    def _make_ioctl_entry(self, offset: str, code_val: int) -> dict[str, Any]:
        """Build a rich IOCTL code entry with decoded fields."""
        device_type = (code_val >> 16) & 0xFFFF
        return {
            "offset": offset,
            "code": f"0x{code_val:08X}",
            "value": code_val,
            "device_type": device_type,
            "function": (code_val >> 2) & 0xFFF,
            "method": code_val & 0x3,
            "access": (code_val >> 14) & 0x3,
            "known_range": self._match_any_range(code_val, DEFAULT_IOCTL_RANGES),
        }

    # ── subprocess wrappers ────────────────────────────────────

    def _run_objdump_disasm(self, binary: Path) -> str:
        """Run objdump -d -j .text and return stdout."""
        try:
            result = subprocess.run(
                ["objdump", "-d", "-j", ".text", str(binary)],
                capture_output=True, timeout=30,
            )
        except (subprocess.TimeoutExpired, OSError, FileNotFoundError):
            return ""
        if result.returncode != 0:
            return ""
        return result.stdout.decode("utf-8", errors="replace")

    def _run_objdump_hexdump(self, binary: Path) -> str:
        """Run objdump -s -j .rdata -j .text to get hex dumps of data sections."""
        try:
            result = subprocess.run(
                ["objdump", "-s", "-j", ".rdata", "-j", ".text", str(binary)],
                capture_output=True, timeout=15,
            )
        except (subprocess.TimeoutExpired, OSError, FileNotFoundError):
            return ""
        if result.returncode != 0:
            return ""
        return result.stdout.decode("utf-8", errors="replace")

    def _run_strings(self, binary: Path, encoding_flag: str, timeout: int = 10) -> str:
        """Run `strings <flag> <binary>` and return stdout."""
        try:
            result = subprocess.run(
                ["strings", encoding_flag, str(binary)],
                capture_output=True, timeout=timeout,
            )
        except (subprocess.TimeoutExpired, OSError, FileNotFoundError):
            return ""
        if result.returncode != 0:
            return ""
        return result.stdout.decode("utf-8", errors="replace")

    # ── device path extraction ─────────────────────────────────

    def _extract_device_paths_combined(self, binary: Path) -> list[str]:
        """Extract device paths from both Unicode (UTF-16LE) and ASCII strings."""
        paths: list[str] = []
        seen: set[str] = set()

        # Unicode strings (most device paths are UTF-16LE)
        unicode_out = self._run_strings(binary, "-el", timeout=10)
        for p in self._find_device_paths(unicode_out):
            if p not in seen:
                seen.add(p)
                paths.append(p)

        # ASCII strings (some drivers use narrow strings)
        ascii_out = self._run_strings(binary, "", timeout=10)
        for p in self._find_device_paths(ascii_out):
            if p not in seen:
                seen.add(p)
                paths.append(p)

        return paths

    @staticmethod
    def _find_device_paths(text: str) -> list[str]:
        """Find Windows NT device path patterns in text."""
        device_pattern = re.compile(
            r'(\\\\Device\\\\[^\s\x00-\x1f<>"|]+|'
            r'\\\\DosDevices\\\\[^\s\x00-\x1f<>"|]+|'
            r'\\\\\?\?\\\\[^\s\x00-\x1f<>"|]+|'
            r'\\\\.\\\\[^\s\x00-\x1f<>"|]+)',
            re.IGNORECASE,
        )
        return [m.group(1).strip() for m in device_pattern.finditer(text)]

    # ── section info ───────────────────────────────────────────

    def _extract_section_info(self, binary: Path) -> dict[str, Any]:
        """Fast section info via objdump -h."""
        info: dict[str, Any] = {
            "has_executable_data": False,
            "text_section_size": 0,
            "section_count": 0,
            "sections": [],
        }
        try:
            result = subprocess.run(
                ["objdump", "-h", str(binary)],
                capture_output=True, timeout=10,
            )
        except (subprocess.TimeoutExpired, OSError, FileNotFoundError):
            return info

        if result.returncode != 0:
            return info

        stdout = result.stdout.decode("utf-8", errors="replace")

        for line in stdout.splitlines():
            parts = line.split()
            if len(parts) < 6:
                continue
            try:
                idx = int(parts[0]) if parts[0].isdigit() else -1
            except (ValueError, IndexError):
                continue
            if idx < 0:
                continue

            name = parts[1] if len(parts) > 1 else ""
            flags = parts[-1] if len(parts) > 5 else ""

            try:
                size = int(parts[2], 16)
            except (ValueError, IndexError):
                size = 0

            info["sections"].append({"name": name, "size": size, "flags": flags})

            if name == ".text":
                info["text_section_size"] = size
            if "CODE" in flags and "DATA" in flags:
                info["has_executable_data"] = True

        info["section_count"] = len(info["sections"])
        return info

    # ── dangerous API refs ─────────────────────────────────────

    def _extract_dangerous_refs(self, binary: Path) -> list[str]:
        """Check if dangerous API names appear as strings in the binary,
        OR are present in upstream pe_ingest import data.

        String scan catches debug builds with error-logging macros.
        Import cross-reference catches all drivers (API names in import table
        are not C strings, but pe_ingest already parsed them).
        """
        found: list[str] = []
        found_lower: set[str] = set()

        # Strategy 1: string scan (debug builds, error messages)
        ascii_out = self._run_strings(binary, "", timeout=10)
        text_lower = ascii_out.lower()

        for api in DANGEROUS_APIS:
            if api.lower() in text_lower:
                found.append(api)
                found_lower.add(api.lower())

        # Unicode strings (some debug drivers)
        unicode_out = self._run_strings(binary, "-el", timeout=10)
        unicode_lower = unicode_out.lower()

        for api in DANGEROUS_APIS:
            if api.lower() not in found_lower and api.lower() in unicode_lower:
                found.append(api)
                found_lower.add(api.lower())

        return sorted(found)

    def _extract_dangerous_refs_from_history(
        self, entry: ProcessorEntry
    ) -> list[str]:
        """Cross-reference with pe_ingest's dangerous_imports from upstream data.

        This catches APIs that are imported symbols (not C strings) and
        would be missed by the string scan. Called during process() to
        enrich the dangerous refs list.
        """
        discover_imports = entry.upstream_data("discover", "dangerous_imports", [])
        if not discover_imports:
            return []

        # Only return APIs that are in our DANGEROUS_APIS list
        dangerous_set = {api.lower() for api in DANGEROUS_APIS}
        return sorted(
            imp for imp in discover_imports
            if imp.lower() in dangerous_set
        )
