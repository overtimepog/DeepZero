from __future__ import annotations

import json
import logging
import sys
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

log = logging.getLogger("deepzero.processor.ioctl_static_analyzer")


class IoctlStaticAnalyzer(MapProcessor):
    """Static IOCTL dispatch analysis using data-flow tracking and Capstone.

    Replaces objdump_extract with a proper static analyzer:
    - Data-flow tracking from IoGetCurrentIrpStackLocation → IOCTL compare
    - Jump table recovery (absolute + relative/RIP-relative)
    - cmp/branch IOCTL case recovery with confidence scoring
    - Optional CFG construction per handler
    - No device type range restrictions — any plausible IOCTL code accepted
    """

    description = "static IOCTL dispatch analysis with data-flow tracking"
    version = "4.0"

    @dataclass
    class Config:
        max_ioctl_codes: int = 50
        extract_device_paths: bool = True
        extract_section_info: bool = True
        extract_rdata_scan: bool = True   # kept for compat, not used by ioctl_analyzer
        # Filtering
        min_ioctl_codes: int = 0
        min_device_paths: int = 0
        require_device_path: bool = False
        min_text_section_size: int = 0
        require_dangerous_refs: bool = False
        # Scoring
        score_per_ioctl: float = 0.5
        score_per_device_path: float = 1.0
        score_per_dangerous_ref: float = 1.5
        score_max: float = 10.0
        # ioctl_analyzer options
        include_cfg: bool = False  # CFG construction is expensive, off by default

    def should_skip(self, ctx: ProcessorContext, entry: ProcessorEntry) -> str | None:
        if entry.sample_dir is None:
            return None
        cached = entry.sample_dir / "ioctl_static" / "result.json"
        if cached.exists():
            try:
                json.loads(cached.read_text(encoding="utf-8"))
                return "ioctl static analysis already cached"
            except (json.JSONDecodeError, OSError):
                pass
        return None

    def process(self, ctx: ProcessorContext, entry: ProcessorEntry) -> ProcessorResult:
        if entry.sample_dir is None:
            return ProcessorResult.fail("sample_dir not set")

        log.info("analyzing %s", entry.filename)
        start_time = time.monotonic()

        output_dir = entry.sample_dir / "ioctl_static"
        output_dir.mkdir(parents=True, exist_ok=True)
        result_path = output_dir / "result.json"

        try:
            data = self._run_analysis(entry)
        except Exception as e:
            log.error("analysis failed for %s: %s", entry.filename, e)
            return ProcessorResult.fail(str(e))

        elapsed = time.monotonic() - start_time
        log.info(
            "analyzed %s (%.1fs) ioctl=%d paths=%d refs=%d score=%.1f",
            entry.filename,
            elapsed,
            data.get("ioctl_count", 0),
            data.get("device_path_count", 0),
            data.get("dangerous_ref_count", 0),
            data.get("priority_score", 0),
        )

        # Persist result
        result_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

        # Filtering
        filter_reason = self._check_filters(data)
        if filter_reason:
            return ProcessorResult.filter(filter_reason, data=data)

        return ProcessorResult.ok(
            data=data,
            artifacts={"ioctl_static_result": "ioctl_static/result.json"},
        )

    # ── analysis ─────────────────────────────────────────────────

    def _run_analysis(self, entry: ProcessorEntry) -> dict[str, Any]:
        """Run ioctl_analyzer.DriverAnalyzer and convert to deepzero data dict."""
        # Add the ioctl_analyzer package to the import path
        analyzer_dir = str(Path(__file__).resolve().parent)
        if analyzer_dir not in sys.path:
            sys.path.insert(0, analyzer_dir)

        from ioctl_analyzer.analysis import DriverAnalyzer
        from ioctl_analyzer.pe_image import PEImage

        image = PEImage(str(entry.source_path))
        analyzer = DriverAnalyzer(image)
        result = analyzer.analyze(include_cfg=self.config.include_cfg)

        # ── convert to deepzero-compatible data dict ──

        # IOCTL codes from all dispatch routines
        ioctl_codes: list[dict[str, Any]] = []
        seen_ioctls: set[int] = set()
        for dispatch in result.device_control_dispatches:
            for case in dispatch.ioctl_cases:
                if case.ioctl_code is None:
                    continue
                if case.ioctl_code in seen_ioctls:
                    continue
                if len(ioctl_codes) >= self.config.max_ioctl_codes:
                    break
                seen_ioctls.add(case.ioctl_code)
                ioctl_codes.append({
                    "code": f"0x{case.ioctl_code:08X}",
                    "value": case.ioctl_code,
                    "device_type": (case.ioctl_code >> 16) & 0xFFFF,
                    "function": (case.ioctl_code >> 2) & 0xFFF,
                    "method": case.ioctl_code & 0x3,
                    "access": (case.ioctl_code >> 14) & 0x3,
                    "confidence": case.confidence,
                    "source": case.source,
                    "handler_va": f"0x{case.handler_va:x}",
                })
            if len(ioctl_codes) >= self.config.max_ioctl_codes:
                break

        ioctl_count = len(ioctl_codes)

        # Device paths from IoCreateDevice refs
        device_paths: list[str] = []
        device_path_count = 0
        if result.io_create_device_refs:
            # We can't extract the actual device name strings without decompilation,
            # but we know the driver creates devices — mark it
            device_paths.append("\\Device\\<IoCreateDevice-ref>")
            device_path_count = 1

        # Symbolic link refs
        if result.io_create_symbolic_link_refs:
            device_paths.append("\\DosDevices\\<IoCreateSymbolicLink-ref>")
            device_path_count += 1

        # Text section size from PE
        text_section_size = 0
        for section in image.sections:
            if section.name == ".text":
                text_section_size = section.virtual_size
                break

        section_count = len(image.sections)

        # Dangerous refs from imports
        dangerous_refs: list[str] = []
        dangerous_ref_count = 0
        dangerous_apis = {
            "MmMapIoSpace", "MmUnmapIoSpace", "MmGetPhysicalAddress",
            "MmCopyVirtualMemory", "MmCopyMemory",
            "ZwMapViewOfSection", "ZwOpenSection", "ZwOpenProcess",
            "ZwTerminateProcess", "ZwLoadDriver",
            "PsLookupProcessByProcessId", "KeStackAttachProcess",
            "__readmsr", "__writemsr",
            "HalGetBusDataByOffset", "HalSetBusDataByOffset",
            "MmProbeAndLockPages", "IoAllocateMdl", "MmIsAddressValid",
            "MmLoadSystemImage",
        }
        for imp in result.imports:
            if imp.name in dangerous_apis:
                dangerous_refs.append(imp.name)
        dangerous_ref_count = len(dangerous_refs)

        # Priority score
        priority_score = self._compute_priority(ioctl_count, device_path_count, dangerous_ref_count)

        # IOCTL summary
        ioctl_summary = self._build_ioctl_summary(ioctl_codes)

        data: dict[str, Any] = {
            "ioctl_codes": ioctl_codes,
            "ioctl_count": ioctl_count,
            "device_paths": device_paths,
            "device_path_count": device_path_count,
            "dangerous_string_refs": dangerous_refs,
            "dangerous_ref_count": dangerous_ref_count,
            "dangerous_refs_strings": 0,
            "dangerous_refs_imports": dangerous_ref_count,
            "text_section_size": text_section_size,
            "has_executable_data": any(
                s.name == ".data" and s.is_executable for s in image.sections
            ),
            "section_count": section_count,
            "priority_score": priority_score,
            "ioctl_summary": ioctl_summary,
            # Additional ioctl_analyzer-specific data
            "machine": result.machine,
            "dispatch_count": len(result.device_control_dispatches),
            "warnings": result.warnings,
        }

        return data

    # ── filtering ──────────────────────────────────────────────

    def _check_filters(self, data: dict[str, Any]) -> str | None:
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
                return "no dangerous API refs found"

        return None

    # ── scoring ─────────────────────────────────────────────────

    def _compute_priority(
        self, ioctl_count: int, device_path_count: int, dangerous_ref_count: int
    ) -> float:
        score = 0.0
        score += ioctl_count * self.config.score_per_ioctl
        score += device_path_count * self.config.score_per_device_path
        score += dangerous_ref_count * self.config.score_per_dangerous_ref
        return min(self.config.score_max, score)

    def _build_ioctl_summary(self, codes: list[dict[str, Any]]) -> dict[str, Any]:
        methods = {0: "METHOD_BUFFERED", 1: "METHOD_IN_DIRECT",
                   2: "METHOD_OUT_DIRECT", 3: "METHOD_NEITHER"}
        summary: dict[str, Any] = {"unique_device_types": [], "by_method": {}}

        device_types: set[int] = set()
        for c in codes:
            dt = c.get("device_type", 0)
            method = c.get("method", 0)
            device_types.add(dt)
            method_name = methods.get(method, f"UNKNOWN_{method}")
            summary["by_method"][method_name] = summary["by_method"].get(method_name, 0) + 1

        summary["unique_device_types"] = sorted(device_types)
        summary["total"] = len(codes)
        return summary
