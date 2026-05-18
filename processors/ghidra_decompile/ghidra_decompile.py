from __future__ import annotations

import gzip
import json
import logging
import os
import shutil
import subprocess
import sys
import tempfile
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

log = logging.getLogger("deepzero.processor.ghidra")


class GhidraDecompile(MapProcessor):
    description = (
        "decompiles binaries using ghidra headless analysis with a configurable post-script"
    )
    version = "2.0"

    @dataclass
    class Config:
        strategy: str = ""
        timeout: int = 300
        max_functions: int | None = None
        max_depth: int | None = None
        ghidra_install_dir: str = ""
        java_home: str = ""
        skip_analysis: bool = False
        jvm_max_heap: str = "4g"
        jvm_init_heap: str = "2g"
        jvm_gc: str = "G1GC"
        project_base: str = "/tmp/ghidra_projects"

    def validate(self, ctx: ProcessorContext) -> list[str]:
        if not self.config.ghidra_install_dir:
            return [
                "ghidra_install_dir is required - set it in config or via ${GHIDRA_INSTALL_DIR}"
            ]
        ghidra_dir = Path(self.config.ghidra_install_dir)
        if not ghidra_dir.exists():
            return [f"ghidra not found at {ghidra_dir}"]
        try:
            self._find_analyze_headless(ghidra_dir)
        except FileNotFoundError as e:
            return [str(e)]
        return []

    def should_skip(self, ctx: ProcessorContext, entry: ProcessorEntry) -> str | None:
        cached = entry.sample_dir / "decompiled" / "ghidra_result.json"
        if cached.exists():
            try:
                with open(cached, "r", encoding="utf-8") as f:
                    json.load(f)
                return "decompilation already cached"
            except (json.JSONDecodeError, OSError, ValueError) as e:
                self.log.debug("failed to read cached ghidra output: %s", e)
        return None

    def process(self, ctx: ProcessorContext, entry: ProcessorEntry) -> ProcessorResult:
        if not self.config.ghidra_install_dir:
            return ProcessorResult.fail("ghidra_install_dir not configured")

        ghidra_dir = Path(self.config.ghidra_install_dir)
        if not ghidra_dir.exists():
            return ProcessorResult.fail(f"ghidra not found: {ghidra_dir}")

        if not self.config.strategy:
            return ProcessorResult.fail("no strategy script configured")

        script_path = self._resolve_script(self.config.strategy)
        output_dir = entry.sample_dir / "decompiled"
        output_dir.mkdir(parents=True, exist_ok=True)

        # Symlink binary into writable temp dir so PyGhidra can create its
        # project directory alongside it (fails on read-only /mnt/c paths)
        tmp_dir = Path(tempfile.mkdtemp(prefix="ghidra_", dir=output_dir))
        binary_copy = tmp_dir / entry.source_path.name
        binary_copy.symlink_to(entry.source_path.resolve())
        self.log.debug("symlinked %s -> %s", entry.source_path, binary_copy)

        extra_env: dict[str, str] = {}
        if self.config.max_functions is not None:
            extra_env["DEEPZERO_MAX_FUNCTIONS"] = str(self.config.max_functions)
        if self.config.max_depth is not None:
            extra_env["DEEPZERO_MAX_DEPTH"] = str(self.config.max_depth)

        active_timeout = self.spec.timeout if self.spec.timeout > 0 else self.config.timeout
        try:
            result = self._run_ghidra_headless(
                binary_path=binary_copy,
                output_dir=output_dir,
                ghidra_install_dir=ghidra_dir,
                post_script=script_path,
                timeout=active_timeout,
                java_home=self.config.java_home,
                extra_env=extra_env if extra_env else None,
            )
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)

        if not result.get("success", False):
            return ProcessorResult.fail(result.get("error", "ghidra analysis failed"))

        # Clean up Ghidra project files (saves significant disk — .gpr/.rep dirs)
        self._cleanup_project(entry.source_path.stem)

        data: dict[str, Any] = {}
        for key in ("device_name", "symbolic_link", "dispatch_name", "function_count"):
            if key in result:
                data[key] = result[key]

        artifacts = {"ghidra_result": "decompiled/ghidra_result.json"}
        dispatch_file = output_dir / "dispatch_ioctl.c"
        if dispatch_file.exists():
            artifacts["dispatch_ioctl"] = "decompiled/dispatch_ioctl.c"

        # Compress large artifacts to save sample-dir storage
        self._compress_artifact(dispatch_file)
        gh_result = output_dir / "ghidra_result.json"
        self._compress_artifact(gh_result)

        return ProcessorResult.ok(artifacts=artifacts, data=data)

    def _cleanup_project(self, binary_stem: str) -> None:
        """Remove Ghidra project dirs (.gpr/.rep) for this binary to reclaim disk."""
        project_path = Path(self.config.project_base)
        for suffix in (".gpr", ".rep"):
            proj_dir = project_path / f"{binary_stem}{suffix}"
            if proj_dir.exists():
                try:
                    shutil.rmtree(proj_dir, ignore_errors=False)
                    self.log.debug("cleaned up %s", proj_dir)
                except OSError as e:
                    self.log.debug("could not clean up %s: %s", proj_dir, e)

    def _compress_artifact(self, path: Path) -> None:
        """gzip a file in-place, replacing the original. No-op if already .gz."""
        if not path.exists():
            return
        gz_path = path.with_suffix(path.suffix + ".gz")
        if gz_path.exists():
            return  # already compressed
        try:
            with open(path, "rb") as f_in, gzip.open(gz_path, "wb", compresslevel=6) as f_out:
                shutil.copyfileobj(f_in, f_out)
            path.unlink()
            self.log.debug("compressed %s -> %s", path.name, gz_path.name)
        except OSError as e:
            self.log.debug("could not compress %s: %s", path.name, e)

    def _resolve_script(self, strategy: str) -> Path:
        local_script = self.processor_dir / "scripts" / strategy
        if local_script.exists():
            return local_script

        abs_path = Path(strategy)
        if abs_path.is_absolute() and abs_path.exists():
            return abs_path

        raise FileNotFoundError(
            f"strategy '{strategy}' not found in {self.processor_dir / 'scripts'}"
        )

    def _build_ghidra_cmd(
        self,
        binary_path: Path,
        output_dir: Path,
        ghidra_install_dir: Path,
        post_script: Path,
        timeout: int,
    ) -> list[str]:
        # Use pyghidra CLI (Ghidra 12.1+)
        pyghidra_bin = self._find_pyghidra()

        # Projects go under configurable temp base (not /mnt/c/ — I/O is 3-5x slower)
        project_path = Path(self.config.project_base)
        project_path.mkdir(parents=True, exist_ok=True)

        cmd = [
            str(pyghidra_bin),
            str(binary_path),
            str(post_script),
            "--install-dir", str(ghidra_install_dir),
            "--project-path", str(project_path),
            # JVM: bump heap from default 2G, use G1GC for better throughput
            "-X", f"-Xmx{self.config.jvm_max_heap}",
            "-X", f"-Xms{self.config.jvm_init_heap}",
            "-X", f"-XX:+Use{self.config.jvm_gc}",
            "-D", "-Dcpu.core.limit=8",
        ]

        # Only skip analysis if explicitly configured AND script doesn't need call graphs
        if self.config.skip_analysis:
            cmd.append("--skip-analysis")

        return cmd

    def _find_pyghidra(self) -> Path:
        """Locate the pyghidra CLI binary."""
        pyghidra_path = shutil.which("pyghidra")
        if pyghidra_path:
            return Path(pyghidra_path)
        # Fallback: try common pip user install locations
        for candidate in [
            Path.home() / ".local" / "bin" / "pyghidra",
            Path("/usr/local/bin/pyghidra"),
        ]:
            if candidate.exists():
                return candidate
        raise FileNotFoundError(
            "pyghidra CLI not found — install with: pip install pyghidra"
        )

    def _run_ghidra_headless(
        self,
        binary_path: Path,
        output_dir: Path,
        ghidra_install_dir: Path,
        post_script: Path,
        timeout: int = 300,
        java_home: str = "",
        extra_env: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        output_dir.mkdir(parents=True, exist_ok=True)

        cached_result = output_dir / "ghidra_result.json"
        if cached_result.exists():
            log.info("ghidra cache hit for %s", binary_path.name)
            try:
                return json.loads(cached_result.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError) as e:
                log.warning("cached result is corrupt, re-running analysis", exc_info=e)
                cached_result.unlink(missing_ok=True)

        cmd = self._build_ghidra_cmd(
            binary_path, output_dir, ghidra_install_dir, post_script, timeout
        )

        env = dict(os.environ)
        env["DEEPZERO_OUTPUT_DIR"] = str(output_dir)

        if java_home:
            env["JAVA_HOME"] = java_home

        if extra_env:
            env.update(extra_env)

        stdout_log = output_dir / "ghidra_stdout.log"
        stderr_log = output_dir / "ghidra_stderr.log"

        log.info("starting ghidra analysis of %s (timeout=%ds)", binary_path.name, timeout)

        start_time = time.monotonic()

        try:
            with open(stdout_log, "wb") as fout, open(stderr_log, "wb") as ferr:
                proc = subprocess.Popen(
                    cmd,
                    stdout=fout,
                    stderr=ferr,
                    stdin=subprocess.DEVNULL,
                    env=env,
                )

                try:
                    proc.wait(timeout=timeout)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    elapsed = time.monotonic() - start_time
                    try:
                        proc.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        log.warning(
                            "ghidra timed out for %s after %.1fs and did not terminate after kill()",
                            binary_path.name,
                            elapsed,
                        )
                        return {
                            "success": False,
                            "error": f"ghidra timed out after {timeout}s and did not terminate after kill()",
                        }
                    log.warning("ghidra timed out for %s after %.1fs", binary_path.name, elapsed)
                    return {"success": False, "error": f"ghidra timed out after {timeout}s"}

        except OSError as e:
            return {"success": False, "error": f"execution error: {e}"}

        elapsed = time.monotonic() - start_time

        if proc.returncode != 0:
            stderr_text = ""
            if stderr_log.exists():
                stderr_text = stderr_log.read_text(encoding="utf-8", errors="replace")[-500:]
            log.warning(
                "ghidra failed for %s (code %d, %.1fs)", binary_path.name, proc.returncode, elapsed
            )
            return {
                "success": False,
                "error": f"ghidra exited with code {proc.returncode}: {stderr_text}",
            }

        if not cached_result.exists():
            log.warning("ghidra produced no result for %s (%.1fs)", binary_path.name, elapsed)
            return {"success": False, "error": "ghidra succeeded but no result found"}

        log.info("ghidra completed %s (%.1fs)", binary_path.name, elapsed)

        try:
            return json.loads(cached_result.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as e:
            return {"success": False, "error": f"failed to parse ghidra output: {e}"}

    def _find_analyze_headless(self, ghidra_dir: Path) -> Path:
        if sys.platform == "win32":
            bat = ghidra_dir / "support" / "analyzeHeadless.bat"
            if bat.exists():
                return bat
        else:
            sh = ghidra_dir / "support" / "analyzeHeadless"
            if sh.exists():
                return sh

        for name in ("analyzeHeadless.bat", "analyzeHeadless"):
            p = ghidra_dir / "support" / name
            if p.exists():
                return p

        raise FileNotFoundError(
            f"analyzeHeadless not found in {ghidra_dir}/support/ - verify ghidra install directory"
        )
