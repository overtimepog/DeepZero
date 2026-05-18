from __future__ import annotations

import gzip
import json
import logging
import os
import shutil
from pathlib import Path
from typing import Any

from deepzero.engine.stage import (
    BulkMapProcessor,
    ProcessorContext,
    ProcessorEntry,
    ProcessorResult,
)

log = logging.getLogger("deepzero.processor.work_cleanup")


class WorkCleanup(BulkMapProcessor):
    description = (
        "post-pipeline storage cleanup — removes filtered/failed sample dirs, "
        "compresses artifacts, and cleans archive extraction caches"
    )
    version = "1.0"

    def process(
        self, ctx: ProcessorContext, entries: list[ProcessorEntry]
    ) -> list[ProcessorResult]:
        """Entry point: entries are the ACTIVE samples after all filtering."""
        clean_filtered = self.config.get("clean_filtered", True)
        compress_artifacts = self.config.get("compress_artifacts", True)
        clean_archive_cache = self.config.get("clean_archive_cache", True)
        cleanup_stale_ghidra = self.config.get("cleanup_stale_ghidra", True)
        ghidra_project_base = self.config.get("ghidra_project_base", "/tmp/ghidra_projects")

        stats: dict[str, int] = {}

        # 1. Remove filtered/failed sample dirs from disk
        if clean_filtered and entries:
            samples_dir = entries[0].sample_dir.parent
            removed = self._clean_filtered_samples(samples_dir)
            stats["filtered_dirs_removed"] = removed

        # 2. Compress remaining artifacts in active sample dirs
        if compress_artifacts:
            stats.update(self._compress_sample_artifacts(entries))

        # 3. Clean archive extraction cache
        if clean_archive_cache:
            removed_mb = self._clean_archive_cache()
            stats["archive_cache_mb_freed"] = int(removed_mb)

        # 4. Clean stale Ghidra projects
        if cleanup_stale_ghidra:
            removed_mb = self._clean_stale_ghidra_projects(ghidra_project_base)
            stats["ghidra_projects_mb_freed"] = int(removed_mb)

        # 5. Clean miscellaneous temp files (pycache, JVM logs, leftover dirs)
        removed_mb = self._clean_temp_files()
        if removed_mb > 0:
            stats["temp_files_mb_freed"] = int(removed_mb)

        self.log.info("cleanup complete: %s", stats)

        # Return one OK result so the pipeline doesn't think every sample failed
        return [
            ProcessorResult.ok(
                artifacts={"cleanup_stats": "cleanup_stats.json"},
                data=stats,
            )
        ]

    # ── filtered sample cleanup ────────────────────────────────────────

    def _clean_filtered_samples(self, samples_dir: Path) -> int:
        """Remove work dirs for samples that were filtered or failed."""
        removed = 0
        if not samples_dir.exists():
            return 0

        for sample_dir in samples_dir.iterdir():
            if not sample_dir.is_dir():
                continue
            state_file = sample_dir / "state.json"
            if not state_file.exists():
                continue
            try:
                state = json.loads(state_file.read_text(encoding="utf-8"))
                verdict = state.get("verdict", "")
                # FILTERED or FAILED samples are dead weight — remove them
                if verdict in ("FILTERED", "FAILED"):
                    size = _dir_size(sample_dir)
                    shutil.rmtree(sample_dir, ignore_errors=True)
                    self.log.debug(
                        "removed %s (%s) — %.1f MB freed",
                        sample_dir.name, verdict, size / (1024 * 1024),
                    )
                    removed += 1
            except (OSError, json.JSONDecodeError, ValueError) as e:
                self.log.debug("skipping %s: %s", sample_dir.name, e)

        self.log.info("removed %d filtered/failed sample directories", removed)
        return removed

    # ── artifact compression ───────────────────────────────────────────

    def _compress_sample_artifacts(self, entries: list[ProcessorEntry]) -> dict[str, int]:
        """gzip large uncompressed files in active sample dirs."""
        compressed_count = 0
        total_bytes_before = 0
        total_bytes_after = 0

        # file extensions worth compressing (text-heavy, compress well)
        compressible = {".c", ".h", ".json", ".log", ".md", ".txt", ".csv", ".xml"}

        for entry in entries:
            sample_dir = entry.sample_dir
            if not sample_dir.exists():
                continue

            for file_path in sample_dir.rglob("*"):
                if not file_path.is_file():
                    continue
                if file_path.suffix not in compressible:
                    continue
                # skip already-compressed files
                if file_path.suffix == ".gz":
                    continue
                # skip small files (< 1 KB — not worth it)
                size = file_path.stat().st_size
                if size < 1024:
                    continue

                gz_path = file_path.with_suffix(file_path.suffix + ".gz")
                if gz_path.exists():
                    continue

                try:
                    with open(file_path, "rb") as f_in, gzip.open(
                        gz_path, "wb", compresslevel=6
                    ) as f_out:
                        shutil.copyfileobj(f_in, f_out)
                    gz_size = gz_path.stat().st_size
                    total_bytes_before += size
                    total_bytes_after += gz_size
                    file_path.unlink()
                    compressed_count += 1
                except OSError as e:
                    self.log.debug("compress fail %s: %s", file_path.name, e)

        ratio = (
            (1 - total_bytes_after / total_bytes_before) * 100
            if total_bytes_before > 0
            else 0
        )
        self.log.info(
            "compressed %d artifacts: %.1f MB -> %.1f MB (%.0f%% savings)",
            compressed_count,
            total_bytes_before / (1024 * 1024),
            total_bytes_after / (1024 * 1024),
            ratio,
        )
        return {
            "artifacts_compressed": compressed_count,
            "artifact_bytes_before": total_bytes_before,
            "artifact_bytes_after": total_bytes_after,
        }

    # ── archive cache cleanup ──────────────────────────────────────────

    def _clean_archive_cache(self) -> float:
        """Remove .deepzero_cache/extracted dirs in common locations."""
        freed = 0.0
        search_dirs = [
            Path.cwd(),
            Path("/mnt/c/Users/truen/Desktop/Stuff"),
        ]
        for base in search_dirs:
            cache = base / ".deepzero_cache" / "extracted"
            if cache.exists():
                size = _dir_size(cache)
                shutil.rmtree(cache, ignore_errors=True)
                freed += size / (1024 * 1024)
                self.log.info(
                    "removed archive cache %s — %.1f MB freed", cache, size / (1024 * 1024)
                )
        return freed

    # ── stale Ghidra project cleanup ───────────────────────────────────

    def _clean_stale_ghidra_projects(self, project_base: str) -> float:
        """Remove orphaned Ghidra project dirs (.gpr/.rep) from project_base."""
        base = Path(project_base)
        if not base.exists():
            return 0.0

        freed = 0.0
        for proj_dir in base.iterdir():
            if proj_dir.suffix in (".gpr", ".rep") and proj_dir.is_dir():
                size = _dir_size(proj_dir)
                shutil.rmtree(proj_dir, ignore_errors=True)
                freed += size / (1024 * 1024)
                self.log.debug(
                    "removed stale ghidra project %s — %.1f MB",
                    proj_dir.name, size / (1024 * 1024),
                )

        if freed > 0:
            self.log.info("removed stale Ghidra projects — %.1f MB freed", freed)
        return freed


    # ── temp file cleanup ────────────────────────────────────────

    def _clean_temp_files(self) -> float:
        """Remove __pycache__, JVM crash logs, leftover bulk/temp dirs, and Ghidra tmp dirs."""
        freed = 0.0
        processors_dir = Path(__file__).resolve().parent.parent

        # __pycache__ dirs under processors/
        for pycache in processors_dir.rglob("__pycache__"):
            if pycache.is_dir():
                size = _dir_size(pycache)
                shutil.rmtree(pycache, ignore_errors=True)
                freed += size

        # JVM crash logs (hs_err_pid*.log)
        for pattern in ["hs_err_pid*.log", "replay_pid*.log", "javacore*.txt"]:
            for f in Path.cwd().glob(pattern):
                if f.is_file():
                    freed += f.stat().st_size
                    f.unlink(missing_ok=True)

        # Leftover Ghidra temp dirs (/tmp/ghidra_*)
        for tmp_dir in Path("/tmp").glob("ghidra_*"):
            if tmp_dir.is_dir():
                size = _dir_size(tmp_dir)
                shutil.rmtree(tmp_dir, ignore_errors=True)
                freed += size

        # Leftover bulk temp dirs from semgrep
        for bulk_dir in Path("/tmp").glob(".bulk_temp*"):
            if bulk_dir.is_dir():
                size = _dir_size(bulk_dir)
                shutil.rmtree(bulk_dir, ignore_errors=True)
                freed += size

        if freed > 0:
            self.log.info("cleaned temp files — %.1f MB freed", freed / (1024 * 1024))
        return freed / (1024 * 1024)


# ── helpers ────────────────────────────────────────────────────────────────


def _dir_size(path: Path) -> int:
    """Total size of all files under path, in bytes."""
    total = 0
    try:
        for f in path.rglob("*"):
            if f.is_file():
                total += f.stat().st_size
    except OSError:
        pass
    return total
