"""parse_prefetch — typed MCP function for Windows Prefetch (.pf) parsing.

Wraps Eric Zimmerman's PECmd. Produces a `Notarized[list[PrefetchEntry]]` that
binds every emitted entry to the source image SHA-256 + PECmd version.

Why Prefetch matters for PtH / lateral-movement triage
------------------------------------------------------
Prefetch (\\Windows\\Prefetch\\*.pf) is the closest thing Windows has to an
execution receipt that's hard to forge:

  - Each .pf is created on first execution of a PE and updated thereafter.
  - The Last8RunTimes field records up to 8 execution timestamps per binary.
  - The ReferencedFiles list captures every DLL/data file the process touched
    during its first ~10 seconds — useful for proving a process loaded the
    Mimikatz DLL even if the on-disk Mimikatz binary was later deleted.

For PtH cases, Prefetch is the cheapest way to corroborate "did psexesvc.exe
actually run on this host?" — paired with Amcache (which proves the file was
there) and EVTX 4688/Sysmon 1 (which logs the process create event).

Anti-forensic note: prefetch CAN be disabled via the Registry
(EnablePrefetcher=0) but doing so is itself suspicious. Servers default to
disabled; workstations default to enabled. The agent should note the state.
"""
from __future__ import annotations

import csv
import io
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from oath.mcp.evidence_handle import EvidenceHandle
from oath.mcp.tools.parse_evtx import SubprocessExecutor, ToolExecutor
from oath.receipt.notarized import (
    EvidenceOffset,
    Notarized,
    SigningContext,
    mint,
)

PECMD_VERSION = "1.5.0.0"


# --------------------------------------------------------------------------- #
# Typed schema                                                                #
# --------------------------------------------------------------------------- #


class PrefetchEntry(BaseModel):
    """One .pf row from PECmd's structured CSV."""

    model_config = ConfigDict(frozen=True)

    # Identity
    source_filename: str = Field(..., description="Original .pf filename (e.g. PSEXESVC.EXE-12345678.pf).")
    executable_name: str = Field(..., description="Lowercased target executable name.")
    hash: str = Field(..., description="PE hash from the .pf filename (after the dash).")

    # Run statistics
    run_count: int = Field(..., ge=0, description="Total execution count recorded by Prefetcher.")
    last_run: str | None = Field(None, description="Most recent execution (ISO-8601 UTC).")
    all_run_times: tuple[str, ...] = Field(
        default=(),
        description="Up to 8 execution timestamps; the most recent is duplicated as last_run.",
    )
    size: int | None = Field(None, ge=0, description="Size of the .pf file in bytes.")
    volume_information: str | None = None

    # Referenced files (first ~10s of process execution)
    files_count: int | None = Field(None, ge=0, description="Number of referenced files.")
    directories_count: int | None = Field(None, ge=0)
    referenced_files_summary: str | None = Field(
        None, description="Pipe-joined list of referenced file paths (best-effort)."
    )

    # Provenance
    pf_path_in_image: str | None = Field(
        None, description="Original Prefetch directory path (e.g. C:\\Windows\\Prefetch\\X.pf)."
    )
    pf_image_offset: int = Field(..., ge=0)


# --------------------------------------------------------------------------- #
# Parser                                                                      #
# --------------------------------------------------------------------------- #


def _to_int_or_none(s: str | None) -> int | None:
    if s is None or not s.strip():
        return None
    try:
        return int(s.strip())
    except ValueError:
        return None


def _split_run_times(s: str | None) -> tuple[str, ...]:
    """PECmd packs 'RunTimes' as a semicolon-delimited list."""
    if not s:
        return ()
    return tuple(t.strip() for t in s.split(";") if t.strip())


def _parse_pecmd_csv(
    csv_bytes: bytes,
    pf_offset: int,
    *,
    name_filter: str | None,
) -> list[PrefetchEntry]:
    """Parse PECmd 1.5.0.0 CSV.

    Columns (canonical order):
      SourceFilename, SourceCreated, SourceModified, SourceAccessed,
      ExecutableName, Hash, Size, Version, RunCount, LastRun, PreviousRun0..6,
      Volume0Info, Volume0Created, Volume0Serial, ...
      Directories, FilesCount, Files
    """
    entries: list[PrefetchEntry] = []
    reader = csv.DictReader(io.StringIO(csv_bytes.decode("utf-8", errors="replace")))
    for row in reader:
        source = (row.get("SourceFilename") or "").strip()
        if not source:
            continue

        exe = (row.get("ExecutableName") or "").strip().lower()
        if name_filter and name_filter.lower() not in exe and name_filter.lower() not in source.lower():
            continue

        run_times = (
            (row.get("LastRun"),)
            + tuple(row.get(f"PreviousRun{i}") for i in range(7))
        )
        valid_runs = tuple(t for t in run_times if t and t.strip())

        entries.append(
            PrefetchEntry(
                source_filename=source,
                executable_name=exe,
                hash=(row.get("Hash") or "").strip(),
                run_count=_to_int_or_none(row.get("RunCount")) or 0,
                last_run=row.get("LastRun") or None,
                all_run_times=valid_runs,
                size=_to_int_or_none(row.get("Size")),
                volume_information=row.get("Volume0Info") or None,
                files_count=_to_int_or_none(row.get("FilesCount")),
                directories_count=_to_int_or_none(row.get("Directories")),
                referenced_files_summary=row.get("Files") or None,
                pf_path_in_image=None,  # PECmd doesn't surface the image-relative path
                pf_image_offset=pf_offset,
            )
        )
    return entries


# --------------------------------------------------------------------------- #
# Public typed function                                                       #
# --------------------------------------------------------------------------- #


def parse_prefetch(
    handle: EvidenceHandle,
    *,
    prefetch_dir: Path,
    name_filter: str | None = None,
    ctx: SigningContext,
    executor: ToolExecutor | None = None,
    prev_hash: str | None = None,
    pf_image_offset: int = 0,
) -> Notarized[list[PrefetchEntry]]:
    """Parse every .pf in `prefetch_dir` and mint a Notarized envelope.

    Parameters
    ----------
    handle
        Mounted-read-only EvidenceHandle.
    prefetch_dir
        Path to the directory containing .pf files (typically
        C:\\Windows\\Prefetch). PECmd recursively parses everything in it.
    name_filter
        Optional case-insensitive substring filter on executable name or
        original .pf filename.
    """
    executor = executor or SubprocessExecutor()
    args: dict[str, object] = {
        "prefetch_dir": str(prefetch_dir),
        "name_filter": name_filter,
        "pf_image_offset": pf_image_offset,
    }

    argv: list[str] = [
        "dotnet",
        "PECmd",
        "-d",
        str(prefetch_dir),
        "--csv",
        "-",
        "--csvf",
        "stdout",
    ]
    stdout_bytes = executor.run(argv)
    entries = _parse_pecmd_csv(stdout_bytes, pf_offset=pf_image_offset, name_filter=name_filter)

    return mint(
        data=entries,
        tool_name="parse_prefetch",
        tool_version=PECMD_VERSION,
        args=args,
        image_sha256=handle.image_sha256,
        stdout_bytes=stdout_bytes,
        offsets=(
            EvidenceOffset(
                start=pf_image_offset,
                length=1,  # Directory; length isn't meaningful for a folder reference.
                artifact_label=f"Prefetch dir {prefetch_dir.name}",
            ),
        ),
        prev_hash=prev_hash,
        ctx=ctx,
    )


def reverify(
    envelope: Notarized[list[PrefetchEntry]],
    *,
    prefetch_dir: Path,
    executor: ToolExecutor | None = None,
) -> tuple[bool, str]:
    """Re-run PECmd, recompute BLAKE3 of stdout, compare to envelope record."""
    import blake3

    executor = executor or SubprocessExecutor()
    argv = ["dotnet", "PECmd", "-d", str(prefetch_dir), "--csv", "-", "--csvf", "stdout"]
    try:
        stdout_bytes = executor.run(argv)
    except Exception as e:
        return False, f"PECmd re-run failed: {e}"
    actual = blake3.blake3(stdout_bytes).hexdigest()
    expected = envelope.header.stdout_blake3
    if actual != expected:
        return False, f"stdout BLAKE3 drift: expected {expected[:16]}…, got {actual[:16]}…"
    return True, "ok"


__all__ = [
    "PECMD_VERSION",
    "PrefetchEntry",
    "parse_prefetch",
    "reverify",
]
