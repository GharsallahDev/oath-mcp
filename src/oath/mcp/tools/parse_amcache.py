"""parse_amcache — typed MCP function for Amcache.hve (program execution residue).

Wraps Eric Zimmerman's AmcacheParser. Produces a `Notarized[list[AmcacheEntry]]`
binding every emitted entry to the source image SHA-256 + AmcacheParser version.

Why Amcache matters for PtH / lateral-movement triage
-----------------------------------------------------
Amcache.hve records *every* PE that has been seen on the host — usually within
a few minutes of execution, even if the file is later deleted. For an
incident-response agent it's the cheapest way to answer four high-value
questions:

  - "Did psexesvc.exe ever exist on this host?" → InventoryApplicationFile entry
  - "What was its SHA-1 hash?"                  → FileId field (raw SHA-1 with
                                                  a leading "0000" sentinel)
  - "Who signed it?"                            → BinaryType + Publisher
  - "When was it first seen?"                   → FileKeyLastWriteTimestamp

Adversaries who drop tools and clean up still leave Amcache traces. Detection
guidance: pair Amcache FileId hashes with VirusTotal / NSRL / your own
known-bad set; cross-reference InventoryApplicationFile entries against
Prefetch (parse_prefetch.py) to corroborate execution timing.

Important: Microsoft has changed Amcache.hve's internal schema across Windows
builds (notably Win10 1909 → 20H2 and Win11 22H2 → 23H2). AmcacheParser tracks
those changes; we pin the parser version so the Witness Oath Verifier can
reproduce.
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

AMCACHEPARSER_VERSION = "2026.5.0"


# --------------------------------------------------------------------------- #
# Typed schema                                                                #
# --------------------------------------------------------------------------- #


class AmcacheEntry(BaseModel):
    """One Amcache InventoryApplicationFile row.

    AmcacheParser emits multiple CSV files (UnassociatedFileEntries,
    AssociatedFileEntries, ProgramEntries, ShortcutEntries, DriverEntries,
    DeviceEntries, DriverBinaries, DevicePnps). For autonomous IR the load-
    bearing one is *AssociatedFileEntries* — that's "program X was here at
    time T with SHA-1 H". We surface its key columns natively.
    """

    model_config = ConfigDict(frozen=True)

    # Identity
    file_id: str = Field(
        ..., description="AmcacheParser FileId — Windows-prefixed SHA-1, '0000<sha1>' form."
    )
    sha1: str | None = Field(
        None, description="SHA-1 stripped of the Windows '0000' prefix; lowercase hex."
    )
    name: str = Field(..., description="Original file name from Amcache.")
    full_path: str | None = Field(None, description="Original full path if available.")

    # Signing
    publisher: str | None = None
    is_pe_file: bool | None = None
    is_signed: bool | None = None
    binary_type: str | None = Field(None, description="e.g. pe32_i386, pe64_amd64.")

    # Sizes
    size: int | None = Field(None, ge=0)
    product_name: str | None = None
    product_version: str | None = None
    file_version: str | None = None
    company_name: str | None = None
    description: str | None = None

    # Timestamps
    file_key_last_write_ts: str | None = Field(
        None, description="First-seen-by-Amcache time (ISO-8601 UTC)."
    )
    link_date: str | None = Field(None, description="PE link timestamp from the binary itself.")

    # Provenance
    amcache_image_offset: int = Field(..., ge=0, description="Byte offset of Amcache.hve.")


def _to_int_or_none(s: str | None) -> int | None:
    if s is None or not s.strip():
        return None
    try:
        return int(s.strip())
    except ValueError:
        return None


def _to_optional_bool(s: str | None) -> bool | None:
    if s is None or not s.strip():
        return None
    return s.strip().lower() in {"true", "1", "yes"}


def _strip_sha1_prefix(file_id: str) -> str | None:
    """Amcache stores SHA-1 as '0000<sha1hex>' — strip the sentinel."""
    if file_id and len(file_id) == 44 and file_id.startswith("0000"):
        return file_id[4:].lower()
    return None


# --------------------------------------------------------------------------- #
# Parser                                                                      #
# --------------------------------------------------------------------------- #


def _parse_amcache_csv(
    csv_bytes: bytes,
    amcache_offset: int,
    *,
    sha1_filter: set[str] | None,
    name_substring: str | None,
) -> list[AmcacheEntry]:
    """Parse AmcacheParser 2.0.0.1 AssociatedFileEntries CSV.

    Columns (canonical order):
      ApplicationName, ProgramId, FileId, LinkDate, Path, Hash, Size, Version,
      ProductName, ProductVersion, ProgramInstanceId, IsPeFile, IsOsComponent,
      FileKeyLastWriteTimestamp, Publisher, BinaryType, Description, Language,
      FileVersionString, ...
    """
    entries: list[AmcacheEntry] = []
    reader = csv.DictReader(io.StringIO(csv_bytes.decode("utf-8", errors="replace")))
    for row in reader:
        file_id = (row.get("FileId") or "").strip()
        if not file_id:
            continue
        sha1 = _strip_sha1_prefix(file_id)

        if sha1_filter and (sha1 is None or sha1 not in sha1_filter):
            continue

        name = (row.get("ApplicationName") or row.get("Path") or "").strip()
        if name_substring and name_substring.lower() not in name.lower():
            continue

        entries.append(
            AmcacheEntry(
                file_id=file_id,
                sha1=sha1,
                name=name,
                full_path=row.get("Path") or None,
                publisher=row.get("Publisher") or None,
                is_pe_file=_to_optional_bool(row.get("IsPeFile")),
                is_signed=_to_optional_bool(row.get("IsOsComponent"))
                if row.get("IsOsComponent")
                else None,
                binary_type=row.get("BinaryType") or None,
                size=_to_int_or_none(row.get("Size")),
                product_name=row.get("ProductName") or None,
                product_version=row.get("ProductVersion") or None,
                file_version=row.get("Version") or row.get("FileVersionString") or None,
                company_name=row.get("Publisher") or None,
                description=row.get("Description") or None,
                file_key_last_write_ts=row.get("FileKeyLastWriteTimestamp") or None,
                link_date=row.get("LinkDate") or None,
                amcache_image_offset=amcache_offset,
            )
        )
    return entries


# --------------------------------------------------------------------------- #
# Public typed function                                                       #
# --------------------------------------------------------------------------- #


def parse_amcache(
    handle: EvidenceHandle,
    *,
    amcache_path: Path,
    sha1_filter: list[str] | None = None,
    name_substring: str | None = None,
    ctx: SigningContext,
    executor: ToolExecutor | None = None,
    prev_hash: str | None = None,
    amcache_image_offset: int = 0,
) -> Notarized[list[AmcacheEntry]]:
    """Extract Amcache.hve entries and mint a Notarized envelope.

    Parameters
    ----------
    handle
        Mounted-read-only EvidenceHandle.
    amcache_path
        Path to the Amcache.hve registry file (typically extracted from
        C:\\Windows\\AppCompat\\Programs\\Amcache.hve via Sleuthkit `icat`).
    sha1_filter
        Optional set of SHA-1 hashes to match (case-insensitive, no prefix).
        When set, only entries whose `sha1` is in the set survive.
    name_substring
        Optional case-insensitive substring filter on ApplicationName or Path.
    """
    executor = executor or SubprocessExecutor()
    normalized_sha1_filter = (
        {s.lower().strip() for s in sha1_filter if s.strip()} if sha1_filter else None
    )

    args: dict[str, object] = {
        "amcache_path": str(amcache_path),
        "sha1_filter": sorted(normalized_sha1_filter) if normalized_sha1_filter else None,
        "name_substring": name_substring,
        "amcache_image_offset": amcache_image_offset,
    }

    argv: list[str] = [
        "AmcacheParser",
        "-f",
        str(amcache_path),
        "--csv",
        "-",
        "--csvf",
        "stdout",
        "-i",  # include UnassociatedFileEntries too
    ]
    stdout_bytes = executor.run(argv)
    entries = _parse_amcache_csv(
        stdout_bytes,
        amcache_offset=amcache_image_offset,
        sha1_filter=normalized_sha1_filter,
        name_substring=name_substring,
    )

    return mint(
        data=entries,
        tool_name="parse_amcache",
        tool_version=AMCACHEPARSER_VERSION,
        args=args,
        image_sha256=handle.image_sha256,
        stdout_bytes=stdout_bytes,
        offsets=(
            EvidenceOffset(
                start=amcache_image_offset,
                length=max(amcache_path.stat().st_size, 1) if amcache_path.exists() else 1,
                artifact_label="Amcache.hve",
            ),
        ),
        prev_hash=prev_hash,
        ctx=ctx,
    )


def reverify(
    envelope: Notarized[list[AmcacheEntry]],
    *,
    amcache_path: Path,
    executor: ToolExecutor | None = None,
) -> tuple[bool, str]:
    """Re-run AmcacheParser, recompute BLAKE3 of stdout, compare."""
    import blake3

    executor = executor or SubprocessExecutor()
    argv = [
        "AmcacheParser",
        "-f",
        str(amcache_path),
        "--csv",
        "-",
        "--csvf",
        "stdout",
        "-i",
    ]
    try:
        stdout_bytes = executor.run(argv)
    except Exception as e:
        return False, f"AmcacheParser re-run failed: {e}"
    actual = blake3.blake3(stdout_bytes).hexdigest()
    expected = envelope.header.stdout_blake3
    if actual != expected:
        return False, f"stdout BLAKE3 drift: expected {expected[:16]}…, got {actual[:16]}…"
    return True, "ok"


__all__ = [
    "AMCACHEPARSER_VERSION",
    "AmcacheEntry",
    "parse_amcache",
    "reverify",
]
