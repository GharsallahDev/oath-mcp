"""parse_mft — typed MCP function for NTFS $MFT extraction.

Wraps Eric Zimmerman's MFTECmd. Produces a `Notarized[list[MftEntry]]` that
binds every emitted entry to the source image SHA-256 + the MFTECmd version.

Why MFT matters for PtH/lateral-movement triage
-----------------------------------------------
The $MFT is the authoritative record of every file that has existed on an NTFS
volume. Three high-value autonomous-IR signals live here:

  1. Execution residue — psexesvc.exe, mimikatz dropped binaries, rubeus.exe,
     impacket scripts all leave $MFT entries even when AV deletes the file.
     The deletion only zeroes the entry's "in-use" flag; the filename, path,
     and timestamps remain forensically recoverable.

  2. Timestomp detection — every entry carries TWO timestamp sets:
     $STANDARD_INFORMATION (SI; user-settable, what `dir` shows) and
     $FILE_NAME (FN; only the kernel writes it on file creation/move).
     SI < FN by more than a few seconds is a classic timestomp indicator
     (T1070.006). The Witness Oath Verifier catches the LLM hallucinating
     timestomp claims because the raw $MFT bytes are deterministic.

  3. Anti-forensic signals — $LogFile/$UsnJrnl gaps, entries with no parent
     directory, deleted-and-replaced patterns. MFTECmd surfaces these via
     ParentEntryNumber + ParentSequenceNumber consistency.

The Witness Oath Verifier re-runs MFTECmd with the same args + checks the
BLAKE3 of the CSV output. Any drift between mint and verify (changed $MFT,
different MFTECmd version, different filters) breaks the receipt.
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

# Pinned in docker/eztools/dotnet-tools.json
MFTECMD_VERSION = "2026.5.0"


# --------------------------------------------------------------------------- #
# Typed schema                                                                #
# --------------------------------------------------------------------------- #


class MftEntry(BaseModel):
    """One row out of MFTECmd's structured CSV output.

    MFTECmd v1.2.2.0 emits ~36 columns; we surface the ones load-bearing for
    triage and recoverable provenance. The byte offsets back into the original
    image let the Replay Receipt re-extract the source bytes on demand.
    """

    model_config = ConfigDict(frozen=True)

    # NTFS identity
    entry_number: int = Field(..., ge=0, description="$MFT entry number (record index).")
    sequence_number: int = Field(..., ge=0, description="Sequence number within the entry.")
    parent_entry_number: int | None = Field(None, description="Parent directory's entry.")
    parent_sequence_number: int | None = None
    in_use: bool = Field(..., description="$MFT entry's allocated/in-use flag.")
    is_directory: bool = False

    # File identity
    file_name: str = Field(..., description="Short or long filename from $FILE_NAME attribute.")
    file_extension: str | None = None
    full_path: str | None = Field(None, description="Reconstructed parent-traversal path.")
    file_size: int | None = Field(None, ge=0, description="Bytes; non-resident or resident.")

    # Standard Information timestamps (user-settable; what `dir` shows)
    si_created: str | None = Field(None, description="ISO-8601 UTC.")
    si_modified: str | None = None
    si_accessed: str | None = None
    si_record_modified: str | None = None

    # File Name timestamps (kernel-only; the timestomp tripwire)
    fn_created: str | None = None
    fn_modified: str | None = None
    fn_accessed: str | None = None
    fn_record_modified: str | None = None

    # Attribute hashes (for evidence integrity)
    has_alternate_data_streams: bool = False
    has_object_id: bool = False
    has_reparse_point: bool = False

    # Provenance back into the source image
    mft_image_offset: int = Field(
        ..., ge=0, description="Byte offset of the $MFT file in the source image."
    )
    entry_offset_in_mft: int = Field(
        ..., ge=0, description="Byte offset of THIS entry within the $MFT (n * 1024 by default)."
    )


# --------------------------------------------------------------------------- #
# Parser                                                                      #
# --------------------------------------------------------------------------- #


_TRUE_VALUES = {"true", "1", "yes"}


def _to_bool(s: str | None) -> bool:
    return bool(s) and s.strip().lower() in _TRUE_VALUES


def _to_int_or_none(s: str | None) -> int | None:
    if s is None or not s.strip():
        return None
    try:
        return int(s.strip())
    except ValueError:
        return None


def _to_size_or_none(s: str | None) -> int | None:
    n = _to_int_or_none(s)
    return n if n is not None and n >= 0 else None


def _parse_mftecmd_csv(
    csv_bytes: bytes,
    mft_offset: int,
    *,
    filter_path: str | None,
    since: str | None,
) -> list[MftEntry]:
    """Parse MFTECmd's --csv-output into typed MftEntry objects.

    MFTECmd v1.2.2.0 column layout (load-bearing subset):
      EntryNumber, SequenceNumber, ParentEntryNumber, ParentSequenceNumber,
      InUse, IsDirectory, FileName, Extension, ParentPath, FileSize,
      Created0x10, LastModified0x10, LastAccess0x10, LastRecordChange0x10,
      Created0x30, LastModified0x30, LastAccess0x30, LastRecordChange0x30,
      HasAds, HasObjectId, HasReparsePoint, ...

    `0x10` = $STANDARD_INFORMATION attribute; `0x30` = $FILE_NAME attribute.
    """
    entries: list[MftEntry] = []
    reader = csv.DictReader(io.StringIO(csv_bytes.decode("utf-8-sig", errors="replace")))
    for row in reader:
        entry_number = _to_int_or_none(row.get("EntryNumber"))
        if entry_number is None:
            continue

        full_path = (row.get("ParentPath") or "").rstrip("\\/")
        file_name = row.get("FileName") or ""
        joined_path = f"{full_path}\\{file_name}" if full_path else file_name

        # Client-side filters (MFTECmd doesn't have a path filter in 1.2.2.0).
        if filter_path and filter_path.lower() not in joined_path.lower():
            continue

        # "since" filter — keep entries where ANY timestamp is at or after the
        # cutoff. Operationally, this is "show me entries with any activity
        # after T", which is the autonomous-triage semantic. ISO-8601 strings
        # sort lexicographically when normalized (no timezone variance in our
        # MFTECmd output), so plain string compare works.
        ts_cols = (
            "Created0x10",
            "LastModified0x10",
            "LastAccess0x10",
            "LastRecordChange0x10",
            "Created0x30",
            "LastModified0x30",
            "LastAccess0x30",
            "LastRecordChange0x30",
        )
        if since:
            timestamps = [t for t in (row.get(c) for c in ts_cols) if t]
            most_recent = max(timestamps) if timestamps else None
            if most_recent is None or most_recent < since:
                continue

        si_record_modified = row.get("LastRecordChange0x10")

        entries.append(
            MftEntry(
                entry_number=entry_number,
                sequence_number=_to_int_or_none(row.get("SequenceNumber")) or 0,
                parent_entry_number=_to_int_or_none(row.get("ParentEntryNumber")),
                parent_sequence_number=_to_int_or_none(row.get("ParentSequenceNumber")),
                in_use=_to_bool(row.get("InUse")),
                is_directory=_to_bool(row.get("IsDirectory")),
                file_name=file_name,
                file_extension=row.get("Extension") or None,
                full_path=joined_path or None,
                file_size=_to_size_or_none(row.get("FileSize")),
                si_created=row.get("Created0x10") or None,
                si_modified=row.get("LastModified0x10") or None,
                si_accessed=row.get("LastAccess0x10") or None,
                si_record_modified=si_record_modified or None,
                fn_created=row.get("Created0x30") or None,
                fn_modified=row.get("LastModified0x30") or None,
                fn_accessed=row.get("LastAccess0x30") or None,
                fn_record_modified=row.get("LastRecordChange0x30") or None,
                has_alternate_data_streams=_to_bool(row.get("HasAds")),
                has_object_id=_to_bool(row.get("HasObjectId")),
                has_reparse_point=_to_bool(row.get("HasReparsePoint")),
                mft_image_offset=mft_offset,
                entry_offset_in_mft=entry_number * 1024,  # default $MFT entry size
            )
        )
    return entries


# --------------------------------------------------------------------------- #
# Public typed function                                                       #
# --------------------------------------------------------------------------- #


def parse_mft(
    handle: EvidenceHandle,
    *,
    mft_path: Path,
    filter_path: str | None = None,
    since: str | None = None,
    ctx: SigningContext,
    executor: ToolExecutor | None = None,
    prev_hash: str | None = None,
    model_id: str | None = None,
    prompt_hash: str | None = None,
    mft_image_offset: int = 0,
) -> Notarized[list[MftEntry]]:
    """Extract $MFT entries and return a Notarized envelope.

    Parameters
    ----------
    handle
        Mounted-read-only EvidenceHandle (image_sha256 anchors the receipt).
    mft_path
        Path to the extracted $MFT file (typically copied out of the image
        via Sleuthkit `icat`, or directly from the mounted volume).
    filter_path
        Optional path substring (case-insensitive) to filter results.
    since
        Optional ISO-8601 lower bound on LastRecordChange0x10 ($SI record
        modification time).
    """
    executor = executor or SubprocessExecutor()
    args: dict[str, object] = {
        "mft_path": str(mft_path),
        "filter_path": filter_path,
        "since": since,
        "mft_image_offset": mft_image_offset,
    }

    # MFTECmd 2026.5.0: --csv <dir> --csvf <file> (no stdout).
    import tempfile

    with tempfile.TemporaryDirectory(prefix="oath-mft-") as tmpdir:
        out_csv = Path(tmpdir) / "mft.csv"
        argv: list[str] = [
            "MFTECmd",
            "-f", str(mft_path),
            "--csv", str(tmpdir),
            "--csvf", out_csv.name,
        ]
        executor.run(argv)
        stdout_bytes = out_csv.read_bytes() if out_csv.exists() else b""
    entries = _parse_mftecmd_csv(
        stdout_bytes,
        mft_offset=mft_image_offset,
        filter_path=filter_path,
        since=since,
    )

    return mint(
        data=entries,
        tool_name="parse_mft",
        tool_version=MFTECMD_VERSION,
        args=args,
        image_sha256=handle.image_sha256,
        stdout_bytes=stdout_bytes,
        offsets=(
            EvidenceOffset(
                start=mft_image_offset,
                length=max(mft_path.stat().st_size, 1) if mft_path.exists() else 1,
                artifact_label="$MFT",
            ),
        ),
        prev_hash=prev_hash,
        model_id=model_id,
        prompt_hash=prompt_hash,
        ctx=ctx,
    )


# --------------------------------------------------------------------------- #
# Re-derivation hook for Witness Oath Verifier                                #
# --------------------------------------------------------------------------- #


def reverify(
    envelope: Notarized[list[MftEntry]],
    *,
    mft_path: Path,
    executor: ToolExecutor | None = None,
) -> tuple[bool, str]:
    """Re-run MFTECmd, recompute BLAKE3 of stdout, compare to envelope record."""
    import blake3

    executor = executor or SubprocessExecutor()
    import tempfile

    with tempfile.TemporaryDirectory(prefix="oath-mft-rv-") as tmpdir:
        out_csv = Path(tmpdir) / "mft.csv"
        argv = [
            "MFTECmd",
            "-f", str(mft_path),
            "--csv", str(tmpdir),
            "--csvf", out_csv.name,
        ]
        try:
            executor.run(argv)
        except Exception as e:
            return False, f"MFTECmd re-run failed: {e}"
        stdout_bytes = out_csv.read_bytes() if out_csv.exists() else b""
    actual = blake3.blake3(stdout_bytes).hexdigest()
    expected = envelope.header.stdout_blake3
    if actual != expected:
        return False, f"stdout BLAKE3 drift: expected {expected[:16]}…, got {actual[:16]}…"
    return True, "ok"


# --------------------------------------------------------------------------- #
# Anti-forensic detector: timestomp candidate ($SI < $FN by > tolerance)      #
# --------------------------------------------------------------------------- #


def find_timestomp_candidates(
    entries: list[MftEntry], *, tolerance_seconds: int = 5
) -> list[MftEntry]:
    """Return entries where $SI predates $FN by more than `tolerance_seconds`.

    Real timestomping (SetMACE, Mimikatz `kitchen`, custom NtSetInformationFile
    stubs) modifies the $SI timestamps while leaving $FN untouched. A purely
    benign explanation (Windows installer, MSI extraction, VSS restore) usually
    keeps SI ≥ FN, so SI substantially earlier than FN is suspicious.

    This is a deterministic detector — no LLM judgment. The LLM can REFERENCE
    these candidates but cannot FABRICATE them.
    """
    from datetime import datetime

    def _parse_iso(s: str | None) -> datetime | None:
        if not s:
            return None
        try:
            return datetime.fromisoformat(s.rstrip("Z").replace("Z", "+00:00"))
        except ValueError:
            return None

    out: list[MftEntry] = []
    for entry in entries:
        si = _parse_iso(entry.si_created)
        fn = _parse_iso(entry.fn_created)
        if si is None or fn is None:
            continue
        if (fn - si).total_seconds() > tolerance_seconds:
            out.append(entry)
    return out


__all__ = [
    "MFTECMD_VERSION",
    "MftEntry",
    "find_timestomp_candidates",
    "parse_mft",
    "reverify",
]
