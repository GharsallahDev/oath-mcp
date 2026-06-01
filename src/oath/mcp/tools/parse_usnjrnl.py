"""parse_usnjrnl — typed MCP function for NTFS $UsnJrnl ($J) extraction.

Wraps MFTECmd's `--json $J` mode against the extracted $UsnJrnl:$J alternate
data stream. Produces a `Notarized[list[UsnRecord]]` binding every record to
the source image SHA-256 + MFTECmd version.

Why $UsnJrnl matters for autonomous triage
------------------------------------------
The USN journal is NTFS's continuous changelog of file system events: create,
delete, rename, data-overwrite, EA changes, named-data-stream changes. For
incident response it answers a question $MFT alone can't:

  "What happened to this file between observed timestamp T-5 and T+5?"

Three high-value autonomous-IR signals live in $J:

  1. Deletion traces (`USN_REASON_FILE_DELETE`): the attacker's clean-up step.
     Even when $MFT entries have been recycled, the journal entry persists
     until the journal wraps. Pair with parse_mft to confirm an artifact
     was deleted, not just inaccessible.

  2. Rename traces: PsExec drops `PSEXESVC.exe` then renames it to a benign-
     looking name. $MFT only shows the final name; $J shows the rename event.

  3. Stream-creation events: alternate data streams (ADS) used for
     persistence (e.g. `Zone.Identifier` stripping) are visible only as $J
     `USN_REASON_NAMED_DATA_OVERWRITE` events.

The Witness Oath Verifier re-runs MFTECmd against the same $J path and
confirms the BLAKE3 of stdout matches. Anti-forensic operators who edit $J
directly (rare but possible via raw disk writes) are caught by the drift.
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

# Same MFTECmd binary; the version match here is intentional. We list it
# independently in case the typed surfaces diverge across versions.
MFTECMD_VERSION = "2026.5.0"


# Canonical USN reason codes (subset most often triaged). MFTECmd emits the
# `UpdateReasons` column as a pipe-joined string; we surface a typed enum-like
# set for the LLM to filter on without re-parsing.
USN_REASON_FILE_DELETE = "FileDelete"
USN_REASON_FILE_CREATE = "FileCreate"
USN_REASON_RENAME_NEW = "RenameNewName"
USN_REASON_RENAME_OLD = "RenameOldName"
USN_REASON_DATA_OVERWRITE = "DataOverwrite"
USN_REASON_DATA_EXTEND = "DataExtend"
USN_REASON_DATA_TRUNCATION = "DataTruncation"
USN_REASON_NAMED_DATA_OVERWRITE = "NamedDataOverwrite"
USN_REASON_OBJECT_ID_CHANGE = "ObjectIdChange"
USN_REASON_CLOSE = "Close"

ANTI_FORENSIC_REASONS = frozenset(
    {
        USN_REASON_FILE_DELETE,
        USN_REASON_RENAME_NEW,
        USN_REASON_RENAME_OLD,
        USN_REASON_DATA_OVERWRITE,
        USN_REASON_NAMED_DATA_OVERWRITE,
    }
)


# --------------------------------------------------------------------------- #
# Typed schema                                                                #
# --------------------------------------------------------------------------- #


class UsnRecord(BaseModel):
    """One $UsnJrnl:$J record from MFTECmd's CSV output.

    Schema (MFTECmd v1.2.2.0 USN mode):
      UpdateTimestamp, UpdateSequenceNumber, UpdateReasons, FileAttributes,
      OffsetToData, ParentFileRecordNumber, ParentFileRecordSequenceNumber,
      FileRecordNumber, FileRecordSequenceNumber, ParentPath, FileName,
      Extension, SecurityId, SourceInfo
    """

    model_config = ConfigDict(frozen=True)

    timestamp: str = Field(..., description="Update timestamp (ISO-8601 UTC).")
    usn: int = Field(..., ge=0, description="UpdateSequenceNumber.")
    update_reasons: tuple[str, ...] = Field(
        default=(),
        description="MFTECmd's UpdateReasons split on '|'. See USN_REASON_* constants.",
    )

    # File identity (resolved via parent-traversal at MFTECmd time)
    file_name: str
    file_extension: str | None = None
    full_path: str | None = None

    # NTFS records this row points at
    file_record_number: int = Field(..., ge=0)
    file_record_sequence_number: int = Field(..., ge=0)
    parent_file_record_number: int = Field(..., ge=0)
    parent_file_record_sequence_number: int = Field(..., ge=0)

    # Source flags (helps distinguish OS-internal events from user/attacker)
    source_info: str | None = None
    security_id: int | None = None

    # Provenance back into the source image
    j_image_offset: int = Field(..., ge=0, description="Byte offset of $UsnJrnl:$J.")
    record_offset_in_j: int = Field(..., ge=0)


def _to_int_or_none(s: str | None) -> int | None:
    if s is None or not s.strip():
        return None
    try:
        return int(s.strip())
    except ValueError:
        return None


# --------------------------------------------------------------------------- #
# Parser                                                                      #
# --------------------------------------------------------------------------- #


def _parse_usnjrnl_csv(
    csv_bytes: bytes,
    *,
    j_offset: int,
    reason_filter: set[str] | None,
    since: str | None,
) -> list[UsnRecord]:
    """Parse MFTECmd's $J CSV output into typed records."""
    records: list[UsnRecord] = []
    reader = csv.DictReader(io.StringIO(csv_bytes.decode("utf-8-sig", errors="replace")))
    for i, row in enumerate(reader):
        usn = _to_int_or_none(row.get("UpdateSequenceNumber"))
        if usn is None:
            continue

        ts = row.get("UpdateTimestamp", "")
        if since and ts and ts < since:
            continue

        reasons_raw = row.get("UpdateReasons", "") or ""
        reasons = tuple(r.strip() for r in reasons_raw.split("|") if r.strip())
        if reason_filter and not (set(reasons) & reason_filter):
            continue

        full_path = (row.get("ParentPath") or "").rstrip("\\/")
        file_name = row.get("Name", "")
        joined_path = f"{full_path}\\{file_name}" if full_path else file_name

        records.append(
            UsnRecord(
                timestamp=ts,
                usn=usn,
                update_reasons=reasons,
                file_name=file_name,
                file_extension=row.get("Extension") or None,
                full_path=joined_path or None,
                file_record_number=_to_int_or_none(row.get("EntryNumber")) or 0,
                file_record_sequence_number=_to_int_or_none(
                    row.get("SequenceNumber")
                )
                or 0,
                parent_file_record_number=_to_int_or_none(row.get("ParentEntryNumber"))
                or 0,
                parent_file_record_sequence_number=_to_int_or_none(
                    row.get("ParentSequenceNumber")
                )
                or 0,
                source_info=row.get("SourceInfo") or None,
                security_id=_to_int_or_none(row.get("SecurityId")),
                j_image_offset=j_offset,
                record_offset_in_j=i * 96,  # USN_RECORD_V2 typical size; placeholder
            )
        )
    return records


# --------------------------------------------------------------------------- #
# Public typed function                                                       #
# --------------------------------------------------------------------------- #


def parse_usnjrnl(
    handle: EvidenceHandle,
    *,
    j_path: Path,
    reason_filter: list[str] | None = None,
    since: str | None = None,
    filter_path: str | None = None,
    ctx: SigningContext,
    executor: ToolExecutor | None = None,
    prev_hash: str | None = None,
    j_image_offset: int = 0,
) -> Notarized[list[UsnRecord]]:
    """Extract $UsnJrnl:$J records.

    Parameters
    ----------
    handle
        Mounted-read-only EvidenceHandle.
    j_path
        Absolute path to the extracted $UsnJrnl:$J stream (typically copied
        out via Sleuthkit `icat` or directly from the mounted volume).
    reason_filter
        Optional list of USN reason names (e.g. ["FileDelete", "RenameNewName"]).
        Matches the typed constants in this module — see USN_REASON_*.
    since
        Optional ISO-8601 lower bound on UpdateTimestamp.
    filter_path
        Optional case-insensitive substring filter on full_path.
    """
    executor = executor or SubprocessExecutor()
    normalized_filter = (
        {r.strip() for r in reason_filter if r.strip()} if reason_filter else None
    )
    args: dict[str, object] = {
        "j_path": str(j_path),
        "reason_filter": sorted(normalized_filter) if normalized_filter else None,
        "since": since,
        "filter_path": filter_path,
        "j_image_offset": j_image_offset,
    }

    # MFTECmd 2026.5.0 ($J mode): --csv <dir> --csvf <file>.
    import tempfile

    with tempfile.TemporaryDirectory(prefix="oath-usn-") as tmpdir:
        out_csv = Path(tmpdir) / "usn.csv"
        argv: list[str] = [
            "MFTECmd",
            "-f", str(j_path),
            "--csv", str(tmpdir),
            "--csvf", out_csv.name,
        ]
        executor.run(argv)
        stdout_bytes = out_csv.read_bytes() if out_csv.exists() else b""
    records = _parse_usnjrnl_csv(
        stdout_bytes,
        j_offset=j_image_offset,
        reason_filter=normalized_filter,
        since=since,
    )

    # Apply optional path filter post-parse (MFTECmd doesn't have one for $J)
    if filter_path:
        needle = filter_path.lower()
        records = [r for r in records if r.full_path and needle in r.full_path.lower()]

    return mint(
        data=records,
        tool_name="parse_usnjrnl",
        tool_version=MFTECMD_VERSION,
        args=args,
        image_sha256=handle.image_sha256,
        stdout_bytes=stdout_bytes,
        offsets=(
            EvidenceOffset(
                start=j_image_offset,
                length=max(j_path.stat().st_size, 1) if j_path.exists() else 1,
                artifact_label="$UsnJrnl:$J",
            ),
        ),
        prev_hash=prev_hash,
        ctx=ctx,
    )


def reverify(
    envelope: Notarized[list[UsnRecord]],
    *,
    j_path: Path,
    executor: ToolExecutor | None = None,
) -> tuple[bool, str]:
    """Re-run MFTECmd on the same $J; recompute BLAKE3 of stdout; compare."""
    import blake3

    executor = executor or SubprocessExecutor()
    import tempfile

    with tempfile.TemporaryDirectory(prefix="oath-usn-rv-") as tmpdir:
        out_csv = Path(tmpdir) / "usn.csv"
        argv = [
            "MFTECmd",
            "-f", str(j_path),
            "--csv", str(tmpdir),
            "--csvf", out_csv.name,
        ]
        try:
            executor.run(argv)
        except Exception as e:
            return False, f"MFTECmd ($J) re-run failed: {e}"
        stdout_bytes = out_csv.read_bytes() if out_csv.exists() else b""
    actual = blake3.blake3(stdout_bytes).hexdigest()
    expected = envelope.header.stdout_blake3
    if actual != expected:
        return False, f"stdout BLAKE3 drift: expected {expected[:16]}…, got {actual[:16]}…"
    return True, "ok"


# --------------------------------------------------------------------------- #
# Anti-forensic detection helpers                                             #
# --------------------------------------------------------------------------- #


def find_deletion_events(records: list[UsnRecord]) -> list[UsnRecord]:
    """Return records with a FileDelete update reason.

    The single highest-signal anti-forensic indicator $J surfaces. Pair with
    parse_amcache + parse_prefetch to corroborate "this binary existed,
    executed, then was deleted."
    """
    return [r for r in records if USN_REASON_FILE_DELETE in r.update_reasons]


def find_rename_pairs(records: list[UsnRecord]) -> list[tuple[UsnRecord, UsnRecord]]:
    """Return (old_record, new_record) rename pairs.

    Two records with the same FileRecordNumber, sharing a single rename
    operation: one carries RenameOldName, the other RenameNewName. Useful for
    detecting "drop binary as benign-looking name; immediately rename to
    target name" patterns (or the reverse for cleanup).
    """
    by_frn: dict[int, list[UsnRecord]] = {}
    for r in records:
        if USN_REASON_RENAME_OLD in r.update_reasons or USN_REASON_RENAME_NEW in r.update_reasons:
            by_frn.setdefault(r.file_record_number, []).append(r)

    pairs: list[tuple[UsnRecord, UsnRecord]] = []
    for frn, rs in by_frn.items():
        rs_sorted = sorted(rs, key=lambda r: (r.timestamp, r.usn))
        old = next((r for r in rs_sorted if USN_REASON_RENAME_OLD in r.update_reasons), None)
        new = next((r for r in rs_sorted if USN_REASON_RENAME_NEW in r.update_reasons), None)
        if old is not None and new is not None:
            pairs.append((old, new))
    return pairs


__all__ = [
    "ANTI_FORENSIC_REASONS",
    "MFTECMD_VERSION",
    "USN_REASON_DATA_EXTEND",
    "USN_REASON_DATA_OVERWRITE",
    "USN_REASON_DATA_TRUNCATION",
    "USN_REASON_FILE_CREATE",
    "USN_REASON_FILE_DELETE",
    "USN_REASON_NAMED_DATA_OVERWRITE",
    "USN_REASON_RENAME_NEW",
    "USN_REASON_RENAME_OLD",
    "UsnRecord",
    "find_deletion_events",
    "find_rename_pairs",
    "parse_usnjrnl",
    "reverify",
]
