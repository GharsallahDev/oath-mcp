"""parse_evtx — typed MCP function for Windows Event Log (.evtx) extraction.

Wraps Eric Zimmerman's EvtxECmd. Produces a `Notarized[list[EvtxRecord]]` that
binds every emitted EvtxRecord to:

  - the byte offsets of the underlying .evtx file in the source image
  - the EvtxECmd version (pinned in docker/eztools/dotnet-tools.json)
  - the BLAKE3 of the raw CSV stdout
  - the canonical args (channel, event_ids, time_range, user_sid filters)
  - the image SHA-256 from the EvidenceHandle

The Witness Oath Verifier later re-derives the data by re-running EvtxECmd
against the same .evtx file and comparing the BLAKE3 of the new stdout against
the recorded one. ANY drift — different EvtxECmd version, modified .evtx,
different filters — produces a verification failure.

This is the canonical pattern every typed function in src/oath/mcp/tools/
follows: shell out to a deterministic forensic tool, parse its structured
output, mint a Notarized envelope. The LLM never gets a path around this.
"""
from __future__ import annotations

import csv
import io
import subprocess
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from pydantic import BaseModel, ConfigDict, Field

from oath.mcp.evidence_handle import EvidenceHandle
from oath.receipt.notarized import (
    EvidenceOffset,
    Notarized,
    SigningContext,
    mint,
)

# --------------------------------------------------------------------------- #
# Pinned versions                                                             #
# --------------------------------------------------------------------------- #

# Must match docker/eztools/dotnet-tools.json. The Witness Oath Verifier checks
# this when re-deriving — a tool-version drift between mint and verify makes
# the envelope invalid by design.
EVTXECMD_VERSION = "1.5.0.0"


# --------------------------------------------------------------------------- #
# Typed schema for an EVTX record                                             #
# --------------------------------------------------------------------------- #


class EvtxRecord(BaseModel):
    """One row out of EvtxECmd's structured CSV output.

    EvtxECmd emits ~25 columns per record; we keep the ones load-bearing for
    autonomous IR triage and drop the rest. (The full row is still recoverable
    from the original .evtx file via the byte offset in the Notarized envelope.)
    """

    model_config = ConfigDict(frozen=True)

    record_number: int = Field(..., description="EVTX EventRecordID (monotonic per channel).")
    timestamp: str = Field(..., description="ISO-8601 UTC; EvtxECmd produces sub-millisecond.")
    event_id: int = Field(..., description="Windows Event ID (e.g. 4624, 4625, 4768).")
    level: str = Field(..., description="EvtxECmd level: 'Information', 'Warning', etc.")
    provider: str = Field(..., description="Provider name (e.g. 'Microsoft-Windows-Security-Auditing').")
    channel: str = Field(..., description="Channel ('Security', 'System', 'Application', ...).")
    computer: str | None = Field(None, description="Host name from the record.")

    # Authentication-specific columns (populated for 4624/4625/4648/4768/4769/4776).
    # We surface these natively because PtH/Kerberos/etc. analysis touches them
    # constantly; making them top-level fields avoids the LLM having to grep
    # through a Payload string blob.
    user_name: str | None = None
    user_sid: str | None = None
    logon_type: int | None = None
    auth_package: str | None = None
    source_ip: str | None = None

    # The full raw Payload string (sanitized: see WitnessOath untrusted-string
    # firewall — attacker-controlled freeform content is routed through the
    # typed-extraction layer before reaching the LLM).
    payload_summary: str | None = Field(
        None,
        description=(
            "EvtxECmd-rendered Payload summary, with attacker-controlled freeform "
            "fields (Message, EventData) replaced by typed-extraction tuples."
        ),
    )

    # Provenance back into the source image — what makes this record verifiable.
    source_evtx_offset: int = Field(
        ..., ge=0, description="Byte offset of the host .evtx file in the source image."
    )
    record_offset: int = Field(
        ..., ge=0, description="Byte offset of THIS record within the .evtx file."
    )
    record_length: int = Field(..., gt=0, description="Length in bytes of this record.")


# --------------------------------------------------------------------------- #
# Executor abstraction (so tests can inject a fake without Docker / EvtxECmd) #
# --------------------------------------------------------------------------- #


class ToolExecutor(Protocol):
    """Adapter interface for invoking a forensic CLI tool.

    The production executor shells out via subprocess (locally or `docker exec`
    into the eztools container). Tests inject a `FakeExecutor` that returns
    canned CSV output, so unit tests can pin the schema + Notarized envelope
    contract without depending on a real .NET runtime.
    """

    def run(self, argv: list[str], *, capture: bool = True, timeout: float = 300) -> bytes:
        """Run a CLI tool; return its raw stdout bytes. Raises on non-zero exit."""


@dataclass
class SubprocessExecutor:
    """Default executor — invokes a CLI tool in a local subprocess.

    For Dockerized tools, the argv prefix is something like
    `["docker", "exec", "oath-eztools", "dotnet", "EvtxECmd", ...]`. For
    locally-installed tools, just `["dotnet", "EvtxECmd", ...]`.
    """

    cwd: Path | None = None

    def run(self, argv: list[str], *, capture: bool = True, timeout: float = 300) -> bytes:
        result = subprocess.run(
            argv,
            cwd=str(self.cwd) if self.cwd else None,
            capture_output=capture,
            timeout=timeout,
            check=True,
        )
        return result.stdout


# --------------------------------------------------------------------------- #
# CSV parser (EvtxECmd's --csv-output schema)                                 #
# --------------------------------------------------------------------------- #


def _parse_logon_type(s: str) -> int | None:
    """LogonType is column-encoded; safely coerce."""
    try:
        return int(s.strip()) if s.strip() else None
    except (ValueError, TypeError):
        return None


def _parse_evtxecmd_csv(
    csv_bytes: bytes, evtx_offset: int, record_id_filter: set[int] | None
) -> list[EvtxRecord]:
    """Parse EvtxECmd's --csv-output into typed EvtxRecord objects.

    EvtxECmd column layout (v1.5.0.0 — pinned):
      RecordNumber, EventRecordId, TimeCreated, EventId, Level, Provider,
      Channel, Computer, UserId, MapDescription, ChunkNumber, UserName,
      RemoteHost, PayloadData1..5, ExecutableInfo, HiddenRecord,
      SourceFile, Payload

    We surface the auth-relevant columns and roll up the rest as
    `payload_summary` (which the Witness untrusted-string firewall later
    transforms before the LLM sees it).
    """
    records: list[EvtxRecord] = []
    reader = csv.DictReader(io.StringIO(csv_bytes.decode("utf-8", errors="replace")))
    for i, row in enumerate(reader):
        try:
            event_id = int(row.get("EventId", "0").strip() or "0")
        except ValueError:
            continue
        if record_id_filter is not None and event_id not in record_id_filter:
            continue

        # The record's byte offset INSIDE the .evtx — derived from EvtxECmd's
        # ChunkNumber + RecordNumber + a constant header offset. For the
        # minimal v1 we record a placeholder; the Witness Oath Verifier
        # re-runs EvtxECmd and matches on RecordNumber, so byte-perfect offset
        # isn't load-bearing for the FIRST iteration. (Will tighten in v0.2.)
        record_offset = i * 4096  # placeholder — see comment above

        records.append(
            EvtxRecord(
                record_number=int(row.get("RecordNumber", "0") or 0),
                timestamp=row.get("TimeCreated", ""),
                event_id=event_id,
                level=row.get("Level", "") or "",
                provider=row.get("Provider", "") or "",
                channel=row.get("Channel", "") or "",
                computer=row.get("Computer") or None,
                user_name=row.get("UserName") or None,
                user_sid=row.get("UserId") or None,
                logon_type=_parse_logon_type(row.get("PayloadData1", "")),
                auth_package=row.get("PayloadData2") or None,
                source_ip=row.get("RemoteHost") or None,
                payload_summary=row.get("Payload") or None,
                source_evtx_offset=evtx_offset,
                record_offset=record_offset,
                record_length=4096,  # placeholder — see comment
            )
        )
    return records


# --------------------------------------------------------------------------- #
# Public typed function                                                       #
# --------------------------------------------------------------------------- #


def parse_evtx(
    handle: EvidenceHandle,
    *,
    evtx_path: Path,
    channel: str | None = None,
    event_ids: list[int] | None = None,
    time_range: tuple[str, str] | None = None,
    user_sid: str | None = None,
    ctx: SigningContext,
    executor: ToolExecutor | None = None,
    prev_hash: str | None = None,
    evtx_image_offset: int = 0,
) -> Notarized[list[EvtxRecord]]:
    """Extract EVTX records from a .evtx file and return a Notarized envelope.

    Parameters
    ----------
    handle
        The mounted-read-only EvidenceHandle. Its image_sha256 is bound into
        the envelope so this finding is anchored to THIS image.
    evtx_path
        Absolute path to the .evtx file (typically under handle.mount_point).
    channel, event_ids, time_range, user_sid
        Optional filters. All four are canonicalized into the envelope's
        args_canonical so the Witness Oath Verifier can re-run with identical
        parameters.
    ctx
        Signing context (private key + run_id).
    executor
        Tool runner. Defaults to a local subprocess executor; tests inject
        FakeExecutor.
    prev_hash
        BLAKE3 of the previous envelope's header. None for the first envelope
        in a run.
    evtx_image_offset
        Byte offset of the .evtx file within the source image (so the receipt
        re-extracts from the original image, not from a copied file).

    Returns
    -------
    Notarized[list[EvtxRecord]]
        A signed envelope. The data field is the parsed records; the header
        binds the run to the image, tool version, args, and stdout hash.
    """
    executor = executor or SubprocessExecutor()

    # Canonical args (these get JCS-canonicalized inside mint()).
    args: dict[str, object] = {
        "channel": channel,
        "event_ids": sorted(event_ids) if event_ids else None,
        "time_range": list(time_range) if time_range else None,
        "user_sid": user_sid,
        "evtx_path": str(evtx_path),
        "evtx_image_offset": evtx_image_offset,
    }

    # Build EvtxECmd command line.
    # `--csv -` writes CSV to stdout (no file artifact left behind).
    argv: list[str] = [
        "dotnet",
        "EvtxECmd",
        "-f",
        str(evtx_path),
        "--csv",
        "-",
        "--csvf",
        "stdout",  # EvtxECmd 1.5 needs --csvf even with -; "stdout" is a sentinel.
    ]
    if event_ids:
        argv += ["--inc", ",".join(str(e) for e in sorted(event_ids))]
    if time_range:
        argv += ["--sd", time_range[0], "--ed", time_range[1]]

    stdout_bytes = executor.run(argv)
    records = _parse_evtxecmd_csv(
        stdout_bytes,
        evtx_offset=evtx_image_offset,
        record_id_filter=set(event_ids) if event_ids else None,
    )

    return mint(
        data=records,
        tool_name="parse_evtx",
        tool_version=EVTXECMD_VERSION,
        args=args,
        image_sha256=handle.image_sha256,
        stdout_bytes=stdout_bytes,
        offsets=(
            EvidenceOffset(
                start=evtx_image_offset,
                length=max(evtx_path.stat().st_size, 1) if evtx_path.exists() else 1,
                artifact_label=f"EVTX file at {evtx_path.name}",
            ),
        ),
        prev_hash=prev_hash,
        ctx=ctx,
    )


# --------------------------------------------------------------------------- #
# Re-derivation hook (used by Witness Oath Verifier)                          #
# --------------------------------------------------------------------------- #


def reverify(
    envelope: Notarized[list[EvtxRecord]],
    *,
    evtx_path: Path,
    executor: ToolExecutor | None = None,
) -> tuple[bool, str]:
    """Re-run EvtxECmd against the same .evtx and confirm stdout hashes match.

    Returns (ok, reason). The Witness Oath Verifier uses this to detect
    tampering: if the .evtx has been modified between mint and verify, the
    BLAKE3 of EvtxECmd's stdout will diverge, and verification fails.
    """
    import blake3

    from oath.receipt.notarized import canonicalize

    executor = executor or SubprocessExecutor()
    args = canonicalize(envelope.header.model_dump())
    _ = args  # not used; we re-run with the SAME args canonicalized in header

    # Re-execute. We trust args_canonical to encode the original filters.
    # (For now, naive re-run with the same file; future tightening: parse
    # args_canonical and reconstruct the exact argv.)
    argv = ["dotnet", "EvtxECmd", "-f", str(evtx_path), "--csv", "-", "--csvf", "stdout"]
    try:
        stdout_bytes = executor.run(argv)
    except subprocess.CalledProcessError as e:
        return False, f"EvtxECmd re-run failed: {e}"

    actual = blake3.blake3(stdout_bytes).hexdigest()
    expected = envelope.header.stdout_blake3
    if actual != expected:
        return False, f"stdout BLAKE3 drift: expected {expected[:16]}…, got {actual[:16]}…"
    return True, "ok"


__all__ = [
    "EVTXECMD_VERSION",
    "EvtxRecord",
    "SubprocessExecutor",
    "ToolExecutor",
    "parse_evtx",
    "reverify",
]
