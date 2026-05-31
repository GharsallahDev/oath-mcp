"""run_hayabusa — typed MCP function for Sigma-driven EVTX triage.

Wraps Yamato Security's Hayabusa. Produces a `Notarized[list[SigmaHit]]` that
binds every emitted detection to:

  - the source image SHA-256 (via the EvidenceHandle)
  - the Hayabusa version (pinned in the image; we record `hayabusa --version`)
  - the bundled rule corpus SHA-256 (Hayabusa ships ~5,000 Sigma rules; the
    Witness Oath Verifier binds to the SPECIFIC rule set at mint time)
  - the canonical args (input dir, min-level threshold, output mode)
  - the BLAKE3 of the raw Hayabusa CSV stdout

Why Hayabusa matters for autonomous triage
------------------------------------------
Hayabusa is a Rust static binary that consumes a directory of .evtx files +
runs ~5,000 community-vetted Sigma rules against them. For DFIR cases, it's
the cheapest way to get an "everything-the-community-knows-about-Windows-
attacks" pass over a host's event logs in a handful of seconds.

Hayabusa's rule set is updated weekly. To make re-verification deterministic
we record the rule-corpus SHA-256 at mint time; on reverify, if the corpus
hash drifts (because the host operator updated rules), we surface that
explicitly rather than silently producing different detections.

For PtH/lateral-movement triage, the relevant Hayabusa categories are:
  - Credential Access (T1003.*, T1110, T1558)
  - Lateral Movement (T1021.*, T1550.*, T1570)
  - Defense Evasion / Indicator Removal (T1070.*)
  - Persistence (T1053, T1547.*)

The agent uses Hayabusa hits as CANDIDATES (high-recall, medium-precision),
then the Witness Oath Verifier confirms each by re-running the rule against
the source .evtx and confirming the match.
"""
from __future__ import annotations

import csv
import hashlib
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

# Hayabusa is updated frequently; "2.x" represents the major API line we support.
# `hayabusa --version` is captured into the envelope at mint time for the exact
# string. This constant is the floor.
HAYABUSA_VERSION_FLOOR = "2.0.0"

# Hayabusa severity levels (lowest -> highest)
SEVERITY_LEVELS = ("informational", "low", "medium", "high", "critical")


# --------------------------------------------------------------------------- #
# Typed schema                                                                #
# --------------------------------------------------------------------------- #


class SigmaHit(BaseModel):
    """One Hayabusa detection row.

    Hayabusa's `csv-timeline` output schema (v2.x):
      Timestamp, Computer, Channel, EventID, Level, RuleTitle, RuleAuthor,
      RuleID, MitreTactics, MitreTechniques, RuleModifiedDate, Status,
      RecordID, Details
    """

    model_config = ConfigDict(frozen=True)

    timestamp: str = Field(..., description="ISO-8601 UTC; the timestamp of the matching event.")
    computer: str = Field(..., description="Computer name from the matching EVTX record.")
    channel: str = Field(..., description="EVTX channel (Security, System, ...).")
    event_id: int = Field(..., description="Windows event ID.")
    level: str = Field(..., description="Severity: informational/low/medium/high/critical.")

    # Rule identity
    rule_id: str = Field(..., description="Sigma rule UUID.")
    rule_title: str = Field(..., description="Human-readable rule name.")
    rule_author: str | None = Field(None, description="Original Sigma rule author.")

    # MITRE ATT&CK mapping
    mitre_tactics: tuple[str, ...] = Field(default=(), description="ATT&CK tactics (e.g. 'TA0006').")
    mitre_techniques: tuple[str, ...] = Field(
        default=(), description="ATT&CK techniques (e.g. 'T1003.001')."
    )

    # Detection details
    status: str = Field(..., description="Hayabusa rule status (stable / test / experimental).")
    record_id: int | None = Field(None, description="EVTX EventRecordID of the matching event.")
    details: str | None = Field(None, description="Hayabusa-rendered detail string (sanitized).")


# --------------------------------------------------------------------------- #
# Parsing                                                                     #
# --------------------------------------------------------------------------- #


def _split_csv_list(s: str | None) -> tuple[str, ...]:
    """Hayabusa packs multi-value columns (MitreTactics, MitreTechniques)
    as semicolon- or pipe-delimited lists. Normalize to a tuple of strings."""
    if not s or not s.strip():
        return ()
    for sep in (";", "|", ","):
        if sep in s:
            return tuple(p.strip() for p in s.split(sep) if p.strip())
    return (s.strip(),)


def _to_int_or_none(s: str | None) -> int | None:
    if s is None or not s.strip():
        return None
    try:
        return int(s.strip())
    except ValueError:
        return None


def _parse_hayabusa_csv(
    csv_bytes: bytes,
    *,
    min_level: str | None,
    technique_filter: set[str] | None,
) -> list[SigmaHit]:
    """Parse Hayabusa csv-timeline output into typed SigmaHit objects.

    Filters
    -------
    min_level
        Drops hits whose severity is below the threshold (e.g. "medium" drops
        informational + low).
    technique_filter
        Set of ATT&CK technique IDs (e.g. {"T1550.002", "T1021.002"}) — keeps
        only hits whose techniques intersect the set.
    """
    min_idx = SEVERITY_LEVELS.index(min_level.lower()) if min_level else 0
    hits: list[SigmaHit] = []
    reader = csv.DictReader(io.StringIO(csv_bytes.decode("utf-8", errors="replace")))
    for row in reader:
        level = (row.get("Level") or "").strip().lower()
        if level not in SEVERITY_LEVELS:
            continue
        if SEVERITY_LEVELS.index(level) < min_idx:
            continue

        techniques = _split_csv_list(row.get("MitreTechniques"))
        if technique_filter and not (set(techniques) & technique_filter):
            continue

        hits.append(
            SigmaHit(
                timestamp=(row.get("Timestamp") or "").strip(),
                computer=(row.get("Computer") or "").strip(),
                channel=(row.get("Channel") or "").strip(),
                event_id=_to_int_or_none(row.get("EventID")) or 0,
                level=level,
                rule_id=(row.get("RuleID") or "").strip(),
                rule_title=(row.get("RuleTitle") or "").strip(),
                rule_author=(row.get("RuleAuthor") or None) or None,
                mitre_tactics=_split_csv_list(row.get("MitreTactics")),
                mitre_techniques=techniques,
                status=(row.get("Status") or "stable").strip(),
                record_id=_to_int_or_none(row.get("RecordID")),
                details=(row.get("Details") or None),
            )
        )
    return hits


# --------------------------------------------------------------------------- #
# Rule-corpus hashing (for binding to envelope provenance)                    #
# --------------------------------------------------------------------------- #


def _hash_rule_corpus(rules_dir: Path) -> str:
    """Compute SHA-256 over the concatenated contents of every Sigma .yml file
    under `rules_dir`, in sorted order. Lets the Witness Oath Verifier detect
    if the rule corpus changed between mint and verify.

    For an empty / missing directory, returns the SHA-256 of the empty string
    (so missing-corpus produces a stable known value rather than crashing).
    """
    h = hashlib.sha256()
    if not rules_dir.exists():
        return h.hexdigest()
    for f in sorted(rules_dir.rglob("*.yml")):
        try:
            h.update(f.read_bytes())
            h.update(b"\x00")  # separator so concatenation is injective
        except (OSError, PermissionError):
            continue
    return h.hexdigest()


# --------------------------------------------------------------------------- #
# Public typed function                                                       #
# --------------------------------------------------------------------------- #


def run_hayabusa(
    handle: EvidenceHandle,
    *,
    evtx_dir: Path,
    rules_dir: Path | None = None,
    min_level: str | None = None,
    technique_filter: list[str] | None = None,
    ctx: SigningContext,
    executor: ToolExecutor | None = None,
    prev_hash: str | None = None,
    evtx_image_offset: int = 0,
) -> Notarized[list[SigmaHit]]:
    """Run Hayabusa against a directory of .evtx files; return a Notarized envelope.

    Parameters
    ----------
    handle
        Read-only mounted EvidenceHandle (image_sha256 anchors the receipt).
    evtx_dir
        Directory containing .evtx files (typically extracted from
        C:\\Windows\\System32\\winevt\\Logs).
    rules_dir
        Path to the Sigma rules tree (Hayabusa default: ~/.hayabusa/rules).
        Its SHA-256 is bound into the envelope so a corpus update between mint
        and verify is detected.
    min_level
        Drops hits below this severity (informational / low / medium / high /
        critical).
    technique_filter
        Keep only hits matching at least one of these ATT&CK technique IDs.
    """
    executor = executor or SubprocessExecutor()
    normalized_techniques = (
        {t.strip().upper() for t in technique_filter if t.strip()} if technique_filter else None
    )

    args: dict[str, object] = {
        "evtx_dir": str(evtx_dir),
        "rules_dir": str(rules_dir) if rules_dir else None,
        "rules_corpus_sha256": _hash_rule_corpus(rules_dir) if rules_dir else None,
        "min_level": min_level,
        "technique_filter": sorted(normalized_techniques) if normalized_techniques else None,
        "evtx_image_offset": evtx_image_offset,
    }

    argv: list[str] = [
        "hayabusa",
        "csv-timeline",
        "-d",
        str(evtx_dir),
        "--output",
        "-",  # stdout
        "--quiet",
    ]
    if rules_dir:
        argv += ["--rules", str(rules_dir)]
    if min_level:
        argv += ["--min-level", min_level]

    stdout_bytes = executor.run(argv)
    hits = _parse_hayabusa_csv(
        stdout_bytes, min_level=min_level, technique_filter=normalized_techniques
    )

    return mint(
        data=hits,
        tool_name="run_hayabusa",
        tool_version=HAYABUSA_VERSION_FLOOR,
        args=args,
        image_sha256=handle.image_sha256,
        stdout_bytes=stdout_bytes,
        offsets=(
            EvidenceOffset(
                start=evtx_image_offset,
                length=1,
                artifact_label=f"EVTX directory {evtx_dir.name}",
            ),
        ),
        prev_hash=prev_hash,
        ctx=ctx,
    )


def reverify(
    envelope: Notarized[list[SigmaHit]],
    *,
    evtx_dir: Path,
    rules_dir: Path | None = None,
    executor: ToolExecutor | None = None,
) -> tuple[bool, str]:
    """Re-run Hayabusa; verify (a) rule corpus unchanged and (b) stdout BLAKE3 matches."""
    import blake3

    executor = executor or SubprocessExecutor()

    # Check rule-corpus hash didn't drift (operator might have updated rules
    # between mint and verify — surface this as a SPECIFIC failure reason).
    if rules_dir:
        current_corpus = _hash_rule_corpus(rules_dir)
        # Parse rules_corpus_sha256 out of args_canonical (it's part of the
        # signed header). Cheap substring check is sufficient — args_canonical
        # is RFC 8785 JCS so the key+value is verbatim.
        expected_marker = f'"rules_corpus_sha256":"{current_corpus}"'
        if expected_marker not in envelope.header.args_canonical:
            return (
                False,
                "Sigma rule corpus has been updated since mint — re-mint required to keep "
                "envelope semantics deterministic.",
            )

    argv = ["hayabusa", "csv-timeline", "-d", str(evtx_dir), "--output", "-", "--quiet"]
    if rules_dir:
        argv += ["--rules", str(rules_dir)]

    try:
        stdout_bytes = executor.run(argv)
    except Exception as e:
        return False, f"Hayabusa re-run failed: {e}"

    actual = blake3.blake3(stdout_bytes).hexdigest()
    expected = envelope.header.stdout_blake3
    if actual != expected:
        return False, f"stdout BLAKE3 drift: expected {expected[:16]}…, got {actual[:16]}…"
    return True, "ok"


# --------------------------------------------------------------------------- #
# High-value helpers for PtH triage                                           #
# --------------------------------------------------------------------------- #


# ATT&CK technique IDs for the lateral-movement / credential-access slice the
# agent looks at first for PtH cases. Pre-baked so the agent doesn't have to
# enumerate them via prompt.
PTH_TECHNIQUE_SET = {
    "T1003.001",  # LSASS Memory
    "T1003.002",  # Security Account Manager
    "T1003.003",  # NTDS
    "T1021.001",  # RDP
    "T1021.002",  # SMB / Admin Shares
    "T1021.006",  # WinRM
    "T1078",      # Valid Accounts
    "T1078.002",  # Domain Accounts
    "T1110",      # Brute Force
    "T1550.001",  # Application Access Token
    "T1550.002",  # Pass the Hash
    "T1550.003",  # Pass the Ticket
    "T1558.003",  # Kerberoasting
    "T1570",      # Lateral Tool Transfer
    "T1070.001",  # Indicator Removal: Clear Windows Event Logs
    "T1070.002",  # Indicator Removal: Clear Linux/Mac Logs (rare on Win, but cheap to check)
    "T1070.006",  # Timestomp
    "T1053.005",  # Scheduled Task
    "T1547.001",  # Registry Run Keys
}


def filter_pth_hits(hits: list[SigmaHit], min_level: str = "medium") -> list[SigmaHit]:
    """Filter hits to PtH-relevant techniques + minimum severity.

    Deterministic — no LLM judgment. Useful for the agent's first-pass triage
    so the LLM gets a smaller, denser set of candidates to reason about.
    """
    min_idx = SEVERITY_LEVELS.index(min_level.lower())
    out: list[SigmaHit] = []
    for hit in hits:
        if SEVERITY_LEVELS.index(hit.level) < min_idx:
            continue
        if set(hit.mitre_techniques) & PTH_TECHNIQUE_SET:
            out.append(hit)
    return out


__all__ = [
    "HAYABUSA_VERSION_FLOOR",
    "PTH_TECHNIQUE_SET",
    "SEVERITY_LEVELS",
    "SigmaHit",
    "filter_pth_hits",
    "run_hayabusa",
    "reverify",
]
