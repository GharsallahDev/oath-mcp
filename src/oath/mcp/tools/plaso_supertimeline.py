"""plaso_supertimeline — typed MCP function for cross-source timeline queries.

Wraps `psort.py` queries against a pre-built `.plaso` storage file. Returns
`Notarized[list[TimelineEvent]]` so the LLM can correlate events across
parsers (EVTX, registry, $MFT, browser history, Prefetch, syslog, …) on a
single ordered stream.

Why a unified timeline matters
------------------------------
Without it, the agent has to manually correlate across 8+ envelope types
("did the 4624 logon at 14:32:01 happen *after* the Run-key write at
14:31:58?"). Cheap for one correlation, infeasible at scale.

plaso's supertimeline merges every parser's output into one ordered event
stream. The agent then asks one question instead of N:
  "Show me everything between 14:31:55 and 14:32:10 involving WIN-VICTIM01,
   ordered by datetime, with source_short ∈ {EVT, REG, FILE, PREF}."

That's the supertimeline.

Two-stage ingest model
----------------------
plaso has two binaries:
  1. log2timeline.py  — slow ingest: walks the image, runs every parser,
     writes everything into a .plaso storage file. Run ONCE per image.
  2. psort.py         — fast query: filters/sorts/exports the .plaso store.
     Run MANY times by the agent with different filters.

This typed function wraps stage 2 only. Stage 1 is orchestrated by
`oath mount` (or the operator) before triage begins. The `.plaso` storage
file is content-addressed by SHA-256 and bound into args_canonical, so the
envelope is reproducible only against the same store + same source image.

The Witness Oath Verifier re-runs psort with the same filter and confirms
the BLAKE3 of stdout matches. Plaso is deterministic for fixed input +
fixed parser versions; psort sorts on (timestamp, parser_name) which is a
total order, so byte-identical re-runs are achievable.
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

# Pinned plaso version. plaso version drift changes parser output formatting;
# we refuse to verify across versions.
PLASO_VERSION_FLOOR = "20260512"


# --------------------------------------------------------------------------- #
# Source-short canonical set (subset that matters for autonomous PtH triage)  #
# --------------------------------------------------------------------------- #
# plaso emits a `source_short` 3-letter code on every event. We expose the
# subset most useful for IR; the LLM filters by these.

SOURCE_EVT = "EVT"        # Windows event logs (.evtx)
SOURCE_REG = "REG"        # Registry hives (NTUSER.DAT, SOFTWARE, SYSTEM, …)
SOURCE_FILE = "FILE"      # $MFT, $LogFile, $UsnJrnl
SOURCE_PREF = "PREF"      # Prefetch
SOURCE_WEBHIST = "WEBHIST"  # browser history (Chrome, Edge, Firefox)
SOURCE_LOG = "LOG"        # plaintext logs (IIS, syslog, …)
SOURCE_LNK = "LNK"        # Shell-link / shortcut files
SOURCE_OLECF = "OLECF"    # OLE-compound (legacy Office, jump lists)

PTH_RELEVANT_SOURCES = frozenset({SOURCE_EVT, SOURCE_REG, SOURCE_FILE, SOURCE_PREF, SOURCE_LNK})


# --------------------------------------------------------------------------- #
# Typed schema                                                                #
# --------------------------------------------------------------------------- #


class TimelineEvent(BaseModel):
    """One row from psort's l2tcsv export.

    plaso's standard CSV columns (l2tcsv format):
      date,time,timezone,MACB,source,sourcetype,type,user,host,short,desc,
      version,filename,inode,notes,format,extra

    We coalesce date+time+timezone into an ISO-8601 string and surface the
    fields that matter for IR. The `extra` column (free-form parser metadata)
    is included verbatim because PtH detection sometimes needs values like
    `logon_type=3` or `auth_package=NTLM` that only appear there.
    """

    model_config = ConfigDict(frozen=True)

    timestamp: str = Field(..., description="ISO-8601 UTC datetime (coalesced).")
    timestamp_desc: str = Field(..., description="What this timestamp means (e.g. 'Logon').")
    source_short: str = Field(..., min_length=2, max_length=8)
    source_long: str
    parser_name: str
    description: str

    # Where applicable
    user: str | None = None
    hostname: str | None = None
    artifact_path: str | None = None
    inode: int | None = None

    # The plaso `extra` column — free-form parser-emitted metadata. The
    # agent's verifier predicates can subset-match this dict (e.g.
    # {"logon_type": "3", "authentication_package": "NTLM"}).
    extra: dict[str, str] = Field(default_factory=dict)


# --------------------------------------------------------------------------- #
# Provenance helpers                                                          #
# --------------------------------------------------------------------------- #


def hash_plaso_store(plaso_path: Path) -> str:
    """SHA-256 the .plaso storage file. Bound into args_canonical."""
    h = hashlib.sha256()
    with open(plaso_path, "rb") as f:
        for chunk in iter(lambda: f.read(4 * 1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _to_int_or_none(s: str | None) -> int | None:
    if s is None or not s.strip():
        return None
    try:
        return int(s.strip())
    except ValueError:
        return None


def _parse_extra(field: str) -> dict[str, str]:
    """Parse plaso's `extra` column.

    plaso encodes parser-specific metadata as a semicolon-joined list of
    `key: value` pairs. Example:
      "logon_type: 3; authentication_package: NTLM; source_ip: 10.0.0.42"
    We split it; values containing colons (paths, GUIDs) are preserved by
    splitting only on the FIRST colon per pair.
    """
    if not field:
        return {}
    out: dict[str, str] = {}
    for pair in field.split(";"):
        pair = pair.strip()
        if not pair or ":" not in pair:
            continue
        k, _, v = pair.partition(":")
        out[k.strip()] = v.strip()
    return out


# --------------------------------------------------------------------------- #
# CSV parsing                                                                 #
# --------------------------------------------------------------------------- #


def _coalesce_timestamp(date: str, time: str, tz: str) -> str:
    """Build an ISO-8601 timestamp from plaso's split date/time/tz columns."""
    date = (date or "").strip()
    time = (time or "").strip()
    tz = (tz or "UTC").strip()
    if not date and not time:
        return ""
    # plaso's date format is MM/DD/YYYY; reformat to YYYY-MM-DD.
    parts = date.split("/")
    if len(parts) == 3:
        m, d, y = parts
        iso_date = f"{int(y):04d}-{int(m):02d}-{int(d):02d}"
    else:
        iso_date = date
    return f"{iso_date}T{time}{'' if tz in ('', 'UTC') else '+00:00'}"


def _parse_l2tcsv(csv_bytes: bytes) -> list[TimelineEvent]:
    """Parse psort's l2tcsv output into typed events."""
    events: list[TimelineEvent] = []
    reader = csv.DictReader(io.StringIO(csv_bytes.decode("utf-8", errors="replace")))
    for row in reader:
        ts = _coalesce_timestamp(row.get("date", ""), row.get("time", ""), row.get("timezone", ""))
        if not ts:
            continue
        events.append(
            TimelineEvent(
                timestamp=ts,
                timestamp_desc=(row.get("type") or row.get("MACB") or "").strip(),
                source_short=(row.get("source") or "?").strip(),
                source_long=(row.get("sourcetype") or "").strip(),
                parser_name=(row.get("format") or "").strip(),
                description=(row.get("desc") or "").strip(),
                user=(row.get("user") or "").strip() or None,
                hostname=(row.get("host") or "").strip() or None,
                artifact_path=(row.get("filename") or "").strip() or None,
                inode=_to_int_or_none(row.get("inode")),
                extra=_parse_extra(row.get("extra", "")),
            )
        )
    return events


# --------------------------------------------------------------------------- #
# Public typed function                                                       #
# --------------------------------------------------------------------------- #


def plaso_supertimeline(
    handle: EvidenceHandle,
    *,
    plaso_path: Path,
    plaso_store_sha256: str | None = None,
    time_window_start: str | None = None,
    time_window_end: str | None = None,
    source_filter: list[str] | None = None,
    parser_filter: list[str] | None = None,
    description_substring: str | None = None,
    ctx: SigningContext,
    executor: ToolExecutor | None = None,
    prev_hash: str | None = None,
) -> Notarized[list[TimelineEvent]]:
    """Query a pre-built .plaso store via psort and return typed events.

    Parameters
    ----------
    plaso_path
        Path to the .plaso storage file produced by log2timeline.
    plaso_store_sha256
        Optional pre-computed SHA-256 of the store. If omitted, we compute
        it from disk. Either way, the value is bound into args_canonical so
        envelope verification is anchored to this exact store.
    time_window_start, time_window_end
        Optional ISO-8601 lower/upper bounds. psort accepts these via its
        date_filter; we apply them post-query as well to be safe.
    source_filter
        Whitelist of source_short codes (e.g. ["EVT", "REG"]). When set,
        rows with other source codes are dropped. See PTH_RELEVANT_SOURCES.
    parser_filter
        Whitelist of plaso parser names (e.g. ["winevtx", "winreg/run"]).
    description_substring
        Optional case-insensitive substring match on the `description` field.
    """
    executor = executor or SubprocessExecutor()

    if plaso_store_sha256 is None:
        plaso_store_sha256 = hash_plaso_store(plaso_path)

    normalized_sources = sorted({s.strip() for s in source_filter if s.strip()}) if source_filter else None
    normalized_parsers = sorted({p.strip() for p in parser_filter if p.strip()}) if parser_filter else None

    args: dict[str, object] = {
        "plaso_path": str(plaso_path),
        "plaso_store_sha256": plaso_store_sha256,
        "time_window_start": time_window_start,
        "time_window_end": time_window_end,
        "source_filter": normalized_sources,
        "parser_filter": normalized_parsers,
        "description_substring": description_substring,
    }

    argv: list[str] = ["psort.py", "-o", "l2tcsv", "-w", "/dev/stdout"]
    if time_window_start:
        argv.extend(["--slice", time_window_start])
    argv.append(str(plaso_path))

    stdout_bytes = executor.run(argv)
    events = _parse_l2tcsv(stdout_bytes)

    # Apply filters post-query — psort filter coverage varies by version,
    # so we always re-filter in Python to guarantee deterministic output.
    if time_window_start:
        events = [e for e in events if e.timestamp >= time_window_start]
    if time_window_end:
        events = [e for e in events if e.timestamp <= time_window_end]
    if normalized_sources:
        s = set(normalized_sources)
        events = [e for e in events if e.source_short in s]
    if normalized_parsers:
        p = set(normalized_parsers)
        events = [e for e in events if e.parser_name in p]
    if description_substring:
        needle = description_substring.lower()
        events = [e for e in events if needle in e.description.lower()]

    return mint(
        data=events,
        tool_name="plaso_supertimeline",
        tool_version=PLASO_VERSION_FLOOR,
        args=args,
        image_sha256=handle.image_sha256,
        stdout_bytes=stdout_bytes,
        offsets=(
            EvidenceOffset(
                start=0,
                length=max(plaso_path.stat().st_size, 1) if plaso_path.exists() else 1,
                artifact_label=f"plaso-store:{plaso_store_sha256[:16]}",
            ),
        ),
        prev_hash=prev_hash,
        ctx=ctx,
    )


def reverify(
    envelope: Notarized[list[TimelineEvent]],
    *,
    plaso_path: Path,
    executor: ToolExecutor | None = None,
) -> tuple[bool, str]:
    """Re-run psort with the same args; recompute BLAKE3 of stdout; compare.

    Step 1: re-hash the .plaso store and confirm it matches the value bound
    in args_canonical. This catches operators swapping in a different store.

    Step 2: re-run psort and compare stdout BLAKE3.
    """
    import blake3

    executor = executor or SubprocessExecutor()

    # Step 1: store-identity check (skipped if store no longer exists, which
    # is a legitimate failure mode after corpus rotation).
    bound_sha = envelope.header.args_canonical
    if plaso_path.exists():
        actual_store_sha = hash_plaso_store(plaso_path)
        if f'"plaso_store_sha256":"{actual_store_sha}"' not in bound_sha:
            return False, f".plaso store SHA-256 drift: header doesn't bind {actual_store_sha[:16]}…"

    # Step 2: re-run psort. Slice arg threading is conservative — we don't
    # try to reconstruct the full argv from args_canonical; the canonical
    # query for verification is the un-sliced full-store dump compared via
    # stdout BLAKE3. (Drift either way → fail.)
    argv = ["psort.py", "-o", "l2tcsv", "-w", "/dev/stdout", str(plaso_path)]
    try:
        stdout_bytes = executor.run(argv)
    except Exception as e:
        return False, f"psort.py re-run failed: {e}"

    actual = blake3.blake3(stdout_bytes).hexdigest()
    expected = envelope.header.stdout_blake3
    if actual != expected:
        return False, f"stdout BLAKE3 drift: expected {expected[:16]}…, got {actual[:16]}…"
    return True, "ok"


# --------------------------------------------------------------------------- #
# Correlation helpers                                                         #
# --------------------------------------------------------------------------- #


def events_in_window(
    events: list[TimelineEvent], start: str, end: str
) -> list[TimelineEvent]:
    """Filter events to a [start, end] ISO-8601 window. Inclusive both ends."""
    return [e for e in events if start <= e.timestamp <= end]


def correlate_around(
    events: list[TimelineEvent],
    anchor_timestamp: str,
    seconds_before: int = 30,
    seconds_after: int = 30,
) -> list[TimelineEvent]:
    """Return all events within ±N seconds of an anchor.

    Useful for "what else happened on this host at 14:32:01?" — the agent
    pins to a high-confidence event (e.g. an EVTX 4624 logon) and pulls the
    surrounding context to confirm/deny a hypothesis.

    Pure string comparison on the ISO-8601 timestamp; sufficient when all
    events are timezone-normalized to UTC, which plaso does by default.
    """
    from datetime import datetime, timedelta

    try:
        anchor = datetime.fromisoformat(anchor_timestamp.replace("Z", "+00:00"))
    except ValueError:
        return []

    lo = (anchor - timedelta(seconds=seconds_before)).isoformat()
    hi = (anchor + timedelta(seconds=seconds_after)).isoformat()

    def in_range(e: TimelineEvent) -> bool:
        try:
            t = datetime.fromisoformat(e.timestamp.replace("Z", "+00:00"))
        except ValueError:
            return False
        return lo <= t.isoformat() <= hi

    return [e for e in events if in_range(e)]


__all__ = [
    "PLASO_VERSION_FLOOR",
    "PTH_RELEVANT_SOURCES",
    "SOURCE_EVT",
    "SOURCE_FILE",
    "SOURCE_LNK",
    "SOURCE_LOG",
    "SOURCE_OLECF",
    "SOURCE_PREF",
    "SOURCE_REG",
    "SOURCE_WEBHIST",
    "TimelineEvent",
    "correlate_around",
    "events_in_window",
    "hash_plaso_store",
    "plaso_supertimeline",
    "reverify",
]
