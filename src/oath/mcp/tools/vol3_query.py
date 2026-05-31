"""vol3_query — typed MCP function for Volatility 3 memory analysis.

Wraps the Volatility 3 framework (`vol`). Produces a `Notarized[Vol3Result]`
binding every plugin run to:

  - the source image SHA-256 (via the EvidenceHandle)
  - the Volatility 3 version (we record `vol --info` output truncated to the
    version string)
  - the plugin name (e.g. 'windows.pslist.PsList', 'windows.lsadump.Lsadump')
  - the plugin's canonical argument vector
  - the BLAKE3 of the raw plugin JSON stdout
  - the symbol-pack hash (Microsoft PDB cache contents, since plugin output
    depends on which symbols were available)

Why vol3 matters
----------------
Most 2024-2025 intrusions are fileless (CrowdStrike GTR: 79% malware-free).
Disk parsing alone cannot see Cobalt Strike beacons in memory, hollowed
svchost processes, in-memory Mimikatz invocations, or LSA secrets — they
live only in the memory image. Volatility 3's plugins cover this surface:

  - windows.pslist            — running processes
  - windows.pstree            — parent/child process trees
  - windows.cmdline           — full command lines (esp. for PowerShell)
  - windows.netscan           — network connections (active + closed)
  - windows.lsadump.Lsadump   — LSA secrets / cached creds / hashes
  - windows.lsadump.Cachedump — DCC2 cached domain credentials
  - windows.lsadump.Hashdump  — SAM hashes
  - windows.handles           — handle tables (e.g. lsass minidump handles)
  - windows.malfind           — injected/RWX VAD anomalies

Schema diversity & the generic envelope
---------------------------------------
Unlike EZ tools (each tool has one stable CSV schema), every Volatility 3
plugin has its OWN schema. Modeling each as a Pydantic type would be
~50 classes. Instead, we use a generic `Vol3Row = dict[str, Any]` and
a single `Vol3Result` envelope; per-plugin convenience extractors live
alongside (PsListProcess, etc.) for the highest-value PtH plugins.

This is the right tradeoff: the cryptographic Notarized<T> binding is
identical; the LLM-side ergonomics are slightly looser for rare plugins but
tight for the must-haves.
"""
from __future__ import annotations

import csv
import io
import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from oath.mcp.evidence_handle import EvidenceHandle
from oath.mcp.tools.parse_evtx import SubprocessExecutor, ToolExecutor
from oath.receipt.notarized import (
    EvidenceOffset,
    Notarized,
    SigningContext,
    mint,
)

VOL3_VERSION_FLOOR = "2.7.0"


# Plugins the autonomous PtH agent uses on every memory image, with a quick
# note about what they prove. The verifier maps each to an output schema.
PTH_RELEVANT_PLUGINS: tuple[str, ...] = (
    "windows.pslist.PsList",
    "windows.pstree.PsTree",
    "windows.cmdline.CmdLine",
    "windows.netscan.NetScan",
    "windows.lsadump.Lsadump",
    "windows.lsadump.Cachedump",
    "windows.lsadump.Hashdump",
    "windows.handles.Handles",
    "windows.malfind.Malfind",
    "windows.svcscan.SvcScan",
)


# --------------------------------------------------------------------------- #
# Typed result wrapper                                                        #
# --------------------------------------------------------------------------- #


class Vol3Row(BaseModel):
    """A single row of plugin output, as the LLM sees it.

    Volatility 3 plugin output schemas vary; we don't try to model each. The
    `data` dict carries the plugin's native columns. `plugin` is repeated on
    every row so a list[Vol3Row] is self-describing.
    """

    model_config = ConfigDict(frozen=True)

    plugin: str = Field(..., description="Plugin name, e.g. 'windows.pslist.PsList'.")
    row_index: int = Field(..., ge=0, description="Position in the plugin's row stream.")
    data: dict[str, Any] = Field(..., description="The native plugin row.")


class Vol3Result(BaseModel):
    """Wrapper carrying the plugin name + every row from one plugin run."""

    model_config = ConfigDict(frozen=True)

    plugin: str
    rows: tuple[Vol3Row, ...]
    # Optional banner text (e.g. plugin warnings about partial symbol coverage).
    banner: str | None = None


# --------------------------------------------------------------------------- #
# Output parsing — Volatility 3 emits JSON-lines OR pretty-printed text       #
# --------------------------------------------------------------------------- #


def _parse_vol3_output(stdout_bytes: bytes, plugin: str) -> Vol3Result:
    """Parse Volatility 3 output into typed rows.

    Strategy:
      1. Try JSON-lines (jsonl) — what `--renderer json_lines` produces. This
         is the preferred format because it's deterministic, line-oriented,
         and trivially streamable for large memory images.
      2. Fall back to JSON-array (`--renderer json`).
      3. Fall back to CSV if neither parses.

    Volatility 3 can also emit pretty-text output; we treat that as a fatal
    parse error rather than guessing — the agent should always invoke with
    `--renderer json_lines`.
    """
    text = stdout_bytes.decode("utf-8", errors="replace").strip()
    if not text:
        return Vol3Result(plugin=plugin, rows=(), banner=None)

    # 1. JSON-lines: one well-formed JSON object per line.
    rows: list[Vol3Row] = []
    is_jsonl = "\n" in text and text.startswith("{")
    if is_jsonl:
        for i, line in enumerate(text.split("\n")):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                is_jsonl = False
                break
            if isinstance(obj, dict):
                rows.append(Vol3Row(plugin=plugin, row_index=i, data=obj))
        if is_jsonl and rows:
            return Vol3Result(plugin=plugin, rows=tuple(rows), banner=None)

    # 2. JSON-array
    if text.startswith("["):
        try:
            arr = json.loads(text)
        except json.JSONDecodeError:
            arr = None
        if isinstance(arr, list):
            return Vol3Result(
                plugin=plugin,
                rows=tuple(
                    Vol3Row(plugin=plugin, row_index=i, data=obj if isinstance(obj, dict) else {"value": obj})
                    for i, obj in enumerate(arr)
                ),
                banner=None,
            )

    # 3. CSV fallback (when running with `--renderer csv`)
    reader = csv.DictReader(io.StringIO(text))
    csv_rows = [
        Vol3Row(plugin=plugin, row_index=i, data=dict(row)) for i, row in enumerate(reader)
    ]
    if csv_rows:
        return Vol3Result(plugin=plugin, rows=tuple(csv_rows), banner=None)

    # No structured rows parsed — surface as a banner for the agent to see.
    return Vol3Result(plugin=plugin, rows=(), banner=text[:1000])


# --------------------------------------------------------------------------- #
# Public typed function                                                       #
# --------------------------------------------------------------------------- #


def vol3_query(
    handle: EvidenceHandle,
    *,
    memdump_path: Path,
    plugin: str,
    plugin_args: dict[str, Any] | None = None,
    ctx: SigningContext,
    executor: ToolExecutor | None = None,
    prev_hash: str | None = None,
    memdump_image_offset: int = 0,
    symbol_pack_hash: str | None = None,
) -> Notarized[Vol3Result]:
    """Run a Volatility 3 plugin against a memory image; return a Notarized envelope.

    Parameters
    ----------
    handle
        Mounted-read-only EvidenceHandle (image_sha256 anchors the receipt).
    memdump_path
        Absolute path to the memory image (.raw, .vmem, .mem, .lime, .dmp).
    plugin
        Volatility 3 plugin name, e.g. 'windows.pslist.PsList' or
        'windows.lsadump.Lsadump'. Must match the plugin module path.
    plugin_args
        Optional per-plugin flag map, e.g. {"--pid": "1234"}. Flags are passed
        as `--key value` (or `--key` alone for True), preserving the order
        that the args dict iterates in (after RFC 8785 canonicalization for
        the args_canonical envelope field).
    symbol_pack_hash
        SHA-256 of the Windows symbol pack used. Bound into args_canonical so
        the verifier surfaces "symbol pack updated since mint" as a distinct
        failure mode (vol3 plugin output can shift when symbols rev).
    """
    executor = executor or SubprocessExecutor()

    args: dict[str, Any] = {
        "memdump_path": str(memdump_path),
        "plugin": plugin,
        "plugin_args": dict(sorted((plugin_args or {}).items())),
        "memdump_image_offset": memdump_image_offset,
        "symbol_pack_hash": symbol_pack_hash,
    }

    argv: list[str] = [
        "vol",
        "-r",
        "json_lines",
        "-q",  # quiet — suppresses progress logs to stderr
        "-f",
        str(memdump_path),
        plugin,
    ]
    for k, v in sorted((plugin_args or {}).items()):
        argv.append(k)
        if v is not True and v is not None:
            argv.append(str(v))

    stdout_bytes = executor.run(argv)
    result = _parse_vol3_output(stdout_bytes, plugin)

    return mint(
        data=result,
        tool_name="vol3_query",
        tool_version=VOL3_VERSION_FLOOR,
        args=args,
        image_sha256=handle.image_sha256,
        stdout_bytes=stdout_bytes,
        offsets=(
            EvidenceOffset(
                start=memdump_image_offset,
                length=max(memdump_path.stat().st_size, 1) if memdump_path.exists() else 1,
                artifact_label=f"memory image: {memdump_path.name}",
            ),
        ),
        prev_hash=prev_hash,
        ctx=ctx,
    )


def reverify(
    envelope: Notarized[Vol3Result],
    *,
    memdump_path: Path,
    executor: ToolExecutor | None = None,
) -> tuple[bool, str]:
    """Re-run the plugin; recompute stdout BLAKE3; compare to envelope record."""
    import blake3

    executor = executor or SubprocessExecutor()
    plugin = envelope.data.plugin

    # Parse args_canonical to reconstruct plugin_args (RFC 8785 JCS, sorted).
    args_canonical = envelope.header.args_canonical
    try:
        args_dict = json.loads(args_canonical)
    except json.JSONDecodeError:
        return False, "envelope args_canonical is not valid JSON; cannot re-derive argv."

    plugin_args = args_dict.get("plugin_args") or {}

    argv: list[str] = [
        "vol",
        "-r",
        "json_lines",
        "-q",
        "-f",
        str(memdump_path),
        plugin,
    ]
    for k, v in sorted(plugin_args.items()):
        argv.append(k)
        if v is not True and v is not None:
            argv.append(str(v))

    try:
        stdout_bytes = executor.run(argv)
    except Exception as e:
        return False, f"vol3 re-run failed: {e}"

    actual = blake3.blake3(stdout_bytes).hexdigest()
    expected = envelope.header.stdout_blake3
    if actual != expected:
        return False, f"stdout BLAKE3 drift: expected {expected[:16]}…, got {actual[:16]}…"
    return True, "ok"


# --------------------------------------------------------------------------- #
# Per-plugin helpers for the highest-value PtH plugins                        #
# --------------------------------------------------------------------------- #


def pslist_processes(envelope: Notarized[Vol3Result]) -> list[dict[str, Any]]:
    """Return the .data rows from a pslist run (just the raw dicts).

    The pslist schema: PID, PPID, ImageFileName, Offset(V), Threads, Handles,
    SessionId, Wow64, CreateTime, ExitTime. Useful for cheap walks like
    `next(p for p in pslist_processes(env) if p['ImageFileName'] == 'lsass.exe')`.
    """
    if envelope.data.plugin not in ("windows.pslist.PsList",):
        return []
    return [row.data for row in envelope.data.rows]


def lsadump_secrets(envelope: Notarized[Vol3Result]) -> list[dict[str, Any]]:
    """Return LSA secret rows from a windows.lsadump.Lsadump run.

    Schema includes: Key, Secret (encrypted), Hex bytes. For PtH triage,
    surface DefaultPassword / NL$KM / cached service-account creds.
    """
    if envelope.data.plugin not in ("windows.lsadump.Lsadump", "windows.lsadump.Cachedump"):
        return []
    return [row.data for row in envelope.data.rows]


__all__ = [
    "PTH_RELEVANT_PLUGINS",
    "VOL3_VERSION_FLOOR",
    "Vol3Result",
    "Vol3Row",
    "lsadump_secrets",
    "pslist_processes",
    "reverify",
    "vol3_query",
]
