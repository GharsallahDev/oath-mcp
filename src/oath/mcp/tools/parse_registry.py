"""parse_registry — typed MCP function for Windows registry hive parsing.

Wraps Eric Zimmerman's RECmd with batch-plugin mode. Produces a
`Notarized[list[RegistryFinding]]` binding every emitted finding to the
source image SHA-256 + the plugin pack hash + RECmd version.

Why registry forensics matter for autonomous triage
---------------------------------------------------
The Windows registry is the persistence and execution-residue substrate:

  - HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run + RunOnce + Services
    — autorun persistence (T1547.001)
  - HKLM\\System\\CurrentControlSet\\Services
    — service-install persistence + lateral-movement evidence (T1543.003)
  - HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache
    — scheduled task persistence (T1053.005), including Tarrask hidden tasks
  - HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist
    — execution residue (ROT13-encoded program names)
  - HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Schedule\\TaskCache\\Tree
    — Tarrask anti-forensic signature (orphaned Tree entries without
    matching Tasks entries)

RECmd's batch plugins encode ~150 deterministic rules over these keys.
The plugin output is a CSV-per-rule, which we normalize into a flat
RegistryFinding list. Each finding carries the rule name + the key path it
came from, so the LLM can reason about it without grep'ing raw hives.

Plugin-pack hash binding
------------------------
RECmd's batch plugins are independently versioned. We record the SHA-256
of the plugin pack at mint time; the Witness Oath Verifier surfaces "plugin
pack changed since mint" as a distinct failure mode.
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

RECMD_VERSION = "2026.5.0"

# Common persistence + execution-residue plugins shipped with RECmd. Authors
# add more; we include the canonical PtH-triage set as a default starting
# point. The actual list of plugins applied is recorded in the envelope's
# args_canonical.
PTH_PERSISTENCE_PLUGINS: tuple[str, ...] = (
    "RunKeys",
    "RunOnce",
    "Services",
    "TaskCache",
    "UserAssist",
    "ShimCache",
    "AppCompatCache",
    "BAM",  # Background Activity Moderator — execution timeline (Win10+)
    "WinlogonShellRunOnce",
)


# --------------------------------------------------------------------------- #
# Typed schema                                                                #
# --------------------------------------------------------------------------- #


class RegistryFinding(BaseModel):
    """One row from a RECmd batch-plugin CSV.

    RECmd plugins each emit slightly different columns; we normalize to a
    minimal common shape with the raw plugin row preserved in `raw` for the
    LLM to inspect when a tighter typed field isn't there.
    """

    model_config = ConfigDict(frozen=True)

    plugin: str = Field(..., description="RECmd plugin name (e.g. 'RunKeys', 'TaskCache').")
    hive: str = Field(..., description="Source hive: SOFTWARE / SYSTEM / SAM / NTUSER / USRCLASS.")
    key_path: str = Field(..., description="Full registry key path the finding came from.")
    value_name: str | None = Field(None, description="Registry value name, if applicable.")
    value_data: str | None = Field(
        None,
        description=(
            "String-rendered value data. Attacker-controlled fields go through the "
            "untrusted-string firewall before reaching the LLM."
        ),
    )
    last_write_ts: str | None = Field(None, description="Key last-write time (ISO-8601 UTC).")
    raw: dict[str, str] = Field(
        default_factory=dict, description="Raw plugin-row columns for LLM-side inspection."
    )

    # Provenance
    hive_image_offset: int = Field(..., ge=0)


def _to_int_or_none(s: str | None) -> int | None:
    if s is None or not s.strip():
        return None
    try:
        return int(s.strip())
    except ValueError:
        return None


# --------------------------------------------------------------------------- #
# Plugin-pack hashing                                                         #
# --------------------------------------------------------------------------- #


def _hash_plugin_pack(plugins_dir: Path) -> str:
    """SHA-256 over the concatenated contents of every .reb plugin file (sorted)."""
    h = hashlib.sha256()
    if not plugins_dir.exists():
        return h.hexdigest()
    for f in sorted(plugins_dir.rglob("*.reb")):
        try:
            h.update(f.read_bytes())
            h.update(b"\x00")
        except (OSError, PermissionError):
            continue
    return h.hexdigest()


# --------------------------------------------------------------------------- #
# Parser                                                                      #
# --------------------------------------------------------------------------- #


def _parse_recmd_csv(
    csv_bytes: bytes,
    *,
    hive_label: str,
    plugin_filter: set[str] | None,
    hive_offset: int,
) -> list[RegistryFinding]:
    """Parse RECmd batch-mode CSV output into typed findings.

    RECmd batch CSV columns (canonical):
      HivePath, HiveType, Description, Category, KeyPath, ValueName, ValueType,
      ValueData, ValueData2, ValueData3, Comment, Recursive, Deleted,
      LastWriteTimestamp, PluginDetailFile
    """
    findings: list[RegistryFinding] = []
    reader = csv.DictReader(io.StringIO(csv_bytes.decode("utf-8", errors="replace")))
    for row in reader:
        plugin = (row.get("Description") or row.get("Category") or "").strip()
        if plugin_filter and plugin not in plugin_filter:
            continue
        findings.append(
            RegistryFinding(
                plugin=plugin,
                hive=hive_label,
                key_path=(row.get("KeyPath") or "").strip(),
                value_name=row.get("ValueName") or None,
                value_data=row.get("ValueData") or None,
                last_write_ts=row.get("LastWriteTimestamp") or None,
                raw={k: v for k, v in row.items() if v},
                hive_image_offset=hive_offset,
            )
        )
    return findings


# --------------------------------------------------------------------------- #
# Public typed function                                                       #
# --------------------------------------------------------------------------- #


def parse_registry(
    handle: EvidenceHandle,
    *,
    hive_path: Path,
    hive_label: str,
    plugins_dir: Path | None = None,
    plugin_filter: list[str] | None = None,
    ctx: SigningContext,
    executor: ToolExecutor | None = None,
    prev_hash: str | None = None,
    hive_image_offset: int = 0,
) -> Notarized[list[RegistryFinding]]:
    """Parse a registry hive with RECmd batch-plugin mode.

    Parameters
    ----------
    handle
        Read-only mounted EvidenceHandle (image_sha256 anchors the receipt).
    hive_path
        Absolute path to the registry hive file (SOFTWARE / SYSTEM / SAM /
        SECURITY / NTUSER.DAT / UsrClass.dat).
    hive_label
        Friendly label for the hive ('SOFTWARE', 'SYSTEM', 'NTUSER:jdoe', ...).
        Recorded in every finding for cross-hive correlation.
    plugins_dir
        Directory containing RECmd batch plugins (default ~/RECmd/Plugins).
        Its SHA-256 is bound into the envelope so plugin-pack drift is
        detectable.
    plugin_filter
        Optional whitelist of plugin Description fields to keep. Useful for
        narrow PtH triage (e.g. ["RunKeys", "TaskCache", "Services"]).
    """
    executor = executor or SubprocessExecutor()
    normalized_filter = (
        {p.strip() for p in plugin_filter if p.strip()} if plugin_filter else None
    )

    args: dict[str, object] = {
        "hive_path": str(hive_path),
        "hive_label": hive_label,
        "plugins_dir": str(plugins_dir) if plugins_dir else None,
        "plugin_pack_sha256": _hash_plugin_pack(plugins_dir) if plugins_dir else None,
        "plugin_filter": sorted(normalized_filter) if normalized_filter else None,
        "hive_image_offset": hive_image_offset,
    }

    argv: list[str] = [
        "RECmd",
        "-f",
        str(hive_path),
        "--bn",  # batch mode (named plugins)
        "ALL",
        "--csv",
        "-",
        "--csvf",
        "stdout",
    ]
    if plugins_dir:
        argv += ["--bp", str(plugins_dir)]

    stdout_bytes = executor.run(argv)
    findings = _parse_recmd_csv(
        stdout_bytes,
        hive_label=hive_label,
        plugin_filter=normalized_filter,
        hive_offset=hive_image_offset,
    )

    return mint(
        data=findings,
        tool_name="parse_registry",
        tool_version=RECMD_VERSION,
        args=args,
        image_sha256=handle.image_sha256,
        stdout_bytes=stdout_bytes,
        offsets=(
            EvidenceOffset(
                start=hive_image_offset,
                length=max(hive_path.stat().st_size, 1) if hive_path.exists() else 1,
                artifact_label=f"Registry hive: {hive_label}",
            ),
        ),
        prev_hash=prev_hash,
        ctx=ctx,
    )


def reverify(
    envelope: Notarized[list[RegistryFinding]],
    *,
    hive_path: Path,
    plugins_dir: Path | None = None,
    executor: ToolExecutor | None = None,
) -> tuple[bool, str]:
    """Re-run RECmd; check (a) plugin-pack unchanged and (b) stdout BLAKE3 matches."""
    import blake3

    executor = executor or SubprocessExecutor()

    if plugins_dir:
        current = _hash_plugin_pack(plugins_dir)
        if f'"plugin_pack_sha256":"{current}"' not in envelope.header.args_canonical:
            return (
                False,
                "RECmd plugin pack has changed since mint — re-mint required for "
                "deterministic semantics.",
            )

    argv = ["RECmd", "-f", str(hive_path), "--bn", "ALL", "--csv", "-", "--csvf", "stdout"]
    if plugins_dir:
        argv += ["--bp", str(plugins_dir)]
    try:
        stdout_bytes = executor.run(argv)
    except Exception as e:
        return False, f"RECmd re-run failed: {e}"
    actual = blake3.blake3(stdout_bytes).hexdigest()
    expected = envelope.header.stdout_blake3
    if actual != expected:
        return False, f"stdout BLAKE3 drift: expected {expected[:16]}…, got {actual[:16]}…"
    return True, "ok"


# --------------------------------------------------------------------------- #
# Persistence-key helpers                                                     #
# --------------------------------------------------------------------------- #


def filter_persistence_findings(findings: list[RegistryFinding]) -> list[RegistryFinding]:
    """Keep only findings from canonical persistence plugins.

    Cheap, deterministic, non-LLM filter so the agent's first-pass triage sees
    a smaller / denser set of registry candidates.
    """
    pset = set(PTH_PERSISTENCE_PLUGINS)
    return [f for f in findings if f.plugin in pset]


def find_tarrask_candidates(findings: list[RegistryFinding]) -> list[RegistryFinding]:
    """Find TaskCache findings consistent with the Tarrask anti-forensic technique.

    Tarrask (Microsoft DART 2022) creates a scheduled task whose Tree entry
    points at a Tasks GUID — but DELETES the SD value in the Tasks/{GUID}
    subkey. The result: the task still runs (the scheduler reads Tree) but is
    invisible to `schtasks`. RECmd's TaskCache plugin surfaces "orphaned"
    Tree entries — we filter to those.
    """
    return [
        f
        for f in findings
        if f.plugin == "TaskCache"
        and (
            "orphan" in (f.value_data or "").lower()
            or "missing" in (f.value_data or "").lower()
            or "no-sd" in (f.value_data or "").lower()
        )
    ]


__all__ = [
    "PTH_PERSISTENCE_PLUGINS",
    "RECMD_VERSION",
    "RegistryFinding",
    "filter_persistence_findings",
    "find_tarrask_candidates",
    "parse_registry",
    "reverify",
]
