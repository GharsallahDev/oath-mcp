"""OATH MCP server — exposes typed forensic functions to Claude Code.

Boot:
    python -m oath.mcp.server                 # stdio transport (Claude Code default)
    # or via CLI:
    oath serve --transport stdio

Tools exposed to the agent:

  oath_mount(image_path)                          — create EvidenceHandle, returns handle_id
  oath_list_handles()                              — list known handles
  parse_evtx(handle_id, evtx_path, ...)            — Windows event-log records (EvtxECmd)
  parse_mft(handle_id, mft_path, ...)              — NTFS $MFT entries with $SI/$FN tripwire
  parse_amcache(handle_id, amcache_path, ...)      — Amcache program-execution residue + SHA-1
  parse_prefetch(handle_id, prefetch_dir, ...)     — Prefetch run history (up to 8 timestamps)
  parse_registry(handle_id, hive_path, ...)        — RECmd batch-plugin findings (Run/Services/TaskCache)
  parse_usnjrnl(handle_id, j_path, ...)            — NTFS $UsnJrnl:$J change journal (anti-forensic surface)
  plaso_supertimeline(handle_id, plaso_path, ...)  — cross-source ordered timeline via psort
  run_hayabusa(handle_id, evtx_dir, ...)           — Sigma-driven EVTX triage with MITRE ATT&CK tagging
  vol3_query(handle_id, memdump_path, plugin, ...) — Volatility 3 plugin against a memory image
  find_strings_on_image(handle_id, pattern, ...)   — NIST String Search: typed (inode, filename) match list
  enumerate_credential_artifacts(handle_id, ...)   — filesystem inventory of credential-bearing files (FIRST call)
  oath_verify_claim(claim)                         — submit an AgentClaim to the Witness Oath Verifier

Each typed-function tool:
  1. Materializes the EvidenceHandle from handle_id
  2. Loads the SigningContext (shared per-run key in ./keys/)
  3. Calls the bundled typed function (which shells out to the forensic tool)
  4. Mints a Notarized envelope, appends it to the run's EnvelopeStore
  5. Returns a structured LLM-facing summary: {envelope_id, row_count, sample,
     prev_chain_link} — NOT the full envelope (those can be megabytes)

The LLM uses envelope_ids when constructing AgentClaim objects for
oath_verify_claim. The Witness Oath Verifier (verifier.py) re-runs the tool
to confirm the envelope's stdout_blake3 still matches and that the LLM's
record_predicate matches at least one record in the envelope's data.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import uuid
from pathlib import Path
from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
import mcp.types as types

from oath import __version__
from oath.mcp.evidence_handle import open_handle
from oath.mcp.persistence import (
    EnvelopeStore,
    list_envelopes_anywhere,
    load_handle,
    read_envelope_anywhere,
    save_handle,
)
from oath.mcp.tools import (
    enumerate_credential_artifacts,
    find_strings_on_image,
    parse_amcache,
    parse_evtx,
    parse_mft,
    parse_prefetch,
    parse_registry,
    parse_usnjrnl,
    plaso_supertimeline,
    run_hayabusa,
    vol3_query,
)
from oath.receipt.notarized import SigningContext
from oath.witness.claim import AgentClaim
from oath.witness.verifier import WitnessOathVerifier, default_registry


# --------------------------------------------------------------------------- #
# Server state                                                                #
# --------------------------------------------------------------------------- #


class OathServer:
    """Holds per-process state across MCP tool calls.

    A single OathServer corresponds to one agent run (run_id = uuid). Handles
    and envelopes are persisted to disk so a server restart doesn't lose them,
    but the in-memory caches make tool calls fast.
    """

    def __init__(
        self,
        *,
        logs_dir: Path,
        keys_dir: Path,
        run_id: str | None = None,
    ) -> None:
        self.run_id = run_id or uuid.uuid4().hex
        self.logs_dir = logs_dir
        self.handles_dir = logs_dir / "handles"
        self.envelopes_dir = logs_dir / "envelopes"
        self.keys_dir = keys_dir
        self.envelope_store = EnvelopeStore(self.run_id, self.envelopes_dir)
        self.signing_ctx = SigningContext.load_or_mint(keys_dir, run_id=self.run_id)

    def get_handle(self, handle_id: str):
        return load_handle(handle_id, self.handles_dir)


# --------------------------------------------------------------------------- #
# Tool schemas (JSON Schema for MCP)                                          #
# --------------------------------------------------------------------------- #


def _build_tool_descriptors() -> list[types.Tool]:
    return [
        types.Tool(
            name="oath_mount",
            description=(
                "Mount a forensic image read-only and return a handle_id. "
                "Use this once per image at the start of triage; subsequent typed-"
                "function calls reference the handle_id."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "image_path": {
                        "type": "string",
                        "description": "Absolute path to the forensic image (.E01, .dd, .raw, ...).",
                    }
                },
                "required": ["image_path"],
            },
        ),
        types.Tool(
            name="oath_list_handles",
            description="List known EvidenceHandle IDs in the current run's logs directory.",
            inputSchema={"type": "object", "properties": {}},
        ),
        types.Tool(
            name="oath_list_envelopes",
            description=(
                "List every signed Notarized envelope visible under the OATH "
                "logs directory. Spans the current agent run plus any read-"
                "only pre-staged chains (logs/sample-run/, logs/demo-run/, "
                "etc.). Each record carries envelope_id, scope, tool_name, "
                "tool_version, image_sha256 prefix, row_count, prev-link. "
                "Use this BEFORE citing any envelope_id in a claim; replaces "
                "any need to inspect logs/ via shell."
            ),
            inputSchema={"type": "object", "properties": {}},
        ),
        types.Tool(
            name="oath_read_envelope",
            description=(
                "Read a specific Notarized envelope by envelope_id. Searches "
                "every store under logs/ (current run + pre-staged chains). "
                "Returns the full envelope payload (header + data + sig) so "
                "the agent can inspect the signed record fields before "
                "constructing a claim. Use after oath_list_envelopes."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "envelope_id": {
                        "type": "string",
                        "description": "The 64-hex envelope_id from oath_list_envelopes.",
                    }
                },
                "required": ["envelope_id"],
            },
        ),
        types.Tool(
            name="parse_evtx",
            description=(
                "Parse a Windows .evtx file via EvtxECmd. Returns structured event "
                "records with typed auth fields (LogonType, AuthPackage, SourceIP). "
                "Use event_ids=[4624, 4625, 4648, 4672, 4768, 4769, 4776] for "
                "authentication-focused PtH triage."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "handle_id": {"type": "string"},
                    "evtx_path": {"type": "string"},
                    "channel": {"type": "string"},
                    "event_ids": {"type": "array", "items": {"type": "integer"}},
                    "time_range": {
                        "type": "array",
                        "items": {"type": "string"},
                        "minItems": 2,
                        "maxItems": 2,
                    },
                    "user_sid": {"type": "string"},
                },
                "required": ["handle_id", "evtx_path"],
            },
        ),
        types.Tool(
            name="parse_mft",
            description=(
                "Parse NTFS $MFT via MFTECmd. Returns entries with native $SI/$FN "
                "timestamp pairs (the timestomp tripwire) and parent-traversal paths."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "handle_id": {"type": "string"},
                    "mft_path": {"type": "string"},
                    "filter_path": {"type": "string"},
                    "since": {"type": "string", "description": "ISO-8601; keep entries with any timestamp ≥ this."},
                },
                "required": ["handle_id", "mft_path"],
            },
        ),
        types.Tool(
            name="parse_amcache",
            description=(
                "Parse Amcache.hve via AmcacheParser. Returns program-execution "
                "residue with SHA-1 hashes (Amcache '0000' prefix already stripped)."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "handle_id": {"type": "string"},
                    "amcache_path": {"type": "string"},
                    "sha1_filter": {"type": "array", "items": {"type": "string"}},
                    "name_substring": {"type": "string"},
                },
                "required": ["handle_id", "amcache_path"],
            },
        ),
        types.Tool(
            name="parse_prefetch",
            description=(
                "Parse Windows Prefetch (.pf) files via PECmd. Returns execution "
                "receipts with up to 8 run times per binary + referenced-files list."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "handle_id": {"type": "string"},
                    "prefetch_dir": {"type": "string"},
                    "name_filter": {"type": "string"},
                },
                "required": ["handle_id", "prefetch_dir"],
            },
        ),
        types.Tool(
            name="run_hayabusa",
            description=(
                "Run Hayabusa Sigma-driven triage over a directory of .evtx files. "
                "Returns Sigma rule hits with MITRE ATT&CK tactics + techniques. "
                "Use technique_filter for narrow PtH lookups (e.g. T1550.002, T1070.001)."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "handle_id": {"type": "string"},
                    "evtx_dir": {"type": "string"},
                    "rules_dir": {"type": "string"},
                    "min_level": {
                        "type": "string",
                        "enum": ["informational", "low", "medium", "high", "critical"],
                    },
                    "technique_filter": {"type": "array", "items": {"type": "string"}},
                },
                "required": ["handle_id", "evtx_dir"],
            },
        ),
        types.Tool(
            name="parse_registry",
            description=(
                "Parse a Windows registry hive (SOFTWARE/SYSTEM/SAM/NTUSER.DAT/"
                "UsrClass.dat) via RECmd batch-plugin mode. Returns persistence "
                "findings (RunKeys/RunOnce/Services/TaskCache) + execution residue "
                "(UserAssist/ShimCache/BAM). Use plugin_filter=['RunKeys','TaskCache',"
                "'Services'] for narrow PtH persistence triage."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "handle_id": {"type": "string"},
                    "hive_path": {"type": "string"},
                    "hive_label": {
                        "type": "string",
                        "description": (
                            "Friendly hive label (SOFTWARE / SYSTEM / NTUSER:<user>)."
                        ),
                    },
                    "plugins_dir": {"type": "string"},
                    "plugin_filter": {"type": "array", "items": {"type": "string"}},
                },
                "required": ["handle_id", "hive_path", "hive_label"],
            },
        ),
        types.Tool(
            name="parse_usnjrnl",
            description=(
                "Parse the NTFS $UsnJrnl:$J change journal via MFTECmd. Returns "
                "USN records (create / rename / delete / data-overwrite). The "
                "highest-signal anti-forensic surface: catches attackers who "
                "deleted files (FileDelete reason) or dropped-then-renamed "
                "(RenameOldName/RenameNewName pairs). Filter by reason name."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "handle_id": {"type": "string"},
                    "j_path": {"type": "string", "description": "Path to extracted $J stream."},
                    "reason_filter": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "USN reason names (FileDelete, RenameNewName, RenameOldName, DataOverwrite, NamedDataOverwrite, FileCreate, …).",
                    },
                    "since": {"type": "string", "description": "ISO-8601 lower bound on UpdateTimestamp."},
                    "filter_path": {"type": "string", "description": "Case-insensitive substring filter on full_path."},
                },
                "required": ["handle_id", "j_path"],
            },
        ),
        types.Tool(
            name="plaso_supertimeline",
            description=(
                "Query a pre-built plaso .plaso storage file via psort. Returns a "
                "cross-source ordered timeline (EVTX, registry, $MFT, Prefetch, "
                "browser history, …). Pin a high-confidence anchor event then use "
                "the timeline to correlate surrounding context. source_filter "
                "accepts plaso source_short codes (EVT, REG, FILE, PREF, LNK)."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "handle_id": {"type": "string"},
                    "plaso_path": {"type": "string"},
                    "plaso_store_sha256": {"type": "string"},
                    "time_window_start": {"type": "string"},
                    "time_window_end": {"type": "string"},
                    "source_filter": {"type": "array", "items": {"type": "string"}},
                    "parser_filter": {"type": "array", "items": {"type": "string"}},
                    "description_substring": {"type": "string"},
                },
                "required": ["handle_id", "plaso_path"],
            },
        ),
        types.Tool(
            name="vol3_query",
            description=(
                "Run a Volatility 3 plugin against a memory image. The plugin must "
                "be a valid Vol3 plugin path (e.g. 'windows.pslist.PsList'). "
                "PtH-relevant plugins: windows.pslist.PsList, windows.pstree.PsTree, "
                "windows.cmdline.CmdLine, windows.netscan.NetScan, "
                "windows.lsadump.Lsadump, windows.lsadump.Cachedump, "
                "windows.lsadump.Hashdump, windows.handles.Handles, "
                "windows.malfind.Malfind, windows.svcscan.SvcScan."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "handle_id": {"type": "string"},
                    "memdump_path": {"type": "string"},
                    "plugin": {"type": "string"},
                    "plugin_args": {"type": "object"},
                },
                "required": ["handle_id", "memdump_path", "plugin"],
            },
        ),
        types.Tool(
            name="find_strings_on_image",
            description=(
                "Search a forensic disk image for files whose content matches a "
                "regex or literal substring. Backs NIST String Search-style "
                "questions: returns typed (inode, filename, deleted, "
                "first_match_offset, total_match_count) records, deduplicated "
                "and sorted. Use to_nss_answer_payload() on the data field to "
                "render the corpus-comparable answer."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "handle_id": {"type": "string"},
                    "pattern": {"type": "string"},
                    "is_regex": {"type": "boolean"},
                    "case_sensitive": {"type": "boolean"},
                    "image_offset": {"type": "integer", "description": "Partition byte offset in sectors. Default 0."},
                    "name_substring": {"type": "string", "description": "Case-insensitive filename filter applied BEFORE icat (cheap)."},
                    "include_deleted": {"type": "boolean", "description": "Default true; NSS questions need deleted entries."},
                    "max_file_size_bytes": {"type": "integer"},
                    "max_matches_per_file": {"type": "integer"},
                },
                "required": ["handle_id", "pattern"],
            },
        ),
        types.Tool(
            name="enumerate_credential_artifacts",
            description=(
                "Walk the mounted volume and return a typed inventory of "
                "credential-bearing artifacts (registry hives, DPAPI keys, "
                "browser credential DBs, LSASS dumps, hiberfil/pagefile, "
                "NTDS.dit, SSH keys). Every artifact carries its SHA-256. "
                "This is the FIRST call in autonomous triage — it tells the "
                "agent which downstream typed functions to invoke with which "
                "paths."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "handle_id": {"type": "string"},
                    "artifact_class_filter": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Whitelist of artifact classes (registry_hive, dpapi_master_key, browser_credential_db, lsass_dump, hibernation_file, pagefile, kernel_crash_dump, ntds_dit, ssh_private_key, ssh_known_hosts, ssh_host_key).",
                    },
                    "max_files": {"type": "integer", "description": "Safety cap; omit for no limit."},
                },
                "required": ["handle_id"],
            },
        ),
        types.Tool(
            name="oath_verify_claim",
            description=(
                "Submit an AgentClaim to the Witness Oath Verifier. The verifier "
                "re-runs the cited tools, confirms stdout BLAKE3 matches, and checks "
                "the record_predicate against the envelope data. Returns "
                "{verdict, reason, envelope_verdicts, predicate_matches}. Verdicts: "
                "VERIFIED, QUARANTINED, or RALPH_WIGGUM."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "claim": {
                        "type": "object",
                        "description": "An AgentClaim — see oath.witness.claim.AgentClaim schema.",
                    },
                    "reverify_kwargs": {
                        "type": "object",
                        "description": "Optional per-envelope kwargs for reverify (e.g. {'evtx-001': {'evtx_path': '/mnt/ev/Security.evtx'}}).",
                    },
                },
                "required": ["claim"],
            },
        ),
    ]


# --------------------------------------------------------------------------- #
# LLM-facing response shape                                                   #
# --------------------------------------------------------------------------- #


def _summarize_envelope(envelope_id: str, envelope: Any, sample_n: int = 5) -> dict[str, Any]:
    """Build the small LLM-facing summary of a Notarized envelope.

    We deliberately don't send the entire envelope — many tools produce
    thousands of rows; sending all of them to the LLM blows context. The
    LLM gets:
      - envelope_id (so it can cite the envelope in claims later)
      - row_count
      - first `sample_n` rows
      - tool_name, image_sha256 (so the LLM knows what it's looking at)
      - prev (chain link)
    """
    data = envelope.data
    try:
        all_rows = list(data) if hasattr(data, "__iter__") else [data]
    except TypeError:
        all_rows = [data]

    sample: list[Any] = []
    for r in all_rows[:sample_n]:
        if hasattr(r, "model_dump"):
            sample.append(r.model_dump())
        else:
            sample.append(r)

    return {
        "envelope_id": envelope_id,
        "tool_name": envelope.header.tool_name,
        "tool_version": envelope.header.tool_version,
        "image_sha256": envelope.header.image_sha256,
        "row_count": len(all_rows),
        "sample": sample,
        "prev": envelope.header.prev,
    }


# --------------------------------------------------------------------------- #
# Tool dispatch                                                               #
# --------------------------------------------------------------------------- #


def _dispatch_tool(
    server: OathServer,
    name: str,
    arguments: dict[str, Any],
) -> dict[str, Any]:
    """Synchronous dispatch from MCP tool name → typed function → response.

    Kept synchronous because the underlying forensic tools (EvtxECmd, vol3,
    Hayabusa) are blocking subprocess calls. MCP's async wrapper handles the
    event loop; we just run our tool here.

    Errors are returned as `{"error": "...", "tool": name}` rather than raising
    — the LLM consuming this layer expects every call to return a JSON dict
    (even on failure), so it can keep reasoning rather than seeing a stream
    abort.
    """
    try:
        return _dispatch_tool_inner(server, name, arguments)
    except Exception as e:  # noqa: BLE001 — surface ALL errors as content, not crash
        return {"error": f"{type(e).__name__}: {e}", "tool": name}


def _dispatch_tool_inner(
    server: OathServer,
    name: str,
    arguments: dict[str, Any],
) -> dict[str, Any]:
    """The actual dispatch logic, wrapped by `_dispatch_tool` for error surfacing."""
    # ----- control plane -----
    if name == "oath_mount":
        image_path = Path(arguments["image_path"]).expanduser().resolve()
        handle = open_handle(image_path)
        handle_id = save_handle(handle, server.handles_dir)
        return {
            "handle_id": handle_id,
            "image_sha256": handle.image_sha256,
            "image_size_bytes": handle.image_size_bytes,
            "mount_point": str(handle.mount_point) if handle.mount_point else None,
            "mount_tech": handle.mount_tech,
        }

    if name == "oath_list_handles":
        ids = sorted(p.stem for p in server.handles_dir.glob("*.json"))
        return {"handle_ids": ids}

    if name == "oath_list_envelopes":
        records = list_envelopes_anywhere(server.logs_dir)
        return {"count": len(records), "envelopes": records}

    if name == "oath_read_envelope":
        envelope_id = arguments["envelope_id"]
        return read_envelope_anywhere(server.logs_dir, envelope_id)

    # ----- typed function tools -----
    if name == "parse_evtx":
        handle = server.get_handle(arguments["handle_id"])
        env = parse_evtx.parse_evtx(
            handle,
            evtx_path=Path(arguments["evtx_path"]),
            channel=arguments.get("channel"),
            event_ids=arguments.get("event_ids"),
            time_range=tuple(arguments["time_range"]) if arguments.get("time_range") else None,
            user_sid=arguments.get("user_sid"),
            ctx=server.signing_ctx,
            prev_hash=server.envelope_store.last_prev_hash,
        )
        envelope_id = server.envelope_store.append(env)
        return _summarize_envelope(envelope_id, env)

    if name == "parse_mft":
        handle = server.get_handle(arguments["handle_id"])
        env = parse_mft.parse_mft(
            handle,
            mft_path=Path(arguments["mft_path"]),
            filter_path=arguments.get("filter_path"),
            since=arguments.get("since"),
            ctx=server.signing_ctx,
            prev_hash=server.envelope_store.last_prev_hash,
        )
        envelope_id = server.envelope_store.append(env)
        return _summarize_envelope(envelope_id, env)

    if name == "parse_amcache":
        handle = server.get_handle(arguments["handle_id"])
        env = parse_amcache.parse_amcache(
            handle,
            amcache_path=Path(arguments["amcache_path"]),
            sha1_filter=arguments.get("sha1_filter"),
            name_substring=arguments.get("name_substring"),
            ctx=server.signing_ctx,
            prev_hash=server.envelope_store.last_prev_hash,
        )
        envelope_id = server.envelope_store.append(env)
        return _summarize_envelope(envelope_id, env)

    if name == "parse_prefetch":
        handle = server.get_handle(arguments["handle_id"])
        env = parse_prefetch.parse_prefetch(
            handle,
            prefetch_dir=Path(arguments["prefetch_dir"]),
            name_filter=arguments.get("name_filter"),
            ctx=server.signing_ctx,
            prev_hash=server.envelope_store.last_prev_hash,
        )
        envelope_id = server.envelope_store.append(env)
        return _summarize_envelope(envelope_id, env)

    if name == "run_hayabusa":
        handle = server.get_handle(arguments["handle_id"])
        env = run_hayabusa.run_hayabusa(
            handle,
            evtx_dir=Path(arguments["evtx_dir"]),
            rules_dir=Path(arguments["rules_dir"]) if arguments.get("rules_dir") else None,
            min_level=arguments.get("min_level"),
            technique_filter=arguments.get("technique_filter"),
            ctx=server.signing_ctx,
            prev_hash=server.envelope_store.last_prev_hash,
        )
        envelope_id = server.envelope_store.append(env)
        return _summarize_envelope(envelope_id, env)

    if name == "parse_registry":
        handle = server.get_handle(arguments["handle_id"])
        env = parse_registry.parse_registry(
            handle,
            hive_path=Path(arguments["hive_path"]),
            hive_label=arguments["hive_label"],
            plugins_dir=Path(arguments["plugins_dir"]) if arguments.get("plugins_dir") else None,
            plugin_filter=arguments.get("plugin_filter"),
            ctx=server.signing_ctx,
            prev_hash=server.envelope_store.last_prev_hash,
        )
        envelope_id = server.envelope_store.append(env)
        return _summarize_envelope(envelope_id, env)

    if name == "parse_usnjrnl":
        handle = server.get_handle(arguments["handle_id"])
        env = parse_usnjrnl.parse_usnjrnl(
            handle,
            j_path=Path(arguments["j_path"]),
            reason_filter=arguments.get("reason_filter"),
            since=arguments.get("since"),
            filter_path=arguments.get("filter_path"),
            ctx=server.signing_ctx,
            prev_hash=server.envelope_store.last_prev_hash,
        )
        envelope_id = server.envelope_store.append(env)
        return _summarize_envelope(envelope_id, env)

    if name == "plaso_supertimeline":
        handle = server.get_handle(arguments["handle_id"])
        env = plaso_supertimeline.plaso_supertimeline(
            handle,
            plaso_path=Path(arguments["plaso_path"]),
            plaso_store_sha256=arguments.get("plaso_store_sha256"),
            time_window_start=arguments.get("time_window_start"),
            time_window_end=arguments.get("time_window_end"),
            source_filter=arguments.get("source_filter"),
            parser_filter=arguments.get("parser_filter"),
            description_substring=arguments.get("description_substring"),
            ctx=server.signing_ctx,
            prev_hash=server.envelope_store.last_prev_hash,
        )
        envelope_id = server.envelope_store.append(env)
        return _summarize_envelope(envelope_id, env)

    if name == "vol3_query":
        handle = server.get_handle(arguments["handle_id"])
        env = vol3_query.vol3_query(
            handle,
            memdump_path=Path(arguments["memdump_path"]),
            plugin=arguments["plugin"],
            plugin_args=arguments.get("plugin_args"),
            ctx=server.signing_ctx,
            prev_hash=server.envelope_store.last_prev_hash,
        )
        envelope_id = server.envelope_store.append(env)
        return _summarize_envelope(envelope_id, env)

    if name == "find_strings_on_image":
        handle = server.get_handle(arguments["handle_id"])
        env = find_strings_on_image.find_strings_on_image(
            handle,
            pattern=arguments["pattern"],
            is_regex=bool(arguments.get("is_regex", False)),
            case_sensitive=bool(arguments.get("case_sensitive", False)),
            image_offset=int(arguments.get("image_offset", 0)),
            name_substring=arguments.get("name_substring"),
            include_deleted=bool(arguments.get("include_deleted", True)),
            max_file_size_bytes=int(arguments.get("max_file_size_bytes", 256 * 1024 * 1024)),
            max_matches_per_file=int(arguments.get("max_matches_per_file", 32)),
            ctx=server.signing_ctx,
            prev_hash=server.envelope_store.last_prev_hash,
        )
        envelope_id = server.envelope_store.append(env)
        return _summarize_envelope(envelope_id, env)

    if name == "enumerate_credential_artifacts":
        handle = server.get_handle(arguments["handle_id"])
        env = enumerate_credential_artifacts.enumerate_credential_artifacts(
            handle,
            artifact_class_filter=arguments.get("artifact_class_filter"),
            max_files=arguments.get("max_files"),
            ctx=server.signing_ctx,
            prev_hash=server.envelope_store.last_prev_hash,
        )
        envelope_id = server.envelope_store.append(env)
        return _summarize_envelope(envelope_id, env)

    # ----- Witness Oath verification -----
    if name == "oath_verify_claim":
        from oath.receipt.notarized import Notarized
        claim_obj = arguments["claim"]
        # Reconstruct AgentClaim from a dict the LLM sent.
        claim = AgentClaim.model_validate(claim_obj)
        # Load all envelopes the claim references. Try the current run's
        # writable EnvelopeStore first (fast path); fall through to any
        # read-only pre-staged store under logs/ so claims that cite
        # demo-run / sample-run envelopes can be verified the same way.
        envelopes_by_id = {}
        for evidence in claim.supporting_evidence:
            try:
                envelopes_by_id[evidence.envelope_id] = server.envelope_store.load(
                    evidence.envelope_id
                )
                continue
            except KeyError:
                pass
            try:
                raw = read_envelope_anywhere(server.logs_dir, evidence.envelope_id)
                envelopes_by_id[evidence.envelope_id] = Notarized(**raw)
            except KeyError:
                pass  # the verifier will report this as unknown envelope
        reverify_kwargs = {
            eid: {k: Path(v) if k.endswith("_path") or k.endswith("_dir") else v
                  for k, v in kw.items()}
            for eid, kw in (arguments.get("reverify_kwargs") or {}).items()
        }
        verifier = WitnessOathVerifier(
            envelopes_by_id=envelopes_by_id,
            reverify_kwargs=reverify_kwargs,
            registry=default_registry(),
        )
        result = verifier.verify(claim)
        return result.model_dump()

    return {"error": f"unknown tool: {name}"}


# --------------------------------------------------------------------------- #
# MCP wiring                                                                  #
# --------------------------------------------------------------------------- #


def build_mcp_server(server_state: OathServer) -> Server:
    """Return a configured mcp.Server bound to the given OathServer state."""
    app = Server("oath")

    @app.list_tools()
    async def list_tools() -> list[types.Tool]:
        return _build_tool_descriptors()

    @app.call_tool()
    async def call_tool(name: str, arguments: dict[str, Any]) -> list[types.TextContent]:
        # `_dispatch_tool` already wraps its body in try/except and returns
        # `{"error": ...}` on failure — see its docstring. No double-wrap.
        result = _dispatch_tool(server_state, name, arguments)
        return [types.TextContent(type="text", text=json.dumps(result, default=str, indent=2))]

    return app


# --------------------------------------------------------------------------- #
# Entry point                                                                 #
# --------------------------------------------------------------------------- #


async def _async_main(*, logs_dir: Path, keys_dir: Path, run_id: str | None) -> None:
    state = OathServer(logs_dir=logs_dir, keys_dir=keys_dir, run_id=run_id)
    app = build_mcp_server(state)
    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())


def _default_data_root() -> Path:
    """Return the per-user OATH state root, honoring XDG_DATA_HOME.

    `uvx oath-mcp` typically runs with whatever cwd Claude Code spawned it in,
    so cwd-relative ./logs / ./keys defaults would scatter run state across
    every project the analyst opens. XDG keeps everything under one stable
    location: $XDG_DATA_HOME/oath, or ~/.local/share/oath as the fallback.
    """
    xdg = os.environ.get("XDG_DATA_HOME")
    base = Path(xdg).expanduser() if xdg else Path.home() / ".local" / "share"
    return base / "oath"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="oath-mcp", description="OATH MCP server")
    data_root = _default_data_root()
    parser.add_argument("--logs-dir", type=Path, default=data_root / "logs")
    parser.add_argument("--keys-dir", type=Path, default=data_root / "keys")
    parser.add_argument(
        "--run-id",
        type=str,
        default=None,
        help="Pre-existing run_id to resume, otherwise a fresh UUID is minted.",
    )
    parser.add_argument("--version", action="version", version=f"oath-mcp {__version__}")
    args = parser.parse_args(argv)
    args.logs_dir.mkdir(parents=True, exist_ok=True)
    args.keys_dir.mkdir(parents=True, exist_ok=True)

    try:
        asyncio.run(
            _async_main(logs_dir=args.logs_dir, keys_dir=args.keys_dir, run_id=args.run_id)
        )
    except KeyboardInterrupt:
        return 130
    return 0


if __name__ == "__main__":
    sys.exit(main())
