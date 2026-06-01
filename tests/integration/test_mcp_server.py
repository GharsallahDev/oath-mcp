"""Integration tests for the MCP server's tool-dispatch layer.

We exercise the server's `_dispatch_tool()` directly rather than via stdio —
the stdio layer is a thin pass-through to the dispatch, and testing it
adds no architectural coverage. The dispatch is what matters: each tool name
maps to the correct typed function, the right envelope is minted, the right
LLM-facing summary is returned.

A monkeypatched ToolExecutor lets us drive these end-to-end without EvtxECmd
/ MFTECmd / Hayabusa / vol3 actually installed.
"""
from __future__ import annotations

import os
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from unittest.mock import patch

import pytest

from oath.mcp.evidence_handle import EvidenceHandle
from oath.mcp.server import OathServer, _dispatch_tool, _summarize_envelope


# --------------------------------------------------------------------------- #
# Fixtures                                                                    #
# --------------------------------------------------------------------------- #


SAMPLE_EVTX_CSV = (
    b"RecordNumber,EventRecordId,TimeCreated,EventId,Level,Provider,Channel,Computer,UserId,"
    b"MapDescription,ChunkNumber,UserName,RemoteHost,PayloadData1,PayloadData2,PayloadData3,"
    b"PayloadData4,PayloadData5,ExecutableInfo,HiddenRecord,SourceFile,Payload\n"
    b"8392,8392,2026-04-12T14:32:01Z,4624,Information,Microsoft-Windows-Security-Auditing,"
    b"Security,WIN-VICTIM01,S-1-5-21-1001,,1,Administrator,10.0.0.42,3,NTLM,NTLM V2,,,,,,"
    b"Security.evtx,An account was successfully logged on. ...\n"
)


SAMPLE_MFT_CSV = (
    b"EntryNumber,SequenceNumber,ParentEntryNumber,ParentSequenceNumber,InUse,IsDirectory,"
    b"FileName,Extension,ParentPath,FileSize,Created0x10,LastModified0x10,LastAccess0x10,"
    b"LastRecordChange0x10,Created0x30,LastModified0x30,LastAccess0x30,LastRecordChange0x30,"
    b"HasAds,HasObjectId,HasReparsePoint\n"
    b"12346,1,5,5,true,false,psexesvc.exe,exe,C:\\Windows,191872,"
    b"2018-01-01T00:00:00,2018-01-01T00:00:00,2026-04-12T14:32:01,2018-01-01T00:00:00,"
    b"2026-04-12T14:32:00,2026-04-12T14:32:00,2026-04-12T14:32:01,2026-04-12T14:32:00,"
    b"false,false,false\n"
)


@dataclass
class FakeExecutor:
    payload: bytes
    calls: list[list[str]] = None

    def __post_init__(self) -> None:
        self.calls = []

    def run(self, argv: list[str], *, capture: bool = True, timeout: float = 300) -> bytes:
        self.calls.append(list(argv))
        # EvtxECmd 2026.5.0 writes to `--csv <dir> --csvf <file>`. Mirror.
        if "--csv" in argv and "--csvf" in argv:
            csv_idx = argv.index("--csv")
            csvf_idx = argv.index("--csvf")
            if csv_idx + 1 < len(argv) and csvf_idx + 1 < len(argv):
                from pathlib import Path as _P
                outpath = _P(argv[csv_idx + 1]) / argv[csvf_idx + 1]
                outpath.parent.mkdir(parents=True, exist_ok=True)
                outpath.write_bytes(self.payload)
        return self.payload


@pytest.fixture
def server_state(tmp_path: Path) -> OathServer:
    logs_dir = tmp_path / "logs"
    keys_dir = tmp_path / "keys"
    return OathServer(logs_dir=logs_dir, keys_dir=keys_dir)


@pytest.fixture
def image_file(tmp_path: Path) -> Path:
    p = tmp_path / "test_image.E01"
    p.write_bytes(b"\x00" * 4096)
    return p


# --------------------------------------------------------------------------- #
# Tool dispatch — oath_mount + oath_list_handles                              #
# --------------------------------------------------------------------------- #


class TestControlPlane:
    def test_mount_returns_handle_id_and_records_handle(
        self, server_state: OathServer, image_file: Path
    ) -> None:
        result = _dispatch_tool(server_state, "oath_mount", {"image_path": str(image_file)})
        assert "handle_id" in result
        assert len(result["handle_id"]) == 16
        assert "image_sha256" in result
        assert len(result["image_sha256"]) == 64

        # Listing should now return the new handle
        listing = _dispatch_tool(server_state, "oath_list_handles", {})
        assert result["handle_id"] in listing["handle_ids"]

    def test_mount_of_missing_file_returns_error(
        self, server_state: OathServer, tmp_path: Path
    ) -> None:
        result = _dispatch_tool(
            server_state, "oath_mount", {"image_path": str(tmp_path / "does-not-exist.E01")}
        )
        assert "error" in result
        assert "not found" in result["error"].lower() or "FileNotFoundError" in result["error"]


# --------------------------------------------------------------------------- #
# Tool dispatch — typed function plumbing                                     #
# --------------------------------------------------------------------------- #


class TestTypedFunctionDispatch:
    def test_parse_evtx_mints_envelope_and_returns_summary(
        self, server_state: OathServer, image_file: Path, tmp_path: Path
    ) -> None:
        # Mount
        mount_result = _dispatch_tool(server_state, "oath_mount", {"image_path": str(image_file)})
        handle_id = mount_result["handle_id"]

        # Make a fake .evtx file for the test
        evtx = tmp_path / "Security.evtx"
        evtx.write_bytes(b"EVTX_PLACEHOLDER")

        # Patch the SubprocessExecutor at the parse_evtx module level so the typed
        # function uses our fake instead of shelling out to EvtxECmd.
        with patch(
            "oath.mcp.tools.parse_evtx.SubprocessExecutor",
            return_value=FakeExecutor(payload=SAMPLE_EVTX_CSV),
        ):
            result = _dispatch_tool(
                server_state,
                "parse_evtx",
                {
                    "handle_id": handle_id,
                    "evtx_path": str(evtx),
                    "event_ids": [4624, 4625],
                },
            )

        # The LLM-facing summary must include envelope_id, tool name, row count, sample.
        assert "envelope_id" in result
        assert result["tool_name"] == "parse_evtx"
        assert result["row_count"] == 1  # one record in SAMPLE_EVTX_CSV
        assert isinstance(result["sample"], list)
        assert result["sample"][0]["event_id"] == 4624
        assert result["sample"][0]["logon_type"] == 3
        assert result["image_sha256"] == mount_result["image_sha256"]

    def test_parse_mft_mints_envelope_and_returns_summary(
        self, server_state: OathServer, image_file: Path, tmp_path: Path
    ) -> None:
        mount_result = _dispatch_tool(server_state, "oath_mount", {"image_path": str(image_file)})
        handle_id = mount_result["handle_id"]

        mft = tmp_path / "$MFT"
        mft.write_bytes(b"MFT_PLACEHOLDER" * 8)

        with patch(
            "oath.mcp.tools.parse_mft.SubprocessExecutor",
            return_value=FakeExecutor(payload=SAMPLE_MFT_CSV),
        ):
            result = _dispatch_tool(
                server_state,
                "parse_mft",
                {"handle_id": handle_id, "mft_path": str(mft)},
            )

        assert result["tool_name"] == "parse_mft"
        assert result["row_count"] == 1
        assert result["sample"][0]["file_name"] == "psexesvc.exe"

    def test_two_sequential_calls_chain_via_prev_hash(
        self, server_state: OathServer, image_file: Path, tmp_path: Path
    ) -> None:
        """Second envelope's `prev` field links to first envelope's header_hash."""
        mount_result = _dispatch_tool(server_state, "oath_mount", {"image_path": str(image_file)})
        handle_id = mount_result["handle_id"]

        evtx = tmp_path / "Security.evtx"
        evtx.write_bytes(b"EVTX_PLACEHOLDER")
        mft = tmp_path / "$MFT"
        mft.write_bytes(b"MFT_PLACEHOLDER" * 8)

        with patch(
            "oath.mcp.tools.parse_evtx.SubprocessExecutor",
            return_value=FakeExecutor(payload=SAMPLE_EVTX_CSV),
        ):
            r1 = _dispatch_tool(
                server_state,
                "parse_evtx",
                {"handle_id": handle_id, "evtx_path": str(evtx)},
            )
        with patch(
            "oath.mcp.tools.parse_mft.SubprocessExecutor",
            return_value=FakeExecutor(payload=SAMPLE_MFT_CSV),
        ):
            r2 = _dispatch_tool(
                server_state,
                "parse_mft",
                {"handle_id": handle_id, "mft_path": str(mft)},
            )

        # First envelope had no prev (None); second envelope's prev == first's envelope_id.
        assert r1["prev"] is None
        assert r2["prev"] == r1["envelope_id"]


# --------------------------------------------------------------------------- #
# Tool dispatch — error surfacing                                             #
# --------------------------------------------------------------------------- #


class TestErrorSurfacing:
    def test_unknown_tool_returns_error_dict(self, server_state: OathServer) -> None:
        result = _dispatch_tool(server_state, "nonexistent_tool", {})
        assert "error" in result
        assert "unknown tool" in result["error"].lower()

    def test_parse_evtx_with_unknown_handle_returns_error(
        self, server_state: OathServer, tmp_path: Path
    ) -> None:
        evtx = tmp_path / "Security.evtx"
        evtx.write_bytes(b"x")
        result = _dispatch_tool(
            server_state,
            "parse_evtx",
            {"handle_id": "deadbeef00000000", "evtx_path": str(evtx)},
        )
        assert "error" in result


# --------------------------------------------------------------------------- #
# Summary builder                                                             #
# --------------------------------------------------------------------------- #


class TestSummaryShape:
    def test_summarize_envelope_includes_required_fields(
        self, server_state: OathServer, image_file: Path, tmp_path: Path
    ) -> None:
        mount_result = _dispatch_tool(server_state, "oath_mount", {"image_path": str(image_file)})
        evtx = tmp_path / "Security.evtx"
        evtx.write_bytes(b"x")

        with patch(
            "oath.mcp.tools.parse_evtx.SubprocessExecutor",
            return_value=FakeExecutor(payload=SAMPLE_EVTX_CSV),
        ):
            result = _dispatch_tool(
                server_state,
                "parse_evtx",
                {"handle_id": mount_result["handle_id"], "evtx_path": str(evtx)},
            )

        # The LLM-facing schema we promised in server.py
        for field in (
            "envelope_id",
            "tool_name",
            "tool_version",
            "image_sha256",
            "row_count",
            "sample",
            "prev",
        ):
            assert field in result, f"missing field: {field}"

    def test_sample_is_truncated_not_full_data(
        self, server_state: OathServer, image_file: Path, tmp_path: Path
    ) -> None:
        """A 100-row tool output should only return ~5 sample rows to the LLM."""
        big_csv_lines = [SAMPLE_EVTX_CSV.split(b"\n", 1)[0].decode()]  # header
        for i in range(100):
            big_csv_lines.append(
                f"{8000 + i},{8000 + i},2026-04-12T14:32:01Z,4624,Information,"
                "Microsoft-Windows-Security-Auditing,Security,WIN-VICTIM01,S-1-5,,1,user,"
                "10.0.0.1,3,NTLM,NTLM V2,,,,,,Security.evtx,An account was successfully logged on."
            )
        big_csv = ("\n".join(big_csv_lines) + "\n").encode()

        mount_result = _dispatch_tool(server_state, "oath_mount", {"image_path": str(image_file)})
        evtx = tmp_path / "Security.evtx"
        evtx.write_bytes(b"x")

        with patch(
            "oath.mcp.tools.parse_evtx.SubprocessExecutor",
            return_value=FakeExecutor(payload=big_csv),
        ):
            result = _dispatch_tool(
                server_state,
                "parse_evtx",
                {"handle_id": mount_result["handle_id"], "evtx_path": str(evtx)},
            )

        assert result["row_count"] == 100
        # Sample is bounded — never the full 100
        assert len(result["sample"]) <= 5
