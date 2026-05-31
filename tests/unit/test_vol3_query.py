"""Unit tests for vol3_query (Volatility 3 memory analysis)."""
from __future__ import annotations

import tempfile
from dataclasses import dataclass
from pathlib import Path

import pytest

from oath.mcp.evidence_handle import EvidenceHandle
from oath.mcp.tools.vol3_query import (
    PTH_RELEVANT_PLUGINS,
    VOL3_VERSION_FLOOR,
    Vol3Result,
    Vol3Row,
    _parse_vol3_output,
    lsadump_secrets,
    pslist_processes,
    reverify,
    vol3_query,
)
from oath.receipt.notarized import SigningContext, verify_signature


# Realistic Volatility 3 windows.pslist.PsList output (json_lines format)
PSLIST_JSONL = b"""{"PID": 4, "PPID": 0, "ImageFileName": "System", "Offset(V)": "0xffff8e00", "Threads": 234, "Handles": null, "SessionId": null, "Wow64": false, "CreateTime": "2026-04-12 12:00:00.000000 UTC", "ExitTime": null}
{"PID": 808, "PPID": 4, "ImageFileName": "lsass.exe", "Offset(V)": "0xffff8e01", "Threads": 9, "Handles": null, "SessionId": 0, "Wow64": false, "CreateTime": "2026-04-12 12:00:30.000000 UTC", "ExitTime": null}
{"PID": 4444, "PPID": 808, "ImageFileName": "rundll32.exe", "Offset(V)": "0xffff8e99", "Threads": 5, "Handles": null, "SessionId": 1, "Wow64": false, "CreateTime": "2026-04-12 14:32:01.000000 UTC", "ExitTime": null}
"""

# Realistic windows.lsadump.Lsadump output — encrypted LSA secrets
LSADUMP_JSONL = b"""{"Key": "DefaultPassword", "Secret": "\\\\x00s\\\\x00e\\\\x00c\\\\x00r\\\\x00e\\\\x00t\\\\x00"}
{"Key": "NL$KM", "Secret": "binary blob"}
"""


@dataclass
class FakeExecutor:
    payload: bytes
    calls: list[list[str]] = None

    def __post_init__(self) -> None:
        self.calls = []

    def run(self, argv: list[str], *, capture: bool = True, timeout: float = 300) -> bytes:
        self.calls.append(list(argv))
        return self.payload


@pytest.fixture
def ctx() -> SigningContext:
    with tempfile.TemporaryDirectory() as tmp:
        yield SigningContext.load_or_mint(Path(tmp), run_id="test-vol3")


@pytest.fixture
def handle(tmp_path: Path) -> EvidenceHandle:
    img = tmp_path / "dummy.E01"
    img.write_bytes(b"\x00" * 1024)
    return EvidenceHandle(
        image_path=img,
        image_sha256="9" * 64,
        image_size_bytes=1024,
        mount_point=tmp_path,
        mount_tech="raw-file",
        run_id="vol3-test",
    )


@pytest.fixture
def memdump(tmp_path: Path) -> Path:
    p = tmp_path / "victim.lime"
    p.write_bytes(b"MEM_PLACEHOLDER" * 64)
    return p


# --------------------------------------------------------------------------- #
# Output parsing — JSONL / JSON-array / CSV                                   #
# --------------------------------------------------------------------------- #


class TestVol3OutputParsing:
    def test_jsonl_parsed_into_rows(self) -> None:
        result = _parse_vol3_output(PSLIST_JSONL, "windows.pslist.PsList")
        assert isinstance(result, Vol3Result)
        assert result.plugin == "windows.pslist.PsList"
        assert len(result.rows) == 3
        assert result.rows[0].data["ImageFileName"] == "System"
        assert result.rows[1].data["ImageFileName"] == "lsass.exe"
        assert result.rows[2].data["ImageFileName"] == "rundll32.exe"

    def test_empty_output_returns_empty_result(self) -> None:
        result = _parse_vol3_output(b"", "windows.pslist.PsList")
        assert result.rows == ()
        assert result.banner is None

    def test_unparseable_output_becomes_banner(self) -> None:
        garbage = b"Volatility 3 says: this is a stack trace not a plugin output"
        result = _parse_vol3_output(garbage, "windows.pslist.PsList")
        assert result.rows == ()
        assert result.banner is not None
        assert "stack trace" in result.banner

    def test_json_array_form(self) -> None:
        json_array = b'[{"PID": 1, "ImageFileName": "a"}, {"PID": 2, "ImageFileName": "b"}]'
        result = _parse_vol3_output(json_array, "windows.pslist.PsList")
        assert len(result.rows) == 2


# --------------------------------------------------------------------------- #
# Round-trip + envelope provenance                                            #
# --------------------------------------------------------------------------- #


class TestVol3QueryRoundTrip:
    def test_round_trip_verifies(self, ctx, handle, memdump):
        env = vol3_query(
            handle,
            memdump_path=memdump,
            plugin="windows.pslist.PsList",
            ctx=ctx,
            executor=FakeExecutor(payload=PSLIST_JSONL),
        )
        assert verify_signature(env, ctx.public_key) is True
        assert env.header.tool_name == "vol3_query"
        assert env.header.tool_version == VOL3_VERSION_FLOOR
        assert env.header.image_sha256 == handle.image_sha256
        assert env.data.plugin == "windows.pslist.PsList"
        assert len(env.data.rows) == 3

    def test_plugin_name_is_in_argv_and_args_canonical(self, ctx, handle, memdump):
        executor = FakeExecutor(payload=PSLIST_JSONL)
        env = vol3_query(
            handle,
            memdump_path=memdump,
            plugin="windows.lsadump.Lsadump",
            ctx=ctx,
            executor=executor,
        )
        # Plugin name appears in argv after the file flag
        argv = executor.calls[0]
        assert "windows.lsadump.Lsadump" in argv
        # Plugin name is bound into the canonical args
        assert '"plugin":"windows.lsadump.Lsadump"' in env.header.args_canonical

    def test_plugin_args_flow_to_argv_and_canonicalized(self, ctx, handle, memdump):
        executor = FakeExecutor(payload=PSLIST_JSONL)
        vol3_query(
            handle,
            memdump_path=memdump,
            plugin="windows.handles.Handles",
            plugin_args={"--pid": "808", "--object-type": "Process"},
            ctx=ctx,
            executor=executor,
        )
        argv = executor.calls[0]
        # Both flags appear; order is sorted (canonical)
        assert "--object-type" in argv
        assert "--pid" in argv
        assert "808" in argv
        assert "Process" in argv

    def test_symbol_pack_hash_bound_into_args_canonical(self, ctx, handle, memdump):
        sym_hash = "f" * 64
        env = vol3_query(
            handle,
            memdump_path=memdump,
            plugin="windows.pslist.PsList",
            ctx=ctx,
            symbol_pack_hash=sym_hash,
            executor=FakeExecutor(payload=PSLIST_JSONL),
        )
        assert sym_hash in env.header.args_canonical


# --------------------------------------------------------------------------- #
# Helper extractors for high-value PtH plugins                                #
# --------------------------------------------------------------------------- #


class TestPluginHelpers:
    def test_pslist_processes_returns_raw_dicts(self, ctx, handle, memdump):
        env = vol3_query(
            handle,
            memdump_path=memdump,
            plugin="windows.pslist.PsList",
            ctx=ctx,
            executor=FakeExecutor(payload=PSLIST_JSONL),
        )
        procs = pslist_processes(env)
        assert len(procs) == 3
        names = {p["ImageFileName"] for p in procs}
        assert {"System", "lsass.exe", "rundll32.exe"} == names

    def test_lsadump_secrets_returns_rows_for_lsadump_plugin(self, ctx, handle, memdump):
        env = vol3_query(
            handle,
            memdump_path=memdump,
            plugin="windows.lsadump.Lsadump",
            ctx=ctx,
            executor=FakeExecutor(payload=LSADUMP_JSONL),
        )
        secrets = lsadump_secrets(env)
        keys = {s["Key"] for s in secrets}
        assert "DefaultPassword" in keys
        assert "NL$KM" in keys

    def test_pslist_helper_returns_empty_for_other_plugins(self, ctx, handle, memdump):
        """pslist_processes() only returns rows for the pslist plugin; other plugins yield []."""
        env = vol3_query(
            handle,
            memdump_path=memdump,
            plugin="windows.lsadump.Lsadump",
            ctx=ctx,
            executor=FakeExecutor(payload=LSADUMP_JSONL),
        )
        assert pslist_processes(env) == []

    def test_pth_relevant_plugins_includes_key_must_haves(self):
        """The canonical PtH plugin set must cover credential dumps + lateral movement."""
        assert "windows.lsadump.Lsadump" in PTH_RELEVANT_PLUGINS
        assert "windows.lsadump.Hashdump" in PTH_RELEVANT_PLUGINS
        assert "windows.lsadump.Cachedump" in PTH_RELEVANT_PLUGINS
        assert "windows.pslist.PsList" in PTH_RELEVANT_PLUGINS
        assert "windows.netscan.NetScan" in PTH_RELEVANT_PLUGINS
        assert "windows.malfind.Malfind" in PTH_RELEVANT_PLUGINS


# --------------------------------------------------------------------------- #
# Tamper detection (reverify)                                                 #
# --------------------------------------------------------------------------- #


class TestVol3Reverify:
    def test_reverify_passes_when_unchanged(self, ctx, handle, memdump):
        env = vol3_query(
            handle,
            memdump_path=memdump,
            plugin="windows.pslist.PsList",
            ctx=ctx,
            executor=FakeExecutor(payload=PSLIST_JSONL),
        )
        ok, _ = reverify(env, memdump_path=memdump, executor=FakeExecutor(payload=PSLIST_JSONL))
        assert ok is True

    def test_reverify_fails_on_drift(self, ctx, handle, memdump):
        env = vol3_query(
            handle,
            memdump_path=memdump,
            plugin="windows.pslist.PsList",
            ctx=ctx,
            executor=FakeExecutor(payload=PSLIST_JSONL),
        )
        tampered = PSLIST_JSONL.replace(b"lsass.exe", b"benign.exe")
        ok, reason = reverify(env, memdump_path=memdump, executor=FakeExecutor(payload=tampered))
        assert ok is False
        assert "drift" in reason.lower()
