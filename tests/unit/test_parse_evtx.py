"""Unit tests for parse_evtx — the first typed MCP function.

These tests pin the contract between the typed function and the Notarized
envelope: identical input → identical args_canonical and stdout_blake3;
filter changes → different args_canonical (different envelopes); tampering
with the underlying tool output → re-verification fails.

We inject a FakeExecutor so tests don't depend on EvtxECmd or .NET being
installed — the same dependency-injection pattern every typed function will
use, which makes the entire typed-function layer unit-testable without the
forensic toolchain in CI.
"""
from __future__ import annotations

import tempfile
from dataclasses import dataclass
from pathlib import Path

import pytest

from oath.mcp.evidence_handle import EvidenceHandle
from oath.mcp.tools.parse_evtx import (
    EVTXECMD_VERSION,
    EvtxRecord,
    ToolExecutor,
    parse_evtx,
    reverify,
)
from oath.receipt.notarized import SigningContext, verify_signature


# --------------------------------------------------------------------------- #
# Test fixtures                                                               #
# --------------------------------------------------------------------------- #


# A minimal CSV that mimics EvtxECmd 1.5.0.0 --csv output. Two records:
# a Type-3 NTLM logon (canonical PtH shape) and a Type-2 interactive logon.
SAMPLE_CSV = b"""RecordNumber,EventRecordId,TimeCreated,EventId,Level,Provider,Channel,Computer,UserId,MapDescription,ChunkNumber,UserName,RemoteHost,PayloadData1,PayloadData2,PayloadData3,PayloadData4,PayloadData5,ExecutableInfo,HiddenRecord,SourceFile,Payload
8392,8392,2026-04-12T14:32:01.1234567Z,4624,Information,Microsoft-Windows-Security-Auditing,Security,WIN-VICTIM01,S-1-5-21-1234-5678-9012-1001,,1,Administrator,10.0.0.42,3,NTLM,NTLM V2,,,,,,Security.evtx,An account was successfully logged on. ...
8393,8393,2026-04-12T14:33:55.7654321Z,4624,Information,Microsoft-Windows-Security-Auditing,Security,WIN-VICTIM01,S-1-5-21-1234-5678-9012-1001,,1,jdoe,,2,Kerberos,Kerberos,,,,,,Security.evtx,An account was successfully logged on. ...
"""


@dataclass
class FakeExecutor:
    """Test-only ToolExecutor returning a canned bytes payload."""

    payload: bytes
    calls: list[list[str]] = None

    def __post_init__(self) -> None:
        self.calls = []

    def run(self, argv: list[str], *, capture: bool = True, timeout: float = 300) -> bytes:
        self.calls.append(list(argv))
        # EvtxECmd 2026.5.0 writes to `--csv <dir> --csvf <file>`; mirror that
        # contract so production code's "executor.run(); open(out_csv)" pattern
        # works against this fake.
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
def ctx():
    with tempfile.TemporaryDirectory() as tmp:
        yield SigningContext.load_or_mint(Path(tmp), run_id="test-evtx")


@pytest.fixture
def handle(tmp_path: Path) -> EvidenceHandle:
    """Fake EvidenceHandle anchored to a dummy image SHA-256."""
    img = tmp_path / "dummy.E01"
    img.write_bytes(b"\x00" * 1024)
    return EvidenceHandle(
        image_path=img,
        image_sha256="a" * 64,
        image_size_bytes=1024,
        mount_point=tmp_path,
        mount_tech="raw-file",
        run_id="test-evtx-run",
    )


@pytest.fixture
def fake_evtx(tmp_path: Path) -> Path:
    """A dummy .evtx file (we don't actually parse it — the executor is faked)."""
    p = tmp_path / "Security.evtx"
    p.write_bytes(b"EVTX_PLACEHOLDER")
    return p


# --------------------------------------------------------------------------- #
# Core contract: mint emits a valid signed envelope                           #
# --------------------------------------------------------------------------- #


def test_parse_evtx_produces_valid_signed_envelope(
    ctx: SigningContext, handle: EvidenceHandle, fake_evtx: Path
) -> None:
    executor = FakeExecutor(payload=SAMPLE_CSV)
    env = parse_evtx(
        handle,
        evtx_path=fake_evtx,
        event_ids=[4624, 4625],
        ctx=ctx,
        executor=executor,
    )

    # Envelope verifies under the run's public key.
    assert verify_signature(env, ctx.public_key) is True

    # Tool + version pinned correctly.
    assert env.header.tool_name == "parse_evtx"
    assert env.header.tool_version == EVTXECMD_VERSION

    # Image binding present.
    assert env.header.image_sha256 == handle.image_sha256

    # Two records survived the 4624/4625 filter.
    assert len(env.data) == 2
    assert all(isinstance(r, EvtxRecord) for r in env.data)


def test_records_extract_auth_columns_natively(
    ctx: SigningContext, handle: EvidenceHandle, fake_evtx: Path
) -> None:
    """LogonType / AuthPackage / RemoteHost are surfaced as typed fields, not buried in Payload."""
    env = parse_evtx(
        handle,
        evtx_path=fake_evtx,
        ctx=ctx,
        executor=FakeExecutor(payload=SAMPLE_CSV),
    )
    pth_candidate = env.data[0]
    assert pth_candidate.event_id == 4624
    assert pth_candidate.logon_type == 3
    assert pth_candidate.auth_package == "NTLM"
    assert pth_candidate.source_ip == "10.0.0.42"
    assert pth_candidate.user_name == "Administrator"


# --------------------------------------------------------------------------- #
# Args canonicalization (filter changes → different args_canonical)           #
# --------------------------------------------------------------------------- #


def test_filter_change_produces_different_envelope_header(
    ctx: SigningContext, handle: EvidenceHandle, fake_evtx: Path
) -> None:
    e1 = parse_evtx(
        handle,
        evtx_path=fake_evtx,
        event_ids=[4624],
        ctx=ctx,
        executor=FakeExecutor(payload=SAMPLE_CSV),
    )
    e2 = parse_evtx(
        handle,
        evtx_path=fake_evtx,
        event_ids=[4624, 4625],
        ctx=ctx,
        executor=FakeExecutor(payload=SAMPLE_CSV),
    )
    # Different event_id filter → different args_canonical → different header.
    assert e1.header.args_canonical != e2.header.args_canonical


def test_filter_order_does_not_affect_canonicalization(
    ctx: SigningContext, handle: EvidenceHandle, fake_evtx: Path
) -> None:
    """[4624, 4625] and [4625, 4624] must produce identical canonical args."""
    e1 = parse_evtx(
        handle,
        evtx_path=fake_evtx,
        event_ids=[4624, 4625],
        ctx=ctx,
        executor=FakeExecutor(payload=SAMPLE_CSV),
    )
    e2 = parse_evtx(
        handle,
        evtx_path=fake_evtx,
        event_ids=[4625, 4624],
        ctx=ctx,
        executor=FakeExecutor(payload=SAMPLE_CSV),
    )
    assert e1.header.args_canonical == e2.header.args_canonical


# --------------------------------------------------------------------------- #
# Argv plumbing (downstream tool gets the right flags)                        #
# --------------------------------------------------------------------------- #


def test_event_id_filter_flows_to_argv(
    ctx: SigningContext, handle: EvidenceHandle, fake_evtx: Path
) -> None:
    executor = FakeExecutor(payload=SAMPLE_CSV)
    parse_evtx(
        handle,
        evtx_path=fake_evtx,
        event_ids=[4624, 4625, 4768],
        ctx=ctx,
        executor=executor,
    )
    assert len(executor.calls) == 1
    argv = executor.calls[0]
    assert "--inc" in argv
    inc_value = argv[argv.index("--inc") + 1]
    assert "4624" in inc_value
    assert "4625" in inc_value
    assert "4768" in inc_value


def test_time_range_flows_to_argv(
    ctx: SigningContext, handle: EvidenceHandle, fake_evtx: Path
) -> None:
    executor = FakeExecutor(payload=SAMPLE_CSV)
    parse_evtx(
        handle,
        evtx_path=fake_evtx,
        time_range=("2026-04-12T00:00:00Z", "2026-04-13T00:00:00Z"),
        ctx=ctx,
        executor=executor,
    )
    argv = executor.calls[0]
    assert "--sd" in argv and "--ed" in argv


# --------------------------------------------------------------------------- #
# Tamper detection — re-verification                                          #
# --------------------------------------------------------------------------- #


def test_reverify_passes_when_tool_output_unchanged(
    ctx: SigningContext, handle: EvidenceHandle, fake_evtx: Path
) -> None:
    executor = FakeExecutor(payload=SAMPLE_CSV)
    env = parse_evtx(handle, evtx_path=fake_evtx, ctx=ctx, executor=executor)
    ok, reason = reverify(env, evtx_path=fake_evtx, executor=FakeExecutor(payload=SAMPLE_CSV))
    assert ok is True, reason


def test_reverify_fails_when_tool_output_drifts(
    ctx: SigningContext, handle: EvidenceHandle, fake_evtx: Path
) -> None:
    env = parse_evtx(
        handle,
        evtx_path=fake_evtx,
        ctx=ctx,
        executor=FakeExecutor(payload=SAMPLE_CSV),
    )
    tampered = SAMPLE_CSV.replace(b"10.0.0.42", b"10.0.0.99")
    ok, reason = reverify(env, evtx_path=fake_evtx, executor=FakeExecutor(payload=tampered))
    assert ok is False
    assert "drift" in reason.lower()
