"""Unit tests for parse_mft + the timestomp-candidate detector."""
from __future__ import annotations

import tempfile
from dataclasses import dataclass
from pathlib import Path

import pytest

from oath.mcp.evidence_handle import EvidenceHandle
from oath.mcp.tools.parse_mft import (
    MFTECMD_VERSION,
    MftEntry,
    find_timestomp_candidates,
    parse_mft,
    reverify,
)
from oath.receipt.notarized import SigningContext, verify_signature

# A 3-row MFTECmd CSV fixture covering:
#   1. A normal Windows file (SI ~ FN, no timestomp)
#   2. A timestomp candidate (SI predates FN by a year — classic SetMACE pattern)
#   3. A directory entry (the canonical "Users" folder)
SAMPLE_CSV = b"""EntryNumber,SequenceNumber,ParentEntryNumber,ParentSequenceNumber,InUse,IsDirectory,FileName,Extension,ParentPath,FileSize,Created0x10,LastModified0x10,LastAccess0x10,LastRecordChange0x10,Created0x30,LastModified0x30,LastAccess0x30,LastRecordChange0x30,HasAds,HasObjectId,HasReparsePoint
12345,1,5,5,true,false,kernel32.dll,dll,C:\\Windows\\System32,712704,2024-12-01T08:00:00,2024-12-01T08:00:00,2026-04-12T14:00:00,2024-12-01T08:00:00,2024-12-01T08:00:00,2024-12-01T08:00:00,2024-12-01T08:00:00,2024-12-01T08:00:00,false,false,false
12346,1,5,5,true,false,psexesvc.exe,exe,C:\\Windows,191872,2018-01-01T00:00:00,2018-01-01T00:00:00,2026-04-12T14:32:01,2018-01-01T00:00:00,2026-04-12T14:32:00,2026-04-12T14:32:00,2026-04-12T14:32:01,2026-04-12T14:32:00,false,false,false
12347,1,5,5,true,true,Users,,C:\\,0,2024-11-15T12:00:00,2024-11-15T12:00:00,2026-04-12T14:00:00,2024-11-15T12:00:00,2024-11-15T12:00:00,2024-11-15T12:00:00,2024-11-15T12:00:00,2024-11-15T12:00:00,false,false,false
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
        yield SigningContext.load_or_mint(Path(tmp), run_id="test-mft")


@pytest.fixture
def handle(tmp_path: Path) -> EvidenceHandle:
    img = tmp_path / "dummy.E01"
    img.write_bytes(b"\x00" * 1024)
    return EvidenceHandle(
        image_path=img,
        image_sha256="b" * 64,
        image_size_bytes=1024,
        mount_point=tmp_path,
        mount_tech="raw-file",
        run_id="test-mft-run",
    )


@pytest.fixture
def mft_file(tmp_path: Path) -> Path:
    p = tmp_path / "$MFT"
    p.write_bytes(b"MFT_PLACEHOLDER" * 64)
    return p


# --------------------------------------------------------------------------- #
# Round-trip + tool-version pinning                                           #
# --------------------------------------------------------------------------- #


def test_parse_mft_round_trip_verifies(
    ctx: SigningContext, handle: EvidenceHandle, mft_file: Path
) -> None:
    env = parse_mft(
        handle,
        mft_path=mft_file,
        ctx=ctx,
        executor=FakeExecutor(payload=SAMPLE_CSV),
    )
    assert verify_signature(env, ctx.public_key) is True
    assert env.header.tool_name == "parse_mft"
    assert env.header.tool_version == MFTECMD_VERSION
    assert env.header.image_sha256 == handle.image_sha256


def test_records_have_typed_si_and_fn_timestamps(
    ctx: SigningContext, handle: EvidenceHandle, mft_file: Path
) -> None:
    env = parse_mft(
        handle,
        mft_path=mft_file,
        ctx=ctx,
        executor=FakeExecutor(payload=SAMPLE_CSV),
    )
    psexesvc = next(e for e in env.data if e.file_name == "psexesvc.exe")
    assert psexesvc.si_created == "2018-01-01T00:00:00"
    assert psexesvc.fn_created == "2026-04-12T14:32:00"
    assert psexesvc.parent_entry_number == 5
    assert psexesvc.in_use is True
    assert psexesvc.is_directory is False


def test_full_path_reconstruction(
    ctx: SigningContext, handle: EvidenceHandle, mft_file: Path
) -> None:
    env = parse_mft(
        handle,
        mft_path=mft_file,
        ctx=ctx,
        executor=FakeExecutor(payload=SAMPLE_CSV),
    )
    psexesvc = next(e for e in env.data if e.file_name == "psexesvc.exe")
    assert psexesvc.full_path == "C:\\Windows\\psexesvc.exe"


# --------------------------------------------------------------------------- #
# Filtering                                                                   #
# --------------------------------------------------------------------------- #


def test_path_filter_is_case_insensitive(
    ctx: SigningContext, handle: EvidenceHandle, mft_file: Path
) -> None:
    env = parse_mft(
        handle,
        mft_path=mft_file,
        filter_path="WINDOWS\\system32",  # case-insensitive against "C:\\Windows\\System32"
        ctx=ctx,
        executor=FakeExecutor(payload=SAMPLE_CSV),
    )
    assert len(env.data) == 1
    assert env.data[0].file_name == "kernel32.dll"


def test_since_filter_drops_old_entries(
    ctx: SigningContext, handle: EvidenceHandle, mft_file: Path
) -> None:
    """`since` keeps entries where ANY timestamp is >= cutoff.

    Fixture data:
      - kernel32.dll: max ts = 2026-04-12T14:00:00
      - psexesvc.exe: max ts = 2026-04-12T14:32:01 (FN accessed)
      - Users:        max ts = 2026-04-12T14:00:00

    With since="2026-04-12T14:30:00", only psexesvc survives (its 14:32 access
    is the only post-cutoff timestamp).
    """
    env = parse_mft(
        handle,
        mft_path=mft_file,
        since="2026-04-12T14:30:00",
        ctx=ctx,
        executor=FakeExecutor(payload=SAMPLE_CSV),
    )
    assert len(env.data) == 1
    assert env.data[0].file_name == "psexesvc.exe"


# --------------------------------------------------------------------------- #
# Tamper detection (re-verification)                                          #
# --------------------------------------------------------------------------- #


def test_reverify_passes_when_unchanged(
    ctx: SigningContext, handle: EvidenceHandle, mft_file: Path
) -> None:
    env = parse_mft(handle, mft_path=mft_file, ctx=ctx, executor=FakeExecutor(payload=SAMPLE_CSV))
    ok, _ = reverify(env, mft_path=mft_file, executor=FakeExecutor(payload=SAMPLE_CSV))
    assert ok is True


def test_reverify_fails_on_drift(
    ctx: SigningContext, handle: EvidenceHandle, mft_file: Path
) -> None:
    env = parse_mft(handle, mft_path=mft_file, ctx=ctx, executor=FakeExecutor(payload=SAMPLE_CSV))
    tampered = SAMPLE_CSV.replace(b"psexesvc.exe", b"benign.exe   ")
    ok, reason = reverify(env, mft_path=mft_file, executor=FakeExecutor(payload=tampered))
    assert ok is False
    assert "drift" in reason.lower()


# --------------------------------------------------------------------------- #
# Timestomp detector (deterministic, non-LLM)                                 #
# --------------------------------------------------------------------------- #


def test_timestomp_candidate_detected_when_si_predates_fn(
    ctx: SigningContext, handle: EvidenceHandle, mft_file: Path
) -> None:
    env = parse_mft(handle, mft_path=mft_file, ctx=ctx, executor=FakeExecutor(payload=SAMPLE_CSV))
    candidates = find_timestomp_candidates(env.data, tolerance_seconds=5)
    # psexesvc.exe has SI=2018-01-01 and FN=2026-04-12 → clear timestomp candidate.
    assert len(candidates) == 1
    assert candidates[0].file_name == "psexesvc.exe"
    # The benign kernel32.dll and Users directory have matching SI/FN → not flagged.
    assert "kernel32.dll" not in {c.file_name for c in candidates}
    assert "Users" not in {c.file_name for c in candidates}


def test_timestomp_tolerance_threshold(
    ctx: SigningContext, handle: EvidenceHandle, mft_file: Path
) -> None:
    """An ~8-year delta is flagged at 5-second tolerance, not flagged at decade-scale tolerance.

    psexesvc.exe in the fixture has SI=2018-01-01 and FN=2026-04-12 → ~8.3 years.
    """
    env = parse_mft(handle, mft_path=mft_file, ctx=ctx, executor=FakeExecutor(payload=SAMPLE_CSV))
    assert len(find_timestomp_candidates(env.data, tolerance_seconds=5)) == 1
    # 10-year tolerance is wider than the planted 8.3-year gap → flagged set is empty.
    assert len(find_timestomp_candidates(env.data, tolerance_seconds=86400 * 365 * 10)) == 0
