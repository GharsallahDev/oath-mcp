"""Unit tests for parse_usnjrnl + the anti-forensic helpers."""
from __future__ import annotations

import tempfile
from dataclasses import dataclass
from pathlib import Path

import pytest

from oath.mcp.evidence_handle import EvidenceHandle
from oath.mcp.tools.parse_usnjrnl import (
    ANTI_FORENSIC_REASONS,
    MFTECMD_VERSION,
    USN_REASON_FILE_DELETE,
    USN_REASON_RENAME_NEW,
    USN_REASON_RENAME_OLD,
    UsnRecord,
    find_deletion_events,
    find_rename_pairs,
    parse_usnjrnl,
    reverify,
)
from oath.receipt.notarized import SigningContext, verify_signature


# Fixture: a 4-row $J CSV.
#   1. Create mimi.exe at 14:25
#   2. Rename mimi.exe → svchost-helper.exe (old + new pair, same FRN 12340)
#   3. Delete svchost-helper.exe at 14:40 (the cleanup)
#   4. Unrelated benign FileClose on notepad.exe
SAMPLE_CSV = b"""Name,Extension,EntryNumber,SequenceNumber,ParentEntryNumber,ParentSequenceNumber,ParentPath,UpdateSequenceNumber,UpdateTimestamp,UpdateReasons,FileAttributes,OffsetToData,SourceFile
mimi.exe,.exe,12340,1,5,5,C:\\Users\\Public,1000,2026-04-12T14:25:00,FileCreate|Close,Archive,0,UsnJrnl
mimi.exe,.exe,12340,1,5,5,C:\\Users\\Public,1001,2026-04-12T14:28:00,RenameOldName,Archive,0,UsnJrnl
svchost-helper.exe,.exe,12340,1,5,5,C:\\Users\\Public,1002,2026-04-12T14:28:00,RenameNewName|Close,Archive,0,UsnJrnl
svchost-helper.exe,.exe,12340,1,5,5,C:\\Users\\Public,1003,2026-04-12T14:40:00,FileDelete|Close,Archive,0,UsnJrnl
notepad.exe,.exe,99999,1,5,5,C:\\Windows\\System32,1004,2026-04-12T15:00:00,Close,Archive,0,UsnJrnl
"""


@dataclass
class FakeExecutor:
    payload: bytes
    calls: list[list[str]] = None

    def __post_init__(self) -> None:
        self.calls = []

    def run(self, argv: list[str], *, capture: bool = True, timeout: float = 300) -> bytes:
        self.calls.append(list(argv))
        # EZ Tool 2026.5.0 contract: --csv <dir> --csvf <file>. Mirror the
        # file-output so production code's "executor.run(); open(path)"
        # pattern works against this fake.
        if "--csv" in argv and "--csvf" in argv:
            csv_idx = argv.index("--csv")
            csvf_idx = argv.index("--csvf")
            if csv_idx + 1 < len(argv) and csvf_idx + 1 < len(argv):
                outpath = Path(argv[csv_idx + 1]) / argv[csvf_idx + 1]
                outpath.parent.mkdir(parents=True, exist_ok=True)
                outpath.write_bytes(self.payload)
        return self.payload


@pytest.fixture
def ctx() -> SigningContext:
    with tempfile.TemporaryDirectory() as tmp:
        yield SigningContext.load_or_mint(Path(tmp), run_id="test-usnjrnl")


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
        run_id="usn-run",
    )


@pytest.fixture
def j_file(tmp_path: Path) -> Path:
    p = tmp_path / "UsnJrnl_J"
    p.write_bytes(b"USN_PLACEHOLDER" * 8)
    return p


# --------------------------------------------------------------------------- #
# Round-trip + tool-version pinning                                           #
# --------------------------------------------------------------------------- #


def test_round_trip_verifies(ctx, handle, j_file):
    env = parse_usnjrnl(handle, j_path=j_file, ctx=ctx, executor=FakeExecutor(payload=SAMPLE_CSV))
    assert verify_signature(env, ctx.public_key) is True
    assert env.header.tool_name == "parse_usnjrnl"
    assert env.header.tool_version == MFTECMD_VERSION


def test_all_records_parsed(ctx, handle, j_file):
    env = parse_usnjrnl(handle, j_path=j_file, ctx=ctx, executor=FakeExecutor(payload=SAMPLE_CSV))
    assert len(env.data) == 5
    # USN numbers are preserved
    assert {r.usn for r in env.data} == {1000, 1001, 1002, 1003, 1004}


def test_update_reasons_split_on_pipe(ctx, handle, j_file):
    env = parse_usnjrnl(handle, j_path=j_file, ctx=ctx, executor=FakeExecutor(payload=SAMPLE_CSV))
    create = next(r for r in env.data if r.usn == 1000)
    assert "FileCreate" in create.update_reasons
    assert "Close" in create.update_reasons


def test_filter_by_reason(ctx, handle, j_file):
    env = parse_usnjrnl(
        handle,
        j_path=j_file,
        reason_filter=[USN_REASON_FILE_DELETE],
        ctx=ctx,
        executor=FakeExecutor(payload=SAMPLE_CSV),
    )
    # Only USN 1003 has FileDelete
    assert len(env.data) == 1
    assert env.data[0].usn == 1003


def test_since_filter_drops_old_records(ctx, handle, j_file):
    env = parse_usnjrnl(
        handle,
        j_path=j_file,
        since="2026-04-12T14:30:00",
        ctx=ctx,
        executor=FakeExecutor(payload=SAMPLE_CSV),
    )
    # USNs 1000 (14:25) and 1001/1002 (14:28) are dropped; 1003 (14:40) and 1004 (15:00) remain
    usns = {r.usn for r in env.data}
    assert usns == {1003, 1004}


def test_path_filter_is_case_insensitive(ctx, handle, j_file):
    env = parse_usnjrnl(
        handle,
        j_path=j_file,
        filter_path="users\\PUBLIC",
        ctx=ctx,
        executor=FakeExecutor(payload=SAMPLE_CSV),
    )
    # All Users\Public events survive (4 of 5); notepad in System32 dropped
    paths = {r.full_path for r in env.data}
    assert all(p and "Users\\Public" in p for p in paths)
    assert not any(p and "System32" in p for p in paths)


# --------------------------------------------------------------------------- #
# Anti-forensic helpers                                                       #
# --------------------------------------------------------------------------- #


def test_find_deletion_events(ctx, handle, j_file):
    env = parse_usnjrnl(handle, j_path=j_file, ctx=ctx, executor=FakeExecutor(payload=SAMPLE_CSV))
    deletions = find_deletion_events(env.data)
    assert len(deletions) == 1
    assert deletions[0].file_name == "svchost-helper.exe"
    assert deletions[0].usn == 1003


def test_find_rename_pairs(ctx, handle, j_file):
    env = parse_usnjrnl(handle, j_path=j_file, ctx=ctx, executor=FakeExecutor(payload=SAMPLE_CSV))
    pairs = find_rename_pairs(env.data)
    assert len(pairs) == 1
    old, new = pairs[0]
    assert old.file_name == "mimi.exe"
    assert new.file_name == "svchost-helper.exe"
    assert old.file_record_number == new.file_record_number


def test_anti_forensic_reasons_is_a_proper_superset_of_delete():
    """The high-signal anti-forensic set must at minimum include FileDelete and both rename sides."""
    assert USN_REASON_FILE_DELETE in ANTI_FORENSIC_REASONS
    assert USN_REASON_RENAME_OLD in ANTI_FORENSIC_REASONS
    assert USN_REASON_RENAME_NEW in ANTI_FORENSIC_REASONS


# --------------------------------------------------------------------------- #
# Tamper detection                                                            #
# --------------------------------------------------------------------------- #


def test_reverify_passes_when_unchanged(ctx, handle, j_file):
    env = parse_usnjrnl(handle, j_path=j_file, ctx=ctx, executor=FakeExecutor(payload=SAMPLE_CSV))
    ok, _ = reverify(env, j_path=j_file, executor=FakeExecutor(payload=SAMPLE_CSV))
    assert ok is True


def test_reverify_fails_on_drift(ctx, handle, j_file):
    env = parse_usnjrnl(handle, j_path=j_file, ctx=ctx, executor=FakeExecutor(payload=SAMPLE_CSV))
    tampered = SAMPLE_CSV.replace(b"svchost-helper.exe", b"different-name.exe")
    ok, reason = reverify(env, j_path=j_file, executor=FakeExecutor(payload=tampered))
    assert ok is False
    assert "drift" in reason.lower()
