"""Unit tests for parse_prefetch."""
from __future__ import annotations

import tempfile
from dataclasses import dataclass
from pathlib import Path

import pytest

from oath.mcp.evidence_handle import EvidenceHandle
from oath.mcp.tools.parse_prefetch import (
    PECMD_VERSION,
    PrefetchEntry,
    parse_prefetch,
    reverify,
)
from oath.receipt.notarized import SigningContext, verify_signature


SAMPLE_CSV = b"""SourceFilename,SourceCreated,SourceModified,SourceAccessed,ExecutableName,Hash,Size,Version,RunCount,LastRun,PreviousRun0,PreviousRun1,PreviousRun2,PreviousRun3,PreviousRun4,PreviousRun5,PreviousRun6,Volume0Info,Volume0Created,Volume0Serial,Directories,FilesCount,Files
PSEXESVC.EXE-12345678.pf,2026-04-12T14:32:00,2026-04-12T14:32:01,2026-04-12T14:32:01,psexesvc.exe,12345678,89523,30,2,2026-04-12T14:32:01,2026-04-12T14:35:11,,,,,,,C:\\,2025-09-12T00:00:00,DEAD-BEEF,3,12,C:\\Windows\\psexesvc.exe|C:\\Windows\\System32\\ntdll.dll
MIMIKATZ.EXE-ABCD1234.pf,2026-04-12T14:25:00,2026-04-12T14:25:01,2026-04-12T14:25:01,mimikatz.exe,ABCD1234,124235,2.2.0,1,2026-04-12T14:25:01,,,,,,,,C:\\,2025-09-12T00:00:00,DEAD-BEEF,2,7,C:\\Users\\Public\\mimi.exe|C:\\Windows\\System32\\advapi32.dll
NOTEPAD.EXE-FEDC9999.pf,2026-03-01T08:00:00,2026-03-01T08:00:01,2026-03-01T08:00:01,notepad.exe,FEDC9999,60876,10.0.0,5,2026-03-15T11:00:00,2026-03-14T10:00:00,2026-03-10T15:00:00,2026-03-05T09:00:00,2026-03-02T07:00:00,,,,C:\\,2025-09-12T00:00:00,DEAD-BEEF,4,8,
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
        yield SigningContext.load_or_mint(Path(tmp), run_id="test-pf")


@pytest.fixture
def handle(tmp_path: Path) -> EvidenceHandle:
    img = tmp_path / "dummy.E01"
    img.write_bytes(b"\x00" * 1024)
    return EvidenceHandle(
        image_path=img,
        image_sha256="d" * 64,
        image_size_bytes=1024,
        mount_point=tmp_path,
        mount_tech="raw-file",
        run_id="pf-run",
    )


@pytest.fixture
def pf_dir(tmp_path: Path) -> Path:
    d = tmp_path / "Prefetch"
    d.mkdir()
    return d


def test_round_trip(ctx, handle, pf_dir):
    env = parse_prefetch(handle, prefetch_dir=pf_dir, ctx=ctx, executor=FakeExecutor(payload=SAMPLE_CSV))
    assert verify_signature(env, ctx.public_key) is True
    assert env.header.tool_name == "parse_prefetch"
    assert env.header.tool_version == PECMD_VERSION


def test_three_entries_parsed(ctx, handle, pf_dir):
    env = parse_prefetch(handle, prefetch_dir=pf_dir, ctx=ctx, executor=FakeExecutor(payload=SAMPLE_CSV))
    assert len(env.data) == 3
    names = {e.executable_name for e in env.data}
    assert names == {"psexesvc.exe", "mimikatz.exe", "notepad.exe"}


def test_last_run_and_run_count_extracted(ctx, handle, pf_dir):
    env = parse_prefetch(handle, prefetch_dir=pf_dir, ctx=ctx, executor=FakeExecutor(payload=SAMPLE_CSV))
    psexesvc = next(e for e in env.data if e.executable_name == "psexesvc.exe")
    assert psexesvc.run_count == 2
    assert psexesvc.last_run == "2026-04-12T14:32:01"


def test_all_run_times_collected(ctx, handle, pf_dir):
    """PECmd packs up to 8 runs across LastRun + PreviousRun0..6; we collect all valid ones."""
    env = parse_prefetch(handle, prefetch_dir=pf_dir, ctx=ctx, executor=FakeExecutor(payload=SAMPLE_CSV))
    notepad = next(e for e in env.data if e.executable_name == "notepad.exe")
    # 5 valid runs: LastRun + PreviousRun0..3
    assert len(notepad.all_run_times) == 5
    assert "2026-03-15T11:00:00" in notepad.all_run_times


def test_name_filter(ctx, handle, pf_dir):
    env = parse_prefetch(
        handle,
        prefetch_dir=pf_dir,
        name_filter="mimi",
        ctx=ctx,
        executor=FakeExecutor(payload=SAMPLE_CSV),
    )
    assert len(env.data) == 1
    assert env.data[0].executable_name == "mimikatz.exe"


def test_referenced_files_summary_surfaced(ctx, handle, pf_dir):
    env = parse_prefetch(handle, prefetch_dir=pf_dir, ctx=ctx, executor=FakeExecutor(payload=SAMPLE_CSV))
    mimi = next(e for e in env.data if e.executable_name == "mimikatz.exe")
    assert mimi.referenced_files_summary is not None
    assert "advapi32" in mimi.referenced_files_summary.lower()


def test_reverify_fails_on_drift(ctx, handle, pf_dir):
    env = parse_prefetch(handle, prefetch_dir=pf_dir, ctx=ctx, executor=FakeExecutor(payload=SAMPLE_CSV))
    tampered = SAMPLE_CSV.replace(b"mimikatz.exe", b"benign.exe  ")
    ok, reason = reverify(env, prefetch_dir=pf_dir, executor=FakeExecutor(payload=tampered))
    assert ok is False
    assert "drift" in reason.lower()
