"""Unit tests for parse_amcache."""
from __future__ import annotations

import tempfile
from dataclasses import dataclass
from pathlib import Path

import pytest

from oath.mcp.evidence_handle import EvidenceHandle
from oath.mcp.tools.parse_amcache import (
    AMCACHEPARSER_VERSION,
    AmcacheEntry,
    parse_amcache,
    reverify,
)
from oath.receipt.notarized import SigningContext, verify_signature


# Amcache FileId format: "0000" prefix + 40-char lowercase SHA-1 = 44 chars total.
# Verified lengths: each FileId below is exactly 44 chars (4 + 40).
SAMPLE_CSV = b"""ApplicationName,ProgramId,FileId,LinkDate,Path,Size,Version,ProductName,ProductVersion,IsPeFile,IsOsComponent,FileKeyLastWriteTimestamp,Publisher,BinaryType,Description
PSEXESVC.EXE,001,00006e5da5f3aae9c3f0a23a4dca0c2e9b3c7f7a3b1b,2025-09-12T00:00:00,C:\\Windows\\psexesvc.exe,191872,2.4.0.0,Sysinternals PsExec,2.40,true,false,2026-04-12T14:32:00,Sysinternals,pe32_i386,PsExec Service
mimikatz.exe,002,0000abcd1234ef567890abcdef1234567890abcdef12,2024-01-01T00:00:00,C:\\Users\\Public\\mimi.exe,1234567,2.2.0,mimikatz,2.2.0,true,false,2026-04-12T14:25:00,gentilkiwi,pe64_amd64,A little tool to play with Windows security
notepad.exe,003,00001111222233334444555566667777888899990000,2024-11-01T00:00:00,C:\\Windows\\System32\\notepad.exe,201728,10.0.0,Microsoft Windows,10.0.0,true,true,2026-03-01T00:00:00,Microsoft,pe64_amd64,Notepad
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
        yield SigningContext.load_or_mint(Path(tmp), run_id="test-amcache")


@pytest.fixture
def handle(tmp_path: Path) -> EvidenceHandle:
    img = tmp_path / "dummy.E01"
    img.write_bytes(b"\x00" * 1024)
    return EvidenceHandle(
        image_path=img,
        image_sha256="c" * 64,
        image_size_bytes=1024,
        mount_point=tmp_path,
        mount_tech="raw-file",
        run_id="amcache-run",
    )


@pytest.fixture
def amcache_file(tmp_path: Path) -> Path:
    p = tmp_path / "Amcache.hve"
    p.write_bytes(b"AMCACHE_PLACEHOLDER" * 64)
    return p


def test_round_trip(ctx, handle, amcache_file):
    env = parse_amcache(handle, amcache_path=amcache_file, ctx=ctx, executor=FakeExecutor(payload=SAMPLE_CSV))
    assert verify_signature(env, ctx.public_key) is True
    assert env.header.tool_name == "parse_amcache"
    assert env.header.tool_version == AMCACHEPARSER_VERSION


def test_sha1_extraction_strips_amcache_prefix(ctx, handle, amcache_file):
    """Amcache stores SHA-1 as '0000<hex40>'; we must strip the prefix."""
    env = parse_amcache(handle, amcache_path=amcache_file, ctx=ctx, executor=FakeExecutor(payload=SAMPLE_CSV))
    psexesvc = next(e for e in env.data if e.name == "PSEXESVC.EXE")
    assert psexesvc.sha1 == "6e5da5f3aae9c3f0a23a4dca0c2e9b3c7f7a3b1b"
    assert psexesvc.file_id == "00006e5da5f3aae9c3f0a23a4dca0c2e9b3c7f7a3b1b"
    assert len(psexesvc.sha1) == 40


def test_sha1_filter_matches_case_insensitive(ctx, handle, amcache_file):
    """Filtering by SHA-1 hash returns only matching entries (uppercase input must match lowercase store)."""
    target = "ABCD1234EF567890ABCDEF1234567890ABCDEF12"  # full 40-hex SHA-1 of mimikatz entry
    env = parse_amcache(
        handle,
        amcache_path=amcache_file,
        sha1_filter=[target.lower()],
        ctx=ctx,
        executor=FakeExecutor(payload=SAMPLE_CSV),
    )
    assert len(env.data) == 1
    assert env.data[0].name == "mimikatz.exe"


def test_name_substring_filter(ctx, handle, amcache_file):
    env = parse_amcache(
        handle,
        amcache_path=amcache_file,
        name_substring="mimi",
        ctx=ctx,
        executor=FakeExecutor(payload=SAMPLE_CSV),
    )
    assert len(env.data) == 1
    assert env.data[0].name == "mimikatz.exe"


def test_publisher_and_binary_type_surface(ctx, handle, amcache_file):
    env = parse_amcache(handle, amcache_path=amcache_file, ctx=ctx, executor=FakeExecutor(payload=SAMPLE_CSV))
    mimi = next(e for e in env.data if "mimikatz" in e.name)
    assert mimi.binary_type == "pe64_amd64"
    assert mimi.publisher == "gentilkiwi"
    assert mimi.is_pe_file is True


def test_reverify_fails_on_drift(ctx, handle, amcache_file):
    env = parse_amcache(handle, amcache_path=amcache_file, ctx=ctx, executor=FakeExecutor(payload=SAMPLE_CSV))
    tampered = SAMPLE_CSV.replace(b"mimikatz.exe", b"benign.exe  ")
    ok, reason = reverify(env, amcache_path=amcache_file, executor=FakeExecutor(payload=tampered))
    assert ok is False
    assert "drift" in reason.lower()
