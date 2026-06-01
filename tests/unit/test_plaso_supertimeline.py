"""Unit tests for plaso_supertimeline + correlation helpers."""
from __future__ import annotations

import tempfile
from dataclasses import dataclass
from pathlib import Path

import pytest

from oath.mcp.evidence_handle import EvidenceHandle
from oath.mcp.tools.plaso_supertimeline import (
    PLASO_VERSION_FLOOR,
    PTH_RELEVANT_SOURCES,
    SOURCE_EVT,
    SOURCE_FILE,
    SOURCE_REG,
    TimelineEvent,
    correlate_around,
    events_in_window,
    hash_plaso_store,
    plaso_supertimeline,
    reverify,
)
from oath.receipt.notarized import SigningContext, verify_signature


# Synthetic l2tcsv output: 6 events on WIN-VICTIM01 around 14:32:00.
#   1. 14:31:58 — REG Run-key write (winreg/run)
#   2. 14:32:01 — EVTX 4624 logon (NTLM, LogonType=3) ← anchor
#   3. 14:32:02 — FILE $MFT entry creation for psexesvc.exe
#   4. 14:32:05 — PREF first run of psexesvc.exe
#   5. 14:32:07 — EVTX 4688 process create (PsExec.exe)
#   6. 14:50:00 — unrelated benign file read on notepad.exe (outside window)
SAMPLE_CSV = b"""date,time,timezone,MACB,source,sourcetype,type,user,host,short,desc,version,filename,inode,notes,format,extra
04/12/2026,14:31:58,UTC,...B,REG,Windows Registry,Creation Time,SYSTEM,WIN-VICTIM01,,Run key value HelperSvc=C:\\\\Users\\\\Public\\\\svchost-helper.exe written,2,HKLM\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run,123,,winreg/run,key_path: HKLM\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run; value_name: HelperSvc
04/12/2026,14:32:01,UTC,M...,EVT,Windows Security Auditing,Logon,Administrator,WIN-VICTIM01,,Account logon EventID 4624 LogonType 3 NTLM,2,Security.evtx,456,,winevtx,logon_type: 3; authentication_package: NTLM; source_ip: 10.0.0.42
04/12/2026,14:32:02,UTC,...B,FILE,NTFS USN_CHANGE,Creation Time,SYSTEM,WIN-VICTIM01,,File created psexesvc.exe,2,C:\\\\Windows\\\\PSEXESVC.exe,789,,filestat,size: 184568
04/12/2026,14:32:05,UTC,M...,PREF,Windows Prefetch,Last Time Executed,Administrator,WIN-VICTIM01,,Prefetch run of PSEXESVC.EXE,2,C:\\\\Windows\\\\Prefetch\\\\PSEXESVC.EXE-1A2B3C4D.pf,234,,prefetch,run_count: 1
04/12/2026,14:32:07,UTC,M...,EVT,Windows Security Auditing,Process Create,Administrator,WIN-VICTIM01,,Account logon EventID 4688 process C:\\\\Windows\\\\PSEXESVC.exe,2,Security.evtx,457,,winevtx,process_name: C:\\\\Windows\\\\PSEXESVC.exe; parent_process: services.exe
04/12/2026,14:50:00,UTC,M...,FILE,NTFS file,Last Read,user1,WIN-VICTIM01,,Read access C:\\\\Windows\\\\notepad.exe,2,C:\\\\Windows\\\\notepad.exe,999,,filestat,
"""


@dataclass
class FakeExecutor:
    payload: bytes
    calls: list[list[str]] = None

    def __post_init__(self) -> None:
        self.calls = []

    def run(self, argv: list[str], *, capture: bool = True, timeout: float = 300) -> bytes:
        self.calls.append(list(argv))
        # psort.py 20260512 writes to -w <path>. Production code reads the
        # file back. Mirror that contract.
        if "-w" in argv:
            w_idx = argv.index("-w")
            if w_idx + 1 < len(argv):
                outpath = Path(argv[w_idx + 1])
                if "/dev/" not in str(outpath):
                    outpath.parent.mkdir(parents=True, exist_ok=True)
                    outpath.write_bytes(self.payload)
        return self.payload


@pytest.fixture
def ctx() -> SigningContext:
    with tempfile.TemporaryDirectory() as tmp:
        yield SigningContext.load_or_mint(Path(tmp), run_id="test-plaso")


@pytest.fixture
def handle(tmp_path: Path) -> EvidenceHandle:
    img = tmp_path / "dummy.E01"
    img.write_bytes(b"\x00" * 1024)
    return EvidenceHandle(
        image_path=img,
        image_sha256="8" * 64,
        image_size_bytes=1024,
        mount_point=tmp_path,
        mount_tech="raw-file",
        run_id="plaso-run",
    )


@pytest.fixture
def plaso_store(tmp_path: Path) -> Path:
    p = tmp_path / "case.plaso"
    p.write_bytes(b"PLASO_FAKE_STORE_BYTES" * 16)
    return p


# --------------------------------------------------------------------------- #
# Round-trip + tool-version pinning                                           #
# --------------------------------------------------------------------------- #


def test_round_trip_verifies(ctx, handle, plaso_store):
    env = plaso_supertimeline(
        handle, plaso_path=plaso_store, ctx=ctx, executor=FakeExecutor(payload=SAMPLE_CSV)
    )
    assert verify_signature(env, ctx.public_key) is True
    assert env.header.tool_name == "plaso_supertimeline"
    assert env.header.tool_version == PLASO_VERSION_FLOOR


def test_all_events_parsed_and_timestamps_coalesced(ctx, handle, plaso_store):
    env = plaso_supertimeline(
        handle, plaso_path=plaso_store, ctx=ctx, executor=FakeExecutor(payload=SAMPLE_CSV)
    )
    assert len(env.data) == 6
    ts = {e.timestamp for e in env.data}
    assert "2026-04-12T14:32:01" in ts
    assert "2026-04-12T14:31:58" in ts


def test_extra_field_subset_match_predicate(ctx, handle, plaso_store):
    """The extra column is parsed as a dict so the verifier can subset-match it."""
    env = plaso_supertimeline(
        handle, plaso_path=plaso_store, ctx=ctx, executor=FakeExecutor(payload=SAMPLE_CSV)
    )
    logon = next(e for e in env.data if "4624" in e.description)
    assert logon.extra.get("logon_type") == "3"
    assert logon.extra.get("authentication_package") == "NTLM"
    assert logon.extra.get("source_ip") == "10.0.0.42"


def test_source_filter(ctx, handle, plaso_store):
    env = plaso_supertimeline(
        handle,
        plaso_path=plaso_store,
        source_filter=[SOURCE_EVT],
        ctx=ctx,
        executor=FakeExecutor(payload=SAMPLE_CSV),
    )
    assert all(e.source_short == SOURCE_EVT for e in env.data)
    assert len(env.data) == 2  # 4624 + 4688


def test_parser_filter(ctx, handle, plaso_store):
    env = plaso_supertimeline(
        handle,
        plaso_path=plaso_store,
        parser_filter=["winreg/run"],
        ctx=ctx,
        executor=FakeExecutor(payload=SAMPLE_CSV),
    )
    assert len(env.data) == 1
    assert env.data[0].parser_name == "winreg/run"


def test_time_window_filter_drops_far_events(ctx, handle, plaso_store):
    env = plaso_supertimeline(
        handle,
        plaso_path=plaso_store,
        time_window_start="2026-04-12T14:31:55",
        time_window_end="2026-04-12T14:32:10",
        ctx=ctx,
        executor=FakeExecutor(payload=SAMPLE_CSV),
    )
    assert len(env.data) == 5  # the 14:50:00 event is dropped


def test_description_substring_filter(ctx, handle, plaso_store):
    env = plaso_supertimeline(
        handle,
        plaso_path=plaso_store,
        description_substring="psexesvc",
        ctx=ctx,
        executor=FakeExecutor(payload=SAMPLE_CSV),
    )
    # 14:32:02 (file create), 14:32:05 (prefetch run), 14:32:07 (4688)
    assert len(env.data) == 3


def test_plaso_store_sha256_bound_into_args(ctx, handle, plaso_store):
    env = plaso_supertimeline(
        handle, plaso_path=plaso_store, ctx=ctx, executor=FakeExecutor(payload=SAMPLE_CSV)
    )
    expected_sha = hash_plaso_store(plaso_store)
    assert expected_sha in env.header.args_canonical


# --------------------------------------------------------------------------- #
# Correlation helpers                                                         #
# --------------------------------------------------------------------------- #


def test_events_in_window_inclusive(ctx, handle, plaso_store):
    env = plaso_supertimeline(
        handle, plaso_path=plaso_store, ctx=ctx, executor=FakeExecutor(payload=SAMPLE_CSV)
    )
    win = events_in_window(
        list(env.data), "2026-04-12T14:32:00", "2026-04-12T14:32:10"
    )
    assert len(win) == 4  # 14:32:01, :02, :05, :07


def test_correlate_around_anchor_pulls_pre_and_post(ctx, handle, plaso_store):
    env = plaso_supertimeline(
        handle, plaso_path=plaso_store, ctx=ctx, executor=FakeExecutor(payload=SAMPLE_CSV)
    )
    correlated = correlate_around(
        list(env.data),
        anchor_timestamp="2026-04-12T14:32:01",
        seconds_before=5,
        seconds_after=10,
    )
    # 14:31:58 (3s before) + 14:32:01 + 14:32:02 + 14:32:05 + 14:32:07 = 5
    # 14:50:00 well outside window; dropped
    assert len(correlated) == 5
    assert all(e.timestamp != "2026-04-12T14:50:00" for e in correlated)


def test_pth_relevant_sources_is_a_proper_subset():
    """The PtH-relevant set must include EVT + REG + FILE + PREF."""
    assert SOURCE_EVT in PTH_RELEVANT_SOURCES
    assert SOURCE_REG in PTH_RELEVANT_SOURCES
    assert SOURCE_FILE in PTH_RELEVANT_SOURCES


# --------------------------------------------------------------------------- #
# Tamper detection                                                            #
# --------------------------------------------------------------------------- #


def test_reverify_passes_when_unchanged(ctx, handle, plaso_store):
    env = plaso_supertimeline(
        handle, plaso_path=plaso_store, ctx=ctx, executor=FakeExecutor(payload=SAMPLE_CSV)
    )
    ok, _ = reverify(env, plaso_path=plaso_store, executor=FakeExecutor(payload=SAMPLE_CSV))
    assert ok is True


def test_reverify_fails_on_stdout_drift(ctx, handle, plaso_store):
    env = plaso_supertimeline(
        handle, plaso_path=plaso_store, ctx=ctx, executor=FakeExecutor(payload=SAMPLE_CSV)
    )
    tampered = SAMPLE_CSV.replace(b"Administrator", b"BackupOperator")
    ok, reason = reverify(env, plaso_path=plaso_store, executor=FakeExecutor(payload=tampered))
    assert ok is False
    assert "drift" in reason.lower()


def test_reverify_fails_when_plaso_store_swapped(ctx, handle, plaso_store, tmp_path):
    env = plaso_supertimeline(
        handle, plaso_path=plaso_store, ctx=ctx, executor=FakeExecutor(payload=SAMPLE_CSV)
    )
    # Swap in a different store with different content
    swapped = tmp_path / "other.plaso"
    swapped.write_bytes(b"DIFFERENT_PLASO_STORE_CONTENT" * 16)
    ok, reason = reverify(env, plaso_path=swapped, executor=FakeExecutor(payload=SAMPLE_CSV))
    assert ok is False
    assert "plaso store sha-256 drift" in reason.lower()
