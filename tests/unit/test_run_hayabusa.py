"""Unit tests for run_hayabusa + the PtH-technique filter."""
from __future__ import annotations

import tempfile
from dataclasses import dataclass
from pathlib import Path

import pytest

from oath.mcp.evidence_handle import EvidenceHandle
from oath.mcp.tools.run_hayabusa import (
    HAYABUSA_VERSION_FLOOR,
    PTH_TECHNIQUE_SET,
    SigmaHit,
    _hash_rule_corpus,
    filter_pth_hits,
    reverify,
    run_hayabusa,
)
from oath.receipt.notarized import SigningContext, verify_signature


# Three rows: one PtH-relevant (T1550.002 + level=high), one defense-evasion
# (T1070.001 — log clearing, also PtH-relevant), one benign (T1059.001 +
# level=low — not in PTH_TECHNIQUE_SET).
SAMPLE_CSV = b"""Timestamp,Computer,Channel,EventID,Level,RuleTitle,RuleAuthor,RuleID,MitreTactics,MitreTechniques,RuleModifiedDate,Status,RecordID,Details
2026-04-12T14:32:01,WIN-VICTIM01,Security,4624,high,Suspicious NTLM Logon From Untrusted Source,Florian Roth,deadbeef-1234,TA0008,T1550.002;T1078.002,2025-12-01,stable,8392,Account Administrator authenticated via NTLM from 10.0.0.42
2026-04-12T14:35:00,WIN-VICTIM01,Security,1102,critical,Audit Log Cleared,Yamato Security,c0ffee01-5678,TA0005,T1070.001,2025-11-15,stable,8421,The audit log was cleared
2026-04-12T13:10:00,WIN-VICTIM01,Microsoft-Windows-PowerShell/Operational,4104,low,Generic PowerShell Script Block,Yamato Security,9a8b7c6d-3344,TA0002,T1059.001,2025-10-10,stable,18221,Get-Process | Where-Object {$_.CPU -gt 1}
"""


@dataclass
class FakeExecutor:
    payload: bytes
    calls: list[list[str]] = None

    def __post_init__(self) -> None:
        self.calls = []

    def run(self, argv: list[str], *, capture: bool = True, timeout: float = 300) -> bytes:
        self.calls.append(list(argv))
        # Hayabusa 3.x writes results to the file at `-o <path>`. Production
        # code calls executor.run() then opens that file. Mirror the contract.
        if "-o" in argv:
            idx = argv.index("-o")
            if idx + 1 < len(argv):
                Path(argv[idx + 1]).write_bytes(self.payload)
        return self.payload


@pytest.fixture
def ctx() -> SigningContext:
    with tempfile.TemporaryDirectory() as tmp:
        yield SigningContext.load_or_mint(Path(tmp), run_id="test-hayabusa")


@pytest.fixture
def handle(tmp_path: Path) -> EvidenceHandle:
    img = tmp_path / "dummy.E01"
    img.write_bytes(b"\x00" * 1024)
    return EvidenceHandle(
        image_path=img,
        image_sha256="e" * 64,
        image_size_bytes=1024,
        mount_point=tmp_path,
        mount_tech="raw-file",
        run_id="hayabusa-run",
    )


@pytest.fixture
def evtx_dir(tmp_path: Path) -> Path:
    d = tmp_path / "winevt"
    d.mkdir()
    return d


@pytest.fixture
def rules_dir(tmp_path: Path) -> Path:
    d = tmp_path / "hayabusa-rules"
    d.mkdir()
    (d / "rule1.yml").write_text("title: Rule 1\ndetection:\n  selection: a\n")
    (d / "rule2.yml").write_text("title: Rule 2\ndetection:\n  selection: b\n")
    return d


# --------------------------------------------------------------------------- #
# Core round-trip                                                             #
# --------------------------------------------------------------------------- #


def test_round_trip(ctx, handle, evtx_dir, rules_dir):
    env = run_hayabusa(
        handle,
        evtx_dir=evtx_dir,
        rules_dir=rules_dir,
        ctx=ctx,
        executor=FakeExecutor(payload=SAMPLE_CSV),
    )
    assert verify_signature(env, ctx.public_key) is True
    assert env.header.tool_name == "run_hayabusa"
    assert env.header.tool_version == HAYABUSA_VERSION_FLOOR


def test_three_hits_parsed(ctx, handle, evtx_dir):
    env = run_hayabusa(handle, evtx_dir=evtx_dir, ctx=ctx, executor=FakeExecutor(payload=SAMPLE_CSV))
    assert len(env.data) == 3


def test_mitre_techniques_extracted_as_tuple(ctx, handle, evtx_dir):
    env = run_hayabusa(handle, evtx_dir=evtx_dir, ctx=ctx, executor=FakeExecutor(payload=SAMPLE_CSV))
    pth = next(h for h in env.data if "T1550.002" in h.mitre_techniques)
    assert pth.event_id == 4624
    assert pth.level == "high"
    assert "T1078.002" in pth.mitre_techniques


# --------------------------------------------------------------------------- #
# Filters                                                                     #
# --------------------------------------------------------------------------- #


def test_min_level_drops_low_severity(ctx, handle, evtx_dir):
    env = run_hayabusa(
        handle,
        evtx_dir=evtx_dir,
        min_level="medium",
        ctx=ctx,
        executor=FakeExecutor(payload=SAMPLE_CSV),
    )
    # The "low" PowerShell hit is dropped; the high + critical remain.
    assert len(env.data) == 2
    levels = {h.level for h in env.data}
    assert "low" not in levels


def test_technique_filter_keeps_only_matching(ctx, handle, evtx_dir):
    env = run_hayabusa(
        handle,
        evtx_dir=evtx_dir,
        technique_filter=["T1550.002"],
        ctx=ctx,
        executor=FakeExecutor(payload=SAMPLE_CSV),
    )
    assert len(env.data) == 1
    assert "T1550.002" in env.data[0].mitre_techniques


def test_filter_pth_hits_uses_canonical_technique_set(ctx, handle, evtx_dir):
    env = run_hayabusa(handle, evtx_dir=evtx_dir, ctx=ctx, executor=FakeExecutor(payload=SAMPLE_CSV))
    pth_hits = filter_pth_hits(env.data, min_level="medium")
    # T1550.002 (high) and T1070.001 (critical) both in PTH_TECHNIQUE_SET; T1059.001 not.
    assert len(pth_hits) == 2
    titles = {h.rule_title for h in pth_hits}
    assert "Suspicious NTLM Logon From Untrusted Source" in titles
    assert "Audit Log Cleared" in titles


def test_pth_technique_set_contains_key_lateral_movement_techniques():
    """Sanity — the bundled PTH set covers the four most-cited PtH techniques."""
    assert "T1550.002" in PTH_TECHNIQUE_SET  # Pass the Hash itself
    assert "T1003.001" in PTH_TECHNIQUE_SET  # LSASS Memory
    assert "T1021.002" in PTH_TECHNIQUE_SET  # SMB / Admin Shares
    assert "T1070.001" in PTH_TECHNIQUE_SET  # Log clearing (the anti-forensic correlate)


# --------------------------------------------------------------------------- #
# Rule-corpus hashing (binding to envelope provenance)                        #
# --------------------------------------------------------------------------- #


def test_rule_corpus_hash_is_deterministic(rules_dir):
    h1 = _hash_rule_corpus(rules_dir)
    h2 = _hash_rule_corpus(rules_dir)
    assert h1 == h2
    assert len(h1) == 64  # SHA-256 hex


def test_rule_corpus_hash_changes_on_rule_modification(rules_dir):
    h1 = _hash_rule_corpus(rules_dir)
    (rules_dir / "rule3.yml").write_text("title: Added\ndetection:\n  selection: c\n")
    h2 = _hash_rule_corpus(rules_dir)
    assert h1 != h2


def test_empty_or_missing_corpus_returns_known_hash(tmp_path):
    missing = tmp_path / "does-not-exist"
    h = _hash_rule_corpus(missing)
    # SHA-256 of empty input
    assert h == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def test_reverify_detects_rule_corpus_drift(ctx, handle, evtx_dir, rules_dir):
    env = run_hayabusa(
        handle,
        evtx_dir=evtx_dir,
        rules_dir=rules_dir,
        ctx=ctx,
        executor=FakeExecutor(payload=SAMPLE_CSV),
    )
    # Modify the rule corpus
    (rules_dir / "rule_new.yml").write_text("title: New\ndetection:\n  selection: z\n")
    ok, reason = reverify(
        env, evtx_dir=evtx_dir, rules_dir=rules_dir, executor=FakeExecutor(payload=SAMPLE_CSV)
    )
    assert ok is False
    assert "rule corpus" in reason.lower()


# --------------------------------------------------------------------------- #
# Tamper detection                                                            #
# --------------------------------------------------------------------------- #


def test_reverify_passes_when_unchanged(ctx, handle, evtx_dir, rules_dir):
    env = run_hayabusa(
        handle,
        evtx_dir=evtx_dir,
        rules_dir=rules_dir,
        ctx=ctx,
        executor=FakeExecutor(payload=SAMPLE_CSV),
    )
    ok, _ = reverify(
        env, evtx_dir=evtx_dir, rules_dir=rules_dir, executor=FakeExecutor(payload=SAMPLE_CSV)
    )
    assert ok is True


def test_reverify_fails_on_evtx_drift(ctx, handle, evtx_dir, rules_dir):
    env = run_hayabusa(
        handle,
        evtx_dir=evtx_dir,
        rules_dir=rules_dir,
        ctx=ctx,
        executor=FakeExecutor(payload=SAMPLE_CSV),
    )
    tampered = SAMPLE_CSV.replace(b"WIN-VICTIM01", b"WIN-ELSE0123")
    ok, reason = reverify(
        env, evtx_dir=evtx_dir, rules_dir=rules_dir, executor=FakeExecutor(payload=tampered)
    )
    assert ok is False
    assert "drift" in reason.lower()


def test_reverify_reconstructs_min_level_from_args_canonical(
    ctx, handle, evtx_dir, rules_dir
):
    """If mint used `-m high`, reverify MUST also pass `-m high` — otherwise
    stdout would always drift on filtered envelopes.

    Regression test for a bug where reverify rebuilt argv with fixed flags
    and dropped the original min_level.
    """
    env = run_hayabusa(
        handle,
        evtx_dir=evtx_dir,
        rules_dir=rules_dir,
        min_level="high",
        ctx=ctx,
        executor=FakeExecutor(payload=SAMPLE_CSV),
    )

    rv_executor = FakeExecutor(payload=SAMPLE_CSV)
    ok, reason = reverify(
        env, evtx_dir=evtx_dir, rules_dir=rules_dir, executor=rv_executor
    )
    assert ok is True, reason
    assert len(rv_executor.calls) == 1
    argv = rv_executor.calls[0]
    assert "-m" in argv
    assert argv[argv.index("-m") + 1] == "high"
