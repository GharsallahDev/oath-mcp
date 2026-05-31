"""Unit tests for the Witness Oath Verifier — the core architectural primitive.

These tests pin the three-state verdict contract:
  - VERIFIED: all envelopes re-derive, all predicates match
  - QUARANTINED: envelopes re-derive but a predicate doesn't match
  - RALPH_WIGGUM: re-derivation fails (tool drift / evidence tamper)

A regression here breaks the headline architectural claim of the submission.
"""
from __future__ import annotations

import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from oath.mcp.evidence_handle import EvidenceHandle
from oath.mcp.tools.parse_evtx import parse_evtx
from oath.receipt.notarized import Notarized, SigningContext
from oath.witness.claim import (
    AgentClaim,
    ClaimEvidence,
    FindingType,
    VerifyVerdict,
)
from oath.witness.verifier import (
    ReverifyRegistry,
    WitnessOathVerifier,
    _matches_predicate,
)


# --------------------------------------------------------------------------- #
# Reusable fixtures (mirror parse_evtx test fixtures)                         #
# --------------------------------------------------------------------------- #


SAMPLE_EVTX_CSV = b"""RecordNumber,EventRecordId,TimeCreated,EventId,Level,Provider,Channel,Computer,UserId,MapDescription,ChunkNumber,UserName,RemoteHost,PayloadData1,PayloadData2,PayloadData3,PayloadData4,PayloadData5,ExecutableInfo,HiddenRecord,SourceFile,Payload
8392,8392,2026-04-12T14:32:01.1234567Z,4624,Information,Microsoft-Windows-Security-Auditing,Security,WIN-VICTIM01,S-1-5-21-1234-5678-9012-1001,,1,Administrator,10.0.0.42,3,NTLM,NTLM V2,,,,,,Security.evtx,An account was successfully logged on. ...
8393,8393,2026-04-12T14:33:55.7654321Z,4624,Information,Microsoft-Windows-Security-Auditing,Security,WIN-VICTIM01,S-1-5-21-1234-5678-9012-1001,,1,jdoe,,2,Kerberos,Kerberos,,,,,,Security.evtx,An account was successfully logged on. ...
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
        yield SigningContext.load_or_mint(Path(tmp), run_id="test-witness")


@pytest.fixture
def handle(tmp_path: Path) -> EvidenceHandle:
    img = tmp_path / "dummy.E01"
    img.write_bytes(b"\x00" * 1024)
    return EvidenceHandle(
        image_path=img,
        image_sha256="f" * 64,
        image_size_bytes=1024,
        mount_point=tmp_path,
        mount_tech="raw-file",
        run_id="witness-test",
    )


@pytest.fixture
def evtx_file(tmp_path: Path) -> Path:
    p = tmp_path / "Security.evtx"
    p.write_bytes(b"EVTX_PLACEHOLDER")
    return p


def _make_claim(
    *,
    claim_id: str = "claim-1",
    envelope_id: str = "evtx-001",
    predicate: dict[str, Any],
    finding_type: FindingType = FindingType.PTH_CANDIDATE,
) -> AgentClaim:
    return AgentClaim(
        claim_id=claim_id,
        finding_type=finding_type,
        natural_language="Pass-the-Hash candidate at WIN-VICTIM01 14:32:01",
        supporting_evidence=(
            ClaimEvidence(envelope_id=envelope_id, record_predicate=predicate),
        ),
        confidence=0.85,
        reasoning_hash="b" * 64,
        model_id="claude-opus-4-7",
        temperature=0.0,
        seed=1,
    )


# --------------------------------------------------------------------------- #
# Predicate matching                                                          #
# --------------------------------------------------------------------------- #


class TestPredicateMatching:
    def test_subset_match_on_pydantic_model(self) -> None:
        from oath.mcp.tools.parse_evtx import EvtxRecord

        record = EvtxRecord(
            record_number=1,
            timestamp="2026-04-12T14:32:01Z",
            event_id=4624,
            level="Information",
            provider="Microsoft-Windows-Security-Auditing",
            channel="Security",
            logon_type=3,
            auth_package="NTLM",
            source_evtx_offset=0,
            record_offset=0,
            record_length=1024,
        )
        assert _matches_predicate(record, {"event_id": 4624, "logon_type": 3}) is True
        assert _matches_predicate(record, {"event_id": 4624, "logon_type": 2}) is False

    def test_missing_field_does_not_match(self) -> None:
        record = {"event_id": 4624}
        assert _matches_predicate(record, {"nonexistent_field": "anything"}) is False

    def test_list_value_in_predicate_means_membership(self) -> None:
        record = {"event_id": 4624}
        assert _matches_predicate(record, {"event_id": [4624, 4625]}) is True
        assert _matches_predicate(record, {"event_id": [4720, 4725]}) is False

    def test_empty_predicate_is_invalid(self) -> None:
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            ClaimEvidence(envelope_id="x", record_predicate={})


# --------------------------------------------------------------------------- #
# VERIFIED — happy path                                                       #
# --------------------------------------------------------------------------- #


class TestVerifiedVerdict:
    def test_claim_with_matching_predicate_verifies(
        self,
        ctx: SigningContext,
        handle: EvidenceHandle,
        evtx_file: Path,
    ) -> None:
        # Mint a real envelope using parse_evtx + the fake executor.
        envelope = parse_evtx(
            handle,
            evtx_path=evtx_file,
            ctx=ctx,
            executor=FakeExecutor(payload=SAMPLE_EVTX_CSV),
        )

        # Build a verifier that re-runs the SAME fake executor (so reverify passes).
        registry = ReverifyRegistry()
        from oath.mcp.tools import parse_evtx as parse_evtx_mod

        def reverify_with_fake(envelope, *, evtx_path):
            return parse_evtx_mod.reverify(
                envelope, evtx_path=evtx_path, executor=FakeExecutor(payload=SAMPLE_EVTX_CSV)
            )

        registry.register("parse_evtx", reverify_with_fake, required_kwargs=("evtx_path",))

        verifier = WitnessOathVerifier(
            envelopes_by_id={"evtx-001": envelope},
            reverify_kwargs={"evtx-001": {"evtx_path": evtx_file}},
            registry=registry,
        )

        # The PtH candidate predicate matches record 8392 in the fixture.
        claim = _make_claim(
            predicate={"event_id": 4624, "logon_type": 3, "auth_package": "NTLM"}
        )
        result = verifier.verify(claim)

        assert result.verdict == VerifyVerdict.VERIFIED
        assert result.envelope_verdicts["evtx-001"][0] is True
        assert len(result.predicate_matches["evtx-001"]) >= 1


# --------------------------------------------------------------------------- #
# QUARANTINED — envelope verifies but predicate doesn't match any record       #
# --------------------------------------------------------------------------- #


class TestQuarantinedVerdict:
    def test_envelope_ok_but_predicate_unmatched_yields_quarantine(
        self,
        ctx: SigningContext,
        handle: EvidenceHandle,
        evtx_file: Path,
    ) -> None:
        envelope = parse_evtx(
            handle,
            evtx_path=evtx_file,
            ctx=ctx,
            executor=FakeExecutor(payload=SAMPLE_EVTX_CSV),
        )

        registry = ReverifyRegistry()
        from oath.mcp.tools import parse_evtx as parse_evtx_mod

        def reverify_with_fake(envelope, *, evtx_path):
            return parse_evtx_mod.reverify(
                envelope, evtx_path=evtx_path, executor=FakeExecutor(payload=SAMPLE_EVTX_CSV)
            )

        registry.register("parse_evtx", reverify_with_fake, required_kwargs=("evtx_path",))

        verifier = WitnessOathVerifier(
            envelopes_by_id={"evtx-001": envelope},
            reverify_kwargs={"evtx-001": {"evtx_path": evtx_file}},
            registry=registry,
        )

        # Fabricated predicate — there's no 4625 in the fixture.
        claim = _make_claim(predicate={"event_id": 4625, "logon_type": 3})
        result = verifier.verify(claim)

        assert result.verdict == VerifyVerdict.QUARANTINED
        assert "predicate" in result.reason.lower() or "did not match" in result.reason.lower()
        assert result.predicate_matches["evtx-001"] == []


# --------------------------------------------------------------------------- #
# RALPH_WIGGUM — envelope reverify fails (tool drift / evidence tamper)        #
# --------------------------------------------------------------------------- #


class TestRalphWiggumVerdict:
    def test_envelope_drift_triggers_ralph_wiggum(
        self,
        ctx: SigningContext,
        handle: EvidenceHandle,
        evtx_file: Path,
    ) -> None:
        envelope = parse_evtx(
            handle,
            evtx_path=evtx_file,
            ctx=ctx,
            executor=FakeExecutor(payload=SAMPLE_EVTX_CSV),
        )

        # The re-run executor returns DIFFERENT bytes → BLAKE3 drift.
        registry = ReverifyRegistry()
        from oath.mcp.tools import parse_evtx as parse_evtx_mod

        tampered_csv = SAMPLE_EVTX_CSV.replace(b"10.0.0.42", b"10.0.0.99")

        def reverify_with_tampered(envelope, *, evtx_path):
            return parse_evtx_mod.reverify(
                envelope, evtx_path=evtx_path, executor=FakeExecutor(payload=tampered_csv)
            )

        registry.register("parse_evtx", reverify_with_tampered, required_kwargs=("evtx_path",))

        verifier = WitnessOathVerifier(
            envelopes_by_id={"evtx-001": envelope},
            reverify_kwargs={"evtx-001": {"evtx_path": evtx_file}},
            registry=registry,
        )

        claim = _make_claim(predicate={"event_id": 4624, "logon_type": 3})
        result = verifier.verify(claim)

        assert result.verdict == VerifyVerdict.RALPH_WIGGUM
        assert "re-propose" in result.reason.lower() or "drift" in result.reason.lower()
        # Predicate matches are irrelevant once we've hit Ralph Wiggum.

    def test_unknown_envelope_id_yields_ralph_wiggum(
        self, ctx: SigningContext, handle: EvidenceHandle, evtx_file: Path
    ) -> None:
        verifier = WitnessOathVerifier(envelopes_by_id={}, reverify_kwargs={})
        claim = _make_claim(envelope_id="nonexistent", predicate={"event_id": 4624})
        result = verifier.verify(claim)
        assert result.verdict == VerifyVerdict.RALPH_WIGGUM
        assert "unknown envelope" in result.reason.lower()


# --------------------------------------------------------------------------- #
# Batch verification                                                          #
# --------------------------------------------------------------------------- #


class TestBatchVerify:
    def test_batch_returns_one_result_per_claim_in_order(
        self,
        ctx: SigningContext,
        handle: EvidenceHandle,
        evtx_file: Path,
    ) -> None:
        envelope = parse_evtx(
            handle,
            evtx_path=evtx_file,
            ctx=ctx,
            executor=FakeExecutor(payload=SAMPLE_EVTX_CSV),
        )

        registry = ReverifyRegistry()
        from oath.mcp.tools import parse_evtx as parse_evtx_mod

        def reverify_with_fake(envelope, *, evtx_path):
            return parse_evtx_mod.reverify(
                envelope, evtx_path=evtx_path, executor=FakeExecutor(payload=SAMPLE_EVTX_CSV)
            )

        registry.register("parse_evtx", reverify_with_fake, required_kwargs=("evtx_path",))

        verifier = WitnessOathVerifier(
            envelopes_by_id={"evtx-001": envelope},
            reverify_kwargs={"evtx-001": {"evtx_path": evtx_file}},
            registry=registry,
        )

        c1 = _make_claim(claim_id="c1", predicate={"event_id": 4624, "logon_type": 3})  # VERIFIED
        c2 = _make_claim(claim_id="c2", predicate={"event_id": 4625})  # QUARANTINED
        results = verifier.verify_batch([c1, c2])

        assert [r.claim_id for r in results] == ["c1", "c2"]
        assert results[0].verdict == VerifyVerdict.VERIFIED
        assert results[1].verdict == VerifyVerdict.QUARANTINED
