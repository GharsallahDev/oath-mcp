"""Unit tests for the AgentRunner orchestration.

These pin the contract that turns isolated hypothesis evaluations into a
structured TriageReport — the artifact the examiner reads at the end of a run.
The LLM seam (propose_fn) is injected as a fake; tests don't need a real model.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any

import pytest

from oath.agent.runner import (
    AgentRunner,
    HypothesisOutcome,
    HypothesisSpec,
    TriageReport,
    default_pth_hypotheses,
)
from oath.witness.claim import (
    AgentClaim,
    ClaimEvidence,
    FindingType,
    VerifyResult,
    VerifyVerdict,
)


# --------------------------------------------------------------------------- #
# Fake verifier — pre-programmed verdicts                                     #
# --------------------------------------------------------------------------- #


@dataclass
class FakeVerifier:
    """A WitnessOathVerifier stub that returns canned verdicts in order."""

    verdicts: list[VerifyResult]
    calls: list[AgentClaim] = field(default_factory=list)

    def verify(self, claim: AgentClaim) -> VerifyResult:
        self.calls.append(claim)
        if not self.verdicts:
            raise AssertionError("FakeVerifier exhausted")
        return self.verdicts.pop(0)


def _claim(claim_id: str = "c1", finding_type: FindingType = FindingType.PTH_CANDIDATE) -> AgentClaim:
    return AgentClaim(
        claim_id=claim_id,
        finding_type=finding_type,
        natural_language=f"Claim {claim_id}",
        supporting_evidence=(
            ClaimEvidence(envelope_id="e1", record_predicate={"event_id": 4624}),
        ),
        confidence=0.9,
        reasoning_hash="0" * 64,
        model_id="claude-opus-4-7",
        temperature=0.0,
        seed=1,
    )


def _verdict(
    claim_id: str, verdict: VerifyVerdict, reason: str = "ok", **kw: Any
) -> VerifyResult:
    return VerifyResult(
        claim_id=claim_id,
        verdict=verdict,
        reason=reason,
        envelope_verdicts=kw.get("envelope_verdicts", {}),
        predicate_matches=kw.get("predicate_matches", {}),
    )


# --------------------------------------------------------------------------- #
# Single-hypothesis paths                                                     #
# --------------------------------------------------------------------------- #


class TestRunOne:
    def test_verified_hypothesis_records_verdict_and_zero_events(self) -> None:
        verifier = FakeVerifier(verdicts=[_verdict("c1", VerifyVerdict.VERIFIED, reason="all good")])
        runner = AgentRunner(
            verifier=verifier,
            propose_fn=lambda h, c: _claim("c1", finding_type=h.finding_type),
            run_id="r1",
        )
        hyp = HypothesisSpec(
            name="PtH check",
            finding_type=FindingType.PTH_CANDIDATE,
            guidance="...",
        )
        outcome = runner.run_one(hyp)
        assert outcome.verdict == VerifyVerdict.VERIFIED
        assert outcome.final_claim_id == "c1"
        assert outcome.ralph_wiggum_events == ()
        assert outcome.gave_up is False

    def test_quarantined_hypothesis_records_quarantine_no_retries(self) -> None:
        verifier = FakeVerifier(
            verdicts=[_verdict("c1", VerifyVerdict.QUARANTINED, reason="predicate empty")]
        )
        runner = AgentRunner(
            verifier=verifier,
            propose_fn=lambda h, c: _claim("c1", finding_type=h.finding_type),
            run_id="r1",
        )
        outcome = runner.run_one(
            HypothesisSpec(
                name="PtH check",
                finding_type=FindingType.PTH_CANDIDATE,
                guidance="...",
            )
        )
        assert outcome.verdict == VerifyVerdict.QUARANTINED
        assert outcome.ralph_wiggum_events == ()
        assert outcome.gave_up is False

    def test_ralph_wiggum_then_verified_records_one_event(self) -> None:
        verifier = FakeVerifier(
            verdicts=[
                _verdict(
                    "c1",
                    VerifyVerdict.RALPH_WIGGUM,
                    reason="envelope 'e1' failed re-derivation: drift",
                    envelope_verdicts={"e1": (False, "drift")},
                ),
                _verdict("c2", VerifyVerdict.VERIFIED, reason="ok"),
            ]
        )

        attempt = [0]
        def propose(h: HypothesisSpec, constraints: list[str]) -> AgentClaim:
            attempt[0] += 1
            return _claim(f"c{attempt[0]}", finding_type=h.finding_type)

        runner = AgentRunner(verifier=verifier, propose_fn=propose, run_id="r1")
        outcome = runner.run_one(
            HypothesisSpec(
                name="PtH check",
                finding_type=FindingType.PTH_CANDIDATE,
                guidance="...",
            )
        )
        assert outcome.verdict == VerifyVerdict.VERIFIED
        assert outcome.final_claim_id == "c2"
        assert len(outcome.ralph_wiggum_events) == 1
        assert outcome.ralph_wiggum_events[0].abandoned_claim_id == "c1"
        assert outcome.gave_up is False

    def test_gave_up_when_max_revisions_exceeded(self) -> None:
        verifier = FakeVerifier(
            verdicts=[
                _verdict(
                    f"c{i}",
                    VerifyVerdict.RALPH_WIGGUM,
                    reason="drift",
                    envelope_verdicts={"e1": (False, "drift")},
                )
                for i in range(10)
            ]
        )

        attempt = [0]
        def propose(h: HypothesisSpec, constraints: list[str]) -> AgentClaim:
            attempt[0] += 1
            return _claim(f"c{attempt[0]}", finding_type=h.finding_type)

        runner = AgentRunner(verifier=verifier, propose_fn=propose, run_id="r1")
        outcome = runner.run_one(
            HypothesisSpec(
                name="PtH check",
                finding_type=FindingType.PTH_CANDIDATE,
                guidance="...",
                max_revisions=2,
            )
        )
        # 3 attempts (initial + 2 revisions), all RW, all events recorded
        assert outcome.gave_up is True
        assert len(outcome.ralph_wiggum_events) == 3
        assert outcome.verdict == VerifyVerdict.RALPH_WIGGUM


# --------------------------------------------------------------------------- #
# Full-run roll-up                                                            #
# --------------------------------------------------------------------------- #


class TestRunAll:
    def test_report_aggregates_three_hypothesis_outcomes(self) -> None:
        """One VERIFIED, one QUARANTINED, one GAVE-UP — roll-ups correct."""
        # Verdicts in order:
        #   h1: VERIFIED on first attempt
        #   h2: QUARANTINED on first attempt
        #   h3: 3 RALPH_WIGGUMs in a row (max_revisions=2 → 3 attempts → gave up)
        verifier = FakeVerifier(
            verdicts=[
                _verdict("h1c1", VerifyVerdict.VERIFIED, reason="ok"),
                _verdict("h2c1", VerifyVerdict.QUARANTINED, reason="empty predicate"),
                _verdict("h3c1", VerifyVerdict.RALPH_WIGGUM, reason="drift",
                         envelope_verdicts={"e1": (False, "drift")}),
                _verdict("h3c2", VerifyVerdict.RALPH_WIGGUM, reason="drift again",
                         envelope_verdicts={"e1": (False, "drift")}),
                _verdict("h3c3", VerifyVerdict.RALPH_WIGGUM, reason="drift again again",
                         envelope_verdicts={"e1": (False, "drift")}),
            ]
        )

        ids = iter(["h1c1", "h2c1", "h3c1", "h3c2", "h3c3"])
        def propose(h: HypothesisSpec, c: list[str]) -> AgentClaim:
            return _claim(next(ids), finding_type=h.finding_type)

        runner = AgentRunner(verifier=verifier, propose_fn=propose, run_id="run-3hyp")
        hypotheses = [
            HypothesisSpec("h1", FindingType.PTH_CANDIDATE, "..."),
            HypothesisSpec("h2", FindingType.LOG_CLEARING, "..."),
            HypothesisSpec("h3", FindingType.TIMESTOMP, "...", max_revisions=2),
        ]
        report = runner.run_all(hypotheses)

        assert isinstance(report, TriageReport)
        assert report.run_id == "run-3hyp"
        assert report.total_hypotheses == 3
        assert report.verified_count == 1
        assert report.quarantined_count == 1
        assert report.gave_up_count == 1
        assert report.total_ralph_wiggum_events == 3
        assert len(report.hypothesis_outcomes) == 3
        assert [o.hypothesis_name for o in report.hypothesis_outcomes] == ["h1", "h2", "h3"]

    def test_narrator_fires_on_every_ralph_wiggum_event(self) -> None:
        """The demo overlay subscribes to this — every visible self-correction must fire."""
        verifier = FakeVerifier(
            verdicts=[
                _verdict(f"c{i}", VerifyVerdict.RALPH_WIGGUM, reason=f"drift {i}",
                         envelope_verdicts={"e1": (False, "drift")})
                for i in range(5)
            ]
        )
        narrated = []
        ids = iter([f"c{i}" for i in range(5)])
        runner = AgentRunner(
            verifier=verifier,
            propose_fn=lambda h, c: _claim(next(ids), finding_type=h.finding_type),
            run_id="r1",
            narrator=narrated.append,
        )
        runner.run_one(
            HypothesisSpec("h", FindingType.PTH_CANDIDATE, "...", max_revisions=4)
        )
        assert len(narrated) == 5  # initial + 4 revisions, all RW


# --------------------------------------------------------------------------- #
# Default PtH bundle sanity check                                             #
# --------------------------------------------------------------------------- #


class TestDefaultBundle:
    def test_default_pth_hypotheses_returns_canonical_set(self) -> None:
        hyps = default_pth_hypotheses()
        names = {h.finding_type for h in hyps}
        # Must include the four highest-value PtH hypotheses + a persistence check
        assert FindingType.PTH_CANDIDATE in names
        assert FindingType.LSASS_DUMP_CANDIDATE in names
        assert FindingType.LOG_CLEARING in names
        assert FindingType.TIMESTOMP in names
        assert FindingType.REGISTRY_RUN_KEY in names

    def test_default_bundle_is_in_priority_order(self) -> None:
        """Cheaper / higher-signal hypotheses come first so the agent bails early on clean hosts."""
        hyps = default_pth_hypotheses()
        # First hypothesis is the headline PtH check
        assert hyps[0].finding_type == FindingType.PTH_CANDIDATE
        # All hypotheses have non-empty guidance (the LLM needs steering)
        assert all(h.guidance.strip() for h in hyps)
