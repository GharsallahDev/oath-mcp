"""Tests for the Ralph Wiggum Loop — visible self-correction state machine.

These pin the four critical transitions:
  1. First attempt VERIFIED → exit on attempt 0, no events
  2. First attempt QUARANTINED → exit on attempt 0, no events (not a Ralph Wiggum)
  3. RALPH_WIGGUM → narrator fires + constraint propagates + next attempt called
  4. Hit max_revisions without converging → gave_up=True with all events

The test injects a fake verifier (stub that returns canned verdicts) and a fake
propose_fn (returns canned claims) — no LLM and no forensic tools needed.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import pytest

from oath.witness.claim import (
    AgentClaim,
    ClaimEvidence,
    FindingType,
    VerifyResult,
    VerifyVerdict,
)
from oath.witness.ralph_wiggum import (
    RalphWiggumEvent,
    RalphWiggumLoop,
)


# --------------------------------------------------------------------------- #
# Fake verifier — returns canned verdicts per call                            #
# --------------------------------------------------------------------------- #


@dataclass
class FakeVerifier:
    """A stub WitnessOathVerifier that emits a pre-programmed sequence of verdicts."""

    verdicts: list[VerifyResult]
    calls: list[AgentClaim] = field(default_factory=list)

    def verify(self, claim: AgentClaim) -> VerifyResult:
        self.calls.append(claim)
        if not self.verdicts:
            raise AssertionError("FakeVerifier ran out of canned verdicts")
        return self.verdicts.pop(0)

    def verify_batch(self, claims: list[AgentClaim]) -> list[VerifyResult]:
        return [self.verify(c) for c in claims]


def _make_claim(*, claim_id: str = "c1") -> AgentClaim:
    return AgentClaim(
        claim_id=claim_id,
        finding_type=FindingType.PTH_CANDIDATE,
        natural_language=f"Claim {claim_id}",
        supporting_evidence=(
            ClaimEvidence(envelope_id="e1", record_predicate={"event_id": 4624}),
        ),
        confidence=0.9,
        reasoning_hash="a" * 64,
        model_id="claude-opus-4-7",
        temperature=0.0,
        seed=1,
    )


def _verdict(
    *, verdict: VerifyVerdict, claim_id: str = "c1", reason: str = "", **kw
) -> VerifyResult:
    return VerifyResult(
        claim_id=claim_id,
        verdict=verdict,
        reason=reason or verdict.value,
        envelope_verdicts=kw.get("envelope_verdicts", {}),
        predicate_matches=kw.get("predicate_matches", {}),
    )


# --------------------------------------------------------------------------- #
# 1. Happy path — VERIFIED on attempt 0                                       #
# --------------------------------------------------------------------------- #


def test_first_attempt_verified_exits_with_no_events() -> None:
    verifier = FakeVerifier(
        verdicts=[_verdict(verdict=VerifyVerdict.VERIFIED, reason="all good")]
    )
    loop = RalphWiggumLoop(verifier=verifier, max_revisions=3)

    claim_count = [0]
    def propose(_: list[str]) -> AgentClaim:
        claim_count[0] += 1
        return _make_claim()

    outcome = loop.run(propose)

    assert outcome.final_verdict is not None
    assert outcome.final_verdict.verdict == VerifyVerdict.VERIFIED
    assert outcome.events == []
    assert outcome.gave_up is False
    assert claim_count[0] == 1


# --------------------------------------------------------------------------- #
# 2. QUARANTINED is NOT a Ralph Wiggum trigger                                #
# --------------------------------------------------------------------------- #


def test_quarantined_exits_without_emitting_event() -> None:
    """A quarantined claim surfaces to the examiner — the loop does NOT retry."""
    verifier = FakeVerifier(
        verdicts=[_verdict(verdict=VerifyVerdict.QUARANTINED, reason="predicate empty")]
    )
    loop = RalphWiggumLoop(verifier=verifier, max_revisions=3)

    propose_calls = [0]
    def propose(_: list[str]) -> AgentClaim:
        propose_calls[0] += 1
        return _make_claim()

    outcome = loop.run(propose)

    assert outcome.final_verdict.verdict == VerifyVerdict.QUARANTINED
    assert outcome.events == []
    assert outcome.gave_up is False
    assert propose_calls[0] == 1, "loop must not retry on QUARANTINED"


# --------------------------------------------------------------------------- #
# 3. RALPH_WIGGUM -> visible self-correction + constraint propagation         #
# --------------------------------------------------------------------------- #


def test_ralph_wiggum_emits_event_and_passes_constraint_to_next_proposal() -> None:
    """One Ralph Wiggum on attempt 0, then VERIFIED on attempt 1."""
    verifier = FakeVerifier(
        verdicts=[
            _verdict(
                verdict=VerifyVerdict.RALPH_WIGGUM,
                reason="envelope 'e1' failed re-derivation: stdout BLAKE3 drift",
                envelope_verdicts={"e1": (False, "stdout BLAKE3 drift")},
            ),
            _verdict(verdict=VerifyVerdict.VERIFIED, reason="all good"),
        ]
    )
    narrated: list[RalphWiggumEvent] = []
    loop = RalphWiggumLoop(verifier=verifier, max_revisions=3, narrator=narrated.append)

    received_constraints: list[list[str]] = []
    def propose(constraints: list[str]) -> AgentClaim:
        received_constraints.append(list(constraints))
        return _make_claim(claim_id=f"c{len(received_constraints)}")

    outcome = loop.run(propose)

    # End state: VERIFIED on attempt 1, with one event from attempt 0.
    assert outcome.final_verdict.verdict == VerifyVerdict.VERIFIED
    assert outcome.gave_up is False
    assert len(outcome.events) == 1
    event = outcome.events[0]
    assert event.attempt_number == 0
    assert event.abandoned_claim_id == "c1"
    assert "BLAKE3 drift" in event.abandonment_reason

    # Narrator fired exactly once.
    assert len(narrated) == 1
    assert narrated[0] is event

    # The second propose() call received a non-empty constraint list.
    assert len(received_constraints) == 2
    assert received_constraints[0] == []  # fresh attempt has no constraints
    assert len(received_constraints[1]) == 1
    constraint = received_constraints[1][0]
    assert "e1" in constraint  # the bad envelope id is named
    assert "do not cite" in constraint.lower() or "do not cite" in constraint


# --------------------------------------------------------------------------- #
# 4. Hit max_revisions without converging -> gave_up=True                      #
# --------------------------------------------------------------------------- #


def test_loop_gives_up_after_max_revisions() -> None:
    """If every attempt yields RALPH_WIGGUM, the loop exits with gave_up=True."""
    verifier = FakeVerifier(
        verdicts=[
            _verdict(
                verdict=VerifyVerdict.RALPH_WIGGUM,
                reason="drift " + str(i),
                envelope_verdicts={"e1": (False, "drift")},
            )
            for i in range(10)  # plenty of canned verdicts
        ]
    )
    loop = RalphWiggumLoop(verifier=verifier, max_revisions=2)

    propose_calls = [0]
    def propose(_: list[str]) -> AgentClaim:
        propose_calls[0] += 1
        return _make_claim(claim_id=f"c{propose_calls[0]}")

    outcome = loop.run(propose)

    # max_revisions=2 means attempts 0, 1, 2 — three total — all RALPH_WIGGUM.
    assert propose_calls[0] == 3
    assert len(outcome.events) == 3
    assert outcome.gave_up is True
    assert outcome.final_verdict is not None
    assert outcome.final_verdict.verdict == VerifyVerdict.RALPH_WIGGUM


def test_propose_returning_none_signals_give_up() -> None:
    """If propose_fn returns None mid-loop (LLM has no remaining hypothesis), surface gave_up=True."""
    verifier = FakeVerifier(
        verdicts=[
            _verdict(verdict=VerifyVerdict.RALPH_WIGGUM, reason="bad"),
        ]
    )
    loop = RalphWiggumLoop(verifier=verifier, max_revisions=3)

    attempt = [0]
    def propose(constraints: list[str]) -> AgentClaim | None:
        attempt[0] += 1
        if attempt[0] == 1:
            return _make_claim()
        return None  # No more hypotheses

    outcome = loop.run(propose)

    assert outcome.gave_up is True
    assert len(outcome.events) == 1  # one Ralph Wiggum on the first attempt


# --------------------------------------------------------------------------- #
# 5. Predicate-failure constraint derivation                                  #
# --------------------------------------------------------------------------- #


def test_predicate_unmatched_constraint_steers_next_attempt() -> None:
    """When the verdict's envelope_verdicts are OK but predicate_matches are empty,
    the constraint tells the LLM to pick a different predicate or envelope.

    Note: in production, this combination would yield VerifyVerdict.QUARANTINED
    (not RALPH_WIGGUM), so the loop wouldn't even retry. This test exercises
    _derive_constraint directly via a synthetic RALPH_WIGGUM verdict with no
    bad envelopes but empty predicate_matches — testing the fallback path.
    """
    from oath.witness.ralph_wiggum import _derive_constraint

    claim = _make_claim()
    verdict = _verdict(
        verdict=VerifyVerdict.RALPH_WIGGUM,
        envelope_verdicts={"e1": (True, "ok")},
        predicate_matches={"e1": []},  # empty match
    )
    constraint = _derive_constraint(claim, verdict)
    assert "e1" in constraint
    assert "predicate" in constraint.lower() or "matched zero" in constraint.lower()
