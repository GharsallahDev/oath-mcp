"""The Ralph Wiggum Loop — visible self-correction state machine.

When the Witness Oath Verifier returns `RALPH_WIGGUM` (envelope re-derivation
failed or referenced something that doesn't exist), the agent has *seen* its
own mistake. The Ralph Wiggum Loop is the controlled retry policy that:

  1. Logs the abandonment as a structured event (the examiner reads this in
     the audit trail and watches it in the demo).
  2. Derives a *revision constraint* from the verdict — what specifically
     changed since the agent proposed the claim, OR what the next hypothesis
     must avoid.
  3. Re-prompts the LLM with the constraint added to its working set.
  4. Bounded retry (default 3 revisions) so a stuck loop cannot run forever.

Naming
------
Rob T. Lee coined the name "Ralph Wiggum Loop" in his Substack while writing
about Protocol SIFT — to describe the moment when an agent realizes "I'm in
danger" and corrects course. The term shows up exactly once in OATH's docs
+ once in the code (the class name); we do NOT re-mention it elsewhere to
avoid sycophancy.

What this is NOT
----------------
This module does NOT implement the LLM. It expects a `propose_fn` callable
from the agent loop that, given a list of revision constraints, returns the
next AgentClaim. The loop is a pure orchestration primitive over the
Verifier; the propose_fn is the LLM-shaped seam.

This separation is why the loop is unit-testable without spending tokens —
we inject a fake propose_fn that returns canned claims and assert the loop's
state machine transitions correctly.
"""
from __future__ import annotations

import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone

from pydantic import BaseModel, ConfigDict, Field

from oath.witness.claim import AgentClaim, VerifyResult, VerifyVerdict
from oath.witness.verifier import WitnessOathVerifier


# --------------------------------------------------------------------------- #
# Structured event the examiner sees (audit trail + demo overlay)             #
# --------------------------------------------------------------------------- #


class RalphWiggumEvent(BaseModel):
    """One visible self-correction event.

    The OATH demo video subscribes to a stream of these — every time one fires,
    the on-screen overlay shows the abandoned hypothesis crossed out, the
    reason narrated, and the revised hypothesis pencilled in. This is the
    quantified-resolution moment from the empirical winning pattern.
    """

    model_config = ConfigDict(frozen=True)

    event_id: str = Field(..., description="UUID for this self-correction event.")
    timestamp: str = Field(..., description="ISO-8601 UTC.")
    attempt_number: int = Field(..., ge=0, description="Zero-indexed retry counter.")
    abandoned_claim_id: str
    abandoned_finding_type: str
    abandonment_reason: str = Field(
        ..., description="The Verifier's reason field — re-derivation failure detail."
    )
    revision_constraint: str = Field(
        ...,
        description=(
            "Derived constraint the next LLM attempt must respect — e.g. "
            "'do not cite envelope X; the rule corpus changed since mint.'"
        ),
    )
    narrative: str = Field(
        ...,
        description=(
            "Human-readable narration for the demo overlay and examiner audit "
            "trail (e.g. 'I expected T1078 but the EVTX 4624 LogonType=3 + NTLM "
            "contradicts an interactive logon; revising to T1550.002.')."
        ),
    )


# --------------------------------------------------------------------------- #
# Result of running the loop end-to-end                                       #
# --------------------------------------------------------------------------- #


@dataclass
class RalphWiggumOutcome:
    """What the agent loop receives after a Ralph Wiggum cycle.

    The final claim + its verifier verdict are the load-bearing fields.
    `events` is the structured history of abandonments (possibly empty if
    the first attempt verified). `gave_up` flags hitting the max-revision
    cap without converging.
    """

    final_claim: AgentClaim | None
    final_verdict: VerifyResult | None
    events: list[RalphWiggumEvent] = field(default_factory=list)
    gave_up: bool = False


# --------------------------------------------------------------------------- #
# Propose callable signature                                                  #
# --------------------------------------------------------------------------- #


# The agent-loop side of the seam: given a list of constraint strings derived
# from prior abandonment events, return the next claim. The constraints are
# typically appended to the LLM's system or user prompt.
ProposeFn = Callable[[list[str]], AgentClaim | None]


# --------------------------------------------------------------------------- #
# Constraint derivation — Verifier verdict -> revision string                 #
# --------------------------------------------------------------------------- #


def _derive_constraint(claim: AgentClaim, verdict: VerifyResult) -> str:
    """Turn a verifier-rejected claim's reason into a revision constraint string.

    The constraint is what we tell the LLM on the NEXT attempt to steer it
    away from the same mistake. Three flavors:

      - Envelope failed reverify: tell the LLM the envelope is unreliable and
        not to cite it again.
      - Predicate didn't match: tell the LLM the specific (envelope, predicate)
        pair was empty, so the next attempt must either cite a different
        envelope or use a different predicate.
      - Unknown envelope_id: tell the LLM only to cite envelopes that exist
        in the working set.
    """
    bad_envelopes = [
        eid for eid, (ok, _) in verdict.envelope_verdicts.items() if not ok
    ]
    if bad_envelopes:
        return (
            f"On the previous attempt, claim '{claim.claim_id}' "
            f"({claim.finding_type.value}) cited envelope(s) {bad_envelopes} that "
            "failed re-derivation. Do not cite those envelopes again. If the same "
            "evidence is essential, request a fresh tool run before re-citing it."
        )

    empty_predicates = [
        eid for eid, idxs in verdict.predicate_matches.items() if not idxs
    ]
    if empty_predicates:
        return (
            f"On the previous attempt, claim '{claim.claim_id}' "
            f"({claim.finding_type.value}) cited envelope(s) {empty_predicates} but "
            "the record_predicate matched zero records. Either pick a different "
            "predicate that actually matches records in that envelope, or cite a "
            "different envelope, or downgrade the claim to a narrative inference."
        )

    return (
        f"On the previous attempt, claim '{claim.claim_id}' "
        f"({claim.finding_type.value}) failed verification: {verdict.reason}. "
        "Reconsider whether the underlying hypothesis is supportable by the "
        "available evidence."
    )


def _build_narrative(claim: AgentClaim, verdict: VerifyResult, attempt_number: int) -> str:
    """The human-readable line that appears on the demo overlay + audit trail."""
    return (
        f"[attempt {attempt_number}] abandoning {claim.finding_type.value}: "
        f"{verdict.reason}"
    )


# --------------------------------------------------------------------------- #
# The loop itself                                                             #
# --------------------------------------------------------------------------- #


@dataclass
class RalphWiggumLoop:
    """Bounded retry loop on top of WitnessOathVerifier.

    Behavior:
      - Verifier returns VERIFIED → loop exits with success on first attempt.
      - Verifier returns QUARANTINED → loop exits with QUARANTINED — quarantine
        is NOT a self-correction trigger (the agent thought wrong, but the
        evidence chain is intact; the examiner should see this surface).
      - Verifier returns RALPH_WIGGUM → loop emits a RalphWiggumEvent, derives
        a constraint, re-prompts via propose_fn(constraints), retries.

    The `narrator` callable (if provided) is called with each event as it
    happens — the demo's overlay subscribes to this stream.
    """

    verifier: WitnessOathVerifier
    max_revisions: int = 3
    narrator: Callable[[RalphWiggumEvent], None] | None = None

    def run(self, propose_fn: ProposeFn) -> RalphWiggumOutcome:
        events: list[RalphWiggumEvent] = []
        constraints: list[str] = []

        last_claim: AgentClaim | None = None
        last_verdict: VerifyResult | None = None

        # +1 because attempt 0 is the "fresh" proposal; max_revisions counts retries.
        for attempt in range(self.max_revisions + 1):
            claim = propose_fn(list(constraints))
            if claim is None:
                # The LLM declined to propose anything further (e.g. it
                # genuinely has no remaining hypothesis). Surface that
                # honestly rather than looping forever.
                return RalphWiggumOutcome(
                    final_claim=last_claim,
                    final_verdict=last_verdict,
                    events=events,
                    gave_up=True,
                )

            verdict = self.verifier.verify(claim)
            last_claim = claim
            last_verdict = verdict

            if verdict.verdict == VerifyVerdict.VERIFIED:
                return RalphWiggumOutcome(
                    final_claim=claim, final_verdict=verdict, events=events, gave_up=False
                )

            if verdict.verdict == VerifyVerdict.QUARANTINED:
                # Quarantine is NOT a ralph-wiggum trigger — the agent's
                # supporting envelopes are intact; the predicate just didn't
                # match. The examiner sees this surfaced as 'suspected but
                # unproven' in the report.
                return RalphWiggumOutcome(
                    final_claim=claim, final_verdict=verdict, events=events, gave_up=False
                )

            # RALPH_WIGGUM — visibly abandon and try again with a constraint.
            event = RalphWiggumEvent(
                event_id=uuid.uuid4().hex,
                timestamp=datetime.now(timezone.utc).isoformat(),
                attempt_number=attempt,
                abandoned_claim_id=claim.claim_id,
                abandoned_finding_type=claim.finding_type.value,
                abandonment_reason=verdict.reason,
                revision_constraint=_derive_constraint(claim, verdict),
                narrative=_build_narrative(claim, verdict, attempt),
            )
            events.append(event)
            constraints.append(event.revision_constraint)

            if self.narrator is not None:
                try:
                    self.narrator(event)
                except Exception:  # noqa: BLE001 — narrator is decorative; never block the loop
                    pass

        # Exceeded retries without converging.
        return RalphWiggumOutcome(
            final_claim=last_claim,
            final_verdict=last_verdict,
            events=events,
            gave_up=True,
        )


__all__ = [
    "ProposeFn",
    "RalphWiggumEvent",
    "RalphWiggumLoop",
    "RalphWiggumOutcome",
]
