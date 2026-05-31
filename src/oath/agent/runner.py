"""Autonomous-triage orchestration runner.

Once the MCP server is wired to Claude Code, the LLM does the per-claim
reasoning. But OATH still owns the meta-loop:

  - Which hypotheses to investigate, in what order
  - How many Ralph Wiggum retries to allow per hypothesis
  - What counts as "the triage is done"
  - How to collect verified/quarantined findings into the final report

That's what AgentRunner does. It takes a list of HypothesisSpec entries, runs
each through the Witness Oath Verifier + Ralph Wiggum Loop, and produces a
TriageReport.

The LLM seam is a single callable: ProposeFn (already defined in
ralph_wiggum.py). In production, Claude Code drives this — the user runs
`oath triage` and Claude's MCP-driven session emits AgentClaims via
oath_verify_claim. In tests, we inject a fake propose_fn that returns canned
claims, so the runner is unit-testable without any LLM calls.

This module has no LLM dependencies. It's pure orchestration on top of
already-tested primitives (verifier, ralph_wiggum).
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from oath.witness.claim import AgentClaim, FindingType, VerifyResult, VerifyVerdict
from oath.witness.ralph_wiggum import (
    RalphWiggumEvent,
    RalphWiggumLoop,
    RalphWiggumOutcome,
)
from oath.witness.verifier import WitnessOathVerifier


# --------------------------------------------------------------------------- #
# Hypothesis spec (what the agent investigates)                               #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class HypothesisSpec:
    """A single line of inquiry the agent pursues.

    The runner walks a list of these in order. Each yields one Ralph Wiggum
    loop attempt; the outcome (verified / quarantined / gave up) is collected.

    Examples:
      HypothesisSpec(
        name="T1550.002 PtH on WIN-VICTIM01",
        finding_type=FindingType.PTH_CANDIDATE,
        guidance=(
          "Look for EVTX 4624 LogonType=3 with NTLM auth_package, paired with "
          "Amcache entries for psexesvc/mimikatz on the source host."
        ),
        max_revisions=3,
      )

    Why hypothesis-driven (vs free-form):
      - Bounds the agent's search space (cheaper, faster, more focused)
      - Makes the result narratable ("we asked: is this PtH? Answer: yes,
        here are 3 receipts.")
      - Maps cleanly to MITRE ATT&CK techniques (every IR practitioner
        speaks this)
      - Each hypothesis has a clean PASS/QUARANTINE/GAVE-UP verdict
    """

    name: str
    finding_type: FindingType
    guidance: str
    max_revisions: int = 3


# --------------------------------------------------------------------------- #
# Triage report (what the runner produces)                                    #
# --------------------------------------------------------------------------- #


class HypothesisOutcome(BaseModel):
    """One hypothesis's verdict + supporting evidence + Ralph Wiggum trail."""

    model_config = ConfigDict(frozen=True)

    hypothesis_name: str
    finding_type: str
    verdict: VerifyVerdict | None
    final_claim_id: str | None
    final_claim_text: str | None
    verify_result_reason: str | None
    ralph_wiggum_events: tuple[RalphWiggumEvent, ...] = ()
    gave_up: bool = False


class TriageReport(BaseModel):
    """End-of-run report — the structured artifact the examiner reads."""

    model_config = ConfigDict(frozen=True)

    run_id: str
    started_at: str
    finished_at: str
    hypothesis_outcomes: tuple[HypothesisOutcome, ...]

    # Roll-up stats (so the demo overlay can show "47 findings; 38 verified;
    # 7 quarantined; 2 abandoned" without re-counting client-side)
    total_hypotheses: int
    verified_count: int
    quarantined_count: int
    gave_up_count: int
    total_ralph_wiggum_events: int


# --------------------------------------------------------------------------- #
# Propose-fn factory                                                          #
# --------------------------------------------------------------------------- #


# The propose_fn signature: given a HypothesisSpec and the list of revision
# constraints from previous Ralph Wiggum events, return the next AgentClaim
# (or None to give up). In production, this is a thin wrapper around an LLM
# call (Claude); in tests, a fake.
HypothesisProposeFn = Callable[[HypothesisSpec, list[str]], AgentClaim | None]


# --------------------------------------------------------------------------- #
# Runner                                                                      #
# --------------------------------------------------------------------------- #


@dataclass
class AgentRunner:
    """Run a list of hypotheses through the verifier + ralph_wiggum stack.

    Construction:
      runner = AgentRunner(
        verifier=WitnessOathVerifier(envelopes_by_id=..., reverify_kwargs=..., ...),
        propose_fn=my_propose,
        narrator=lambda event: print(event.narrative),  # optional
        run_id="abcd1234",
      )
      report = runner.run_all(hypotheses=[h1, h2, h3])

    The narrator callback fires on every RalphWiggumEvent (visible self-
    correction); the demo overlay subscribes to this stream.
    """

    verifier: WitnessOathVerifier
    propose_fn: HypothesisProposeFn
    run_id: str
    narrator: Callable[[RalphWiggumEvent], None] | None = None

    def run_one(self, hypothesis: HypothesisSpec) -> HypothesisOutcome:
        """Run one hypothesis through verifier + ralph_wiggum, return outcome."""
        loop = RalphWiggumLoop(
            verifier=self.verifier,
            max_revisions=hypothesis.max_revisions,
            narrator=self.narrator,
        )

        # Adapt the (constraint-list -> claim) propose_fn to also see hypothesis.
        def propose(constraints: list[str]) -> AgentClaim | None:
            return self.propose_fn(hypothesis, constraints)

        outcome: RalphWiggumOutcome = loop.run(propose)

        # Translate the RW outcome into a HypothesisOutcome.
        final_claim = outcome.final_claim
        final_verdict = outcome.final_verdict
        return HypothesisOutcome(
            hypothesis_name=hypothesis.name,
            finding_type=hypothesis.finding_type.value,
            verdict=final_verdict.verdict if final_verdict else None,
            final_claim_id=final_claim.claim_id if final_claim else None,
            final_claim_text=final_claim.natural_language if final_claim else None,
            verify_result_reason=final_verdict.reason if final_verdict else None,
            ralph_wiggum_events=tuple(outcome.events),
            gave_up=outcome.gave_up,
        )

    def run_all(self, hypotheses: list[HypothesisSpec]) -> TriageReport:
        """Run every hypothesis; return the rolled-up TriageReport."""
        started_at = datetime.now(timezone.utc).isoformat()
        outcomes: list[HypothesisOutcome] = []
        for h in hypotheses:
            outcomes.append(self.run_one(h))
        finished_at = datetime.now(timezone.utc).isoformat()

        # Roll-ups
        verified = sum(1 for o in outcomes if o.verdict == VerifyVerdict.VERIFIED)
        quarantined = sum(1 for o in outcomes if o.verdict == VerifyVerdict.QUARANTINED)
        gave_up = sum(1 for o in outcomes if o.gave_up)
        rw_events = sum(len(o.ralph_wiggum_events) for o in outcomes)

        return TriageReport(
            run_id=self.run_id,
            started_at=started_at,
            finished_at=finished_at,
            hypothesis_outcomes=tuple(outcomes),
            total_hypotheses=len(outcomes),
            verified_count=verified,
            quarantined_count=quarantined,
            gave_up_count=gave_up,
            total_ralph_wiggum_events=rw_events,
        )


# --------------------------------------------------------------------------- #
# Default PtH-case hypothesis bundle                                          #
# --------------------------------------------------------------------------- #


def default_pth_hypotheses() -> list[HypothesisSpec]:
    """Canonical PtH/lateral-movement triage hypothesis sequence.

    The order matters: cheaper / higher-confidence checks first so the agent
    bails early on hosts that don't show signal. Each hypothesis is tied to a
    closed FindingType, and the guidance points the LLM at the specific tool
    + filter that's most likely to surface evidence.
    """
    return [
        HypothesisSpec(
            name="T1550.002 Pass-the-Hash candidate",
            finding_type=FindingType.PTH_CANDIDATE,
            guidance=(
                "Find EVTX 4624 with LogonType=3 and AuthenticationPackage=NTLM "
                "that does NOT have a matching prior LogonType=2 interactive logon "
                "from the same user/host pair. Cross-reference Amcache for "
                "psexesvc.exe, mimikatz.exe, rubeus.exe presence on the source host."
            ),
        ),
        HypothesisSpec(
            name="T1003.001 LSASS credential dump candidate",
            finding_type=FindingType.LSASS_DUMP_CANDIDATE,
            guidance=(
                "Run vol3 windows.handles for PROCESS_VM_READ + PROCESS_QUERY_INFORMATION "
                "handles to lsass.exe held by a non-MsMpEng/non-WER process. "
                "Pair with parse_amcache lookup for known credential-dumping tools."
            ),
        ),
        HypothesisSpec(
            name="T1070.001 EVTX log clearing candidate",
            finding_type=FindingType.LOG_CLEARING,
            guidance=(
                "Find EVTX 1102 (Security log cleared) events OR EVTX record-ID gaps "
                "via run_hayabusa with technique_filter=['T1070.001']. Also flag "
                "channels with EventRecordID monotonicity violations."
            ),
        ),
        HypothesisSpec(
            name="T1070.006 Timestomp candidate",
            finding_type=FindingType.TIMESTOMP,
            guidance=(
                "Run parse_mft with filter_path on suspected attacker tooling paths "
                "(e.g. C:\\Windows\\, C:\\Users\\Public). Use the find_timestomp_candidates "
                "helper to flag entries where $SI predates $FN by > 5 seconds."
            ),
        ),
        HypothesisSpec(
            name="T1547.001 Registry Run-key persistence candidate",
            finding_type=FindingType.REGISTRY_RUN_KEY,
            guidance=(
                "Once parse_registry is wired, enumerate "
                "Software\\Microsoft\\Windows\\CurrentVersion\\Run + RunOnce keys in "
                "both NTUSER.DAT (HKCU) and SOFTWARE (HKLM). Flag values pointing to "
                "user-writable paths or unsigned PEs."
            ),
        ),
    ]


__all__ = [
    "AgentRunner",
    "HypothesisOutcome",
    "HypothesisProposeFn",
    "HypothesisSpec",
    "TriageReport",
    "default_pth_hypotheses",
]
