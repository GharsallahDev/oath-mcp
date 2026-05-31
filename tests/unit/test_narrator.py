"""Unit tests for the terminal narrator.

We render into an in-memory Console and assert on the captured text. The
goal isn't to lock in exact escape-codes — just that the right *content*
shows up under the right *style key*.
"""
from __future__ import annotations

from io import StringIO

import pytest
from rich.console import Console

from oath.agent.runner import HypothesisOutcome, TriageReport
from oath.narrator import (
    TerminalNarrator,
    narrate_attempt,
    narrate_event,
    narrate_report,
    narrate_verdict,
)
from oath.witness.claim import VerifyResult, VerifyVerdict
from oath.witness.ralph_wiggum import RalphWiggumEvent


# --------------------------------------------------------------------------- #
# Fixture helpers                                                             #
# --------------------------------------------------------------------------- #


def _console() -> Console:
    return Console(file=StringIO(), force_terminal=False, width=120, no_color=True)


def _ralph_event(attempt: int = 1, reason: str = "rule corpus drift on hayabusa-001") -> RalphWiggumEvent:
    return RalphWiggumEvent(
        event_id=f"ev-{attempt}",
        timestamp="2026-04-12T14:32:01+00:00",
        attempt_number=attempt,
        abandoned_claim_id=f"claim-{attempt}",
        abandoned_finding_type="PTH_CANDIDATE",
        abandonment_reason=reason,
        revision_constraint="re-propose without citing envelope hayabusa-001",
        narrative="Rule corpus drifted; the envelope's stdout BLAKE3 no longer matches.",
    )


def _verdict(verdict: VerifyVerdict, claim_id: str = "claim-1") -> VerifyResult:
    return VerifyResult(
        claim_id=claim_id,
        verdict=verdict,
        reason="all envelopes re-verified" if verdict == VerifyVerdict.VERIFIED else "predicate did not match",
        envelope_verdicts={"evtx-001": (True, "ok"), "amcache-001": (True, "ok")},
        predicate_matches={"evtx-001": [3, 7], "amcache-001": [1]},
    )


def _outcome(verdict: VerifyVerdict | None, with_rw: bool = False) -> HypothesisOutcome:
    rw = (_ralph_event(1), _ralph_event(2)) if with_rw else ()
    return HypothesisOutcome(
        hypothesis_name="T1550.002 PtH",
        finding_type="PTH_CANDIDATE",
        verdict=verdict,
        final_claim_id="claim-final",
        final_claim_text="Pass-the-hash via NTLM logon-type-3 from 10.0.0.42",
        verify_result_reason="all envelopes re-verified",
        ralph_wiggum_events=rw,
        gave_up=verdict is None,
    )


# --------------------------------------------------------------------------- #
# narrate_event                                                               #
# --------------------------------------------------------------------------- #


def test_narrate_event_emits_all_three_stanzas():
    c = _console()
    narrate_event(_ralph_event(), console=c)
    out = c.file.getvalue()
    assert "RALPH WIGGUM #1" in out
    assert "PTH_CANDIDATE" in out
    assert "rule corpus drift" in out
    assert "re-propose without citing envelope hayabusa-001" in out


def test_narrate_event_includes_narrative_when_present():
    c = _console()
    narrate_event(_ralph_event(), console=c)
    out = c.file.getvalue()
    assert "Rule corpus drifted" in out


def test_narrate_event_handles_high_attempt_numbers():
    c = _console()
    narrate_event(_ralph_event(attempt=7), console=c)
    assert "RALPH WIGGUM #7" in c.file.getvalue()


# --------------------------------------------------------------------------- #
# narrate_verdict                                                             #
# --------------------------------------------------------------------------- #


def test_narrate_verdict_verified_includes_envelopes():
    c = _console()
    narrate_verdict(_verdict(VerifyVerdict.VERIFIED), console=c)
    out = c.file.getvalue()
    assert "VERIFIED" in out
    assert "claim-1" in out
    assert "evtx-001" in out


def test_narrate_verdict_quarantined_has_distinct_title():
    c = _console()
    narrate_verdict(_verdict(VerifyVerdict.QUARANTINED), console=c)
    assert "QUARANTINED" in c.file.getvalue()


# --------------------------------------------------------------------------- #
# narrate_attempt                                                             #
# --------------------------------------------------------------------------- #


def test_narrate_attempt_shows_hypothesis_and_verdict():
    c = _console()
    narrate_attempt(_outcome(VerifyVerdict.VERIFIED), console=c)
    out = c.file.getvalue()
    assert "T1550.002 PtH" in out
    assert "VERIFIED" in out
    assert "Pass-the-hash" in out


def test_narrate_attempt_inlines_ralph_wiggum_trail():
    c = _console()
    narrate_attempt(_outcome(VerifyVerdict.VERIFIED, with_rw=True), console=c)
    out = c.file.getvalue()
    # Two RW events should each render their stanza
    assert out.count("RALPH WIGGUM") == 2


def test_narrate_attempt_marks_gave_up_outcome():
    c = _console()
    narrate_attempt(_outcome(None), console=c)
    out = c.file.getvalue()
    assert "GAVE UP" in out


# --------------------------------------------------------------------------- #
# narrate_report                                                              #
# --------------------------------------------------------------------------- #


def test_narrate_report_renders_scoreboard_and_per_hypothesis_stanzas():
    outcomes = (
        _outcome(VerifyVerdict.VERIFIED),
        _outcome(VerifyVerdict.QUARANTINED, with_rw=True),
        _outcome(None),
    )
    report = TriageReport(
        run_id="run-1",
        started_at="2026-04-12T14:00:00+00:00",
        finished_at="2026-04-12T14:35:00+00:00",
        hypothesis_outcomes=outcomes,
        total_hypotheses=3,
        verified_count=1,
        quarantined_count=1,
        gave_up_count=1,
        total_ralph_wiggum_events=2,
    )

    c = _console()
    narrate_report(report, console=c)
    out = c.file.getvalue()
    assert "OATH triage" in out
    assert "run-1" in out
    # Each hypothesis stanza shows up exactly once
    assert out.count("T1550.002 PtH") == 3
    # Scoreboard contains all the counts
    assert "verified" in out and "1" in out
    assert "ralph_wiggum_events" in out
    # RW events from the second outcome render in the per-attempt section
    assert out.count("RALPH WIGGUM") == 2


# --------------------------------------------------------------------------- #
# TerminalNarrator class                                                      #
# --------------------------------------------------------------------------- #


def test_terminal_narrator_on_ralph_wiggum_callback_renders():
    c = _console()
    narrator = TerminalNarrator(console=c)
    narrator.on_ralph_wiggum(_ralph_event())
    assert "RALPH WIGGUM #1" in c.file.getvalue()


def test_terminal_narrator_can_be_passed_as_agent_runner_callback():
    """on_ralph_wiggum must match the (RalphWiggumEvent) -> None signature."""
    c = _console()
    narrator = TerminalNarrator(console=c)
    # Simulate AgentRunner invoking the narrator on a stream of events.
    for i in range(3):
        narrator.on_ralph_wiggum(_ralph_event(attempt=i))
    assert c.file.getvalue().count("RALPH WIGGUM") == 3


def test_terminal_narrator_on_verdict_renders():
    c = _console()
    narrator = TerminalNarrator(console=c)
    narrator.on_verdict(_verdict(VerifyVerdict.VERIFIED))
    assert "VERIFIED" in c.file.getvalue()


def test_terminal_narrator_on_outcome_renders():
    c = _console()
    narrator = TerminalNarrator(console=c)
    narrator.on_outcome(_outcome(VerifyVerdict.VERIFIED, with_rw=True))
    out = c.file.getvalue()
    assert "T1550.002 PtH" in out
    assert "RALPH WIGGUM" in out
