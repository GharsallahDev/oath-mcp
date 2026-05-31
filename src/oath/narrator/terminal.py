"""Rich-based terminal narration for OATH agent events.

The demo's punchline is the visible Ralph Wiggum moment — the agent
abandoning a claim out loud and re-proposing under a verifier-derived
constraint. The narrator is what makes that visible to a viewer in a
screencast.

Designed to be useful in three modes:

  1. Live agent run — narrator hooks into AgentRunner.narrator callback;
     events are rendered as they fire.

  2. Replay from a TriageReport — the report's `hypothesis_outcomes` carry
     the same RalphWiggumEvent records, so `narrate_report(report)` replays
     the entire run with the same visuals.

  3. Demo rehearsal — `narrate_event` / `narrate_verdict` / `narrate_attempt`
     can be called directly with hand-built records, useful for scripting
     a demo without needing a live agent.

Rich is already in the OATH dependency set (we use it elsewhere). No new
dependency is introduced.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from oath.witness.claim import VerifyResult, VerifyVerdict
from oath.witness.ralph_wiggum import RalphWiggumEvent

if TYPE_CHECKING:
    from oath.agent.runner import HypothesisOutcome, TriageReport


# --------------------------------------------------------------------------- #
# Style table                                                                 #
# --------------------------------------------------------------------------- #
#
# The colour table is single-source: every renderer pulls from here so the
# demo viewer learns the colour-coding once and it stays consistent.

_STYLE = {
    "verified": "bold green",
    "quarantined": "bold yellow",
    "ralph_wiggum": "bold magenta",
    "envelope_id": "cyan",
    "tool": "blue",
    "label_dim": "dim",
    "warn": "yellow",
    "fail": "bold red",
    "ok": "green",
}


def _verdict_style(verdict: VerifyVerdict | str) -> str:
    key = verdict.value if isinstance(verdict, VerifyVerdict) else str(verdict).lower()
    return _STYLE.get(key.lower(), "white")


# --------------------------------------------------------------------------- #
# Individual stanzas                                                          #
# --------------------------------------------------------------------------- #


def narrate_verdict(
    result: VerifyResult,
    *,
    console: Console | None = None,
) -> None:
    """Render one VerifyResult — used for VERIFIED + QUARANTINED outcomes.

    RALPH_WIGGUM verdicts are surfaced via `narrate_event` instead; the
    Ralph Wiggum loop owns the visual.
    """
    console = console or Console()
    verdict = result.verdict
    style = _verdict_style(verdict)
    title = Text(f"  {verdict.value.upper()}  ", style=style)

    body = Table.grid(padding=(0, 1))
    body.add_column(style=_STYLE["label_dim"], justify="right")
    body.add_column()
    body.add_row("claim_id", result.claim_id)
    body.add_row("reason", result.reason)

    if result.envelope_verdicts:
        envs = Table.grid(padding=(0, 2))
        envs.add_column(style=_STYLE["envelope_id"])
        envs.add_column()
        for eid, (ok, msg) in result.envelope_verdicts.items():
            marker = Text("✓", style=_STYLE["ok"]) if ok else Text("✗", style=_STYLE["fail"])
            envs.add_row(eid, Text.assemble(marker, " ", msg))
        body.add_row("envelopes", envs)

    console.print(Panel(body, title=title, border_style=style, padding=(0, 1)))


def narrate_event(
    event: RalphWiggumEvent,
    *,
    console: Console | None = None,
) -> None:
    """Render one Ralph Wiggum self-correction event.

    The visual shape is intentional: the abandoned hypothesis is struck
    through, the reason is highlighted, the revision constraint is the
    new working assumption.
    """
    console = console or Console()
    style = _STYLE["ralph_wiggum"]

    abandoned = Text()
    abandoned.append("abandoned: ", style=_STYLE["label_dim"])
    abandoned.append(event.abandoned_finding_type, style="strike yellow")

    reason = Text()
    reason.append("reason:    ", style=_STYLE["label_dim"])
    reason.append(event.abandonment_reason, style=_STYLE["warn"])

    revision = Text()
    revision.append("revision:  ", style=_STYLE["label_dim"])
    revision.append(event.revision_constraint, style=_STYLE["ok"])

    body = Table.grid(padding=(0, 1))
    body.add_column()
    body.add_row(abandoned)
    body.add_row(reason)
    body.add_row(revision)
    if event.narrative:
        narrative = Text(event.narrative, style="italic")
        body.add_row(Text(""))
        body.add_row(narrative)

    title = Text(
        f"  RALPH WIGGUM #{event.attempt_number}  ",
        style=style,
    )
    console.print(Panel(body, title=title, border_style=style, padding=(0, 1)))


def narrate_attempt(
    outcome: "HypothesisOutcome",
    *,
    console: Console | None = None,
) -> None:
    """Render one HypothesisOutcome — the per-hypothesis verdict + RW events."""
    console = console or Console()
    verdict_str = outcome.verdict.value if outcome.verdict else "no_verdict"
    style = _verdict_style(verdict_str)

    header = Table.grid(padding=(0, 1))
    header.add_column(style=_STYLE["label_dim"], justify="right")
    header.add_column()
    header.add_row("hypothesis", outcome.hypothesis_name)
    header.add_row("finding_type", outcome.finding_type)
    header.add_row("verdict", Text(verdict_str.upper(), style=style))
    if outcome.final_claim_text:
        header.add_row("claim", outcome.final_claim_text)
    if outcome.verify_result_reason:
        header.add_row("reason", outcome.verify_result_reason)
    if outcome.gave_up:
        header.add_row("status", Text("GAVE UP", style=_STYLE["fail"]))

    console.print(Panel(header, border_style=style, padding=(0, 1)))

    # Show the Ralph Wiggum trail underneath the hypothesis verdict so the
    # viewer sees the path the agent took to land here.
    for event in outcome.ralph_wiggum_events:
        narrate_event(event, console=console)


def narrate_report(
    report: "TriageReport",
    *,
    console: Console | None = None,
) -> None:
    """Render an entire TriageReport — top-level scoreboard + per-hypothesis stanzas."""
    console = console or Console()

    scoreboard = Table(title="OATH triage", title_style="bold")
    scoreboard.add_column("metric", style=_STYLE["label_dim"], justify="right")
    scoreboard.add_column("value")
    scoreboard.add_row("run_id", report.run_id)
    scoreboard.add_row("hypotheses", str(report.total_hypotheses))
    scoreboard.add_row(
        "verified", Text(str(report.verified_count), style=_STYLE["verified"])
    )
    scoreboard.add_row(
        "quarantined", Text(str(report.quarantined_count), style=_STYLE["quarantined"])
    )
    scoreboard.add_row(
        "gave_up", Text(str(report.gave_up_count), style=_STYLE["fail"])
    )
    scoreboard.add_row(
        "ralph_wiggum_events",
        Text(str(report.total_ralph_wiggum_events), style=_STYLE["ralph_wiggum"]),
    )
    console.print(scoreboard)
    console.print()

    for outcome in report.hypothesis_outcomes:
        narrate_attempt(outcome, console=console)


# --------------------------------------------------------------------------- #
# TerminalNarrator — the AgentRunner-friendly hook                            #
# --------------------------------------------------------------------------- #


@dataclass
class TerminalNarrator:
    """Stateful narrator suitable for AgentRunner.narrator.

    Attaches to one Console (auto-created if not supplied) and exposes
    callback methods matching the AgentRunner / RalphWiggumLoop seams.

    The Console is configurable so tests can redirect output to a
    StringIO + assert on the captured text.
    """

    console: Console = field(default_factory=Console)

    def on_ralph_wiggum(self, event: RalphWiggumEvent) -> None:
        """Hook for RalphWiggumLoop.narrator + AgentRunner.narrator."""
        narrate_event(event, console=self.console)

    def on_verdict(self, result: VerifyResult) -> None:
        """Optional: call after each non-Ralph_Wiggum verdict."""
        narrate_verdict(result, console=self.console)

    def on_outcome(self, outcome: "HypothesisOutcome") -> None:
        narrate_attempt(outcome, console=self.console)

    def on_report(self, report: "TriageReport") -> None:
        narrate_report(report, console=self.console)


__all__ = [
    "TerminalNarrator",
    "narrate_attempt",
    "narrate_event",
    "narrate_report",
    "narrate_verdict",
]
