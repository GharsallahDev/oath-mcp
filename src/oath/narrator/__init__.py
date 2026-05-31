"""Terminal narration for the OATH agent's verifier + Ralph Wiggum loop.

Exports a rich-based narrator that the AgentRunner can plug in via its
`narrator` callback. The narrator turns dry structured events into the
visible self-correction moment that the demo screencast leans on.

  from oath.narrator import TerminalNarrator, narrate_event, narrate_verdict
  runner = AgentRunner(..., narrator=TerminalNarrator().on_ralph_wiggum)
"""
from __future__ import annotations

from oath.narrator.terminal import (
    TerminalNarrator,
    narrate_attempt,
    narrate_event,
    narrate_report,
    narrate_verdict,
)

__all__ = [
    "TerminalNarrator",
    "narrate_attempt",
    "narrate_event",
    "narrate_report",
    "narrate_verdict",
]
