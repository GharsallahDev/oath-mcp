"""DFIR-Metric benchmark orchestrator.

The harness owns the meta-loop:

  for each question in corpus (filtered to the mounted image):
      candidates = agent.answer(question, max_candidates=K)
      attempt   = score_attempt(question, candidates, k=K, ...)
      attempts.append(attempt)

  result = build_result(attempts, ...)
  persist(result)

The "agent" is injected as a single callable so the harness is unit-testable
with fakes and the real implementation (Claude Code session via MCP) can be
swapped in at integration time.
"""
from __future__ import annotations

import json
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from oath.benchmark.question import DfirMetricQuestion
from oath.benchmark.scorer import (
    BenchmarkResult,
    QuestionAttempt,
    build_result,
    score_attempt,
)


# --------------------------------------------------------------------------- #
# Agent seam                                                                  #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class AgentResponse:
    """One agent's response to one question.

    `candidates` is the ranked list (best-first) of up to K candidate answers.
    The rest is optional instrumentation for analysis.
    """

    candidates: list[str]
    wall_clock_seconds: float | None = None
    verified_envelope_count: int | None = None
    quarantined_count: int | None = None
    ralph_wiggum_events: int | None = None


# A pluggable agent function: (question, k) -> ranked candidates + telemetry.
BenchmarkAgentFn = Callable[[DfirMetricQuestion, int], AgentResponse]


# --------------------------------------------------------------------------- #
# Persistence                                                                 #
# --------------------------------------------------------------------------- #


def persist_result(result: BenchmarkResult, out_dir: Path) -> Path:
    """Write a BenchmarkResult to disk as canonical JSON.

    Filename: `{run_id}_{module}_tus{k}.json` (e.g. `abc123_III_tus4.json`).
    Atomic write via `.tmp` + rename — partial writes don't pollute the
    leaderboard input.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    target = out_dir / f"{result.run_id}_{result.module}_tus{result.k}.json"
    tmp = target.with_suffix(target.suffix + ".tmp")

    payload = result.model_dump(mode="json")
    canonical = json.dumps(payload, sort_keys=True, indent=2, ensure_ascii=False)
    tmp.write_text(canonical, encoding="utf-8")
    tmp.replace(target)
    return target


# --------------------------------------------------------------------------- #
# Harness                                                                     #
# --------------------------------------------------------------------------- #


@dataclass
class BenchmarkHarness:
    """Run a list of questions through an agent and produce a BenchmarkResult.

    Construction:
      harness = BenchmarkHarness(
        agent_fn=my_agent,
        k=4,
        run_id="abc123",  # optional; generated if omitted
        progress_callback=lambda i, n, q: print(f"{i+1}/{n}: {q.question_id}"),
      )
      result = harness.run(questions, corpus_sha256=...)
    """

    agent_fn: BenchmarkAgentFn
    k: int = 4
    run_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    module: str = "III"
    progress_callback: Callable[[int, int, DfirMetricQuestion], None] | None = None
    on_attempt: Callable[[QuestionAttempt], None] | None = None

    def __post_init__(self) -> None:
        if self.k < 1:
            raise ValueError("k must be ≥ 1")

    def run(
        self,
        questions: list[DfirMetricQuestion],
        *,
        corpus_sha256: str,
    ) -> BenchmarkResult:
        """Run every question through the agent; return the BenchmarkResult."""
        started_at = datetime.now(timezone.utc).isoformat()
        attempts: list[QuestionAttempt] = []

        for i, q in enumerate(questions):
            if self.progress_callback:
                self.progress_callback(i, len(questions), q)

            response = self.agent_fn(q, self.k)
            attempt = score_attempt(
                q,
                response.candidates,
                k=self.k,
                wall_clock_seconds=response.wall_clock_seconds,
                verified_envelope_count=response.verified_envelope_count,
                quarantined_count=response.quarantined_count,
                ralph_wiggum_events=response.ralph_wiggum_events,
            )
            attempts.append(attempt)

            if self.on_attempt:
                self.on_attempt(attempt)

        return build_result(
            run_id=self.run_id,
            started_at=started_at,
            finished_at=datetime.now(timezone.utc).isoformat(),
            corpus_sha256=corpus_sha256,
            k=self.k,
            attempts=attempts,
            module=self.module,
        )


__all__ = [
    "AgentResponse",
    "BenchmarkAgentFn",
    "BenchmarkHarness",
    "persist_result",
]
