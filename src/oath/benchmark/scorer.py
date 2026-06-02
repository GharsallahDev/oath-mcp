"""DFIR-Metric TUS@K scoring.

TUS@K (Top-K Useful Score) is the DFIR-Metric paper's headline metric for
Module III. Definition:

  For each question:
    - agent emits a ranked list of up to K candidate answers
    - TUS@K(question) = 1 if ANY candidate matches the expected answer
                       0 otherwise

  TUS@K(corpus) = mean(TUS@K(question) over corpus)

The published GPT-4.1 baseline on Module III is **38.5% TUS@4**.

This module wraps that arithmetic + per-question audit trails so the
leaderboard publication is reproducible.
"""
from __future__ import annotations

from datetime import datetime, timezone

from pydantic import BaseModel, ConfigDict, Field

from oath.benchmark.question import AnswerType, DfirMetricQuestion, any_match


# --------------------------------------------------------------------------- #
# Per-question + corpus result models                                         #
# --------------------------------------------------------------------------- #


class QuestionAttempt(BaseModel):
    """The agent's response to one question, plus its scorer adjudication.

    The agent emits up to K candidate answers in ranked order. The scorer
    records the unmodified candidates (so the audit trail captures what the
    agent ACTUALLY said), then records the boolean verdict.
    """

    model_config = ConfigDict(frozen=True)

    question_id: str
    image_sha256: str | None = None
    answer_type: AnswerType
    expected_answer: str
    candidates: tuple[str, ...] = Field(
        ...,
        description="Up to K candidate answers in rank order (best-first).",
    )
    matched: bool
    matched_candidate_index: int | None = Field(
        default=None,
        description="0-based index of the first matching candidate; None if no match.",
    )

    # Optional latency / verifier metadata for downstream analysis.
    wall_clock_seconds: float | None = None
    verified_envelope_count: int | None = None
    quarantined_count: int | None = None
    ralph_wiggum_events: int | None = None

    # LLM usage telemetry (None when the agent is deterministic / no API call).
    model_id: str | None = None
    prompt_token_count: int | None = None
    candidates_token_count: int | None = None
    total_token_count: int | None = None
    # Gemini 3.x exposes explicit reasoning/thinking tokens separate from
    # candidates_token_count; older models return None here.
    thoughts_token_count: int | None = None


class BenchmarkResult(BaseModel):
    """End-of-run scorecard for one corpus pass + one K value.

    Reproducibility contract:
      - `corpus_sha256` binds the exact question corpus used
      - `k` is the cap on candidate count per question
      - `attempts` retains every per-question adjudication

    `tus_at_k` is the mean(matched) over `attempts`. If a question received
    no candidates, it's scored 0 (unanswered = wrong).
    """

    model_config = ConfigDict(frozen=True)

    run_id: str
    started_at: str
    finished_at: str
    corpus_sha256: str = Field(..., min_length=64, max_length=64)
    module: str = "III"
    k: int = Field(..., ge=1)
    attempts: tuple[QuestionAttempt, ...]
    tus_at_k: float = Field(..., ge=0.0, le=1.0)
    total_questions: int = Field(..., ge=0)
    matched_count: int = Field(..., ge=0)


# --------------------------------------------------------------------------- #
# The scorer (pure adjudication, no orchestration)                            #
# --------------------------------------------------------------------------- #


def score_attempt(
    question: DfirMetricQuestion,
    candidates: list[str],
    *,
    k: int,
    wall_clock_seconds: float | None = None,
    verified_envelope_count: int | None = None,
    quarantined_count: int | None = None,
    ralph_wiggum_events: int | None = None,
    model_id: str | None = None,
    prompt_token_count: int | None = None,
    candidates_token_count: int | None = None,
    total_token_count: int | None = None,
    thoughts_token_count: int | None = None,
) -> QuestionAttempt:
    """Adjudicate one question's response.

    `candidates` is truncated to `k` entries (per DFIR-Metric's TUS@K
    contract). The first matching candidate's 0-based index is recorded.
    """
    if k < 1:
        raise ValueError("k must be ≥ 1")
    capped = tuple(candidates[:k])

    matched_index: int | None = None
    for i, c in enumerate(capped):
        if any_match(question.answer_type, question.expected_answer, [c]):
            matched_index = i
            break

    return QuestionAttempt(
        question_id=question.question_id,
        image_sha256=question.image_sha256,
        answer_type=question.answer_type,
        expected_answer=question.expected_answer,
        candidates=capped,
        matched=matched_index is not None,
        matched_candidate_index=matched_index,
        wall_clock_seconds=wall_clock_seconds,
        verified_envelope_count=verified_envelope_count,
        quarantined_count=quarantined_count,
        ralph_wiggum_events=ralph_wiggum_events,
        model_id=model_id,
        prompt_token_count=prompt_token_count,
        candidates_token_count=candidates_token_count,
        total_token_count=total_token_count,
        thoughts_token_count=thoughts_token_count,
    )


def compute_tus_at_k(attempts: list[QuestionAttempt]) -> float:
    """Compute mean(matched) over attempts. Empty list → 0.0."""
    if not attempts:
        return 0.0
    matched = sum(1 for a in attempts if a.matched)
    return matched / len(attempts)


def build_result(
    *,
    run_id: str,
    started_at: str,
    finished_at: str | None,
    corpus_sha256: str,
    k: int,
    attempts: list[QuestionAttempt],
    module: str = "III",
) -> BenchmarkResult:
    """Assemble the BenchmarkResult from a list of QuestionAttempts."""
    matched = sum(1 for a in attempts if a.matched)
    return BenchmarkResult(
        run_id=run_id,
        started_at=started_at,
        finished_at=finished_at or datetime.now(timezone.utc).isoformat(),
        corpus_sha256=corpus_sha256,
        module=module,
        k=k,
        attempts=tuple(attempts),
        tus_at_k=compute_tus_at_k(attempts),
        total_questions=len(attempts),
        matched_count=matched,
    )


__all__ = [
    "BenchmarkResult",
    "QuestionAttempt",
    "build_result",
    "compute_tus_at_k",
    "score_attempt",
]
