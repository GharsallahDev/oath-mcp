"""DFIR-Metric Module III scoring harness.

Exports:
  - DfirMetricQuestion + AnswerType (question schema + closed answer-type set)
  - matches / any_match (per-type adjudication)
  - load_corpus / hash_corpus / filter_by_image / filter_by_techniques
  - BenchmarkResult + QuestionAttempt + score_attempt / compute_tus_at_k / build_result
  - BenchmarkHarness + AgentResponse + BenchmarkAgentFn + persist_result
"""
from __future__ import annotations

from oath.benchmark.corpus import (
    filter_by_image,
    filter_by_techniques,
    hash_corpus,
    load_corpus,
    load_nss_corpus,
)
from oath.benchmark.harness import (
    AgentResponse,
    BenchmarkAgentFn,
    BenchmarkHarness,
    persist_result,
)
from oath.benchmark.question import (
    LIST_ANSWER_TYPES,
    AnswerType,
    DfirMetricQuestion,
    any_match,
    list_match_stats,
    matches,
)
from oath.benchmark.scorer import (
    BenchmarkResult,
    QuestionAttempt,
    build_result,
    compute_tus_at_k,
    score_attempt,
)

__all__ = [
    "LIST_ANSWER_TYPES",
    "AgentResponse",
    "AnswerType",
    "BenchmarkAgentFn",
    "BenchmarkHarness",
    "BenchmarkResult",
    "DfirMetricQuestion",
    "QuestionAttempt",
    "any_match",
    "build_result",
    "compute_tus_at_k",
    "filter_by_image",
    "filter_by_techniques",
    "hash_corpus",
    "list_match_stats",
    "load_corpus",
    "load_nss_corpus",
    "matches",
    "persist_result",
    "score_attempt",
]
