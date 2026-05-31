"""DFIR-Metric Module III question model + per-type answer matching.

The DFIR-Metric benchmark (arXiv:2505.19973) ships its Module III
practical-analysis subset as a corpus of (image, question, expected_answer)
tuples. Each question has a typed answer (string, hex hash, numeric,
timestamp, path, SID) with type-specific matching rules.

This module is the deterministic adjudication layer. No fuzzy LLM-judging,
no synonym tables, no "looks right." Match or fail.
"""
from __future__ import annotations

import re
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator


# --------------------------------------------------------------------------- #
# Closed answer-type set                                                      #
# --------------------------------------------------------------------------- #


class AnswerType(str, Enum):
    """Closed set of answer-types the scorer knows how to adjudicate.

    The corpus author MUST tag every question with one of these. Tags drive
    per-type matching rules (see `matches` below).
    """

    EXACT_STRING = "exact_string"  # case-sensitive exact
    STRING_CI = "string_ci"        # case-insensitive
    HEX_HASH = "hex_hash"          # case-insensitive hex (md5/sha1/sha256)
    NUMERIC = "numeric"            # int or float equality
    TIMESTAMP = "timestamp"        # ISO-8601 with second-level tolerance
    PATH = "path"                  # case-insensitive, backslash-normalized
    SID = "sid"                    # Windows SID; canonical uppercased


# --------------------------------------------------------------------------- #
# Question record                                                             #
# --------------------------------------------------------------------------- #


class DfirMetricQuestion(BaseModel):
    """One question from the DFIR-Metric Module III corpus.

    The (image_sha256, question_id) pair is the natural key. The image_sha256
    is the SHA-256 of the unmodified source image bound to the question; the
    benchmark harness refuses to score a run whose EvidenceHandle SHA-256
    doesn't match.
    """

    model_config = ConfigDict(frozen=True)

    question_id: str = Field(..., min_length=1)
    image_sha256: str = Field(..., min_length=64, max_length=64)
    question_text: str = Field(..., min_length=1)
    answer_type: AnswerType
    expected_answer: str = Field(..., min_length=1)

    # Optional metadata
    module: str = Field(default="III", description="DFIR-Metric module (typically 'III' for OATH).")
    case_label: str | None = Field(default=None, description="Human case name (e.g. 'CFReDS-Hacking').")
    mitre_techniques: tuple[str, ...] = Field(
        default=(),
        description="Optional MITRE ATT&CK technique tags for question selection.",
    )

    @model_validator(mode="after")
    def _validate_hex_hash(self) -> "DfirMetricQuestion":
        if self.answer_type == AnswerType.HEX_HASH:
            cleaned = self.expected_answer.strip().lower()
            if not re.fullmatch(r"[0-9a-f]+", cleaned):
                raise ValueError(
                    f"hex_hash expected_answer must be hex characters only: {self.expected_answer!r}"
                )
            if len(cleaned) not in (32, 40, 64):
                raise ValueError(
                    f"hex_hash expected_answer length must be 32 (md5), 40 (sha1), or 64 (sha256); got {len(cleaned)}"
                )
        return self


# --------------------------------------------------------------------------- #
# Per-type matching                                                           #
# --------------------------------------------------------------------------- #
#
# Each helper returns a bool. None of them tolerate fuzzy matches: the
# adjudication is deterministic, and the scorer's TUS@K can therefore be
# recomputed by anyone with the same corpus + same agent output.


def _normalize_path(p: str) -> str:
    """Lowercase, collapse backslash-runs, strip trailing slash."""
    p = p.strip().lower().replace("/", "\\")
    p = re.sub(r"\\+", r"\\", p)
    return p.rstrip("\\")


_TIMESTAMP_TOLERANCE_SECONDS = 2


def _parse_timestamp(s: str) -> float | None:
    """Parse an ISO-8601 timestamp into a POSIX float. Returns None on failure.

    Tolerant of: trailing Z, missing TZ (assumed UTC), microsecond truncation.
    Strict about: anything else.
    """
    from datetime import datetime, timezone

    s = s.strip()
    if not s:
        return None
    s = s.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        # Common alternate format: 'YYYY-MM-DD HH:MM:SS'
        try:
            dt = datetime.strptime(s, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


def matches(answer_type: AnswerType, expected: str, candidate: str) -> bool:
    """Return True iff `candidate` satisfies the expected answer under the answer_type's rules.

    Adjudication rules:
      EXACT_STRING : `expected == candidate` (no normalization)
      STRING_CI    : `expected.lower() == candidate.lower()`, leading/trailing whitespace stripped
      HEX_HASH     : case-insensitive hex; length must match
      NUMERIC      : exact equality after `float(...)` parse on both sides
      TIMESTAMP    : ISO-8601 parse on both; |Δ| ≤ 2 seconds
      PATH         : posix/backslash-normalized + lowercased + trailing-slash stripped
      SID          : exact match after upcasing both
    """
    expected = expected.strip()
    candidate = candidate.strip()

    if answer_type == AnswerType.EXACT_STRING:
        return expected == candidate

    if answer_type == AnswerType.STRING_CI:
        return expected.lower() == candidate.lower()

    if answer_type == AnswerType.HEX_HASH:
        e, c = expected.lower(), candidate.lower()
        if len(e) != len(c):
            return False
        return e == c and bool(re.fullmatch(r"[0-9a-f]+", c))

    if answer_type == AnswerType.NUMERIC:
        try:
            return float(expected) == float(candidate)
        except (TypeError, ValueError):
            return False

    if answer_type == AnswerType.TIMESTAMP:
        e_ts = _parse_timestamp(expected)
        c_ts = _parse_timestamp(candidate)
        if e_ts is None or c_ts is None:
            return False
        return abs(e_ts - c_ts) <= _TIMESTAMP_TOLERANCE_SECONDS

    if answer_type == AnswerType.PATH:
        return _normalize_path(expected) == _normalize_path(candidate)

    if answer_type == AnswerType.SID:
        return expected.upper() == candidate.upper()

    # Defensive — closed enum makes this unreachable.
    return False


def any_match(answer_type: AnswerType, expected: str, candidates: list[str]) -> bool:
    """Return True iff at least one candidate matches the expected answer."""
    return any(matches(answer_type, expected, c) for c in candidates)


__all__ = [
    "AnswerType",
    "DfirMetricQuestion",
    "any_match",
    "matches",
]
