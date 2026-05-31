"""DFIR-Metric question model + per-type answer matching.

Supports two adjudication families:

  Single-answer (string, hex hash, numeric, timestamp, path, SID):
    The agent emits up to K candidate strings; TUS@K = 1 if any candidate
    matches the expected_answer under the type-specific match rule.

  List-of-strings (LIST_OF_STRINGS / NSS_INODE_FILENAME_LIST):
    DFIR-Metric Module III ships as NIST String Search (NSS) — the agent
    finds all files on a disk image matching a search pattern and returns
    the FULL inode:filename list. TUS@K = 1 if any of the K candidate LISTS
    matches the expected list as a SET (order-independent).

This module is the deterministic adjudication layer. No fuzzy LLM-judging,
no synonym tables, no "looks right." Match or fail.

NSS answer encoding contract
----------------------------
For LIST_OF_STRINGS / NSS_INODE_FILENAME_LIST, the corpus author serializes
the expected_list into `expected_answer` as a canonical JSON array string
(json.dumps with sort_keys, no whitespace). The agent's candidates are
JSON arrays in the same form. We compare as Python sets. This keeps the
single `expected_answer: str` field and the on-the-wire payload uniform.
"""
from __future__ import annotations

import json
import re
from enum import Enum

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
    # List-of-strings answers. Each item compared as exact-string. The full
    # list is compared as a Python set (order-independent set equality).
    LIST_OF_STRINGS = "list_of_strings"
    # NIST String Search items: "<inode>:<filename>". Same set-equality rule
    # as LIST_OF_STRINGS but the type tag preserves intent for downstream
    # analytics (e.g. precision/recall against the NSS subset only).
    NSS_INODE_FILENAME_LIST = "nss_inode_filename_list"


# Closed set of types whose `expected_answer` is a canonical JSON-array string.
LIST_ANSWER_TYPES = frozenset(
    {AnswerType.LIST_OF_STRINGS, AnswerType.NSS_INODE_FILENAME_LIST}
)


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
    # Optional: NSS questions reference NIST CFTT images by name, not hash.
    # When the corpus author can bind a specific image, do so here; the
    # harness will refuse to score questions whose image_sha256 doesn't
    # match the mounted handle.
    image_sha256: str | None = Field(
        default=None,
        description="64-char hex SHA-256 of the source image, or None if unbound.",
    )
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
    def _validate_payload(self) -> "DfirMetricQuestion":
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
        elif self.answer_type in LIST_ANSWER_TYPES:
            # The expected_answer must parse as a JSON array of strings.
            try:
                payload = json.loads(self.expected_answer)
            except json.JSONDecodeError as e:
                raise ValueError(
                    f"{self.answer_type.value} expected_answer must be a JSON array; "
                    f"got {self.expected_answer[:80]!r} ({e.msg})"
                ) from e
            if not isinstance(payload, list) or not all(
                isinstance(x, str) for x in payload
            ):
                raise ValueError(
                    f"{self.answer_type.value} expected_answer JSON must be a list of strings."
                )
        if self.image_sha256 is not None:
            sha = self.image_sha256.strip().lower()
            if not re.fullmatch(r"[0-9a-f]{64}", sha):
                raise ValueError(
                    "image_sha256 must be a 64-char hex string when provided."
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


def _parse_list_payload(payload: str) -> set[str] | None:
    """Parse a JSON-array-of-strings payload into a Python set. None on failure."""
    payload = payload.strip()
    if not payload:
        return None
    try:
        obj = json.loads(payload)
    except json.JSONDecodeError:
        return None
    if not isinstance(obj, list) or not all(isinstance(x, str) for x in obj):
        return None
    return {x.strip() for x in obj}


def list_match_stats(expected: str, candidate: str) -> dict[str, float] | None:
    """For LIST answer types, return {precision, recall, f1, exact} stats.

    Returns None if either side fails to parse as JSON array of strings.
    Used for downstream telemetry — the scorer's binary `matches` decision
    uses set equality (exact = 1.0).
    """
    e = _parse_list_payload(expected)
    c = _parse_list_payload(candidate)
    if e is None or c is None:
        return None
    if not e and not c:
        return {"precision": 1.0, "recall": 1.0, "f1": 1.0, "exact": 1.0}
    tp = len(e & c)
    precision = tp / len(c) if c else 0.0
    recall = tp / len(e) if e else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    return {
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "exact": 1.0 if e == c else 0.0,
    }


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
      LIST_OF_STRINGS / NSS_INODE_FILENAME_LIST :
        Both sides parsed as JSON arrays of strings; set-equality after
        per-element strip.
    """
    if answer_type in LIST_ANSWER_TYPES:
        e = _parse_list_payload(expected)
        c = _parse_list_payload(candidate)
        if e is None or c is None:
            return False
        return e == c

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
    "LIST_ANSWER_TYPES",
    "AnswerType",
    "DfirMetricQuestion",
    "any_match",
    "list_match_stats",
    "matches",
]
