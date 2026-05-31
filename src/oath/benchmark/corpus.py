"""DFIR-Metric corpus loader.

Reads a question corpus from JSONL (one DfirMetricQuestion per line) or a
single JSON array file. Computes a stable SHA-256 over the canonical
serialization so the BenchmarkResult can prove which corpus it was run on.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from oath.benchmark.question import DfirMetricQuestion


def _canonical_json(question: DfirMetricQuestion) -> str:
    """Canonical single-line JSON for one question (stable across re-runs).

    Uses sort_keys + no whitespace + ensure_ascii=False. Mirrors the
    Notarized envelope's RFC 8785 JCS-style canonicalization without pulling
    in the full canonicalize helper from receipt/notarized.py — the
    benchmark module is intentionally independent of the receipt module.
    """
    payload = question.model_dump(mode="json")
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def hash_corpus(questions: list[DfirMetricQuestion]) -> str:
    """SHA-256 the canonical concatenation of a sorted-by-id corpus."""
    sorted_qs = sorted(questions, key=lambda q: q.question_id)
    h = hashlib.sha256()
    for q in sorted_qs:
        h.update(_canonical_json(q).encode("utf-8"))
        h.update(b"\n")
    return h.hexdigest()


def load_corpus(path: Path) -> tuple[list[DfirMetricQuestion], str]:
    """Load a corpus from a JSONL file (one question per line) or a JSON array.

    Returns (questions, corpus_sha256). The corpus is sorted by question_id
    BEFORE hashing so re-orderings of the input file don't change the hash.
    """
    text = path.read_text(encoding="utf-8").strip()
    if not text:
        return [], hash_corpus([])

    questions: list[DfirMetricQuestion] = []
    if text.startswith("["):
        # JSON array form.
        for raw in json.loads(text):
            questions.append(DfirMetricQuestion.model_validate(raw))
    else:
        # JSONL form: one question per non-empty line.
        for lineno, line in enumerate(text.splitlines(), start=1):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                raw = json.loads(stripped)
            except json.JSONDecodeError as e:
                raise ValueError(
                    f"corpus line {lineno} is not valid JSON: {e.msg}"
                ) from e
            questions.append(DfirMetricQuestion.model_validate(raw))

    return questions, hash_corpus(questions)


def filter_by_image(
    questions: list[DfirMetricQuestion], image_sha256: str
) -> list[DfirMetricQuestion]:
    """Return only questions bound to the given image SHA-256.

    The harness uses this to pick the subset of the corpus that matches the
    currently-mounted evidence; questions for other images are skipped
    rather than scored 0 (since we couldn't have answered them anyway).
    """
    return [q for q in questions if q.image_sha256.lower() == image_sha256.lower()]


def filter_by_techniques(
    questions: list[DfirMetricQuestion], techniques: list[str]
) -> list[DfirMetricQuestion]:
    """Return questions tagged with any of the given MITRE technique IDs.

    Useful for hypothesis-focused benchmarking (e.g. "score only T1550.002
    questions"). Match is exact-string on technique ID.
    """
    if not techniques:
        return list(questions)
    wanted = set(techniques)
    return [q for q in questions if any(t in wanted for t in q.mitre_techniques)]


__all__ = [
    "filter_by_image",
    "filter_by_techniques",
    "hash_corpus",
    "load_corpus",
]
