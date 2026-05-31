"""DFIR-Metric corpus loader.

Two on-disk formats are supported:

  OATH-native (JSONL):
    One DfirMetricQuestion dict per line. Image-bound, fully-typed.

  DFIR-Metric paper (`DFIR-Metric-NSS.json`):
    Top-level shape `{"questions": [{"question": "...", "answer": [...]}, ...]}`.
    Mapped to typed DfirMetricQuestion records via `load_nss_corpus` with
    answer_type = NSS_INODE_FILENAME_LIST and the expected_answer as a
    canonical JSON array. Image binding is left None (the paper references
    NIST CFTT images by name in the question prose).

Both loaders compute a stable corpus SHA-256 over the canonical
serialization of the sorted-by-id question list so the BenchmarkResult
provably identifies the corpus it ran against.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from oath.benchmark.question import AnswerType, DfirMetricQuestion


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
    """Load a corpus from any supported shape — auto-detected from the file.

    Supported shapes:
      - JSONL: one OATH-native DfirMetricQuestion dict per line
      - JSON array: a list of OATH-native dicts
      - DFIR-Metric paper format: top-level `{"questions": [...]}` — routed
        to `load_nss_corpus` (handles both list-answer and scalar-answer
        entries in the mixed NSS file).

    Returns (questions, corpus_sha256). Question IDs are sorted before
    hashing so file ordering doesn't change the hash.
    """
    text = path.read_text(encoding="utf-8").strip()
    if not text:
        return [], hash_corpus([])

    # Try to parse the whole file as a single JSON document first. If it
    # succeeds AND looks like the DFIR-Metric NSS shape, route there. If
    # it succeeds as a list, treat as a JSON array of OATH-native dicts.
    # If parsing fails, fall back to JSONL (one OATH-native dict per line).
    try:
        whole = json.loads(text)
    except json.JSONDecodeError:
        whole = None

    questions: list[DfirMetricQuestion] = []
    if isinstance(whole, dict) and isinstance(whole.get("questions"), list):
        return load_nss_corpus(path)
    if isinstance(whole, list):
        for raw in whole:
            questions.append(DfirMetricQuestion.model_validate(raw))
        return questions, hash_corpus(questions)

    # JSONL fallback.
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
    currently-mounted evidence. Questions with `image_sha256 is None`
    (image-unbound, like the NSS subset) are skipped — the filter is for
    use cases where we have a specific mounted image and want only the
    questions that target it.
    """
    target = image_sha256.lower()
    return [
        q for q in questions
        if q.image_sha256 is not None and q.image_sha256.lower() == target
    ]


# --------------------------------------------------------------------------- #
# DFIR-Metric paper format (`DFIR-Metric-NSS.json`)                           #
# --------------------------------------------------------------------------- #


_NUMERIC_RE = "^-?\\d+(?:\\.\\d+)?$"


def _infer_scalar_answer_type(answer: str) -> AnswerType:
    """Pick an AnswerType for a bare-string answer in the DFIR-Metric corpus.

    The NSS file mixes two shapes: string-search list answers (which become
    NSS_INODE_FILENAME_LIST) and scalar-answer questions tail-spliced in
    (counts, identifiers, paths). For scalar answers we pick:
      - NUMERIC if the answer parses as int/float
      - STRING_CI otherwise (case-insensitive exact match)
    """
    import re

    s = answer.strip()
    if re.fullmatch(_NUMERIC_RE, s):
        return AnswerType.NUMERIC
    return AnswerType.STRING_CI


def load_nss_corpus(
    path: Path,
    *,
    question_id_prefix: str = "nss",
    image_sha256: str | None = None,
) -> tuple[list[DfirMetricQuestion], str]:
    """Load the DFIR-Metric Module III NSS file.

    The file mixes two answer shapes — the loader handles both:
      list-of-strings  → NSS_INODE_FILENAME_LIST (canonical JSON array)
      scalar string    → NUMERIC (if it parses as a number) else STRING_CI

    Top-level shape:
      { "questions": [ { "question": "...", "answer": <list-or-string> }, ... ] }

    Each entry becomes a DfirMetricQuestion with:
      - question_id: f"{question_id_prefix}-{ordinal:04d}"
      - answer_type: per the rule above
      - expected_answer: canonical-JSON for list answers, stripped string otherwise

    If `image_sha256` is provided, every question is bound to it; otherwise
    image_sha256 stays None.
    """
    raw = json.loads(path.read_text(encoding="utf-8"))
    entries = raw.get("questions") if isinstance(raw, dict) else None
    if not isinstance(entries, list):
        raise ValueError(
            f"{path}: expected top-level shape {{'questions': [...]}}; got {type(raw).__name__}"
        )

    questions: list[DfirMetricQuestion] = []
    for i, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise ValueError(f"{path}: entry {i} is not a JSON object.")
        text = entry.get("question")
        answer = entry.get("answer")
        if not isinstance(text, str) or not text.strip():
            raise ValueError(f"{path}: entry {i} has no 'question' string.")

        if isinstance(answer, list):
            if not all(isinstance(x, str) for x in answer):
                raise ValueError(
                    f"{path}: entry {i} list 'answer' must contain only strings."
                )
            payload = json.dumps(
                sorted(answer), sort_keys=True, separators=(",", ":"), ensure_ascii=False
            )
            answer_type = AnswerType.NSS_INODE_FILENAME_LIST
        elif isinstance(answer, (str, int, float)):
            scalar = str(answer).strip()
            if not scalar:
                raise ValueError(f"{path}: entry {i} has empty scalar 'answer'.")
            payload = scalar
            answer_type = _infer_scalar_answer_type(scalar)
        else:
            raise ValueError(
                f"{path}: entry {i} 'answer' must be a list or scalar; got {type(answer).__name__}."
            )

        questions.append(
            DfirMetricQuestion(
                question_id=f"{question_id_prefix}-{i:04d}",
                image_sha256=image_sha256,
                question_text=text,
                answer_type=answer_type,
                expected_answer=payload,
                module="III",
                case_label="DFIR-Metric-NSS",
            )
        )

    return questions, hash_corpus(questions)


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
    "load_nss_corpus",
]
