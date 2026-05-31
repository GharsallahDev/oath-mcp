"""Tests for the NSS (list-of-strings) answer type + DFIR-Metric NSS loader."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from oath.benchmark import (
    AnswerType,
    BenchmarkHarness,
    DfirMetricQuestion,
    any_match,
    list_match_stats,
    load_nss_corpus,
    matches,
    score_attempt,
)
from oath.benchmark.harness import AgentResponse


# --------------------------------------------------------------------------- #
# Helpers                                                                     #
# --------------------------------------------------------------------------- #


def _jlist(*items: str) -> str:
    """Canonical JSON-array form used by the wire protocol."""
    return json.dumps(sorted(items), sort_keys=True, separators=(",", ":"), ensure_ascii=False)


# --------------------------------------------------------------------------- #
# matches() — set equality for LIST_OF_STRINGS / NSS_INODE_FILENAME_LIST      #
# --------------------------------------------------------------------------- #


def test_nss_exact_set_match():
    expected = _jlist("122150:foo.txt", "122151:bar.txt")
    candidate = _jlist("122151:bar.txt", "122150:foo.txt")  # different order
    assert matches(AnswerType.NSS_INODE_FILENAME_LIST, expected, candidate) is True


def test_nss_missing_element_fails():
    expected = _jlist("a", "b", "c")
    candidate = _jlist("a", "b")
    assert matches(AnswerType.NSS_INODE_FILENAME_LIST, expected, candidate) is False


def test_nss_extra_element_fails():
    expected = _jlist("a", "b")
    candidate = _jlist("a", "b", "spurious")
    assert matches(AnswerType.NSS_INODE_FILENAME_LIST, expected, candidate) is False


def test_nss_both_empty_match():
    """Set-equality means {} == {}: a question with no hits is solvable by emitting []."""
    assert matches(AnswerType.NSS_INODE_FILENAME_LIST, "[]", "[]") is True


def test_nss_malformed_candidate_returns_false():
    expected = _jlist("a", "b")
    assert (
        matches(AnswerType.NSS_INODE_FILENAME_LIST, expected, "not a JSON array")
        is False
    )


def test_list_of_strings_distinct_from_nss():
    """LIST_OF_STRINGS uses the same matching rule but is a separate tag."""
    expected = _jlist("alpha", "beta")
    candidate = _jlist("beta", "alpha")
    assert matches(AnswerType.LIST_OF_STRINGS, expected, candidate) is True


def test_any_match_first_correct_list_wins():
    expected = _jlist("a", "b")
    candidates = [_jlist("a"), _jlist("a", "b", "c"), _jlist("a", "b")]
    assert any_match(AnswerType.LIST_OF_STRINGS, expected, candidates) is True


# --------------------------------------------------------------------------- #
# list_match_stats — precision/recall/F1 telemetry                             #
# --------------------------------------------------------------------------- #


def test_list_stats_perfect_recall_lower_precision():
    expected = _jlist("a", "b")
    candidate = _jlist("a", "b", "c")
    stats = list_match_stats(expected, candidate)
    assert stats is not None
    assert stats["recall"] == 1.0
    assert stats["precision"] == pytest.approx(2 / 3)
    assert stats["exact"] == 0.0


def test_list_stats_perfect_precision_lower_recall():
    expected = _jlist("a", "b", "c")
    candidate = _jlist("a")
    stats = list_match_stats(expected, candidate)
    assert stats is not None
    assert stats["precision"] == 1.0
    assert stats["recall"] == pytest.approx(1 / 3)


def test_list_stats_exact_match():
    expected = _jlist("a", "b")
    candidate = _jlist("a", "b")
    stats = list_match_stats(expected, candidate)
    assert stats == {"precision": 1.0, "recall": 1.0, "f1": 1.0, "exact": 1.0}


def test_list_stats_both_empty():
    stats = list_match_stats("[]", "[]")
    assert stats == {"precision": 1.0, "recall": 1.0, "f1": 1.0, "exact": 1.0}


def test_list_stats_malformed_returns_none():
    assert list_match_stats(_jlist("a"), "not json") is None
    assert list_match_stats("not json", _jlist("a")) is None


# --------------------------------------------------------------------------- #
# Question model validation                                                   #
# --------------------------------------------------------------------------- #


def test_nss_question_rejects_non_array_payload():
    with pytest.raises(ValueError, match="must be a JSON array"):
        DfirMetricQuestion(
            question_id="q1",
            image_sha256=None,
            question_text="find strings",
            answer_type=AnswerType.NSS_INODE_FILENAME_LIST,
            expected_answer="not-an-array",
        )


def test_nss_question_rejects_array_of_non_strings():
    with pytest.raises(ValueError, match="must be a list of strings"):
        DfirMetricQuestion(
            question_id="q1",
            image_sha256=None,
            question_text="find strings",
            answer_type=AnswerType.NSS_INODE_FILENAME_LIST,
            expected_answer='[1, 2, 3]',
        )


def test_image_sha256_optional():
    q = DfirMetricQuestion(
        question_id="q1",
        image_sha256=None,
        question_text="x",
        answer_type=AnswerType.NSS_INODE_FILENAME_LIST,
        expected_answer="[]",
    )
    assert q.image_sha256 is None


def test_image_sha256_must_be_hex_64_when_set():
    with pytest.raises(ValueError, match="64-char hex"):
        DfirMetricQuestion(
            question_id="q1",
            image_sha256="not-hex",
            question_text="x",
            answer_type=AnswerType.STRING_CI,
            expected_answer="Administrator",
        )


# --------------------------------------------------------------------------- #
# score_attempt with LIST answers                                             #
# --------------------------------------------------------------------------- #


def test_score_attempt_nss_picks_best_list():
    q = DfirMetricQuestion(
        question_id="nss-0001",
        image_sha256=None,
        question_text="find all .txt with banking strings",
        answer_type=AnswerType.NSS_INODE_FILENAME_LIST,
        expected_answer=_jlist("122150:fee.txt", "122151:fi.txt", "122152:fo.txt"),
    )
    # Candidate 0 = subset (wrong). Candidate 1 = exact match.
    candidates = [
        _jlist("122150:fee.txt"),
        _jlist("122152:fo.txt", "122151:fi.txt", "122150:fee.txt"),  # different order ok
    ]
    a = score_attempt(q, candidates, k=4)
    assert a.matched is True
    assert a.matched_candidate_index == 1


# --------------------------------------------------------------------------- #
# load_nss_corpus — DFIR-Metric paper format                                  #
# --------------------------------------------------------------------------- #


def test_load_nss_corpus_maps_paper_format_to_typed_questions(tmp_path: Path):
    payload = {
        "questions": [
            {
                "question": "Find all files containing 'banking'",
                "answer": ["122150:fee.txt", "122151:fi.txt"],
            },
            {
                "question": "Find all DELETED files containing 'iron'",
                "answer": ["122160:DELETED-foo.txt"],
            },
        ]
    }
    p = tmp_path / "DFIR-Metric-NSS.json"
    p.write_text(json.dumps(payload), encoding="utf-8")

    questions, sha = load_nss_corpus(p)
    assert len(questions) == 2
    assert sha and len(sha) == 64

    q0 = questions[0]
    assert q0.question_id == "nss-0000"
    assert q0.answer_type == AnswerType.NSS_INODE_FILENAME_LIST
    assert q0.image_sha256 is None
    assert q0.case_label == "DFIR-Metric-NSS"
    # Payload is canonical JSON of sorted items
    assert q0.expected_answer == _jlist("122150:fee.txt", "122151:fi.txt")


def test_load_nss_corpus_optional_image_binding(tmp_path: Path):
    payload = {"questions": [{"question": "x", "answer": ["a"]}]}
    p = tmp_path / "nss.json"
    p.write_text(json.dumps(payload), encoding="utf-8")

    sha = "a" * 64
    questions, _ = load_nss_corpus(p, image_sha256=sha)
    assert questions[0].image_sha256 == sha


def test_load_nss_corpus_rejects_wrong_shape(tmp_path: Path):
    p = tmp_path / "wrong.json"
    p.write_text(json.dumps([{"question": "x", "answer": []}]), encoding="utf-8")
    with pytest.raises(ValueError, match="expected top-level shape"):
        load_nss_corpus(p)


def test_load_nss_corpus_rejects_non_string_answer(tmp_path: Path):
    p = tmp_path / "wrong.json"
    p.write_text(
        json.dumps({"questions": [{"question": "x", "answer": [1, 2, 3]}]}),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="must contain only strings"):
        load_nss_corpus(p)


def test_load_nss_corpus_accepts_scalar_answer(tmp_path: Path):
    """The real DFIR-Metric-NSS file mixes list answers and scalar counts."""
    payload = {
        "questions": [
            {"question": "Find files containing iron", "answer": ["1:a.txt"]},
            {"question": "How many deleted files contain iron?", "answer": "390"},
            {"question": "What is the SID of the user?", "answer": "S-1-5-21-XXX"},
        ]
    }
    p = tmp_path / "mixed.json"
    p.write_text(json.dumps(payload), encoding="utf-8")
    questions, _ = load_nss_corpus(p)
    assert questions[0].answer_type == AnswerType.NSS_INODE_FILENAME_LIST
    assert questions[1].answer_type == AnswerType.NUMERIC
    assert questions[1].expected_answer == "390"
    # SID-looking strings get STRING_CI (the SID heuristic is left to the
    # corpus author to retag if desired).
    assert questions[2].answer_type == AnswerType.STRING_CI


def test_nss_corpus_hash_is_order_independent(tmp_path: Path):
    payload_a = {
        "questions": [
            {"question": "q1", "answer": ["a"]},
            {"question": "q2", "answer": ["b"]},
        ]
    }
    payload_b = {
        "questions": [
            {"question": "q2", "answer": ["b"]},
            {"question": "q1", "answer": ["a"]},
        ]
    }
    pa = tmp_path / "a.json"
    pb = tmp_path / "b.json"
    pa.write_text(json.dumps(payload_a), encoding="utf-8")
    pb.write_text(json.dumps(payload_b), encoding="utf-8")

    # The two NSS files have different question_id assignments (positional);
    # the corpus hash differs by question_id but the underlying questions
    # are equivalent. Verify the SET of (text, answer) pairs match.
    qs_a, _ = load_nss_corpus(pa)
    qs_b, _ = load_nss_corpus(pb)
    set_a = {(q.question_text, q.expected_answer) for q in qs_a}
    set_b = {(q.question_text, q.expected_answer) for q in qs_b}
    assert set_a == set_b


# --------------------------------------------------------------------------- #
# End-to-end via harness                                                      #
# --------------------------------------------------------------------------- #


def test_nss_harness_round_trip(tmp_path: Path):
    payload = {
        "questions": [
            {"question": "Find iron files", "answer": ["1:a.txt", "2:b.txt"]},
            {"question": "Find tin files", "answer": ["3:c.txt"]},
        ]
    }
    p = tmp_path / "nss.json"
    p.write_text(json.dumps(payload), encoding="utf-8")
    questions, sha = load_nss_corpus(p)

    answers = {
        # First question: correct answer in second candidate slot
        "nss-0000": [
            _jlist("1:a.txt"),  # subset (wrong)
            _jlist("2:b.txt", "1:a.txt"),  # exact (set equal)
        ],
        # Second question: wrong list (extra element)
        "nss-0001": [_jlist("3:c.txt", "spurious")],
    }

    def agent(q: DfirMetricQuestion, k: int) -> AgentResponse:
        return AgentResponse(candidates=answers[q.question_id])

    harness = BenchmarkHarness(agent_fn=agent, k=4, run_id="nss-run")
    result = harness.run(questions, corpus_sha256=sha)
    assert result.total_questions == 2
    assert result.matched_count == 1
    assert result.tus_at_k == 0.5
