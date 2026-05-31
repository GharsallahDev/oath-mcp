"""Unit tests for the DFIR-Metric scoring harness."""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from oath.benchmark import (
    AgentResponse,
    AnswerType,
    BenchmarkHarness,
    DfirMetricQuestion,
    any_match,
    compute_tus_at_k,
    filter_by_image,
    filter_by_techniques,
    hash_corpus,
    load_corpus,
    matches,
    persist_result,
    score_attempt,
)


# --------------------------------------------------------------------------- #
# matches() per-type adjudication                                             #
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "answer_type, expected, candidate, want",
    [
        # Exact string — case-sensitive
        (AnswerType.EXACT_STRING, "Administrator", "Administrator", True),
        (AnswerType.EXACT_STRING, "Administrator", "administrator", False),
        (AnswerType.EXACT_STRING, "Administrator", " Administrator ", True),  # stripped
        # Case-insensitive string
        (AnswerType.STRING_CI, "PSEXESVC", "psexesvc", True),
        (AnswerType.STRING_CI, "PSEXESVC", "PsExesvc", True),
        (AnswerType.STRING_CI, "PSEXESVC", "psexesvc.exe", False),
        # Hex hash
        (
            AnswerType.HEX_HASH,
            "0BDA9C28C8C16E1A37CB0739EB13B5E4",  # md5, uppercase
            "0bda9c28c8c16e1a37cb0739eb13b5e4",
            True,
        ),
        (
            AnswerType.HEX_HASH,
            "0bda9c28c8c16e1a37cb0739eb13b5e4",  # md5 (32)
            "1234567890abcdef1234567890abcdef",
            False,
        ),
        # Numeric
        (AnswerType.NUMERIC, "1234", "1234", True),
        (AnswerType.NUMERIC, "1234", "1234.0", True),
        (AnswerType.NUMERIC, "1234", "1235", False),
        (AnswerType.NUMERIC, "1234", "not a number", False),
        # Timestamp — ISO-8601 with 2-second tolerance
        (
            AnswerType.TIMESTAMP,
            "2026-04-12T14:32:01+00:00",
            "2026-04-12T14:32:02+00:00",
            True,
        ),
        (
            AnswerType.TIMESTAMP,
            "2026-04-12T14:32:01+00:00",
            "2026-04-12T14:32:10+00:00",
            False,
        ),
        (
            AnswerType.TIMESTAMP,
            "2026-04-12T14:32:01Z",  # Z = +00:00
            "2026-04-12T14:32:01+00:00",
            True,
        ),
        # Path — case + slash normalization
        (
            AnswerType.PATH,
            "C:\\Windows\\System32\\cmd.exe",
            "c:/windows/system32/cmd.exe",
            True,
        ),
        (
            AnswerType.PATH,
            "C:\\Windows\\System32\\cmd.exe",
            "C:\\Windows\\\\System32\\\\cmd.exe",  # collapse backslash runs
            True,
        ),
        (
            AnswerType.PATH,
            "C:\\Windows\\System32\\cmd.exe",
            "C:\\Windows\\System32\\notepad.exe",
            False,
        ),
        # SID
        (AnswerType.SID, "S-1-5-21-1004336348-1177238915-682003330-512", "s-1-5-21-1004336348-1177238915-682003330-512", True),
        (AnswerType.SID, "S-1-5-21-XXX", "S-1-5-21-YYY", False),
    ],
)
def test_matches_per_type(answer_type, expected, candidate, want):
    assert matches(answer_type, expected, candidate) is want


def test_any_match_first_hit_wins():
    assert (
        any_match(
            AnswerType.NUMERIC, "42", ["wrong", "also wrong", "42", "42 too"]
        )
        is True
    )


def test_any_match_none_match():
    assert any_match(AnswerType.NUMERIC, "42", ["1", "2", "3"]) is False


# --------------------------------------------------------------------------- #
# Question validation                                                         #
# --------------------------------------------------------------------------- #


def test_hex_hash_validation_rejects_non_hex():
    with pytest.raises(ValueError, match="hex characters only"):
        DfirMetricQuestion(
            question_id="q1",
            image_sha256="a" * 64,
            question_text="What is the md5?",
            answer_type=AnswerType.HEX_HASH,
            expected_answer="not-a-hash",
        )


def test_hex_hash_validation_rejects_wrong_length():
    with pytest.raises(ValueError, match="length must be 32"):
        DfirMetricQuestion(
            question_id="q1",
            image_sha256="a" * 64,
            question_text="What is the md5?",
            answer_type=AnswerType.HEX_HASH,
            expected_answer="abcdef",  # 6 hex chars; not 32/40/64
        )


# --------------------------------------------------------------------------- #
# score_attempt                                                               #
# --------------------------------------------------------------------------- #


def _q(answer_type: AnswerType, expected: str, qid: str = "q1") -> DfirMetricQuestion:
    return DfirMetricQuestion(
        question_id=qid,
        image_sha256="a" * 64,
        question_text="test",
        answer_type=answer_type,
        expected_answer=expected,
    )


def test_score_attempt_records_first_matching_index():
    q = _q(AnswerType.NUMERIC, "42")
    a = score_attempt(q, ["1", "42", "wrong"], k=4)
    assert a.matched is True
    assert a.matched_candidate_index == 1
    assert a.candidates == ("1", "42", "wrong")


def test_score_attempt_truncates_to_k():
    q = _q(AnswerType.NUMERIC, "42")
    a = score_attempt(q, ["1", "2", "3", "42", "5"], k=4)
    # 42 is at index 3 in the truncated list; the 5th candidate is dropped
    assert a.candidates == ("1", "2", "3", "42")
    assert a.matched is True
    assert a.matched_candidate_index == 3


def test_score_attempt_no_match_when_correct_answer_is_beyond_k():
    q = _q(AnswerType.NUMERIC, "42")
    a = score_attempt(q, ["1", "2", "3", "4", "42"], k=4)
    assert a.matched is False
    assert a.matched_candidate_index is None


def test_score_attempt_empty_candidates_is_zero():
    q = _q(AnswerType.NUMERIC, "42")
    a = score_attempt(q, [], k=4)
    assert a.matched is False
    assert a.candidates == ()


def test_score_attempt_k_must_be_positive():
    q = _q(AnswerType.NUMERIC, "42")
    with pytest.raises(ValueError, match="k must be ≥ 1"):
        score_attempt(q, ["1"], k=0)


# --------------------------------------------------------------------------- #
# compute_tus_at_k                                                            #
# --------------------------------------------------------------------------- #


def test_compute_tus_at_k_three_of_four():
    q = _q(AnswerType.NUMERIC, "42")
    attempts = [
        score_attempt(q, ["42"], k=4),
        score_attempt(q, ["43"], k=4),
        score_attempt(q, ["41", "42"], k=4),
        score_attempt(q, ["wrong", "42"], k=4),
    ]
    assert compute_tus_at_k(attempts) == 0.75


def test_compute_tus_at_k_empty_is_zero():
    assert compute_tus_at_k([]) == 0.0


# --------------------------------------------------------------------------- #
# Corpus loading + hashing                                                    #
# --------------------------------------------------------------------------- #


def _write_jsonl(path: Path, questions: list[dict]) -> None:
    path.write_text(
        "\n".join(json.dumps(q, sort_keys=True) for q in questions),
        encoding="utf-8",
    )


def test_load_corpus_jsonl(tmp_path: Path):
    corpus_path = tmp_path / "corpus.jsonl"
    _write_jsonl(
        corpus_path,
        [
            {
                "question_id": "q1",
                "image_sha256": "a" * 64,
                "question_text": "What user?",
                "answer_type": "string_ci",
                "expected_answer": "Administrator",
            },
            {
                "question_id": "q2",
                "image_sha256": "b" * 64,
                "question_text": "How many bytes?",
                "answer_type": "numeric",
                "expected_answer": "1024",
            },
        ],
    )

    qs, sha = load_corpus(corpus_path)
    assert len(qs) == 2
    assert qs[0].question_id in {"q1", "q2"}
    assert len(sha) == 64


def test_load_corpus_json_array(tmp_path: Path):
    corpus_path = tmp_path / "corpus.json"
    corpus_path.write_text(
        json.dumps(
            [
                {
                    "question_id": "q1",
                    "image_sha256": "a" * 64,
                    "question_text": "What user?",
                    "answer_type": "string_ci",
                    "expected_answer": "Administrator",
                }
            ]
        ),
        encoding="utf-8",
    )
    qs, _ = load_corpus(corpus_path)
    assert len(qs) == 1


def test_corpus_hash_is_order_independent(tmp_path: Path):
    q_a = DfirMetricQuestion(
        question_id="a",
        image_sha256="0" * 64,
        question_text="x",
        answer_type=AnswerType.NUMERIC,
        expected_answer="1",
    )
    q_b = DfirMetricQuestion(
        question_id="b",
        image_sha256="0" * 64,
        question_text="x",
        answer_type=AnswerType.NUMERIC,
        expected_answer="2",
    )
    assert hash_corpus([q_a, q_b]) == hash_corpus([q_b, q_a])


def test_filter_by_image_case_insensitive():
    q1 = DfirMetricQuestion(
        question_id="q1", image_sha256="A" * 64, question_text="x",
        answer_type=AnswerType.NUMERIC, expected_answer="1",
    )
    q2 = DfirMetricQuestion(
        question_id="q2", image_sha256="B" * 64, question_text="x",
        answer_type=AnswerType.NUMERIC, expected_answer="2",
    )
    out = filter_by_image([q1, q2], "a" * 64)
    assert [q.question_id for q in out] == ["q1"]


def test_filter_by_techniques_any_match():
    q1 = DfirMetricQuestion(
        question_id="q1", image_sha256="0" * 64, question_text="x",
        answer_type=AnswerType.NUMERIC, expected_answer="1",
        mitre_techniques=("T1550.002", "T1003.001"),
    )
    q2 = DfirMetricQuestion(
        question_id="q2", image_sha256="0" * 64, question_text="x",
        answer_type=AnswerType.NUMERIC, expected_answer="2",
        mitre_techniques=("T1078",),
    )
    out = filter_by_techniques([q1, q2], ["T1550.002"])
    assert [q.question_id for q in out] == ["q1"]


def test_filter_by_techniques_empty_returns_all():
    q1 = DfirMetricQuestion(
        question_id="q1", image_sha256="0" * 64, question_text="x",
        answer_type=AnswerType.NUMERIC, expected_answer="1",
    )
    assert filter_by_techniques([q1], []) == [q1]


# --------------------------------------------------------------------------- #
# Harness end-to-end                                                          #
# --------------------------------------------------------------------------- #


def _make_agent(answers_by_qid: dict[str, list[str]]):
    """Build a deterministic fake agent_fn for the harness."""

    def agent(q: DfirMetricQuestion, k: int) -> AgentResponse:
        return AgentResponse(
            candidates=answers_by_qid.get(q.question_id, []),
            wall_clock_seconds=0.01,
            verified_envelope_count=3,
            quarantined_count=0,
            ralph_wiggum_events=0,
        )

    return agent


def test_harness_runs_all_questions_and_reports_tus():
    q1 = _q(AnswerType.NUMERIC, "42", qid="q1")
    q2 = _q(AnswerType.STRING_CI, "Administrator", qid="q2")
    q3 = _q(AnswerType.NUMERIC, "1024", qid="q3")
    q4 = _q(AnswerType.HEX_HASH, "a" * 64, qid="q4")  # nothing answers

    agent = _make_agent(
        {
            "q1": ["wrong", "42"],
            "q2": ["administrator"],
            "q3": ["1024"],
            # q4 unanswered → 0
        }
    )

    harness = BenchmarkHarness(agent_fn=agent, k=4, run_id="run-1")
    result = harness.run([q1, q2, q3, q4], corpus_sha256="c" * 64)

    assert result.run_id == "run-1"
    assert result.total_questions == 4
    assert result.matched_count == 3
    assert result.tus_at_k == 0.75
    assert result.module == "III"
    assert result.k == 4


def test_harness_progress_callback_fires_per_question():
    q1 = _q(AnswerType.NUMERIC, "42", qid="q1")
    q2 = _q(AnswerType.NUMERIC, "43", qid="q2")
    agent = _make_agent({"q1": ["42"], "q2": ["43"]})

    seen: list[str] = []

    def progress(i: int, n: int, q: DfirMetricQuestion) -> None:
        seen.append(f"{i+1}/{n}:{q.question_id}")

    harness = BenchmarkHarness(agent_fn=agent, k=4, progress_callback=progress)
    harness.run([q1, q2], corpus_sha256="c" * 64)
    assert seen == ["1/2:q1", "2/2:q2"]


def test_harness_propagates_agent_telemetry():
    q = _q(AnswerType.NUMERIC, "42")
    agent = _make_agent({"q1": ["42"]})
    harness = BenchmarkHarness(agent_fn=agent, k=4)
    result = harness.run([q], corpus_sha256="c" * 64)
    attempt = result.attempts[0]
    assert attempt.wall_clock_seconds == 0.01
    assert attempt.verified_envelope_count == 3


# --------------------------------------------------------------------------- #
# Persistence                                                                 #
# --------------------------------------------------------------------------- #


def test_persist_result_writes_canonical_json(tmp_path: Path):
    q = _q(AnswerType.NUMERIC, "42")
    agent = _make_agent({"q1": ["42"]})
    harness = BenchmarkHarness(agent_fn=agent, k=4, run_id="run-x")
    result = harness.run([q], corpus_sha256="c" * 64)

    path = persist_result(result, tmp_path)
    assert path.exists()
    assert path.name == "run-x_III_tus4.json"

    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["tus_at_k"] == 1.0
    assert payload["k"] == 4
    assert payload["corpus_sha256"] == "c" * 64


def test_persist_result_overwrites_previous(tmp_path: Path):
    q = _q(AnswerType.NUMERIC, "42")
    agent_correct = _make_agent({"q1": ["42"]})
    agent_wrong = _make_agent({"q1": ["43"]})
    h1 = BenchmarkHarness(agent_fn=agent_correct, k=4, run_id="run-overwrite")
    h2 = BenchmarkHarness(agent_fn=agent_wrong, k=4, run_id="run-overwrite")
    persist_result(h1.run([q], corpus_sha256="c" * 64), tmp_path)
    path = persist_result(h2.run([q], corpus_sha256="c" * 64), tmp_path)

    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["tus_at_k"] == 0.0  # last write wins
