"""Unit tests for the live Claude-driven agent_fn (with a fake interactor)."""
from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from oath.benchmark import AnswerType, BenchmarkHarness, DfirMetricQuestion
from oath.benchmark.claude_agent import (
    SYSTEM_PROMPT,
    ClaudeAgentConfig,
    build_claude_agent_fn,
    build_user_message,
    parse_candidates,
)


# --------------------------------------------------------------------------- #
# parse_candidates                                                            #
# --------------------------------------------------------------------------- #


def test_parse_candidates_fenced_json():
    text = (
        'Some reasoning text.\n'
        '```json\n{"candidates": ["a", "b", "c"]}\n```\n'
    )
    assert parse_candidates(text, k=4) == ["a", "b", "c"]


def test_parse_candidates_fenced_no_lang():
    text = '```\n{"candidates": ["x"]}\n```'
    assert parse_candidates(text, k=4) == ["x"]


def test_parse_candidates_truncates_to_k():
    text = '```json\n{"candidates": ["a","b","c","d","e","f"]}\n```'
    assert parse_candidates(text, k=3) == ["a", "b", "c"]


def test_parse_candidates_last_fenced_block_wins():
    """When the agent drafts and refines, only the LAST candidate set counts."""
    text = (
        '```json\n{"candidates": ["draft-1", "draft-2"]}\n```\n'
        'After more reasoning:\n'
        '```json\n{"candidates": ["final-1", "final-2"]}\n```\n'
    )
    assert parse_candidates(text, k=4) == ["final-1", "final-2"]


def test_parse_candidates_bare_json_fallback():
    text = 'No fence: {"candidates": ["unfenced"]}.'
    assert parse_candidates(text, k=4) == ["unfenced"]


def test_parse_candidates_returns_empty_on_malformed_json():
    text = '```json\n{"candidates": [missing-quotes]}\n```'
    assert parse_candidates(text, k=4) == []


def test_parse_candidates_returns_empty_on_no_json():
    text = "I have no idea."
    assert parse_candidates(text, k=4) == []


def test_parse_candidates_stringifies_non_strings():
    text = '```json\n{"candidates": [42, "Administrator", 1024]}\n```'
    # Non-string entries become their str() form so the scorer still works
    assert parse_candidates(text, k=4) == ["42", "Administrator", "1024"]


# --------------------------------------------------------------------------- #
# Prompt construction                                                         #
# --------------------------------------------------------------------------- #


def _q(answer_type: AnswerType, expected: str, qid: str = "q1", **kw) -> DfirMetricQuestion:
    return DfirMetricQuestion(
        question_id=qid,
        image_sha256="a" * 64,
        question_text="What user ran cmd.exe?",
        answer_type=answer_type,
        expected_answer=expected,
        **kw,
    )


def test_build_user_message_includes_all_required_fields():
    q = _q(AnswerType.STRING_CI, "Administrator", mitre_techniques=("T1550.002",))
    msg = build_user_message(q, k=4)
    assert q.question_id in msg
    assert q.image_sha256 in msg
    assert "string_ci" in msg
    assert "T1550.002" in msg
    assert "What user ran cmd.exe?" in msg
    assert "K             : 4" in msg


def test_build_user_message_handles_empty_mitre():
    q = _q(AnswerType.NUMERIC, "42")
    msg = build_user_message(q, k=4)
    assert "mitre         : -" in msg


def test_system_prompt_documents_verifier_contract():
    assert "Witness Oath Verifier" in SYSTEM_PROMPT
    assert "QUARANTINED" in SYSTEM_PROMPT
    assert "candidates" in SYSTEM_PROMPT


# --------------------------------------------------------------------------- #
# End-to-end via fake interactor                                              #
# --------------------------------------------------------------------------- #


def _make_fake_interactor(answer_text: str, captured: list[tuple[Any, ...]] | None = None):
    """Build an interactor that returns canned text and optionally records calls."""

    def fake(config, system_prompt, user_message):
        if captured is not None:
            captured.append((config, system_prompt, user_message))
        return answer_text, {"model": config.model, "stop_reason": "end_turn"}

    return fake


def test_agent_fn_parses_candidates_and_returns_telemetry():
    q = _q(AnswerType.NUMERIC, "42")
    fake_text = (
        'Reasoning...\n```json\n{"candidates": ["42", "wrong"]}\n```\n'
    )
    captured: list = []
    agent_fn = build_claude_agent_fn(
        ClaudeAgentConfig(api_key="fake-key"),
        interactor=_make_fake_interactor(fake_text, captured),
    )
    response = agent_fn(q, 4)
    assert response.candidates == ["42", "wrong"]
    assert response.wall_clock_seconds is not None
    assert response.wall_clock_seconds >= 0
    # The interactor was passed the system + user prompts
    assert len(captured) == 1
    _, sys_prompt, user_msg = captured[0]
    assert sys_prompt == SYSTEM_PROMPT
    assert q.question_id in user_msg


def test_agent_fn_returns_empty_candidates_on_malformed_response():
    q = _q(AnswerType.NUMERIC, "42")
    agent_fn = build_claude_agent_fn(
        ClaudeAgentConfig(api_key="fake-key"),
        interactor=_make_fake_interactor("no JSON here"),
    )
    response = agent_fn(q, 4)
    assert response.candidates == []
    # Empty candidates → harness scores it 0; no exception


def test_agent_fn_can_drive_harness_end_to_end():
    """The live agent_fn drops cleanly into BenchmarkHarness."""
    q1 = _q(AnswerType.NUMERIC, "42", qid="q1")
    q2 = _q(AnswerType.STRING_CI, "Administrator", qid="q2")

    answers = {
        "q1": '```json\n{"candidates": ["42"]}\n```',
        "q2": '```json\n{"candidates": ["administrator"]}\n```',
    }

    def fake(config, system_prompt, user_message):
        qid = user_message.split("question_id   : ", 1)[1].split("\n", 1)[0].strip()
        return answers[qid], {"model": config.model, "stop_reason": "end_turn"}

    agent_fn = build_claude_agent_fn(
        ClaudeAgentConfig(api_key="fake-key"), interactor=fake
    )
    harness = BenchmarkHarness(agent_fn=agent_fn, k=4, run_id="claude-test")
    result = harness.run([q1, q2], corpus_sha256="c" * 64)

    assert result.total_questions == 2
    assert result.matched_count == 2
    assert result.tus_at_k == 1.0


def test_envelope_telemetry_captured_when_dirs_provided(tmp_path: Path):
    envelopes_dir = tmp_path / "envelopes"
    envelopes_dir.mkdir()
    journal = tmp_path / "claims.jsonl"
    journal.touch()

    q = _q(AnswerType.NUMERIC, "42")
    fake_text = '```json\n{"candidates": ["42"]}\n```'

    def fake(config, system_prompt, user_message):
        # Simulate the agent making 3 MCP envelope writes + 1 claim entry
        (envelopes_dir / "env-1.json").write_text("{}")
        (envelopes_dir / "env-2.json").write_text("{}")
        (envelopes_dir / "env-3.json").write_text("{}")
        journal.write_text("claim line 1\n")
        return fake_text, {"model": config.model, "stop_reason": "end_turn"}

    agent_fn = build_claude_agent_fn(
        ClaudeAgentConfig(api_key="fake-key"),
        interactor=fake,
        envelopes_dir=envelopes_dir,
        claims_journal=journal,
    )
    response = agent_fn(q, 4)
    assert response.verified_envelope_count == 3
    assert response.ralph_wiggum_events == 1
