"""Tests for the Claude NSS args-proposal agent."""
from __future__ import annotations

import pytest

from oath.benchmark import AgentResponse, AnswerType, DfirMetricQuestion
from oath.benchmark.claude_nss_agent import (
    SYSTEM_PROMPT,
    ClaudeNSSConfig,
    LLMArgs,
    build_claude_nss_agent_fn,
    build_user_message,
    parse_llm_args,
)


# --------------------------------------------------------------------------- #
# parse_llm_args                                                              #
# --------------------------------------------------------------------------- #


def test_parse_fenced_list_response():
    text = (
        'Here we go:\n'
        '```json\n'
        '{"image": "ss-win-07-25-18.dd", "answer_type": "list", '
        '"partition": "first windows data", "pattern": "potus@capitol.gov", '
        '"extensions": null, "include_deleted": true, "include_live": true, '
        '"rationale": "test"}\n'
        '```\n'
    )
    args = parse_llm_args(text)
    assert args is not None
    assert args.image == "ss-win-07-25-18.dd"
    assert args.answer_type == "list"
    assert args.partition == "first windows data"
    assert args.pattern == "potus@capitol.gov"
    assert args.extensions == []
    assert args.include_deleted is True


def test_parse_count_response():
    text = (
        '```json\n'
        '{"image": "ss-win-07-25-18.dd", "answer_type": "count", '
        '"partition": "first windows data", "pattern": null, '
        '"extensions": [".txt", ".doc"], "include_deleted": true, '
        '"include_live": true, "rationale": "count both"}\n'
        '```\n'
    )
    args = parse_llm_args(text)
    assert args is not None
    assert args.answer_type == "count"
    assert args.pattern is None
    assert args.extensions == ["txt", "doc"]  # leading dots stripped


def test_parse_bare_object_fallback():
    text = (
        'Here is the spec: {"image": "ss-win-07-25-18.dd", '
        '"answer_type": "list", "partition": "first windows data", '
        '"pattern": "x@y.com", "extensions": null, "include_deleted": true, '
        '"include_live": true, "rationale": "r"}.'
    )
    args = parse_llm_args(text)
    assert args is not None
    assert args.pattern == "x@y.com"


def test_parse_invalid_returns_none():
    assert parse_llm_args("no json here") is None
    assert parse_llm_args("```json\n{not a real object}\n```") is None


def test_parse_extensions_normalized():
    text = '```json\n{"image":"a","answer_type":"count","partition":"first windows data","pattern":null,"extensions":[".TXT", ".doc", "html"],"include_deleted":true,"include_live":true,"rationale":""}\n```'
    args = parse_llm_args(text)
    assert args is not None
    assert sorted(args.extensions) == ["doc", "html", "txt"]


# --------------------------------------------------------------------------- #
# build_user_message                                                          #
# --------------------------------------------------------------------------- #


def _q(qid: str = "q1", text: str = "Find iron in first windows data partition") -> DfirMetricQuestion:
    return DfirMetricQuestion(
        question_id=qid,
        image_sha256=None,
        question_text=text,
        answer_type=AnswerType.NSS_INODE_FILENAME_LIST,
        expected_answer="[]",
    )


def test_user_message_includes_question_text_and_id():
    q = _q(qid="abc-123", text="What user...?")
    msg = build_user_message(q)
    assert "abc-123" in msg
    assert "What user...?" in msg
    assert "nss_inode_filename_list" in msg


def test_system_prompt_documents_schema_and_verifier():
    assert "Witness Oath Verifier" in SYSTEM_PROMPT
    assert "answer_type" in SYSTEM_PROMPT
    assert "first windows data" in SYSTEM_PROMPT
    assert "extensions" in SYSTEM_PROMPT


# --------------------------------------------------------------------------- #
# build_claude_nss_agent_fn — end-to-end with a fake interactor + executor    #
# --------------------------------------------------------------------------- #


def test_agent_fn_routes_llm_args_to_executor():
    """The agent_fn passes the parsed args to the deterministic executor."""
    captured: list[LLMArgs | None] = []

    def fake_interactor(_cfg, _sys, _usr):
        text = (
            '```json\n'
            '{"image": "ss-win-07-25-18.dd", "answer_type": "list", '
            '"partition": "second windows data", "pattern": "iron.man@marvel.com", '
            '"extensions": null, "include_deleted": true, "include_live": true, '
            '"rationale": "exfat partition"}\n'
            '```\n'
        )
        return text, {"model": "fake", "stop_reason": "end_turn"}

    def fake_executor(_q, _k, args):
        captured.append(args)
        return AgentResponse(candidates=['["dummy"]'])

    agent_fn = build_claude_nss_agent_fn(
        deterministic_executor=fake_executor,
        config=ClaudeNSSConfig(api_key="fake"),
        interactor=fake_interactor,
    )
    response = agent_fn(_q(), 4)
    assert response.candidates == ['["dummy"]']
    assert response.wall_clock_seconds is not None
    assert len(captured) == 1
    assert captured[0] is not None
    assert captured[0].partition == "second windows data"
    assert captured[0].pattern == "iron.man@marvel.com"


def test_agent_fn_falls_back_when_interactor_errors():
    """API failure -> deterministic executor still runs (with args=None)."""
    fallback_called = []

    def broken_interactor(_cfg, _sys, _usr):
        raise RuntimeError("API down")

    def fake_executor(_q, _k, args):
        fallback_called.append(args)
        return AgentResponse(candidates=["[]"])

    agent_fn = build_claude_nss_agent_fn(
        deterministic_executor=fake_executor,
        config=ClaudeNSSConfig(api_key="fake"),
        interactor=broken_interactor,
    )
    response = agent_fn(_q(), 4)
    assert response.candidates == ["[]"]
    assert fallback_called == [None]


def test_agent_fn_falls_back_when_llm_emits_garbage():
    """LLM emits no parseable JSON -> args=None passed to executor."""
    def fake_interactor(_cfg, _sys, _usr):
        return "I don't know how to answer this.", {"model": "fake", "stop_reason": "end_turn"}

    received: list[LLMArgs | None] = []

    def fake_executor(_q, _k, args):
        received.append(args)
        return AgentResponse(candidates=["[]"])

    agent_fn = build_claude_nss_agent_fn(
        deterministic_executor=fake_executor,
        config=ClaudeNSSConfig(api_key="fake"),
        interactor=fake_interactor,
    )
    agent_fn(_q(), 4)
    assert received == [None]
