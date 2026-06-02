"""Tests for the Gemini NSS args-proposal agent."""
from __future__ import annotations

import pytest

from oath.benchmark import AgentResponse, AnswerType, DfirMetricQuestion
from oath.benchmark.gemini_nss_agent import (
    DEFAULT_LOCATION,
    DEFAULT_MODEL,
    DEFAULT_PROJECT,
    GeminiNSSConfig,
    build_gemini_nss_agent_fn,
)
from oath.benchmark.claude_nss_agent import LLMArgs


def _q(qid: str = "q1") -> DfirMetricQuestion:
    return DfirMetricQuestion(
        question_id=qid,
        image_sha256=None,
        question_text="Find iron.man@marvel.com in first windows data partition.",
        answer_type=AnswerType.NSS_INODE_FILENAME_LIST,
        expected_answer="[]",
    )


# --------------------------------------------------------------------------- #
# Defaults                                                                    #
# --------------------------------------------------------------------------- #


def test_default_config_uses_gemini_31_pro_preview():
    """Defaults track the latest Gemini preview available on Vertex.

    Updated 2026-06: gemini-3.1-pro-preview supersedes gemini-2.5-flash as the
    default. The 3.x previews live on the `global` endpoint (no regional
    endpoints yet), so DEFAULT_LOCATION moved from `us-central1` to `global`.
    """
    cfg = GeminiNSSConfig()
    assert cfg.model == DEFAULT_MODEL == "gemini-3.1-pro-preview"
    assert cfg.project == DEFAULT_PROJECT == "zarda-e0938"
    assert cfg.location == DEFAULT_LOCATION == "global"
    assert cfg.temperature == 0.0


# --------------------------------------------------------------------------- #
# build_gemini_nss_agent_fn — full round trip with fakes                      #
# --------------------------------------------------------------------------- #


def test_agent_fn_routes_args_to_executor():
    captured: list[LLMArgs | None] = []

    def fake_interactor(_cfg, _sys, _usr):
        text = (
            '{"image": "ss-win-07-25-18.dd", "answer_type": "list", '
            '"partition": "first windows data", "pattern": "iron.man@marvel.com", '
            '"extensions": null, "include_deleted": true, "include_live": true, '
            '"rationale": "FAT32 GORDO partition"}'
        )
        return text, {"model": "gemini-2.5-flash"}

    def fake_executor(_q, _k, args, **_kw):
        captured.append(args)
        return AgentResponse(candidates=['["dummy"]'])

    agent_fn = build_gemini_nss_agent_fn(
        deterministic_executor=fake_executor,
        config=GeminiNSSConfig(),
        interactor=fake_interactor,
    )
    response = agent_fn(_q(), 4)
    assert response.candidates == ['["dummy"]']
    assert response.wall_clock_seconds is not None
    assert len(captured) == 1
    assert captured[0] is not None
    assert captured[0].pattern == "iron.man@marvel.com"
    assert captured[0].image == "ss-win-07-25-18.dd"


def test_agent_fn_falls_back_when_vertex_errors():
    fallback_called: list[LLMArgs | None] = []

    def broken_interactor(_cfg, _sys, _usr):
        raise RuntimeError("vertex unavailable")

    def fake_executor(_q, _k, args, **_kw):
        fallback_called.append(args)
        return AgentResponse(candidates=["[]"])

    agent_fn = build_gemini_nss_agent_fn(
        deterministic_executor=fake_executor,
        config=GeminiNSSConfig(),
        interactor=broken_interactor,
    )
    response = agent_fn(_q(), 4)
    assert response.candidates == ["[]"]
    assert fallback_called == [None]


def test_agent_fn_falls_back_when_llm_emits_garbage():
    received: list[LLMArgs | None] = []

    def fake_interactor(_cfg, _sys, _usr):
        return "I do not know.", {"model": "gemini-2.5-flash"}

    def fake_executor(_q, _k, args, **_kw):
        received.append(args)
        return AgentResponse(candidates=["[]"])

    agent_fn = build_gemini_nss_agent_fn(
        deterministic_executor=fake_executor,
        config=GeminiNSSConfig(),
        interactor=fake_interactor,
    )
    agent_fn(_q(), 4)
    assert received == [None]
