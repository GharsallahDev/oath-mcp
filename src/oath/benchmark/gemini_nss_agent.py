"""Live Gemini-driven NSS agent — emits structured search-args; OATH executes.

Same architectural pattern as `claude_nss_agent`: the LLM proposes a
typed search-args JSON for each question; OATH's deterministic executor
runs the search under the Witness Oath Verifier and produces ranked
candidates. The LLM never executes anything itself.

Why Vertex Gemini (not stdio MCP):
  - Vertex AI's GenerativeModel exposes a clean text-in/text-out interface
    perfectly suited to structured-args generation.
  - Single API call per question = cheap, deterministic, easy to score.
  - The MCP-server tool-use path requires either (a) URL-based MCP servers
    in the Anthropic Beta API which is the wrong vendor for this account,
    or (b) full multi-turn tool-use loops which add cost without changing
    the verifier semantics. Args-proposal is functionally equivalent.

Optional dependency: `google-cloud-aiplatform` (oath[vertex]). Import-time
failure when not installed; the CLI gates `--live-vertex` on that dep.
"""
from __future__ import annotations

import json
import os
import re
import time
from collections.abc import Callable
from dataclasses import dataclass

from oath.benchmark.harness import AgentResponse, BenchmarkAgentFn
from oath.benchmark.question import DfirMetricQuestion

# We re-use the LLMArgs dataclass + the SYSTEM_PROMPT and parse_llm_args from
# claude_nss_agent — the contract is identical, only the carrier changes.
from oath.benchmark.claude_nss_agent import (
    SYSTEM_PROMPT,
    LLMArgs,
    build_user_message,
    parse_llm_args,
)


# Defaults — Gemini 2.5 Flash is the right cost/quality tradeoff for NSS;
# Pro is available if we want max accuracy.
DEFAULT_MODEL = "gemini-2.5-flash"
DEFAULT_TEMPERATURE = 0.0
DEFAULT_PROJECT = "zarda-e0938"
DEFAULT_LOCATION = "us-central1"


# --------------------------------------------------------------------------- #
# Configuration                                                               #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class GeminiNSSConfig:
    """Configuration for the live Gemini-driven NSS agent."""

    project: str = DEFAULT_PROJECT
    location: str = DEFAULT_LOCATION
    model: str = DEFAULT_MODEL
    temperature: float = DEFAULT_TEMPERATURE
    max_output_tokens: int = 2048


# --------------------------------------------------------------------------- #
# Interactor seam                                                             #
# --------------------------------------------------------------------------- #


Interactor = Callable[[GeminiNSSConfig, str, str], tuple[str, dict]]


def _default_interactor(
    config: GeminiNSSConfig, system_prompt: str, user_message: str
) -> tuple[str, dict]:
    """Invoke Vertex Gemini with a plain system + user prompt.

    Returns (final_text, telemetry). Telemetry includes the model id and
    the response token counts (for accuracy-report dollars-per-question math).
    """
    try:
        import vertexai
        from vertexai.generative_models import GenerationConfig, GenerativeModel
    except ImportError as e:
        raise RuntimeError(
            "google-cloud-aiplatform not installed. `pip install 'oath[vertex]'`."
        ) from e

    vertexai.init(project=config.project, location=config.location)
    model = GenerativeModel(config.model, system_instruction=system_prompt)
    resp = model.generate_content(
        user_message,
        generation_config=GenerationConfig(
            temperature=config.temperature,
            max_output_tokens=config.max_output_tokens,
            response_mime_type="application/json",
        ),
    )

    text = (resp.text or "").strip()
    usage = getattr(resp, "usage_metadata", None)
    return text, {
        "model": config.model,
        "prompt_token_count": getattr(usage, "prompt_token_count", None),
        "candidates_token_count": getattr(usage, "candidates_token_count", None),
        "total_token_count": getattr(usage, "total_token_count", None),
    }


# --------------------------------------------------------------------------- #
# Agent function                                                              #
# --------------------------------------------------------------------------- #


def build_gemini_nss_agent_fn(
    *,
    deterministic_executor: Callable[[DfirMetricQuestion, int, LLMArgs | None], AgentResponse],
    config: GeminiNSSConfig | None = None,
    interactor: Interactor | None = None,
) -> BenchmarkAgentFn:
    """Build a BenchmarkAgentFn that:
       1. Asks Gemini for an args proposal
       2. Hands the proposal to `deterministic_executor` which runs the
          actual forensic search under the Witness Oath Verifier
       3. Returns the deterministic executor's candidates with the live
          API wall-clock stamped on top
    """
    config = config or GeminiNSSConfig()
    interactor = interactor or _default_interactor

    def agent_fn(question: DfirMetricQuestion, k: int) -> AgentResponse:
        user_msg = build_user_message(question)
        t0 = time.perf_counter()
        try:
            text, _telemetry = interactor(config, SYSTEM_PROMPT, user_msg)
        except Exception as e:
            print(f"  [{question.question_id}] vertex error: {e}", flush=True)
            return deterministic_executor(question, k, None)
        wall = time.perf_counter() - t0

        llm_args = parse_llm_args(text)
        response = deterministic_executor(question, k, llm_args)
        return AgentResponse(
            candidates=response.candidates,
            wall_clock_seconds=wall,
            verified_envelope_count=response.verified_envelope_count,
            quarantined_count=response.quarantined_count,
            ralph_wiggum_events=response.ralph_wiggum_events,
        )

    return agent_fn


__all__ = [
    "DEFAULT_LOCATION",
    "DEFAULT_MODEL",
    "DEFAULT_PROJECT",
    "DEFAULT_TEMPERATURE",
    "GeminiNSSConfig",
    "Interactor",
    "build_gemini_nss_agent_fn",
]
