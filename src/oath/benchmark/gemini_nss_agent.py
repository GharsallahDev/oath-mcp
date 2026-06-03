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
DEFAULT_MODEL = "gemini-3.1-pro-preview"  # June 2026: latest Vertex Gemini preview
DEFAULT_TEMPERATURE = 0.0
DEFAULT_PROJECT = "zarda-e0938"
DEFAULT_LOCATION = "global"  # gemini-3.x previews are served from the global endpoint


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

    # Per-request timeout — long Vertex hangs (especially during regional
    # capacity hiccups) would otherwise wedge the benchmark indefinitely.
    # We pass the timeout via the model's client_options at init time since
    # vertexai 1.x doesn't accept a per-call request_options kwarg on
    # generate_content. The harness's per-question err handler converts a
    # timeout into a deterministic-executor fallback so the run continues.
    vertexai.init(project=config.project, location=config.location)
    model = GenerativeModel(config.model, system_instruction=system_prompt)

    # Wrap the call in a thread + signal-based timeout. Cross-platform and
    # robust to any underlying SDK hang.
    import concurrent.futures as _cf
    import time as _time

    def _call():
        return model.generate_content(
            user_message,
            generation_config=GenerationConfig(
                temperature=config.temperature,
                max_output_tokens=config.max_output_tokens,
                response_mime_type="application/json",
            ),
        )

    # Retry FOREVER on transient failures (timeouts, 429s, 503s, connection
    # resets). Falling back to the deterministic resolver on these errors
    # silently penalizes the score AND charges the user for a wasted call —
    # both unacceptable. Every question MUST receive a real LLM answer.
    # Backoff caps at 600s; we sleep at the cap indefinitely until quota
    # clears or a real (non-transient) error fires. The caller can ctrl-C
    # to abort; otherwise the loop is guaranteed to either produce a real
    # response or raise a non-transient error that propagates.
    attempt_n = 0
    while True:
        attempt_n += 1
        backoff = min(4.0 * (2 ** (attempt_n - 1)), 600.0) if attempt_n > 1 else 0.0
        if backoff > 0:
            print(
                f"  retry #{attempt_n - 1} after {backoff:.0f}s backoff "
                f"(model={config.model})", flush=True,
            )
            _time.sleep(backoff)
        try:
            with _cf.ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(_call)
                try:
                    resp = future.result(timeout=120.0)
                except _cf.TimeoutError as e:
                    raise RuntimeError("vertex generate_content timeout (120s)") from e
            break
        except Exception as e:  # noqa: BLE001
            msg = str(e).lower()
            is_transient = (
                "timeout" in msg or "429" in msg or "resource exhausted" in msg
                or "503" in msg or "504" in msg or "connection reset" in msg
                or "unavailable" in msg or "internal error" in msg
                or "deadline exceeded" in msg
            )
            if not is_transient:
                # Real model-side error (bad input, auth, quota PERMANENTLY
                # exhausted, etc.) — let the caller deal with it.
                raise

    # Gemini 3.x can return only reasoning/thought parts when the final-text
    # part is empty; `resp.text` raises in that case. Walk the candidates'
    # content parts and pick up the first non-thought text we find.
    text = ""
    try:
        text = (resp.text or "").strip()
    except Exception:
        if resp.candidates:
            for c in resp.candidates:
                if c.content and c.content.parts:
                    for p in c.content.parts:
                        # `thought` parts carry chain-of-thought; skip those.
                        if getattr(p, "thought", False):
                            continue
                        t = getattr(p, "text", None)
                        if t:
                            text = t.strip()
                            break
                if text:
                    break

    usage = getattr(resp, "usage_metadata", None)
    return text, {
        "model": config.model,
        "prompt_token_count": getattr(usage, "prompt_token_count", None),
        "candidates_token_count": getattr(usage, "candidates_token_count", None),
        "total_token_count": getattr(usage, "total_token_count", None),
        # Gemini 3.x exposes the thinking budget separately; older models lack this field.
        "thoughts_token_count": getattr(usage, "thoughts_token_count", None),
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
        # Compute the prompt hash UP-FRONT so we can bind it into the envelope
        # whether or not the LLM call succeeds. Daubert binding: the receipt
        # must record which model + which prompt produced this finding.
        from oath.receipt.notarized import hash_prompt
        prompt_hash = hash_prompt(SYSTEM_PROMPT, user_msg)

        t0 = time.perf_counter()
        # NO try/except around the interactor call. The interactor's own
        # retry-with-exponential-backoff handles ALL transient Vertex errors
        # forever (429 quota, timeouts, 503s, connection resets). Anything
        # that escapes that loop is a genuine model-side failure (bad auth,
        # malformed request, permanent quota exhaustion) — silently falling
        # back to the deterministic resolver on those would corrupt the
        # benchmark score by mixing LLM-driven and deterministic attempts
        # without flagging the difference. Let the exception propagate; the
        # harness's resumable-attempts JSONL means a re-run picks up exactly
        # where the run aborted, after the operator fixes the root cause.
        text, telemetry = interactor(config, SYSTEM_PROMPT, user_msg)
        wall = time.perf_counter() - t0

        llm_args = parse_llm_args(text)
        response = deterministic_executor(
            question, k, llm_args, model_id=config.model, prompt_hash=prompt_hash
        )
        return AgentResponse(
            candidates=response.candidates,
            wall_clock_seconds=wall,
            verified_envelope_count=response.verified_envelope_count,
            quarantined_count=response.quarantined_count,
            ralph_wiggum_events=response.ralph_wiggum_events,
            model_id=telemetry.get("model"),
            prompt_token_count=telemetry.get("prompt_token_count"),
            candidates_token_count=telemetry.get("candidates_token_count"),
            total_token_count=telemetry.get("total_token_count"),
            thoughts_token_count=telemetry.get("thoughts_token_count"),
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
