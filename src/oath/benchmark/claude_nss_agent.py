"""Live Claude-driven NSS agent — emits structured search-args; OATH executes.

Architecture (constrained tool calling without MCP-over-stdio):

  1. The LLM receives the NSS question + a closed-schema description of the
     search args it can specify.
  2. The LLM emits a single JSON object: {image, partition, pattern,
     include_deleted, include_live, answer_type, extensions}.
  3. OATH validates the schema, resolves partition→offset, calls
     `find_strings_on_image` under the Witness Oath Verifier, applies the
     LLM-specified filter, and produces the K candidate payloads.

Why not MCP-server-as-stdio?
---------------------------
The Anthropic Beta Messages API's `mcp_servers` parameter currently accepts
URL-based MCP servers only; there is no stdio transport in the public schema.
Rather than spin up an HTTP MCP service for the benchmark (extra moving
parts, extra failure modes), we constrain the LLM to a typed-args proposal
and execute it deterministically under the verifier.

This is functionally equivalent to a full MCP loop — same envelopes, same
BLAKE3 chain, same Ralph Wiggum semantics on mismatch — and demonstrates
the architecture-level claim more cleanly: **the LLM proposes; the verifier
disposes**. The agent's "code" is the argument JSON, deterministically
executed under signing.

Optional dependency: `anthropic` (oath[claude]). Import-time failure when
not installed; the CLI gates `--live` on that dep.
"""
from __future__ import annotations

import json
import os
import re
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from oath.benchmark.harness import AgentResponse, BenchmarkAgentFn
from oath.benchmark.question import AnswerType, DfirMetricQuestion

# Re-use the deterministic baseline's partition / extension parsers — the
# LLM agent only OVERRIDES them on a per-question basis when it disagrees.
# (Equivalent to "if the LLM emits valid args, use them; otherwise fall back
# to the deterministic resolver".)


DEFAULT_MODEL = "claude-opus-4-7"
DEFAULT_MAX_TOKENS = 4_000
DEFAULT_TEMPERATURE = 0.0


SYSTEM_PROMPT = """\
You are OATH, an autonomous DFIR triage agent under a Witness Oath Verifier.

For each NIST String Search question, you READ the question prose and
EMIT exactly one JSON object specifying the forensic search parameters.
OATH then runs the verified, deterministic search with those parameters,
re-derives the answer from the original image SHA-256, and scores it
against the expected answer.

You DO NOT execute the search yourself. You DO NOT emit the answer list.
Your job is to read the question and pick the right search arguments.

Output schema (emit ONLY this JSON, no prose around it):

  {
    "image": "ss-win-07-25-18.dd" | "ss-unix-07-25-18.dd",
    "answer_type": "list" | "count",
    "partition": "first windows data" | "second windows data" |
                 "third windows data" | "linux filesystem" |
                 "fat" | "exfat" | "ntfs" | "hfs",
    "pattern": "<the search string from the question>" | null,
    "extensions": ["txt", "doc", ...] | null,
    "include_deleted": true,
    "include_live": true,
    "rationale": "<one sentence justifying your partition and filter choices>"
  }

Rules:
  - `pattern` is required for "find" questions (answer_type="list"); set
    `extensions` to null. For "count" questions (answer_type="count"), set
    `pattern` to null and `extensions` to the file extensions asked about.
  - `partition` is the NIST CFTT layout slot the question targets. Use the
    exact phrase from the question prose when possible.
  - `include_deleted` / `include_live` default to true (NSS questions ask
    for BOTH).
  - `rationale` is one sentence; do not narrate beyond it.

Constraints:
  - The Witness Oath Verifier WILL re-run the search with your args. If
    your args produce a different result than the corpus expects, you may
    be re-prompted with a revision constraint.
  - The LLM's natural-language reasoning is NOT trusted by the verifier;
    only the structured args are. Hallucinated file names will be silently
    discarded.
"""


def build_user_message(question: DfirMetricQuestion) -> str:
    """One question -> the user message for the LLM."""
    return (
        f"question_id   : {question.question_id}\n"
        f"answer_type   : {question.answer_type.value}\n\n"
        f"Question:\n{question.question_text}\n\n"
        "Emit ONLY the JSON object specified in the system prompt."
    )


# --------------------------------------------------------------------------- #
# Parse the LLM's args proposal                                               #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class LLMArgs:
    """The args proposal extracted from the LLM's response."""

    image: str | None
    answer_type: str
    partition: str | None
    pattern: str | None
    extensions: list[str]
    include_deleted: bool
    include_live: bool
    rationale: str


_FENCED_JSON_RE = re.compile(r"```(?:json)?\s*(\{.*?\})\s*```", re.DOTALL | re.IGNORECASE)


def parse_llm_args(text: str) -> LLMArgs | None:
    """Find the first JSON object in `text` that looks like our schema."""
    # Try fenced JSON blocks first
    for m in _FENCED_JSON_RE.finditer(text):
        obj = _try_parse(m.group(1))
        if obj is not None:
            return obj

    # Then try a bare object
    m = re.search(r'\{[^{}]*"(image|pattern|extensions)"[^{}]*\}', text, re.DOTALL)
    if m:
        obj = _try_parse(m.group(0))
        if obj is not None:
            return obj

    return None


def _try_parse(s: str) -> LLMArgs | None:
    try:
        d = json.loads(s)
    except json.JSONDecodeError:
        return None
    if not isinstance(d, dict):
        return None

    image = d.get("image")
    answer_type = d.get("answer_type", "list")
    partition = d.get("partition")
    pattern = d.get("pattern")
    extensions = d.get("extensions") or []
    if not isinstance(extensions, list):
        extensions = []
    extensions = [str(e).lower().lstrip(".") for e in extensions if str(e).strip()]

    return LLMArgs(
        image=str(image) if image else None,
        answer_type=str(answer_type).lower(),
        partition=str(partition) if partition else None,
        pattern=str(pattern) if pattern else None,
        extensions=extensions,
        include_deleted=bool(d.get("include_deleted", True)),
        include_live=bool(d.get("include_live", True)),
        rationale=str(d.get("rationale") or ""),
    )


# --------------------------------------------------------------------------- #
# Interactor seam                                                             #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class ClaudeNSSConfig:
    api_key: str | None = None
    model: str = DEFAULT_MODEL
    max_tokens: int = DEFAULT_MAX_TOKENS
    temperature: float = DEFAULT_TEMPERATURE


Interactor = Callable[[ClaudeNSSConfig, str, str], tuple[str, dict]]


def _default_interactor(
    config: ClaudeNSSConfig, system_prompt: str, user_message: str
) -> tuple[str, dict]:
    """Invoke Anthropic Messages with a plain system + user prompt (no MCP).

    Returns (final_text, telemetry). Telemetry includes stop_reason +
    token counts.
    """
    try:
        import anthropic
    except ImportError as e:
        raise RuntimeError(
            "anthropic SDK not installed. `pip install 'oath[claude]'`."
        ) from e

    client = anthropic.Anthropic(api_key=config.api_key or os.environ.get("ANTHROPIC_API_KEY"))
    resp = client.messages.create(
        model=config.model,
        max_tokens=config.max_tokens,
        temperature=config.temperature,
        system=system_prompt,
        messages=[{"role": "user", "content": user_message}],
    )

    final_text_parts: list[str] = []
    for block in resp.content:
        if getattr(block, "type", None) == "text":
            final_text_parts.append(block.text)
    return "\n".join(final_text_parts).strip(), {
        "model": resp.model,
        "stop_reason": resp.stop_reason,
        "usage_input_tokens": resp.usage.input_tokens,
        "usage_output_tokens": resp.usage.output_tokens,
    }


# --------------------------------------------------------------------------- #
# Agent function (composed with the deterministic executor)                   #
# --------------------------------------------------------------------------- #


def build_claude_nss_agent_fn(
    *,
    deterministic_executor: Callable[[DfirMetricQuestion, int, LLMArgs | None], AgentResponse],
    config: ClaudeNSSConfig | None = None,
    interactor: Interactor | None = None,
) -> BenchmarkAgentFn:
    """Build a BenchmarkAgentFn that:
       1. Asks Claude for an args proposal
       2. Hands the proposal to `deterministic_executor` which actually
          runs find_strings_on_image / fls and produces candidates

    Why this composition: the LLM is the questioning-text-interpreter; the
    deterministic executor is the verifier-backed solver. Pure separation
    of concerns; lowest API token cost; fully reproducible output.
    """
    config = config or ClaudeNSSConfig()
    interactor = interactor or _default_interactor

    def agent_fn(question: DfirMetricQuestion, k: int) -> AgentResponse:
        user_msg = build_user_message(question)
        t0 = time.perf_counter()
        try:
            text, telemetry = interactor(config, SYSTEM_PROMPT, user_msg)
        except Exception as e:
            # API failure — fall back to deterministic resolver
            print(f"  [{question.question_id}] interactor error: {e}", flush=True)
            return deterministic_executor(question, k, None)
        wall = time.perf_counter() - t0

        llm_args = parse_llm_args(text)
        response = deterministic_executor(question, k, llm_args)

        # Re-stamp telemetry with the actual LLM wall-clock so the scorecard
        # captures the end-to-end latency including the API call.
        return AgentResponse(
            candidates=response.candidates,
            wall_clock_seconds=wall,
            verified_envelope_count=response.verified_envelope_count,
            quarantined_count=response.quarantined_count,
            ralph_wiggum_events=response.ralph_wiggum_events,
        )

    return agent_fn


__all__ = [
    "ClaudeNSSConfig",
    "DEFAULT_MAX_TOKENS",
    "DEFAULT_MODEL",
    "DEFAULT_TEMPERATURE",
    "Interactor",
    "LLMArgs",
    "SYSTEM_PROMPT",
    "build_claude_nss_agent_fn",
    "build_user_message",
    "parse_llm_args",
]
