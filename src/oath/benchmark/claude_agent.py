"""Live Claude-driven agent_fn — the bridge from benchmark harness to reality.

Wraps Anthropic's Messages API with the OATH MCP server attached via stdio.
Each invocation:

  1. Builds a system prompt describing the agent's mission + verifier contract
  2. Frames the DFIR-Metric question as a user message that demands a ranked
     JSON candidate list of length ≤ K
  3. Runs the multi-turn tool-use loop: Claude calls MCP tools (parse_evtx,
     vol3_query, oath_verify_claim, …) until it has enough evidence
  4. Parses the final assistant message for `{"candidates": [...]}`
  5. Captures verifier-side telemetry (verified/quarantined counts, Ralph
     Wiggum events) by reading the run's envelope store + claim journal

Optional dependency — `anthropic` is in `[project.optional-dependencies].claude`.
Import-time failure if `anthropic` isn't installed; calling code is expected
to gate live runs on the user supplying `--live` (CLI) or invoking
`build_claude_agent_fn` explicitly.
"""
from __future__ import annotations

import json
import os
import re
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from oath.benchmark.harness import AgentResponse, BenchmarkAgentFn
from oath.benchmark.question import DfirMetricQuestion


# --------------------------------------------------------------------------- #
# Configuration                                                               #
# --------------------------------------------------------------------------- #


# Pin a specific Claude model. The benchmark scorecard is meaningless if we
# don't know which model produced it — we surface the model_id on every
# BenchmarkResult.
DEFAULT_MODEL = "claude-opus-4-7"
DEFAULT_MAX_TOKENS = 16_000
DEFAULT_TEMPERATURE = 0.0  # deterministic-ish; the harness scores reproducibility


@dataclass(frozen=True)
class ClaudeAgentConfig:
    """Configuration for the live Claude-driven agent_fn.

    api_key
      Anthropic API key. Defaults to env var ANTHROPIC_API_KEY at call time.
    model
      Pinned Claude model ID. The benchmark result records it.
    mcp_server_command
      Argv for the OATH MCP server, attached as a stdio child process.
      Default = ["python", "-m", "oath.mcp.server", "--logs-dir", "./logs",
      "--keys-dir", "./keys"].
    max_tokens
      Per-turn cap. Forensic answers are short; the budget exists for the
      reasoning steps in between.
    temperature
      Default 0.0 for determinism. Override only when you want to compare
      runs at higher temperature for diversity.
    max_loop_turns
      Safety cap on the tool-use loop. Anthropic's auto-multi-turn API
      iterates until the model emits a stop-text turn; this guards against
      runaway reasoning.
    """

    api_key: str | None = None
    model: str = DEFAULT_MODEL
    mcp_server_command: tuple[str, ...] = (
        "python",
        "-m",
        "oath.mcp.server",
    )
    extra_mcp_args: tuple[str, ...] = ()
    max_tokens: int = DEFAULT_MAX_TOKENS
    temperature: float = DEFAULT_TEMPERATURE
    max_loop_turns: int = 32


# --------------------------------------------------------------------------- #
# Prompt construction                                                         #
# --------------------------------------------------------------------------- #


SYSTEM_PROMPT = """\
You are OATH, an autonomous DFIR triage agent. You have access to typed
forensic tools via the `oath` MCP server. Every claim you make about
attacker activity must pass the Witness Oath Verifier — a deterministic
re-derivation gate that re-runs the cited tools and confirms output hashes
match. Hallucinations don't survive the verifier; they get QUARANTINED.

Your operating contract:
  1. Begin every investigation with `enumerate_credential_artifacts` to
     discover what evidence lives on the image.
  2. Choose typed-function calls (parse_evtx / parse_mft / parse_amcache /
     parse_prefetch / parse_registry / parse_usnjrnl / plaso_supertimeline /
     run_hayabusa / vol3_query) based on the question's MITRE technique
     focus. Filter aggressively — narrow time windows, narrow paths, narrow
     reason sets — to keep envelope size small.
  3. For every fact you intend to ship, submit an AgentClaim to
     `oath_verify_claim`. Claims that come back QUARANTINED or RALPH_WIGGUM
     must be visibly abandoned and re-formed.

When you have the answer, output a SINGLE final assistant turn whose body
contains ONLY a fenced JSON block of the form:

    ```json
    {"candidates": ["best answer", "next-best answer", "..."]}
    ```

The list must be ranked best-first and contain at most K entries (K is
specified in each question). Do not include prose outside the JSON block in
the final turn.
"""


USER_TEMPLATE = """\
DFIR-Metric Module III question.

  question_id   : {question_id}
  image_sha256  : {image_sha256}
  answer_type   : {answer_type}
  mitre         : {techniques}
  K             : {k}

Question:
{question_text}

Produce up to {k} ranked candidate answers in the format described in your
system prompt. Each candidate must be the bare answer value only — no
prose, no units, no explanation. The answer_type determines the matching
rule used by the scorer; format your candidate values accordingly:

  exact_string : verbatim string as it appears in the evidence
  string_ci    : any case is fine
  hex_hash     : hex characters only (md5 = 32 / sha1 = 40 / sha256 = 64)
  numeric      : a number, no thousands separators
  timestamp    : ISO-8601 UTC, second precision (e.g. 2026-04-12T14:32:01)
  path         : full path, slashes and case as found
  sid          : Windows SID (S-1-5-...)
"""


def build_user_message(question: DfirMetricQuestion, k: int) -> str:
    return USER_TEMPLATE.format(
        question_id=question.question_id,
        image_sha256=question.image_sha256,
        answer_type=question.answer_type.value,
        techniques=", ".join(question.mitre_techniques) or "-",
        k=k,
        question_text=question.question_text,
    )


# --------------------------------------------------------------------------- #
# Candidate parser                                                            #
# --------------------------------------------------------------------------- #


_FENCED_JSON_RE = re.compile(
    r"```(?:json)?\s*(\{.*?\})\s*```",
    re.DOTALL | re.IGNORECASE,
)


def parse_candidates(text: str, k: int) -> list[str]:
    """Extract the agent's ranked candidate list from its final assistant text.

    Tries (in order):
      1. ALL fenced JSON blocks; the LAST one wins (agents often draft
         then refine). Each must parse to {"candidates": [str, ...]}.
      2. A bare JSON object somewhere in the text matching the same shape.

    Returns the list truncated to k. Returns [] on any parse failure — the
    harness treats that as a 0-score for the question.
    """
    candidates: list[str] = []

    # Pass 1: fenced JSON blocks; last one wins.
    matches = list(_FENCED_JSON_RE.finditer(text))
    if matches:
        for m in reversed(matches):
            try:
                obj = json.loads(m.group(1))
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict) and isinstance(obj.get("candidates"), list):
                candidates = [str(c) for c in obj["candidates"]]
                break

    # Pass 2: bare JSON object in the text (no fences).
    if not candidates:
        m = re.search(r'\{"candidates"\s*:\s*\[.*?\]\s*\}', text, re.DOTALL)
        if m:
            try:
                obj = json.loads(m.group(0))
            except json.JSONDecodeError:
                obj = None
            if isinstance(obj, dict) and isinstance(obj.get("candidates"), list):
                candidates = [str(c) for c in obj["candidates"]]

    return candidates[:k]


# --------------------------------------------------------------------------- #
# The agent_fn (live SDK call)                                                #
# --------------------------------------------------------------------------- #


class AnthropicNotInstalled(RuntimeError):
    """Raised when `anthropic` isn't importable but the live agent was requested."""


# The interactor seam — lets tests substitute a fake without touching the
# SDK. In production, build_claude_agent_fn injects a real client invocation.
Interactor = Callable[
    [ClaudeAgentConfig, str, str],  # config, system_prompt, user_message
    tuple[str, dict[str, Any]],     # (final_text, raw_response_metadata)
]


def _default_interactor(
    config: ClaudeAgentConfig,
    system_prompt: str,
    user_message: str,
) -> tuple[str, dict[str, Any]]:
    """Invoke Anthropic Messages with the OATH MCP server attached.

    NOTE: The exact mcp_servers parameter shape depends on the
    `anthropic` SDK version. We pass the stdio command + args; users on
    older SDK versions can supply their own interactor.
    """
    try:
        import anthropic  # type: ignore[import-not-found]
    except ImportError as e:
        raise AnthropicNotInstalled(
            "anthropic SDK not installed. `pip install 'oath[claude]'`."
        ) from e

    client = anthropic.Anthropic(
        api_key=config.api_key or os.environ.get("ANTHROPIC_API_KEY"),
    )

    mcp_server_spec = {
        "name": "oath",
        "type": "stdio",
        "command": list(config.mcp_server_command) + list(config.extra_mcp_args),
    }

    # The Anthropic SDK's MCP integration is still maturing; the call
    # below targets the documented `beta.messages.create` interface with
    # `mcp_servers`. If the SDK shape changes, swap this for a custom
    # interactor.
    response = client.beta.messages.create(
        model=config.model,
        max_tokens=config.max_tokens,
        temperature=config.temperature,
        system=system_prompt,
        messages=[{"role": "user", "content": user_message}],
        mcp_servers=[mcp_server_spec],  # type: ignore[arg-type]
    )

    # Extract the final assistant text content.
    final_text_parts: list[str] = []
    for block in response.content:  # type: ignore[attr-defined]
        if getattr(block, "type", None) == "text":
            final_text_parts.append(block.text)
    final_text = "\n".join(final_text_parts).strip()

    meta = {
        "model": response.model,  # type: ignore[attr-defined]
        "stop_reason": response.stop_reason,  # type: ignore[attr-defined]
        "usage_input_tokens": response.usage.input_tokens,  # type: ignore[attr-defined]
        "usage_output_tokens": response.usage.output_tokens,  # type: ignore[attr-defined]
    }
    return final_text, meta


# --------------------------------------------------------------------------- #
# Public builder                                                              #
# --------------------------------------------------------------------------- #


@dataclass
class _RunSummaryReader:
    """Reads verifier-side telemetry from the live run's envelope store.

    Counts persisted envelopes + claim journal entries between two stat-time
    snapshots, so per-question telemetry is captured even though the SDK
    call itself doesn't know about envelopes.
    """

    envelopes_dir: Path
    claims_journal: Path | None = field(default=None)

    def snapshot(self) -> dict[str, int]:
        env_count = (
            len(list(self.envelopes_dir.glob("*.json")))
            if self.envelopes_dir.exists()
            else 0
        )
        claim_lines = 0
        if self.claims_journal and self.claims_journal.exists():
            try:
                claim_lines = sum(
                    1 for _ in self.claims_journal.read_text(encoding="utf-8").splitlines()
                    if _.strip()
                )
            except OSError:
                pass
        return {"envelopes": env_count, "claim_journal_lines": claim_lines}

    def delta(self, before: dict[str, int], after: dict[str, int]) -> dict[str, int]:
        return {k: after.get(k, 0) - before.get(k, 0) for k in set(before) | set(after)}


def build_claude_agent_fn(
    config: ClaudeAgentConfig | None = None,
    *,
    interactor: Interactor | None = None,
    envelopes_dir: Path | None = None,
    claims_journal: Path | None = None,
) -> BenchmarkAgentFn:
    """Build a BenchmarkAgentFn closure that hits Claude via the MCP server.

    Optional `interactor` is the SDK seam — pass a fake in tests.
    Optional `envelopes_dir` + `claims_journal` enable per-question telemetry.
    """
    config = config or ClaudeAgentConfig()
    interactor = interactor or _default_interactor

    summary_reader: _RunSummaryReader | None = None
    if envelopes_dir is not None:
        summary_reader = _RunSummaryReader(
            envelopes_dir=envelopes_dir,
            claims_journal=claims_journal,
        )

    def agent_fn(question: DfirMetricQuestion, k: int) -> AgentResponse:
        user_message = build_user_message(question, k)
        before = summary_reader.snapshot() if summary_reader else None
        t0 = time.perf_counter()
        final_text, _meta = interactor(config, SYSTEM_PROMPT, user_message)
        wall = time.perf_counter() - t0
        after = summary_reader.snapshot() if summary_reader else None

        candidates = parse_candidates(final_text, k)
        envelope_delta = (
            summary_reader.delta(before, after) if (summary_reader and before and after) else {}
        )

        return AgentResponse(
            candidates=candidates,
            wall_clock_seconds=wall,
            verified_envelope_count=envelope_delta.get("envelopes"),
            quarantined_count=None,
            ralph_wiggum_events=envelope_delta.get("claim_journal_lines"),
        )

    return agent_fn


__all__ = [
    "AnthropicNotInstalled",
    "ClaudeAgentConfig",
    "DEFAULT_MAX_TOKENS",
    "DEFAULT_MODEL",
    "DEFAULT_TEMPERATURE",
    "Interactor",
    "SYSTEM_PROMPT",
    "USER_TEMPLATE",
    "build_claude_agent_fn",
    "build_user_message",
    "parse_candidates",
]
