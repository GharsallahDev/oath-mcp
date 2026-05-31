"""The Witness Oath Verifier.

The architectural primitive that turns OATH from "yet another LLM-driven DFIR
agent" into a system where every shipped finding has survived a deterministic
re-derivation gate. Per the README's load-bearing claim:

    Every claim the LLM emits must pass a deterministic re-derivation gate
    before entering the evidence graph. Claims that fail are QUARANTINED,
    visible to the examiner as 'the agent suspected this but couldn't prove
    it.' Hallucinations are made VISIBLE, not hidden.

How the verifier operates on one claim
--------------------------------------
1. **Envelope re-verification.** For each `ClaimEvidence` in the claim, the
   verifier looks up the corresponding Notarized envelope and calls the
   tool-specific `reverify()` function (parse_evtx.reverify, parse_mft.reverify,
   etc.). This catches: tool-version drift, raw stdout drift, rule-corpus
   drift (Hayabusa), and any tampering with the underlying evidence file.

2. **Predicate matching.** For each ClaimEvidence's `record_predicate`, the
   verifier confirms that AT LEAST ONE record in the envelope's data field
   satisfies the predicate as a subset match. This catches: the LLM citing a
   real envelope but fabricating which record it points at.

3. **Verdict assignment.**
     - If ALL envelope reverify() return ok AND all predicates match → VERIFIED
     - If envelope reverify() ok but a predicate doesn't match → QUARANTINED
     - If any envelope reverify() fails → RALPH_WIGGUM (tool/evidence drift,
       agent must re-propose with constraint)

Importantly: the verifier returns a STRUCTURED VerifyResult. The agent loop
consumes the result, surfaces quarantined claims to the examiner as
"suspected-but-unproven" (NOT silently dropped), and on RALPH_WIGGUM
verdicts the agent visibly abandons the hypothesis and re-proposes — that
visible self-correction is the Ralph Wiggum Loop (see ralph_wiggum.py).

This module has no LLM calls. It's pure orchestration over deterministic
re-verification + predicate matching.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from oath.receipt.notarized import Notarized, verify_signature
from oath.witness.claim import (
    AgentClaim,
    ClaimEvidence,
    VerifyResult,
    VerifyVerdict,
)


# --------------------------------------------------------------------------- #
# Reverify-function registry                                                  #
# --------------------------------------------------------------------------- #

# Each typed function in src/oath/mcp/tools/ exposes a `reverify(envelope,
# **kwargs)` callable. The verifier dispatches on the envelope's `tool_name`
# to find the right one. Tool authors register here once.
#
# A reverify function takes the envelope + a tool-specific kwargs dict (the
# path to the original artifact for re-running) and returns (ok, reason).

ReverifyFn = Callable[..., tuple[bool, str]]


@dataclass
class ReverifyRegistry:
    """Maps tool_name → reverify() function + the kwarg names it needs.

    The verifier consults this to know HOW to re-run a tool given an envelope.
    Tools register themselves at module import time (lazy import below).
    """

    by_tool: dict[str, ReverifyFn] = field(default_factory=dict)
    required_kwargs: dict[str, tuple[str, ...]] = field(default_factory=dict)

    def register(
        self,
        tool_name: str,
        fn: ReverifyFn,
        required_kwargs: tuple[str, ...] = (),
    ) -> None:
        self.by_tool[tool_name] = fn
        self.required_kwargs[tool_name] = required_kwargs

    def call(
        self,
        envelope: Notarized[Any],
        kwargs: dict[str, Any],
    ) -> tuple[bool, str]:
        tool = envelope.header.tool_name
        fn = self.by_tool.get(tool)
        if fn is None:
            return False, f"no reverify() registered for tool '{tool}'"

        # Take only the kwargs the tool's reverify wants, to avoid leakage.
        required = self.required_kwargs.get(tool, ())
        passed = {k: kwargs[k] for k in required if k in kwargs}
        missing = [k for k in required if k not in passed]
        if missing:
            return False, f"missing required reverify kwargs for {tool}: {missing}"

        try:
            return fn(envelope, **passed)
        except Exception as e:  # noqa: BLE001 — reverify can fail in many ways
            return False, f"reverify raised: {type(e).__name__}: {e}"


# Module-level default registry. `register_builtin_reverifiers()` populates it
# with OATH's bundled typed functions; tests construct their own to avoid
# import-order coupling.
_DEFAULT_REGISTRY: ReverifyRegistry | None = None


def default_registry() -> ReverifyRegistry:
    """Return (lazily-populated) registry of all bundled OATH reverifiers."""
    global _DEFAULT_REGISTRY
    if _DEFAULT_REGISTRY is not None:
        return _DEFAULT_REGISTRY

    registry = ReverifyRegistry()

    # Lazy imports so this module doesn't pull in every tool at import time.
    from oath.mcp.tools import (
        parse_amcache,
        parse_evtx,
        parse_mft,
        parse_prefetch,
        parse_registry,
        parse_usnjrnl,
        plaso_supertimeline,
        run_hayabusa,
        vol3_query,
    )

    registry.register("parse_evtx", parse_evtx.reverify, required_kwargs=("evtx_path",))
    registry.register("parse_mft", parse_mft.reverify, required_kwargs=("mft_path",))
    registry.register(
        "parse_amcache", parse_amcache.reverify, required_kwargs=("amcache_path",)
    )
    registry.register(
        "parse_prefetch", parse_prefetch.reverify, required_kwargs=("prefetch_dir",)
    )
    registry.register(
        "parse_registry",
        parse_registry.reverify,
        required_kwargs=("hive_path", "plugins_dir"),
    )
    registry.register(
        "parse_usnjrnl", parse_usnjrnl.reverify, required_kwargs=("j_path",)
    )
    registry.register(
        "plaso_supertimeline",
        plaso_supertimeline.reverify,
        required_kwargs=("plaso_path",),
    )
    registry.register(
        "run_hayabusa", run_hayabusa.reverify, required_kwargs=("evtx_dir", "rules_dir")
    )
    registry.register(
        "vol3_query", vol3_query.reverify, required_kwargs=("memdump_path",)
    )

    _DEFAULT_REGISTRY = registry
    return registry


# --------------------------------------------------------------------------- #
# Predicate matching                                                          #
# --------------------------------------------------------------------------- #


def _matches_predicate(record: Any, predicate: dict[str, Any]) -> bool:
    """Return True iff `record` matches `predicate` as a subset.

    The record is typically a pydantic model (EvtxRecord, MftEntry, etc.).
    The predicate is a dict of {field_name: expected_value}. Match semantics:

      - For each (field, expected) in the predicate:
        - The record must HAVE the field (attribute access works)
        - The actual value must EQUAL expected, with one relaxation:
          if expected is a list/tuple, the actual must be IN it (membership)

    A predicate matches if EVERY (field, expected) pair is satisfied.
    Predicates are deliberately strict — the LLM cannot use fuzzy semantics
    to satisfy them; it must point at records whose fields literally agree.
    """
    if isinstance(record, dict):
        get = record.get
    else:
        get = lambda k, default=None: getattr(record, k, default)  # noqa: E731

    sentinel = object()
    for key, expected in predicate.items():
        actual = get(key, sentinel)
        if actual is sentinel:
            return False
        if isinstance(expected, (list, tuple, set)):
            if actual not in expected:
                return False
        else:
            if actual != expected:
                return False
    return True


def _find_matching_indices(envelope: Notarized[Any], predicate: dict[str, Any]) -> list[int]:
    """Return indices of records in envelope.data that match `predicate`.

    Returns empty list if data is not iterable or no records match.
    """
    data = envelope.data
    try:
        records = list(data)
    except TypeError:
        # Not iterable — treat as single-record envelope.
        return [0] if _matches_predicate(data, predicate) else []
    return [i for i, rec in enumerate(records) if _matches_predicate(rec, predicate)]


# --------------------------------------------------------------------------- #
# The Verifier                                                                #
# --------------------------------------------------------------------------- #


@dataclass
class WitnessOathVerifier:
    """Verifies AgentClaims by orchestrating per-envelope reverify + predicate matching.

    Construction:
      v = WitnessOathVerifier(envelopes_by_id={...}, reverify_kwargs={...})

    `envelopes_by_id` maps `envelope_id` (the string the agent uses in
    ClaimEvidence) to the Notarized envelope. `reverify_kwargs` maps
    envelope_id → the per-envelope kwargs the tool's reverify() needs
    (e.g. {"evtx_path": Path(...)}).
    """

    envelopes_by_id: dict[str, Notarized[Any]]
    reverify_kwargs: dict[str, dict[str, Any]] = field(default_factory=dict)
    registry: ReverifyRegistry = field(default_factory=default_registry)
    public_key_for_signatures: Any | None = None  # nacl.signing.VerifyKey or None to skip

    def verify(self, claim: AgentClaim) -> VerifyResult:
        """Verify a single AgentClaim end-to-end."""
        envelope_verdicts: dict[str, tuple[bool, str]] = {}
        predicate_matches: dict[str, list[int]] = {}

        for evidence in claim.supporting_evidence:
            envelope_id = evidence.envelope_id
            envelope = self.envelopes_by_id.get(envelope_id)
            if envelope is None:
                envelope_verdicts[envelope_id] = (
                    False,
                    f"claim references unknown envelope_id '{envelope_id}'",
                )
                predicate_matches[envelope_id] = []
                continue

            # Optional cryptographic signature check (when caller provides a pub key).
            if self.public_key_for_signatures is not None:
                if not verify_signature(envelope, self.public_key_for_signatures):
                    envelope_verdicts[envelope_id] = (
                        False,
                        "ed25519 signature does not verify under provided public key",
                    )
                    predicate_matches[envelope_id] = []
                    continue

            # Step 1 — re-derive the envelope's tool output and confirm BLAKE3 match.
            kwargs = self.reverify_kwargs.get(envelope_id, {})
            ok, reason = self.registry.call(envelope, kwargs)
            envelope_verdicts[envelope_id] = (ok, reason)
            if not ok:
                predicate_matches[envelope_id] = []
                continue

            # Step 2 — check at least one record in envelope.data matches the predicate.
            indices = _find_matching_indices(envelope, evidence.record_predicate)
            predicate_matches[envelope_id] = indices

        # Aggregate verdict.
        return self._aggregate(claim, envelope_verdicts, predicate_matches)

    def _aggregate(
        self,
        claim: AgentClaim,
        envelope_verdicts: dict[str, tuple[bool, str]],
        predicate_matches: dict[str, list[int]],
    ) -> VerifyResult:
        # Tool/evidence drift on ANY envelope → RALPH_WIGGUM (agent must self-correct).
        for envelope_id, (ok, reason) in envelope_verdicts.items():
            if not ok:
                return VerifyResult(
                    claim_id=claim.claim_id,
                    verdict=VerifyVerdict.RALPH_WIGGUM,
                    reason=(
                        f"envelope '{envelope_id}' failed re-derivation: {reason}. "
                        "Agent must abandon this hypothesis and re-propose."
                    ),
                    envelope_verdicts=envelope_verdicts,
                    predicate_matches=predicate_matches,
                )

        # All envelopes re-verified. Now check predicates.
        unmatched = [eid for eid, idxs in predicate_matches.items() if not idxs]
        if unmatched:
            return VerifyResult(
                claim_id=claim.claim_id,
                verdict=VerifyVerdict.QUARANTINED,
                reason=(
                    f"envelopes verified but predicate(s) did not match any record(s) in: "
                    f"{unmatched}. Surfacing as 'suspected but unproven'."
                ),
                envelope_verdicts=envelope_verdicts,
                predicate_matches=predicate_matches,
            )

        return VerifyResult(
            claim_id=claim.claim_id,
            verdict=VerifyVerdict.VERIFIED,
            reason="all envelopes re-verified and all predicates matched ≥1 record each.",
            envelope_verdicts=envelope_verdicts,
            predicate_matches=predicate_matches,
        )

    def verify_batch(self, claims: list[AgentClaim]) -> list[VerifyResult]:
        return [self.verify(c) for c in claims]


__all__ = [
    "ReverifyFn",
    "ReverifyRegistry",
    "WitnessOathVerifier",
    "default_registry",
]
