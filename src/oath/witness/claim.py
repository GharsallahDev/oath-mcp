"""AgentClaim — the structured shape an LLM finding must take to be considered for promotion.

The Witness Oath Verifier (verifier.py) consumes AgentClaim instances. The LLM
never gets a path to ship a finding without one — the autonomous agent loop
wraps every LLM emission in this envelope, refusing to ship raw text.

Design intent
-------------
Most "AI hallucinates" failure modes in DFIR look like this:

   LLM: "the attacker used Pass-the-Hash against the DC at 14:32:01"
   Reality: there is no 4624 with LogonType=3 + NTLM at 14:32:01 in the EVTX.
            The LLM invented the time, the auth method, or both.

AgentClaim forces the LLM to expose its reasoning as a set of STRUCTURED
PREDICATES that point at specific Notarized envelopes:

   {
     finding_type: "T1550.002_candidate",
     supporting_evidence: [
       { envelope_id: "evtx-001",
         record_predicate: {"event_id": 4624, "logon_type": 3,
                            "auth_package": "NTLM",
                            "timestamp": "2026-04-12T14:32:01Z"} },
       { envelope_id: "amcache-001",
         record_predicate: {"name": "psexesvc.exe"} }
     ]
   }

The Verifier checks each predicate against the corresponding envelope's `data`
field — a subset-match operation that's deterministic and non-LLM. If ANY
predicate fails to match a record, the claim is QUARANTINED (visible to the
examiner as "the agent thought this but couldn't prove it") and the agent
enters the Ralph Wiggum Loop.

The model_id / temperature / seed are bound for reproducibility — the same
model + same prompts + same seed should produce the same claims, so a
verifier can replay the agent's reasoning later.
"""
from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class ClaimEvidence(BaseModel):
    """A pointer from a claim to one Notarized envelope + a record predicate.

    The `record_predicate` is a key/value dict that must be a SUBSET match of
    at least one record in `envelope.data`. Subset-match means: for each
    (key, value) in the predicate, that key exists on the record and equals
    the value. This is straightforwardly checkable and forgery-resistant —
    the LLM cannot satisfy a predicate by hallucinating data; it can only
    point at records that genuinely exist in the structured tool output.
    """

    model_config = ConfigDict(frozen=True)

    envelope_id: str = Field(..., description="ID of the Notarized envelope this claim cites.")
    record_predicate: dict[str, Any] = Field(
        ..., description="Subset-match predicate to apply to envelope.data records."
    )

    @field_validator("record_predicate")
    @classmethod
    def predicate_must_be_nonempty(cls, v: dict[str, Any]) -> dict[str, Any]:
        if not v:
            raise ValueError(
                "record_predicate must be non-empty — pointing at an envelope without "
                "specifying which record(s) you mean is not a verifiable claim."
            )
        return v


class FindingType(str, Enum):
    """Closed-set finding types the agent can emit.

    Closing the set is deliberate: the LLM can't invent new finding types in
    prompt space. Adding a new type requires a code change AND (usually) a
    new deterministic detector somewhere in the tools layer.
    """

    # Lateral movement / credential abuse
    PTH_CANDIDATE = "T1550.002_pass_the_hash_candidate"
    PTT_CANDIDATE = "T1550.003_pass_the_ticket_candidate"
    KERBEROAST_CANDIDATE = "T1558.003_kerberoasting_candidate"
    OPTH_CANDIDATE = "T1550.002_overpass_the_hash_candidate"

    # Persistence
    REGISTRY_RUN_KEY = "T1547.001_registry_run_key"
    SCHEDULED_TASK = "T1053.005_scheduled_task"
    HIDDEN_SCHEDULED_TASK = "T1053.005_hidden_scheduled_task_tarrask"

    # Defense evasion / anti-forensics
    LOG_CLEARING = "T1070.001_log_clearing"
    TIMESTOMP = "T1070.006_timestomp_candidate"
    EVTX_RECORDID_GAP = "T1070.001_evtx_recordid_gap"

    # Credential access
    LSASS_DUMP_CANDIDATE = "T1003.001_lsass_dump_candidate"
    SAM_DUMP_CANDIDATE = "T1003.002_sam_dump_candidate"

    # Execution
    SUSPICIOUS_EXECUTION = "execution_residue_suspicious"

    # Catch-all for the agent's narrative findings; carries supporting evidence
    # but isn't tied to a specific ATT&CK technique.
    NARRATIVE = "narrative_inference"


class AgentClaim(BaseModel):
    """One claim the agent makes after a tool call cycle.

    Lifecycle:
      DRAFT — emitted by the LLM, not yet verified.
      VERIFIED — passed the Witness Oath Verifier (all evidence valid, all
                 predicates matched). Eligible for shipping in the final report.
      QUARANTINED — predicates didn't match the cited envelopes. Visible to the
                    examiner but NOT shipped as a finding. Surfaces as "agent
                    suspected but couldn't prove."
      RALPH_WIGGUM — envelope tampered with or reverify failed. Triggers the
                     visible self-correction loop; the agent must abandon this
                     hypothesis and re-propose with a constraint.
    """

    model_config = ConfigDict(frozen=True)

    claim_id: str = Field(..., description="Unique ID for this claim (UUID hex).")
    finding_type: FindingType
    natural_language: str = Field(
        ..., description="Human-readable summary; the examiner reads this in the report."
    )
    supporting_evidence: tuple[ClaimEvidence, ...] = Field(
        ..., min_length=1, description="At least one cited envelope + predicate."
    )

    # Reasoning provenance
    confidence: float = Field(
        ..., ge=0.0, le=1.0, description="Agent's self-reported confidence; calibrated later."
    )
    reasoning_hash: str = Field(
        ..., description="BLAKE3 of the LLM's chain-of-thought that led to this claim."
    )

    # Reproducibility binding (so the verifier can replay the agent's run)
    model_id: str = Field(..., description="Model identifier (e.g. 'claude-opus-4-7').")
    temperature: float = Field(..., ge=0.0, le=2.0)
    seed: int


class VerifyVerdict(str, Enum):
    """The Witness Oath Verifier's output classification for one claim."""

    VERIFIED = "verified"
    QUARANTINED = "quarantined"
    RALPH_WIGGUM = "ralph_wiggum"  # tool drift detected — agent must self-correct


class VerifyResult(BaseModel):
    """One claim's verification outcome — what the examiner sees in the audit trail."""

    model_config = ConfigDict(frozen=True)

    claim_id: str
    verdict: VerifyVerdict
    reason: str = Field(..., description="Human-readable explanation of the verdict.")
    envelope_verdicts: dict[str, tuple[bool, str]] = Field(
        default_factory=dict,
        description="Per-envelope reverify() results: envelope_id -> (ok, reason).",
    )
    predicate_matches: dict[str, list[int]] = Field(
        default_factory=dict,
        description="Per-envelope record indices that satisfied the predicate.",
    )


__all__ = [
    "AgentClaim",
    "ClaimEvidence",
    "FindingType",
    "VerifyResult",
    "VerifyVerdict",
]
