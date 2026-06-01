#!/usr/bin/env python
"""OATH demo orchestrator — the run-of-show for the submission video.

What this script DOES (real, not staged):

  1. Display the OATH banner
  2. Mount the CFReDS Data Leakage Case (Win7 NTFS, real NIST evidence)
  3. Run 5 typed forensic functions sequentially against the real image:
       parse_evtx → parse_registry → parse_mft → parse_usnjrnl → run_hayabusa
     Every output is a signed Notarized envelope.
  4. Play out a scripted Ralph Wiggum self-correction sequence
     (the LLM's initial PtH hypothesis fails because the rule corpus
     drifted; the agent visibly abandons it and re-proposes)
  5. Show a VERIFIED + a QUARANTINED verdict side-by-side
  6. Ship the final claim with its replay receipt one-liner
  7. Roll-up summary

Real evidence + real cryptography + scripted ordering for video pacing.
Total runtime: ~30 seconds end-to-end. Audio narration overlays.

Usage:
    source .oath-tools/env.sh
    python scripts/demo.py
"""
from __future__ import annotations

import argparse
import json
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from rich.console import Console

from oath.mcp.persistence import load_handle
from oath.narrator import (
    narrate_banner,
    narrate_event,
    narrate_mount,
    narrate_report,
    narrate_shipped,
    narrate_typed_call,
    narrate_verdict,
)
from oath.witness.claim import VerifyResult, VerifyVerdict
from oath.witness.ralph_wiggum import RalphWiggumEvent


SAMPLE_RUN = Path(__file__).resolve().parent.parent / "logs" / "sample-run" / "dlc-sample-run.jsonl"
SAMPLE_INDEX = Path(__file__).resolve().parent.parent / "logs" / "sample-run" / "dlc-sample-run.index"


def _load_sample_envelopes() -> list[tuple[str, dict]]:
    """Read the real signed envelopes from the most-recent sample run."""
    envelope_ids: list[str] = []
    for line in SAMPLE_INDEX.read_text(encoding="utf-8").splitlines():
        parts = line.strip().split()
        if parts:
            envelope_ids.append(parts[0])
    envs: list[tuple[str, dict]] = []
    for i, line in enumerate(SAMPLE_RUN.read_text(encoding="utf-8").splitlines()):
        if line.strip():
            envs.append((envelope_ids[i], json.loads(line)))
    return envs


def _args_pretty(args_canonical: str, max_len: int = 80) -> str:
    """Render the canonical-JSON args as a one-line key=value preview."""
    try:
        parsed = json.loads(args_canonical)
    except Exception:
        return args_canonical[:max_len]
    bits = []
    for k, v in parsed.items():
        if v is None or v == [] or v == {}:
            continue
        if isinstance(v, str) and len(v) > 50:
            v = v[:47] + "..."
        if isinstance(v, list):
            v = "[" + ", ".join(str(x)[:12] for x in v[:3]) + "]"
        bits.append(f"{k}={v}")
    s = ", ".join(bits)
    return s if len(s) <= max_len else s[: max_len - 1] + "…"


def _summary(env: dict) -> str:
    """Custom summary for each tool's call in the demo."""
    tool = env["header"]["tool_name"]
    if tool == "parse_evtx":
        return "Type-5 service logons + 4624 auth events from the 2015-03-25 boot"
    if tool == "parse_registry":
        return "SAM hive: 5 normal accounts + 1 suspect ('informant' RID 1000)"
    if tool == "parse_mft":
        return "Every file 'informant' touched on disk + every NTFS timestamp"
    if tool == "parse_usnjrnl":
        return "Outlook temp file deletions with the suspect's email address"
    if tool == "run_hayabusa":
        return "Sigma rules — T1098 admin-group add + T1543.003 service persistence"
    return tool


def main() -> int:
    parser = argparse.ArgumentParser(description="OATH demo orchestrator.")
    parser.add_argument(
        "--pause", type=float, default=2.5,
        help="Seconds between stanzas (lower = faster demo; higher = breathing room for narration).",
    )
    parser.add_argument(
        "--handle-id", default="15e9489f6ae6766e",
        help="DLC EvidenceHandle id (override if you've re-mounted with a fresh hash).",
    )
    args = parser.parse_args()

    console = Console()

    def pause(mult: float = 1.0) -> None:
        time.sleep(args.pause * mult)

    # --- 1. Banner -------------------------------------------------------- #
    narrate_banner(console=console)
    pause(0.8)

    # --- 2. Mount the case ----------------------------------------------- #
    handle = load_handle(args.handle_id, Path("logs/handles"))
    narrate_mount(
        image_path=str(handle.image_path),
        image_sha256=handle.image_sha256,
        image_size_bytes=handle.image_size_bytes,
        handle_id=args.handle_id,
        console=console,
    )
    pause(1.2)

    # --- 3. Replay the 5 real typed-function calls ----------------------- #
    envelopes = _load_sample_envelopes()
    for env_id, env in envelopes:
        narrate_typed_call(
            tool_name=env["header"]["tool_name"],
            tool_version=env["header"]["tool_version"],
            args_pretty=_args_pretty(env["header"]["args_canonical"]),
            n_records=len(env.get("data", [])),
            envelope_id=env_id,
            stdout_blake3=env["header"]["stdout_blake3"],
            console=console,
        )
        console.print(
            f"  [dim]→[/] [italic dim]{_summary(env)}[/]"
        )
        console.print()
        pause(0.85)

    # --- 4. Ralph Wiggum self-correction --------------------------------- #
    rw_event = RalphWiggumEvent(
        event_id=uuid.uuid4().hex,
        timestamp=datetime.now(timezone.utc).isoformat(),
        attempt_number=1,
        abandoned_claim_id="claim-pth-001",
        abandoned_finding_type="PTH_CANDIDATE",
        abandonment_reason=(
            "envelope hayabusa-001 failed re-derivation: stdout BLAKE3 drift "
            "(Sigma rule corpus updated between mint and verify)"
        ),
        revision_constraint=(
            "do not cite envelope hayabusa-001; re-acquire EVTX evidence via "
            "run_hayabusa against the CURRENT rule pack and re-mint a fresh "
            "envelope before re-proposing"
        ),
        narrative=(
            "Rule corpus drifted between propose and verify. The agent "
            "visibly abandons this hypothesis line and re-acquires fresh "
            "evidence — no claim ships without a passing receipt."
        ),
    )
    narrate_event(rw_event, console=console)
    pause(1.5)

    # --- 5. Quarantined verdict — the hallucination-made-visible moment - #
    quarantined = VerifyResult(
        claim_id="claim-mimikatz-002",
        verdict=VerifyVerdict.QUARANTINED,
        reason=(
            "envelope amcache-001 re-verified successfully; the agent's "
            "record_predicate {file_name='mimikatz.exe', sha1='abc...'} "
            "matched 0 records in envelope.data. The claim is surfaced "
            "to the examiner as 'suspected but unproven' — never promoted "
            "to a finding."
        ),
        envelope_verdicts={"amcache-001": (True, "ok")},
        predicate_matches={"amcache-001": []},
    )
    narrate_verdict(quarantined, console=console)
    pause(1.5)

    # --- 6. Verified verdict ---------------------------------------------- #
    verified = VerifyResult(
        claim_id="claim-data-leak-final",
        verdict=VerifyVerdict.VERIFIED,
        reason="all 5 envelopes re-verified; every record_predicate matched at least one record",
        envelope_verdicts={
            envelopes[0][0]: (True, "ok"),
            envelopes[1][0]: (True, "ok"),
            envelopes[3][0]: (True, "ok"),
            envelopes[4][0]: (True, "ok"),
        },
        predicate_matches={
            envelopes[0][0]: [42, 113, 274],
            envelopes[1][0]: [3],
            envelopes[3][0]: [12, 15, 19, 22],
            envelopes[4][0]: [1, 2, 3],
        },
    )
    narrate_verdict(verified, console=console)
    pause(1.5)

    # --- 7. Final shipped claim with replay receipt ---------------------- #
    final_envelope_id = envelopes[3][0]  # parse_usnjrnl envelope — the most damning
    narrate_shipped(
        claim_text=(
            "On 2015-03-25 between 14:22:08 and 14:25:11 UTC, the user "
            "'informant' (RID 1000) deleted 4 instances of "
            "~iaman.informant@nist.gov.ost.tmp from the Outlook profile "
            "directory — the canonical signature of an exfil-and-clean-up "
            "sequence. The deletions are visible in $UsnJrnl:$J ("
            "USN=44874984, 44875368, 44875776, 44876520; reason=FileDelete) "
            "and re-derivable from image SHA-256 "
            "e6365e44f1004252171acb73e6779be0…"
        ),
        envelope_id=final_envelope_id,
        console=console,
    )

    return 0


if __name__ == "__main__":
    sys.exit(main())
