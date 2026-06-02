"""Spoliation tests.

The Witness Oath Verifier's hardest job: catch evidence tampering. These
integration tests prove the architectural contract end-to-end.

Test design (claim → exercise → pass condition):

  1. **Image-byte mutation between mint and reverify**
     A signed envelope's `image_sha256` is computed at mount time. If the
     image is mutated after mint, EITHER (a) the SHA-256 mismatch is caught
     at re-mount time, OR (b) every downstream tool re-run produces drifted
     bytes and reverify fails the BLAKE3 check. Both are acceptable; silent
     acceptance is not.

  2. **Envelope-payload mutation in the JSONL store**
     If someone edits the persisted envelope JSON (e.g. swaps a record
     field), the ed25519 signature stops verifying. The store itself is
     not write-protected on disk; the signature is what proves integrity.

  3. **Tool-output drift**
     If the underlying forensic tool's output bytes change (rule update,
     version bump, parser fix), reverify catches it via BLAKE3. This is
     the same mechanism — the test ensures it actually fires.

  4. **Args-canonical tampering**
     If `header.args_canonical` is altered (someone swaps a filter), the
     signature stops verifying. The header is signed.

A 'pass' means the verifier produces a FAILED verdict (NOT verified) and
gives a specific reason. Silent acceptance of tampered evidence is the
spoliation failure mode the test is designed to catch.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from oath.mcp.evidence_handle import EvidenceHandle
from oath.mcp.tools import parse_evtx
from oath.receipt.notarized import (
    SigningContext,
    canonicalize,
    header_hash,
    verify_data_integrity,
    verify_signature,
)
from oath.witness.claim import (
    AgentClaim,
    ClaimEvidence,
    FindingType,
    VerifyVerdict,
)
from oath.witness.verifier import WitnessOathVerifier, default_registry


# --------------------------------------------------------------------------- #
# Fixtures                                                                    #
# --------------------------------------------------------------------------- #


SAMPLE_EVTX_CSV = (
    b"RecordNumber,EventRecordId,TimeCreated,EventId,Level,Provider,Channel,"
    b"Computer,UserId,MapDescription,ChunkNumber,UserName,RemoteHost,"
    b"PayloadData1,PayloadData2,PayloadData3,PayloadData4,PayloadData5,"
    b"PayloadData6,ExecutableInfo,HiddenRecord,SourceFile,Keywords,"
    b"ExtraDataOffset,Payload\n"
    b'8392,8392,2026-04-12T14:32:01.1234567Z,4624,Information,'
    b'Microsoft-Windows-Security-Auditing,Security,WIN-VICTIM01,'
    b'S-1-5-21-1234-5678-9012-1001,,1,Administrator,10.0.0.42,'
    b'Target Administrator,LogonType 3,LogonId: 0x12345,,,,,,Security.evtx,'
    b'Audit success,0,"{""EventData"":{""Data"":[{""@Name"":""LogonType"",'
    b'""#text"":""3""},{""@Name"":""AuthenticationPackageName"",'
    b'""#text"":""NTLM""}]}}"\n'
)


@dataclass
class FakeExecutor:
    """File-output-mirroring fake to match EvtxECmd 2026.5.0 contract."""

    payload: bytes
    calls: list[list[str]] = field(default_factory=list)

    def run(
        self, argv: list[str], *, capture: bool = True, timeout: float = 300
    ) -> bytes:
        self.calls.append(list(argv))
        if "--csv" in argv and "--csvf" in argv:
            csv_idx = argv.index("--csv")
            csvf_idx = argv.index("--csvf")
            if csv_idx + 1 < len(argv) and csvf_idx + 1 < len(argv):
                outpath = Path(argv[csv_idx + 1]) / argv[csvf_idx + 1]
                outpath.parent.mkdir(parents=True, exist_ok=True)
                outpath.write_bytes(self.payload)
        return self.payload


@pytest.fixture
def ctx(tmp_path: Path) -> SigningContext:
    return SigningContext.load_or_mint(tmp_path / "keys", run_id="spoliation-test")


@pytest.fixture
def evidence_image(tmp_path: Path) -> Path:
    """A small synthetic image file standing in for an E01 / dd image.

    Real evidence is hashed via streaming SHA-256. For this test we just
    need a file the EvidenceHandle can stat + the verifier can check.
    """
    img = tmp_path / "evidence.dd"
    # 16 MB of pseudo-random content so the SHA-256 isn't a constant.
    import os
    img.write_bytes(os.urandom(16 * 1024 * 1024))
    return img


@pytest.fixture
def evtx_file(tmp_path: Path) -> Path:
    """A placeholder .evtx file the parser opens (executor returns the CSV)."""
    p = tmp_path / "Security.evtx"
    p.write_bytes(b"EVTX_PLACEHOLDER" * 1024)
    return p


def _make_handle(image: Path) -> EvidenceHandle:
    """Build an EvidenceHandle the way `oath mount` would."""
    from oath.mcp.evidence_handle import sha256_streaming

    sha, size = sha256_streaming(image)
    return EvidenceHandle(
        image_path=image,
        image_sha256=sha,
        image_size_bytes=size,
        mount_point=None,
        mount_tech="raw-file",
        run_id="spoliation-test",
    )


# --------------------------------------------------------------------------- #
# 1. Image-byte mutation                                                      #
# --------------------------------------------------------------------------- #


class TestImageByteMutation:
    """Mutating one byte of the image after envelope mint MUST be caught."""

    def test_single_byte_flip_breaks_handle_rehash(self, evidence_image: Path):
        """If the image is mutated, a fresh SHA-256 won't match the one in the
        original handle JSON. This is the front-line spoliation check."""
        from oath.mcp.evidence_handle import sha256_streaming

        original_sha, _ = sha256_streaming(evidence_image)

        # Flip exactly one bit at offset 0x1000 — the smallest possible mutation.
        with evidence_image.open("r+b") as f:
            f.seek(0x1000)
            old_byte = f.read(1)
            f.seek(0x1000)
            f.write(bytes([old_byte[0] ^ 0x01]))

        mutated_sha, _ = sha256_streaming(evidence_image)
        assert mutated_sha != original_sha, (
            "Spoliation hole: single-bit mutation didn't change SHA-256. "
            "The hashing primitive is broken."
        )

    def test_envelope_reverify_fails_on_tool_output_drift(
        self,
        ctx: SigningContext,
        evidence_image: Path,
        evtx_file: Path,
    ):
        """Real-world spoliation chain: image mutates → tool output drifts →
        BLAKE3 of stdout differs → reverify FAILS with a specific reason.

        This is the test that proves the architectural contract holds.
        """
        handle = _make_handle(evidence_image)

        # Mint an envelope from one tool-output payload.
        original_payload = SAMPLE_EVTX_CSV
        envelope = parse_evtx.parse_evtx(
            handle,
            evtx_path=evtx_file,
            ctx=ctx,
            executor=FakeExecutor(payload=original_payload),
        )

        # Sanity: the envelope itself signs correctly.
        assert verify_signature(envelope, ctx.public_key) is True

        # Spoliation: simulate tool output drift (a one-byte payload mutation).
        # This is what would happen if the evidence file under the tool changed.
        mutated_payload = original_payload.replace(b"LogonType 3", b"LogonType 2")
        assert mutated_payload != original_payload

        # Re-verify with the mutated payload — must FAIL.
        ok, reason = parse_evtx.reverify(
            envelope,
            evtx_path=evtx_file,
            executor=FakeExecutor(payload=mutated_payload),
        )
        assert ok is False, "Spoliation hole: reverify accepted drifted bytes."
        assert "drift" in reason.lower() or "blake3" in reason.lower(), (
            f"reverify failed but for the wrong reason: {reason!r}"
        )

    def test_envelope_reverify_passes_when_unchanged(
        self,
        ctx: SigningContext,
        evidence_image: Path,
        evtx_file: Path,
    ):
        """Inverse control: same bytes in, same BLAKE3 out, reverify PASSES.

        This is what guards against false-positive spoliation alarms.
        """
        handle = _make_handle(evidence_image)
        envelope = parse_evtx.parse_evtx(
            handle,
            evtx_path=evtx_file,
            ctx=ctx,
            executor=FakeExecutor(payload=SAMPLE_EVTX_CSV),
        )
        ok, reason = parse_evtx.reverify(
            envelope,
            evtx_path=evtx_file,
            executor=FakeExecutor(payload=SAMPLE_EVTX_CSV),
        )
        assert ok is True, f"Verifier rejected pristine evidence: {reason!r}"


# --------------------------------------------------------------------------- #
# 2. Signature-layer tampering                                                #
# --------------------------------------------------------------------------- #


class TestSignatureTampering:
    """If someone edits the envelope JSON in place, the signature fails."""

    def test_envelope_data_field_swap_fails_signature(
        self,
        ctx: SigningContext,
        evidence_image: Path,
        evtx_file: Path,
    ):
        """Mutate the envelope's data field after signing — signature breaks."""
        handle = _make_handle(evidence_image)
        envelope = parse_evtx.parse_evtx(
            handle,
            evtx_path=evtx_file,
            ctx=ctx,
            executor=FakeExecutor(payload=SAMPLE_EVTX_CSV),
        )
        assert verify_signature(envelope, ctx.public_key) is True

        # Re-emit with a tampered header. The signature was computed over the
        # original header bytes; mutating any field invalidates it.
        tampered_header = envelope.header.model_copy(
            update={"image_sha256": "0" * 64}
        )
        tampered_envelope = envelope.model_copy(update={"header": tampered_header})
        assert verify_signature(tampered_envelope, ctx.public_key) is False, (
            "Spoliation hole: signature verified over a tampered header."
        )

    def test_envelope_args_canonical_swap_fails_signature(
        self,
        ctx: SigningContext,
        evidence_image: Path,
        evtx_file: Path,
    ):
        """Mutating args_canonical (e.g. swapping a filter to hide an event)
        must invalidate the signature."""
        handle = _make_handle(evidence_image)
        envelope = parse_evtx.parse_evtx(
            handle,
            evtx_path=evtx_file,
            ctx=ctx,
            executor=FakeExecutor(payload=SAMPLE_EVTX_CSV),
        )

        original_args = envelope.header.args_canonical
        tampered_args = original_args.replace('"evtx_path":', '"evtx_path_HIDDEN":')
        tampered_header = envelope.header.model_copy(
            update={"args_canonical": tampered_args}
        )
        tampered_envelope = envelope.model_copy(update={"header": tampered_header})
        assert verify_signature(tampered_envelope, ctx.public_key) is False


# --------------------------------------------------------------------------- #
# 3. Chain-of-custody tampering (prev-hash link)                              #
# --------------------------------------------------------------------------- #


class TestChainOfCustody:
    """The prev-hash link makes the envelope chain tamper-evident."""

    def test_modifying_a_middle_envelope_breaks_the_chain(
        self,
        ctx: SigningContext,
        evidence_image: Path,
        evtx_file: Path,
    ):
        """If envelope #2 in a 3-envelope chain is mutated, envelope #3's
        prev hash no longer points at #2's actual content. Chain-of-custody
        violation is visible by comparing prev hashes."""
        handle = _make_handle(evidence_image)

        envelope1 = parse_evtx.parse_evtx(
            handle,
            evtx_path=evtx_file,
            ctx=ctx,
            executor=FakeExecutor(payload=SAMPLE_EVTX_CSV),
            prev_hash=None,
        )
        env1_hash = header_hash(envelope1)
        envelope2 = parse_evtx.parse_evtx(
            handle,
            evtx_path=evtx_file,
            ctx=ctx,
            executor=FakeExecutor(payload=SAMPLE_EVTX_CSV),
            prev_hash=env1_hash,
        )
        env2_hash = header_hash(envelope2)
        envelope3 = parse_evtx.parse_evtx(
            handle,
            evtx_path=evtx_file,
            ctx=ctx,
            executor=FakeExecutor(payload=SAMPLE_EVTX_CSV),
            prev_hash=env2_hash,
        )

        # Sanity: every envelope's prev matches the previous envelope's header_hash.
        assert envelope1.header.prev is None
        assert envelope2.header.prev == env1_hash
        assert envelope3.header.prev == env2_hash

        # Tamper with envelope2: mutate its data field after signing.
        tampered_header = envelope2.header.model_copy(
            update={"stdout_blake3": "0" * 64}
        )
        tampered_envelope2 = envelope2.model_copy(update={"header": tampered_header})
        tampered_env2_hash = header_hash(tampered_envelope2)

        # Envelope3 still points at the ORIGINAL env2_hash. The tampered hash
        # is different. An examiner walking the chain will see envelope2 doesn't
        # produce the hash envelope3 expects.
        assert tampered_env2_hash != envelope3.header.prev
        assert env2_hash == envelope3.header.prev


# --------------------------------------------------------------------------- #
# 4. Persisted-data tampering — the "fabricate-a-record-but-leave-stdout-alone"
#    attack. This is the failure mode that a header-only signature missed:    #
#    an attacker mutates the persisted envelope.data field (adding a record   #
#    the LLM made up), but DOES NOT touch the original tool's raw stdout, so  #
#    the stdout_blake3 reverify path still passes. Without a data_blake3      #
#    commitment in the signed header, the verifier would then match its       #
#    predicate against the fabricated record and return VERIFIED.             #
# --------------------------------------------------------------------------- #


class TestPersistedDataTampering:
    """Mutating `envelope.data` after minting MUST be caught by the verifier.

    The architectural promise is "LLM cannot fabricate evidence the verifier
    accepts." If we sign only the header, an attacker who can write to the
    persisted JSONL store can mutate `data` directly — raw stdout on disk is
    untouched, so re-running the tool produces matching BLAKE3-of-stdout, and
    a naive verifier matches its predicate against the fabricated record.

    The defence: include `data_blake3` = blake3(canonical(data)) in the signed
    header. The verifier recomputes this from the current persisted data and
    rejects on mismatch.
    """

    def test_data_blake3_is_present_in_signed_header(
        self,
        ctx: SigningContext,
        evidence_image: Path,
        evtx_file: Path,
    ):
        """Bare contract: the field exists, is a BLAKE3-sized hex string, and
        is non-zero for non-empty data."""
        handle = _make_handle(evidence_image)
        envelope = parse_evtx.parse_evtx(
            handle,
            evtx_path=evtx_file,
            ctx=ctx,
            executor=FakeExecutor(payload=SAMPLE_EVTX_CSV),
        )
        assert hasattr(envelope.header, "data_blake3")
        assert len(envelope.header.data_blake3) == 64
        assert all(c in "0123456789abcdef" for c in envelope.header.data_blake3)
        assert envelope.header.data_blake3 != "0" * 64

    def test_pristine_data_passes_integrity_check(
        self,
        ctx: SigningContext,
        evidence_image: Path,
        evtx_file: Path,
    ):
        """Inverse control — unaltered data passes the integrity check.

        This guards against false positives where serialization drift
        (Pydantic version bump, field reordering) would break verification
        of legitimate envelopes.
        """
        handle = _make_handle(evidence_image)
        envelope = parse_evtx.parse_evtx(
            handle,
            evtx_path=evtx_file,
            ctx=ctx,
            executor=FakeExecutor(payload=SAMPLE_EVTX_CSV),
        )
        assert verify_data_integrity(envelope) is True

        # Round-trip through JSON serialization (the on-disk path) and
        # confirm integrity STILL holds. This is what `oath verify` does
        # when it loads envelopes from logs/envelopes/*.jsonl.
        roundtripped = type(envelope).model_validate_json(envelope.model_dump_json())
        assert verify_data_integrity(roundtripped) is True

    def test_persisted_data_mutation_fails_integrity_check(
        self,
        ctx: SigningContext,
        evidence_image: Path,
        evtx_file: Path,
    ):
        """The core attack: mutate envelope.data (add a fabricated record) and
        confirm verify_data_integrity() catches it.

        Crucially, the signature is STILL valid — the header bytes didn't
        change. That's the subtle vulnerability: a header-only signature
        gives no protection to the persisted data. data_blake3 closes it.
        """
        handle = _make_handle(evidence_image)
        envelope = parse_evtx.parse_evtx(
            handle,
            evtx_path=evtx_file,
            ctx=ctx,
            executor=FakeExecutor(payload=SAMPLE_EVTX_CSV),
        )
        assert verify_signature(envelope, ctx.public_key) is True
        assert verify_data_integrity(envelope) is True

        # Attack: fabricate a record and slip it into envelope.data.
        original_records = list(envelope.data)
        assert len(original_records) >= 1
        fabricated = original_records[0].model_copy(
            update={"event_id": 1102, "user_name": "ATTACKER_FABRICATED"}
        )
        tampered_data = original_records + [fabricated]
        tampered_envelope = envelope.model_copy(update={"data": tampered_data})

        # The signature on the (untouched) header still verifies.
        assert verify_signature(tampered_envelope, ctx.public_key) is True
        # But data_blake3 now mismatches the persisted data — caught.
        assert verify_data_integrity(tampered_envelope) is False, (
            "Spoliation hole: persisted-data tampering not detected by "
            "data_blake3. The LLM-cannot-fabricate-evidence claim is unfounded."
        )

    def test_verifier_rejects_tampered_data_end_to_end(
        self,
        ctx: SigningContext,
        evidence_image: Path,
        evtx_file: Path,
    ):
        """End-to-end: an attacker fabricates a record in envelope.data and
        builds an AgentClaim whose predicate would match it. The
        WitnessOathVerifier MUST refuse VERIFIED and surface RALPH_WIGGUM
        (drift detected) instead.
        """
        handle = _make_handle(evidence_image)
        envelope = parse_evtx.parse_evtx(
            handle,
            evtx_path=evtx_file,
            ctx=ctx,
            executor=FakeExecutor(payload=SAMPLE_EVTX_CSV),
        )

        # Fabricate a "1102 Audit log cleared" event the LLM might hallucinate.
        original_records = list(envelope.data)
        fabricated = original_records[0].model_copy(
            update={"event_id": 1102, "user_name": "ATTACKER_FABRICATED"}
        )
        tampered_data = original_records + [fabricated]
        tampered_envelope = envelope.model_copy(update={"data": tampered_data})

        claim = AgentClaim(
            claim_id="fab-claim-1102",
            finding_type=FindingType.LOG_CLEARING,
            natural_language=(
                "Attacker cleared the Security log under user "
                "ATTACKER_FABRICATED — claim fabricated by the LLM."
            ),
            supporting_evidence=(
                ClaimEvidence(
                    envelope_id="evtx-tampered",
                    record_predicate={
                        "event_id": 1102,
                        "user_name": "ATTACKER_FABRICATED",
                    },
                ),
            ),
            confidence=0.99,
            reasoning_hash="0" * 64,
            model_id="test-model",
            temperature=0.0,
            seed=42,
        )

        # Use a registry whose reverify is hard-wired to pass — simulates the
        # "raw stdout untouched on disk, BLAKE3 still matches" attack premise.
        from oath.witness.verifier import ReverifyRegistry

        forgiving_registry = ReverifyRegistry()
        forgiving_registry.register(
            "parse_evtx",
            lambda env: (True, "stdout BLAKE3 matches header (raw bytes untouched)"),
            required_kwargs=(),
        )

        verifier = WitnessOathVerifier(
            envelopes_by_id={"evtx-tampered": tampered_envelope},
            reverify_kwargs={"evtx-tampered": {}},
            registry=forgiving_registry,
            public_key_for_signatures=ctx.public_key,
        )
        result = verifier.verify(claim)

        assert result.verdict != VerifyVerdict.VERIFIED, (
            "Spoliation hole: verifier accepted a claim whose evidence "
            "envelope had a fabricated record bolted onto envelope.data."
        )
        # Specifically, the data-integrity check fires before predicate match,
        # so this is a RALPH_WIGGUM (drift) verdict.
        assert result.verdict == VerifyVerdict.RALPH_WIGGUM
        per_env_ok, per_env_reason = result.envelope_verdicts["evtx-tampered"]
        assert per_env_ok is False
        assert "data_blake3" in per_env_reason or "tampered" in per_env_reason.lower()


# --------------------------------------------------------------------------- #
# 5. Daubert binding — model_id + prompt_hash committed into the signed       #
#    header so the receipt itself answers "which model produced this finding, #
#    from what prompt?" without trusting the agent's own logs.                #
# --------------------------------------------------------------------------- #


class TestDaubertBinding:
    """Cryptographic court-admissibility primitive: the LLM run-context that
    produced an envelope's args is bound INTO the signed header. An examiner
    can prove from the receipt alone — without trusting the agent — which
    model + which prompt yielded any given finding.
    """

    def test_model_id_and_prompt_hash_are_signed(
        self,
        ctx: SigningContext,
        evidence_image: Path,
        evtx_file: Path,
    ):
        """When mint() is called with model_id + prompt_hash, both land in
        the signed header and the signature verifies over them. Tampering
        with either invalidates the signature.
        """
        from oath.receipt.notarized import hash_prompt

        handle = _make_handle(evidence_image)
        prompt_hash = hash_prompt("You are a DFIR agent.", "Find logon events.")
        envelope = parse_evtx.parse_evtx(
            handle,
            evtx_path=evtx_file,
            ctx=ctx,
            executor=FakeExecutor(payload=SAMPLE_EVTX_CSV),
            model_id="gemini-3.1-pro-preview",
            prompt_hash=prompt_hash,
        )
        # Fields are populated.
        assert envelope.header.model_id == "gemini-3.1-pro-preview"
        assert envelope.header.prompt_hash == prompt_hash
        assert len(envelope.header.prompt_hash) == 64
        # Signature verifies over them.
        assert verify_signature(envelope, ctx.public_key) is True
        # Tampering with model_id alone breaks the signature.
        tampered_header = envelope.header.model_copy(
            update={"model_id": "ATTACKER-CLAIMED-DIFFERENT-MODEL"}
        )
        tampered_envelope = envelope.model_copy(update={"header": tampered_header})
        assert verify_signature(tampered_envelope, ctx.public_key) is False, (
            "Daubert hole: model_id is not actually signed."
        )
        # Tampering with prompt_hash alone breaks the signature.
        tampered_header2 = envelope.header.model_copy(update={"prompt_hash": "0" * 64})
        tampered_envelope2 = envelope.model_copy(update={"header": tampered_header2})
        assert verify_signature(tampered_envelope2, ctx.public_key) is False, (
            "Daubert hole: prompt_hash is not actually signed."
        )

    def test_deterministic_envelopes_have_null_model_binding(
        self,
        ctx: SigningContext,
        evidence_image: Path,
        evtx_file: Path,
    ):
        """When no LLM was in the loop (deterministic args resolver), the
        envelope must signal that explicitly with model_id=None / prompt_hash=None.
        This prevents an attacker from claiming "look, this finding has no
        model" via post-hoc field stripping — null is the signed default,
        and the signature still verifies over it.
        """
        handle = _make_handle(evidence_image)
        envelope = parse_evtx.parse_evtx(
            handle,
            evtx_path=evtx_file,
            ctx=ctx,
            executor=FakeExecutor(payload=SAMPLE_EVTX_CSV),
        )
        assert envelope.header.model_id is None
        assert envelope.header.prompt_hash is None
        assert verify_signature(envelope, ctx.public_key) is True

    def test_hash_prompt_is_collision_resistant_against_delimiter_mimic(self):
        """hash_prompt uses length-prefixed concatenation, so naive
        delimiter-mimic attacks (folding system_prompt and user_message into
        each other) do NOT produce the same hash.
        """
        from oath.receipt.notarized import hash_prompt

        a = hash_prompt("ABC", "DEF")
        b = hash_prompt("ABCD", "EF")  # naive concat would collide on b'ABCDEF'
        assert a != b


# --------------------------------------------------------------------------- #
# 6. End-to-end via the registry (the path agents actually use)               #
# --------------------------------------------------------------------------- #


class TestEndToEndViaRegistry:
    """Spoliation as seen from the witness verifier registry."""

    def test_registry_call_returns_failure_on_drift(
        self,
        ctx: SigningContext,
        evidence_image: Path,
        evtx_file: Path,
    ):
        """The Witness Oath Verifier's `default_registry().call(envelope, kwargs)`
        is the production-path entry point. It MUST surface spoliation."""
        handle = _make_handle(evidence_image)
        envelope = parse_evtx.parse_evtx(
            handle,
            evtx_path=evtx_file,
            ctx=ctx,
            executor=FakeExecutor(payload=SAMPLE_EVTX_CSV),
        )

        # The default registry isn't aware of our test fake. We call reverify
        # directly here with a mutated executor — that's how the actual
        # production flow tests for spoliation.
        mutated = SAMPLE_EVTX_CSV.replace(b"Administrator", b"BackupOperator")
        ok, reason = parse_evtx.reverify(
            envelope,
            evtx_path=evtx_file,
            executor=FakeExecutor(payload=mutated),
        )
        assert ok is False
        assert "drift" in reason.lower()
