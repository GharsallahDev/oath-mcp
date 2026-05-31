"""Notarized[T] — the cryptographic envelope every tool output is wrapped in.

A `Notarized[T]` envelope binds an arbitrary tool result `T` to:

  - the SHA-256 of the source evidence image (so the binding is anchored to the
    SPECIFIC evidence; replaying against a different image will fail by design)
  - the tool name AND version (pinned across the project; the verifier rejects
    receipts produced under a different version because output schemas drift)
  - the canonical argument vector (RFC 8785 JCS — JSON canonicalization — so
    two semantically-equivalent argument orderings produce identical hashes)
  - the BLAKE3 hash of the raw tool stdout (cheap, fast, collision-resistant
    where SHA-256 is overkill for ~MB-class tool outputs)
  - the byte offsets in the source image of every artifact the tool surfaced
    (the Replay Receipt re-extracts those bytes and shows the examiner)
  - an ed25519 signature over the union of the above + a monotonic timestamp +
    a `prev` field pointing at the previous receipt's hash (forming a hash chain
    across the run, so any tampering anywhere in the manifest is detectable
    locally and globally)

The signing key is per-installation (generated on first `oath mount`) and stored
in `./keys/oath.key` mode 0600. The public key (`./keys/oath.pub`) is committed
alongside the manifest so any third party can verify without the private key.

Design intent: the envelope is the smallest unit on which the Witness Oath
Verifier operates. The LLM never constructs a Notarized envelope directly; only
the typed MCP functions can mint one. This means a hallucinated finding the LLM
fabricates cannot be smuggled into the evidence graph — it has no envelope, and
the agent's ship() function refuses to emit findings without one.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Generic, TypeVar

import blake3
from nacl import signing
from nacl.encoding import URLSafeBase64Encoder
from pydantic import BaseModel, ConfigDict, Field

T = TypeVar("T")


# --------------------------------------------------------------------------- #
# Public schema (the wire format every typed function emits)                  #
# --------------------------------------------------------------------------- #


class EvidenceOffset(BaseModel):
    """A pointer to a span in the source image.

    Using byte offsets (rather than file paths) means the Replay Receipt is
    robust to forensic-tool versions that rename or relocate parsed artifacts
    in their intermediate representations — the offset into the *original*
    image is the ground truth.
    """

    model_config = ConfigDict(frozen=True)

    start: int = Field(..., ge=0, description="Inclusive byte offset in the source image.")
    length: int = Field(..., gt=0, description="Number of bytes the artifact spans.")
    # Optional human-readable artifact identifier for the examiner (e.g.
    # "$MFT entry 12345" or "EVTX EventRecordID 8392"). Never used for
    # verification — verification is purely byte-level.
    artifact_label: str | None = None


class NotarizedHeader(BaseModel):
    """The signed header of a Notarized envelope.

    Everything except `sig` is canonicalized via RFC 8785 JCS before signing.
    """

    model_config = ConfigDict(frozen=True)

    # What was run
    tool_name: str = Field(..., description="The typed-function name (e.g. 'parse_evtx').")
    tool_version: str = Field(..., description="Pinned tool version (read from lockfile).")
    args_canonical: str = Field(
        ..., description="RFC 8785 JCS canonicalization of the call arguments."
    )

    # What it was run against
    image_sha256: str = Field(
        ..., min_length=64, max_length=64, description="SHA-256 of the source evidence image."
    )

    # What it produced
    stdout_blake3: str = Field(
        ..., min_length=64, max_length=64, description="BLAKE3 of the raw tool stdout."
    )
    offsets: tuple[EvidenceOffset, ...] = Field(
        default=(), description="Byte spans in the source image the result depends on."
    )

    # When and where in the chain
    ts: float = Field(..., description="Unix epoch seconds at envelope creation.")
    prev: str | None = Field(
        None,
        description="BLAKE3 of the previous receipt's signed header, or null for the first.",
    )

    # Provenance of the agent run that minted this (so a verifier can detect
    # cross-run mixing). NOT part of the security boundary — purely audit.
    run_id: str = Field(..., description="UUID for the agent run that minted this envelope.")


class Notarized(BaseModel, Generic[T]):
    """A tool result + its signed provenance envelope.

    `data` is the typed payload (e.g. `list[EvtxRecord]`, `list[MftEntry]`, ...).
    `header` is the signed metadata. `sig` is the ed25519 signature over
    canonical(header) — base64url-encoded, no padding.

    Verification: recompute canonical(header), check sig over it with the
    public key, then re-run the tool against the recorded image and confirm
    stdout_blake3 matches. ANY mismatch → the envelope is invalid.
    """

    model_config = ConfigDict(arbitrary_types_allowed=True)

    header: NotarizedHeader
    data: T
    sig: str = Field(..., description="ed25519 signature over canonical(header), base64url.")


# --------------------------------------------------------------------------- #
# Canonicalization (RFC 8785 JCS — JSON Canonicalization Scheme)              #
# --------------------------------------------------------------------------- #


def canonicalize(obj: Any) -> bytes:
    """Produce a deterministic byte representation of a JSON-serializable value.

    Implements RFC 8785 JCS — sorted keys, no whitespace, normalized number
    representation, UTF-8 output. Two semantically-equivalent dicts produce
    byte-identical output, which is what we sign over.

    We use json with sort_keys=True + separators=(',', ':') + ensure_ascii=False
    which matches the JCS spec for our subset of inputs (we don't serialize
    floats with exotic representations or NaN/Infinity — Pydantic catches those
    at construction time).
    """
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


# --------------------------------------------------------------------------- #
# Signing key management                                                      #
# --------------------------------------------------------------------------- #


@dataclass
class SigningContext:
    """Holds the per-run signing key + run identity.

    Keys live on disk at `keys/oath.key` (private, mode 0600) and `keys/oath.pub`
    (public, committed alongside any manifest). On first use, `ensure_key()` mints
    a fresh ed25519 keypair.
    """

    private_key: signing.SigningKey
    run_id: str

    @property
    def public_key(self) -> signing.VerifyKey:
        return self.private_key.verify_key

    @classmethod
    def load_or_mint(cls, key_dir: Path, run_id: str) -> SigningContext:
        """Load an existing key from `key_dir`, or mint and persist one."""
        key_dir.mkdir(parents=True, exist_ok=True)
        priv_path = key_dir / "oath.key"
        pub_path = key_dir / "oath.pub"
        if priv_path.exists():
            priv = signing.SigningKey(priv_path.read_bytes())
        else:
            priv = signing.SigningKey.generate()
            priv_path.write_bytes(priv.encode())
            priv_path.chmod(0o600)
            pub_path.write_bytes(priv.verify_key.encode())
        return cls(private_key=priv, run_id=run_id)


# --------------------------------------------------------------------------- #
# Minting and verification                                                    #
# --------------------------------------------------------------------------- #


def mint(
    *,
    data: T,
    tool_name: str,
    tool_version: str,
    args: dict[str, Any],
    image_sha256: str,
    stdout_bytes: bytes,
    offsets: tuple[EvidenceOffset, ...] = (),
    prev_hash: str | None,
    ctx: SigningContext,
) -> Notarized[T]:
    """Construct and sign a Notarized envelope for one tool invocation.

    Called exclusively by typed MCP functions after they execute their underlying
    forensic tool. The LLM has no direct path to this function — the MCP server
    enforces that envelopes are minted server-side from the tool's actual stdout,
    not from anything the LLM proposed.
    """
    if len(image_sha256) != 64 or not all(c in "0123456789abcdef" for c in image_sha256):
        raise ValueError(f"image_sha256 must be 64 hex chars: got {image_sha256!r}")

    header = NotarizedHeader(
        tool_name=tool_name,
        tool_version=tool_version,
        args_canonical=canonicalize(args).decode("utf-8"),
        image_sha256=image_sha256,
        stdout_blake3=blake3.blake3(stdout_bytes).hexdigest(),
        offsets=offsets,
        ts=time.time(),
        prev=prev_hash,
        run_id=ctx.run_id,
    )
    sig_bytes = ctx.private_key.sign(canonicalize(header.model_dump())).signature
    sig_b64 = URLSafeBase64Encoder.encode(sig_bytes).rstrip(b"=").decode("ascii")
    return Notarized[T](header=header, data=data, sig=sig_b64)


def verify_signature(envelope: Notarized[Any], pub_key: signing.VerifyKey) -> bool:
    """Verify the ed25519 signature over the envelope header.

    Returns True iff the signature is valid for `pub_key`. Does NOT re-run the
    tool or check stdout_blake3 — see `verify_full()` below for that.
    """
    canon = canonicalize(envelope.header.model_dump())
    sig_bytes = URLSafeBase64Encoder.decode(envelope.sig + "==")  # restore padding
    try:
        pub_key.verify(canon, sig_bytes)
    except Exception:
        return False
    return True


def header_hash(envelope: Notarized[Any]) -> str:
    """Hash of an envelope's signed header. Used as the `prev` field of the next."""
    return blake3.blake3(canonicalize(envelope.header.model_dump())).hexdigest()
