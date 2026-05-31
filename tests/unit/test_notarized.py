"""Unit tests for src/oath/receipt/notarized.py.

These tests pin the canonical-form contract (RFC 8785 JCS) and the ed25519
sign/verify cycle — both of which are load-bearing for the Witness Oath
Verifier. If any of these regress, the Replay Receipt format breaks and the
submission's core architectural claim collapses.
"""
from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from oath.receipt.notarized import (
    EvidenceOffset,
    SigningContext,
    canonicalize,
    header_hash,
    mint,
    verify_signature,
)


# --------------------------------------------------------------------------- #
# Canonicalization                                                            #
# --------------------------------------------------------------------------- #


class TestCanonicalize:
    def test_dict_key_order_is_normalized(self) -> None:
        a = canonicalize({"b": 1, "a": 2})
        b = canonicalize({"a": 2, "b": 1})
        assert a == b
        assert a == b'{"a":2,"b":1}'

    def test_nested_dicts_are_normalized(self) -> None:
        a = canonicalize({"x": {"b": 1, "a": 2}})
        b = canonicalize({"x": {"a": 2, "b": 1}})
        assert a == b

    def test_whitespace_is_stripped(self) -> None:
        out = canonicalize({"a": 1, "b": 2})
        assert b" " not in out
        assert b"\n" not in out

    def test_nan_and_infinity_are_rejected(self) -> None:
        with pytest.raises(ValueError):
            canonicalize({"x": float("nan")})
        with pytest.raises(ValueError):
            canonicalize({"x": float("inf")})

    def test_unicode_is_preserved_as_utf8(self) -> None:
        out = canonicalize({"name": "Élise"})
        assert "Élise".encode("utf-8") in out


# --------------------------------------------------------------------------- #
# Signing context                                                             #
# --------------------------------------------------------------------------- #


class TestSigningContext:
    def test_first_use_mints_a_key(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ctx = SigningContext.load_or_mint(Path(tmp), run_id="r1")
            assert (Path(tmp) / "oath.key").exists()
            assert (Path(tmp) / "oath.pub").exists()
            assert ctx.run_id == "r1"

    def test_second_use_loads_the_same_key(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            c1 = SigningContext.load_or_mint(Path(tmp), run_id="r1")
            c2 = SigningContext.load_or_mint(Path(tmp), run_id="r2")
            assert c1.public_key.encode() == c2.public_key.encode()

    def test_private_key_file_is_mode_0600(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            SigningContext.load_or_mint(Path(tmp), run_id="r1")
            mode = (Path(tmp) / "oath.key").stat().st_mode & 0o777
            assert mode == 0o600


# --------------------------------------------------------------------------- #
# Mint and verify                                                             #
# --------------------------------------------------------------------------- #


class TestMintAndVerify:
    @pytest.fixture
    def ctx(self) -> SigningContext:
        with tempfile.TemporaryDirectory() as tmp:
            yield SigningContext.load_or_mint(Path(tmp), run_id="test-run")

    def test_mint_round_trip_verifies(self, ctx: SigningContext) -> None:
        envelope = mint(
            data={"event_records": ["a", "b", "c"]},
            tool_name="parse_evtx",
            tool_version="1.5.0.0",
            args={"channel": "Security", "event_ids": [4624, 4625]},
            image_sha256="0" * 64,
            stdout_bytes=b"raw evtx output bytes",
            offsets=(EvidenceOffset(start=1024, length=512, artifact_label="EVTX rec 1"),),
            prev_hash=None,
            ctx=ctx,
        )
        assert verify_signature(envelope, ctx.public_key) is True

    def test_mutating_header_breaks_verification(self, ctx: SigningContext) -> None:
        envelope = mint(
            data={"x": 1},
            tool_name="parse_mft",
            tool_version="1.2.2.0",
            args={"since": "2026-01-01"},
            image_sha256="a" * 64,
            stdout_bytes=b"mft output",
            prev_hash=None,
            ctx=ctx,
        )
        tampered = envelope.model_copy(
            update={"header": envelope.header.model_copy(update={"tool_name": "parse_amcache"})}
        )
        assert verify_signature(tampered, ctx.public_key) is False

    def test_image_sha256_must_be_hex_64(self, ctx: SigningContext) -> None:
        with pytest.raises(ValueError, match="image_sha256"):
            mint(
                data={},
                tool_name="x",
                tool_version="1",
                args={},
                image_sha256="not-a-hash",
                stdout_bytes=b"",
                prev_hash=None,
                ctx=ctx,
            )

    def test_args_canonical_is_key_order_independent(self, ctx: SigningContext) -> None:
        e1 = mint(
            data={},
            tool_name="t",
            tool_version="1",
            args={"a": 1, "b": 2},
            image_sha256="b" * 64,
            stdout_bytes=b"x",
            prev_hash=None,
            ctx=ctx,
        )
        e2 = mint(
            data={},
            tool_name="t",
            tool_version="1",
            args={"b": 2, "a": 1},
            image_sha256="b" * 64,
            stdout_bytes=b"x",
            prev_hash=None,
            ctx=ctx,
        )
        # The args_canonical field should be identical; only ts/sig differ
        # (we don't compare those here — they're inherently per-mint).
        assert e1.header.args_canonical == e2.header.args_canonical


# --------------------------------------------------------------------------- #
# Header hash (chain integrity)                                               #
# --------------------------------------------------------------------------- #


class TestHeaderHash:
    @pytest.fixture
    def ctx(self) -> SigningContext:
        with tempfile.TemporaryDirectory() as tmp:
            yield SigningContext.load_or_mint(Path(tmp), run_id="chain-test")

    def test_header_hash_chain_links(self, ctx: SigningContext) -> None:
        e1 = mint(
            data={},
            tool_name="first",
            tool_version="1",
            args={},
            image_sha256="c" * 64,
            stdout_bytes=b"first",
            prev_hash=None,
            ctx=ctx,
        )
        h1 = header_hash(e1)
        e2 = mint(
            data={},
            tool_name="second",
            tool_version="1",
            args={},
            image_sha256="c" * 64,
            stdout_bytes=b"second",
            prev_hash=h1,
            ctx=ctx,
        )
        assert e2.header.prev == h1
        assert verify_signature(e2, ctx.public_key) is True
