"""Unit tests for find_strings_on_image + NSS adapter."""
from __future__ import annotations

import json
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from oath.mcp.evidence_handle import EvidenceHandle
from oath.mcp.tools.find_strings_on_image import (
    StringMatch,
    TSK_VERSION_FLOOR,
    find_strings_on_image,
    reverify,
    to_nss_answer_payload,
    to_nss_string,
)
from oath.receipt.notarized import SigningContext, verify_signature


# fls -m / -p sample output: three live files + one deleted file.
# Format per row: md5|name|inode|mode|uid|gid|size|atime|mtime|ctime|crtime
FLS_BODY = b"""\
0|/Users/Alice/fee.txt|122150|r/-rwxrwxrwx|0|0|34|0|0|0|0
0|/Users/Alice/fi.txt|122151|r/-rwxrwxrwx|0|0|22|0|0|0|0
0|/Users/Alice/fo.txt|122152|r/-rwxrwxrwx|0|0|18|0|0|0|0
0|/Users/Alice/iron.txt (deleted)|*122160-128-3|r/-rwxrwxrwx|0|0|41|0|0|0|0
0|/Users/Alice/notes.txt|122170|r/-rwxrwxrwx|0|0|999999999999|0|0|0|0
"""

# Per-inode icat output. The matcher's `pattern` lives in each.
ICAT_DATA = {
    122150: b"Banking records for the iron-fat conspiracy.\n",
    122151: b"Iron, fat, ASCII -- the secret words.\n",
    122152: b"Just a regular Fo.\n",
    122160: b"This file was deleted but contains iron-fat-ascii markers.\n",
    122170: b"x" * 100,  # huge file (per fls), but icat returns small noise
}


@dataclass
class FakeTSKExecutor:
    """In-memory fls + icat for unit testing without an actual image."""

    fls_payload: bytes = FLS_BODY
    icat_by_inode: dict[int, bytes] = field(default_factory=lambda: dict(ICAT_DATA))
    fls_calls: list[tuple[Path, int]] = field(default_factory=list)
    icat_calls: list[tuple[Path, int, int]] = field(default_factory=list)

    def fls(self, image_path: Path, offset: int) -> bytes:
        self.fls_calls.append((image_path, offset))
        return self.fls_payload

    def icat(self, image_path: Path, offset: int, inode: int) -> bytes:
        self.icat_calls.append((image_path, offset, inode))
        return self.icat_by_inode.get(inode, b"")


@pytest.fixture
def ctx() -> SigningContext:
    with tempfile.TemporaryDirectory() as tmp:
        yield SigningContext.load_or_mint(Path(tmp), run_id="test-find-strings")


@pytest.fixture
def handle(tmp_path: Path) -> EvidenceHandle:
    img = tmp_path / "dummy.E01"
    img.write_bytes(b"\x00" * 1024)
    return EvidenceHandle(
        image_path=img,
        image_sha256="6" * 64,
        image_size_bytes=1024,
        mount_point=tmp_path,
        mount_tech="raw-file",
        run_id="find-strings-run",
    )


# --------------------------------------------------------------------------- #
# Round-trip + tool-version pinning                                           #
# --------------------------------------------------------------------------- #


def test_round_trip_verifies(ctx, handle):
    env = find_strings_on_image(
        handle, pattern="iron", ctx=ctx, executor=FakeTSKExecutor()
    )
    assert verify_signature(env, ctx.public_key) is True
    assert env.header.tool_name == "find_strings_on_image"
    assert env.header.tool_version == TSK_VERSION_FLOOR


def test_finds_literal_substring_in_three_files(ctx, handle):
    env = find_strings_on_image(
        handle, pattern="iron", ctx=ctx, executor=FakeTSKExecutor()
    )
    inodes = sorted(m.inode for m in env.data)
    assert inodes == [122150, 122151, 122160]  # 122152 (Fo) and 122170 don't match


def test_case_insensitive_by_default(ctx, handle):
    env = find_strings_on_image(
        handle, pattern="IRON", ctx=ctx, executor=FakeTSKExecutor()
    )
    inodes = sorted(m.inode for m in env.data)
    assert inodes == [122150, 122151, 122160]


def test_case_sensitive_when_requested(ctx, handle):
    env = find_strings_on_image(
        handle,
        pattern="IRON",
        case_sensitive=True,
        ctx=ctx,
        executor=FakeTSKExecutor(),
    )
    assert list(env.data) == []  # No file has the literal uppercase IRON


def test_regex_pattern(ctx, handle):
    env = find_strings_on_image(
        handle,
        pattern=r"\b(iron|fat)\b",
        is_regex=True,
        ctx=ctx,
        executor=FakeTSKExecutor(),
    )
    inodes = sorted(m.inode for m in env.data)
    # Files containing iron OR fat: 122150 (both), 122151 (both), 122160 (both)
    assert inodes == [122150, 122151, 122160]


def test_exclude_deleted_filters_out_deleted_entries(ctx, handle):
    env = find_strings_on_image(
        handle,
        pattern="iron",
        include_deleted=False,
        ctx=ctx,
        executor=FakeTSKExecutor(),
    )
    inodes = sorted(m.inode for m in env.data)
    assert 122160 not in inodes  # The deleted file is gone
    assert inodes == [122150, 122151]


def test_name_substring_filter(ctx, handle):
    env = find_strings_on_image(
        handle,
        pattern="iron",
        name_substring=".txt",
        ctx=ctx,
        executor=FakeTSKExecutor(),
    )
    # All matching files happen to be .txt; ensure the filter passes them
    assert {m.inode for m in env.data} == {122150, 122151, 122160}


def test_max_file_size_skips_huge_files(ctx, handle):
    """notes.txt has size 999999999999; default cap is 256MiB so it's skipped."""
    env = find_strings_on_image(
        handle, pattern="x", ctx=ctx, executor=FakeTSKExecutor()
    )
    # notes.txt's bytes contain only 'x' characters but it's filtered out by size cap
    assert all(m.inode != 122170 for m in env.data)


def test_match_count_and_offset_per_file(ctx, handle):
    env = find_strings_on_image(
        handle, pattern="iron", ctx=ctx, executor=FakeTSKExecutor()
    )
    by_inode = {m.inode: m for m in env.data}
    # 122150's content contains "iron" once, at byte offset ~25
    assert by_inode[122150].total_match_count == 1
    assert by_inode[122150].first_match_offset >= 0


def test_deleted_flag_reflected_in_records(ctx, handle):
    env = find_strings_on_image(
        handle, pattern="iron", ctx=ctx, executor=FakeTSKExecutor()
    )
    deleted_records = [m for m in env.data if m.deleted]
    assert len(deleted_records) == 1
    assert deleted_records[0].inode == 122160


def test_output_sorted_for_determinism(ctx, handle):
    env = find_strings_on_image(
        handle, pattern="iron", ctx=ctx, executor=FakeTSKExecutor()
    )
    keys = [(m.deleted, m.inode, m.filename) for m in env.data]
    assert keys == sorted(keys)


# --------------------------------------------------------------------------- #
# NSS-string conversion                                                       #
# --------------------------------------------------------------------------- #


def test_to_nss_string_for_live_and_deleted():
    live = StringMatch(
        inode=122150,
        filename="Users/Alice/fee.txt",
        deleted=False,
        file_size_bytes=34,
        first_match_offset=0,
        total_match_count=1,
    )
    deleted = StringMatch(
        inode=122160,
        filename="Users/Alice/iron.txt",
        deleted=True,
        file_size_bytes=41,
        first_match_offset=0,
        total_match_count=1,
    )
    assert to_nss_string(live) == "122150:Users/Alice/fee.txt"
    assert to_nss_string(deleted) == "122160:DELETED-Users/Alice/iron.txt"


def test_to_nss_answer_payload_is_canonical_json(ctx, handle):
    env = find_strings_on_image(
        handle, pattern="iron", ctx=ctx, executor=FakeTSKExecutor()
    )
    payload = to_nss_answer_payload(list(env.data))
    # Must parse as JSON array of strings, sorted alphabetically
    parsed = json.loads(payload)
    assert isinstance(parsed, list)
    assert all(isinstance(x, str) for x in parsed)
    assert parsed == sorted(parsed)
    # Must contain the three matching inode:filename strings
    assert "122150:Users/Alice/fee.txt" in parsed
    assert "122160:DELETED-Users/Alice/iron.txt" in parsed


# --------------------------------------------------------------------------- #
# Tamper detection via reverify                                               #
# --------------------------------------------------------------------------- #


def test_reverify_passes_when_unchanged(ctx, handle):
    fake = FakeTSKExecutor()
    env = find_strings_on_image(handle, pattern="iron", ctx=ctx, executor=fake)
    # Re-use the same fake (deterministic output)
    ok, _ = reverify(env, image_path=handle.image_path, executor=FakeTSKExecutor())
    assert ok is True


def test_reverify_fails_when_file_contents_drift(ctx, handle):
    env = find_strings_on_image(
        handle, pattern="iron", ctx=ctx, executor=FakeTSKExecutor()
    )
    # Tamper: one matching file's content changes (drops the keyword)
    tampered = FakeTSKExecutor(
        icat_by_inode={**ICAT_DATA, 122151: b"keyword removed in tampered copy.\n"}
    )
    ok, reason = reverify(env, image_path=handle.image_path, executor=tampered)
    assert ok is False
    assert "drift" in reason.lower()


def test_reverify_fails_when_inode_list_drifts(ctx, handle):
    env = find_strings_on_image(
        handle, pattern="iron", ctx=ctx, executor=FakeTSKExecutor()
    )
    # Tamper: a different fls output (one less file)
    altered_body = FLS_BODY.replace(
        b"0|/Users/Alice/fi.txt|122151|r/-rwxrwxrwx|0|0|22|0|0|0|0\n", b""
    )
    tampered = FakeTSKExecutor(fls_payload=altered_body)
    ok, reason = reverify(env, image_path=handle.image_path, executor=tampered)
    assert ok is False
    assert "drift" in reason.lower()
