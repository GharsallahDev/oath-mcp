"""Unit tests for enumerate_credential_artifacts.

The function is pure-Python (filesystem walk + SHA-256), so we build a
synthetic mount-root in tmp_path that mimics the canonical Windows layout.
"""
from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from oath.mcp.evidence_handle import EvidenceHandle
from oath.mcp.tools.enumerate_credential_artifacts import (
    BROWSER_CREDENTIAL_DB,
    CREDENTIAL_ARTIFACT_CLASSES,
    DPAPI_MASTER_KEY,
    ENUMERATOR_VERSION,
    HIBERNATION_FILE,
    LSASS_DUMP,
    NTDS_DIT,
    PAGEFILE,
    REGISTRY_HIVE,
    SSH_PRIVATE_KEY,
    artifacts_by_class,
    enumerate_credential_artifacts,
    has_lsass_dump,
    reverify,
)
from oath.receipt.notarized import SigningContext, verify_signature


def _touch(p: Path, content: bytes = b"x") -> Path:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(content)
    return p


@pytest.fixture
def ctx() -> SigningContext:
    with tempfile.TemporaryDirectory() as tmp:
        yield SigningContext.load_or_mint(Path(tmp), run_id="test-enum")


@pytest.fixture
def mount_root(tmp_path: Path) -> Path:
    """Synthetic Windows-layout mount root with a mix of artifacts + noise."""
    root = tmp_path / "mount"
    root.mkdir()

    # Registry hives
    _touch(root / "Windows/System32/config/SAM", b"SAM_HIVE_BYTES")
    _touch(root / "Windows/System32/config/SECURITY", b"SECURITY_HIVE_BYTES")
    _touch(root / "Windows/System32/config/SYSTEM", b"SYSTEM_HIVE_BYTES")
    _touch(root / "Windows/System32/config/SOFTWARE", b"SOFTWARE_HIVE_BYTES")
    _touch(root / "Users/admin/NTUSER.DAT", b"NTUSER_BYTES")

    # DPAPI master key
    _touch(
        root / "Users/admin/AppData/Roaming/Microsoft/Protect/S-1-5-21-XXX/GUID-A",
        b"DPAPI_MASTER",
    )

    # Browser credentials
    _touch(
        root / "Users/admin/AppData/Local/Google/Chrome/User Data/Default/Login Data",
        b"CHROME_LOGIN_DB",
    )
    _touch(
        root / "Users/admin/AppData/Roaming/Mozilla/Firefox/Profiles/abc.default/logins.json",
        b"{}",
    )

    # LSASS dump dropped by an attacker
    _touch(root / "Users/Public/lsass.dmp", b"LSASS_DUMP_BYTES" * 128)

    # OS state files
    _touch(root / "hiberfil.sys", b"HIBER_BYTES" * 64)
    _touch(root / "pagefile.sys", b"PAGE_BYTES" * 64)

    # Domain-controller NTDS (will exist on DCs, harmless on workstations)
    _touch(root / "Windows/NTDS/NTDS.dit", b"NTDS_BYTES" * 64)

    # SSH keys
    _touch(root / "Users/admin/.ssh/id_rsa", b"-----BEGIN RSA PRIVATE KEY-----")
    _touch(root / "Users/admin/.ssh/known_hosts", b"github.com ssh-rsa AAAA...")

    # NOISE — must NOT be classified
    _touch(root / "Windows/notepad.exe", b"NOT_AN_ARTIFACT")
    _touch(root / "Users/admin/Documents/notes.txt", b"random user content")
    _touch(root / "Windows/System32/cmd.exe", b"NOT_AN_ARTIFACT")

    return root


@pytest.fixture
def handle(mount_root: Path, tmp_path: Path) -> EvidenceHandle:
    img = tmp_path / "dummy.E01"
    img.write_bytes(b"\x00" * 1024)
    return EvidenceHandle(
        image_path=img,
        image_sha256="7" * 64,
        image_size_bytes=1024,
        mount_point=mount_root,
        mount_tech="raw-file",
        run_id="enum-run",
    )


# --------------------------------------------------------------------------- #
# Round-trip + tool-version pinning                                           #
# --------------------------------------------------------------------------- #


def test_round_trip_verifies(ctx, handle):
    env = enumerate_credential_artifacts(handle, ctx=ctx)
    assert verify_signature(env, ctx.public_key) is True
    assert env.header.tool_name == "enumerate_credential_artifacts"
    assert env.header.tool_version == ENUMERATOR_VERSION


def test_finds_all_canonical_artifact_classes(ctx, handle):
    env = enumerate_credential_artifacts(handle, ctx=ctx)
    classes_found = {a.artifact_class for a in env.data}
    # Every class we planted must appear
    assert REGISTRY_HIVE in classes_found
    assert DPAPI_MASTER_KEY in classes_found
    assert BROWSER_CREDENTIAL_DB in classes_found
    assert LSASS_DUMP in classes_found
    assert HIBERNATION_FILE in classes_found
    assert PAGEFILE in classes_found
    assert NTDS_DIT in classes_found
    assert SSH_PRIVATE_KEY in classes_found


def test_does_not_misclassify_noise(ctx, handle):
    env = enumerate_credential_artifacts(handle, ctx=ctx)
    rels = {a.relative_path for a in env.data}
    assert "windows/notepad.exe" not in rels
    assert "windows/system32/cmd.exe" not in rels
    assert "users/admin/documents/notes.txt" not in rels


def test_artifact_class_filter(ctx, handle):
    env = enumerate_credential_artifacts(
        handle, artifact_class_filter=[REGISTRY_HIVE], ctx=ctx
    )
    assert env.data, "expected at least one registry hive in the fixture"
    assert all(a.artifact_class == REGISTRY_HIVE for a in env.data)


def test_unknown_artifact_class_filter_raises(ctx, handle):
    with pytest.raises(ValueError, match="unknown artifact_class"):
        enumerate_credential_artifacts(
            handle, artifact_class_filter=["not_a_real_class"], ctx=ctx
        )


def test_max_files_cap(ctx, handle):
    env = enumerate_credential_artifacts(handle, max_files=3, ctx=ctx)
    assert len(env.data) <= 3


def test_sha256_is_actual_content_hash(ctx, handle, mount_root):
    """The sha256 column must be the actual file-content hash, not a stub."""
    import hashlib

    env = enumerate_credential_artifacts(handle, ctx=ctx)
    sam = next(a for a in env.data if a.relative_path.endswith("/sam"))
    expected = hashlib.sha256(b"SAM_HIVE_BYTES").hexdigest()
    assert sam.sha256 == expected


def test_relative_paths_are_posix_lowercase(ctx, handle):
    env = enumerate_credential_artifacts(handle, ctx=ctx)
    for a in env.data:
        assert "\\" not in a.relative_path, "expected posix-style paths"
        assert a.relative_path == a.relative_path.lower(), "expected lowercased paths"


def test_output_is_sorted_for_deterministic_hashing(ctx, handle):
    env = enumerate_credential_artifacts(handle, ctx=ctx)
    rels = [a.relative_path for a in env.data]
    assert rels == sorted(rels)


# --------------------------------------------------------------------------- #
# Helpers                                                                     #
# --------------------------------------------------------------------------- #


def test_has_lsass_dump_detects_planted_dump(ctx, handle):
    env = enumerate_credential_artifacts(handle, ctx=ctx)
    assert has_lsass_dump(list(env.data)) is True


def test_has_lsass_dump_false_when_filtered_out(ctx, handle):
    env = enumerate_credential_artifacts(
        handle, artifact_class_filter=[REGISTRY_HIVE], ctx=ctx
    )
    assert has_lsass_dump(list(env.data)) is False


def test_artifacts_by_class_grouping(ctx, handle):
    env = enumerate_credential_artifacts(handle, ctx=ctx)
    grouped = artifacts_by_class(list(env.data))
    # Multiple registry hives planted; they must all land in one bucket
    assert len(grouped[REGISTRY_HIVE]) >= 4
    # Pagefile is a one-off; exactly one
    assert len(grouped[PAGEFILE]) == 1


def test_credential_artifact_classes_is_closed():
    """The classes used by helpers must be a strict subset of the closed set."""
    for cls in (
        REGISTRY_HIVE,
        DPAPI_MASTER_KEY,
        BROWSER_CREDENTIAL_DB,
        LSASS_DUMP,
        HIBERNATION_FILE,
        PAGEFILE,
        NTDS_DIT,
        SSH_PRIVATE_KEY,
    ):
        assert cls in CREDENTIAL_ARTIFACT_CLASSES


# --------------------------------------------------------------------------- #
# Tamper detection                                                            #
# --------------------------------------------------------------------------- #


def test_reverify_passes_when_unchanged(ctx, handle, mount_root):
    env = enumerate_credential_artifacts(handle, ctx=ctx)
    ok, _ = reverify(env, mount_point=mount_root)
    assert ok is True


def test_reverify_fails_when_artifact_modified(ctx, handle, mount_root):
    env = enumerate_credential_artifacts(handle, ctx=ctx)
    # Mutate one of the artifacts after envelope is minted
    (mount_root / "Windows/System32/config/SAM").write_bytes(b"TAMPERED")
    ok, reason = reverify(env, mount_point=mount_root)
    assert ok is False
    assert "drift" in reason.lower()


def test_reverify_fails_when_new_artifact_planted(ctx, handle, mount_root):
    env = enumerate_credential_artifacts(handle, ctx=ctx)
    # Plant an additional registry hive after the envelope is minted
    _touch(
        mount_root / "Users/intruder/NTUSER.DAT",
        b"NEW_INTRUDER_NTUSER",
    )
    ok, reason = reverify(env, mount_point=mount_root)
    assert ok is False
    assert "drift" in reason.lower()


def test_reverify_fails_when_mount_missing(ctx, handle, tmp_path):
    env = enumerate_credential_artifacts(handle, ctx=ctx)
    ok, reason = reverify(env, mount_point=tmp_path / "nonexistent")
    assert ok is False
    assert "missing" in reason.lower()


def test_reverify_reconstructs_artifact_class_filter_from_args_canonical(
    ctx, handle, mount_root
):
    """If mint was filtered (e.g. only REGISTRY_HIVE), reverify must walk with
    the same filter — otherwise an unfiltered re-walk would canonicalize a
    superset and always fail BLAKE3.

    Regression test for a bug where reverify always walked unfiltered.
    """
    env = enumerate_credential_artifacts(
        handle, artifact_class_filter=[REGISTRY_HIVE], ctx=ctx
    )
    ok, reason = reverify(env, mount_point=mount_root)
    assert ok is True, reason
