r"""enumerate_credential_artifacts — typed filesystem inventory of credential-bearing files.

Walks a mounted-read-only Windows (or NTFS) volume and produces a typed,
hash-anchored inventory of every credential-bearing artifact: registry
hives (SAM, SECURITY, SYSTEM, NTUSER.DAT), DPAPI master keys, browser
saved-credentials databases, SSH key files, LSASS dumps, hibernation files
and pagefiles, NTDS.dit, Kerberos ticket caches.

Why this is the first call in an autonomous-DFIR triage
-------------------------------------------------------
Before any per-artifact tool runs, the agent needs to know WHICH artifacts
exist on this image. Without enumeration:

  - The agent asks parse_amcache(amcache_path=???) — but doesn't know where
    Amcache.hve lives on this particular image (could be Windows\AppCompat\
    Programs\, or rolled into a backup, or absent entirely).
  - The agent calls vol3 lsadump but doesn't know if there's a memory dump.
  - The agent looks for credential dumps but doesn't know if LSASS was
    dumped to disk (a common attacker step before PtH).

enumerate_credential_artifacts answers all of this in one Notarized envelope.
The agent reads the inventory, then calls the right typed function with the
right path.

Why pure Python (no external tool)
----------------------------------
Determinism. Every byte read here comes from the mounted image. The
SHA-256 of each artifact is the only thing in the output — no parser drift,
no tool-version dance. reverify() re-walks the same paths and confirms
matching SHA-256s.

What makes a file "credential-bearing"
---------------------------------------
A path is matched if it satisfies any of these patterns (case-insensitive
on Windows-style backslash paths):

  Registry hives:
    Windows\\System32\\config\\SAM
    Windows\\System32\\config\\SECURITY
    Windows\\System32\\config\\SYSTEM
    Windows\\System32\\config\\SOFTWARE
    Users\\*\\NTUSER.DAT
    Users\\*\\AppData\\Local\\Microsoft\\Windows\\UsrClass.dat

  DPAPI master keys:
    Users\\*\\AppData\\Roaming\\Microsoft\\Protect\\<SID>\\<KEY-GUID>

  Browser-saved credentials:
    Users\\*\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data
    Users\\*\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Cookies
    Users\\*\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\Login Data
    Users\\*\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\*\\logins.json

  LSASS dumps:
    Any file matching lsass*.dmp / lsa*.dmp / *.dmp in
    %TEMP% / Public / Users\\*\\Downloads (likely-attacker locations)

  Hibernation / pagefiles / memory:
    \\hiberfil.sys
    \\pagefile.sys
    \\swapfile.sys
    \\memory.dmp (kernel crash dump)

  Domain controller:
    Windows\\NTDS\\NTDS.dit
    Windows\\NTDS\\edb.log

  SSH:
    Users\\*\\.ssh\\id_rsa, id_dsa, id_ecdsa, id_ed25519
    Users\\*\\.ssh\\authorized_keys, known_hosts
    ProgramData\\ssh\\ssh_host_*_key

  Kerberos ticket caches:
    Windows\\System32\\config\\systemprofile\\AppData\\Roaming\\Microsoft\\Protect\\
    (covered by DPAPI master-key match above)

This is a closed set — the agent doesn't extend it. Closed sets are
deterministic. Open sets are not.
"""
from __future__ import annotations

import fnmatch
import hashlib
import os
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from oath.mcp.evidence_handle import EvidenceHandle
from oath.receipt.notarized import (
    EvidenceOffset,
    Notarized,
    SigningContext,
    mint,
)

# Bump this when the artifact-class set or sha256 contract changes; the
# verifier refuses to re-derive across version drift.
ENUMERATOR_VERSION = "1.0.0"


# --------------------------------------------------------------------------- #
# Closed artifact-class set                                                   #
# --------------------------------------------------------------------------- #


REGISTRY_HIVE = "registry_hive"
DPAPI_MASTER_KEY = "dpapi_master_key"
BROWSER_CREDENTIAL_DB = "browser_credential_db"
LSASS_DUMP = "lsass_dump"
HIBERNATION_FILE = "hibernation_file"
PAGEFILE = "pagefile"
KERNEL_CRASH_DUMP = "kernel_crash_dump"
NTDS_DIT = "ntds_dit"
SSH_PRIVATE_KEY = "ssh_private_key"
SSH_KNOWN_HOSTS = "ssh_known_hosts"
SSH_HOST_KEY = "ssh_host_key"

CREDENTIAL_ARTIFACT_CLASSES = frozenset(
    {
        REGISTRY_HIVE,
        DPAPI_MASTER_KEY,
        BROWSER_CREDENTIAL_DB,
        LSASS_DUMP,
        HIBERNATION_FILE,
        PAGEFILE,
        KERNEL_CRASH_DUMP,
        NTDS_DIT,
        SSH_PRIVATE_KEY,
        SSH_KNOWN_HOSTS,
        SSH_HOST_KEY,
    }
)


# --------------------------------------------------------------------------- #
# Pattern table (closed)                                                      #
# --------------------------------------------------------------------------- #
# Each entry: (artifact_class, posix-style glob relative to mount root).
# We match against the lowercase POSIX path of every file we visit.
_PATTERNS: tuple[tuple[str, str], ...] = (
    # Registry hives
    (REGISTRY_HIVE, "windows/system32/config/sam"),
    (REGISTRY_HIVE, "windows/system32/config/security"),
    (REGISTRY_HIVE, "windows/system32/config/system"),
    (REGISTRY_HIVE, "windows/system32/config/software"),
    (REGISTRY_HIVE, "windows/system32/config/default"),
    (REGISTRY_HIVE, "users/*/ntuser.dat"),
    (REGISTRY_HIVE, "users/*/appdata/local/microsoft/windows/usrclass.dat"),
    # DPAPI master keys
    (DPAPI_MASTER_KEY, "users/*/appdata/roaming/microsoft/protect/*/*"),
    (DPAPI_MASTER_KEY, "windows/system32/microsoft/protect/*/*"),
    # Browser credential DBs
    (BROWSER_CREDENTIAL_DB, "users/*/appdata/local/google/chrome/user data/*/login data"),
    (BROWSER_CREDENTIAL_DB, "users/*/appdata/local/google/chrome/user data/*/cookies"),
    (BROWSER_CREDENTIAL_DB, "users/*/appdata/local/microsoft/edge/user data/*/login data"),
    (BROWSER_CREDENTIAL_DB, "users/*/appdata/local/microsoft/edge/user data/*/cookies"),
    (BROWSER_CREDENTIAL_DB, "users/*/appdata/roaming/mozilla/firefox/profiles/*/logins.json"),
    (BROWSER_CREDENTIAL_DB, "users/*/appdata/roaming/mozilla/firefox/profiles/*/key4.db"),
    # LSASS-style dumps
    (LSASS_DUMP, "users/public/*.dmp"),
    (LSASS_DUMP, "users/*/downloads/*.dmp"),
    (LSASS_DUMP, "windows/temp/*.dmp"),
    (LSASS_DUMP, "users/*/appdata/local/temp/*.dmp"),
    (LSASS_DUMP, "programdata/*.dmp"),
    # OS-level memory state
    (HIBERNATION_FILE, "hiberfil.sys"),
    (PAGEFILE, "pagefile.sys"),
    (PAGEFILE, "swapfile.sys"),
    (KERNEL_CRASH_DUMP, "windows/memory.dmp"),
    (KERNEL_CRASH_DUMP, "windows/minidump/*.dmp"),
    # Domain controller (NTDS)
    (NTDS_DIT, "windows/ntds/ntds.dit"),
    (NTDS_DIT, "windows/ntds/edb.log"),
    # SSH (Windows OpenSSH installations)
    (SSH_PRIVATE_KEY, "users/*/.ssh/id_rsa"),
    (SSH_PRIVATE_KEY, "users/*/.ssh/id_dsa"),
    (SSH_PRIVATE_KEY, "users/*/.ssh/id_ecdsa"),
    (SSH_PRIVATE_KEY, "users/*/.ssh/id_ed25519"),
    (SSH_KNOWN_HOSTS, "users/*/.ssh/known_hosts"),
    (SSH_KNOWN_HOSTS, "users/*/.ssh/authorized_keys"),
    (SSH_HOST_KEY, "programdata/ssh/ssh_host_*_key"),
)


# --------------------------------------------------------------------------- #
# Typed schema                                                                #
# --------------------------------------------------------------------------- #


class CredentialArtifact(BaseModel):
    """One credential-bearing file found on the mounted volume.

    All fields are deterministic functions of the mount point + the file's
    bytes. reverify() can recompute every field from scratch.
    """

    model_config = ConfigDict(frozen=True)

    artifact_class: str = Field(..., description="One of CREDENTIAL_ARTIFACT_CLASSES.")
    absolute_path: str = Field(..., description="Absolute path under the mount point.")
    relative_path: str = Field(..., description="POSIX-style path relative to mount root.")
    size_bytes: int = Field(..., ge=0)
    sha256: str = Field(..., min_length=64, max_length=64)


# --------------------------------------------------------------------------- #
# Walking + matching                                                          #
# --------------------------------------------------------------------------- #


def _relative_posix(p: Path, root: Path) -> str:
    """Return a posix-style, lowercased, leading-slashless path relative to root."""
    rel = p.resolve().relative_to(root.resolve())
    return str(rel).replace("\\", "/").lower()


def _classify(rel_lower: str) -> str | None:
    """Match a relative path against the closed pattern table.

    Returns the artifact_class on first match, or None.
    Ordering: more-specific patterns come first in _PATTERNS, so first-match
    wins (e.g. SSH_PRIVATE_KEY vs. SSH_HOST_KEY for id_rsa.pub doesn't
    arise because we require the exact key-suffix glob).
    """
    for cls, pat in _PATTERNS:
        if fnmatch.fnmatchcase(rel_lower, pat):
            return cls
    return None


def _sha256_file(path: Path, chunk: int = 4 * 1024 * 1024) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(chunk), b""):
            h.update(block)
    return h.hexdigest()


def _walk_and_classify(
    mount_root: Path,
    *,
    artifact_class_filter: set[str] | None,
    max_files: int | None,
) -> list[CredentialArtifact]:
    """Walk mount_root, classify every file, return matches sorted by relative_path."""
    results: list[CredentialArtifact] = []
    mount_root = mount_root.resolve()

    for dirpath, dirnames, filenames in os.walk(mount_root, followlinks=False):
        # Deterministic walk: sort children before descending. os.walk doesn't
        # guarantee an order across filesystems, but we control it ourselves.
        dirnames.sort()
        filenames.sort()

        for name in filenames:
            full = Path(dirpath) / name
            if not full.is_file():
                continue

            try:
                rel_lower = _relative_posix(full, mount_root)
            except ValueError:
                continue  # symlink escape or similar

            cls = _classify(rel_lower)
            if cls is None:
                continue
            if artifact_class_filter is not None and cls not in artifact_class_filter:
                continue

            try:
                size = full.stat().st_size
                sha = _sha256_file(full)
            except OSError:
                continue  # unreadable file — skip rather than fail the whole walk

            results.append(
                CredentialArtifact(
                    artifact_class=cls,
                    absolute_path=str(full),
                    relative_path=rel_lower,
                    size_bytes=size,
                    sha256=sha,
                )
            )

            if max_files is not None and len(results) >= max_files:
                # Deterministic short-circuit. Sort happens below.
                break
        if max_files is not None and len(results) >= max_files:
            break

    # Stable, sorted output makes the BLAKE3 of the canonical-serialized data
    # identical across re-runs.
    results.sort(key=lambda a: a.relative_path)
    return results


# --------------------------------------------------------------------------- #
# Public typed function                                                       #
# --------------------------------------------------------------------------- #


def enumerate_credential_artifacts(
    handle: EvidenceHandle,
    *,
    artifact_class_filter: list[str] | None = None,
    max_files: int | None = None,
    ctx: SigningContext,
    prev_hash: str | None = None,
    model_id: str | None = None,
    prompt_hash: str | None = None,
) -> Notarized[list[CredentialArtifact]]:
    """Walk the mounted volume; return a typed inventory of credential artifacts.

    Parameters
    ----------
    handle
        Mounted-read-only EvidenceHandle. We walk `handle.mount_point`.
    artifact_class_filter
        Optional whitelist of artifact classes (see CREDENTIAL_ARTIFACT_CLASSES).
        When set, other classes are skipped.
    max_files
        Safety cap. None = no limit (default). Useful for large images where
        the agent only needs to know if a class exists.
    """
    if not handle.mount_point or not handle.mount_point.exists():
        raise FileNotFoundError(f"mount_point missing: {handle.mount_point}")

    normalized_filter = (
        {c.strip() for c in artifact_class_filter if c.strip()}
        if artifact_class_filter
        else None
    )
    if normalized_filter:
        unknown = normalized_filter - CREDENTIAL_ARTIFACT_CLASSES
        if unknown:
            raise ValueError(f"unknown artifact_class values: {sorted(unknown)}")

    args: dict[str, object] = {
        "mount_point": str(handle.mount_point),
        "artifact_class_filter": sorted(normalized_filter) if normalized_filter else None,
        "max_files": max_files,
    }

    artifacts = _walk_and_classify(
        handle.mount_point,
        artifact_class_filter=normalized_filter,
        max_files=max_files,
    )

    # The "stdout" for hashing purposes is the deterministic concatenation of
    # each artifact's SHA-256 + relative_path + size, newline-joined. This
    # gives us a stable bytes representation reverify() can recompute without
    # invoking pydantic.
    stdout_bytes = (
        "\n".join(f"{a.sha256}  {a.size_bytes}  {a.relative_path}" for a in artifacts)
        + "\n"
    ).encode("utf-8")

    return mint(
        data=artifacts,
        tool_name="enumerate_credential_artifacts",
        tool_version=ENUMERATOR_VERSION,
        args=args,
        image_sha256=handle.image_sha256,
        stdout_bytes=stdout_bytes,
        offsets=tuple(),  # Whole-volume walk; no single offset is meaningful.
        prev_hash=prev_hash,
        model_id=model_id,
        prompt_hash=prompt_hash,
        ctx=ctx,
    )


def reverify(
    envelope: Notarized[list[CredentialArtifact]],
    *,
    mount_point: Path,
) -> tuple[bool, str]:
    """Re-walk the mount; recompute the canonical stdout; compare BLAKE3.

    This is pure Python — no subprocess. Determinism comes from sorted-walk
    + stable artifact-class set + content-hashing.

    Reads `artifact_class_filter` and `max_files` back from `args_canonical`
    so the re-walk uses IDENTICAL filtering to the original mint. Walking
    unfiltered when the mint was filtered would always produce a different
    canonical stdout and spuriously fail BLAKE3 — a real bug from a prior
    revision of this function.
    """
    import json

    import blake3

    if not mount_point.exists():
        return False, f"mount_point missing: {mount_point}"

    try:
        original_args = json.loads(envelope.header.args_canonical)
    except Exception as e:
        return False, f"args_canonical not valid JSON: {e}"
    raw_filter = original_args.get("artifact_class_filter") or None
    artifact_class_filter = set(raw_filter) if raw_filter else None
    max_files = original_args.get("max_files") or None

    artifacts = _walk_and_classify(
        mount_point,
        artifact_class_filter=artifact_class_filter,
        max_files=max_files,
    )
    stdout_bytes = (
        "\n".join(f"{a.sha256}  {a.size_bytes}  {a.relative_path}" for a in artifacts)
        + "\n"
    ).encode("utf-8")

    actual = blake3.blake3(stdout_bytes).hexdigest()
    expected = envelope.header.stdout_blake3
    if actual != expected:
        return False, f"stdout BLAKE3 drift: expected {expected[:16]}…, got {actual[:16]}…"
    return True, "ok"


# --------------------------------------------------------------------------- #
# Convenience aggregators                                                     #
# --------------------------------------------------------------------------- #


def has_lsass_dump(artifacts: list[CredentialArtifact]) -> bool:
    """True iff any artifact is classified as an LSASS-style memory dump.

    Used by the agent's PtH hypothesis: if no LSASS dump is found on disk
    AND no in-memory hashdump succeeds, the "credential theft via LSASS"
    sub-hypothesis is downgraded — saving wasted verifier cycles.
    """
    return any(a.artifact_class == LSASS_DUMP for a in artifacts)


def artifacts_by_class(
    artifacts: list[CredentialArtifact],
) -> dict[str, list[CredentialArtifact]]:
    """Group artifacts by their class. Order preserved within each group."""
    out: dict[str, list[CredentialArtifact]] = {}
    for a in artifacts:
        out.setdefault(a.artifact_class, []).append(a)
    return out


__all__ = [
    "BROWSER_CREDENTIAL_DB",
    "CREDENTIAL_ARTIFACT_CLASSES",
    "CredentialArtifact",
    "DPAPI_MASTER_KEY",
    "ENUMERATOR_VERSION",
    "HIBERNATION_FILE",
    "KERNEL_CRASH_DUMP",
    "LSASS_DUMP",
    "NTDS_DIT",
    "PAGEFILE",
    "REGISTRY_HIVE",
    "SSH_HOST_KEY",
    "SSH_KNOWN_HOSTS",
    "SSH_PRIVATE_KEY",
    "artifacts_by_class",
    "enumerate_credential_artifacts",
    "has_lsass_dump",
    "reverify",
]
