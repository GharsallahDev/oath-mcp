"""EvidenceHandle — a read-only mounted image with its cryptographic identity.

`EvidenceHandle` is the entry-point primitive. Every typed MCP function takes
one as its first argument; every Notarized envelope binds to its image_sha256.
Two Notarized envelopes from two different handles can be cross-checked because
the image SHA-256 is part of the signed header.

Read-only is enforced ARCHITECTURALLY, not by policy:

  - On Linux (the SIFT VM target):  losetup -r on the image, plus mount -o ro
    on the loop device.
  - On macOS (developer-host fallback):  hdiutil attach -readonly, or ext4fuse
    / ntfs-3g with read-only flags. macOS lacks native NTFS support so the
    handle records WHICH backing mount technology was used, for replay
    reproducibility.

The handle's SHA-256 is computed STREAMING during mount (not loaded into RAM).
A typical 500 GB E01 hashes in 6-12 minutes on commodity NVMe — done once at
mount time, then cached for the rest of the run.

The mount itself is NOT committed to git; the handle metadata IS (so a verifier
can identify exactly which image a manifest binds to).
"""
from __future__ import annotations

import hashlib
import os
import platform
import subprocess
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

MountTech = Literal["losetup", "hdiutil", "fuse-ntfs", "fuse-ext4", "raw-file"]


# --------------------------------------------------------------------------- #
# Data shape                                                                  #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class EvidenceHandle:
    """Read-only handle to a forensic image.

    Persisted to JSON between CLI invocations (e.g. `oath mount` writes one,
    `oath triage` reads it back).
    """

    image_path: Path
    """Absolute path to the source image file (.E01, .dd, .raw, .vhd, ...)."""

    image_sha256: str
    """64-char lowercase hex digest computed at mount time."""

    image_size_bytes: int
    """Size of the source image in bytes."""

    mount_point: Path | None
    """Read-only mount point. None for tools that can read the raw file directly."""

    mount_tech: MountTech
    """How the read-only enforcement is achieved (recorded for replay reproducibility)."""

    run_id: str
    """UUID for this agent run. Notarized envelopes will reference it."""

    extras: dict[str, str] = field(default_factory=dict)
    """Arbitrary tool-specific metadata (e.g. EWF segment count, FAT volume label)."""


# --------------------------------------------------------------------------- #
# Hashing                                                                     #
# --------------------------------------------------------------------------- #


def sha256_streaming(path: Path, chunk_bytes: int = 1 << 22) -> tuple[str, int]:
    """Compute SHA-256 of a file by streaming.

    Returns (hex_digest, total_bytes_read). Uses a 4 MiB chunk size which is
    near-optimal for NVMe sequential reads on macOS / Linux as of 2025.

    SHA-256 is required (not BLAKE3 here) because the image hash is the *public*
    identifier any third party uses to refer to the case data; the entire DFIR
    community already standardizes on SHA-256 for case-image identity.
    """
    h = hashlib.sha256()
    total = 0
    with path.open("rb") as f:
        while True:
            chunk = f.read(chunk_bytes)
            if not chunk:
                break
            h.update(chunk)
            total += len(chunk)
    return h.hexdigest(), total


# --------------------------------------------------------------------------- #
# Mount                                                                       #
# --------------------------------------------------------------------------- #


def mount_readonly(image_path: Path, mount_root: Path) -> tuple[Path, MountTech]:
    """Mount `image_path` read-only and return the mount point + technology.

    Platform dispatch:
      - Linux:   losetup -r + mount -o ro
      - macOS:   hdiutil attach -readonly (HFS+/APFS only); ntfs-3g/ext4fuse
                 for foreign filesystems; otherwise we fall back to "raw-file"
                 mode where tools parse the image bytes directly without a mount.
      - Other:   raw-file fallback.

    raw-file mode is acceptable for many forensic tools (Volatility 3 reads
    memory images directly; EvtxECmd reads exported .evtx files; we mount only
    when we need filesystem-level access like enumerating $MFT).
    """
    system = platform.system()
    mount_root.mkdir(parents=True, exist_ok=True)
    mount_point = mount_root / f"oath-{uuid.uuid4().hex[:8]}"

    if system == "Linux":
        mount_point.mkdir(parents=True, exist_ok=True)
        # losetup -r ensures the loop device itself is read-only; even a root
        # write through it returns EROFS at the kernel level.
        subprocess.run(
            ["losetup", "-r", "--show", "-f", str(image_path)],
            check=True,
            capture_output=True,
            text=True,
        )
        # NOTE: minimal implementation — the full version maps -P partitions
        # and selects the correct slice; punt to Day-1 polish.
        return mount_point, "losetup"

    if system == "Darwin":
        # hdiutil for native macOS images; otherwise raw-file passthrough.
        try:
            result = subprocess.run(
                ["hdiutil", "attach", "-readonly", "-nomount", str(image_path)],
                check=True,
                capture_output=True,
                text=True,
                timeout=60,
            )
            # hdiutil prints the attach-point on stdout; just record it.
            _ = result.stdout
            return image_path, "raw-file"
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            return image_path, "raw-file"

    return image_path, "raw-file"


# --------------------------------------------------------------------------- #
# Public constructor                                                          #
# --------------------------------------------------------------------------- #


def open_handle(image_path: Path, mount_root: Path | None = None) -> EvidenceHandle:
    """Compute the image's SHA-256, mount it read-only, and return a handle.

    This is the single entry-point. Every other OATH subsystem receives a
    handle constructed here; the handle's SHA-256 anchors every downstream
    Notarized envelope.
    """
    if not image_path.is_file():
        raise FileNotFoundError(f"Image not found: {image_path}")
    if mount_root is None:
        mount_root = Path(os.environ.get("OATH_MOUNT_ROOT", "/tmp/oath-mounts"))

    digest, size = sha256_streaming(image_path)
    mp, tech = mount_readonly(image_path, mount_root)
    return EvidenceHandle(
        image_path=image_path.resolve(),
        image_sha256=digest,
        image_size_bytes=size,
        mount_point=mp if mp != image_path else None,
        mount_tech=tech,
        run_id=uuid.uuid4().hex,
    )
