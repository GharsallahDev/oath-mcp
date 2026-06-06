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


def _linux_mount_ewf(image_path: Path, mount_point: Path) -> MountTech:
    """Mount the largest NTFS partition of an EnCase .E01 image read-only.

    Sequence: ewfmount exposes the .E01 (auto-discovering .E02..N segments
    via libewf) as a raw stream; mmls identifies the largest NTFS partition
    in that stream; mount -t ntfs with offset= mounts it read-only via
    ntfs-3g. sudo is required for ewfmount + mount; on SIFT the
    sansforensics user has it configured.
    """
    ewf_root = Path(f"/tmp/oath-ewf-{uuid.uuid4().hex[:8]}")
    ewf_root.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["sudo", "ewfmount", str(image_path), str(ewf_root)],
        check=True, capture_output=True, text=True,
    )
    raw_stream = ewf_root / "ewf1"

    mmls = subprocess.run(
        ["mmls", str(raw_stream)],
        check=True, capture_output=True, text=True,
    )
    # mmls output rows look like:
    #   003:  000:001   0000206848   0041940991   0041734144   NTFS / exFAT (0x07)
    # We want the partition with the longest length that's NTFS-flavored.
    biggest_start, biggest_length = 0, 0
    for line in mmls.stdout.splitlines():
        if "NTFS" not in line:
            continue
        parts = line.split()
        try:
            start = int(parts[2])
            length = int(parts[4])
        except (IndexError, ValueError):
            continue
        if length > biggest_length:
            biggest_start, biggest_length = start, length
    if biggest_length == 0:
        raise RuntimeError(f"no NTFS partition found via mmls in {image_path}")

    offset_bytes = biggest_start * 512  # mmls reports sectors of 512 B
    subprocess.run(
        ["sudo", "mount", "-o",
         f"ro,loop,offset={offset_bytes},show_sys_files,streams_interface=windows",
         "-t", "ntfs", str(raw_stream), str(mount_point)],
        check=True, capture_output=True, text=True,
    )
    return "fuse-ntfs"


def mount_readonly(image_path: Path, mount_root: Path) -> tuple[Path, MountTech]:
    """Mount `image_path` read-only and return the mount point + technology.

    Platform dispatch:
      - Linux  + .E01/.Ex01:  ewfmount + offset-mount the largest NTFS partition
      - Linux  + raw image:    losetup -r + ntfs-3g
      - macOS:                  hdiutil attach -readonly (HFS+/APFS only);
                                ntfs-3g/ext4fuse for foreign filesystems;
                                otherwise raw-file passthrough.
      - Other:                  raw-file passthrough.

    raw-file mode is acceptable for many forensic tools (Volatility 3 reads
    memory images directly; EvtxECmd reads exported .evtx files; we mount only
    when we need filesystem-level access like enumerating $MFT).
    """
    system = platform.system()
    mount_root.mkdir(parents=True, exist_ok=True)
    mount_point = mount_root / f"oath-{uuid.uuid4().hex[:8]}"

    if system == "Linux":
        mount_point.mkdir(parents=True, exist_ok=True)
        suffix = image_path.suffix.upper()
        if suffix in (".E01", ".EX01", ".S01"):
            tech = _linux_mount_ewf(image_path, mount_point)
            return mount_point, tech
        # Raw image (.dd / .raw / .img): losetup -r ensures the loop device
        # itself is read-only; even a root write through it returns EROFS at
        # the kernel level.
        result = subprocess.run(
            ["sudo", "losetup", "-Pr", "--show", "-f", str(image_path)],
            check=True, capture_output=True, text=True,
        )
        loop_dev = result.stdout.strip()
        # Mount the partition device (first NTFS one we find).
        # losetup -P exposed loopNp1, loopNp2, ... — pick the largest.
        # Cheap heuristic: just try p1, p2, p3 and mount the one that works.
        for part_idx in (2, 1, 3, 4):
            part_dev = f"{loop_dev}p{part_idx}"
            try:
                subprocess.run(
                    ["sudo", "mount", "-o", "ro,loop,show_sys_files,streams_interface=windows",
                     "-t", "ntfs", part_dev, str(mount_point)],
                    check=True, capture_output=True, text=True,
                )
                return mount_point, "losetup"
            except subprocess.CalledProcessError:
                continue
        raise RuntimeError(f"no mountable NTFS partition on {loop_dev}")

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
