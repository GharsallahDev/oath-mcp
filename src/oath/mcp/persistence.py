"""On-disk persistence for EvidenceHandle + Notarized envelope chains.

The MCP server is stateless from Claude Code's perspective — each tool call
arrives without memory of prior calls. We persist:

  - EvidenceHandle objects (so subsequent tool calls can reference an image
    by handle_id without re-mounting)
  - Notarized envelopes (one JSONL file per agent run, append-only — the
    `prev` field on each envelope chains to the previous envelope's header
    hash, producing a tamper-evident manifest)

Layout under ./logs/:

  logs/handles/<handle_id>.json     — one EvidenceHandle per file
  logs/envelopes/<run_id>.jsonl     — append-only chain of envelopes for one run
  logs/envelopes/<run_id>.index     — envelope_id -> file_offset (for fast lookup)

Envelope IDs are derived from BLAKE3(canonical(header)) — content-addressed,
so the LLM citing envelope_id X uniquely identifies the receipt regardless of
what run it lives in.
"""
from __future__ import annotations

import json
import os
import threading
from dataclasses import asdict
from pathlib import Path
from typing import Any

import blake3
from pydantic import BaseModel

from oath.mcp.evidence_handle import EvidenceHandle, MountTech
from oath.receipt.notarized import (
    Notarized,
    NotarizedHeader,
    canonicalize,
    header_hash,
)


# --------------------------------------------------------------------------- #
# EvidenceHandle persistence                                                  #
# --------------------------------------------------------------------------- #


def save_handle(handle: EvidenceHandle, handles_dir: Path) -> str:
    """Persist an EvidenceHandle and return its short handle_id.

    handle_id = first 16 hex of blake3(image_sha256 || run_id) — stable per
    (image, run) pair, and short enough for the LLM to reference in prompts.
    """
    handles_dir.mkdir(parents=True, exist_ok=True)
    handle_id = blake3.blake3(
        (handle.image_sha256 + handle.run_id).encode()
    ).hexdigest()[:16]
    path = handles_dir / f"{handle_id}.json"
    payload = {
        "image_path": str(handle.image_path),
        "image_sha256": handle.image_sha256,
        "image_size_bytes": handle.image_size_bytes,
        "mount_point": str(handle.mount_point) if handle.mount_point else None,
        "mount_tech": handle.mount_tech,
        "run_id": handle.run_id,
        "extras": dict(handle.extras),
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True))
    return handle_id


def load_handle(handle_id: str, handles_dir: Path) -> EvidenceHandle:
    """Re-hydrate an EvidenceHandle from disk."""
    path = handles_dir / f"{handle_id}.json"
    if not path.exists():
        raise FileNotFoundError(f"No such EvidenceHandle: {handle_id}")
    obj = json.loads(path.read_text())
    return EvidenceHandle(
        image_path=Path(obj["image_path"]),
        image_sha256=obj["image_sha256"],
        image_size_bytes=int(obj["image_size_bytes"]),
        mount_point=Path(obj["mount_point"]) if obj["mount_point"] else None,
        mount_tech=obj["mount_tech"],  # already validated by EvidenceHandle dataclass
        run_id=obj["run_id"],
        extras=obj.get("extras", {}),
    )


# --------------------------------------------------------------------------- #
# Envelope-chain persistence (append-only JSONL per run)                      #
# --------------------------------------------------------------------------- #


class EnvelopeStore:
    """Append-only JSONL store for Notarized envelopes within one agent run.

    Thread-safe via an internal lock — multiple typed-function MCP calls within
    one run can append concurrently. Each line is one envelope serialized as
    JSON (header + data + sig). The `prev_hash` field of each new envelope
    points to header_hash of the most recent one, forming the tamper chain.
    """

    def __init__(self, run_id: str, envelopes_dir: Path) -> None:
        self.run_id = run_id
        self.envelopes_dir = envelopes_dir
        envelopes_dir.mkdir(parents=True, exist_ok=True)
        self.jsonl_path = envelopes_dir / f"{run_id}.jsonl"
        self.index_path = envelopes_dir / f"{run_id}.index"
        self._lock = threading.Lock()
        # In-memory map of envelope_id → byte offset in the JSONL.
        self._index: dict[str, int] = self._load_index()
        # The previous envelope's header_hash, for the prev-chain link.
        self._last_hash: str | None = self._compute_last_hash_from_index()

    def _load_index(self) -> dict[str, int]:
        if not self.index_path.exists():
            return {}
        out: dict[str, int] = {}
        for line in self.index_path.read_text().splitlines():
            if not line.strip():
                continue
            try:
                eid, offset = line.split("\t", 1)
                out[eid] = int(offset)
            except ValueError:
                continue
        return out

    def _compute_last_hash_from_index(self) -> str | None:
        if not self._index:
            return None
        # Largest offset = most recent entry
        last_eid = max(self._index, key=lambda eid: self._index[eid])
        return last_eid

    @property
    def last_prev_hash(self) -> str | None:
        """The header_hash of the most recent envelope (for the next envelope's `prev`)."""
        return self._last_hash

    def append(self, envelope: Notarized[Any]) -> str:
        """Append an envelope to the JSONL and update the index.

        Returns the envelope_id (= header_hash). Thread-safe.
        """
        eid = header_hash(envelope)
        payload = envelope.model_dump_json()

        with self._lock:
            offset = self.jsonl_path.stat().st_size if self.jsonl_path.exists() else 0
            with self.jsonl_path.open("ab") as f:
                f.write(payload.encode("utf-8") + b"\n")
            with self.index_path.open("ab") as idx:
                idx.write(f"{eid}\t{offset}\n".encode("utf-8"))
            self._index[eid] = offset
            self._last_hash = eid
        return eid

    def load(self, envelope_id: str) -> Notarized[Any]:
        """Re-hydrate an envelope by ID."""
        offset = self._index.get(envelope_id)
        if offset is None:
            raise KeyError(f"No such envelope_id: {envelope_id}")
        with self.jsonl_path.open("rb") as f:
            f.seek(offset)
            line = f.readline().decode("utf-8")
        payload = json.loads(line)
        return Notarized(**payload)

    def known_ids(self) -> list[str]:
        return list(self._index.keys())

    def __len__(self) -> int:
        return len(self._index)


__all__ = [
    "EnvelopeStore",
    "load_handle",
    "save_handle",
]
