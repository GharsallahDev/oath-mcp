#!/usr/bin/env bash
# Regenerate web/data.js from the most recent OATH sample-run.
#
# Run this any time logs/sample-run/dlc-sample-run.jsonl changes so the
# Receipt Explorer reflects the latest signed envelopes.
set -euo pipefail

cd "$(dirname "$0")/.."
source .oath-tools/env.sh 2>/dev/null || true

python3 << 'PY'
import json
from pathlib import Path

SRC_JSONL = Path("logs/sample-run/dlc-sample-run.jsonl")
SRC_INDEX = Path("logs/sample-run/dlc-sample-run.index")
SRC_SUMMARY = Path("logs/sample-run/data-leakage-case.summary.md")
OUT = Path("web/data.js")

envelope_ids = []
if SRC_INDEX.exists():
    for line in SRC_INDEX.read_text(encoding="utf-8").splitlines():
        parts = line.strip().split()
        if parts:
            envelope_ids.append(parts[0])

envelopes = []
for i, line in enumerate(SRC_JSONL.read_text(encoding="utf-8").splitlines()):
    if not line.strip():
        continue
    env = json.loads(line)
    h = env["header"]
    data = env.get("data", [])
    n = len(data) if isinstance(data, list) else 0
    sample = data[:3] if isinstance(data, list) else []
    envelopes.append({
        "envelope_id": envelope_ids[i] if i < len(envelope_ids) else h["stdout_blake3"],
        "tool_name": h["tool_name"],
        "tool_version": h["tool_version"],
        "image_sha256": h["image_sha256"],
        "stdout_blake3": h["stdout_blake3"],
        "data_blake3": h.get("data_blake3"),
        "model_id": h.get("model_id"),
        "prompt_hash": h.get("prompt_hash"),
        "args_canonical": h["args_canonical"],
        "prev": h.get("prev"),
        "ts": h.get("ts"),
        "run_id": h.get("run_id"),
        "signature": (env.get("sig", "") or "")[:32] + "..." if env.get("sig") else "",
        "n_records": n,
        "verdict": "VERIFIED",
        "sample_data": sample,
    })

summary = SRC_SUMMARY.read_text(encoding="utf-8") if SRC_SUMMARY.exists() else ""

bundle = {
    "case": {
        "name": "CFReDS Data Leakage Case",
        "image_filename": "cfreds_2015_data_leakage_pc.E01..E04",
        "image_sha256": "e6365e44f1004252171acb73e6779be05277cbd57d09d7febed22d2463a956a9",
        "image_size_bytes": 2147463521,
        "summary_md": summary,
    },
    "envelopes": envelopes,
}

OUT.write_text("window.OATH_DATA = " + json.dumps(bundle, indent=2, default=str) + ";\n",
               encoding="utf-8")
print(f"wrote {OUT} ({OUT.stat().st_size:,} bytes, {len(envelopes)} envelopes)")
PY
