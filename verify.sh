#!/usr/bin/env bash
# OATH — verify.sh
#
# One-line examiner verifier. Re-runs a single finding's Replay Receipt
# against the original-image SHA-256 and confirms the supporting evidence
# reproduces deterministically. Designed to run on an analyst's commodity
# laptop in well under a minute.
#
# Usage:
#   ./verify.sh                          # list known envelopes
#   ./verify.sh <envelope-id>            # verify one envelope
#   ./verify.sh --logs-dir <path> <envelope-id>
#
# Requires: a Python interpreter and the OATH package (no LLM, no MCP).

set -euo pipefail

OATH_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OATH_BIN="${OATH_ROOT}/src/oath/cli.py"

# Detect Python
PYTHON_BIN="$(command -v python3 || command -v python)"
if [ -z "$PYTHON_BIN" ]; then
  echo "ERROR: python3 not found on PATH." >&2
  exit 1
fi

# Boot the OATH CLI in verifier-only mode (no LLM, no MCP, just receipt replay).
exec "$PYTHON_BIN" -m oath verify "$@"
