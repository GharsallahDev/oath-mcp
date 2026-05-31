#!/usr/bin/env bash
# OATH — verify.sh
#
# One-line judge verifier. Re-runs a single finding's Replay Receipt on the
# original-image SHA-256 and proves the supporting evidence reproduces
# deterministically. Designed to run on a judge's laptop in <60 seconds.
#
# Usage:
#   ./verify.sh                          # interactive picker
#   ./verify.sh <finding-id>             # specific finding
#   ./verify.sh dfir-metric-case-42      # specific DFIR-Metric benchmark case
#
# Requires: docker (for sandboxed tool execution) OR direct vol3/eztools install.

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
