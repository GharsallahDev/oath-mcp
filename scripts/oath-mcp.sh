#!/usr/bin/env bash
# DEV ONLY — source-tree wrapper for hacking on OATH without `pip install -e .`.
#
# End users should NOT run this. The canonical install path is:
#
#   claude mcp add --transport stdio oath -- uvx oath-mcp \
#       --logs-dir ~/.local/share/oath/logs \
#       --keys-dir ~/.local/share/oath/keys
#
# That uses the published PyPI wheel (or the git+ fallback), needs no clone,
# no venv sourcing, no PYTHONPATH munging. See README.md "Quick Start".
#
# This wrapper exists for ONE reason: when you are editing src/oath/mcp/**
# locally and want Claude Code to spawn the MCP server from your working
# checkout instead of an isolated uvx environment. It sources the local
# tools env so EvtxECmd/MFTECmd/hayabusa resolve, then runs the package
# out of src/ with the local .venv's Python.
#
# Wire it up the same way (just point at this script instead of uvx):
#
#   claude mcp add --transport stdio oath -- /abs/path/to/scripts/oath-mcp.sh
#
# Stays on stdio — Claude Code communicates with the server over stdin/stdout
# per MCP. All status messages MUST go to stderr.
set -euo pipefail

OATH_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Source the tools environment so MFTECmd, EvtxECmd, hayabusa, etc. are on
# PATH inside the MCP subprocess. Claude Code spawns this with a minimal
# env, so without this the typed forensic functions can't shell out.
if [ -f "$OATH_ROOT/.oath-tools/env.sh" ]; then
  # shellcheck source=/dev/null
  . "$OATH_ROOT/.oath-tools/env.sh"
fi

# Prefer the OATH venv's Python.
if [ -x "$OATH_ROOT/.venv/bin/python" ]; then
  PYTHON_BIN="$OATH_ROOT/.venv/bin/python"
else
  PYTHON_BIN="$(command -v python3 || command -v python)"
fi

# Logs + keys live in the repo. The MCP server appends signed envelopes
# to logs/envelopes/ as the agent calls typed functions.
exec env PYTHONPATH="${PYTHONPATH:-}:$OATH_ROOT/src" \
  "$PYTHON_BIN" -m oath.mcp.server \
    --logs-dir "$OATH_ROOT/logs" \
    --keys-dir "$OATH_ROOT/keys"
