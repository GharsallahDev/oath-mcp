#!/usr/bin/env bash
# Wrapper that boots the OATH MCP server under the right environment.
# Registered with Claude Code via `claude mcp add` (see install-oath-mcp.sh).
#
# Stays on stdio — Claude Code communicates with the server over stdin/stdout
# per the Model Context Protocol. All status messages MUST go to stderr.
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
