#!/usr/bin/env bash
# Register the OATH MCP server with Claude Code (one-time setup).
#
# After running this, `claude` will see 13 OATH typed tools alongside its
# default ones:
#   oath_mount, oath_list_handles,
#   parse_evtx, parse_mft, parse_registry, parse_usnjrnl, parse_amcache,
#   parse_prefetch, run_hayabusa, plaso_supertimeline, vol3_query,
#   find_strings_on_image, enumerate_credential_artifacts,
#   oath_verify_claim
#
# Usage:
#   bash scripts/install-oath-mcp.sh
#   claude    # tools should now be in the palette
#
# Idempotent — re-running replaces any existing 'oath' MCP registration.

set -euo pipefail

OATH_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WRAPPER="$OATH_ROOT/scripts/oath-mcp.sh"

if ! command -v claude >/dev/null 2>&1; then
  echo "ERROR: 'claude' (Claude Code) is not on PATH." >&2
  echo "       Install Claude Code first via Protocol SIFT: " >&2
  echo "         curl -fsSL https://raw.githubusercontent.com/teamdfir/protocol-sift/main/install.sh | bash" >&2
  exit 1
fi

if [ ! -x "$WRAPPER" ]; then
  echo "Making wrapper executable: $WRAPPER" >&2
  chmod +x "$WRAPPER"
fi

# Remove any prior registration (claude mcp remove is a no-op if absent).
claude mcp remove oath 2>/dev/null || true

# Register OATH as a stdio MCP server. The wrapper handles env.sh sourcing.
echo "Registering OATH MCP server with Claude Code..." >&2
claude mcp add oath -- "$WRAPPER"

echo "" >&2
echo "✓ OATH MCP server registered. Verify with:" >&2
echo "    claude mcp list" >&2
echo "" >&2
echo "Then start a Claude session:" >&2
echo "    cd $OATH_ROOT" >&2
echo "    claude" >&2
echo "" >&2
echo "In the Claude session, type /mcp to confirm 'oath' is connected." >&2
