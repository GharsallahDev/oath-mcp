#!/usr/bin/env bash
# OATH — full uninstall script.
#
# Removes everything OATH-related from your machine. Reversible to the
# extent that all changes were either inside this repo OR explicit
# brew-package installs.
#
# Usage:
#   bash ~/Desktop/RED/uninstall.sh           # interactive — prompts before each step
#   bash ~/Desktop/RED/uninstall.sh --yes     # non-interactive — no prompts
#
# After this finishes, deleting the RED/ folder itself is the final step
# (this script will not delete its own parent).

set -euo pipefail

NONINTERACTIVE=0
[ "${1:-}" = "--yes" ] && NONINTERACTIVE=1

prompt() {
  if [ "$NONINTERACTIVE" -eq 1 ]; then return 0; fi
  read -r -p "$1 [y/N] " ans
  case "$ans" in
    [Yy]|[Yy][Ee][Ss]) return 0 ;;
    *) return 1 ;;
  esac
}

OATH_ROOT="$(cd "$(dirname "$0")" && pwd)"

echo "OATH uninstall — staged removal."
echo
echo "OATH_ROOT = $OATH_ROOT"
echo

# --- 1. sandboxed tools ---------------------------------------------------- #
if [ -d "$OATH_ROOT/.oath-tools" ]; then
  echo "Step 1 — remove sandboxed forensic tools at $OATH_ROOT/.oath-tools"
  echo "  (~250 MB: EZ Tools, Hayabusa, the env script, downloaded zips)"
  if prompt "  proceed?"; then rm -rf "$OATH_ROOT/.oath-tools"; echo "  ✓ removed"; else echo "  (skipped)"; fi
  echo
fi

# --- 2. Python virtualenv -------------------------------------------------- #
if [ -d "$OATH_ROOT/.venv" ]; then
  echo "Step 2 — remove Python virtualenv at $OATH_ROOT/.venv"
  echo "  (volatility3, anthropic SDK, pydantic, all OATH deps — ~600 MB)"
  if prompt "  proceed?"; then rm -rf "$OATH_ROOT/.venv"; echo "  ✓ removed"; else echo "  (skipped)"; fi
  echo
fi

# --- 3. local corpus + logs ------------------------------------------------ #
if [ -d "$OATH_ROOT/corpus" ] || [ -d "$OATH_ROOT/logs" ] || [ -d "$OATH_ROOT/keys" ]; then
  echo "Step 3 — remove local data (corpus/, logs/, keys/, .oath/)"
  echo "  Includes the DFIR-Metric corpus + every Notarized envelope + per-run keys"
  if prompt "  proceed?"; then
    rm -rf "$OATH_ROOT/corpus" "$OATH_ROOT/logs" "$OATH_ROOT/keys" "$OATH_ROOT/.oath"
    echo "  ✓ removed"
  else
    echo "  (skipped)"
  fi
  echo
fi

# --- 4. brew packages ------------------------------------------------------ #
echo "Step 4 — Homebrew packages installed for OATH"
echo "  dotnet (.NET 10 SDK + runtime, ~400 MB)"
echo "  sleuthkit + deps (afflib, libewf, ~35 MB)"
echo "  powershell (~70 MB; was used to fetch EZ Tools)"
if command -v brew >/dev/null 2>&1; then
  if prompt "  uninstall all four?"; then
    brew uninstall --ignore-dependencies dotnet sleuthkit afflib libewf powershell 2>&1 | sed 's/^/  /'
    echo "  ✓ done"
  else
    echo "  (skipped — brew packages stay installed)"
  fi
else
  echo "  (brew not found — nothing to uninstall)"
fi
echo

# --- 5. final note --------------------------------------------------------- #
echo "Uninstall complete."
echo
echo "Final step (manual): if you want to delete the entire repo, run:"
echo "    rm -rf $OATH_ROOT"
echo
echo "If you used a git remote, also delete the GitHub repo via:"
echo "    gh repo delete <owner>/oath --yes"
