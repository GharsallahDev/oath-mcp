#!/usr/bin/env bash
# OATH — forensic-binary bootstrap for SANS SIFT Workstation (Ubuntu x86_64).
#
# `uvx oath-mcp` pulls only the Python wheel. The MCP server shells out to
# native forensic binaries that SIFT does NOT ship by default:
#
#   - EZ Tools  (EvtxECmd / MFTECmd / RECmd / AmcacheParser / PECmd / ...)
#   - Hayabusa  (Sigma-driven EVTX triage)
#
# This script installs ONLY those, plus their .NET 9 runtime + PATH wiring.
# It does NOT install Python, OATH, uv, Protocol SIFT, or Claude Code —
# those are separate one-liners (see README "Quick Start").
#
# Idempotent. Curl-pipe-bash friendly:
#
#   curl -fsSL https://raw.githubusercontent.com/GharsallahDev/oath-mcp/main/scripts/bootstrap-forensic-tools.sh | bash
#
# Time: ~10 minutes on a fresh SIFT VM.

set -euo pipefail

HAYABUSA_VER="3.9.0"
INSTALL_ROOT="${OATH_TOOLS_ROOT:-$HOME/.local/share/oath-tools}"
EZ_DIR="$INSTALL_ROOT/eztools/net9"
HAYABUSA_DIR="$INSTALL_ROOT/hayabusa"
BIN_DIR="$INSTALL_ROOT/bin"

log() { printf '[bootstrap-forensic-tools] %s\n' "$*" >&2; }
have() { command -v "$1" >/dev/null 2>&1; }

# ---------------------------------------------------------------------------- #
# Guards                                                                       #
# ---------------------------------------------------------------------------- #
ARCH="$(uname -m)"
case "$ARCH" in
  x86_64|amd64) ;;
  *)
    echo "ERROR: only x86_64 is supported (EZ Tools + Hayabusa are x64); detected $ARCH." >&2
    echo "       If on Apple Silicon, run inside an x86_64 SIFT VM (UTM emulation)." >&2
    exit 1
    ;;
esac

if ! grep -qi ubuntu /etc/os-release 2>/dev/null; then
  log "WARN: not detected as Ubuntu/SIFT — proceeding anyway."
fi

mkdir -p "$INSTALL_ROOT" "$BIN_DIR" "$EZ_DIR" "$HAYABUSA_DIR"

# ---------------------------------------------------------------------------- #
# .NET 9 SDK — required by EZ Tools                                            #
# ---------------------------------------------------------------------------- #
if ! have dotnet; then
  log "installing .NET SDK (Microsoft Ubuntu repository)"
  . /etc/os-release
  curl -sSL -o /tmp/packages-microsoft-prod.deb \
    "https://packages.microsoft.com/config/ubuntu/${VERSION_ID}/packages-microsoft-prod.deb"
  sudo dpkg -i /tmp/packages-microsoft-prod.deb
  rm -f /tmp/packages-microsoft-prod.deb
  sudo apt-get update -qq
  sudo apt-get install -y -qq dotnet-sdk-9.0 || sudo apt-get install -y -qq dotnet-sdk-8.0
fi
log "dotnet version: $(dotnet --version)"

# ---------------------------------------------------------------------------- #
# PowerShell — needed by Get-ZimmermanTools.ps1                                #
# ---------------------------------------------------------------------------- #
if ! have pwsh; then
  log "installing PowerShell"
  sudo apt-get install -y -qq powershell || {
    dotnet tool install --global PowerShell || true
    export PATH="$HOME/.dotnet/tools:$PATH"
  }
fi

# ---------------------------------------------------------------------------- #
# EZ Tools (net9 bundle)                                                       #
# ---------------------------------------------------------------------------- #
if [ ! -d "$EZ_DIR/EvtxeCmd" ]; then
  log "downloading EZ Tools (Get-ZimmermanTools.ps1, net9 bundle)"
  curl -sSL -o "$INSTALL_ROOT/eztools/Get-ZimmermanTools.ps1" \
    "https://raw.githubusercontent.com/EricZimmerman/Get-ZimmermanTools/master/Get-ZimmermanTools.ps1"
  pwsh "$INSTALL_ROOT/eztools/Get-ZimmermanTools.ps1" \
    -Dest "$INSTALL_ROOT/eztools" -NetVersion 9
else
  log "EZ Tools already present at $EZ_DIR"
fi

# ---------------------------------------------------------------------------- #
# Hayabusa (Linux x86_64 native binary)                                        #
# ---------------------------------------------------------------------------- #
HAYABUSA_BIN="$HAYABUSA_DIR/hayabusa-${HAYABUSA_VER}-lin-x64-gnu"
if [ ! -x "$HAYABUSA_BIN" ]; then
  log "downloading Hayabusa ${HAYABUSA_VER} (linux x64)"
  curl -sSL -o /tmp/hayabusa.zip \
    "https://github.com/Yamato-Security/hayabusa/releases/download/v${HAYABUSA_VER}/hayabusa-${HAYABUSA_VER}-lin-x64-gnu.zip"
  unzip -qo /tmp/hayabusa.zip -d "$HAYABUSA_DIR"
  chmod +x "$HAYABUSA_BIN"
  rm -f /tmp/hayabusa.zip
else
  log "Hayabusa already present at $HAYABUSA_BIN"
fi

# ---------------------------------------------------------------------------- #
# dotnet-wrap shim + per-tool wrappers                                         #
# ---------------------------------------------------------------------------- #
cat > "$BIN_DIR/_dotnet-wrap.sh" <<'WRAPSH'
#!/usr/bin/env bash
set -euo pipefail
if [ -z "${TARGET_DLL:-}" ] || [ ! -f "${TARGET_DLL}" ]; then
  echo "_dotnet-wrap: TARGET_DLL not set or missing ($TARGET_DLL)" >&2; exit 127
fi
: "${DOTNET_ROOT:=/usr/share/dotnet}"; export DOTNET_ROOT
: "${DOTNET_ROLL_FORWARD:=Major}"; export DOTNET_ROLL_FORWARD
DOTNET_BIN=""
if [ -x "$DOTNET_ROOT/dotnet" ]; then DOTNET_BIN="$DOTNET_ROOT/dotnet"
elif [ -x "/usr/share/dotnet/dotnet" ]; then DOTNET_BIN="/usr/share/dotnet/dotnet"
elif [ -x "/usr/local/bin/dotnet" ]; then DOTNET_BIN="/usr/local/bin/dotnet"
elif command -v dotnet >/dev/null 2>&1; then DOTNET_BIN="$(command -v dotnet)"
else echo "_dotnet-wrap: dotnet binary not found" >&2; exit 127
fi
exec "$DOTNET_BIN" "${TARGET_DLL}" "$@"
WRAPSH
chmod +x "$BIN_DIR/_dotnet-wrap.sh"

for pair in \
  "EvtxECmd|$EZ_DIR/EvtxeCmd/EvtxECmd.dll" \
  "MFTECmd|$EZ_DIR/MFTECmd.dll" \
  "AmcacheParser|$EZ_DIR/AmcacheParser.dll" \
  "PECmd|$EZ_DIR/PECmd.dll" \
  "RECmd|$EZ_DIR/RECmd/RECmd.dll" \
  "SBECmd|$EZ_DIR/SBECmd.dll" \
  "JLECmd|$EZ_DIR/JLECmd.dll" \
  "LECmd|$EZ_DIR/LECmd.dll" \
  "WxTCmd|$EZ_DIR/WxTCmd.dll" \
  "SrumECmd|$EZ_DIR/SrumECmd.dll" \
  "AppCompatCacheParser|$EZ_DIR/AppCompatCacheParser.dll" \
  "RBCmd|$EZ_DIR/RBCmd.dll" \
  "bstrings|$EZ_DIR/bstrings.dll"; do
  name="${pair%%|*}"; dll="${pair#*|}"
  printf '#!/usr/bin/env bash\nTARGET_DLL="%s" exec "$(dirname "$0")/_dotnet-wrap.sh" "$@"\n' "$dll" > "$BIN_DIR/$name"
  chmod +x "$BIN_DIR/$name"
done

# Hayabusa wrapper
printf '#!/usr/bin/env bash\nexec %s "$@"\n' "$HAYABUSA_BIN" > "$BIN_DIR/hayabusa"
chmod +x "$BIN_DIR/hayabusa"

# ---------------------------------------------------------------------------- #
# Persist PATH + DOTNET_ROOT to ~/.bashrc                                      #
# ---------------------------------------------------------------------------- #
BASHRC="$HOME/.bashrc"
MARKER="# >>> oath-mcp forensic-tools (managed by bootstrap-forensic-tools.sh) >>>"
END_MARKER="# <<< oath-mcp forensic-tools <<<"

if ! grep -qF "$MARKER" "$BASHRC" 2>/dev/null; then
  cat >> "$BASHRC" <<RC

$MARKER
export DOTNET_ROOT="\${DOTNET_ROOT:-/usr/share/dotnet}"
export DOTNET_ROLL_FORWARD=Major
export DOTNET_NOLOGO=1
case ":\${PATH}:" in *":$BIN_DIR:"*) ;; *) export PATH="$BIN_DIR:\${PATH}" ;; esac
$END_MARKER
RC
  log "wrote PATH + DOTNET_ROOT exports to ~/.bashrc"
else
  log "~/.bashrc already wired (marker found)"
fi

# ---------------------------------------------------------------------------- #
# Smoke verify (uses BIN_DIR directly — don't rely on a re-sourced shell)      #
# ---------------------------------------------------------------------------- #
export PATH="$BIN_DIR:$PATH"
export DOTNET_ROOT="${DOTNET_ROOT:-/usr/share/dotnet}"
log "smoke testing..."
FAILURES=0
for chk in "EvtxECmd --version" "MFTECmd --version" "RECmd --version" "hayabusa help"; do
  if eval "$chk" >/dev/null 2>&1; then
    log "  ok: $chk"
  else
    log "  FAIL: $chk"
    FAILURES=$((FAILURES + 1))
  fi
done

if [ "$FAILURES" -gt 0 ]; then
  log "$FAILURES smoke check(s) failed."
  exit 1
fi

cat >&2 <<EOF

Forensic-binary bootstrap complete.

Tools installed at: $INSTALL_ROOT
Exports added to:  $HOME/.bashrc

Open a NEW shell (or run \`exec bash\`) before continuing.

Next steps for OATH:
  1. curl -LsSf https://astral.sh/uv/install.sh | sh    # install uv if missing
  2. claude mcp add --transport stdio oath -- uvx oath-mcp
  3. claude  # then type /mcp to confirm 'oath: connected · 13 tools'

EOF
