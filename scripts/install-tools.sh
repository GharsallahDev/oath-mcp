#!/usr/bin/env bash
# OATH — one-shot tool installer for macOS arm64 (Apple Silicon).
#
# Idempotent: rerunning re-uses anything already installed. Self-contained
# under $OATH_ROOT/.oath-tools/ where possible; Homebrew packages live in
# /opt/homebrew/ and are listed in uninstall.sh.
#
# Tools installed:
#   - dotnet 10        (brew, hosts the .NET 9 EZ Tools via DOTNET_ROLL_FORWARD)
#   - sleuthkit        (brew, fls/icat/mmls for image walking)
#   - powershell       (brew, used by Get-ZimmermanTools)
#   - colima + docker  (brew, lightweight Docker runtime — for plaso amd64)
#   - EZ Tools         (.oath-tools/eztools/net9/, via Get-ZimmermanTools.ps1)
#   - Hayabusa 3.9.0   (.oath-tools/hayabusa/, GitHub release arm64 binary)
#   - log2timeline/plaso:latest amd64 Docker image (under Rosetta via colima)
#
# Python deps (volatility3, plaso-via-docker, anthropic, ...) are managed by
# the venv at $OATH_ROOT/.venv — separate from this script. After running
# this, `source $OATH_ROOT/.oath-tools/env.sh` to load PATH + DOTNET_ROOT.

set -euo pipefail

OATH_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OATH_TOOLS="$OATH_ROOT/.oath-tools"
EZ="$OATH_TOOLS/eztools/net9"
HAYABUSA_VER="3.9.0"

log() { printf '[install] %s\n' "$*"; }
have() { command -v "$1" >/dev/null 2>&1; }

# ---------------------------------------------------------------------------- #
# 0. Protocol SIFT baseline                                                    #
# ---------------------------------------------------------------------------- #
# OATH extends Protocol SIFT (teamdfir/protocol-sift). Protocol SIFT installs
# Claude Code + 5 DFIR skill packs + a PDF report generator under ~/.claude.
# OATH inherits that baseline and layers its typed MCP server +
# Notarized<T> envelope + Witness Oath Verifier on top. The Find Evil!
# Get-Started step calls for this install. Skip-flag:
#   OATH_SKIP_PROTOCOL_SIFT=1 bash scripts/install-tools.sh
if [[ "${OATH_SKIP_PROTOCOL_SIFT:-0}" != "1" ]]; then
  if [[ -d "$HOME/.claude/skills/memory-analysis" ]] && \
     [[ -f "$HOME/.claude/CLAUDE.md" ]]; then
    log "Protocol SIFT already present at \$HOME/.claude — skipping baseline install."
  else
    log "installing Protocol SIFT baseline (teamdfir/protocol-sift)..."
    curl -fsSL https://raw.githubusercontent.com/teamdfir/protocol-sift/main/install.sh | bash
    log "Protocol SIFT baseline installed."
  fi
else
  log "OATH_SKIP_PROTOCOL_SIFT=1 set — assuming Protocol SIFT was installed already."
fi

# ---------------------------------------------------------------------------- #
# 1. Homebrew + system packages                                                #
# ---------------------------------------------------------------------------- #
if ! have brew; then
  echo "[install] ERROR: Homebrew not found. Install from https://brew.sh first." >&2
  exit 1
fi

for pkg in dotnet sleuthkit powershell colima docker; do
  if brew list "$pkg" >/dev/null 2>&1; then
    log "$pkg already installed"
  else
    log "brew install $pkg"
    brew install "$pkg"
  fi
done
brew link --overwrite docker >/dev/null 2>&1 || true

# ---------------------------------------------------------------------------- #
# 2. EZ Tools (.NET 9, sandboxed)                                              #
# ---------------------------------------------------------------------------- #
mkdir -p "$EZ"
if [ ! -d "$EZ/EvtxeCmd" ]; then
  log "downloading EZ Tools via Get-ZimmermanTools.ps1"
  curl -sSL -o "$OATH_TOOLS/eztools/Get-ZimmermanTools.ps1" \
    "https://raw.githubusercontent.com/EricZimmerman/Get-ZimmermanTools/master/Get-ZimmermanTools.ps1"
  pwsh "$OATH_TOOLS/eztools/Get-ZimmermanTools.ps1" -Dest "$OATH_TOOLS/eztools" -NetVersion 9
else
  log "EZ Tools already present"
fi

# ---------------------------------------------------------------------------- #
# 3. Hayabusa (Rust, native arm64 binary)                                      #
# ---------------------------------------------------------------------------- #
if [ ! -x "$OATH_TOOLS/hayabusa/hayabusa-${HAYABUSA_VER}-mac-aarch64" ]; then
  log "downloading Hayabusa $HAYABUSA_VER"
  mkdir -p "$OATH_TOOLS/hayabusa"
  curl -sSL -o /tmp/hayabusa.zip \
    "https://github.com/Yamato-Security/hayabusa/releases/download/v${HAYABUSA_VER}/hayabusa-${HAYABUSA_VER}-mac-aarch64.zip"
  unzip -qo /tmp/hayabusa.zip -d "$OATH_TOOLS/hayabusa"
  chmod +x "$OATH_TOOLS/hayabusa/hayabusa-${HAYABUSA_VER}-mac-aarch64"
  xattr -d com.apple.quarantine "$OATH_TOOLS/hayabusa/hayabusa-${HAYABUSA_VER}-mac-aarch64" 2>/dev/null || true
  rm -f /tmp/hayabusa.zip
else
  log "Hayabusa already present"
fi

# ---------------------------------------------------------------------------- #
# 4. plaso Docker image (amd64; runs under Rosetta via colima)                 #
# ---------------------------------------------------------------------------- #
if ! colima status >/dev/null 2>&1; then
  log "starting colima VM"
  colima start --arch aarch64 --cpu 4 --memory 8 --disk 30
fi
if ! docker image inspect log2timeline/plaso:latest >/dev/null 2>&1; then
  log "pulling log2timeline/plaso:latest (linux/amd64)"
  docker pull --platform linux/amd64 log2timeline/plaso:latest
else
  log "plaso image already pulled"
fi

# ---------------------------------------------------------------------------- #
# 5. Generate .oath-tools/env.sh + .oath-tools/bin/ wrappers                   #
# ---------------------------------------------------------------------------- #
log "writing .oath-tools/env.sh + wrappers"
cat > "$OATH_TOOLS/env.sh" <<'ENVSH'
#!/usr/bin/env bash
# OATH local tools environment. Source this BEFORE running `oath`.
OATH_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]:-${(%):-%N}}")/.." && pwd)"
OATH_TOOLS="${OATH_ROOT}/.oath-tools"
export DOTNET_ROOT="/opt/homebrew/opt/dotnet/libexec"
export DOTNET_ROLL_FORWARD=Major
export DOTNET_NOLOGO=1
case ":${PATH}:" in *":${OATH_TOOLS}/hayabusa:"*) ;; *) export PATH="${OATH_TOOLS}/hayabusa:${PATH}" ;; esac
case ":${PATH}:" in *":${OATH_TOOLS}/bin:"*) ;; *) export PATH="${OATH_TOOLS}/bin:${PATH}" ;; esac
export OATH_EZTOOLS="${OATH_TOOLS}/eztools/net9"
export OATH_HAYABUSA="${OATH_TOOLS}/hayabusa"
export OATH_ROOT OATH_TOOLS
if [ -z "${VIRTUAL_ENV:-}" ] && [ -f "${OATH_ROOT}/.venv/bin/activate" ]; then
  . "${OATH_ROOT}/.venv/bin/activate"
fi
ENVSH
chmod +x "$OATH_TOOLS/env.sh"

mkdir -p "$OATH_TOOLS/bin"
cat > "$OATH_TOOLS/bin/_dotnet-wrap.sh" <<'WRAPSH'
#!/usr/bin/env bash
set -euo pipefail
if [ -z "${TARGET_DLL:-}" ] || [ ! -f "${TARGET_DLL}" ]; then
  echo "_dotnet-wrap: TARGET_DLL not set or missing ($TARGET_DLL)" >&2; exit 127
fi
: "${DOTNET_ROOT:=/opt/homebrew/opt/dotnet/libexec}"; export DOTNET_ROOT
: "${DOTNET_ROLL_FORWARD:=Major}"; export DOTNET_ROLL_FORWARD
# Resolve dotnet explicitly so a clean shell (PATH without /opt/homebrew/bin)
# still finds it — ./verify.sh from a fresh shell must work.
DOTNET_BIN=""
if [ -x "$DOTNET_ROOT/dotnet" ]; then DOTNET_BIN="$DOTNET_ROOT/dotnet"
elif [ -x "/opt/homebrew/bin/dotnet" ]; then DOTNET_BIN="/opt/homebrew/bin/dotnet"
elif [ -x "/usr/local/bin/dotnet" ]; then DOTNET_BIN="/usr/local/bin/dotnet"
elif command -v dotnet >/dev/null 2>&1; then DOTNET_BIN="$(command -v dotnet)"
else echo "_dotnet-wrap: dotnet binary not found in DOTNET_ROOT=$DOTNET_ROOT or PATH" >&2; exit 127
fi
exec "$DOTNET_BIN" "${TARGET_DLL}" "$@"
WRAPSH
chmod +x "$OATH_TOOLS/bin/_dotnet-wrap.sh"

for pair in \
  "EvtxECmd|$EZ/EvtxeCmd/EvtxECmd.dll" \
  "MFTECmd|$EZ/MFTECmd.dll" \
  "AmcacheParser|$EZ/AmcacheParser.dll" \
  "PECmd|$EZ/PECmd.dll" \
  "RECmd|$EZ/RECmd/RECmd.dll" \
  "SBECmd|$EZ/SBECmd.dll" \
  "JLECmd|$EZ/JLECmd.dll" \
  "LECmd|$EZ/LECmd.dll" \
  "WxTCmd|$EZ/WxTCmd.dll" \
  "SrumECmd|$EZ/SrumECmd.dll" \
  "AppCompatCacheParser|$EZ/AppCompatCacheParser.dll" \
  "RBCmd|$EZ/RBCmd.dll" \
  "bstrings|$EZ/bstrings.dll"; do
  name="${pair%%|*}"; dll="${pair#*|}"
  printf '#!/usr/bin/env bash\nTARGET_DLL="%s" exec "$(dirname "$0")/_dotnet-wrap.sh" "$@"\n' "$dll" > "$OATH_TOOLS/bin/$name"
  chmod +x "$OATH_TOOLS/bin/$name"
done

printf '#!/usr/bin/env bash\nexec %s/hayabusa-%s-mac-aarch64 "$@"\n' "$OATH_TOOLS/hayabusa" "$HAYABUSA_VER" > "$OATH_TOOLS/bin/hayabusa"
chmod +x "$OATH_TOOLS/bin/hayabusa"

for tool in psort log2timeline; do
  cat > "$OATH_TOOLS/bin/${tool}.py" <<PLASOSH
#!/usr/bin/env bash
set -euo pipefail
VOLUMES=()
seen=""
for arg in "\$@"; do
  if [[ "\$arg" = /* ]]; then
    dir="\$(dirname "\$arg")"
    case ":\$seen:" in
      *":\$dir:"*) ;;
      *) VOLUMES+=("-v" "\$dir:\$dir"); seen="\$seen:\$dir" ;;
    esac
  fi
done
case ":\$seen:" in *":\$PWD:"*) ;; *) VOLUMES+=("-v" "\$PWD:\$PWD") ;; esac
exec docker run --rm --platform linux/amd64 --user "\$(id -u):\$(id -g)" -w "\$PWD" "\${VOLUMES[@]}" log2timeline/plaso:latest $tool "\$@"
PLASOSH
  chmod +x "$OATH_TOOLS/bin/${tool}.py"
done

# ---------------------------------------------------------------------------- #
# 6. Python venv + oath package                                                #
# ---------------------------------------------------------------------------- #
if [ ! -d "$OATH_ROOT/.venv" ]; then
  log "creating Python venv"
  python3 -m venv "$OATH_ROOT/.venv"
fi
# shellcheck disable=SC1091
source "$OATH_ROOT/.venv/bin/activate"
log "installing oath package + claude extras + volatility3"
pip install --quiet --upgrade pip
pip install --quiet -e "$OATH_ROOT[dev,claude]" volatility3

log "done."
echo
echo "Activate the environment:"
echo "    source $OATH_TOOLS/env.sh"
echo
echo "Smoke-test:"
echo "    oath mount path/to/Hacking_Case.E01"
