#!/usr/bin/env bash
# OATH — one-shot installer for the SANS SIFT Workstation (Ubuntu x86_64).
#
# Run this on a freshly-booted SIFT VM. Idempotent: rerunning re-uses any
# tool already on the system. Designed for the SANS Find Evil! hackathon
# judges so they can reproduce the published benchmark numbers on their
# own SIFT instance.
#
# Usage on the SIFT VM:
#   git clone https://github.com/GharsallahDev/oath ~/oath
#   cd ~/oath
#   bash scripts/install-on-sift.sh
#   source .oath-tools/env.sh
#   oath benchmark III --corpus corpus/DFIR-Metric-NSS.json --dry-run
#
# What it does:
#   - Verifies SIFT-baked tools (Sleuthkit, plaso, Volatility 3, etc.) are
#     present (they ship pre-installed on SIFT). Falls back to apt if not.
#   - Installs .NET 9 SDK + Hayabusa 3.9.0 + EZ Tools 2026.5.0 fresh —
#     these are NOT pre-baked into SIFT.
#   - Wires up .oath-tools/bin/ wrappers so OATH's typed functions can
#     shell out to plain commands (EvtxECmd / MFTECmd / RECmd / hayabusa).
#   - Creates a Python venv at .venv/ and installs OATH itself.
#
# SIFT pre-installed tools we rely on without re-installing:
#   sleuthkit (fls, icat, mmls, fsstat)
#   afflib + libewf
#   plaso (log2timeline.py + psort.py — native, no Docker needed on Linux!)
#   volatility3
#   python3
#
# Cleanup: ~/.oath/uninstall.sh or just `rm -rf ~/oath`.

set -euo pipefail

OATH_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OATH_TOOLS="$OATH_ROOT/.oath-tools"
EZ="$OATH_TOOLS/eztools/net9"
HAYABUSA_VER="3.9.0"

log() { printf '[install-on-sift] %s\n' "$*"; }
warn() { printf '[install-on-sift] WARN: %s\n' "$*" >&2; }
have() { command -v "$1" >/dev/null 2>&1; }

# ---------------------------------------------------------------------------- #
# Sanity                                                                       #
# ---------------------------------------------------------------------------- #
if ! uname -a | grep -q -i "linux"; then
  echo "[install-on-sift] ERROR: this script is for the SIFT Workstation (Linux)." >&2
  echo "                  For macOS, run scripts/install-tools.sh instead." >&2
  exit 1
fi

# ---------------------------------------------------------------------------- #
# SIFT-baked tools — should be present; verify and surface any gaps            #
# ---------------------------------------------------------------------------- #
log "verifying SIFT-baked DFIR tools..."

SIFT_BAKED=(sleuthkit volatility3)
SIFT_CMDS=(fls icat mmls vol log2timeline.py psort.py)
MISSING_CMDS=()
for cmd in "${SIFT_CMDS[@]}"; do
  if ! have "$cmd"; then
    MISSING_CMDS+=("$cmd")
  fi
done
if [ "${#MISSING_CMDS[@]}" -gt 0 ]; then
  warn "missing tools (apt-installing): ${MISSING_CMDS[*]}"
  sudo apt-get update -qq
  # SIFT base packages — fls/icat/mmls = sleuthkit; vol = volatility3;
  # log2timeline.py / psort.py = plaso.
  sudo apt-get install -y -qq sleuthkit volatility3 python3-pip python3-venv build-essential pkg-config curl unzip
  # plaso is in the GIFT PPA on Ubuntu; on a SIFT image it should already
  # be installed. If not, install via pip into the venv later.
fi

# ---------------------------------------------------------------------------- #
# .NET runtime — required by EZ Tools                                          #
# ---------------------------------------------------------------------------- #
if ! have dotnet; then
  log "installing .NET SDK (Microsoft Ubuntu repository)"
  # Microsoft's official Ubuntu install path.
  . /etc/os-release
  curl -sSL -o /tmp/packages-microsoft-prod.deb \
    "https://packages.microsoft.com/config/ubuntu/${VERSION_ID}/packages-microsoft-prod.deb"
  sudo dpkg -i /tmp/packages-microsoft-prod.deb
  rm -f /tmp/packages-microsoft-prod.deb
  sudo apt-get update -qq
  sudo apt-get install -y -qq dotnet-sdk-9.0 || sudo apt-get install -y -qq dotnet-sdk-8.0
fi
DOTNET_VER="$(dotnet --version 2>/dev/null || echo unknown)"
log "dotnet version: $DOTNET_VER"

# ---------------------------------------------------------------------------- #
# PowerShell — needed by Get-ZimmermanTools.ps1                                #
# ---------------------------------------------------------------------------- #
if ! have pwsh; then
  log "installing PowerShell"
  sudo apt-get install -y -qq powershell || {
    # Fallback: install via the dotnet-tool snap or direct .NET tool.
    dotnet tool install --global PowerShell || true
    export PATH="$HOME/.dotnet/tools:$PATH"
  }
fi

# ---------------------------------------------------------------------------- #
# EZ Tools (sandboxed under .oath-tools/eztools/net9)                          #
# ---------------------------------------------------------------------------- #
mkdir -p "$EZ"
if [ ! -d "$EZ/EvtxeCmd" ]; then
  log "downloading EZ Tools via Get-ZimmermanTools.ps1"
  curl -sSL -o "$OATH_TOOLS/eztools/Get-ZimmermanTools.ps1" \
    "https://raw.githubusercontent.com/EricZimmerman/Get-ZimmermanTools/master/Get-ZimmermanTools.ps1"
  pwsh "$OATH_TOOLS/eztools/Get-ZimmermanTools.ps1" \
    -Dest "$OATH_TOOLS/eztools" -NetVersion 9
else
  log "EZ Tools already present"
fi

# ---------------------------------------------------------------------------- #
# Hayabusa (Linux x86_64 native binary)                                        #
# ---------------------------------------------------------------------------- #
HAYABUSA_BIN="$OATH_TOOLS/hayabusa/hayabusa-${HAYABUSA_VER}-lin-x64-gnu"
if [ ! -x "$HAYABUSA_BIN" ]; then
  log "downloading Hayabusa $HAYABUSA_VER (linux x64)"
  mkdir -p "$OATH_TOOLS/hayabusa"
  curl -sSL -o /tmp/hayabusa.zip \
    "https://github.com/Yamato-Security/hayabusa/releases/download/v${HAYABUSA_VER}/hayabusa-${HAYABUSA_VER}-lin-x64-gnu.zip"
  unzip -qo /tmp/hayabusa.zip -d "$OATH_TOOLS/hayabusa"
  chmod +x "$HAYABUSA_BIN"
  rm -f /tmp/hayabusa.zip
else
  log "Hayabusa already present"
fi

# ---------------------------------------------------------------------------- #
# Generate env.sh + bin/ wrappers                                              #
# ---------------------------------------------------------------------------- #
log "writing .oath-tools/env.sh + wrappers"
cat > "$OATH_TOOLS/env.sh" <<ENVSH
#!/usr/bin/env bash
# OATH local tools environment (SIFT / Linux variant).
OATH_ROOT="\$(cd "\$(dirname "\${BASH_SOURCE[0]:-\${(%):-%N}}")/.." && pwd)"
OATH_TOOLS="\${OATH_ROOT}/.oath-tools"
export DOTNET_ROLL_FORWARD=Major
export DOTNET_NOLOGO=1
case ":\${PATH}:" in *":\${OATH_TOOLS}/bin:"*) ;; *) export PATH="\${OATH_TOOLS}/bin:\${PATH}" ;; esac
export OATH_EZTOOLS="\${OATH_TOOLS}/eztools/net9"
export OATH_HAYABUSA="\${OATH_TOOLS}/hayabusa"
export OATH_ROOT OATH_TOOLS
if [ -z "\${VIRTUAL_ENV:-}" ] && [ -f "\${OATH_ROOT}/.venv/bin/activate" ]; then
  . "\${OATH_ROOT}/.venv/bin/activate"
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
: "${DOTNET_ROLL_FORWARD:=Major}"; export DOTNET_ROLL_FORWARD
exec dotnet "${TARGET_DLL}" "$@"
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

# Hayabusa wrapper (native linux binary, no docker shim)
printf '#!/usr/bin/env bash\nexec %s "$@"\n' "$HAYABUSA_BIN" > "$OATH_TOOLS/bin/hayabusa"
chmod +x "$OATH_TOOLS/bin/hayabusa"

# plaso wrappers — on Linux/SIFT we use the SIFT-baked native binaries.
# Just symlink, no Docker shim needed.
if have log2timeline.py; then
  ln -sf "$(command -v log2timeline.py)" "$OATH_TOOLS/bin/log2timeline.py"
  ln -sf "$(command -v psort.py)" "$OATH_TOOLS/bin/psort.py"
  log "plaso: using SIFT-baked binaries (no Docker shim needed)"
else
  warn "plaso not on PATH; install via 'sudo apt-get install -y python3-plaso' or skip plaso_supertimeline"
fi

# ---------------------------------------------------------------------------- #
# Python venv + OATH package                                                   #
# ---------------------------------------------------------------------------- #
if [ ! -d "$OATH_ROOT/.venv" ]; then
  log "creating Python venv"
  python3 -m venv "$OATH_ROOT/.venv"
fi
# shellcheck disable=SC1091
source "$OATH_ROOT/.venv/bin/activate"
log "installing oath + extras into venv"
pip install --quiet --upgrade pip
pip install --quiet -e "$OATH_ROOT[dev,vertex]" volatility3

# ---------------------------------------------------------------------------- #
# Smoke verification                                                           #
# ---------------------------------------------------------------------------- #
log "smoke-testing the installed toolchain..."
source "$OATH_TOOLS/env.sh"

set +e
FAILURES=0
check() {
  local name="$1" cmd="$2"
  if eval "$cmd" >/dev/null 2>&1; then
    log "  ✓ $name"
  else
    warn "  ✗ $name FAILED: $cmd"
    FAILURES=$((FAILURES + 1))
  fi
}
check "fls (sleuthkit)"        "fls -V"
check "icat (sleuthkit)"       "icat -V"
check "mmls (sleuthkit)"       "mmls -V"
check "dotnet runtime"         "dotnet --version"
check "EvtxECmd"               "EvtxECmd --version"
check "MFTECmd"                "MFTECmd --version"
check "RECmd"                  "RECmd --version"
check "Hayabusa"               "hayabusa help"
check "vol (volatility 3)"     "vol --help"
check "log2timeline.py (plaso)" "log2timeline.py --version"
check "oath CLI"               "oath --version"
check "pytest suite (279+)"    "PYTHONPATH=$OATH_ROOT/src python -m pytest $OATH_ROOT/tests/ -q --tb=no 2>&1 | grep -E '[0-9]+ passed'"
set -e

if [ $FAILURES -gt 0 ]; then
  warn "$FAILURES smoke check(s) failed — review output above."
  exit 1
fi

# ---------------------------------------------------------------------------- #
# Done                                                                         #
# ---------------------------------------------------------------------------- #
log "install complete."
echo
echo "Activate the environment:"
echo "    source $OATH_TOOLS/env.sh"
echo
echo "Reproduce the DFIR-Metric Module III benchmark (no API key needed):"
echo "    python scripts/nss_baseline.py"
echo
echo "Reproduce with live Gemini agent (requires gcloud auth):"
echo "    python scripts/nss_baseline.py --live-vertex"
echo
echo "Run a triage on a forensic image:"
echo "    oath mount /path/to/image.E01"
echo "    oath verify <envelope-id>"
