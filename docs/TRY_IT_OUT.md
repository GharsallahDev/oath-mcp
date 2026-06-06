# Try OATH

Unabridged walkthrough for the impatient examiner. macOS Apple-Silicon focused; the same recipe works on Intel macOS and Linux with minor adjustments noted inline.

## 1. Prerequisites

Three things, all standard on a developer Mac:

- **Homebrew** — installer at https://brew.sh
- **Python 3.11+** — included with macOS 14+, or `brew install python@3.14`
- **Xcode Command Line Tools** — installed by `xcode-select --install` if you don't have them

For the hosted live-agent mode (optional), you'll additionally need:

- **gcloud CLI** with an authenticated project (`gcloud auth application-default login`)
- The required hosted-model API enabled for the authenticated project

## 2. One-shot install (canonical)

The canonical install is the published Python MCP server. One line wires it
into Claude Code:

```bash
claude mcp add --transport stdio oath -- uvx oath-mcp
```

That single command pulls the `oath-mcp` package from PyPI, isolates it via
`uv`, and registers it as a stdio MCP server. Identical behavior on the SIFT
Workstation and on a developer Mac. Confirm the 16 typed tools are connected
with `claude` → `/mcp`.

### Long-form alternative (full-control install scripts)

If you want the pinned forensic-tool versions and a self-contained source
checkout — for benchmark reproduction, contribution work, or air-gapped
deployment — use the longer-form scripts. Both call Protocol SIFT's
installer first, then layer OATH on top:

```bash
git clone https://github.com/GharsallahDev/oath-mcp && cd oath-mcp
bash scripts/install-tools.sh                       # macOS
# OR — on the SANS SIFT Workstation (Ubuntu x86_64):
bash scripts/install-on-sift.sh
```

**If you already have Protocol SIFT installed**, set
`OATH_SKIP_PROTOCOL_SIFT=1` to skip the baseline step:

```bash
OATH_SKIP_PROTOCOL_SIFT=1 bash scripts/install-on-sift.sh
```

The installer is idempotent. It will:

| Step | Where it lives | Removable via |
|---|---|---|
| `brew install dotnet sleuthkit powershell colima docker` | `/opt/homebrew/` | `uninstall.sh` |
| EZ Tools (.NET 9, calendar-versioned 2026.5.0) | `.oath-tools/eztools/net9/` | `rm -rf .oath-tools` |
| Hayabusa 3.9.0 native-arm64 binary | `.oath-tools/hayabusa/` | `rm -rf .oath-tools` |
| `log2timeline/plaso:latest` amd64 Docker image (runs under Rosetta via colima) | colima VM | `colima delete --force` |
| Wrapper scripts so `EvtxECmd`, `MFTECmd`, `psort.py`, … are plain commands on PATH | `.oath-tools/bin/` | `rm -rf .oath-tools` |
| Python venv with OATH itself, volatility 3, google-cloud-aiplatform | `.venv/` | `rm -rf .venv` |

Total disk: ~1.5 GB across all of the above.

## 3. Activate the environment

```bash
source .oath-tools/env.sh
```

This sets `DOTNET_ROOT`, prepends `.oath-tools/bin/` and `.oath-tools/hayabusa/` to PATH, activates the Python venv, and otherwise touches nothing on your shell. Sourcing twice is safe (idempotent).

Sanity:
```bash
EvtxECmd --version       # 2026.5.0+<sha>
MFTECmd --version        # 2026.5.0+<sha>
hayabusa help            # Hayabusa v3.9.0 - Showa Day Release
psort.py --version       # plaso - psort version 20260512
fls -V                   # The Sleuth Kit ver 4.15.0
vol --help               # volatility 3, framework version 2.28.0
```

## 4. Mount an image

```bash
oath mount path/to/Hacking_Case.E01
```

What it does:
- Streams the image's bytes through BLAKE3 to compute the SHA-256
- Mounts it read-only (`losetup -r` on Linux; raw-file access on macOS)
- Persists an `EvidenceHandle` to `logs/handles/<handle-id>.json`

The `handle-id` is what subsequent tool calls reference. The image SHA-256 is bound into every downstream `Notarized<T>` envelope.

## 5. Run the DFIR-Metric Module III benchmark

The corpus file ships with the repo. The image is from NIST CFTT:

```bash
# Get the NIST String Search Test Data Set (8.7 MB zip; expands to two 2 GB .dd files)
curl -sSL -o /tmp/nss.zip \
  "https://cfreds-archive.nist.gov/StringSearching/string-search-federated-testing-data-set-version-1-1-revised-september-27-2019.zip"
unzip /tmp/nss.zip -d corpus/nss-string-search

# Mount both halves
oath mount corpus/nss-string-search/string-search-federated-testing-data-set-version-1-1-revised-september-27-2019/copy-to-test-computer/ss-win-07-25-18.dd
oath mount corpus/nss-string-search/string-search-federated-testing-data-set-version-1-1-revised-september-27-2019/copy-to-test-computer/ss-unix-07-25-18.dd

# Download the corpus (510 questions, 844 KB)
curl -sSL -o corpus/DFIR-Metric-NSS.json \
  "https://raw.githubusercontent.com/DFIR-Metric/DFIR-Metric/main/DFIR-Metric-NSS.json"

# Run the deterministic baseline (no API; ~3-5 min on M5 Pro)
python scripts/nss_baseline.py

# OR run the live Gemini agent (requires hosted-model credentials)
python scripts/nss_baseline.py --live-vertex
```

Both modes write a signed `BenchmarkResult` JSON to `logs/benchmarks/`.

## 6. Re-verify an envelope

```bash
oath verify --logs-dir ./logs                           # list known envelope IDs
oath verify <envelope-id>                               # PASS / FAIL with details
```

The re-verify path re-runs the bound tool (same args from `args_canonical`), recomputes BLAKE3 of the stdout AND `data_blake3` of the persisted records, compares both to the signed receipt. Catches tampering with either raw stdout or the persisted typed-data field. No LLM, no MCP, fully deterministic. Under a minute on commodity hardware.

## 7. Hypothesis-driven triage over signed envelopes

```bash
oath triage                                             # all 5 default hypotheses
oath triage --hypothesis "Pass-the-Hash"                # filter by substring
oath triage --out triage-report.json                    # write JSON instead of stdout
```

Loads every signed envelope under `logs/envelopes/` and `logs/sample-run/`, then runs the Witness Oath Verifier across the canonical PtH hypothesis bundle (T1550.002, T1003.001, T1070.001, T1070.006, T1547.001). Each hypothesis ends as `verified`, `quarantined`, or `ralph_wiggum` (drift). Pure-Python proposer — no LLM call. For LLM-driven triage, use `oath serve` and connect via Claude Code over MCP instead.

## 8. Cleanup

When you're done:

```bash
bash uninstall.sh
```

Interactive prompts before each step. Non-interactive form: `bash uninstall.sh --yes`. Removes:
- `.oath-tools/` and `.venv/`
- `logs/`, `keys/`, `.oath/` (per-run state)
- The plaso Docker image
- The colima VM
- All brew packages OATH installed (`dotnet`, `sleuthkit`, `powershell`, `colima`, `docker`, `docker-compose`, `lima`)

After the script runs, `rm -rf <oath-checkout>` is the final manual step.

## Troubleshooting

- **Hosted-model API disabled for the project** — enable the provider API for the authenticated project
- **`The credentials need to be configured`** — `gcloud auth application-default login`
- **`Cannot connect to the Docker daemon`** — `colima start --arch aarch64 --cpu 4 --memory 8 --disk 30`
- **EZ Tool says "You must install or update .NET"** — make sure you sourced `.oath-tools/env.sh`; it sets `DOTNET_ROLL_FORWARD=Major` so .NET 10 hosts the .NET 9 EZ Tools.
- **fls / icat segfault on .E01** — `brew reinstall libewf afflib` and re-check the version (must be brew's bottle, not source-built).
