# OATH demo recording playbook

This is the explicit, top-to-bottom playbook for recording the submission
video on the SANS SIFT Workstation. Follow it in order. Every command is
verbatim. Every prompt is verbatim. Total recording time: ~4–5 minutes
end-to-end (with one or two retakes budget for ~30 minutes total).

The video records a real Claude Code session driving OATH's typed MCP tools
against the real NIST CFReDS Data Leakage Case. One of the signed envelopes
is pre-tampered, so the Witness Oath Verifier reliably rejects it,
triggering a real Ralph Wiggum self-correction event — exactly the
spoliation-test attack documented in `tests/integration/test_spoliation.py
::TestPersistedDataTampering`.

---

## Phase 0 — VM setup (one-time, ~45 minutes, no recording yet)

### 0.1 Import the SIFT OVA

UTM (Apple Silicon) or VirtualBox/VMware (Intel). For UTM the path is
documented in [`docs/DEVPOST.md` "Challenges we ran into" §4](DEVPOST.md).
Allocate:

- **8 GB RAM minimum** (16 GB if you have it; helps Plaso cache)
- **4 CPU cores minimum** (8 with "Force Multicore" on UTM)
- **Bridged or NAT networking** (the VM must reach github + Anthropic API)
- **Shared clipboard enabled host↔guest** (you'll paste a long prompt)

Boot. Login (default SIFT credentials: `sansforensics` / `forensics`).

### 0.2 Protocol SIFT baseline

This installs Claude Code itself plus the five DFIR skill packs and
PDF reporter into `~/.claude/`. OATH extends Protocol SIFT.

```bash
curl -fsSL https://raw.githubusercontent.com/teamdfir/protocol-sift/main/install.sh | bash
```

When it finishes, add Claude Code to PATH if the installer didn't:

```bash
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc && source ~/.bashrc
claude --version    # confirm
```

### 0.3 Authenticate Claude Code

```bash
claude
```

Complete the OAuth flow in the browser when prompted. Exit (`Ctrl+D` or
type `/exit`) once you see the welcome screen.

### 0.4 Install `uv`

`uvx oath-mcp` (the on-camera install line) needs the `uv` package
manager:

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
exec bash       # pick up the new PATH
which uvx       # should print: ~/.local/bin/uvx
```

### 0.5 Bootstrap the forensic binaries

`uvx oath-mcp` pulls only the Python wheel. The MCP server shells out to
native binaries that SIFT doesn't ship by default (EZ Tools, Hayabusa,
.NET 9). One curl-pipe-bash installs all of them:

```bash
curl -fsSL https://raw.githubusercontent.com/GharsallahDev/oath-mcp/main/scripts/bootstrap-forensic-tools.sh | bash
exec bash       # pick up DOTNET_ROOT + the new PATH
```

Time: ~10 minutes on a fresh SIFT VM (emulation on Apple Silicon is ~5×
slower than native; budget closer to 25 min there).

Verify:

```bash
which EvtxECmd hayabusa vol psort.py uvx
```

All five should print absolute paths.

### 0.6 Install the OATH operator CLI

You'll need `oath mount` and the `scripts/` helpers for evidence staging.
Install the published wheel as a user tool (separate from the MCP
spawn — they share the same package but live in different uv envs):

```bash
uv tool install oath-mcp
oath --version   # confirm
```

Also grab the demo helpers from the repo (they're not in the wheel):

```bash
cd ~
git clone https://github.com/GharsallahDev/oath-mcp.git
cd oath-mcp
```

### 0.7 Stage the CFReDS Data Leakage Case evidence

Either copy `cfreds_2015_data_leakage_pc.E01..E04` from your host into
`~/oath-mcp/corpus/data-leakage-case/` (via shared folder or scp), OR run
the extraction sequence from `docs/DATASETS.md` §3 to pull from NIST.

Mount it (computes SHA-256, ~30s):

```bash
oath mount corpus/data-leakage-case/cfreds_2015_data_leakage_pc.E01
```

You should see `handle_id: 15e9489f6ae6766e` (or a fresh one — note it down).

### 0.8 Generate the sample-run envelopes

```bash
python scripts/export_sample_run.py --handle-id 15e9489f6ae6766e
```

Takes ~25 min because of plaso. Result lands at
`logs/sample-run/dlc-sample-run.jsonl` (6 envelopes).

### 0.9 Pre-tamper one envelope for the demo

```bash
bash scripts/prepare-demo.sh
```

This copies the sample run into `logs/demo-run/` and tampers the
`run_hayabusa` envelope's persisted `data` field. Note the printed
envelope ID — that's the one the verifier will reject when Claude cites it.

### 0.10 Smoke-test the on-camera command sequence (CRITICAL)

Run the exact lines you're about to record, cold:

```bash
claude mcp add --transport stdio oath -- uvx oath-mcp
claude mcp list                # should show: oath  stdio   ✓ connected
claude                          # then: /mcp → 'oath: connected · 16 tools' → Ctrl+D
```

If anything fails, **fix it now**, don't record. Then remove the
registration so you can do it fresh on tape:

```bash
claude mcp remove oath
```

### 0.11 Install a screen recorder

SIFT comes with `simplescreenrecorder` or `kazam` available via apt. OBS
Studio also works. Configure:

- **Output**: 1920×1080, MP4, 30 fps, H.264
- **Audio**: USB microphone or your laptop mic (test it!)
- **Region**: full desktop OR a single monitor

Test-record 10 seconds and play it back. Confirm audio works.

---

## Phase 1 — The recording (~4–5 min, hit record)

### Pre-flight check (do not skip)

1. ✅ All terminal windows closed except the one you'll use
2. ✅ Browser tabs closed (judges don't need to see them)
3. ✅ `~/oath-mcp` is your cwd
4. ✅ `which EvtxECmd hayabusa vol psort.py uvx` all return paths
5. ✅ `claude mcp list` shows NO `oath` entry (you removed it after smoke test)
6. ✅ Phone on silent
7. ✅ Start screen recorder + voice recording. Wait 2 seconds for both to settle.

### Scene 1 — The marquee MCP install (0:00 → 0:40)

Type, deliberately:

```bash
cat /etc/os-release | grep PRETTY
```

**Voiceover:** *"This is the SANS SIFT Workstation. Ubuntu 24 dot 04."*

Pause 1s, then type:

```bash
ls ~/.claude/skills/
```

**Voiceover:** *"Protocol SIFT is installed — five DFIR skill packs in
the standard Claude home directory."*

Pause 1s. Now the marquee line — type it slowly so the viewer sees every
flag land:

```bash
claude mcp add --transport stdio oath -- uvx oath-mcp
```

**Voiceover (as you type):** *"One line wires OATH into Claude Code.
This is the standard MCP install path — same shape as Airtable, same shape
as Sentry in the Claude Code docs. uv pulls the wheel from PyPI, isolates
it in its own environment, and Claude Code talks to it over stdio."*

Hit Enter. When it returns, type:

```bash
claude mcp list
```

**Voiceover:** *"Registered. Stdio transport. Ready."*

### Scene 2 — Mount real evidence (0:40 → 1:10)

```bash
oath mount corpus/data-leakage-case/cfreds_2015_data_leakage_pc.E01
```

While the SHA-256 streams:

**Voiceover:** *"OATH mounts the NIST CFReDS Data Leakage Case — two point
one gigabytes, Windows 7 NTFS. Read-only. The SHA-256 anchors every
downstream signed claim."*

When the handle appears, leave it on screen for 2s.

### Scene 3 — Boot Claude, confirm tools (1:10 → 1:30)

```bash
claude
```

When Claude's prompt appears, type:

```
/mcp
```

The output shows `oath: connected · 16 tools`.

**Voiceover:** *"Thirteen typed forensic functions. No execute shell.
The model can only call signed, schema-validated tools."*

### Scene 4 — The one prompt (1:30 → 1:45)

Paste this verbatim into Claude (use SIFT's shared-clipboard paste):

```
You are a senior DFIR analyst investigating the NIST CFReDS Data Leakage
Case. The mount is already established at handle id 15e9489f6ae6766e.

Your task: investigate the disk for evidence of suspected data
exfiltration by an insider. Use ONLY the OATH MCP tools available to you.
Cite signed envelopes by ID for every claim. Stop when you have a
court-admissible finding.

Pre-existing signed envelopes are available in logs/demo-run/. Before
running fresh tools, INSPECT what is already there. Build your first
claim citing one of those existing envelopes. If the Witness Oath
Verifier rejects an envelope, do NOT cite it again — instead re-run
the appropriate typed function fresh and cite the new envelope.

Be terse. One sentence per reasoning step.
```

**Voiceover (over the typing):** *"One prompt. One task. Watch the agent
sequence the tools, catch its own mistake, and self-correct."*

Hit Enter. **DO NOT TOUCH THE KEYBOARD AGAIN.**

### Scene 5 — Autonomous execution (1:45 → 3:45)

Claude will now autonomously:

1. **List existing envelopes** by reading `logs/demo-run/demo-run.jsonl`
2. **Inspect the parse_evtx envelope** — sees 4624 auth events
3. **Inspect the parse_registry envelope** — sees suspect "informant" RID 1000
4. **Inspect the parse_usnjrnl envelope** — sees Outlook OST deletions
5. **Build a first claim** citing the `run_hayabusa` envelope (the one we
   tampered) about T1098 admin-group additions
6. **Call `oath_verify_claim`** → returns `RALPH_WIGGUM` with reason
   `envelope.data does not match signed data_blake3 — persisted data has
   been tampered after minting`
7. **Read the constraint** — abandon the tampered envelope
8. **Re-run `run_hayabusa` fresh** to mint a clean envelope
9. **Build a second claim** citing the fresh envelope
10. **Call `oath_verify_claim`** → returns `VERIFIED`
11. **Ship the finding** as the answer

**Voiceover beats** (don't read these word-for-word; ad-lib over what's on
screen, but hit these moments):

- When Claude first lists envelopes: *"It reads the existing signed
  evidence — no shell, no `ls`. Typed tool only."*

- When the first claim is built: *"It drafts a finding about T1098 admin-
  group additions and cites the Hayabusa envelope."*

- When `RALPH_WIGGUM` panel appears: ***"And there's the self-correction
  beat. The Witness Oath Verifier rejected the cited envelope —
  `data_blake3` mismatch. Persisted data was tampered after minting. The
  agent must abandon this hypothesis and re-propose under the verifier's
  derived constraint."*** (← This is the load-bearing moment. Slow down.)

- When Claude re-runs hayabusa: *"It re-runs the tool fresh. New signed
  envelope. New claim."*

- When the second `VERIFIED` lands: *"Verified. The finding ships."*

### Scene 6 — Replay receipt from a fresh shell (3:45 → 4:10)

Open a **second terminal** (Ctrl+Alt+T or new tab). Type:

```bash
oath verify <envelope-id-from-the-verified-claim>
```

(Read the envelope ID off Claude's output above.)

You should see `PASS` in under 3 seconds.

**Voiceover:** *"A fresh shell. No agent. No LLM. The replay receipt
re-derives the finding from the original image SHA-256 in three seconds.
What cannot replay does not exist."*

### Scene 7 — Receipt Explorer click-through (4:10 → 4:35)

Open the browser. Navigate to either:

- The local instance: `firefox http://localhost:8765` (if you ran
  `python3 -m http.server 8765` in `~/oath-mcp/web/` ahead of time)
- The deployed: `https://oath-receipts.pages.dev/` (if deployed)

Click the same envelope from Scene 6.

**Voiceover:** *"The receipt itself answers the Daubert question — which
model produced this finding, from what prompt. Model id. Prompt hash.
Ed25519 signature. BLAKE3 chain. No trust in the agent's logs required.
Trust the math."*

Linger on the modal for 3s.

### Scene 8 — Close (4:35 → 4:50)

Close the browser. Voice only:

*"OATH MCP. Autonomous DFIR with a court-admissible chain of custody.
One line installs it. github dot com slash GharsallahDev slash oath dash
mcp. preprint in the description."*

Stop recording.

---

## Phase 2 — Post-production (~10 min)

### 2.1 Quick check before editing

Watch your recording end-to-end ONCE. Confirm:

- [ ] Audio is audible throughout
- [ ] The `RALPH_WIGGUM` panel is clearly visible
- [ ] Self-correction phrase ("self-correction", "data_blake3", "Ralph Wiggum")
      is spoken at least once
- [ ] No personal info / tokens visible
- [ ] Length < 5:00

If any of those fail, retake from the failing scene.

### 2.2 Trim + minor edits

Use OpenShot, Kdenlive, or any video editor available on SIFT. Trim
dead air at the start and end. **Do not speed up the playback** — judges
will notice and it looks unprofessional. If a scene ran long, cut a few
seconds of static screen between scenes, not from the autonomous-execution
section.

### 2.3 Export

- Container: MP4
- Codec: H.264 + AAC
- Resolution: 1920×1080
- Bitrate: 5–8 Mbps (file ends up ~30–50 MB)
- Audio: 192 kbps AAC

Name: `oath-demo.mp4`

### 2.4 Upload

YouTube unlisted is the standard choice:

1. Upload at studio.youtube.com
2. Visibility: **Unlisted** (only people with the link can find it)
3. Title: `OATH — Autonomous DFIR with verifier-gated claims`
4. Description: paste this verbatim:

```
OATH is an autonomous DFIR agent with cryptographic chain of custody for
LLM-produced forensic findings. Built on the SANS SIFT Workstation,
extending Protocol SIFT. Wired into Claude Code via one line:

    claude mcp add --transport stdio oath -- uvx oath-mcp

Architecture: Custom MCP Server (approach #2 in the Find Evil! taxonomy)
+ Direct Agent Extension features (Ralph Wiggum self-correction loop +
Witness Oath Verifier) layered on top.

Repository: https://github.com/GharsallahDev/oath-mcp
Preprint:   https://osf.io/rk73m/
Artifact:   https://pypi.org/project/oath-mcp/
```

5. Copy the unlisted URL.

### 2.5 Paste into the Devpost submission form

The video URL goes in the **Demo Video URL** field of the Devpost form.
The rest of `docs/DEVPOST.md` content goes into the matching Devpost
sections.

---

## Troubleshooting

### "Claude doesn't see the OATH MCP server"

```bash
claude mcp list
# If oath isn't listed or shows as ✗ failed:
claude mcp remove oath
claude mcp add --transport stdio oath -- uvx oath-mcp
claude mcp list
```

If `uvx` itself can't resolve `oath-mcp`, you're not on the published
version yet — use the git+ fallback:

```bash
claude mcp add --transport stdio oath -- \
    uvx --from git+https://github.com/GharsallahDev/oath-mcp.git oath-mcp
```

### "Claude calls a tool and it errors with 'EvtxECmd: command not found'"

The MCP subprocess Claude Code spawns doesn't see `EvtxECmd` on PATH. This
means `bootstrap-forensic-tools.sh` either wasn't run or didn't take
effect. Verify the PATH entry from your interactive shell:

```bash
which EvtxECmd     # should point under ~/.local/share/oath-tools/bin/
```

If empty, re-run:

```bash
curl -fsSL https://raw.githubusercontent.com/GharsallahDev/oath-mcp/main/scripts/bootstrap-forensic-tools.sh | bash
exec bash
```

The bootstrap writes PATH + `DOTNET_ROOT` exports into `~/.bashrc`. The
MCP subprocess inherits `~/.bashrc` because Claude Code spawns it with the
user's login shell.

### "RALPH_WIGGUM doesn't fire"

Confirm the demo prep ran:

```bash
ls logs/demo-run/
# Should show demo-run.jsonl + demo-run.index
```

If empty, re-run:

```bash
bash scripts/prepare-demo.sh
```

### "Recording is over 5 minutes"

The autonomous-execution scene (Scene 5) is the most variable — Claude
can run for anywhere from 60 seconds to 3 minutes depending on how much
context it loads. If you're consistently over:

- Tighten the prompt: add "Use at most 5 tool calls."
- Edit out dead time in Scene 5 between tool calls (NOT during the
  RALPH_WIGGUM beat).

### "Claude refuses to cite the existing envelopes"

The prompt explicitly directs Claude to inspect `logs/demo-run/` first.
If it doesn't, append to your prompt:

> "Start by reading `logs/demo-run/demo-run.index` to enumerate the
> envelope IDs you'll cite."

---

## Why this video wins

1. **Custom MCP Server (Approach #2)** is visibly the running architecture
   — judges see the canonical `claude mcp add ... -- uvx oath-mcp` install
   line, then 16 typed tools in Claude's palette, and no shell.
2. **Direct Agent Extension (Approach #1)** features layer on top — Ralph
   Wiggum loop + verifier validation.
3. **Real self-correction** — the `data_blake3` rejection is the real
   production verifier path, not a hand-built panel. The spoliation test
   suite covers the exact same trigger.
4. **Real autonomous execution** — Claude sequences tools, no human
   keystrokes during the work.
5. **Replay receipt + Receipt Explorer** — the audit trail is visible,
   re-derivable, and click-throughable.
6. **Daubert binding visible to a non-technical viewer** — model_id +
   prompt_hash + ed25519 sig in the modal.

That hits all six judging criteria, including the **Autonomous Execution
Quality** tiebreaker.
