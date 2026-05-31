# OATH — Architecture

## One-paragraph summary

OATH is an autonomous DFIR agent built on the SIFT Workstation. Its architecture is organized around a single invariant: **no claim leaves the agent unless it can be re-derived from the original-image SHA-256 by a deterministic, non-LLM verifier.** The LLM proposes; the verifier disposes. When the verifier fails, the agent visibly self-corrects (the Ralph Wiggum Loop) and re-attempts. Every shipped finding carries a Replay Receipt — a one-line command that re-runs the supporting tool invocation on the original image and produces matching output. Hallucinations are not suppressed but quarantined and shown to the examiner as "the agent suspected this but could not prove it." OATH ships with a public score on the NIST CFTT Module III practical-analysis corpus (DFIR-Metric) and a `verify.sh` one-liner so any examiner can re-run a benchmark case on their laptop in under sixty seconds.

## Component diagram

```
                            ┌──────────────────────────────────┐
                            │     Public Corpora & SIFT VM     │
                            │  CFReDS · Attack Range · Mordor  │
                            └─────────────────┬────────────────┘
                                              │ read-only mount (losetup -r + FUSE)
                                              ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│                              EvidenceHandle                                  │
│    sha256(image) → handle                                                    │
└──────────────────────────────────────────────────────────────────────────────┘
                                              │
                                              ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│                       Custom MCP Server (10 typed functions)                 │
│                                                                              │
│  enumerate_credential_artifacts  ← FIRST CALL: filesystem inventory          │
│  parse_evtx     parse_mft        parse_amcache    parse_prefetch             │
│  parse_registry parse_usnjrnl    plaso_supertimeline                         │
│  run_hayabusa   vol3_query                                                   │
│                                                                              │
│  Each returns Notarized<T>:                                                  │
│     { data, tool_version, args_canonical, stdout_blake3,                     │
│       evidence_offsets, ed25519_sig }                                        │
└─────────────────────────────────────┬────────────────────────────────────────┘
                                      │
                                      ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│                       Autonomous Agent Loop  (claude --print)                │
│                                                                              │
│  for hypothesis in hypotheses:                                               │
│      claims = propose(hypothesis, evidence)                                  │
│      for claim in claims:                                                    │
│          verdict = WitnessOath.verify(claim, evidence)                       │
│          if verdict.ok:                                                      │
│              receipt = ReplayReceipt.mint(claim, evidence)                   │
│              ship(claim, receipt)                                            │
│          else:                                                               │
│              ralph_wiggum_log(claim, verdict.reason)  # visible self-correct │
│              quarantine(claim, verdict)               # surface to examiner  │
│              re_propose_with_constraint(verdict.reason)                      │
└─────────────────────────────────────┬────────────────────────────────────────┘
                                      │
        ┌─────────────────────────────┼─────────────────────────────┐
        ▼                             ▼                             ▼
┌────────────────────┐  ┌────────────────────────┐  ┌──────────────────────────┐
│  Witness Oath      │  │   Ralph Wiggum Loop    │  │   Replay Receipt         │
│  Verifier          │  │   (visible revision)   │  │   (portable verifier)    │
│                    │  │                        │  │                          │
│  Deterministic     │  │  Wrong hypothesis →    │  │  oath verify <id>        │
│  re-derivation     │  │  narrated abandonment  │  │  → reproduces evidence   │
│  via regex /       │  │  → constrained re-     │  │  from original SHA-256   │
│  YARA / struct-    │  │  proposal              │  │  in seconds, on examiner's  │
│  parse from        │  │                        │  │  laptop                  │
│  original SHA-256  │  │                        │  │                          │
└────────────────────┘  └────────────────────────┘  └──────────────────────────┘
```

## The four load-bearing claims

### 1. Witness Oath Verifier

Each typed MCP function returns a `Notarized<T>` envelope binding the result to:
- the source image SHA-256
- the tool name and version (pinned in `dotnet-tools.json` and `requirements.txt`)
- the canonical argument vector (JSON-canonicalized per RFC 8785)
- the BLAKE3 hash of the tool's stdout
- the byte offsets of the supporting evidence in the original image
- the ed25519 signature over (image_sha256, tool, args, stdout_hash, offsets, ts)

When the LLM emits a natural-language claim ("the attacker authenticated as Administrator at 14:32:01 via NTLM"), the Witness Oath Verifier looks up the supporting `Notarized<T>` entries, deterministically re-derives the relevant fact via a non-LLM verifier (regex over EVTX records, YARA over file blobs, struct-parse over registry hives), and compares against the claim. Mismatches → the claim is quarantined and the agent enters the Ralph Wiggum Loop.

The verifier is the only thing that can promote a claim from DRAFT to CONFIRMED. The LLM has no path around it.

### 2. Ralph Wiggum Loop

When a claim fails the Witness Oath:

```
[2026-05-31T18:42:01Z] CLAIM REJECTED:
  hypothesis: "T1078 Valid Accounts"
  expected: EVTX 4624 LogonType=2 from source IP 10.0.0.42
  found:    EVTX 4624 LogonType=3, AuthenticationPackage=NTLM
  reason:   Type-3 NTLM logon does not match interactive-credential-use pattern;
            consistent with T1550.002 Pass-the-Hash, not T1078.
  revision: re-proposing with hypothesis=T1550.002, constraint=hash-based-auth-only.
```

This is the term Rob T. Lee [coined in his Substack](https://robtlee73.substack.com/p/introducing-protocol-sift-meeting) for the self-correction loop he wanted in Protocol SIFT but hadn't shipped. OATH ships it. (Single attribution; no repeated name-drops.)

### 3. Replay Receipt

Every shipped finding includes a one-line `oath verify <finding-id>` command. When run on the original image, the receipt:

1. Re-executes the exact tool invocation (pinned versions, canonical args, recorded byte offsets)
2. Recomputes the BLAKE3 of the output
3. Compares to the recorded value in the signed manifest
4. Renders the supporting evidence span

Total wall-clock: 5-30 seconds per receipt on commodity hardware. Ships as `verify.sh` in the repo + a Go static binary for cross-platform replay.

### 4. DFIR-Metric Public Leaderboard

OATH is scored on the NIST CFTT Module III practical-analysis subset (the [DFIR-Metric](https://arxiv.org/abs/2505.19973) benchmark). Frontier-LLM baseline (GPT-4.1) = **38.5% TUS@4**. OATH target: **>60% with verifier-gated retries**. Leaderboard URL ships with submission; verify.sh ships with submission; methodology fully reproducible.

## What OATH explicitly does NOT claim

- **No bare "first to X" claims.** Cryptographic evidence sealing, typed evidence graphs, and bidirectional reasoning all exist in the open-source DFIR-AI landscape. OATH's contribution is the *integration*: deterministic verifier + visible self-correction + portable replay + public benchmark dominance, end-to-end.
- **Not Daubert-certified.** The architecture is Daubert-shaped (examiner-reviewable, hash-anchored, methodologically reproducible) but admissibility is a judicial finding, not a property of code. See [`docs/ACCURACY.md`](ACCURACY.md) §6.
- **No synthetic-examiner-avatar video.** The demo is live terminal screencast; no AI-generated faces speaking forensic conclusions.
