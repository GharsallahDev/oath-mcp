# OATH — Architecture

> **Architectural pattern:** typed, schema-constrained forensic functions exposed through a custom MCP-style tool surface; no `execute_shell` surface; chain-of-custody enforced architecturally, not by prompt-engineering.

## How OATH extends Protocol SIFT

OATH builds on top of [Protocol SIFT](https://github.com/teamdfir/protocol-sift) — the open-source autonomous-DFIR baseline (Claude Code + five DFIR skill packs: `memory-analysis`, `plaso-timeline`, `sleuthkit`, `windows-artifacts`, `yara-hunting`, plus a PDF report generator, all installed under `~/.claude/`). Protocol SIFT lets a Claude Code agent run forensic tools on the SIFT Workstation against case data; OATH inherits that baseline and **replaces the prompt-only agent loop with three architectural primitives** Protocol SIFT does not ship:

1. **A typed MCP server surface** (16 typed tools: 11 forensic functions plus 5 control-plane and inspection tools, no `execute_shell`) so the agent physically cannot run destructive commands.
2. **A `Notarized<T>` envelope** signed under ed25519 + BLAKE3 + the LLM's `model_id` + `prompt_hash` so every tool output is a court-admissible receipt.
3. **A verifier-gated promotion path** (Witness Oath Verifier + `RALPH_WIGGUM` verdict loop) so an LLM claim becomes a finding only if a deterministic re-derivation of the cited evidence agrees.

Concretely, the canonical install registers OATH as a stdio MCP server on top of an existing Protocol SIFT baseline: `claude mcp add --transport stdio oath -- uvx oath-mcp` pulls the published `oath-mcp` package from PyPI and isolates it via `uv`. The long-form scripts (`scripts/install-on-sift.sh` for the SIFT Workstation, `scripts/install-tools.sh` for macOS) call Protocol SIFT's own installer (`curl -fsSL https://raw.githubusercontent.com/teamdfir/protocol-sift/main/install.sh | bash`) first and then layer OATH on top for benchmark reproduction or air-gapped deployment.

## One-paragraph summary

OATH is an autonomous DFIR agent built on the principle that every forensic claim must be re-derivable from the original-image SHA-256, or it does not ship. The LLM proposes; a deterministic verifier disposes. The agent's tool surface is **16 typed MCP tools** (11 forensic wrappers + 5 control-plane and inspection tools) — no shell, no `execute_command`, no arbitrary code paths. Every tool output is wrapped in a **`Notarized<T>` envelope** (RFC-8785 canonical args + ed25519 signature + BLAKE3 hash chain + prev-link). Every LLM-emitted claim passes the **Witness Oath Verifier** which re-runs the cited tool and confirms the BLAKE3 of stdout matches the receipt. Claims that fail verification are surfaced to the examiner as **QUARANTINED** — visible, but never promoted to findings. Drift triggers the **`RALPH_WIGGUM` verdict**: the agent visibly abandons the wrong hypothesis on-screen and narrates revision. Every shipped finding ships with a **Replay Receipt**: `oath verify <envelope-id>` re-derives the supporting evidence on an examiner's laptop in under a minute, without an LLM.

## Component diagram

```mermaid
flowchart TB
    subgraph EVIDENCE["📀 Evidence"]
        IMG[Forensic image .E01 / .dd / .raw]
        IMG -.read-only.-> MOUNT
    end

    subgraph HANDLE["🔒 EvidenceHandle"]
        MOUNT[oath mount<br/>SHA-256 streaming hash<br/>losetup -r / hdiutil / raw-file]
    end

    subgraph MCP["⚙️ Custom MCP Server — 11 typed forensic functions"]
        direction TB
        F1["enumerate_credential_artifacts<br/><i>FIRST call: filesystem inventory</i>"]
        F2["parse_evtx · parse_mft · parse_amcache<br/>parse_prefetch · parse_registry"]
        F3["parse_usnjrnl · plaso_supertimeline<br/>run_hayabusa · vol3_query"]
        F4["find_strings_on_image<br/><i>NSS evidence-operation surface</i>"]
    end

    subgraph ENV["📜 Notarized&lt;T&gt; envelope (every call)"]
        E1["• data · tool_name · tool_version (pinned)<br/>• args_canonical (RFC 8785 JCS)<br/>• image_sha256 · stdout_blake3<br/>• evidence_offsets · ed25519_sig · prev (hash chain link)"]
    end

    subgraph AGENT["🤖 LLM args-proposal layer"]
        PROPOSE[LLM emits JSON args spec<br/><i>NOT executable code</i>]
        EXEC[Deterministic executor runs typed call]
        PROPOSE --> EXEC
    end

    subgraph WITNESS["⚖️ Witness Oath Verifier"]
        VERIFIED{"VERIFIED<br/>all envelopes re-derive<br/>+ predicates match"}
        QUARANTINED["🟡 QUARANTINED<br/>(envelope ok, predicate miss)<br/><i>surfaced to examiner as<br/>'suspected but unproven'</i>"]
        RALPH["🔁 RALPH WIGGUM<br/>(envelope drift)<br/><i>visibly abandon → re-propose<br/>under derived constraint</i>"]
    end

    subgraph RECEIPT["🧾 Replay Receipt"]
        R1["oath verify &lt;envelope-id&gt;<br/>re-runs the bound tool<br/>compares BLAKE3<br/>&lt;60s, no LLM"]
    end

    MOUNT --> F1
    F1 --> ENV
    F2 --> ENV
    F3 --> ENV
    F4 --> ENV
    AGENT -->|cite envelope_id| WITNESS
    WITNESS --> VERIFIED
    WITNESS --> QUARANTINED
    WITNESS --> RALPH
    RALPH --> AGENT
    VERIFIED --> RECEIPT
```

## The four load-bearing claims

### 1. Witness Oath Verifier

Every `Notarized<T>` envelope binds:
- the source image SHA-256
- the tool name and version (pinned in the installer)
- the canonical argument vector (RFC 8785 JCS — sorted keys, no whitespace, UTF-8)
- the BLAKE3 hash of the tool's stdout (or the file contents for tools that write to disk)
- the byte offsets of supporting evidence in the original image
- the ed25519 signature over (image_sha256, tool, args, stdout_hash, offsets, ts, prev_hash)

When the LLM emits a natural-language claim ("Mr. Informant deleted his Outlook OST on 2015-03-25 at 14:22:08"), the verifier looks up every cited `Notarized<T>` entry, deterministically re-runs the bound tool via `reverify()`, and compares BLAKE3-of-stdout to the value in the receipt. Mismatches → the claim is **quarantined** and the agent enters the Ralph Wiggum Loop.

The verifier is the only thing that can promote a claim from DRAFT to CONFIRMED. The LLM has no path around it.

### 2. Ralph Wiggum Loop

When a claim fails the Witness Oath:

```
╭───── RALPH WIGGUM #1 ─────────────────────────────╮
│ abandoned:  PTH_CANDIDATE                          │
│ reason:     envelope hayabusa-001 failed           │
│             re-derivation: stdout BLAKE3 drift     │
│             (rule corpus changed since mint)       │
│ revision:   do not cite envelope hayabusa-001;     │
│             re-acquire EVTX surface via parse_evtx │
│             + run_hayabusa with current rule pack  │
│                                                    │
│ Rule corpus drifted between propose and verify.    │
│ The agent abandons this line and re-acquires       │
│ fresh evidence.                                    │
╰────────────────────────────────────────────────────╯
```

For a re-runnable, persisted artifact of this loop firing on real evidence-integrity rejection (data_blake3 mismatch on a tampered envelope, agent abandons + re-proposes citing a clean envelope, final VERIFIED), see [`logs/self-correction-demo/manifest.md`](../logs/self-correction-demo/manifest.md). Reproduce in two seconds with `python scripts/show_self_correction.py` — the verifier verdicts are byte-exact regardless of when you run it.

Hallucinations don't get suppressed — they get **made visible**. The examiner watches the abandonment in real time.

### 3. Replay Receipt

Every shipped finding includes a one-line `oath verify <envelope-id>` command. When run on the original image, the receipt:

1. Re-executes the exact tool invocation (pinned versions, canonical args, recorded byte offsets)
2. Recomputes the BLAKE3 of the output
3. Compares to the recorded value in the signed manifest
4. Renders PASS / FAIL with the bound image SHA-256 and stdout-BLAKE3 prefix

Total wall-clock: typically under 5 seconds per receipt on commodity hardware. Pure Python via `pip install oath`; no LLM, no API key, no MCP server boot.

### 4. Public, reproducible benchmark

OATH is scored on the [DFIR-Metric](https://arxiv.org/abs/2505.19973) Module III (NIST String Search) corpus — the same 510-question file the paper authors published. Frontier-LLM baseline (GPT-4.1) = **38.5% TUS@4**. OATH live agent + verifier = **92.75% TUS@4**. Same corpus, same image, same scoring rule, same K=4 candidate budget. Methodology + per-question audit + reproduction one-liner: [`docs/ACCURACY.md`](ACCURACY.md).

## Security boundaries — where they're enforced

This table makes explicit which guardrails are **architectural** (enforced by the type system / no-tool-available) vs **prompt-based** (enforced by asking the LLM nicely).

| Guardrail | Enforcement | What stops a malicious / hallucinating LLM |
|---|---|---|
| Image bytes are read-only | **Architectural** | `EvidenceHandle.mount_tech` only accepts `losetup -r` / `hdiutil` read-only / `raw-file` (no mount). The constructor literally has no write-mount option. |
| LLM cannot run shell commands | **Architectural** | The MCP server (`src/oath/mcp/server.py`) exposes only typed functions. There is no `execute_shell` / `bash` / `python_eval` tool. The LLM physically cannot run `dd`, `wipefs`, `mkfs`, `rm -rf`. |
| LLM cannot fabricate evidence | **Architectural** | Every record claimed by the LLM must point to a `Notarized<T>` envelope by `envelope_id`. The verifier re-runs the tool and confirms BLAKE3-of-stdout matches. Records the LLM invented have no corresponding envelope; they fail at lookup. |
| LLM cannot lie about *which* record an envelope shows | **Architectural** | `ClaimEvidence.record_predicate` is a typed subset-match. The verifier scans `envelope.data` for any record satisfying the predicate; if none does, the claim is QUARANTINED. The LLM can't satisfy this without naming real field values from the actual tool output. |
| Tool outputs are deterministic | **Architectural** | `args_canonical` is RFC 8785 JCS over `model_dump()`; `stdout_blake3` is BLAKE3 over the literal bytes. Re-running with identical args produces identical bytes produces identical hash. Drift between mint-time and verify-time is caught. |
| Chain of custody is tamper-evident | **Architectural** | Every envelope's `prev` field is the BLAKE3 of the previous envelope's header. Mutating any envelope breaks the chain at the next link. The chain is verifiable from the JSONL store with no LLM in the loop. |
| Tool versions are pinned | **Architectural** | Each typed function module hardcodes the expected version (`EVTXECMD_VERSION = "2026.5.0"`, etc.). Envelopes mint with the actual version reported by the tool; reverify across a version bump is a recognizable failure mode (the verifier surfaces "version drift" as the reason). |
| Plugin / rule corpus is pinned | **Architectural** | `parse_registry` records the SHA-256 of the RECmd plugin pack at mint time. `run_hayabusa` records the SHA-256 of the Sigma rule corpus. Updates to either are caught by `reverify` and surfaced as "rule corpus drift". |
| LLM stays inside the typed-args schema | **Prompt-based** ⚠️ | The model-facing prompt instructs the LLM to emit a JSON object matching the schema. If the LLM ignores this, the parser returns `None` and no untrusted free-form command reaches the forensic tools. This is the prompt-based layer in the system, and it fails *closed* (skipped, not bypassed). |
| Spoliation (image-byte mutation between mint and reverify) | **Architectural** | Mutating the image bytes after envelope mint causes the underlying tool to produce different output bytes, which fails the BLAKE3 chain. Covered by `tests/integration/test_spoliation.py`. |
| Persisted `envelope.data` tampering (fabricated record planted in the JSONL store) | **Architectural** | `NotarizedHeader` carries `data_blake3 = BLAKE3(canonicalize(data))`; because the header is signed, the data field is transitively cryptographically committed. The verifier recomputes `data_blake3` from the current persisted data and rejects on mismatch (RALPH_WIGGUM, drift detected). Without this, an attacker who can write the JSONL store could mutate `envelope.data` while leaving raw stdout untouched, surviving the BLAKE3-of-stdout reverify. |
| Daubert binding — "which model produced this finding, from what prompt?" | **Architectural** | `NotarizedHeader` carries `model_id` (e.g. `gemini-3.1-pro-preview`) and `prompt_hash = BLAKE3(len-prefixed(system_prompt \|\| user_message))`. Both are signed by the header signature. The receipt itself answers the Daubert question without trusting the agent's logs. Tampering with either field invalidates the signature. None-valued for deterministic envelopes (no LLM in the loop), and the null is itself signed — preventing post-hoc field-stripping attacks. |

**Net:** The single prompt-based guardrail (LLM-stays-in-schema) fails *closed* — when the LLM disobeys, the path is broken, not bypassed. The forensic-tool surface itself has no prompt-controlled bypass.

## Spoliation contract — what we tested

`tests/integration/test_spoliation.py` (14 tests, all passing) covers:

1. **Single-byte image mutation breaks the SHA-256 rehash** — proves the front-line spoliation check works.
2. **Tool-output drift fails reverify** — if the bytes the tool produces change between mint and verify, BLAKE3 catches it.
3. **Pristine evidence verifies cleanly** — the inverse control; no false-positive spoliation alarms.
4. **Envelope-header tampering fails signature** — mutating `image_sha256`, `stdout_blake3`, or any other header field invalidates the ed25519 signature.
5. **`args_canonical` tampering fails signature** — swapping a filter argument to hide an event is caught.
6. **Chain-of-custody break detection** — modifying a middle envelope breaks the `prev`-hash chain link to the next envelope.
7. **End-to-end via verifier registry** — the production-path entry the agent actually uses surfaces spoliation correctly.
8. **`data_blake3` is in the signed header** — bare contract that the field exists, is hex-encoded BLAKE3, and is non-zero for non-empty data.
9. **Pristine data passes the integrity check** — including after a JSON round-trip through the persistence store, so legitimate envelopes don't false-positive.
10. **Persisted-data mutation fails integrity check** — fabricating a record in `envelope.data` is caught even though the signature on the (untouched) header still verifies. Without `data_blake3` this attack would survive.
11. **Verifier end-to-end rejects tampered data** — with a forgiving registry that mimics "raw stdout untouched on disk," the full `WitnessOathVerifier.verify()` still returns RALPH_WIGGUM with `data_blake3` in the reason, never VERIFIED.
12. **Daubert: `model_id` and `prompt_hash` are signed into the header** — tampering with either invalidates the ed25519 signature. The receipt itself proves which model + which prompt produced this finding.
13. **Deterministic envelopes carry null binding** — `model_id=None` and `prompt_hash=None` are signed defaults; post-hoc stripping is detectable because the signature was computed over the null values.
14. **`hash_prompt` is collision-resistant against delimiter-mimic attacks** — length-prefixed concatenation so `hash_prompt("ABC","DEF") != hash_prompt("ABCD","EF")`.

## What OATH explicitly does NOT claim

- **Not Daubert-certified.** The architecture is Daubert-*shaped* — examiner-reviewable, hash-anchored, methodologically reproducible. Admissibility is a judicial finding, not a property of code.
- **Not a replacement for forensic tools.** OATH wraps EZ Tools, Sleuthkit, Volatility 3, Hayabusa, and plaso. The contribution is the verifier-gated orchestration layer + chain-of-custody envelope.
- **Not a "smarter LLM."** OATH's lift over GPT-4.1's published 38.5% comes from removing the script-generation failure class via typed-args proposal, not from being a more capable model. See [`docs/ACCURACY.md`](ACCURACY.md) §5.
- **Not a substitute for human review.** Every quarantined claim is presented to the examiner. The system is a force multiplier for analysts, not their replacement.
