# OATH

**Autonomous DFIR agent. Every forensic claim takes the oath: deterministic re-derivation from the original-image SHA-256, or it doesn't ship.**

OATH is an autonomous incident-response agent that wraps a hardened, cryptographically-anchored layer around mainstream forensic tools (Eric Zimmerman's EZ Tools, Sleuthkit, Volatility 3, Hayabusa, plaso). Every finding the agent emits is required to pass a deterministic re-derivation gate; claims that cannot be re-derived are surfaced to the examiner as "the agent suspected this but couldn't prove it" — never as confirmed findings.

## The number

| System | DFIR-Metric Module III | TUS@4 |
|---|---|---|
| GPT-4.1 (paper baseline, arXiv:2505.19973) | NIST String Search corpus, 510 questions | **38.5%** |
| OATH deterministic baseline (no LLM) | same corpus, same scoring rule | **78.43%** (+40 pts) |
| OATH live agent (Vertex Gemini 2.5 + verifier) | same corpus, same scoring rule | **89.22%** (+51 pts) |

See [`docs/ACCURACY.md`](docs/ACCURACY.md) for full methodology, per-question audit, and reproducibility.

## Why it exists

Existing autonomous-DFIR agents treat hallucination as a behavioral problem and patch it with prompt-engineering. Fabricated forensic evidence is a different class of failure: in court it's career-ending; in production it's the kind of mistake that hands the wrong person to legal. OATH treats hallucination as an architectural problem and solves it by construction:

1. **The Witness Oath Verifier** — every LLM-emitted claim must pass a deterministic re-derivation gate (regex / struct-parse / multi-encoding byte search from the original-image SHA-256) before entering the evidence graph. Claims that fail re-derivation are **quarantined** — visible to the examiner, but never promoted to findings.

2. **The Ralph Wiggum Loop** — when the agent's first hypothesis fails the verifier, it visibly abandons the wrong hypothesis on screen and narrates revision. Self-correction is architecturally enforced, not aspirational.

3. **The Replay Receipt** — every finding the agent ships is a one-line replay command (`oath verify <envelope-id>`) that re-extracts the supporting evidence from the original image on any analyst's laptop in seconds. *What cannot replay does not exist.*

4. **A public reproducibility audit** — OATH is scored against the [DFIR-Metric](https://arxiv.org/abs/2505.19973) Module III (NIST String Search) benchmark. `oath verify` lets anyone independently re-run any envelope in under a minute.

## Install and run on macOS (Apple Silicon)

```bash
git clone https://github.com/GharsallahDev/oath && cd oath
bash scripts/install-tools.sh                  # idempotent; runs once per machine

# Activate the sandboxed environment (puts EZ Tools / Hayabusa / plaso shims on PATH)
source .oath-tools/env.sh

# Mount a forensic image read-only — computes SHA-256, persists EvidenceHandle
oath mount path/to/Hacking_Case.E01

# Run a DFIR-Metric benchmark; --dry-run for plumbing test, --live-vertex for the real LLM
oath benchmark III --corpus corpus/DFIR-Metric-NSS.json --live-vertex

# Re-derive any envelope from the original image
oath verify <envelope-id>
```

See [`docs/TRY_IT_OUT.md`](docs/TRY_IT_OUT.md) for the unabridged walkthrough including macOS Apple-Silicon specifics, the colima/Docker plumbing for plaso, and the cleanup path (`uninstall.sh`).

## What's inside

| Layer | Purpose |
|---|---|
| `src/oath/receipt/` | `Notarized[T]` cryptographic envelope (ed25519 + BLAKE3 + RFC 8785 JCS canonicalization + hash chain) |
| `src/oath/mcp/` | Custom MCP server exposing 11 typed forensic functions; per-tool persistence and chain-of-custody |
| `src/oath/mcp/tools/` | Typed wrappers around the forensic toolchain (EZ Tools, Volatility 3, Hayabusa, plaso, Sleuthkit) — each mints a `Notarized` envelope |
| `src/oath/witness/` | The Witness Oath Verifier + the Ralph Wiggum self-correction loop |
| `src/oath/agent/` | Hypothesis-driven orchestration → structured TriageReport |
| `src/oath/benchmark/` | DFIR-Metric harness + Claude/Gemini live-agent bridges + scorer |
| `src/oath/narrator/` | Rich-based terminal narration of verifier + Ralph Wiggum events |

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the full diagram and the four load-bearing claims.

## License

MIT. See [`LICENSE`](LICENSE).
