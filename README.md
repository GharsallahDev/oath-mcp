# OATH

**Autonomous DFIR agent. Every forensic claim takes the oath: deterministic re-derivation from the original-image SHA-256, or it doesn't ship.**

OATH is an autonomous incident-response agent that wraps a hardened, cryptographically-anchored layer around the SIFT Workstation toolchain. Every finding the agent emits is required to pass a deterministic re-derivation gate; claims that cannot be re-derived are surfaced to the examiner as "the agent suspected this but couldn't prove it" — never as confirmed findings.

## Why it exists

Existing autonomous DFIR agents treat hallucination as a behavioral problem and patch it with prompt-engineering. Fabricated forensic evidence is a different class of failure: in court it's career-ending; in production it's the kind of mistake that hands the wrong person to legal. OATH treats hallucination as an architectural problem and solves it by construction:

1. **The Witness Oath Verifier** — every LLM-emitted claim must pass a deterministic re-derivation gate (regex / YARA / struct-parse from the original-image SHA-256) before entering the evidence graph. Claims that fail re-derivation are **quarantined** — visible to the examiner, but never promoted to findings.

2. **The Ralph Wiggum Loop** — when the agent's first hypothesis fails the verifier, it visibly abandons the wrong hypothesis on screen and narrates revision. Self-correction is architecturally enforced, not aspirational.

3. **The Replay Receipt** — every finding the agent ships is a one-line replay command (`oath verify <finding-id>`) that re-extracts the supporting evidence from the original image on any analyst's laptop in seconds. *What cannot replay does not exist.*

4. **A public reproducibility audit** — OATH is scored against the [DFIR-Metric](https://arxiv.org/abs/2505.19973) practical-analysis benchmark and ships `verify.sh` so anyone can independently re-run a benchmark case in under a minute.

## What you can do in 60 seconds

```bash
# Mount any case image read-only
oath mount ./case.E01

# Run autonomous triage
oath triage

# Re-verify any finding from the original image
oath verify <finding-id>

# Re-run one DFIR-Metric benchmark case
./verify.sh dfir-metric-case-42
```

See [`docs/TRY_IT_OUT.md`](docs/TRY_IT_OUT.md) for full install.

## What's inside

| Layer | Purpose |
|---|---|
| `src/oath/receipt/` | `Notarized[T]` cryptographic envelope (ed25519 + BLAKE3 + RFC 8785 JCS canonicalization + hash chain) |
| `src/oath/mcp/` | Custom MCP server exposing typed forensic functions to any MCP-compatible AI runtime; per-tool persistence and chain-of-custody |
| `src/oath/mcp/tools/` | Typed wrappers around the SIFT toolchain (EZ tools, Volatility 3, Hayabusa) — each mints a `Notarized` envelope |
| `src/oath/witness/` | The Witness Oath Verifier + the Ralph Wiggum self-correction loop |
| `src/oath/agent/` | Hypothesis-driven orchestration → structured TriageReport |
| `src/oath/benchmark/` | DFIR-Metric Module III scoring harness |

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the full diagram and the four load-bearing claims.

## License

MIT. See [`LICENSE`](LICENSE).
