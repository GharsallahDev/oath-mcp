# OATH

**Autonomous DFIR agent. Every forensic claim takes the oath: deterministic re-derivation from the original-image SHA-256, or it doesn't ship.**

Submission to the SANS *Find Evil!* hackathon (deadline 2026-06-16). Built on the SANS SIFT Workstation + Protocol SIFT.

---

## The pitch in 60 seconds

Protocol SIFT works. It also hallucinates more than its authors want — and in forensics, fabricated evidence is career-ending. Existing autonomous DFIR agents handle this with prompt-based guardrails ("be careful, cite sources"), which the agent can ignore at any time.

OATH handles it architecturally:

1. **The Witness Oath Verifier** — every LLM-emitted claim must pass a deterministic re-derivation gate (regex / YARA / struct-parse from the original-image SHA-256) before entering the evidence graph. Claims that fail re-derivation are **quarantined** — visible to the examiner as "the agent suspected this but couldn't prove it." Hallucinations are made visible, not hidden.

2. **The Ralph Wiggum Loop** — when the agent's first hypothesis fails the verifier, it visibly abandons the wrong hypothesis on screen and narrates revision. Self-correction is architecturally enforced, not aspirational. *(Term coined by Rob T. Lee for the [Protocol SIFT initiative](https://www.sans.org/blog/protocol-sift-experimental-research-initiative-ai-assisted-dfir).)*

3. **The Replay Receipt** — every finding the agent ships is a one-line replay command (`oath verify <finding-id>`) that re-extracts the supporting evidence from the original image on any analyst's laptop in seconds. What cannot replay does not exist.

4. **The DFIR-Metric Leaderboard** — published score on the public NIST CFTT Module III practical-analysis corpus (DFIR-Metric, [arXiv:2505.19973](https://arxiv.org/abs/2505.19973)). The current frontier LLM baseline is GPT-4.1 at 38.5% TUS@4. OATH targets >60%, with `verify.sh` ships in the repo so any judge can re-run a benchmark case on their laptop in under 60 seconds.

## What you can do in 60 seconds

```bash
# Mount any case image (SIFT loop-r enforced)
oath mount ./splunk-attack-range-pth.E01

# Run autonomous triage
oath triage

# Re-verify any finding on your own machine
oath verify <finding-id>

# Re-run one DFIR-Metric benchmark case
./verify.sh dfir-metric-case-42
```

See [`docs/TRY_IT_OUT.md`](docs/TRY_IT_OUT.md) for full install.

## Submission components (per Find Evil! rules)

| Required | Where |
|---|---|
| Code repository (MIT) | this repo |
| ≤5-min demo video (live terminal, ≥1 self-correction) | [`demo/`](demo/) |
| Architecture diagram | [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) |
| Written project description | [`docs/PROJECT.md`](docs/PROJECT.md) |
| Dataset documentation | [`docs/DATASET.md`](docs/DATASET.md) |
| Accuracy report | [`docs/ACCURACY.md`](docs/ACCURACY.md) |
| Try-it-out instructions | [`docs/TRY_IT_OUT.md`](docs/TRY_IT_OUT.md) |
| Agent execution logs | [`logs/`](logs/) (ed25519-signed JSONL) |

## License

MIT. See [`LICENSE`](LICENSE).
