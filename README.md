# OATH

Verifier-gated evidence receipts for LLM-assisted digital forensics.

[![Preprint DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.20549726.svg)](https://doi.org/10.5281/zenodo.20549726)
[![Artifact DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.20549626.svg)](https://doi.org/10.5281/zenodo.20549626)

OATH is a research prototype for making forensic claims replayable. It separates
what an LLM proposes from what the evidence proves: forensic tools produce signed
`Notarized<T>` envelopes, and the Witness Oath Verifier promotes only claims that
can be deterministically re-derived from the original evidence bytes.

This repository supports the published preprint:

> **OATH: Notarized Evidence Envelopes for LLM-Assisted Forensic Claims**
> Zenodo DOI: [10.5281/zenodo.20549726](https://doi.org/10.5281/zenodo.20549726)

The verifier artifact is archived separately at
[10.5281/zenodo.20549626](https://doi.org/10.5281/zenodo.20549626).

## Relationship to Protocol SIFT

OATH extends [Protocol SIFT](https://github.com/teamdfir/protocol-sift) — the
open-source autonomous-DFIR baseline (Claude Code + five DFIR skill packs +
PDF reporter, installed under `~/.claude/`). Protocol SIFT provides the agent
framework; OATH layers a typed MCP-server tool surface, `Notarized<T>`
envelopes, and a verifier-gated promotion path on top. Both install scripts
(`scripts/install-tools.sh`, `scripts/install-on-sift.sh`) call Protocol SIFT's
own installer first, then install OATH. See
[docs/ARCHITECTURE.md §"How OATH extends Protocol SIFT"](docs/ARCHITECTURE.md#how-oath-extends-protocol-sift)
for the architectural diff.

If you already have Protocol SIFT installed (Claude Code present at
`~/.claude/CLAUDE.md` and the five skill packs at `~/.claude/skills/`), set
`OATH_SKIP_PROTOCOL_SIFT=1` before running either install script to skip the
baseline step:

```bash
OATH_SKIP_PROTOCOL_SIFT=1 bash scripts/install-on-sift.sh
```

## Core Idea

LLM-assisted investigation fails dangerously when a fluent model summary is
treated as evidence. OATH treats that as a systems problem. A finding is not
accepted because the model said it; it is accepted only when it cites a signed
receipt whose contents replay.

Each `Notarized<T>` envelope binds:

- original evidence hash
- typed tool name and version
- canonical tool arguments
- raw tool-output hash
- parsed-data hash
- supporting byte offsets when available
- model identifier and prompt hash when an LLM contributed
- previous-envelope hash for tamper-evident sequencing
- Ed25519 signature over the signed header

The verifier then classifies claims as:

- `VERIFIED`: the receipt and predicate replay successfully
- `QUARANTINED`: the receipt is intact, but the cited claim is not supported
- `RALPH_WIGGUM`: evidence drift or receipt tampering is detected, forcing visible
  abandonment and re-proposal

## Results

The benchmark is DFIR-Metric Module III, using 510 scored string-search
questions in the local harness and a four-candidate answer budget.

| System | TUS@4 |
|---|---:|
| GPT-4.1 published baseline | 38.5% |
| OATH deterministic baseline, no LLM | 78.43% |
| OATH live agent with verifier | 92.75% |

The architectural result matters more than the model headline: typed tool
invocation plus deterministic replay removes a large class of free-form
script-generation failures before any model-specific capability is counted.

Full methodology and audit notes are in [docs/ACCURACY.md](docs/ACCURACY.md).

## Artifact Release

A verifier-focused artifact release is archived on Zenodo:

- Artifact: [OATH verifier artifact v0.1.0](https://doi.org/10.5281/zenodo.20549626)
- Preprint: [OATH: Notarized Evidence Envelopes for LLM-Assisted Forensic Claims](https://doi.org/10.5281/zenodo.20549726)

The release is intended to let an independent reviewer answer the narrow
question: does the receipt, signature, canonicalization, replay, and
self-correction design work? It does not include private case data, signing
secrets, API keys, or operational prompts.

## Quick Start

OATH is published as a Python MCP server. Four one-liners on a SANS SIFT
Workstation get you from cold boot to "Claude Code is driving 13 typed
forensic tools against your evidence":

```bash
# 1. Protocol SIFT baseline (Claude Code + DFIR skill packs)
curl -fsSL https://raw.githubusercontent.com/teamdfir/protocol-sift/main/install.sh | bash

# 2. Forensic-binary bootstrap (.NET 9, EZ Tools, Hayabusa — what SIFT lacks)
curl -fsSL https://raw.githubusercontent.com/GharsallahDev/oath-mcp/main/scripts/bootstrap-forensic-tools.sh | bash
exec bash    # pick up the new PATH

# 3. uv (if not already installed)
curl -LsSf https://astral.sh/uv/install.sh | sh && exec bash

# 4. Wire OATH into Claude Code (this is what goes on screen in the demo)
claude mcp add --transport stdio oath -- uvx oath-mcp
```

Then start a session and confirm the 13 typed tools are connected:

```bash
claude
# inside Claude:
/mcp        # → oath: connected · 13 tools
```

To use the operator CLI (`oath mount`, `oath verify`, `oath demo`) instead
of driving via Claude Code, install the package as a tool:

```bash
uv tool install oath-mcp
oath mount path/to/evidence.E01
oath verify <envelope-id>
```

Full forensic workstation setup, including the longer-form
`install-on-sift.sh` alternative and a non-SIFT Docker path, is documented
in [docs/TRY_IT_OUT.md](docs/TRY_IT_OUT.md).

### Developing locally

For working on `src/oath/`:

```bash
git clone https://github.com/GharsallahDev/oath-mcp-mcp
cd oath-mcp
uv venv && uv pip install -e ".[dev]"
PYTHONPATH=src python -m pytest tests/integration/test_spoliation.py -q
```

## Architecture

```mermaid
flowchart LR
    IMG["Evidence image"] --> HANDLE["Read-only EvidenceHandle"]
    HANDLE --> TOOLS["Typed forensic tools"]
    TOOLS --> ENV["Signed Notarized<T> envelope"]
    LLM["LLM proposes typed arguments and claims"] --> TOOLS
    LLM --> CLAIM["Claim cites envelope_id"]
    CLAIM --> VERIFY{"Witness Oath Verifier"}
    ENV --> VERIFY
    VERIFY -->|receipt replays + predicate matches| OK["VERIFIED"]
    VERIFY -->|receipt intact, predicate missing| Q["QUARANTINED"]
    VERIFY -->|hash/signature/data drift| R["RALPH_WIGGUM"]
    R --> LLM
```

OATH uses a custom MCP-style tool surface with typed functions rather than an
arbitrary shell. The LLM can propose arguments and hypotheses; it cannot promote
its own findings. Promotion is reserved for the deterministic verifier.

Detailed trust-boundary notes are in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Repository Map

| Path | Purpose |
|---|---|
| `src/oath/receipt/` | `Notarized<T>` envelope, canonicalization, signatures, prompt hashing |
| `src/oath/mcp/` | Typed forensic tool surface and evidence-handle plumbing |
| `src/oath/witness/` | Verifier, claim predicates, self-correction events |
| `src/oath/benchmark/` | DFIR-Metric harness and scoring utilities |
| `tests/integration/test_spoliation.py` | Spoliation, data-integrity, chain, and Daubert-binding tests |
| `logs/self-correction-demo/` | Re-runnable self-correction artifact |
| `web/` | Static receipt explorer for signed sample envelopes |

## What OATH Does Not Claim

OATH does not prove legal admissibility, certify tool correctness, make wrappers
honest by magic, prove general DFIR competence, or remove the need for examiner
review. It provides a concrete receipt and verifier pattern for making
LLM-assisted forensic claims auditable.

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Artifact release notes](docs/ARTIFACT.md)
- [Publication and citation notes](docs/PUBLICATION.md)
- [Accuracy and benchmark notes](docs/ACCURACY.md)
- [Dataset documentation](docs/DATASETS.md)
- [Try-it-out instructions](docs/TRY_IT_OUT.md)

## License

MIT. See [LICENSE](LICENSE).
