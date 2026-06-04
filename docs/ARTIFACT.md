# OATH Verifier Artifact

This document describes the public artifact boundary for OATH.

The artifact release is intentionally verifier-focused. It contains the material
needed to inspect and exercise the receipt design without exposing private case
data, signing secrets, API keys, or operational prompts.

## Included

- `Notarized<T>` schema and signing implementation
- canonicalization and prompt-hash helpers
- verifier and claim-predicate code
- spoliation and Daubert-binding tests
- synthetic self-correction demo
- signed sample envelopes and expected verifier outcomes
- installation metadata needed to run the tests

## Not Included

- private signing keys
- real customer or sensitive case data
- API keys or cloud credentials
- private benchmark notes
- prompts containing sensitive operational strategy
- destructive or arbitrary-shell tool surfaces

## Minimal Reproduction

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"

PYTHONPATH=src python -m pytest tests/integration/test_spoliation.py -q
PYTHONPATH=src python scripts/show_self_correction.py
```

The first command block exercises signature binding, data-hash integrity,
prompt/model binding, and replay-failure classification. The second replays the
persisted self-correction artifact and emits the verifier-driven abandonment
event.
