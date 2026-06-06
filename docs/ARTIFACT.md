# OATH Published Implementation

This document describes the public release boundary for OATH.

The implementation is published as a Python MCP server on the Python Package
Index:

- Package: [`oath-mcp` on PyPI](https://pypi.org/project/oath-mcp/)
- Current version: `0.1.3`
- Canonical install: `claude mcp add --transport stdio oath -- uvx oath-mcp`
- Companion preprint: [osf.io/rk73m](https://osf.io/rk73m/)

The release is intentionally verifier-focused. It contains the material
needed to inspect and exercise the receipt design without exposing private
case data, signing secrets, API keys, or operational prompts.

## Included

- `Notarized<T>` schema and signing implementation
- Canonicalization (RFC 8785 JCS) and prompt-hash helpers
- Witness Oath Verifier and claim-predicate code
- 11 typed forensic-tool wrappers and 5 control-plane / inspection tools
- Spoliation and Daubert-binding tests (14 named tests)
- Scripted self-correction artifact
- Signed sample envelopes and expected verifier outcomes

## Not Included

- Private signing keys
- Real customer or sensitive case data
- API keys or cloud credentials
- Private benchmark notes
- Prompts containing sensitive operational strategy
- Destructive or arbitrary-shell tool surfaces

## Minimal Reproduction

```bash
pip install oath-mcp[dev]

python -m pytest --pyargs oath.tests.integration.test_spoliation -q
python -m oath.scripts.show_self_correction
```

The first command exercises signature binding, data-hash integrity,
prompt/model binding, and replay-failure classification. The second replays
the scripted self-correction artifact and emits the verifier-driven
abandonment event.
