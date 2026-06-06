# Publication

The implementation and the accompanying preprint are published as follows.

## Records

| Record | Location | Type |
|---|---|---|
| OATH: Verifier-Gated Evidence Receipts for LLM-Assisted Digital Forensics | [osf.io/rk73m](https://osf.io/rk73m/) | Preprint |
| `oath-mcp` (Python MCP server, version 0.1.3) | [pypi.org/project/oath-mcp](https://pypi.org/project/oath-mcp/) | Published package |

The preprint is the canonical write-up of the receipt protocol and the
benchmark numbers. The published package is the canonical distribution of the
implementation; install with `claude mcp add --transport stdio oath -- uvx oath-mcp`.

## Citation

```bibtex
@misc{gharsallah2026oath,
  author       = {Malek Gharsallah},
  title        = {{OATH}: Verifier-Gated Evidence Receipts for LLM-Assisted Digital Forensics},
  year         = {2026},
  month        = jun,
  howpublished = {Open Science Framework},
  url          = {https://osf.io/rk73m/}
}

@misc{oathmcppackage2026,
  author       = {Malek Gharsallah},
  title        = {{oath-mcp}: Published MCP server for OATH},
  year         = {2026},
  month        = jun,
  howpublished = {Python Package Index},
  url          = {https://pypi.org/project/oath-mcp/},
  note         = {Install via \texttt{claude mcp add --transport stdio oath -- uvx oath-mcp}}
}
```

## Release Boundary

The published package is verifier-focused. It contains the material needed to
inspect the receipt and verifier design, but not private case data, signing
secrets, API keys, hosted-model credentials, sensitive prompts, benchmark
corpus images, or private benchmark notes.
