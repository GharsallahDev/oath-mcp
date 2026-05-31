"""OATH command-line entry point.

The CLI is the thin user-facing surface. The interesting work happens in:

    src/oath/mcp/          — the Custom MCP Server + 12 typed forensic functions
    src/oath/witness/      — the Witness Oath Verifier + Ralph Wiggum Loop
    src/oath/receipt/      — Notarized<T> envelopes + portable Replay Receipts
    src/oath/agent/        — the autonomous orchestration loop
    src/oath/benchmark/    — DFIR-Metric Module III scoring harness

Subcommands:

    oath mount <image>              # mount a case image read-only (losetup -r + FUSE)
    oath triage [--hypothesis ...]  # run autonomous triage; emit findings + receipts
    oath verify <finding-id>        # re-derive a finding from the original image
    oath benchmark <module>         # run a DFIR-Metric module and update leaderboard
    oath serve                      # boot the MCP server (for Claude Code integration)
"""
from __future__ import annotations

import sys

import click

from oath import __version__


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(__version__, "-V", "--version")
def main() -> None:
    """OATH — every forensic claim takes the oath."""


@main.command()
@click.argument("image", type=click.Path(exists=True, dir_okay=False, readable=True))
@click.option("--out", default="./.oath/handle.json", help="Where to write the EvidenceHandle.")
def mount(image: str, out: str) -> None:
    """Mount a case image read-only and emit an EvidenceHandle.

    Read-only is enforced architecturally: losetup -r on Linux, FUSE read-only
    overlay on macOS. The EvidenceHandle records the image SHA-256, mount point,
    and a Notarized signature that downstream tool invocations bind to.
    """
    click.echo(f"[oath mount] {image}  →  {out}")
    click.echo("(not yet implemented)", err=True)
    sys.exit(2)


@main.command()
@click.option("--hypothesis", multiple=True, help="Optional starting hypothesis (e.g. T1550.002).")
@click.option(
    "--handle", default="./.oath/handle.json", help="Path to EvidenceHandle from `oath mount`."
)
def triage(hypothesis: tuple[str, ...], handle: str) -> None:
    """Run autonomous triage on a mounted image.

    The agent loop:
      1. Reads the EvidenceHandle.
      2. Calls the Custom MCP Server's typed functions.
      3. Proposes claims; the Witness Oath Verifier deterministically
         re-derives or rejects each.
      4. On rejection, enters the Ralph Wiggum Loop (visible self-correction).
      5. Ships findings as Replay Receipts (one-line verifier commands).
    """
    click.echo(f"[oath triage] handle={handle}  hypotheses={list(hypothesis) or 'auto'}")
    click.echo("(not yet implemented)", err=True)
    sys.exit(2)


@main.command()
@click.argument("finding_id")
@click.option(
    "--receipt-dir",
    default="./logs/receipts",
    help="Directory containing the Notarized receipts.",
)
def verify(finding_id: str, receipt_dir: str) -> None:
    """Re-derive a single finding from the original image.

    Replays the recorded tool invocation against the original-image SHA-256,
    recomputes the BLAKE3 hash of the output, and compares it to the signed
    receipt. Outputs PASS / FAIL with the supporting evidence span on PASS.

    Designed to run on any analyst's commodity laptop in under 60 seconds.
    """
    click.echo(f"[oath verify] finding={finding_id}  receipts={receipt_dir}")
    click.echo("(not yet implemented)", err=True)
    sys.exit(2)


@main.command()
@click.argument("module", type=click.Choice(["I", "II", "III"]))
@click.option("--corpus", default="./corpus/dfir-metric", help="DFIR-Metric corpus root.")
@click.option(
    "--publish", is_flag=True, help="Publish the resulting score to the public leaderboard."
)
def benchmark(module: str, corpus: str, publish: bool) -> None:
    """Run a DFIR-Metric module and (optionally) update the leaderboard.

    Module III is the practical-analysis subset where the published frontier-LLM
    baseline is GPT-4.1 at 38.5% TUS@4. OATH targets >60%.
    """
    click.echo(
        f"[oath benchmark] module={module}  corpus={corpus}  publish={publish}"
    )
    click.echo("(not yet implemented)", err=True)
    sys.exit(2)


@main.command()
@click.option("--transport", type=click.Choice(["stdio", "http"]), default="stdio")
@click.option("--port", default=8765, type=int)
def serve(transport: str, port: int) -> None:
    """Boot the Custom MCP Server so Claude Code can connect to it.

    Exposes 12 typed forensic functions, each returning Notarized<T>.
    """
    click.echo(f"[oath serve] transport={transport}  port={port}")
    click.echo("(not yet implemented)", err=True)
    sys.exit(2)


if __name__ == "__main__":
    main()
