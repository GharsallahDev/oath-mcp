"""OATH command-line entry point.

The CLI is the thin user-facing surface. The interesting work happens in:

    src/oath/mcp/          — the Custom MCP Server + 11 typed forensic functions
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
@click.argument("envelope_id", required=False)
@click.option(
    "--logs-dir",
    type=click.Path(file_okay=False),
    default="./logs",
    show_default=True,
    help="Logs directory containing envelopes/ + handles/ subdirs.",
)
@click.option(
    "--kwargs",
    "kwargs_json",
    default=None,
    help=(
        "JSON object of per-envelope reverify kwargs (e.g. "
        '\'{"evtx_path": "/mnt/ev/Security.evtx"}\'). When omitted, '
        "the verifier infers paths from args_canonical."
    ),
)
def verify(envelope_id: str | None, logs_dir: str, kwargs_json: str | None) -> None:
    """Re-derive an envelope from the original-image SHA-256.

    Replays the recorded tool invocation, recomputes BLAKE3 of stdout,
    compares to the signed receipt. Designed to run on any analyst's
    commodity laptop in under a minute, with no LLM and no MCP.

    With no argument, lists known envelope IDs in --logs-dir.
    """
    from pathlib import Path
    import json as _json

    logs = Path(logs_dir)
    envelopes_dir = logs / "envelopes"
    if not envelopes_dir.exists():
        click.echo(f"No envelopes/ under {logs_dir}.", err=True)
        sys.exit(2)

    if envelope_id is None:
        ids = sorted(p.stem for p in envelopes_dir.glob("*.json"))
        if not ids:
            click.echo("(no envelopes recorded)")
            return
        click.echo("Known envelope IDs:")
        for eid in ids:
            click.echo(f"  {eid}")
        return

    target = envelopes_dir / f"{envelope_id}.json"
    if not target.exists():
        click.echo(f"envelope not found: {target}", err=True)
        sys.exit(2)

    from oath.receipt.notarized import Notarized
    from oath.witness.verifier import default_registry

    raw = _json.loads(target.read_text(encoding="utf-8"))
    envelope = Notarized.model_validate(raw)

    # Resolve per-envelope kwargs. Two sources, merged left-to-right:
    #   (a) inferred from envelope.header.args_canonical (paths the tool
    #       recorded at mint time — usually correct on the same host)
    #   (b) explicit overrides from --kwargs (for cross-host replay)
    inferred: dict[str, object] = {}
    try:
        args = _json.loads(envelope.header.args_canonical)
    except Exception:  # noqa: BLE001 — best-effort
        args = {}

    # Common pattern: tool-author records its primary artifact path under a
    # _path or _dir-suffixed key. Map those onto the reverify kwarg names.
    PATH_KEYS = {
        "evtx_path", "mft_path", "amcache_path", "prefetch_dir",
        "hive_path", "plugins_dir", "j_path", "plaso_path",
        "memdump_path", "evtx_dir", "rules_dir", "mount_point",
        "image_path",
    }
    for k in PATH_KEYS:
        if k in args and args[k] is not None:
            inferred[k] = Path(str(args[k]))

    if kwargs_json:
        try:
            overrides = _json.loads(kwargs_json)
        except _json.JSONDecodeError as e:
            click.echo(f"--kwargs is not valid JSON: {e.msg}", err=True)
            sys.exit(2)
        for k, v in overrides.items():
            if isinstance(v, str) and (k.endswith("_path") or k.endswith("_dir") or k == "mount_point"):
                inferred[k] = Path(v)
            else:
                inferred[k] = v

    registry = default_registry()
    ok, reason = registry.call(envelope, inferred)

    if ok:
        click.echo(f"PASS  {envelope_id}")
        click.echo(f"  tool        : {envelope.header.tool_name} {envelope.header.tool_version}")
        click.echo(f"  image       : {envelope.header.image_sha256[:16]}…")
        click.echo(f"  stdout_blake3: {envelope.header.stdout_blake3[:16]}…")
        sys.exit(0)
    else:
        click.echo(f"FAIL  {envelope_id}")
        click.echo(f"  reason      : {reason}")
        sys.exit(1)


@main.command()
@click.argument("module", type=click.Choice(["I", "II", "III"]))
@click.option(
    "--corpus",
    type=click.Path(exists=True, dir_okay=False, readable=True),
    required=True,
    help="Path to DFIR-Metric corpus file (JSONL or JSON array).",
)
@click.option("--k", default=4, show_default=True, help="TUS@K — candidates per question.")
@click.option(
    "--image-sha256",
    default=None,
    help=(
        "If set, only questions bound to this image SHA-256 are scored "
        "(other questions are skipped)."
    ),
)
@click.option(
    "--techniques",
    multiple=True,
    help="MITRE ATT&CK technique IDs to filter on (multiple flags = OR).",
)
@click.option(
    "--out-dir",
    type=click.Path(file_okay=False),
    default="./logs/benchmarks",
    show_default=True,
    help="Where to write the BenchmarkResult JSON.",
)
@click.option(
    "--dry-run",
    is_flag=True,
    help=(
        "Run with a stub agent (no LLM calls) that emits empty candidates. "
        "Useful for end-to-end smoke-testing the harness."
    ),
)
@click.option(
    "--live",
    is_flag=True,
    help=(
        "Run with the live Claude-driven agent — calls Anthropic Messages "
        "with the OATH MCP server attached. Requires ANTHROPIC_API_KEY in "
        "the environment and `pip install 'oath[claude]'`."
    ),
)
@click.option(
    "--model",
    default=None,
    help="Override the Claude model ID (defaults to the pinned model).",
)
@click.option(
    "--mcp-logs-dir",
    type=click.Path(file_okay=False),
    default="./logs",
    show_default=True,
    help="Logs directory the MCP server uses for envelope/claim persistence.",
)
def benchmark(
    module: str,
    corpus: str,
    k: int,
    image_sha256: str | None,
    techniques: tuple[str, ...],
    out_dir: str,
    dry_run: bool,
    live: bool,
    model: str | None,
    mcp_logs_dir: str,
) -> None:
    """Score the agent on a DFIR-Metric corpus and persist the result.

    Module III is the practical-analysis subset where the published frontier-LLM
    baseline is GPT-4.1 at 38.5% TUS@4. OATH targets >60% via verifier-gated
    self-correction.
    """
    from pathlib import Path

    from oath.benchmark import (
        AgentResponse,
        BenchmarkHarness,
        filter_by_image,
        filter_by_techniques,
        load_corpus,
        persist_result,
    )

    questions, corpus_sha256 = load_corpus(Path(corpus))
    if image_sha256:
        questions = filter_by_image(questions, image_sha256)
    if techniques:
        questions = filter_by_techniques(questions, list(techniques))

    if not questions:
        click.echo("No questions match the given filters.", err=True)
        sys.exit(2)

    if not (dry_run or live):
        click.echo(
            "Choose one: --dry-run (stub agent, no API calls) or --live "
            "(Claude-driven via Anthropic SDK + OATH MCP server).",
            err=True,
        )
        sys.exit(2)
    if dry_run and live:
        click.echo("--dry-run and --live are mutually exclusive.", err=True)
        sys.exit(2)

    if dry_run:
        # Dry-run stub: every question gets zero candidates. The harness
        # still produces a valid BenchmarkResult (TUS = 0.0) so we can prove
        # the plumbing works end-to-end without making API calls.
        def agent_fn(_q, _k: int) -> AgentResponse:  # noqa: ANN001
            return AgentResponse(candidates=[])
    else:
        from oath.benchmark.claude_agent import (
            ClaudeAgentConfig,
            build_claude_agent_fn,
        )

        cfg_kwargs: dict[str, object] = {
            "extra_mcp_args": (
                "--logs-dir",
                str(mcp_logs_dir),
            ),
        }
        if model:
            cfg_kwargs["model"] = model
        config = ClaudeAgentConfig(**cfg_kwargs)
        agent_fn = build_claude_agent_fn(
            config,
            envelopes_dir=Path(mcp_logs_dir) / "envelopes",
            claims_journal=Path(mcp_logs_dir) / "claims.jsonl",
        )

    harness = BenchmarkHarness(
        agent_fn=agent_fn,
        k=k,
        module=module,
        progress_callback=lambda i, n, q: click.echo(
            f"  [{i+1}/{n}] {q.question_id} ({q.answer_type.value})"
        ),
    )
    result = harness.run(questions, corpus_sha256=corpus_sha256)
    out_path = persist_result(result, Path(out_dir))

    click.echo("")
    click.echo(f"  module:        {result.module}")
    click.echo(f"  k:             {result.k}")
    click.echo(f"  questions:     {result.total_questions}")
    click.echo(f"  matched:       {result.matched_count}")
    click.echo(f"  tus@{result.k}:        {result.tus_at_k:.4f}")
    click.echo(f"  corpus sha256: {result.corpus_sha256}")
    click.echo(f"  result file:   {out_path}")


@main.command()
@click.option("--transport", type=click.Choice(["stdio", "http"]), default="stdio")
@click.option("--port", default=8765, type=int)
def serve(transport: str, port: int) -> None:
    """Boot the Custom MCP Server so Claude Code can connect to it.

    Exposes 11 typed forensic functions, each returning Notarized<T>.
    """
    click.echo(f"[oath serve] transport={transport}  port={port}")
    click.echo("(not yet implemented)", err=True)
    sys.exit(2)


if __name__ == "__main__":
    main()
