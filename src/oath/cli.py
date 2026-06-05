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
from typing import Any

import click

from oath import __version__


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(__version__, "-V", "--version")
def main() -> None:
    """OATH — every forensic claim takes the oath."""


@main.command()
@click.argument("image", type=click.Path(exists=True, dir_okay=False, readable=True))
@click.option(
    "--handles-dir",
    type=click.Path(file_okay=False),
    default="./logs/handles",
    show_default=True,
    help="Directory where the EvidenceHandle JSON is persisted.",
)
def mount(image: str, handles_dir: str) -> None:
    """Open a forensic image and emit an EvidenceHandle.

    Computes the SHA-256 of the image, mounts it read-only where possible
    (losetup -r on Linux, raw-file on macOS), and persists the handle so
    downstream typed-function calls can reference it by handle_id.
    """
    from pathlib import Path

    from oath.mcp.evidence_handle import open_handle
    from oath.mcp.persistence import save_handle

    image_path = Path(image).expanduser().resolve()
    click.echo(f"  computing image SHA-256 ({image_path.stat().st_size / 1e9:.2f} GB)…")
    handle = open_handle(image_path)
    handles_root = Path(handles_dir)
    handle_id = save_handle(handle, handles_root)

    click.echo("")
    click.echo(f"  handle_id     : {handle_id}")
    click.echo(f"  image         : {handle.image_path}")
    click.echo(f"  image_sha256  : {handle.image_sha256}")
    click.echo(f"  image_size    : {handle.image_size_bytes:,} bytes")
    click.echo(f"  mount_tech    : {handle.mount_tech}")
    click.echo(f"  mount_point   : {handle.mount_point or '(none — raw-file access)'}")
    click.echo(f"  saved at      : {handles_root / (handle_id + '.json')}")


@main.command()
@click.option("--hypothesis", multiple=True,
              help="Restrict to hypotheses whose name contains this substring (repeatable). "
                   "Default: run every hypothesis in the canonical PtH bundle.")
@click.option("--logs-dir", type=click.Path(file_okay=False), default="./logs", show_default=True,
              help="Logs directory containing envelopes + sample-run subdirs.")
@click.option("--out", type=click.Path(dir_okay=False), default=None,
              help="Write the TriageReport JSON to this path (else stdout).")
def triage(hypothesis: tuple[str, ...], logs_dir: str, out: str | None) -> None:
    """Run hypothesis-driven triage against previously-minted envelopes.

    The agent loop:
      1. Discovers signed envelopes in --logs-dir (envelopes/ + sample-run/).
      2. For each hypothesis (default: T1550.002 PtH, T1003.001 LSASS dump,
         T1070.001 log clearing, T1070.006 timestomp, T1547.001 Run-key
         persistence), a deterministic propose_fn scans the envelope set for
         records matching the hypothesis's signature pattern.
      3. The Witness Oath Verifier re-derives each cited envelope and confirms
         the predicate matches. Mismatches → QUARANTINED. Re-derive failures
         → RALPH_WIGGUM, with one visible self-correction attempt.
      4. Emits a TriageReport (verified / quarantined / gave-up counts +
         per-hypothesis outcomes).

    To drive triage interactively with a live LLM, instead run
    `oath serve` and connect via Claude Code over MCP — the typed functions
    are the same, the proposer is the LLM, the verifier path is identical.
    """
    from pathlib import Path
    import json as _json

    from oath.agent.runner import AgentRunner, default_pth_hypotheses
    from oath.mcp.persistence import EnvelopeStore
    from oath.witness.claim import AgentClaim, ClaimEvidence, FindingType
    from oath.witness.verifier import WitnessOathVerifier, default_registry

    logs = Path(logs_dir)
    if not logs.exists():
        click.echo(f"logs directory missing: {logs_dir}", err=True)
        sys.exit(2)

    # Re-use the same discovery rule as `oath verify` — envelopes + sample-run.
    candidate_dirs = [logs / "envelopes", logs / "sample-run"]
    for child in sorted(logs.iterdir()):
        if child.is_dir() and child not in candidate_dirs and any(child.glob("*.index")):
            candidate_dirs.append(child)

    envelopes_by_id: dict[str, Any] = {}
    reverify_kwargs: dict[str, dict[str, Any]] = {}
    PATH_KEYS = {
        "evtx_path", "mft_path", "amcache_path", "prefetch_dir",
        "hive_path", "plugins_dir", "j_path", "plaso_path",
        "memdump_path", "evtx_dir", "rules_dir", "mount_point", "image_path",
    }
    for env_dir in candidate_dirs:
        if not env_dir.exists():
            continue
        for jsonl_path in sorted(env_dir.glob("*.jsonl")):
            rid = jsonl_path.stem
            if not (env_dir / f"{rid}.index").exists():
                continue
            store = EnvelopeStore(rid, env_dir)
            for eid in store._index:
                env = store.load(eid)
                envelopes_by_id[eid] = env
                try:
                    args = _json.loads(env.header.args_canonical)
                except Exception:
                    args = {}
                inferred = {k: Path(args[k]) if isinstance(args[k], str) else args[k]
                            for k in PATH_KEYS if k in args and args[k] not in (None, "")}
                reverify_kwargs[eid] = inferred

    if not envelopes_by_id:
        click.echo(
            f"No envelopes under {logs_dir}. Run `oath serve` + drive via Claude Code "
            "(or `python scripts/demo.py` for a scripted walkthrough) to populate envelopes first.",
            err=True,
        )
        sys.exit(2)

    hypotheses = default_pth_hypotheses()
    if hypothesis:
        needles = [h.lower() for h in hypothesis]
        hypotheses = [h for h in hypotheses if any(n in h.name.lower() for n in needles)]
        if not hypotheses:
            click.echo(f"No hypotheses match {list(hypothesis)!r}.", err=True)
            sys.exit(2)

    # Deterministic propose_fn: scan envelopes for records that fit the
    # hypothesis's finding type. The LLM-driven proposer (Claude/Gemini) lives
    # at `oath serve` — same architecture, same verifier — but is not invoked
    # here. Constraints from previous Ralph Wiggum events are honoured by
    # excluding their cited envelope_ids.
    SIGNATURE_BY_FT: dict[FindingType, tuple[str, dict[str, Any]]] = {
        FindingType.PTH_CANDIDATE: ("parse_evtx", {"event_id": 4624}),
        FindingType.LSASS_DUMP_CANDIDATE: ("parse_amcache", {}),
        FindingType.LOG_CLEARING: ("run_hayabusa", {}),
        FindingType.TIMESTOMP: ("parse_mft", {}),
        FindingType.REGISTRY_RUN_KEY: ("parse_registry", {}),
        FindingType.SCHEDULED_TASK: ("parse_evtx", {"event_id": 4698}),
    }
    import uuid as _uuid

    def propose(hyp: Any, constraints: list[str]) -> AgentClaim | None:
        banned: set[str] = set()
        for c in constraints:
            for token in c.split():
                if token.startswith("envelope:"):
                    banned.add(token.split(":", 1)[1].rstrip(",;."))
        tool, baseline_pred = SIGNATURE_BY_FT.get(hyp.finding_type, (None, None))
        if tool is None:
            return None
        for eid, env in envelopes_by_id.items():
            if eid in banned:
                continue
            if env.header.tool_name != tool:
                continue
            data_list = list(env.data) if isinstance(env.data, (list, tuple)) else []
            if not data_list:
                continue
            first = data_list[0]
            d = first.model_dump() if hasattr(first, "model_dump") else dict(first)
            predicate = dict(baseline_pred) if baseline_pred else {}
            # Pick a stable identifier field if available — most typed records
            # expose one of these keys we can pin the predicate to.
            for k in ("event_record_id", "record_number", "entry_number",
                      "usn", "sha1", "name", "rule_title",
                      "key_path", "value_name", "plugin"):
                if k in d and d[k] not in (None, ""):
                    predicate[k] = d[k]
                    break
            if not predicate:
                continue
            return AgentClaim(
                claim_id=f"triage-{_uuid.uuid4().hex[:12]}",
                finding_type=hyp.finding_type,
                natural_language=(
                    f"{hyp.name}: matched record via deterministic envelope scan "
                    f"(tool={tool}, envelope={eid})."
                ),
                supporting_evidence=(
                    ClaimEvidence(envelope_id=eid, record_predicate=predicate),
                ),
                confidence=0.7,
                reasoning_hash="0" * 64,
                model_id="oath-triage-deterministic",
                temperature=0.0,
                seed=0,
            )
        return None

    verifier = WitnessOathVerifier(
        envelopes_by_id=envelopes_by_id,
        reverify_kwargs=reverify_kwargs,
        registry=default_registry(),
    )
    runner = AgentRunner(
        verifier=verifier,
        propose_fn=propose,
        run_id="cli-triage",
    )
    report = runner.run_all(hypotheses)

    payload = _json.dumps(_json.loads(report.model_dump_json()), indent=2)
    if out:
        Path(out).write_text(payload, encoding="utf-8")
        click.echo(
            f"triage report → {out}  "
            f"({report.verified_count} verified, {report.quarantined_count} quarantined, "
            f"{report.gave_up_count} gave up, {report.total_ralph_wiggum_events} RW events)"
        )
    else:
        click.echo(payload)


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
    if not logs.exists():
        click.echo(f"logs directory missing: {logs_dir}", err=True)
        sys.exit(2)

    from oath.mcp.persistence import EnvelopeStore
    from oath.receipt.notarized import Notarized
    from oath.witness.verifier import default_registry

    # Discover all known runs across the logs tree. Each run is a (.jsonl, .index)
    # pair under a subdir of logs/. We accept BOTH the canonical
    # `logs/envelopes/<run_id>.jsonl` layout AND the demo/sample-run layout
    # at `logs/sample-run/<run_id>.jsonl` — without this, real signed envelopes
    # from the bundled sample run are invisible to `oath verify`.
    runs: list[tuple[str, Path]] = []  # (run_id, envelopes_dir)
    candidate_dirs = [
        logs / "envelopes",
        logs / "sample-run",
    ]
    # Also auto-discover any other subdir of logs/ that contains paired
    # .jsonl + .index files — keeps the door open for additional named runs.
    for child in sorted(logs.iterdir()):
        if child.is_dir() and child not in candidate_dirs and any(child.glob("*.index")):
            candidate_dirs.append(child)

    for env_dir in candidate_dirs:
        if not env_dir.exists():
            continue
        for jsonl_path in sorted(env_dir.glob("*.jsonl")):
            if (env_dir / f"{jsonl_path.stem}.index").exists():
                runs.append((jsonl_path.stem, env_dir))

    if envelope_id is None:
        if not runs:
            click.echo("(no envelopes recorded)")
            return
        click.echo("Known envelope IDs:")
        for rid, env_dir in runs:
            store = EnvelopeStore(rid, env_dir)
            for eid in sorted(store._index.keys()):
                click.echo(f"  {env_dir.name}/{rid}/{eid}")
        return

    # Look up the envelope across every discovered run.
    envelope = None
    for rid, env_dir in runs:
        store = EnvelopeStore(rid, env_dir)
        if envelope_id in store._index:
            envelope = store.load(envelope_id)
            break
    if envelope is None:
        click.echo(
            f"envelope not found: {envelope_id} (searched {len(runs)} run(s) "
            f"across {len([d for d in candidate_dirs if d.exists()])} envelope dir(s))",
            err=True,
        )
        sys.exit(2)

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
@click.option("--transport", type=click.Choice(["stdio", "http"]), default="stdio", show_default=True)
@click.option("--port", default=8765, type=int, show_default=True,
              help="Port for HTTP transport (ignored for stdio).")
@click.option("--logs-dir", type=click.Path(file_okay=False), default="./logs", show_default=True)
@click.option("--keys-dir", type=click.Path(file_okay=False), default="./keys", show_default=True)
@click.option("--run-id", default=None,
              help="Resume an existing run_id (otherwise a fresh UUID is minted).")
def serve(transport: str, port: int, logs_dir: str, keys_dir: str, run_id: str | None) -> None:
    """Boot the Custom MCP Server so Claude Code can connect to it.

    Exposes 11 typed forensic functions, each returning Notarized<T>. The
    server reads/writes envelopes under --logs-dir/envelopes/ and signs them
    with the keypair under --keys-dir (minted on first run).
    """
    if transport != "stdio":
        click.echo(
            f"transport={transport!r} not yet supported by `oath serve` — only stdio. "
            "Run the server behind any MCP-capable HTTP gateway (e.g. `mcpo`) for HTTP.",
            err=True,
        )
        sys.exit(2)

    from pathlib import Path

    from oath.mcp.server import main as mcp_main

    argv = ["--logs-dir", logs_dir, "--keys-dir", keys_dir]
    if run_id:
        argv += ["--run-id", run_id]
    click.echo(
        f"[oath serve] booting MCP server (stdio) — logs={logs_dir} keys={keys_dir}",
        err=True,
    )
    sys.exit(mcp_main(argv))


@main.command()
@click.option("--pause", type=float, default=2.5, show_default=True,
              help="Seconds between scenes (lower = faster demo).")
@click.option("--handle-id", default="15e9489f6ae6766e", show_default=True,
              help="EvidenceHandle id of the case to demonstrate.")
@click.option("--sample-dir", type=click.Path(file_okay=False),
              default="logs/sample-run", show_default=True,
              help="Directory containing the sample-run JSONL + index.")
@click.option("--keys-dir", type=click.Path(file_okay=False),
              default="keys", show_default=True)
def demo(pause: float, handle_id: str, sample_dir: str, keys_dir: str) -> None:
    """Run the autonomous DFIR demo end-to-end (~2-3 min, no further input).

    The operator types this command ONCE. The agent then runs unattended:
      - mounts the case (handle SHA-256)
      - runs six typed forensic functions against the real CFReDS Data
        Leakage Case evidence and signs every output
      - hits a tampered envelope and visibly self-corrects via the
        Witness Oath Verifier + Ralph Wiggum Loop
      - emits a QUARANTINED verdict (suspicion not proved)
      - emits a VERIFIED verdict over the surviving envelopes
      - ships the final claim with its replay receipt

    Designed for screencast recording via:
      asciinema rec -c 'oath demo' video/demo.cast
    """
    from pathlib import Path

    from oath.agent.demo import run_demo

    sys.exit(run_demo(
        pause=pause,
        handle_id=handle_id,
        sample_dir=Path(sample_dir),
        keys_dir=Path(keys_dir),
    ))


if __name__ == "__main__":
    main()
