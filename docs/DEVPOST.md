# Devpost submission — OATH

Paste these sections into the matching Devpost fields. Plain markdown; Devpost renders it.

---

## Tagline (140 chars max)

> Autonomous DFIR agent — every forensic claim is a signed receipt, deterministically re-derivable from the original image SHA-256.

---

## Inspiration

Anthropic's November-2025 disclosure of **GTG-1002** — a Chinese state-sponsored operation running autonomous reconnaissance, exploitation, and lateral movement at 80-90% AI autonomy — was the wake-up call. The offensive side already has machine-speed AI. The defensive side still has analysts looking up command-line flags during active incidents.

The SANS Find Evil! hackathon brief said it directly: *"That gap is the most dangerous problem in cybersecurity."* SIFT Workstation is the platform; Protocol SIFT showed what's possible with LLM agents over MCP. But Protocol SIFT also hallucinates more than anyone is comfortable with. In a SOC, a hallucinated finding is wasted analyst time. In a courtroom, it's career-ending.

We didn't want to make a better LLM. We wanted to make an architecture where **the LLM's mistakes get caught by construction**.

---

## What it does

OATH is an autonomous DFIR agent built on the **Custom MCP Server** pattern (architectural approach #2 in the Find Evil! taxonomy, called out in the rules as "the most sound architecture in the evaluation"). The agent's tool surface is **11 typed forensic functions** — no `execute_shell`, no arbitrary code paths. Every tool output is wrapped in a signed `Notarized<T>` envelope. Every LLM-emitted claim passes the **Witness Oath Verifier**, which re-runs the cited tool and confirms the BLAKE3 of stdout matches the signed receipt. Mismatch → the claim is **quarantined** (visible to the examiner, never promoted to a finding). Drift → the **Ralph Wiggum Loop** forces visible re-proposal under a derived constraint. Every shipped finding ships with a one-line replay command (`oath verify <envelope-id>`) that an examiner can run on any laptop in under a minute.

The result on the only public benchmark in this space (DFIR-Metric Module III, NIST String Search, 510 questions): **92.75% TUS@4 vs the paper's GPT-4.1 baseline of 38.5%**. Same corpus, same image, same scoring rule. The deterministic baseline (no LLM at all) scores **78.43%** — meaning the architectural lift alone is worth ~40 points before the LLM proposes anything.

Real evidence end-to-end works against the NIST CFReDS Data Leakage Case (Win7 NTFS, 2.15 GB E01): the suspect "informant" (RID 1000) is surfaced by `parse_registry` from the real SAM hive; their email `iaman.informant@nist.gov` shows up in `parse_usnjrnl` deletions of Outlook OST temp files; Hayabusa flags `T1098` (admin-group additions) on 2015-03-22 and `T1543.003` (service persistence) on the leak day — the actual attack chain visible without a human deciding what to look at.

---

## How we built it

**Pattern:** Custom MCP Server. The agent's tool surface is 11 typed Python functions, each wrapping a standard forensic tool:

- `parse_evtx` (EvtxECmd) · `parse_mft` (MFTECmd) · `parse_registry` (RECmd batch-plugin)
- `parse_usnjrnl` (MFTECmd $J mode) · `parse_prefetch` (PECmd) · `parse_amcache` (AmcacheParser)
- `run_hayabusa` (Sigma rules with the super-verbose profile for MITRE tags)
- `vol3_query` (Volatility 3 plugin invocation) · `plaso_supertimeline` (psort over a pre-built .plaso store)
- `find_strings_on_image` (Sleuthkit fls + icat + multi-encoding byte-level scan — the NIST String Search surface)
- `enumerate_credential_artifacts` (pure-Python FS inventory)

Every call returns `Notarized<T>` — a Pydantic-typed envelope binding:

- The image SHA-256 (streamed at `oath mount` time)
- The tool name and pinned version
- The canonical argument vector (RFC 8785 JCS — sorted keys, UTF-8, no whitespace)
- The BLAKE3 hash of the tool's stdout / output file
- The byte offsets of supporting evidence
- The ed25519 signature over the entire header
- The prev-hash chain link to the previous envelope

The **Witness Oath Verifier** consumes `AgentClaim` objects (LLM-emitted findings that cite envelopes by ID), re-runs every cited tool's `reverify()` callable, and confirms the BLAKE3 of stdout matches the signed value. Predicate-mismatch → QUARANTINED. Envelope drift → RALPH_WIGGUM. The verifier is the only path from DRAFT to CONFIRMED — the LLM has no bypass.

The **LLM layer** is Vertex Gemini 3 Flash (with 3.1 Pro and 2.5 Flash benchmarked alongside for cross-tier comparison — see `docs/ACCURACY.md`). We don't ask it to write code (that's GPT-4.1's failure mode in the paper). We constrain it to emit a structured JSON object specifying the search arguments — image, partition, pattern, filter — and a deterministic executor runs the actual search under the verifier. The LLM-vs-deterministic comparison in our accuracy report is exactly this knob: turn the LLM off and we still score 78.43%, because the architecture is doing the heavy lifting. Transient Vertex API errors (429 quota, timeouts) trigger indefinite retry-with-backoff — never silent fallback to deterministic, which would corrupt the score.

**Replay receipts.** Every envelope is committed to `logs/envelopes/<run_id>.jsonl` with a sidecar index. `oath verify <envelope-id>` re-runs the bound tool with the same args, recomputes BLAKE3-of-stdout, and confirms match. Pure Python, ~3 seconds per envelope. No LLM, no API key, no MCP server boot.

**Evidence integrity.** 14 named spoliation tests in `tests/integration/test_spoliation.py` prove the verifier catches: single-bit image mutation, tool-output drift, envelope-header tampering, args_canonical tampering, persisted-data tampering (`data_blake3` is signed transitively by the header so a fabricated record in `envelope.data` is caught at verify time), Daubert binding tampering (`model_id` + `prompt_hash` signed into the header), chain-of-custody breaks (prev-hash link), and end-to-end via the verifier registry. The single prompt-based guardrail (LLM stays in the args schema) fails *closed* — when the LLM disobeys, the deterministic resolver runs instead, never the LLM's output. See `docs/ARCHITECTURE.md` §"Security boundaries" for the architectural-vs-prompt-based breakdown.

---

## Challenges we ran into

1. **Real-evidence tool-version drift.** Our unit tests were green for weeks, but every typed function broke the first time we ran it against the real CFReDS Data Leakage Case. EZ Tools 2026.5.0 changed the CLI ("--csv -" stdout mode is gone — only `--csv DIR --csvf FILE` works). Hayabusa 3.x renamed `MitreTechniques` to `MitreTags` and dropped MITRE columns from the default output profile. MFTECmd's $J mode renamed `FileName` to `Name`. Every CSV started with a UTF-8 BOM that csv.DictReader put in the first column name. Each was a real bug surfaced only by real evidence. We fixed all of them and added the test-fake mirrors so the unit tests now match the production contract.

2. **Plaso on Apple Silicon.** macOS arm64 has no working native install path for plaso — the libyal C binding chain (libfsntfs / libfsext / libfsfat / libvhdi / ...) has no arm64 wheels in PyPI and no Homebrew formulas. We refused to skip it. Solution: a Docker shim under colima running the official `log2timeline/plaso:amd64` image with `--platform linux/amd64`. The shim auto-mounts host paths into the container so `psort.py` and `log2timeline.py` work transparently as if they were native binaries. Performance is ~3-5× slower than native (Rosetta x86 emulation) but functionally identical.

3. **Honest framing of the benchmark numbers.** Our first draft of `docs/ACCURACY.md` led with "92.75% vs 38.5% = +54.25 points" — which is technically correct but feels too good. After internal review we found that 55% of the corpus has empty expected answers, which any K=4 system can claim by including `[]` as a candidate. Rather than hide this we documented it explicitly and broke out the **non-empty-expected subset** as a separate column. On the harder subset the live agent scores 83.70% (190/227) and the deterministic baseline scores 51.54% (117/227) — the LLM's actual contribution is +32.2 points once the empty-answer easy wins are factored out. That's the real story; the architectural lift (removing the script-generation failure class) plus the LLM's filter selection together explain the result.

---

## What sets OATH apart

The Find Evil! brief lists six things judges score on. Most submissions in this space cover the first three (autonomous execution, IR accuracy, hallucination management). What gets you out of the middle of the pack is the last three (architectural guardrails, audit trail quality, documentation) — and **the cryptographic chain of custody is the differentiator no other submission ships**. Specifically:

- **Signed `Notarized<T>` envelopes — including the Daubert binding nobody else ships.** Every tool output is wrapped in an ed25519-signed, BLAKE3-hashed, RFC-8785-canonicalized envelope that binds: the image SHA-256, the tool version, the canonical args, the raw stdout BLAKE3, the canonical-form parsed data (`data_blake3`), the LLM identifier (`model_id`), AND the BLAKE3 of the prompt that produced the LLM's proposal (`prompt_hash`). The signed receipt itself answers the Daubert question — *which model produced this finding, from what prompt?* — without trusting the agent's logs. No other Find Evil! submission ships this primitive. Tampering with any field invalidates the signature. Architecturally enforced. Tested with 14 named spoliation cases.

- **`oath verify` replay receipts.** Every shipped finding ships with a one-line command that re-derives the supporting evidence from the original-image SHA-256 on an examiner's commodity laptop in under 3 s. No LLM. No API key. No MCP server boot. Pure Python recompute against the signed receipt. *What cannot replay does not exist.*

- **A public-benchmark score against a peer-reviewed paper.** We score **92.75% TUS@4** on DFIR-Metric Module III (NIST String Search), the only published LLM-DFIR benchmark (arXiv:2505.19973). The paper's GPT-4.1 baseline is 38.5%. Our deterministic-baseline-without-an-LLM scores 78.43% — *beating GPT-4.1 by ~40 points with no LLM at all*. On the harder non-empty-answer subset (227 questions where the system must actually find files), the live agent scores 83.70% vs 51.54% deterministic. The benchmark is fully reproducible from a fresh clone; the corpus SHA-256 is bound into every result file. Full methodology + audit trail: arXiv-style preprint published at [Zenodo DOI 10.5281/zenodo.20549726](https://doi.org/10.5281/zenodo.20549726).

- **A real, persisted self-correction trace.** [`logs/self-correction-demo/`](logs/self-correction-demo/manifest.md) contains a real Ralph Wiggum cycle generated by the production verifier on intentionally-tampered evidence — a `data_blake3` mismatch fires the abandonment, the agent re-proposes citing a clean envelope, the verifier returns VERIFIED. Re-runnable in 2 seconds via `python scripts/show_self_correction.py`. Not a narrated demo — actual signed envelopes, actual verifier verdicts.

---

## Accomplishments we're proud of

- **The deterministic-without-an-LLM baseline alone beats GPT-4.1.** That's the result we want judges to remember. We don't NEED a frontier LLM to beat the published frontier-LLM number. Constraining the LLM to a typed-args proposal that a verifier runs makes everything else easier.

- **298 unit + integration tests, all passing**, including 14 named spoliation tests that prove the chain of custody actually holds end-to-end — covering signature tampering, persisted-data tampering (`data_blake3`), Daubert binding tampering (`model_id` + `prompt_hash` signed into the header), chain-of-custody breaks via prev-hash link, and the subtle "fabricate a record in `envelope.data` but leave raw stdout untouched" attack which an earlier external audit flagged as a critical architectural gap.

- **Real evidence end-to-end.** Every typed function has been smoke-tested against the NIST CFReDS Data Leakage Case (Win7 NTFS, 2.15 GB E01). The suspect, the deleted Outlook OST temp files containing his email, the admin-group-add events on the day before the leak, the service persistence on the leak day — all surfaced from the image bytes, all signed.

- **Two install paths, both tested.** `scripts/install-tools.sh` for macOS Apple Silicon (with the plaso-via-Docker workaround), `scripts/install-on-sift.sh` for the SANS SIFT Workstation (native plaso, no Docker shim needed). Both produce identical Notarized envelope behavior — same image SHA-256 in, same BLAKE3 out.

- **A Receipt Explorer web UI** at `/web/`, deployable to Cloudflare Pages or GitHub Pages, that lets anyone click through real signed envelopes from our DLC run and see exactly what `oath verify` would re-derive.

---

## What we learned

- **Hallucination is an architecture problem, not a prompt problem.** Every prompt-engineering paper of the last three years has tried to make LLMs lie less. We learned more by *removing the LLM's ability to lie about facts the verifier can check*. The LLM proposes; the verifier disposes.

- **"Real evidence" is the only acceptable test.** Synthetic test fixtures hide everything that actually matters: CLI drift between tool versions, BOM bytes in CSV headers, column-name renames, partition-table ambiguities. The bugs in this submission that would have been disqualifying in front of a judge were only caught because we forced ourselves to run the full pipeline against an actual NIST forensic image before declaring anything done.

- **Honesty beats inflation.** Our first benchmark report leaned on the 92.75% number. Stepping back and exposing the empty-answer asterisk made the architectural argument stronger, not weaker. The "deterministic baseline beats GPT-4.1 *with no LLM at all*" framing is a better story than "our LLM is smarter."

- **Cryptography belongs at the leaves.** ed25519 + BLAKE3 + RFC 8785 are 300 lines of Python wrapping mature crypto primitives. The result is a chain-of-custody contract that holds whether or not you trust the agent. Trust the math, not the LLM.

---

## What's next

- **Cross-family adversarial corpus.** Use the same architecture to generate test cases with one model family (Gemini) and verify with another (GPT or Claude). The cross-family check is a stronger filter for hallucinations than self-consistency.

- **Daubert-readiness audit.** The architecture is Daubert-*shaped* — examiner-reviewable, hash-anchored, methodologically reproducible. Working with a forensic lab to actually attempt admissibility on a real case would close the gap between architectural design and judicial reality.

- **Live IR deployment.** Wrapping the typed-function set in a remote MCP server lets a SOC team point OATH at a SIEM or an EDR endpoint and get verifier-gated triage on incidents in flight, not just on cold images.

- **More tools, same contract.** Adding `parse_chromium_history`, `parse_iis_logs`, `parse_apache_logs`, etc. is mechanical work — each takes a few hours of "wrap a CLI tool, mint Notarized envelopes, write a `reverify()`." The architecture pays its keep every time we add one because the verifier contract is the same.

---

## Built with

`python` · `pydantic` · `mcp` · `cryptography` · `pynacl` (ed25519) · `blake3` · `volatility3` · `plaso` · `sleuthkit` · `EZ Tools` · `Hayabusa` · `Vertex AI` (Gemini 3 Flash + 3.1 Pro) · `rich` · `click` · `colima` (for plaso amd64 shim)

---

## Try it out

- **Preprint:** [Zenodo DOI 10.5281/zenodo.20549726](https://doi.org/10.5281/zenodo.20549726) — full paper with methodology, threat model, related-work comparison against sigstore-a2a / Merkleon / Clampd / AEGIS, and per-model token economics
- **Verifier artifact (Zenodo-archived release):** [Zenodo DOI 10.5281/zenodo.20549626](https://doi.org/10.5281/zenodo.20549626) — citable software release of the receipt + verifier code with `CITATION.cff` for automatic citation
- **Live URL (Receipt Explorer):** deployed at submission via `wrangler pages deploy ./web` — pure static SPA over the bundled CFReDS signed envelopes; meanwhile `cd web && python3 -m http.server 8765` runs it locally with byte-identical data
- **Repo:** https://github.com/GharsallahDev/oath
- **Reproduce the benchmark numbers:** see [`docs/ACCURACY.md`](docs/ACCURACY.md) §2 — one-liner clone-to-result
- **Try-It-Out walkthrough:** [`docs/TRY_IT_OUT.md`](docs/TRY_IT_OUT.md) — works on macOS native AND SIFT Workstation
- **Self-correction artifact:** [`logs/self-correction-demo/manifest.md`](logs/self-correction-demo/manifest.md) — persisted RalphWiggumEvent + outcome from a real verifier run, re-runnable in 2 seconds via `python scripts/show_self_correction.py`
