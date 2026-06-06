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

OATH is an autonomous DFIR agent that **extends Protocol SIFT** with three architectural primitives Protocol SIFT does not ship. Install OATH alongside the Protocol SIFT baseline with one canonical Model Context Protocol command:

```
claude mcp add --transport stdio oath -- uvx oath-mcp
```

That single line pulls the published `oath-mcp` package from PyPI, isolates it via `uv`, and registers it as a stdio MCP server with Claude Code. Same shape as Airtable, Sentry, or any other published MCP server in the Claude Code documentation.

OATH is also a **Custom MCP Server** (architectural approach #2 in the Find Evil! taxonomy, called out in the rules as "the most sound architecture in the evaluation"). The agent's tool surface is **11 typed forensic functions plus 5 control-plane and inspection tools — 16 typed MCP tools total**. No `execute_shell`, no arbitrary code paths. Every forensic tool output is wrapped in a signed `Notarized<T>` envelope. Every LLM-emitted claim passes the **Witness Oath Verifier**, which re-runs the cited tool and confirms the BLAKE3 of stdout matches the signed receipt. Mismatch → claim is **QUARANTINED** (visible to the examiner, never promoted to a finding). Drift → the verifier returns **`RALPH_WIGGUM`**, forcing visible re-proposal under a derived constraint. Every shipped finding ships with a one-line replay command (`oath verify <envelope-id>`) that an examiner can run on any laptop in under a minute.

The result on the only public benchmark in this space (DFIR-Metric Module III, NIST String Search, 510 questions): **92.75% TUS@4 vs the paper's GPT-4.1 baseline of 38.5%**. Same corpus, same image, same scoring rule. The deterministic baseline (no LLM at all) scores **78.43%** — meaning the architectural lift alone is worth ~40 points before the LLM proposes anything.

Real evidence end-to-end works against the **NIST CFReDS Data Leakage Case** (Win7 NTFS, 2.15 GB E01). In a 31-minute autonomous live run, the agent produced **5 court-admissible findings**, each citing a signed envelope, recovering the complete insider exfiltration chain:

1. **Network share access** — `\\10.11.11.128\secured_drive` in MountPoints2 (parse_registry, NTUSER:informant)
2. **Removable media** — two SanDisk USB serial numbers, last write 2015-03-23 18:31:09 (parse_registry, SYSTEM hive Enum\USB)
3. **Cloud exfiltration channel** — Google Drive sync folder created 2015-03-23 20:05:32 (parse_registry)
4. **Confidential file access** — Recent LNK records for `(secret_project)_pricing_decision.xlsx` and `[secret_project]_final_meeting.pptx` (parse_mft, $MFT)
5. **Anti-forensic cleanup** — bulk `FileDelete` of 17 secret_project documents and their LNK traces (parse_usnjrnl, $UsnJrnl:$J)

The agent's protocol log captures one `RALPH_WIGGUM` rejection on envelope `b7f4ac82…` during the run — the verifier rejected a citation, the agent abandoned the hypothesis and re-derived fresh per protocol. That is the self-correction beat the architecture is designed to make visible.

---

## How we built it

**Pattern:** Custom MCP Server. The agent's tool surface is 16 typed MCP tools — 11 forensic wrappers plus 5 control-plane and inspection tools.

**11 forensic wrappers**, each binding a standard forensic tool into a signed `Notarized<T>` envelope:

- `parse_evtx` (EvtxECmd) · `parse_mft` (MFTECmd) · `parse_registry` (RECmd batch-plugin)
- `parse_usnjrnl` (MFTECmd $J mode) · `parse_prefetch` (PECmd) · `parse_amcache` (AmcacheParser)
- `run_hayabusa` (Sigma rules with the super-verbose profile for MITRE tags)
- `vol3_query` (Volatility 3 plugin invocation) · `plaso_supertimeline` (psort over a pre-built .plaso store)
- `find_strings_on_image` (Sleuthkit fls + icat + multi-encoding byte-level scan — the NIST String Search surface)
- `enumerate_credential_artifacts` (pure-Python FS inventory)

**5 control-plane and inspection tools** that preserve the typed boundary across runs:

- `oath_mount` (establishes a read-only `EvidenceHandle`, streams the image SHA-256)
- `oath_list_handles` · `oath_list_envelopes` (enumerates signed envelope chains under the logs root, including read-only pre-staged chains) · `oath_read_envelope` (fetches a specific envelope payload by content-addressed ID)
- `oath_verify_claim` (routes an `AgentClaim` through the Witness Oath Verifier)

The two inspection tools (`oath_list_envelopes`, `oath_read_envelope`) close a real architectural gap: without them an agent had no way to read pre-existing signed receipts other than shelling out to JSONL files. Adding them to the typed surface keeps the typed-tool boundary intact across runs and across pre-staged evidence chains.

Every call returns `Notarized<T>` — a Pydantic-typed envelope binding:

- The image SHA-256 (streamed at `oath mount` time)
- The tool name and pinned version
- The canonical argument vector (RFC 8785 JCS — sorted keys, UTF-8, no whitespace)
- The BLAKE3 hash of the tool's stdout / output file
- The byte offsets of supporting evidence
- The ed25519 signature over the entire header
- The prev-hash chain link to the previous envelope

The **Witness Oath Verifier** consumes `AgentClaim` objects (LLM-emitted findings that cite envelopes by ID), re-runs every cited tool's `reverify()` callable, and confirms the BLAKE3 of stdout matches the signed value. Predicate-mismatch → QUARANTINED. Envelope drift → RALPH_WIGGUM. The verifier is the only path from DRAFT to CONFIRMED — the LLM has no bypass.

The **LLM layer** has two configurations. For the benchmark numbers reported below, the model is **Vertex Gemini 3 Flash** (with 3.1 Pro and 2.5 Flash benchmarked alongside for cross-tier comparison — see `docs/ACCURACY.md`). For the live recorded demo, the operator-facing agent is **Claude Code (Opus 4.8)** calling the 16 typed OATH tools through MCP. In either configuration, the model never executes forensic code. It proposes a structured JSON argument vector; a deterministic Python executor runs the actual search under the verifier. The LLM-vs-deterministic comparison in our accuracy report is exactly this knob: turn the LLM off and we still score 78.43%, because the architecture is doing the heavy lifting. Transient hosted-model API errors (429 quota, timeouts) trigger indefinite retry-with-backoff — never silent fallback to deterministic, which would corrupt the score.

**Replay receipts.** Every envelope is committed to `logs/envelopes/<run_id>.jsonl` with a sidecar index. `oath verify <envelope-id>` re-runs the bound tool with the same args, recomputes BLAKE3-of-stdout, and confirms match. Pure Python, ~3 seconds per envelope. No LLM, no API key, no MCP server boot.

**Evidence integrity.** 14 named spoliation tests in `tests/integration/test_spoliation.py` prove the verifier catches: single-bit image mutation, tool-output drift, envelope-header tampering, args_canonical tampering, persisted-data tampering (`data_blake3` is signed transitively by the header so a fabricated record in `envelope.data` is caught at verify time), Daubert binding tampering (`model_id` + `prompt_hash` signed into the header), chain-of-custody breaks (prev-hash link), and end-to-end via the verifier registry. The single prompt-based guardrail (LLM stays in the args schema) fails *closed* — when the LLM disobeys, the deterministic resolver runs instead, never the LLM's output. See `docs/ARCHITECTURE.md` §"Security boundaries" for the architectural-vs-prompt-based breakdown.

---

## Challenges we ran into

1. **Real-evidence tool-version drift.** Our unit tests were green for weeks, but every typed function broke the first time we ran it against the real CFReDS Data Leakage Case. EZ Tools 2026.5.0 changed the CLI ("--csv -" stdout mode is gone — only `--csv DIR --csvf FILE` works). Hayabusa 3.x renamed `MitreTechniques` to `MitreTags` and dropped MITRE columns from the default output profile. MFTECmd's $J mode renamed `FileName` to `Name`. Every CSV started with a UTF-8 BOM that csv.DictReader put in the first column name. Each was a real bug surfaced only by real evidence. We fixed all of them and added the test-fake mirrors so the unit tests now match the production contract.

2. **Plaso on Apple Silicon.** macOS arm64 has no working native install path for plaso — the libyal C binding chain (libfsntfs / libfsext / libfsfat / libvhdi / ...) has no arm64 wheels in PyPI and no Homebrew formulas. We refused to skip it. Solution: a Docker shim under colima running the official `log2timeline/plaso:amd64` image with `--platform linux/amd64`. The shim auto-mounts host paths into the container so `psort.py` and `log2timeline.py` work transparently as if they were native binaries. Performance is ~3-5× slower than native (Rosetta x86 emulation) but functionally identical.

3. **Honest framing of the benchmark numbers.** Our first draft of `docs/ACCURACY.md` led with "92.75% vs 38.5% = +54.25 points" — which is technically correct but feels too good. After internal review we found that 55% of the corpus has empty expected answers, which any K=4 system can claim by including `[]` as a candidate. Rather than hide this we documented it explicitly and broke out the **non-empty-expected subset** as a separate column. On the harder subset the live agent scores 83.70% (190/227) and the deterministic baseline scores 51.54% (117/227) — the LLM's actual contribution is +32.2 points once the empty-answer easy wins are factored out. That's the real story; the architectural lift (removing the script-generation failure class) plus the LLM's filter selection together explain the result.

4. **SIFT Workstation on Apple Silicon.** The hackathon Get-Started flow assumes you boot the SIFT Workstation OVA in a hypervisor and run everything there. The OVA is x86_64; one of us records on an Apple Silicon Mac (arm64). The friendly hypervisors — VMware Fusion, VirtualBox — are either Broadcom-account-gated for free use or don't cleanly emulate x86_64 on M-series. We ended up on a non-obvious path that's worth documenting for any judge in the same boat: (a) extract the OVA directly with `tar -xvf sift-2026-04-22.ova` to pull `sift-disk1.vmdk` out — UTM doesn't import OVAs natively but it imports VMDKs; (b) install **UTM** (free, App Store, one click); (c) in UTM, choose **Emulate** (turtle), **Linux**, **Intel ICH9 x86_64**, 8 GB RAM, 4 CPU cores, then **Import existing drive** pointing at the extracted VMDK; (d) before booting, edit the VM → **QEMU** tab → **UNCHECK "UEFI Boot"** — SIFT uses legacy BIOS, and with UEFI enabled the firmware drops into a shell that can't see the boot partition. After that the VM boots cleanly into Ubuntu and `bash scripts/install-on-sift.sh` does the rest (it installs Protocol SIFT first, then OATH). Emulation is roughly 5× slower than native, so the install that takes 10 min on a real SIFT VM takes ~30-45 min here. Worth the friction once.

---

## What sets OATH apart

The Find Evil! brief lists six things judges score on. Most submissions in this space cover the first three (autonomous execution, IR accuracy, hallucination management). What gets you out of the middle of the pack is the last three (architectural guardrails, audit trail quality, documentation) — and **the cryptographic chain of custody is the differentiator no other submission ships**. Specifically:

- **Signed `Notarized<T>` envelopes — including the Daubert binding nobody else ships.** Every tool output is wrapped in an ed25519-signed, BLAKE3-hashed, RFC-8785-canonicalized envelope that binds: the image SHA-256, the tool version, the canonical args, the raw stdout BLAKE3, the canonical-form parsed data (`data_blake3`), the LLM identifier (`model_id`), AND the BLAKE3 of the prompt that produced the LLM's proposal (`prompt_hash`). The signed receipt itself answers the Daubert question — *which model produced this finding, from what prompt?* — without trusting the agent's logs. No other Find Evil! submission ships this primitive. Tampering with any field invalidates the signature. Architecturally enforced. Tested with 14 named spoliation cases.

- **`oath verify` replay receipts.** Every shipped finding ships with a one-line command that re-derives the supporting evidence from the original-image SHA-256 on an examiner's commodity laptop in under 3 s. No LLM. No API key. No MCP server boot. Pure Python recompute against the signed receipt. *What cannot replay does not exist.*

- **A public-benchmark score against a peer-reviewed paper.** We score **92.75% TUS@4** on DFIR-Metric Module III (NIST String Search), the only published LLM-DFIR benchmark (arXiv:2505.19973). The paper's GPT-4.1 baseline is 38.5%. Our deterministic-baseline-without-an-LLM scores 78.43% — *beating GPT-4.1 by ~40 points with no LLM at all*. On the harder non-empty-answer subset (227 questions where the system must actually find files), the live agent scores 83.70% vs 51.54% deterministic. The benchmark is reproducible from the published `oath-mcp` package; the corpus SHA-256 is bound into every result file.

- **Real self-correction on the recorded demo.** The 31-minute autonomous live run on the NIST CFReDS Data Leakage Case produced a real **`RALPH_WIGGUM` verdict on envelope `b7f4ac82…`** — the verifier rejected a citation mid-investigation, the agent abandoned the hypothesis and re-derived the underlying evidence fresh per protocol. The same code path is independently exercised in the 14-test spoliation suite (`tests/integration/test_spoliation.py`), which proves the verifier catches single-bit image mutation, persisted-data tampering, signature tampering, and chain-of-custody breaks end-to-end. Not a narrated demo — actual signed envelopes, actual verifier verdicts.

---

## Accomplishments we're proud of

- **The deterministic-without-an-LLM baseline alone beats GPT-4.1.** That's the result we want judges to remember. We don't NEED a frontier LLM to beat the published frontier-LLM number. Constraining the LLM to a typed-args proposal that a verifier runs makes everything else easier.

- **298 unit + integration tests, all passing**, including 14 named spoliation tests that prove the chain of custody actually holds end-to-end — covering signature tampering, persisted-data tampering (`data_blake3`), Daubert binding tampering (`model_id` + `prompt_hash` signed into the header), chain-of-custody breaks via prev-hash link, and the subtle "fabricate a record in `envelope.data` but leave raw stdout untouched" attack which an earlier external audit flagged as a critical architectural gap.

- **Real evidence end-to-end.** Every typed function has been smoke-tested against the NIST CFReDS Data Leakage Case (Win7 NTFS, 2.15 GB E01). The suspect, the deleted Outlook OST temp files containing his email, the admin-group-add events on the day before the leak, the service persistence on the leak day — all surfaced from the image bytes, all signed.

- **Canonical MCP install via PyPI.** `claude mcp add --transport stdio oath -- uvx oath-mcp` — same one-line shape as Airtable, Sentry, or any other published MCP server in the Claude Code documentation. The published `oath-mcp` package on PyPI is versioned, isolated by `uv`, and works identically on the SIFT Workstation and on a developer laptop. No clone-and-run, no bespoke install script.

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

`python` · `pydantic` · `mcp` (Model Context Protocol Python SDK) · `cryptography` · `pynacl` (ed25519) · `blake3` · `volatility3` · `plaso` · `sleuthkit` · `EZ Tools` · `Hayabusa` · `uv` (for `uvx oath-mcp` distribution) · `Vertex AI` (Gemini 3 Flash + 3.1 Pro — benchmark configuration) · `Claude Code` (Opus 4.8 — live demo configuration) · `rich` · `click` · `PyPI` (package distribution)

---

## Try it out

- **One-line install (canonical):** `claude mcp add --transport stdio oath -- uvx oath-mcp`
- **Published package:** [oath-mcp on PyPI](https://pypi.org/project/oath-mcp/) — versioned, isolated by `uv`, identical behavior on SIFT Workstation and on a developer laptop
- **Preprint:** [OSF project — OATH](https://osf.io/rk73m/) — full paper with methodology, threat model, related-work comparison against sigstore-a2a / AEGIS / Attested Tool-Server Admission / NeMo Guardrails, and per-model token economics
- **Reproduce the benchmark numbers:** see [`docs/ACCURACY.md`](docs/ACCURACY.md) §2
- **Try-It-Out walkthrough:** [`docs/TRY_IT_OUT.md`](docs/TRY_IT_OUT.md) — works on SIFT Workstation and on a developer laptop
- **Self-correction code path:** the verifier-rejection logic is exercised by `tests/integration/test_spoliation.py` (14 named tests) and was hit live during the recorded demo on the NIST CFReDS Data Leakage Case (envelope `b7f4ac82…` rejected with `RALPH_WIGGUM`, agent re-derived fresh per protocol)
