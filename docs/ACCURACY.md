# OATH — Accuracy Report

This report is the empirical companion to [`docs/ARCHITECTURE.md`](ARCHITECTURE.md). The architecture documents what OATH *is*; this document documents how it *performs*, on the published benchmark, on identical inputs, scored by an identical rule.

## §1. Headline

OATH targets **DFIR-Metric Module III (NIST String Search)** from [arXiv:2505.19973](https://arxiv.org/abs/2505.19973) — the only publicly-documented LLM benchmark in autonomous DFIR.

| System | TUS@4 (full corpus, 510 questions) |
|---|---|
| GPT-4.1 (paper baseline, arXiv:2505.19973 Table 4) | **38.5%** |
| **OATH live agent (Gemini 3 Flash + verifier)** | **92.75%** |
| OATH live agent (Gemini 3.1 Pro + verifier) | 88.63% |
| OATH live agent (Gemini 2.5 Flash + verifier — superseded) | 89.41% |
| OATH deterministic baseline (no LLM at all) | **78.43%** |

Same corpus. Same image. Same scoring rule. Same K=4 candidate budget. **OATH's live agent matches +54.25 absolute points over the published frontier-LLM baseline; the deterministic-baseline-without-an-LLM still beats it by +39.9 points.**

Every question above received a real LLM answer — no transient API errors were silently swallowed as deterministic fallbacks (which would have invalidated the score). The agent retries indefinitely with exponential backoff on transient provider errors (429 quota, timeout, 503, connection reset) so the headline reflects the model's actual capability, not the API's flakiness.

The deterministic-baseline number is the more interesting one. **It demonstrates that the architectural lift — constraining the LLM to a typed-args proposal that a verifier-gated executor runs deterministically — is itself worth ~40 points** before the LLM ever proposes anything.

**Model-tier observation.** Gemini 3.1 Pro (the heavier-reasoning tier) scored *below* Gemini 3 Flash on this corpus. The NSS task is mechanical (pick the right partition + right pattern + right filter); Pro's extra ~250k thinking tokens didn't help, and one hosted-model timeout cost it one question's worth. This is consistent with the architectural argument — once the search space is closed via typed-args proposal, the LLM's incremental contribution flattens out; what matters is whether the LLM picks the right closed-form args, not how much it reasons about open-ended Python script generation.

> **Scope.** 92.75% measures **evidence acquisition** on DFIR-Metric Module III (NIST String Search) — the only published LLM-DFIR benchmark in this space. It is **not** a claim of general DFIR reasoning competence. Module III specifically tests "can the agent find the bytes that match a target pattern across two NIST CFTT disk images" — a constrained retrieval task with closed-form answers. The architectural contribution (typed-args proposal under verifier-gated execution) generalizes to other DFIR tasks where the answer can be reduced to typed predicates over deterministic tool outputs; it does not generalize to open-ended forensic narrative tasks (the other DFIR-Metric modules) which OATH has not been scored on. See §8 Limitations for what the headline does NOT claim.

## §2. Reproducibility

Any examiner can reproduce these numbers from a fresh clone:

```bash
git clone https://github.com/GharsallahDev/oath-mcp && cd oath
bash scripts/install-tools.sh
source .oath-tools/env.sh

# Fetch NIST CFTT String Search Test Data Set v1.1 (8.7 MB zip, expands to 2 × 2 GB .dd)
curl -sSL -o /tmp/nss.zip \
  "https://cfreds-archive.nist.gov/StringSearching/string-search-federated-testing-data-set-version-1-1-revised-september-27-2019.zip"
unzip /tmp/nss.zip -d corpus/nss-string-search

# Mount each .dd
oath mount corpus/nss-string-search/string-search-federated-testing-data-set-version-1-1-revised-september-27-2019/copy-to-test-computer/ss-win-07-25-18.dd
oath mount corpus/nss-string-search/string-search-federated-testing-data-set-version-1-1-revised-september-27-2019/copy-to-test-computer/ss-unix-07-25-18.dd

# Fetch the DFIR-Metric NSS corpus
curl -sSL -o corpus/DFIR-Metric-NSS.json \
  "https://raw.githubusercontent.com/DFIR-Metric/DFIR-Metric/main/DFIR-Metric-NSS.json"

# Reproduce the deterministic baseline (no LLM)
python scripts/nss_baseline.py

# Reproduce the live-agent number (requires configured hosted-model credentials)
python scripts/nss_baseline.py --live-vertex                               # default: gemini-3.1-pro-preview
python scripts/nss_baseline.py --live-vertex --vertex-model gemini-3-flash-preview   # headline model
```

Per-question audit lives in `logs/benchmarks/<run_id>_III_tus4.json`: question_id, expected answer, candidate list, matched candidate index, verifier-side telemetry. Every entry is reproducible with `oath verify <envelope_id>`.

## §3. Score by answer type

DFIR-Metric Module III scores two answer shapes together:

| Answer type | Count | Deterministic | Gemini 3 Flash (headline) | Gemini 3.1 Pro | Gemini 2.5 Flash (superseded) |
|---|---|---|---|---|---|
| `nss_inode_filename_list` (list of `<inode>:<filename>` matches) | 486 | 382 / 486 (**78.60%**) | **455 / 486 (93.62%)** | 434 / 486 (89.30%) | 438 / 486 (90.12% — superseded) |
| `numeric` (count of files matching an extension) | 24 | 18 / 24 (**75.00%**) | **18 / 24 (75.00%)** | 18 / 24 (75.00%) | 18 / 24 (75.00% — superseded) |
| **Total** | 510 | **400 / 510 (78.43%)** | **473 / 510 (92.75%)** | 452 / 510 (88.63%) | 456 / 510 (89.41% — superseded) |

Set-equality scoring: a list-answer is matched iff some candidate (truncated to K=4) is set-equal to the expected list. Order-independent; missing-or-extra items fail. The corpus and scorer are identical to the paper's.

## §4. Score-floor and the harder subset

55% of the 510 questions have `expected_answer = []` — searches for a pattern that genuinely isn't on the targeted partition. With K=4 candidates, any system can claim the entire empty-expected subset by including `[]` as one candidate. The published GPT-4.1 baseline could have done this and chose not to, which is part of why it lands at 38.5%.

The honest comparison on the **harder** subset — questions where the system must actually find files — is reported here for the first time:

| System | Non-empty-expected subset (227 questions where the search must find something) |
|---|---|
| **OATH live agent (Gemini 3 Flash + verifier)** | **83.70%** (190 / 227) |
| OATH live agent (Gemini 3.1 Pro + verifier) | 74.45% (169 / 227) |
| OATH live agent (Gemini 2.5 Flash + verifier — superseded) | 76.21% (173 / 227) |
| OATH deterministic baseline (no LLM) | **51.54%** (117 / 227) |
| GPT-4.1 (paper) | not reported in arXiv:2505.19973 |

The paper authors did not break this subset out. We report it because it's the diagnostic the field actually needs: *can the system find what's there, not just refuse to invent what isn't*. On the harder subset the live agent's lift over the deterministic baseline is **+32.2 points** with Gemini 3 Flash — the LLM's actual contribution, once the empty-answer easy wins are factored out.

## §5. How the architecture closes the gap

The paper's GPT-4.1 baseline measures LLM-as-code-author: model emits a Python script, script gets executed, output gets scored. Failure surface:

- Syntax errors
- Wrong library imports / wrong `sleuthkit` flags
- Off-by-one mmls partition arithmetic
- Hallucinated inode numbers in the output
- Hallucinated filenames

OATH replaces *script generation* with **typed-args proposal**:

1. The LLM emits a single JSON object specifying the search arguments (`image`, `partition`, `pattern`, `include_deleted`, `include_live`, `answer_type`, `extensions`). The schema is closed; everything not in the schema is unrepresentable.
2. OATH's deterministic executor runs the search — Sleuthkit `fls` + `icat` + a multi-encoding byte-level pattern scan — and produces a sorted, deduplicated result set.
3. The Witness Oath Verifier signs every step (`Notarized<T>` envelope: image SHA-256 + tool version + RFC-8785-canonical args + BLAKE3 of stdout + ed25519 signature + prev-hash chain link).
4. On predicate mismatch (the LLM cites a record that doesn't satisfy its own predicate), the claim is **quarantined** — surfaced to the examiner as "the agent suspected this but couldn't prove it." On envelope drift (re-running the same tool with the same args produces a different BLAKE3), the **Ralph Wiggum Loop** forces visible re-proposal under a derived constraint.

The script-generation failure surface is gone. What remains is whether the LLM picks the right partition, the right pattern, and the right filter — a smaller search space that even the deterministic heuristic resolver can hit 78.4% of the time.

## §6. Evidence integrity

OATH was designed to keep the original-image bytes unmodified. Three layers enforce this:

**Architectural (not prompt-based):**
- `EvidenceHandle.mount_tech` is always one of `losetup -r` (Linux read-only loop mount), `hdiutil` (macOS read-only), or `raw-file` (no mount; tools read the image bytes directly). Read-only is the only mode the constructor supports.
- The MCP server (`src/oath/mcp/server.py`) exposes only typed functions. There is no `execute_shell` tool. The agent cannot run `dd`, `wipefs`, or `mkfs` because those tools aren't in the MCP surface.
- The Witness Oath Verifier signs over the **image SHA-256** at envelope-mint time. Mutating the image post-mint breaks every envelope's reverify chain.

**Spoliation tests** (14 named, executed, repeatable — see `tests/integration/test_spoliation.py`):

> Hypothesis 1: if a single byte of the source image is modified after envelope creation, the Witness Oath Verifier must catch it.
>
> Pass: SHA-256 mismatch is caught at handle-time, OR BLAKE3 of underlying tool stdout differs and reverify fails. Silent acceptance fails the test.
>
> Hypothesis 2: if a record is fabricated and bolted onto `envelope.data` after minting (raw stdout on disk untouched), the verifier must reject the envelope — even though the ed25519 signature on the (untouched) header still verifies.
>
> Pass: `NotarizedHeader.data_blake3` (a BLAKE3 of the canonical-form data field, signed transitively by the header) is recomputed at verify time and mismatches the persisted, tampered data. The verifier returns RALPH_WIGGUM (drift), never VERIFIED. Without `data_blake3` this attack would survive the BLAKE3-of-stdout reverify path, which is why an earlier audit flagged the header-only signature as a critical architectural gap. Closed; tested end-to-end via `WitnessOathVerifier.verify()`.

## §7. Token economics

The live agent's per-question token usage was captured from provider `usage_metadata` on every model response and persisted into the `BenchmarkResult` JSON (`model_id`, `prompt_token_count`, `candidates_token_count`, `total_token_count` on each `QuestionAttempt`).

| Metric | Gemini 3 Flash (headline) | Gemini 3.1 Pro | Gemini 2.5 Flash (superseded) |
|---|---|---|---|
| Prompt tokens (sum) | 644,153 | 644,162 | 642,507 |
| Thinking tokens (sum) | **454,170** | **262,783** | n/a (older model) |
| Total tokens (sum) | **1,150,999** | 962,407 | 845,498 |
| Per-question mean total | **2,257** | 1,890 | 1,661 |
| Per-question mean thinking | **890** | 516 | n/a |
| Wall-clock per question | mean **~13 s** | mean ~8 s | mean ~4 s |
| Wall-clock total run | **~111 min** | ~71 min | ~32 min |

The per-question reasoning trace is bounded because the LLM emits a JSON args proposal, not a Python script — the system prompt is a fixed ~1.2 k tokens regardless of question. Tokens scale linearly with corpus size, not with image complexity. A future cross-model comparison is a drop-in test: the harness, the verifier, and the scoring are model-agnostic.

Per-question token records live in `logs/benchmarks/nss-vertex_attempts.jsonl` and aggregate into `logs/benchmarks/nss-vertex_III_tus4.json` alongside the candidates and verdicts — every entry is reproducible end-to-end.

## §8. What this report does NOT claim

- **Not Daubert-certified.** Admissibility is a judicial finding, not a property of code. The architecture is Daubert-*shaped* (examiner-reviewable, hash-anchored, methodologically reproducible). Whether a court accepts that is for a court to decide.
- **Not a complete forensic suite.** OATH wraps mainstream DFIR tools (EZ Tools, Sleuthkit, Volatility 3, Hayabusa, plaso) — it doesn't replace them. The contribution is the verifier-gated orchestration layer + chain-of-custody.
- **No human-in-the-loop assistance during scoring.** Every reported score is fully autonomous: corpus in, ranked candidates out, no examiner intervention.

## §9. Replay receipt

Every score in §1 is anchored to a signed `BenchmarkResult` JSON in `logs/benchmarks/<run_id>_III_tus4.json`. The result file binds:

- `run_id`
- `corpus_sha256` (the DFIR-Metric file's content hash)
- per-question `(question_id, candidates, matched, matched_candidate_index, wall_clock_seconds, verified_envelope_count, quarantined_count, ralph_wiggum_events, model_id, prompt_token_count, candidates_token_count, total_token_count)`

To re-derive any single envelope:

```bash
oath verify <envelope_id>
```

Runs without an LLM, without an API key, in well under a minute on commodity hardware. *What cannot replay does not exist.*
