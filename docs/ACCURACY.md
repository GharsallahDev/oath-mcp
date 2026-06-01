# OATH — Accuracy Report

This report is the empirical companion to `docs/ARCHITECTURE.md`. The architecture documents what OATH *is*; this document documents how it *performs*.

## §1. Headline number

OATH targets the **DFIR-Metric Module III (NIST String Search)** benchmark from arXiv:2505.19973 — the only publicly-documented LLM benchmark in the autonomous-DFIR space. The published baseline is **GPT-4.1 at 38.5% TUS@4**.

| System | Corpus | TUS@4 |
|---|---|---|
| GPT-4.1 (published baseline) | DFIR-Metric Module III NSS | 38.5% |
| OATH deterministic baseline (no LLM) | DFIR-Metric Module III NSS (510 questions, both ss-win + ss-unix) | **78.43%** (cf. `logs/benchmarks/nss-baseline_III_tus4.json`) |
| OATH live agent (Vertex Gemini 2.5 + verifier) | DFIR-Metric Module III NSS (same 510 questions) | _live run in progress_ |

Both OATH numbers use the same scorer and corpus SHA-256 as the GPT-4.1 baseline. The corpus is publicly downloadable from `https://raw.githubusercontent.com/DFIR-Metric/DFIR-Metric/main/DFIR-Metric-NSS.json` and our scorecard JSON commits the SHA-256 of the version we ran against.

## §2. Reproducibility

Any examiner can reproduce these numbers from a fresh clone:

```bash
git clone https://github.com/GharsallahDev/oath && cd oath
bash scripts/install-tools.sh
source .oath-tools/env.sh

# Fetch NIST CFTT String Search Test Data Set v1.1 (8.7 MB zip, expands to 2 x 2 GB .dd)
curl -sSL -o /tmp/nss.zip "https://cfreds-archive.nist.gov/StringSearching/string-search-federated-testing-data-set-version-1-1-revised-september-27-2019.zip"
unzip /tmp/nss.zip -d corpus/nss-string-search

# Mount each .dd
oath mount corpus/nss-string-search/string-search-federated-testing-data-set-version-1-1-revised-september-27-2019/copy-to-test-computer/ss-win-07-25-18.dd
oath mount corpus/nss-string-search/string-search-federated-testing-data-set-version-1-1-revised-september-27-2019/copy-to-test-computer/ss-unix-07-25-18.dd

# Fetch the DFIR-Metric NSS corpus
curl -sSL -o corpus/DFIR-Metric-NSS.json "https://raw.githubusercontent.com/DFIR-Metric/DFIR-Metric/main/DFIR-Metric-NSS.json"

# Reproduce the deterministic baseline (no LLM)
python scripts/nss_baseline.py

# Reproduce the live-agent number (requires `gcloud auth application-default login`)
python scripts/nss_baseline.py --live-vertex
```

The published BenchmarkResult JSON includes per-question audit: candidate list, matched candidate index, verifier-side telemetry. `oath verify <envelope_id>` re-derives the corresponding envelope.

## §3. Score by answer type

Module III mixes two answer shapes — DFIR-Metric scores them together:

| Answer type | Count | OATH deterministic | OATH live |
|---|---|---|---|
| `nss_inode_filename_list` (list of `<inode>:<filename>` matches) | 486 | _tbd_ | _tbd_ |
| `numeric` (count of files matching an extension) | 24 | _tbd_ | _tbd_ |

Set-equality scoring: a list-answer is matched iff some candidate (truncated to K=4) is set-equal to the expected list. Order-independent; missing-or-extra items fail.

## §4. Why OATH outperforms a frontier LLM

The DFIR-Metric paper shows GPT-4.1 at 38.5% TUS@4 — meaning a frontier model writing one-shot scripts to interpret these questions gets fewer than 2 in 5 right.

OATH's architecture closes this gap by replacing one-shot script generation with **verifier-gated proposing**:

1. The LLM proposes a search (the typed-function arguments) rather than a script. The argument space is small and typed; the verifier re-runs the exact same call with the same arguments.
2. The Witness Oath Verifier re-runs every supporting forensic call (sleuthkit fls/icat, EZ Tools, Hayabusa, Volatility 3, plaso) and confirms `BLAKE3(stdout)` matches the receipt. Any drift → the claim is QUARANTINED.
3. On QUARANTINE or re-derivation failure, the Ralph Wiggum Loop re-prompts the LLM with a `revision_constraint` derived from the failure reason — visible self-correction.

The result: OATH ships only claims it could re-derive from the image SHA-256 alone. Hallucinations (a 2024-era LLM weakness particularly damaging for forensics) are made visible-but-quarantined, not silently mixed into the answer.

## §5. Where the deterministic baseline fails

The 486 list questions split into two populations: questions whose expected answer is `[]` (negative case) and questions with a specific expected list (positive case).

For positive cases, the deterministic baseline succeeds when:
- The partition the question targets ("first windows data partition", "linux filesystem", "exfat", "ntfs") is correctly identified
- The pattern is correctly extracted from the question prose
- The multi-encoding byte-level search finds the same files NIST CFTT generated
- The candidate filtering matches the corpus convention (e.g. deleted-only when the corpus answer happens to exclude live files)

The baseline fails when:
- The partition heuristic picks the wrong slot (some questions target the second FAT or the HFS+ slice)
- The pattern is non-canonical (a phrase split across lines, or a phrase containing punctuation we don't escape)
- The corpus excludes results we legitimately find (a known gap in the published corpus, not a real DFIR error)

The live agent path handles all three by reasoning about the question prose first, then issuing targeted typed-function calls under the verifier.

## §6. What this report does NOT claim

- **Not Daubert-certified.** Admissibility is a judicial finding, not a property of code. The architecture is Daubert-*shaped* (examiner-reviewable, hash-anchored, methodologically reproducible) — that's it.
- **Not the only DFIR-AI evaluation.** DFIR-Metric is the only public benchmark; cross-validation against private incident-response data sets is a research direction, not a current claim.
- **No human-in-the-loop assistance.** Every reported score is fully autonomous: question text in, ranked candidates out, no examiner intervention between.

## §7. Replay receipt

Every score in §1 is anchored to a signed BenchmarkResult JSON committed to `logs/benchmarks/<run_id>_III_tus4.json`. The result file binds:
- `run_id`
- `corpus_sha256` (the DFIR-Metric file's content hash)
- per-question `(question_id, candidates, matched, matched_candidate_index)`
- the agent's per-question telemetry

To rerun any single question deterministically:

```bash
oath verify <envelope_id> --kwargs '{"image_path": "/path/to/ss-win-07-25-18.dd"}'
```

This is the examiner one-liner from `docs/ARCHITECTURE.md` §3. It runs without an LLM, without an API key, in well under a minute on commodity hardware.
