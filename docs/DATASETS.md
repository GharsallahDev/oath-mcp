# Datasets

This document inventories every dataset OATH was tested against, with source URLs, file hashes, sizes, and the reproduction steps a reviewer or examiner needs to use them. Reproducibility starts here.

All datasets are publicly downloadable and free of cost. None are bundled into this repository — they live under `corpus/` (gitignored) so the repo stays small.

## 1. DFIR-Metric Module III — NIST String Search corpus

The benchmark from [arXiv:2505.19973](https://arxiv.org/abs/2505.19973) — the only publicly-documented LLM benchmark in autonomous DFIR. OATH is scored against this corpus in [`docs/ACCURACY.md`](ACCURACY.md).

| Property | Value |
|---|---|
| Source URL | `https://raw.githubusercontent.com/DFIR-Metric/DFIR-Metric/main/DFIR-Metric-NSS.json` |
| Local path | `corpus/DFIR-Metric-NSS.json` |
| Size | 844,289 bytes (~824 KB) |
| Format | JSON — `{"questions": [{"question": "...", "answer": [...] or "<scalar>"}, ...]}` |
| Question count | 510 (486 list-answer + 24 scalar-answer) |
| License | Repository has no LICENSE file; treat as research-use-only. The questions are derived from public NIST CFTT data. |
| Citation | Kahaki et al., *DFIR-Metric: A Benchmarking Framework for Evaluating LLMs in Digital Forensics and Incident Response*. arXiv:2505.19973, 2025. |

The corpus hash committed into every signed `BenchmarkResult` JSON in `logs/benchmarks/` is the SHA-256 of the questions sorted by `question_id` and canonically serialized (see `oath.benchmark.corpus.hash_corpus`). For the version we ran against:

```
corpus_sha256: 30a53a0dbc77375ec22b58f7e7fd389a23ac21bd6443354ed4472168824f5f1c
```

## 2. NIST CFTT String Search Test Data Set v1.1 — the image the corpus questions target

NIST's reference disk image package for the String Search benchmark. The DFIR-Metric NSS questions reference inodes and filenames from this image; we computed all OATH benchmark scores by mounting it via `oath mount`.

| Property | Value |
|---|---|
| Source URL | `https://cfreds-archive.nist.gov/StringSearching/string-search-federated-testing-data-set-version-1-1-revised-september-27-2019.zip` |
| Zip size | 9,091,069 bytes (~8.7 MB compressed) |
| Zip SHA-256 | (downloadable from the NIST page next to the zip; not redistributed here) |
| Contents | Two raw `.dd` images: `ss-win-07-25-18.dd` (~1.95 GiB) + `ss-unix-07-25-18.dd` (~1.95 GiB) |
| `ss-win-07-25-18.dd` SHA-256 | `1574185b8dedc343ceb7dd306099a7bd41ceb77730b52c8d97181aeb792b6eb9` |
| `ss-unix-07-25-18.dd` SHA-256 | `42bc298d973710c9906568d2d460f980c4523d0308a73f85984fa29d58a320ee` |
| Filesystems | ss-win: GPT with FAT32 (GORDO) + exFAT + NTFS; ss-unix: GPT with HFS+ + ext4 + HFS+ |
| Last revised | 2019-09-27 (the package itself; the underlying images are dated 2018-07-25) |
| License | Public domain (U.S. government work) |
| Citation | National Institute of Standards and Technology. CFTT String Search Federated Testing Data Set v1.1. |

Reproduce:

```bash
mkdir -p corpus/nss-string-search && cd corpus/nss-string-search
curl -sSL -O \
  "https://cfreds-archive.nist.gov/StringSearching/string-search-federated-testing-data-set-version-1-1-revised-september-27-2019.zip"
unzip string-search-federated-testing-data-set-version-1-1-revised-september-27-2019.zip
cd ../..
oath mount corpus/nss-string-search/string-search-federated-testing-data-set-version-1-1-revised-september-27-2019/copy-to-test-computer/ss-win-07-25-18.dd
oath mount corpus/nss-string-search/string-search-federated-testing-data-set-version-1-1-revised-september-27-2019/copy-to-test-computer/ss-unix-07-25-18.dd
```

## 3. NIST CFReDS Data Leakage Case — modern Windows 7 evidence

NIST's most-modern publicly-available Windows forensic case, used to exercise every typed function against real evidence. Scenario: "Iaman Informant", a manager at an unnamed technology company, accepts a bribe and exfiltrates confidential data to a rival via personal cloud storage, email, USB stick, and CD-R.

| Property | Value |
|---|---|
| Source page | `https://cfreds-archive.nist.gov/data_leakage_case/data-leakage-case.html` |
| OS | Microsoft Windows 7 Ultimate SP1 |
| Acquisition date | 2015-04-23 |
| Image format | EnCase E01 (split into 4 segments) |
| PC SHA-256 (`cfreds_2015_data_leakage_pc.E01`) | `e6365e44f1004252171acb73e6779be05277cbd57d09d7febed22d2463a956a9` |
| File system | NTFS (System Reserved 100 MB + main 20 GB) |
| Compressed total | ~7.28 GB across `pc.E01..E04` |
| Suspect identity | "informant" (Windows user RID 1000, email `iaman.informant@nist.gov`) |
| License | Public domain (U.S. government work) |

Download links (right-click → Save Link As; the server doesn't send `Content-Disposition`):

```bash
mkdir -p corpus/data-leakage-case && cd corpus/data-leakage-case
for n in 01 02 03 04; do
  curl --retry 5 --retry-delay 3 --retry-all-errors -OL \
    "https://cfreds-archive.nist.gov/data_leakage_case/images/pc/cfreds_2015_data_leakage_pc.E${n}"
done
cd ../..
oath mount corpus/data-leakage-case/cfreds_2015_data_leakage_pc.E01
```

What OATH surfaces from this image (each finding bound to a signed `Notarized<T>` envelope):

| Typed function | Result on the DLC image |
|---|---|
| `parse_evtx` (Security.evtx, 1.1 MB, 1,194 records) | 274 auth records (event_ids 4624/4625/4634/4647/4672/4768/4769/4776); native `logon_type` + `auth_package` + `source_ip` from the JSON Payload |
| `parse_registry` (SAM hive) | 20 records, including the suspect: `Username: informant Id: 1000 ValidUserId: True` |
| `parse_mft` (full $MFT, 76,714 entries) | 5,347 entries with path-prefix `informant` |
| `parse_usnjrnl` ($UsnJrnl:$J, 67 MB, 50,173 FileDelete entries) | With `filter_path='informant'`: 69 deletions including `~iaman.informant@nist.gov.ost.tmp` x4 (Outlook temp file with the suspect's email encoded in the filename) |
| `run_hayabusa` (3 EVTX files, all rules, level=high+) | 4 hits: 3× `T1098` (User Added To Local Admin Grp) on 2015-03-22; 1× `T1543.003` (Suspicious Service Path) on 2015-03-25 — the actual attack chain |
| `plaso_supertimeline` (full 20 GB volume, 766 MB .plaso store) | _query result depends on filter; see logs/benchmarks/ for the canonical run_ |

## 4. NIST CFReDS Hacking Case — Windows XP legacy evidence

Older NIST case used to validate the install path and Sleuthkit pipeline. Windows XP era; uses `.Evt` (legacy event log) which our `parse_evtx` (EvtxECmd) doesn't read. Used for the initial mount/verify smoke test only.

| Property | Value |
|---|---|
| Source page | `https://cfreds-archive.nist.gov/Hacking_Case.html` |
| OS | Microsoft Windows XP |
| Image format | EnCase E01 (split into 2 segments) |
| `Hacking_Case.E01` SHA-256 | `96bebe80f00541bf28fbc2ef0b02b580082ee6ad58837e991852ae66f077ec31` |
| File system | NTFS (single volume) |
| Compressed total | ~1.04 GB across `.E01` + `.E02` |
| License | Public domain (U.S. government work) |

We used this image to validate `oath mount`, `parse_registry` (works against the XP-era SAM hive), and `oath verify` end-to-end. EVTX-era functions (`parse_evtx`, `run_hayabusa`) require the modern `.evtx` format and don't apply here — that's what the Data Leakage Case is for.

## 5. EZ Tools (Eric Zimmerman) — 2026.5.0 unified release

| Tool | Version | License |
|---|---|---|
| EvtxECmd | 2026.5.0 | MIT |
| MFTECmd | 2026.5.0 | MIT |
| AmcacheParser | 2026.5.0 | MIT |
| PECmd | 2026.5.0 | MIT |
| RECmd | 2026.5.0 | MIT |
| SBECmd, JLECmd, LECmd, SrumECmd, WxTCmd, ... | 2026.5.0 | MIT |

Fetched via the official `Get-ZimmermanTools.ps1` script. Pinned in `scripts/install-tools.sh` (macOS) and `scripts/install-on-sift.sh` (SIFT/Linux).

## 6. Other tools

| Tool | Version | Source | License |
|---|---|---|---|
| Sleuthkit | 4.15.0 | https://www.sleuthkit.org/ | IBM Public License / Common Public License |
| libewf | 20140816 | https://github.com/libyal/libewf | LGPLv3 |
| afflib | 3.7.22 | https://github.com/sshock/AFFLIBv3 | BSD |
| Hayabusa | 3.9.0 | https://github.com/Yamato-Security/hayabusa | GPLv3 |
| Volatility 3 | 2.28.0 | https://github.com/volatilityfoundation/volatility3 | VSL (Volatility Software License) |
| plaso (log2timeline) | 20260512 | https://github.com/log2timeline/plaso | Apache 2.0 |
| .NET SDK | 9.0 / 10.0 | https://dotnet.microsoft.com/ | MIT |

## 7. Reproducing the published benchmark numbers

End-to-end from a fresh git clone:

```bash
git clone https://github.com/GharsallahDev/oath-mcp && cd oath
bash scripts/install-tools.sh             # macOS Apple Silicon
# OR
bash scripts/install-on-sift.sh           # SIFT Workstation / Ubuntu x86_64
source .oath-tools/env.sh

# Fetch the DFIR-Metric corpus + the NIST CFTT image bundle
curl -sSL -o corpus/DFIR-Metric-NSS.json \
  "https://raw.githubusercontent.com/DFIR-Metric/DFIR-Metric/main/DFIR-Metric-NSS.json"
mkdir -p corpus/nss-string-search && cd corpus/nss-string-search
curl -sSL -O \
  "https://cfreds-archive.nist.gov/StringSearching/string-search-federated-testing-data-set-version-1-1-revised-september-27-2019.zip"
unzip *.zip && cd ../..

# Mount the two .dd files; oath mount streams the SHA-256 and writes EvidenceHandle JSON
oath mount corpus/nss-string-search/*/copy-to-test-computer/ss-win-07-25-18.dd
oath mount corpus/nss-string-search/*/copy-to-test-computer/ss-unix-07-25-18.dd

# Deterministic baseline — no API key, no LLM
python scripts/nss_baseline.py
# Expected: TUS@4 = 0.7843 (382/486 list + 18/24 numeric = 400/510 matched)

# Live agent — requires configured hosted-model credentials
python scripts/nss_baseline.py --live-vertex
# Expected: TUS@4 = 0.9275 (455/486 list + 18/24 numeric = 473/510 matched, gemini-3-flash-preview)
```

The published `BenchmarkResult` JSON in `logs/benchmarks/` commits the corpus SHA-256, the run start/finish timestamps, every question's candidate list, and every verifier verdict. `oath verify <envelope_id>` re-derives any single record.
