#!/usr/bin/env python
"""Render a markdown audit report from a BenchmarkResult JSON.

Used by docs/ACCURACY.md to expose:
  - the headline TUS@K + question/match counts
  - per-answer-type breakdown
  - per-image breakdown (ss-win vs ss-unix)
  - per-partition breakdown
  - a small representative sample of failures (with first-line question +
    expected vs primary-candidate diff) so a reader can see what kind of
    questions the system is missing
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path


def _classify_question(question_text: str) -> dict[str, str]:
    """Bucket a question by image + filesystem target + pattern shape."""
    t = question_text
    img = "ss-unix" if "ss-unix" in t else "ss-win"
    # Trim to the user question line (before the mmls dump)
    head = t.split("The mmls")[0].lower()
    fs = "?"
    for k in (
        "first windows data", "second windows data", "third windows data",
        "linux", "hfs", "exfat", "ntfs", "fat",
    ):
        if k in head:
            fs = k
            break
    if "phone number" in head:
        shape = "phone"
    elif "@" in head and "." in head and "extension" not in head:
        shape = "email"
    elif "extension" in head:
        shape = "count"
    else:
        shape = "other"
    return {"image": img, "filesystem": fs, "shape": shape}


def render(result_path: Path, corpus_path: Path) -> str:
    result = json.loads(result_path.read_text())
    corpus = json.loads(corpus_path.read_text())
    qs = corpus["questions"]
    qs_by_id = {f"nss-{i:04d}": q for i, q in enumerate(qs)}

    lines: list[str] = []
    lines.append(f"## Benchmark run `{result['run_id']}` — TUS@{result['k']} = **{result['tus_at_k']:.4f}**")
    lines.append("")
    lines.append(f"- corpus_sha256: `{result['corpus_sha256']}`")
    lines.append(f"- module: {result['module']}")
    lines.append(f"- questions: {result['total_questions']}")
    lines.append(f"- matched: {result['matched_count']}")
    lines.append(f"- started: {result['started_at']}")
    lines.append(f"- finished: {result['finished_at']}")
    lines.append("")

    # Per-answer-type breakdown
    by_type: Counter = Counter()
    matched_by_type: Counter = Counter()
    for a in result["attempts"]:
        by_type[a["answer_type"]] += 1
        if a["matched"]:
            matched_by_type[a["answer_type"]] += 1
    lines.append("### Score by answer type")
    lines.append("")
    lines.append("| answer_type | matched | total | pct |")
    lines.append("|---|---|---|---|")
    for at, total in by_type.most_common():
        m = matched_by_type[at]
        lines.append(f"| `{at}` | {m} | {total} | {m/total:.2%} |")
    lines.append("")

    # Per-image breakdown
    by_image: Counter = Counter()
    matched_by_image: Counter = Counter()
    for a in result["attempts"]:
        q = qs_by_id[a["question_id"]]
        img = _classify_question(q["question"])["image"]
        by_image[img] += 1
        if a["matched"]:
            matched_by_image[img] += 1
    lines.append("### Score by image")
    lines.append("")
    lines.append("| image | matched | total | pct |")
    lines.append("|---|---|---|---|")
    for img, total in by_image.most_common():
        m = matched_by_image[img]
        lines.append(f"| `{img}` | {m} | {total} | {m/total:.2%} |")
    lines.append("")

    # Per-filesystem breakdown
    by_fs: Counter = Counter()
    matched_by_fs: Counter = Counter()
    for a in result["attempts"]:
        q = qs_by_id[a["question_id"]]
        fs = _classify_question(q["question"])["filesystem"]
        by_fs[fs] += 1
        if a["matched"]:
            matched_by_fs[fs] += 1
    lines.append("### Score by filesystem target")
    lines.append("")
    lines.append("| filesystem | matched | total | pct |")
    lines.append("|---|---|---|---|")
    for fs, total in sorted(by_fs.items(), key=lambda kv: (-kv[1], kv[0])):
        m = matched_by_fs[fs]
        lines.append(f"| `{fs}` | {m} | {total} | {m/total:.2%} |")
    lines.append("")

    # Per-pattern-shape breakdown
    by_shape: Counter = Counter()
    matched_by_shape: Counter = Counter()
    for a in result["attempts"]:
        q = qs_by_id[a["question_id"]]
        shape = _classify_question(q["question"])["shape"]
        by_shape[shape] += 1
        if a["matched"]:
            matched_by_shape[shape] += 1
    lines.append("### Score by question shape")
    lines.append("")
    lines.append("| shape | matched | total | pct |")
    lines.append("|---|---|---|---|")
    for shape, total in by_shape.most_common():
        m = matched_by_shape[shape]
        lines.append(f"| `{shape}` | {m} | {total} | {m/total:.2%} |")
    lines.append("")

    # Failure samples
    lines.append("### Representative failures (first 6)")
    lines.append("")
    shown = 0
    for a in result["attempts"]:
        if a["matched"]:
            continue
        if shown >= 6:
            break
        q = qs_by_id[a["question_id"]]
        first = q["question"].strip().split("\n")[0]
        expected = a["expected_answer"]
        primary = a["candidates"][0] if a["candidates"] else "(no candidate)"
        lines.append(f"**{a['question_id']}** ({a['answer_type']})")
        lines.append("")
        lines.append(f"- question: {first[:200]}")
        lines.append(f"- expected: `{expected[:200]}`")
        lines.append(f"- primary candidate: `{primary[:200]}`")
        lines.append("")
        shown += 1

    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Render NSS BenchmarkResult as markdown.")
    parser.add_argument(
        "--result",
        type=Path,
        default=Path("logs/benchmarks/nss-baseline_III_tus4.json"),
        help="Path to BenchmarkResult JSON.",
    )
    parser.add_argument(
        "--corpus",
        type=Path,
        default=Path("corpus/DFIR-Metric-NSS.json"),
        help="Path to the DFIR-Metric NSS corpus file (for question prose).",
    )
    args = parser.parse_args()

    if not args.result.exists():
        print(f"missing result: {args.result}", file=sys.stderr)
        return 2
    if not args.corpus.exists():
        print(f"missing corpus: {args.corpus}", file=sys.stderr)
        return 2

    print(render(args.result, args.corpus))
    return 0


if __name__ == "__main__":
    sys.exit(main())
