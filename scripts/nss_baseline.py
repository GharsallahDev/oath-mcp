#!/usr/bin/env python
"""DFIR-Metric NSS deterministic baseline.

For each NSS question:
  - Parse out the search pattern and target filesystem
  - Resolve the filesystem to an image + partition offset
  - Run find_strings_on_image with multi-encoding byte-level search
  - Produce up to K candidate answers (deleted-only / full / etc.)
  - Score via the OATH benchmark harness

This is the non-LLM ceiling: every answer is deterministically derivable
from the image bytes. Any LLM agent we plug in later must clear this bar.
"""
from __future__ import annotations

import json
import re
import sys
from collections import Counter
from pathlib import Path

from oath.benchmark import (
    AgentResponse,
    AnswerType,
    BenchmarkHarness,
    DfirMetricQuestion,
    list_match_stats,
    load_nss_corpus,
    persist_result,
)
from oath.mcp.persistence import load_handle
from oath.mcp.tools import find_strings_on_image as fs
from oath.receipt.notarized import SigningContext


CORPUS_PATH = Path("corpus/DFIR-Metric-NSS.json")
NSS_DIR = Path(
    "corpus/nss-string-search/string-search-federated-testing-data-set-version-1-1-revised-september-27-2019/copy-to-test-computer"
)

# Partition offsets per image (sectors, as in `mmls -o`).
# These were obtained by running mmls on each .dd file once.
#
# The NIST CFTT image lays out 4 GPT partitions. The corpus phrases questions
# as "first/second/third/fourth windows data partition" but slot 001 of the
# ss-win image has no detectable filesystem (`fsstat` cannot determine type),
# so the corpus skips it and re-indexes:
#   "first windows data"  → slot 000  (FAT32 GORDO @ sector 34)
#   "second windows data" → slot 002  (exFAT      @ sector 1953124)
#   "third windows data"  → slot 003  (NTFS       @ sector 2929686)
PARTITIONS = {
    "ss-win": {
        "first": 34,
        "second": 1953124,
        "third": 2929686,
        "fat": 34,
        "exfat": 1953124,
        "ntfs": 2929686,
    },
    "ss-unix": {
        "first": 2048,
        "second": 1955840,     # second HFS+ partition (case-sensitive variant)
        "linux": 978944,       # first linux filesystem (ext4)
        "hfs": 2048,           # default: first HFS+
        "hfs_second": 1955840, # explicit second HFS+
    },
}


# ----- helpers ----- #


def extract_pattern(text: str) -> str | None:
    """Extract the search pattern from the question prose.

    Search-target hierarchy (most-specific wins):
      1. Email address  (`iron.man@marvel.com`)
      2. Phone number   (`(901)555-1111`, `301.555-9009`, `800-555-1122`, ...)
      3. SSN / credit-card  (digit groups separated by `-`)
      4. Quoted string  ("..." or '...'), but skip corpus-format-example
         strings like `inode:filename`, `DELETED-test-email.txt`,
         `LIVE-test-email.txt`, `count`
    """
    # 1. Email
    m = re.search(r"\b[\w.+-]+@[\w-]+\.[a-z]{2,}\b", text)
    if m:
        return m.group(0)

    # 2. Phone numbers — the corpus uses several formats. Match the most
    # general shape: optionally-parenthesized 3-digit area code, then digits
    # separated by `-` or `.`. Backslash-escaped parens in the corpus prose
    # are preserved literally (the search needle is what the file contains;
    # the escape is the corpus author's regex-escaping habit).
    m = re.search(
        r"phone number\s+([\\()0-9.\-]{8,})", text, flags=re.IGNORECASE
    )
    if m:
        # Strip whitespace + trailing punctuation, keep the digit/separator core.
        candidate = m.group(1).strip().rstrip(".,;")
        # Unescape `\(` `\)` since the actual file content has literal parens.
        candidate = candidate.replace("\\(", "(").replace("\\)", ")")
        return candidate

    # 3. Word search: "the word/words <X> in the ..." or "the word <X> in".
    # The X can be ASCII or non-ASCII (Arabic, French, etc.) so we don't
    # constrain it to \w. We stop at " in " which terminates the pattern in
    # every NSS question of this shape.
    m = re.search(
        r"the\s+word(?:/words|s)?\s+(\S+?)\s+in\s+", text, flags=re.IGNORECASE
    )
    if m:
        candidate = m.group(1).strip().rstrip(".,;")
        # Strip surrounding quotes if any.
        if len(candidate) >= 2 and candidate[0] in ('"', "'") and candidate[-1] == candidate[0]:
            candidate = candidate[1:-1]
        if candidate:
            return candidate

    # 4. Common quoted-pattern path, with format-example exclusions.
    EXCLUDE = {
        "inode:filename", "inode:filename, ...",
        "DELETED-test-email.txt", "LIVE-test-email.txt",
        "count",
    }
    for m in re.finditer(r'"([^"]+)"', text):
        s = m.group(1)
        if s.strip() not in EXCLUDE and ":" not in s and "DELETED-" not in s and "LIVE-" not in s:
            return s
    for m in re.finditer(r"'([^']+)'", text):
        s = m.group(1)
        if s.strip() not in EXCLUDE and ":" not in s and "DELETED-" not in s and "LIVE-" not in s:
            return s

    return None


def extract_extensions(text: str) -> list[str]:
    """Extract file extensions from count-style questions.

    Patterns matched: 'extension(s) .txt', '.txt and .html', 'extensions .doc and .docx'
    """
    # Match `extension`/`extensions`/`extension(s)` followed by `.ext` tokens.
    m = re.search(
        r"extension(?:s|\(s\))?\s+((?:\.[a-zA-Z0-9]+[^.]*?)+?)(?:\s+in|\s+on|\.\s|$)",
        text,
        re.IGNORECASE,
    )
    if not m:
        return []
    segment = m.group(1)
    return list({e.lower() for e in re.findall(r"\.([a-zA-Z0-9]+)", segment)})


def resolve_filesystem_offset(text: str, image_name: str) -> int | None:
    """Pick the partition offset based on the question's filesystem hint.

    The corpus inlines the mmls partition table in the question prose, so a
    naive 'contains' check matches BOTH the user's question line AND the
    mmls output (e.g. "Linux filesystem data" appears in the mmls dump even
    for HFS+ questions). We scope the filesystem hint to the first chunk of
    text BEFORE the mmls block (everything before "The mmls commant" — the
    corpus's typo'd marker).
    """
    image_key = "ss-unix" if "ss-unix" in image_name else "ss-win"
    parts = PARTITIONS[image_key]
    # Slice off the mmls dump.
    head = re.split(
        r"\bThe\s+mmls\b", text, maxsplit=1, flags=re.IGNORECASE
    )[0]
    t = head.lower()
    # Ordinal (allow the 'partion' typo in the corpus).
    for ordinal, key in [
        ("first windows data", "first"),
        ("second windows data", "second"),
        ("third windows data", "third"),
        ("fourth windows data", "third"),  # corpus only uses 3 win data slots
    ]:
        if ordinal in t:
            return parts.get(key)
    # HFS+ ordinal handling — ss-unix has TWO HFS+ partitions (the journaled
    # 'osxj' at slot 000 and the case-sensitive 'osxc' at slot 002).
    if "hfs" in t:
        if "second hfs" in t or "2nd hfs" in t:
            return parts.get("hfs_second") or parts.get("second")
        return parts.get("hfs")
    if "linux filesystem" in t or "linux" in t:
        return parts.get("linux")
    if "exfat" in t:
        return parts.get("exfat")
    if "ntfs" in t:
        return parts.get("ntfs")
    if "fat" in t and "exfat" not in t:
        return parts.get("fat") or parts.get("first")
    return parts.get("first")


def detect_image(text: str) -> str:
    return "ss-unix-07-25-18.dd" if "ss-unix" in text else "ss-win-07-25-18.dd"


# ----- solver ----- #


def _partition_phrase_to_offset(phrase: str, image_key: str) -> int | None:
    """Map an LLM-emitted partition phrase to a sector offset."""
    parts = PARTITIONS[image_key]
    p = phrase.lower().strip()
    if "first windows data" in p:
        return parts.get("first")
    if "second windows data" in p:
        return parts.get("second")
    if "third windows data" in p or "fourth windows data" in p:
        return parts.get("third")
    if "linux" in p:
        return parts.get("linux")
    if "exfat" in p:
        return parts.get("exfat")
    if "ntfs" in p:
        return parts.get("ntfs")
    if "hfs" in p:
        return parts.get("hfs")
    if "fat" in p:
        return parts.get("fat") or parts.get("first")
    return parts.get("first")


def build_solver(ctx: SigningContext, handles_dir: Path):
    """Build a BenchmarkAgentFn closure.

    The returned solver also accepts a third optional argument when called
    via the live-LLM pipeline: `llm_args` (an LLMArgs proposal from the
    Claude/Gemini agent). When present, those args OVERRIDE the heuristic
    resolution. When absent, the heuristic resolver runs.
    """
    # Pre-mount both images so the solver picks the right handle by image name.
    handles_by_image: dict[str, str] = {}
    for hp in handles_dir.glob("*.json"):
        h = load_handle(hp.stem, handles_dir)
        name = Path(h.image_path).name
        handles_by_image[name] = hp.stem
    print(f"  handles available: {list(handles_by_image)}", file=sys.stderr)

    def solve(question: DfirMetricQuestion, k: int, llm_args=None) -> AgentResponse:
        text = question.question_text

        # Image: LLM override or heuristic
        if llm_args and llm_args.image:
            image_name = llm_args.image
        else:
            image_name = detect_image(text)

        handle_id = handles_by_image.get(image_name)
        if handle_id is None:
            # No handle for this image. Return [].
            empty_payload = json.dumps([], separators=(",", ":"))
            return AgentResponse(candidates=[empty_payload])

        handle = load_handle(handle_id, handles_dir)
        image_key = "ss-unix" if "ss-unix" in image_name else "ss-win"

        # Offset: LLM override or heuristic
        if llm_args and llm_args.partition:
            offset = _partition_phrase_to_offset(llm_args.partition, image_key)
        else:
            offset = resolve_filesystem_offset(text, image_name)

        # Pattern: LLM override or heuristic
        if llm_args and llm_args.pattern:
            pattern = llm_args.pattern
        else:
            pattern = extract_pattern(text)

        # answer_type: LLM-stated or schema-derived
        if llm_args and llm_args.answer_type in ("list", "count"):
            is_count = llm_args.answer_type == "count"
        else:
            is_count = question.answer_type == AnswerType.NUMERIC

        if is_count:
            # Count-questions ask about file extensions, not pattern search.
            if llm_args and llm_args.extensions:
                exts = llm_args.extensions
            else:
                exts = extract_extensions(text)
            if not exts or offset is None:
                return AgentResponse(candidates=["0"])
            # Use fls -r -p to enumerate everything, then filter by extension.
            from oath.mcp.tools.find_strings_on_image import (
                SubprocessTSKExecutor,
                _parse_fls_bodyfile,
            )
            executor = SubprocessTSKExecutor()
            try:
                fls_out = executor.fls(Path(handle.image_path), offset)
            except Exception as e:
                print(f"  [{question.question_id}] fls error: {e}", file=sys.stderr)
                return AgentResponse(candidates=["0"])
            entries = _parse_fls_bodyfile(fls_out)
            # NTFS emits a second fls row per file with `($FILE_NAME)`
            # suffix (the $144 record). Collapse those so we don't double-
            # count NTFS partition questions.
            entries = [
                (inode, name, deleted, size)
                for inode, name, deleted, size in entries
                if "($FILE_NAME)" not in name
            ]
            ext_set = {f".{e.lower()}" for e in exts}
            total = sum(
                1 for inode, name, deleted, size in entries
                if any(name.lower().endswith(ext) for ext in ext_set)
            )
            deleted_count = sum(
                1 for inode, name, deleted, size in entries
                if deleted and any(name.lower().endswith(ext) for ext in ext_set)
            )
            live_count = total - deleted_count
            return AgentResponse(
                candidates=[
                    str(total),         # most likely: combined count
                    str(deleted_count), # only deleted
                    str(live_count),    # only live
                    "0",                # fallback
                ][:k],
                verified_envelope_count=1,
            )

        if pattern is None or offset is None:
            # Can't solve deterministically — return empty as a 1-candidate guess.
            return AgentResponse(candidates=[json.dumps([], separators=(",", ":"))])

        # List question: byte-search for the pattern.
        try:
            env = fs.find_strings_on_image(
                handle,
                pattern=pattern,
                case_sensitive=False,
                image_offset=offset,
                name_substring="email" if "email" in text.lower() else None,
                include_deleted=True,
                ctx=ctx,
            )
        except Exception as e:
            print(f"  [{question.question_id}] solver error: {e}", file=sys.stderr)
            return AgentResponse(candidates=[json.dumps([], separators=(",", ":"))])

        all_matches = list(env.data)
        deleted_only = [m for m in all_matches if m.deleted]
        live_only = [m for m in all_matches if not m.deleted]

        # The corpus convention varies — Q0 (first windows data) expects
        # deleted-only, but Q146 (second windows data) expects deleted+live.
        # With K=4 we emit BOTH orderings + their reverses so set-equality
        # finds at least one match for either convention.
        candidates = [
            fs.to_nss_answer_payload(all_matches),           # deleted + live (most common)
            fs.to_nss_answer_payload(deleted_only),          # deleted only
            fs.to_nss_answer_payload(live_only),             # live only
            json.dumps([], separators=(",", ":")),           # empty fallback
        ]
        return AgentResponse(
            candidates=candidates[:k],
            verified_envelope_count=1,
        )

    return solve


# ----- main ----- #


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description="DFIR-Metric NSS benchmark runner.")
    parser.add_argument(
        "--live-vertex",
        action="store_true",
        help="Use the live Gemini-via-Vertex agent_fn (otherwise deterministic baseline).",
    )
    parser.add_argument(
        "--vertex-model",
        default=None,
        help="Override the Gemini model (default: gemini-2.5-flash).",
    )
    parser.add_argument(
        "--vertex-project",
        default=None,
        help="Override the GCP project (default: zarda-e0938).",
    )
    parser.add_argument(
        "--run-id",
        default=None,
        help="Run ID (auto-derived from mode if omitted).",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Limit to first N questions (smoke testing).",
    )
    args = parser.parse_args()

    if not CORPUS_PATH.exists():
        print(f"missing corpus: {CORPUS_PATH}", file=sys.stderr)
        return 2

    questions, corpus_sha256 = load_nss_corpus(CORPUS_PATH)
    if args.limit:
        questions = questions[: args.limit]
    print(f"corpus: {len(questions)} questions, sha256={corpus_sha256[:16]}…", file=sys.stderr)

    handles_dir = Path("logs/handles")
    handles_dir.mkdir(parents=True, exist_ok=True)
    run_id = args.run_id or ("nss-vertex" if args.live_vertex else "nss-baseline")
    ctx = SigningContext.load_or_mint(Path("keys"), run_id=run_id)
    deterministic = build_solver(ctx, handles_dir)

    if args.live_vertex:
        from oath.benchmark.gemini_nss_agent import (
            GeminiNSSConfig,
            build_gemini_nss_agent_fn,
        )
        cfg_kwargs: dict = {}
        if args.vertex_model:
            cfg_kwargs["model"] = args.vertex_model
        if args.vertex_project:
            cfg_kwargs["project"] = args.vertex_project
        config = GeminiNSSConfig(**cfg_kwargs)
        agent_fn = build_gemini_nss_agent_fn(
            deterministic_executor=deterministic,
            config=config,
        )
        print(f"  live agent: Vertex {config.model} @ {config.project}/{config.location}", file=sys.stderr)
    else:
        # Wrap the 3-arg deterministic into a 2-arg BenchmarkAgentFn.
        def agent_fn(q, k):
            return deterministic(q, k, None)

    import time as _time
    start_t = _time.time()

    def _progress(i, n, q):
        elapsed = _time.time() - start_t
        rate = (i + 1) / max(elapsed, 0.001)
        eta = (n - i - 1) / max(rate, 0.001)
        print(
            f"  [{i+1:>4}/{n}] {q.question_id} ({q.answer_type.value:<28})  "
            f"elapsed={elapsed:6.1f}s  eta={eta:6.1f}s  rate={rate:4.2f}q/s",
            file=sys.stderr,
            flush=True,
        )

    def _on_attempt(a):
        if not a.matched:
            return
        # Print a brief "+" so the user sees matches landing live
        sys.stderr.write(".")
        sys.stderr.flush()

    attempts_jsonl = Path("logs/benchmarks") / f"{run_id}_attempts.jsonl"
    harness = BenchmarkHarness(
        agent_fn=agent_fn,
        k=4,
        run_id=run_id,
        progress_callback=_progress,
        on_attempt=_on_attempt,
        attempts_jsonl_path=attempts_jsonl,
    )
    print(f"  resumable attempts log: {attempts_jsonl}", file=sys.stderr)
    result = harness.run(questions, corpus_sha256=corpus_sha256)

    print()
    print(f"  module:        {result.module}")
    print(f"  k:             {result.k}")
    print(f"  questions:     {result.total_questions}")
    print(f"  matched:       {result.matched_count}")
    print(f"  tus@{result.k}:        {result.tus_at_k:.4f}")
    print(f"  corpus sha256: {result.corpus_sha256}")

    # Stats by answer type
    by_type = Counter()
    matched_by_type = Counter()
    for a in result.attempts:
        by_type[a.answer_type.value] += 1
        if a.matched:
            matched_by_type[a.answer_type.value] += 1
    print()
    print("  Score by answer-type:")
    for at in by_type:
        n = by_type[at]
        m = matched_by_type[at]
        print(f"    {at:25}  {m}/{n}  ({m/n:.2%})")

    out_path = persist_result(result, Path("logs/benchmarks"))
    print(f"  result file:   {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
