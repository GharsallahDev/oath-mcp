"""find_strings_on_image — typed MCP function for NIST String Search-style queries.

Searches a forensic disk image for files whose content matches a given
regex or literal substring, returning a typed list of
(inode, filename, deleted_flag, first_match_offset) records. Backs the
DFIR-Metric Module III (NSS) workload + ad-hoc string-pivot triage.

Backing tool: Sleuthkit's `fls` + `icat` (every file's bytes piped through a
literal-or-regex matcher). We DON'T shell out to `srch_strings` because its
output format is inode-less (just file paths). The two-stage fls→icat path
gives us the (inode, filename, deleted) tuple the NSS corpus requires.

Determinism contract
--------------------
- The candidate file list is the sorted output of `fls -r -p` against a
  fixed offset (default 0 — whole image). Sleuthkit's fls is deterministic
  for a fixed input image + fixed args.
- For each candidate file, `icat` produces the file's bytes; the matcher is
  pure-Python (re.finditer) so determinism is fully under our control.
- Output records are sorted by (deleted_flag, inode, filename) before
  Notarization, so the BLAKE3 of stdout is reproducible across re-runs.

reverify() re-walks the same fls+icat pipeline with the same args; if any
file's bytes drifted (or fls saw a different inode set), the BLAKE3 of the
canonical record stream changes and verification fails.
"""
from __future__ import annotations

import re
import subprocess
from pathlib import Path
from typing import Protocol

from pydantic import BaseModel, ConfigDict, Field

from oath.mcp.evidence_handle import EvidenceHandle
from oath.receipt.notarized import (
    EvidenceOffset,
    Notarized,
    SigningContext,
    mint,
)

# Pinned Sleuthkit version. The benchmark refuses to score across version drift.
TSK_VERSION_FLOOR = "4.12.0"


# --------------------------------------------------------------------------- #
# Typed schema                                                                #
# --------------------------------------------------------------------------- #


class StringMatch(BaseModel):
    """One file that matched the search pattern, plus where the first hit was.

    For NSS scoring, only (inode, filename) matters; the rest is auxiliary
    telemetry useful for ad-hoc triage.
    """

    model_config = ConfigDict(frozen=True)

    inode: int = Field(..., ge=0)
    filename: str = Field(..., min_length=1)
    deleted: bool = Field(
        ..., description="True iff fls flagged this entry as DELETED."
    )
    file_size_bytes: int = Field(..., ge=0)
    first_match_offset: int = Field(
        ..., ge=0, description="Byte offset of the first match within the file."
    )
    total_match_count: int = Field(..., ge=0)


def to_nss_string(m: StringMatch) -> str:
    """Render a StringMatch as the NIST String Search "<inode>:<filename>" form.

    Corpus convention (DFIR-Metric / NIST CFTT String Search Test Data Set):
    - filename is the BASENAME only (no directory prefix)
    - the DELETED-/LIVE- prefix comes from NIST's test-data filename convention
      itself, NOT from any wrapper we add
    - NTFS `$FILE_NAME` duplicate-attribute entries (where one inode has BOTH
      a standard $30 name record AND a $144 $FILE_NAME record) are collapsed
      to a single entry — the corpus uses one `<inode>:<filename>` per file
    """
    # Strip directory prefix (e.g. "fat/DELETED-email-iron.txt" → "DELETED-email-iron.txt")
    name = m.filename.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
    # Strip NTFS `$FILE_NAME` duplicate-record suffix
    name = name.replace(" ($FILE_NAME)", "")
    return f"{m.inode}:{name}"


# --------------------------------------------------------------------------- #
# Tool executor seam                                                          #
# --------------------------------------------------------------------------- #


class TSKExecutor(Protocol):
    """Lightweight seam over Sleuthkit `fls` + `icat`. Tests substitute fakes."""

    def fls(self, image_path: Path, offset: int) -> bytes:
        """Run `fls -r -p -m / <image>` at the given partition offset."""

    def icat(self, image_path: Path, offset: int, inode: int) -> bytes:
        """Run `icat <image> <inode>` — return the file's bytes."""


class SubprocessTSKExecutor:
    """Default real-subprocess implementation."""

    def fls(self, image_path: Path, offset: int) -> bytes:
        argv = ["fls", "-r", "-p", "-m", "/", "-o", str(offset), str(image_path)]
        return subprocess.run(argv, capture_output=True, check=True, timeout=600).stdout

    def icat(self, image_path: Path, offset: int, inode: int) -> bytes:
        argv = ["icat", "-o", str(offset), str(image_path), str(inode)]
        return subprocess.run(argv, capture_output=True, check=True, timeout=600).stdout


# --------------------------------------------------------------------------- #
# fls output parser                                                           #
# --------------------------------------------------------------------------- #
# fls -m / -p emits one body-file row per file:
#   md5|name|inode|...|size|...
# When -p (full path) is set, `name` is the full slash-separated path.
# Deleted entries are prefixed with "(realloc)" or marked by inode "*".
_FLS_BODY_RE = re.compile(
    r"^(?P<md5>\*?[0-9a-f]*)\|(?P<name>.*?)\|(?P<inode>\d+)(?:-\d+)?(?:-\d+)?\|"
    r"(?P<mode>[^|]*)\|(?P<uid>[^|]*)\|(?P<gid>[^|]*)\|(?P<size>\d+)\|",
)


def _parse_fls_bodyfile(body: bytes) -> list[tuple[int, str, bool, int]]:
    """Parse fls -m output into (inode, name, deleted, size) tuples.

    Deleted entries: fls marks deletions with "(realloc)" suffix on the name
    OR the special "*" inode prefix in older versions. We honor the "*"
    convention which is what the NSS corpus uses.
    """
    out: list[tuple[int, str, bool, int]] = []
    for line in body.decode("utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Quick parse: split on '|' with a fixed expected column count.
        cols = line.split("|")
        if len(cols) < 8:
            continue
        name_raw = cols[1].strip()
        inode_raw = cols[2].strip()
        size_raw = cols[6].strip() if len(cols) > 6 else "0"

        # Detect deletion: fls -m prefixes deleted names with "(realloc)"
        # OR uses a leading "*" before the inode number.
        deleted = False
        if inode_raw.startswith("*"):
            deleted = True
            inode_raw = inode_raw.lstrip("*")
        if name_raw.endswith("(realloc)") or name_raw.endswith("(deleted)"):
            deleted = True
            name_raw = re.sub(r"\s*\((?:realloc|deleted)\)$", "", name_raw)

        # Strip the NTFS-attribute suffix "-128-X" / "-144-X" from inode.
        base_inode = inode_raw.split("-", 1)[0]
        try:
            inode = int(base_inode)
        except ValueError:
            continue

        try:
            size = int(size_raw)
        except ValueError:
            size = 0

        # Normalize the name: fls outputs paths like "/Users/foo/bar.txt"
        # — we keep the leading slash off for the NSS string format.
        name = name_raw.lstrip("/").strip()
        if not name:
            continue

        out.append((inode, name, deleted, size))
    return out


# --------------------------------------------------------------------------- #
# Public typed function                                                       #
# --------------------------------------------------------------------------- #


# Canonical default encodings for NSS-style multi-encoding email/keyword search.
# NIST CFTT test data ships each plaintext sample in ascii / utf-8 / utf-16-le
# / utf-16-be — exhaustive coverage requires we search the file bytes for the
# pattern encoded under each of these.
DEFAULT_ENCODINGS: tuple[str, ...] = ("ascii", "utf-8", "utf-16-le", "utf-16-be")


def _encode_pattern_per_encoding(
    pattern: str,
    encodings: tuple[str, ...],
    case_sensitive: bool,
) -> list[tuple[str, bytes]]:
    """Encode `pattern` once per encoding, returning (encoding_name, bytes) pairs.

    Case-folding is handled in the search loop (data.lower() vs pattern.lower())
    so we only need ONE encoded form per encoding regardless of case_sensitive.
    Identical byte sequences across encodings (e.g. ascii == utf-8 for pure
    ASCII patterns) are deduplicated.
    """
    out: list[tuple[str, bytes]] = []
    seen: set[bytes] = set()
    for enc in encodings:
        try:
            b = pattern.encode(enc)
        except (UnicodeEncodeError, LookupError):
            continue
        if not b or b in seen:
            continue
        seen.add(b)
        out.append((enc, b))
    return out


def find_strings_on_image(
    handle: EvidenceHandle,
    *,
    pattern: str,
    is_regex: bool = False,
    case_sensitive: bool = False,
    encodings: tuple[str, ...] | list[str] = DEFAULT_ENCODINGS,
    image_offset: int = 0,
    name_substring: str | None = None,
    include_deleted: bool = True,
    max_file_size_bytes: int = 256 * 1024 * 1024,
    max_matches_per_file: int = 32,
    ctx: SigningContext,
    executor: TSKExecutor | None = None,
    prev_hash: str | None = None,
    model_id: str | None = None,
    prompt_hash: str | None = None,
) -> Notarized[list[StringMatch]]:
    """Search every file on the image for `pattern`.

    Parameters
    ----------
    pattern
        The search string. When `is_regex` is False (default), treated as a
        literal substring; when True, compiled as a Python regex against the
        utf-8 decoded text (single encoding — regex multi-encoding is not
        currently supported).
    case_sensitive
        Default False (NSS-style matching is case-insensitive).
    encodings
        Byte-encodings to search for the pattern under (literal mode only).
        Default: ascii / utf-8 / utf-16-le / utf-16-be. NIST CFTT plaintext
        samples ship in all four. Bound into args_canonical so reverify
        recreates the same encoding set.
    image_offset
        Partition byte offset, in 512-byte sectors. Default 0 = whole image.
    name_substring
        Optional case-insensitive substring filter on the file path before
        we read its contents — speeds up large images dramatically when
        the corpus question constrains by name/extension.
    include_deleted
        Default True. NSS questions explicitly include deleted entries.
    max_file_size_bytes
        Files larger than this are skipped (default 256 MiB). Stops a single
        hiberfil.sys from eating the whole search.
    max_matches_per_file
        Cap on iterations per file. Total_match_count tells the agent
        whether it was truncated.
    """
    executor = executor or SubprocessTSKExecutor()

    # Normalize the args BEFORE binding into args_canonical so the verifier's
    # re-derivation lands on the same canonical form. Encodings are sorted +
    # tupled for stable ordering.
    normalized_encodings = tuple(sorted({str(e).strip().lower() for e in encodings if str(e).strip()}))
    if not normalized_encodings:
        normalized_encodings = DEFAULT_ENCODINGS

    norm_args: dict[str, object] = {
        "pattern": pattern,
        "is_regex": is_regex,
        "case_sensitive": case_sensitive,
        "encodings": list(normalized_encodings),
        "image_offset": image_offset,
        "name_substring": name_substring,
        "include_deleted": include_deleted,
        "max_file_size_bytes": max_file_size_bytes,
        "max_matches_per_file": max_matches_per_file,
    }

    # Build matchers. Regex mode = single-encoding utf-8-decoded text path
    # (regex+multi-encoding is non-trivial; use byte-level literal for NSS).
    # Literal mode = per-encoding byte patterns.
    flags = 0 if case_sensitive else re.IGNORECASE
    regex_matcher = re.compile(pattern, flags) if is_regex else None
    byte_patterns = (
        []
        if is_regex
        else _encode_pattern_per_encoding(pattern, normalized_encodings, case_sensitive)
    )

    # Step 1: enumerate files via fls.
    fls_out = executor.fls(handle.image_path, image_offset)
    entries = _parse_fls_bodyfile(fls_out)

    # Filter early.
    if not include_deleted:
        entries = [e for e in entries if not e[2]]
    if name_substring:
        needle = name_substring.lower()
        entries = [e for e in entries if needle in e[1].lower()]
    entries = [e for e in entries if 0 < e[3] <= max_file_size_bytes]

    # Step 2: for each candidate file, icat the bytes and run the matcher.
    matches: list[StringMatch] = []
    for inode, name, deleted, size in entries:
        try:
            data = executor.icat(handle.image_path, image_offset, inode)
        except subprocess.CalledProcessError:
            continue
        if not data:
            continue

        first_offset: int | None = None
        count = 0
        if regex_matcher is not None:
            text = data.decode("utf-8", errors="replace")
            for m in regex_matcher.finditer(text):
                if first_offset is None:
                    first_offset = m.start()
                count += 1
                if count >= max_matches_per_file:
                    break
        else:
            # Byte-level multi-encoding literal search. For each encoded
            # pattern, walk the file with bytes.find/index until exhausted or
            # the cap is hit.
            for _enc, pat in byte_patterns:
                if not pat:
                    continue
                pos = 0
                while True:
                    if case_sensitive:
                        idx = data.find(pat, pos)
                    else:
                        idx = data.lower().find(pat.lower(), pos)
                    if idx < 0:
                        break
                    if first_offset is None or idx < first_offset:
                        first_offset = idx
                    count += 1
                    pos = idx + max(1, len(pat))
                    if count >= max_matches_per_file:
                        break
                if count >= max_matches_per_file:
                    break
        if first_offset is None:
            continue
        matches.append(
            StringMatch(
                inode=inode,
                filename=name,
                deleted=deleted,
                file_size_bytes=size,
                first_match_offset=first_offset,
                total_match_count=count,
            )
        )

    # Sort for determinism: deleted-flag first (False < True), then inode,
    # then filename. The Notarized envelope's stdout hash needs this stable
    # ordering or re-runs would drift.
    matches.sort(key=lambda m: (m.deleted, m.inode, m.filename))

    # Canonical "stdout" representation (also what we hash for BLAKE3): one
    # line per match in the NSS "<inode>:<name>\t<size>\t<first_offset>"
    # form. The expected NSS string is reproducible from this stream.
    stdout_bytes = (
        "\n".join(
            f"{to_nss_string(m)}\t{m.file_size_bytes}\t{m.first_match_offset}\t{m.total_match_count}"
            for m in matches
        )
        + "\n"
    ).encode("utf-8")

    return mint(
        data=matches,
        tool_name="find_strings_on_image",
        tool_version=TSK_VERSION_FLOOR,
        args=norm_args,
        image_sha256=handle.image_sha256,
        stdout_bytes=stdout_bytes,
        offsets=(
            EvidenceOffset(
                start=image_offset * 512,
                length=handle.image_size_bytes,
                artifact_label="image",
            ),
        ),
        prev_hash=prev_hash,
        model_id=model_id,
        prompt_hash=prompt_hash,
        ctx=ctx,
    )


def _recompute_stdout(
    image_path: Path,
    args: dict[str, object],
    executor: TSKExecutor,
) -> bytes:
    """Re-derive the canonical stdout bytes from the same args + same image.

    Mirrors the `stdout_bytes` construction inside `find_strings_on_image`
    but without going through mint() / signing — we only need the bytes for
    BLAKE3 comparison.
    """
    pattern = str(args["pattern"])
    is_regex = bool(args.get("is_regex", False))
    case_sensitive = bool(args.get("case_sensitive", False))
    encodings = tuple(args.get("encodings") or DEFAULT_ENCODINGS)
    image_offset = int(args.get("image_offset", 0))
    name_substring = args.get("name_substring")
    include_deleted = bool(args.get("include_deleted", True))
    max_file_size_bytes = int(args.get("max_file_size_bytes", 256 * 1024 * 1024))
    max_matches_per_file = int(args.get("max_matches_per_file", 32))

    flags = 0 if case_sensitive else re.IGNORECASE
    regex_matcher = re.compile(pattern, flags) if is_regex else None
    byte_patterns = (
        []
        if is_regex
        else _encode_pattern_per_encoding(pattern, encodings, case_sensitive)
    )

    fls_out = executor.fls(image_path, image_offset)
    entries = _parse_fls_bodyfile(fls_out)
    if not include_deleted:
        entries = [e for e in entries if not e[2]]
    if name_substring:
        needle = str(name_substring).lower()
        entries = [e for e in entries if needle in e[1].lower()]
    entries = [e for e in entries if 0 < e[3] <= max_file_size_bytes]

    matches: list[StringMatch] = []
    for inode, name, deleted, size in entries:
        try:
            data = executor.icat(image_path, image_offset, inode)
        except subprocess.CalledProcessError:
            continue
        if not data:
            continue

        first_offset: int | None = None
        count = 0
        if regex_matcher is not None:
            text = data.decode("utf-8", errors="replace")
            for m in regex_matcher.finditer(text):
                if first_offset is None:
                    first_offset = m.start()
                count += 1
                if count >= max_matches_per_file:
                    break
        else:
            for _enc, pat in byte_patterns:
                if not pat:
                    continue
                pos = 0
                while True:
                    if case_sensitive:
                        idx = data.find(pat, pos)
                    else:
                        idx = data.lower().find(pat.lower(), pos)
                    if idx < 0:
                        break
                    if first_offset is None or idx < first_offset:
                        first_offset = idx
                    count += 1
                    pos = idx + max(1, len(pat))
                    if count >= max_matches_per_file:
                        break
                if count >= max_matches_per_file:
                    break
        if first_offset is None:
            continue
        matches.append(
            StringMatch(
                inode=inode,
                filename=name,
                deleted=deleted,
                file_size_bytes=size,
                first_match_offset=first_offset,
                total_match_count=count,
            )
        )

    matches.sort(key=lambda m: (m.deleted, m.inode, m.filename))
    return (
        "\n".join(
            f"{to_nss_string(m)}\t{m.file_size_bytes}\t{m.first_match_offset}\t{m.total_match_count}"
            for m in matches
        )
        + "\n"
    ).encode("utf-8")


def reverify(
    envelope: Notarized[list[StringMatch]],
    *,
    image_path: Path,
    executor: TSKExecutor | None = None,
) -> tuple[bool, str]:
    """Re-run fls + icat with the same args; recompute BLAKE3 of stdout; compare."""
    import blake3
    import json

    executor = executor or SubprocessTSKExecutor()

    try:
        args = json.loads(envelope.header.args_canonical)
    except (json.JSONDecodeError, AttributeError):
        return False, "args_canonical missing or not JSON"

    if not image_path.exists():
        return False, f"image_path missing: {image_path}"

    try:
        stdout_bytes = _recompute_stdout(image_path, args, executor)
    except Exception as e:
        return False, f"re-run raised: {type(e).__name__}: {e}"

    actual = blake3.blake3(stdout_bytes).hexdigest()
    expected = envelope.header.stdout_blake3
    if actual != expected:
        return False, f"stdout BLAKE3 drift: expected {expected[:16]}…, got {actual[:16]}…"
    return True, "ok"


# --------------------------------------------------------------------------- #
# NSS adapter — convert matches to the corpus answer format                   #
# --------------------------------------------------------------------------- #


def to_nss_answer_payload(matches: list[StringMatch]) -> str:
    """Render a list[StringMatch] as the canonical JSON-array payload the scorer expects.

    Deduplicates by (inode, filename, deleted) so the agent's candidate
    payload is set-equal-ready against the corpus expected answer.
    """
    import json

    items = sorted({to_nss_string(m) for m in matches})
    return json.dumps(items, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


__all__ = [
    "DEFAULT_ENCODINGS",
    "StringMatch",
    "SubprocessTSKExecutor",
    "TSKExecutor",
    "TSK_VERSION_FLOOR",
    "find_strings_on_image",
    "reverify",
    "to_nss_answer_payload",
    "to_nss_string",
]
