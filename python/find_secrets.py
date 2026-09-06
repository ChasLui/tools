#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = []
# ///

"""Highlight possible secrets in a local text file or HTTP(S) response."""

import argparse
from collections import Counter
from dataclasses import dataclass
import math
import os
from pathlib import Path
import re
import sys
import urllib.error
import urllib.request


# Keep common token alphabets, including base64 padding and JWT separators.
# An equals sign ends a candidate so unquoted KEY=value assignments work.
TOKEN_RE = re.compile(r"[A-Za-z0-9_+/-]+(?:\.[A-Za-z0-9_+/-]+)*={0,2}")
PREFIX_RE = re.compile(
    r"(?:sk-(?:proj-|ant-)?|gh[pousr]_|github_pat_|xox[baprs]-|"
    r"AIza|AKIA|ASIA|sk_live_|rk_live_)[A-Za-z0-9_+/-]{12,}"
)


@dataclass(frozen=True)
class Finding:
    start: int
    end: int
    entropy: float
    reason: str


def entropy(value: str) -> float:
    """Shannon entropy in bits per character (not a validity check)."""
    if not value:
        return 0.0
    length = len(value)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in Counter(value).values()
    )


def find_secrets(
    text: str,
    min_length: int = 20,
    threshold: float = 4.0,
    hex_threshold: float = 3.0,
):
    """Yield one finding per candidate, retaining repeated occurrences."""
    for match in TOKEN_RE.finditer(text):
        value = match.group()
        score = entropy(value)
        if PREFIX_RE.fullmatch(value):
            reason = "token prefix"
        elif len(value) < min_length:
            continue
        elif re.fullmatch(r"[0-9a-fA-F]+", value):
            # Hex has at most four bits per character; normalize letter case.
            score = entropy(value.lower())
            if score < hex_threshold:
                continue
            reason = "high-entropy hex"
        elif score >= threshold:
            reason = "high entropy"
        else:
            continue
        yield Finding(match.start(), match.end(), score, reason)


def read_source(source: str) -> str:
    """Read only the supplied resource; do not follow links or test secrets."""
    if source == "-":
        return sys.stdin.read()
    if source.lower().startswith(("http://", "https://")):
        request = urllib.request.Request(
            source, headers={"User-Agent": "find_secrets.py/1.0"}
        )
        with urllib.request.urlopen(request, timeout=30) as response:
            encoding = response.headers.get_content_charset() or "utf-8"
            return response.read().decode(encoding, errors="replace")
    return Path(source).expanduser().read_text(encoding="utf-8", errors="replace")


def visible(value: str) -> str:
    """Escape line breaks and terminal controls without hiding printable text."""
    escapes = {"\n": r"\n", "\r": r"\r", "\t": r"\t", "\\": r"\\"}
    return "".join(
        escapes.get(char, char if char.isprintable() else ascii(char)[1:-1])
        for char in value
    )


def render_finding(text: str, finding: Finding, context: int, color: bool) -> str:
    start, end = finding.start, finding.end
    left, right = max(0, start - context), min(len(text), end + context)
    before = visible(text[left:start])
    secret = visible(text[start:end])
    after = visible(text[end:right])
    # Brackets also identify the exact match when output is redirected.
    highlighted = f"[[{secret}]]"
    if color:
        highlighted = f"\033[1;31m{highlighted}\033[0m"
    return (
        ("…" if left else "")
        + before + highlighted + after
        + ("…" if right < len(text) else "")
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Highlight possible secrets in a local text file or HTTP(S) response. "
            "Prints full matches with 15 context characters on each side. "
            "Heuristic results can include hashes and miss secrets."
        )
    )
    parser.add_argument("source", help="local file path, HTTP(S) URL, or - for stdin")
    parser.add_argument("-c", "--context", type=int, default=15,
                        help="context characters on each side (default: 15)")
    parser.add_argument("--min-length", type=int, default=20,
                        help="minimum length for entropy checks (default: 20)")
    parser.add_argument("--threshold", type=float, default=4.0,
                        help="minimum entropy in bits/character (default: 4.0)")
    parser.add_argument("--hex-threshold", type=float, default=3.0,
                        help="minimum entropy for hexadecimal strings (default: 3.0)")
    parser.add_argument("--color", choices=("auto", "always", "never"), default="auto")
    args = parser.parse_args()
    if args.context < 0 or args.min_length < 1:
        parser.error("--context must be nonnegative and --min-length must be positive")
    if not all(math.isfinite(n) and n >= 0 for n in (args.threshold, args.hex_threshold)):
        parser.error("entropy thresholds must be finite, nonnegative numbers")

    try:
        text = read_source(args.source)
    except (OSError, UnicodeError, LookupError, ValueError, urllib.error.URLError) as ex:
        parser.error(f"could not read source: {ex}")

    color = args.color == "always" or (
        args.color == "auto" and sys.stdout.isatty() and "NO_COLOR" not in os.environ
    )
    count = 0
    line = 1
    previous = 0
    for finding in find_secrets(text, args.min_length, args.threshold, args.hex_threshold):
        line += text.count("\n", previous, finding.start)
        previous = finding.start
        column = finding.start - text.rfind("\n", 0, finding.start)
        print(f"{line}:{column}  {finding.reason} ({finding.entropy:.2f} bits/char)")
        print("  " + render_finding(text, finding, args.context, color))
        count += 1
    print(f"{count} possible secret(s) found.", file=sys.stderr)


if __name__ == "__main__":
    main()
