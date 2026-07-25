#!/usr/bin/env python3
"""Aggregate libtest pass/fail/ignored counts from a Cargo test log."""

from __future__ import annotations

import argparse
import re
import sys
from collections.abc import Iterable
from pathlib import Path


RESULT_RE = re.compile(
    r"^\s*test result: [^.]+\.\s+"
    r"(\d+) passed;\s+(\d+) failed;\s+(\d+) ignored;"
)


def parse_counts(lines: Iterable[str]) -> tuple[int, int, int]:
    passed = failed = ignored = 0
    summaries = 0
    for line in lines:
        match = RESULT_RE.search(line)
        if match:
            summaries += 1
            passed += int(match.group(1))
            failed += int(match.group(2))
            ignored += int(match.group(3))
    if summaries == 0:
        raise ValueError("test log contains no libtest result summary")
    return passed, failed, ignored


def counts_from_path(path: Path) -> tuple[int, int, int]:
    try:
        with path.open(encoding="utf-8", errors="replace") as handle:
            return parse_counts(handle)
    except OSError as error:
        raise ValueError(f"cannot read test log {path}: {error}") from error


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("log", type=Path)
    args = parser.parse_args(argv)
    try:
        counts = counts_from_path(args.log)
    except ValueError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    print("\t".join(str(count) for count in counts))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
