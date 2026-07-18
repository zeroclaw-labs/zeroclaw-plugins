#!/usr/bin/env python3
"""Single source of truth for per-plugin CI TSV reports."""

from __future__ import annotations

import argparse
import csv
import re
import sys
from collections.abc import Iterable, Mapping
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from registry_contract import PLUGIN_NAME_RE

COLUMNS = (
    "stack",
    "plugin",
    "source_head",
    "registry",
    "strict",
    "name",
    "version",
    "provides",
    "capabilities",
    "permissions",
    "test_rc",
    "tests_passed",
    "tests_failed",
    "tests_ignored",
    "clippy_rc",
    "wasm_clippy_rc",
    "build_rc",
    "artifact",
    "artifact_bytes",
    "log_dir",
)

RETURN_CODE_COLUMNS = ("test_rc", "clippy_rc", "wasm_clippy_rc", "build_rc")
COUNT_COLUMNS = ("tests_passed", "tests_failed", "tests_ignored")
SHA_RE = re.compile(r"^[0-9a-fA-F]{40}(?:[0-9a-fA-F]{24})?$")


class SchemaError(ValueError):
    """A report does not match the canonical schema."""


def _clean_value(column: str, value: object) -> str:
    text = str(value)
    if any(separator in text for separator in ("\t", "\r", "\n")):
        raise SchemaError(f"{column} contains a TSV row separator")
    return text


def validate_row(row: Mapping[str, object]) -> dict[str, str]:
    """Validate and normalize one row in canonical column order."""
    missing = [column for column in COLUMNS if column not in row]
    extra = sorted(set(row) - set(COLUMNS), key=str)
    if missing or extra:
        details = []
        if missing:
            details.append(f"missing columns: {', '.join(missing)}")
        if extra:
            details.append(f"unknown columns: {', '.join(map(str, extra))}")
        raise SchemaError("; ".join(details))

    normalized = {column: _clean_value(column, row[column]) for column in COLUMNS}
    if not normalized["stack"]:
        raise SchemaError("stack must not be empty")
    if not PLUGIN_NAME_RE.fullmatch(normalized["plugin"]):
        raise SchemaError("plugin must be a lowercase slug")
    if not SHA_RE.fullmatch(normalized["source_head"]):
        raise SchemaError("source_head must be a 40- or 64-hex Git object ID")
    if normalized["registry"] not in {"true", "false"}:
        raise SchemaError("registry must be true or false")
    if normalized["strict"] not in {"true", "false"}:
        raise SchemaError("strict must be true or false")

    for column in (*RETURN_CODE_COLUMNS, *COUNT_COLUMNS):
        value = normalized[column]
        if not value.isascii() or not value.isdigit():
            raise SchemaError(f"{column} must be a non-negative integer")
    if normalized["test_rc"] == "0" and int(normalized["tests_failed"]) != 0:
        raise SchemaError("test_rc cannot be zero when tests_failed is nonzero")

    artifact_bytes = normalized["artifact_bytes"]
    if artifact_bytes and (not artifact_bytes.isascii() or not artifact_bytes.isdigit()):
        raise SchemaError("artifact_bytes must be empty or a non-negative integer")
    if bool(normalized["artifact"]) != bool(artifact_bytes):
        raise SchemaError("artifact and artifact_bytes must either both be set or both be empty")
    return normalized


def write_header(path: Path) -> None:
    """Create a report with exactly the canonical header."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        csv.writer(handle, dialect="excel-tab", lineterminator="\n").writerow(COLUMNS)


def _read_header(path: Path) -> list[str]:
    try:
        with path.open(encoding="utf-8", newline="") as handle:
            header = next(csv.reader(handle, dialect="excel-tab"), None)
    except OSError as error:
        raise SchemaError(f"cannot read report {path}: {error}") from error
    if header != list(COLUMNS):
        raise SchemaError(
            f"report {path} has invalid header: expected {list(COLUMNS)!r}, found {header!r}"
        )
    return header


def append_row(path: Path, row: Mapping[str, object]) -> None:
    """Validate and append one row to a report with a canonical header."""
    _read_header(path)
    normalized = validate_row(row)
    with path.open("a", encoding="utf-8", newline="") as handle:
        csv.writer(handle, dialect="excel-tab", lineterminator="\n").writerow(
            normalized[column] for column in COLUMNS
        )


def read_report(path: Path) -> list[dict[str, str]]:
    """Read a report, rejecting malformed headers and row widths."""
    try:
        handle = path.open(encoding="utf-8", newline="")
    except OSError as error:
        raise SchemaError(f"cannot read report {path}: {error}") from error

    with handle:
        reader = csv.DictReader(handle, dialect="excel-tab")
        if reader.fieldnames != list(COLUMNS):
            raise SchemaError(
                f"report {path} has invalid header: expected {list(COLUMNS)!r}, "
                f"found {reader.fieldnames!r}"
            )
        rows = []
        for line_number, row in enumerate(reader, start=2):
            if None in row or any(value is None for value in row.values()):
                raise SchemaError(f"report {path}:{line_number} has the wrong column count")
            try:
                rows.append(validate_row(row))
            except SchemaError as error:
                raise SchemaError(f"report {path}:{line_number}: {error}") from error
    return rows


def read_reports(paths: Iterable[Path]) -> list[dict[str, str]]:
    rows = []
    for path in paths:
        rows.extend(read_report(path))
    return rows


def _parse_assignments(assignments: list[str]) -> dict[str, str]:
    row = {}
    for assignment in assignments:
        if "=" not in assignment:
            raise SchemaError(f"row value must use column=value syntax: {assignment!r}")
        column, value = assignment.split("=", 1)
        if column in row:
            raise SchemaError(f"duplicate row column: {column}")
        row[column] = value
    return row


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    header = commands.add_parser("write-header", help="write the canonical TSV header")
    header.add_argument("path", type=Path)

    append = commands.add_parser("append-row", help="append a validated TSV row")
    append.add_argument("path", type=Path)
    append.add_argument("assignments", nargs="+")

    validate = commands.add_parser("validate", help="validate one or more TSV reports")
    validate.add_argument("paths", nargs="+", type=Path)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        if args.command == "write-header":
            write_header(args.path)
        elif args.command == "append-row":
            append_row(args.path, _parse_assignments(args.assignments))
        else:
            read_reports(args.paths)
    except SchemaError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
