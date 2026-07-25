#!/usr/bin/env python3
"""Render validated component TSV reports as a GitHub Markdown summary."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

# `tools/registry_contract.py` owns host package limits. Resolve it rather than
# copying the cap into this presentation layer.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from registry_contract import MAX_PLUGIN_ZIP_BYTES
from plan_matrix import PlanError, parse_matrix_json
from report_schema import SchemaError, read_reports


SOFT_ARTIFACT_LIMIT = 5 * 1024 * 1024


def markdown(value: object) -> str:
    return str(value).replace("\\", "\\\\").replace("|", "\\|").replace("\n", " ")


def check_status(return_code: str, *, strict: bool = True) -> str:
    if return_code == "0":
        return "ok"
    return f"FAIL (rc {return_code})" if strict else f"WARN baseline (rc {return_code})"


def test_status(row: dict[str, str]) -> str:
    passed = int(row["tests_passed"])
    failed = int(row["tests_failed"])
    ignored = int(row["tests_ignored"])
    parts = [f"{passed} passed"]
    if failed:
        parts.append(f"{failed} failed")
    if ignored:
        parts.append(f"{ignored} ignored")
    result = ", ".join(parts)
    if row["test_rc"] != "0":
        result += f" (rc {row['test_rc']})"
    return result


def artifact_status(row: dict[str, str]) -> str:
    if not row["artifact_bytes"]:
        return "—"
    size = int(row["artifact_bytes"])
    percent = size / MAX_PLUGIN_ZIP_BYTES * 100
    rendered = f"{size:,} B ({percent:.1f}% of cap)"
    if size > SOFT_ARTIFACT_LIMIT:
        rendered = f"⚠ {rendered}"
    return rendered


def rows_pass(rows: list[dict[str, str]]) -> bool:
    return all(
        row["test_rc"] == "0"
        and row["build_rc"] == "0"
        and int(row["tests_failed"]) == 0
        and (
            row["strict"] == "false"
            or (row["clippy_rc"] == "0" and row["wasm_clippy_rc"] == "0")
        )
        for row in rows
    )


def render_table(rows: list[dict[str, str]]) -> str:
    lines = [
        "| Plugin | Version | Registry | Tests | Clippy (host) | Clippy (wasm) | Build | Artifact |",
        "|---|---|---:|---|---|---|---|---:|",
    ]
    for row in sorted(rows, key=lambda item: item["plugin"]):
        strict = row["strict"] == "true"
        cells = (
            row["plugin"],
            row["version"] or "—",
            row["registry"],
            test_status(row),
            check_status(row["clippy_rc"], strict=strict),
            check_status(row["wasm_clippy_rc"], strict=strict),
            check_status(row["build_rc"]),
            artifact_status(row),
        )
        lines.append("| " + " | ".join(markdown(cell) for cell in cells) + " |")
    return "\n".join(lines)


def render_summary(
    rows: list[dict[str, str]],
    *,
    aggregate: bool,
    sha: str,
    event: str,
    mode: str,
    expected_count: int | None,
    verdict: str,
    planned_policy: dict[str, bool] | None = None,
) -> str:
    plugins = [row["plugin"] for row in rows]
    duplicates = sorted({plugin for plugin in plugins if plugins.count(plugin) > 1})
    if duplicates:
        raise SchemaError(f"duplicate plugin rows: {', '.join(duplicates)}")
    if planned_policy is not None:
        expected_plugins = set(planned_policy)
        actual_plugins = set(plugins)
        missing = sorted(expected_plugins - actual_plugins)
        unexpected = sorted(actual_plugins - expected_plugins)
        if missing or unexpected:
            details = []
            if missing:
                details.append(f"missing report plugins: {', '.join(missing)}")
            if unexpected:
                details.append(f"unexpected report plugins: {', '.join(unexpected)}")
            raise SchemaError("; ".join(details))
        strict_mismatches = sorted(
            row["plugin"]
            for row in rows
            if (row["strict"] == "true") != planned_policy[row["plugin"]]
        )
        if strict_mismatches:
            raise SchemaError(
                "report strictness does not match the planned matrix: "
                + ", ".join(strict_mismatches)
            )
        if expected_count is not None and expected_count != len(planned_policy):
            raise SchemaError(
                f"workflow count {expected_count} does not match the matrix's "
                f"{len(planned_policy)} plugin identities"
            )
    elif expected_count is not None and expected_count != len(rows):
        raise SchemaError(f"planned {expected_count} plugin rows but received {len(rows)}")
    if aggregate:
        mismatched_sources = sorted(
            row["plugin"] for row in rows if row["source_head"] != sha
        )
        if mismatched_sources:
            raise SchemaError(
                f"report source_head does not match validated SHA {sha}: "
                f"{', '.join(mismatched_sources)}"
            )

    sections = []
    if aggregate:
        sections.append(
            f"Validated `{markdown(sha)}` — event `{markdown(event)}`, "
            f"mode `{markdown(mode)}`, {len(rows)} plugin(s)"
        )
    if rows:
        sections.append(render_table(rows))
    elif aggregate:
        sections.append("No plugin components required validation.")

    if aggregate:
        passed = rows_pass(rows) if verdict == "auto" else verdict == "pass"
        sections.append(
            "**Verdict: PASS — all deterministic checks green**"
            if passed
            else "**Verdict: FAIL — one or more deterministic checks failed**"
        )
    return "\n\n".join(sections) + "\n"


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("reports", nargs="*", type=Path)
    parser.add_argument("--aggregate", action="store_true")
    parser.add_argument("--sha", default=os.environ.get("GITHUB_SHA", "unknown"))
    parser.add_argument("--event", default=os.environ.get("GITHUB_EVENT_NAME", "unknown"))
    parser.add_argument("--mode", choices=("changed", "full"), default="full")
    parser.add_argument("--count", type=int)
    parser.add_argument("--matrix-json")
    parser.add_argument("--verdict", choices=("auto", "pass", "fail"), default="auto")
    parser.add_argument("--output", type=Path)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.count is not None and args.count < 0:
        print("error: count must be non-negative", file=sys.stderr)
        return 1
    try:
        if args.aggregate and args.matrix_json is None:
            raise SchemaError("--matrix-json is required with --aggregate")
        planned_policy = (
            parse_matrix_json(args.matrix_json)
            if args.matrix_json is not None
            else None
        )
        rows = read_reports(args.reports)
        rendered = render_summary(
            rows,
            aggregate=args.aggregate,
            sha=args.sha,
            event=args.event,
            mode=args.mode,
            expected_count=args.count,
            planned_policy=planned_policy,
            verdict=args.verdict,
        )
    except (PlanError, SchemaError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
