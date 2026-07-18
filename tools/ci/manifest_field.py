#!/usr/bin/env python3
"""Read and normalize one top-level field from a TOML manifest."""

from __future__ import annotations

import argparse
import sys
import tomllib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from registry_contract import (
    MAX_PLUGIN_EXTRACTED_BYTES,
    PLUGIN_NAME_RE,
    WASM_PATH_RE,
    copy_regular_file,
    package_tree_errors,
)


class ManifestFieldError(ValueError):
    pass


def normalize(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return str(value).lower()
    if isinstance(value, (str, int, float)):
        return str(value)
    if isinstance(value, list):
        if any(isinstance(item, (dict, list)) or item is None for item in value):
            raise ManifestFieldError("arrays must contain only scalar values")
        return ",".join(normalize(item) for item in value)
    raise ManifestFieldError(f"unsupported TOML value type: {type(value).__name__}")


def read_field(manifest: Path, field: str) -> str:
    if not field or "." in field:
        raise ManifestFieldError("field must name one top-level TOML key")
    try:
        with manifest.open("rb") as handle:
            values = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise ManifestFieldError(f"cannot read {manifest}: {error}") from error
    return normalize(values.get(field))


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    checks = parser.add_mutually_exclusive_group()
    checks.add_argument("--validate-plugin-name")
    checks.add_argument("--validate-wasm-path")
    checks.add_argument("--validate-package-tree", type=Path)
    checks.add_argument("--copy-regular-file", nargs=2, type=Path)
    parser.add_argument("manifest", type=Path, nargs="?")
    parser.add_argument("field", nargs="?")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        if args.validate_plugin_name is not None:
            if not PLUGIN_NAME_RE.fullmatch(args.validate_plugin_name):
                raise ManifestFieldError("plugin name must be a lowercase slug")
            return 0
        if args.validate_wasm_path is not None:
            if not WASM_PATH_RE.fullmatch(args.validate_wasm_path):
                raise ManifestFieldError(
                    "wasm_path must be a safe relative .wasm filename"
                )
            return 0
        if args.validate_package_tree is not None:
            errors = package_tree_errors(args.validate_package_tree)
            if errors:
                raise ManifestFieldError("; ".join(errors))
            return 0
        if args.copy_regular_file is not None:
            source, destination = args.copy_regular_file
            try:
                size = copy_regular_file(
                    source,
                    destination,
                    byte_limit=MAX_PLUGIN_EXTRACTED_BYTES,
                )
            except (OSError, ValueError) as error:
                raise ManifestFieldError(f"cannot materialize regular file: {error}") from error
            print(size)
            return 0
        if args.manifest is None or args.field is None:
            raise ManifestFieldError("manifest and field are required when not validating")
        print(read_field(args.manifest, args.field))
    except ManifestFieldError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
