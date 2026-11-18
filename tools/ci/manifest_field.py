#!/usr/bin/env python3
"""Read and normalize one top-level field from a TOML manifest."""

from __future__ import annotations

import argparse
import re
import shutil
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
    read_regular_file,
    withheld_wit_directories,
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


def prepare_wit_snapshot(manifest: Path, wit_root: Path, plugin: str) -> None:
    with manifest.open("rb") as handle:
        values = tomllib.load(handle)
    if not PLUGIN_NAME_RE.fullmatch(plugin) or values.get("name") != plugin:
        raise ManifestFieldError("snapshot plugin must match the canonical manifest name")
    registry = values.get("registry", True)
    if not isinstance(registry, bool):
        raise ManifestFieldError("registry must be a boolean when present")
    for directory in withheld_wit_directories(plugin, registry=registry):
        path = wit_root / directory
        if path.exists() or path.is_symlink():
            shutil.rmtree(path)


def read_wit_pin(pin_file: Path, vendored: Path) -> str:
    if vendored.is_symlink() or not vendored.is_dir():
        raise ManifestFieldError("WIT pin requires its matching vendored directory")
    contents = read_regular_file(pin_file, byte_limit=4096).decode("utf-8")
    refs = [line.partition("#")[0].strip() for line in contents.splitlines()]
    refs = [ref for ref in refs if ref]
    if len(refs) != 1 or not re.fullmatch(r"[0-9a-f]{40}", refs[0]):
        raise ManifestFieldError("WIT pin must contain exactly one lowercase 40-hex SHA")
    return refs[0]


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    checks = parser.add_mutually_exclusive_group()
    checks.add_argument("--validate-plugin-name")
    checks.add_argument("--validate-wasm-path")
    checks.add_argument("--validate-package-tree", type=Path)
    checks.add_argument("--copy-regular-file", nargs=2, type=Path)
    checks.add_argument("--prepare-wit-snapshot", nargs=3, metavar=("MANIFEST", "WIT", "PLUGIN"))
    checks.add_argument("--wit-pin", nargs=2, type=Path, metavar=("PIN", "DIRECTORY"))
    parser.add_argument("manifest", type=Path, nargs="?")
    parser.add_argument("field", nargs="?")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        if args.prepare_wit_snapshot is not None:
            manifest, wit_root, plugin = args.prepare_wit_snapshot
            prepare_wit_snapshot(Path(manifest), Path(wit_root), plugin)
            return 0
        if args.wit_pin is not None:
            print(read_wit_pin(*args.wit_pin))
            return 0
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
    except (ValueError, OSError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
