#!/usr/bin/env python3
"""Stage locally built Safe Hands components into dist/local."""

from __future__ import annotations

import argparse
import os
import re
import shutil
import stat
import sys
import tempfile
import tomllib
from pathlib import Path

SAFE_HANDS_PLUGINS = (
    "payment-verify",
    "solana-tx-authorize",
    "spl-transfer-build",
    "squads-proposal-build",
)
PLUGIN_NAME_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
WASM_PATH_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*\.wasm$")


class StageLocalError(ValueError):
    pass


def _absolute_lexical(path: Path) -> Path:
    return Path(os.path.abspath(os.fspath(path)))


def _within(repository: Path, path: Path, *, label: str) -> Path:
    absolute = _absolute_lexical(path)
    try:
        absolute.relative_to(repository)
    except ValueError as error:
        raise StageLocalError(f"{label} must remain inside repository: {absolute}") from error
    return absolute


def _reject_symlink_components(repository: Path, path: Path, *, label: str) -> None:
    relative = path.relative_to(repository)
    current = repository
    for part in relative.parts:
        current = current / part
        if not current.exists() and not current.is_symlink():
            continue
        try:
            mode = current.lstat().st_mode
        except OSError as error:
            raise StageLocalError(f"cannot inspect {label} {current}: {error}") from error
        if stat.S_ISLNK(mode):
            raise StageLocalError(f"{label} must not contain a symbolic link: {current}")


def _regular_nonempty(path: Path, *, label: str) -> int:
    try:
        mode = path.lstat().st_mode
        size = path.stat().st_size
    except OSError as error:
        raise StageLocalError(f"cannot inspect {label} {path}: {error}") from error
    if stat.S_ISLNK(mode) or not stat.S_ISREG(mode):
        raise StageLocalError(f"{label} must be a regular file: {path}")
    if size <= 0:
        raise StageLocalError(f"{label} must be non-empty: {path}")
    return size


def _read_manifest(path: Path, plugin: str) -> str:
    _regular_nonempty(path, label="plugin manifest")
    try:
        with path.open("rb") as handle:
            document = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise StageLocalError(f"cannot read plugin manifest {path}: {error}") from error
    if document.get("name") != plugin:
        raise StageLocalError(f"manifest name must match plugin {plugin!r}: {path}")
    wasm_path = document.get("wasm_path")
    if not isinstance(wasm_path, str) or not WASM_PATH_RE.fullmatch(wasm_path):
        raise StageLocalError(f"manifest has unsafe wasm_path: {path}")
    return wasm_path


def _validate_existing_destination(output: Path, expected_files: set[Path]) -> None:
    if not output.exists() and not output.is_symlink():
        return
    try:
        mode = output.lstat().st_mode
    except OSError as error:
        raise StageLocalError(f"cannot inspect staging destination {output}: {error}") from error
    if stat.S_ISLNK(mode) or not stat.S_ISDIR(mode):
        raise StageLocalError(f"staging destination must be a real directory: {output}")

    actual_files: set[Path] = set()
    actual_directories: set[Path] = set()
    for current_root, directory_names, file_names in os.walk(output):
        root = Path(current_root)
        for name in directory_names:
            candidate = root / name
            relative = candidate.relative_to(output)
            if candidate.is_symlink():
                raise StageLocalError(
                    f"staging destination must not contain symbolic links: {candidate}"
                )
            actual_directories.add(relative)
        for name in file_names:
            candidate = root / name
            relative = candidate.relative_to(output)
            if candidate.is_symlink() or not candidate.is_file():
                raise StageLocalError(
                    f"staging destination must contain only regular files: {candidate}"
                )
            actual_files.add(relative)

    expected_directories = {Path(plugin) for plugin in SAFE_HANDS_PLUGINS}
    if actual_files != expected_files or actual_directories != expected_directories:
        raise StageLocalError(
            "existing staging destination contains unexpected or incomplete paths; "
            "remove it before retrying"
        )


def stage_plugins(repository: Path, target_dir: Path, output_dir: Path) -> list[tuple[str, int]]:
    repository = _absolute_lexical(repository)
    if repository.is_symlink() or not repository.is_dir():
        raise StageLocalError(f"repository must be a real directory: {repository}")
    target_dir = _within(repository, target_dir, label="target directory")
    output_dir = _within(repository, output_dir, label="output directory")
    _reject_symlink_components(repository, target_dir, label="target directory")
    _reject_symlink_components(repository, output_dir, label="output directory")

    packages: list[tuple[str, Path, Path, str, int]] = []
    expected_files: set[Path] = set()
    for plugin in SAFE_HANDS_PLUGINS:
        if not PLUGIN_NAME_RE.fullmatch(plugin):
            raise StageLocalError(f"unsafe configured plugin name: {plugin!r}")
        plugin_dir = repository / "plugins" / plugin
        _reject_symlink_components(repository, plugin_dir, label="plugin directory")
        if not plugin_dir.is_dir():
            raise StageLocalError(f"plugin directory does not exist: {plugin_dir}")
        manifest = plugin_dir / "manifest.toml"
        wasm_path = _read_manifest(manifest, plugin)
        artifact = target_dir / wasm_path
        size = _regular_nonempty(artifact, label="wasm artifact")
        packages.append((plugin, manifest, artifact, wasm_path, size))
        expected_files.update(
            {Path(plugin) / "manifest.toml", Path(plugin) / wasm_path}
        )

    output_dir.parent.mkdir(parents=True, exist_ok=True)
    _reject_symlink_components(repository, output_dir.parent, label="output parent")
    _validate_existing_destination(output_dir, expected_files)

    temporary = Path(tempfile.mkdtemp(prefix=".stage-local-", dir=output_dir.parent))
    committed = False
    try:
        for plugin, manifest, artifact, wasm_path, _ in packages:
            destination = temporary / plugin
            destination.mkdir()
            shutil.copyfile(manifest, destination / "manifest.toml")
            shutil.copyfile(artifact, destination / wasm_path)
            _regular_nonempty(destination / "manifest.toml", label="staged manifest")
            _regular_nonempty(destination / wasm_path, label="staged wasm artifact")
        if output_dir.exists():
            shutil.rmtree(output_dir)
        os.replace(temporary, output_dir)
        committed = True
    except OSError as error:
        raise StageLocalError(f"cannot materialize local staging directory: {error}") from error
    finally:
        if not committed:
            shutil.rmtree(temporary, ignore_errors=True)

    return [(plugin, size) for plugin, _, _, _, size in packages]


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    default_repository = Path(__file__).resolve().parents[1]
    parser.add_argument("--repository", type=Path, default=default_repository)
    parser.add_argument("--target-dir", type=Path)
    parser.add_argument("--output-dir", type=Path)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    repository = _absolute_lexical(args.repository)
    target_dir = args.target_dir or repository / "target" / "wasm32-wasip2" / "release"
    output_dir = args.output_dir or repository / "dist" / "local"
    try:
        staged = stage_plugins(repository, target_dir, output_dir)
    except StageLocalError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    for plugin, size in staged:
        print(f"staged {plugin} ({size} bytes)")
    print(f"local components: {_absolute_lexical(output_dir)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
