#!/usr/bin/env python3
"""Discover repository-local Cargo path dependency closures safely."""

from __future__ import annotations

import argparse
import os
import stat
import sys
import tomllib
from collections.abc import Iterator
from pathlib import Path, PurePosixPath

DEPENDENCY_TABLES = ("dependencies", "dev-dependencies", "build-dependencies")


class CargoPathDependencyError(ValueError):
    pass


def _load_manifest(manifest: Path) -> dict[str, object]:
    try:
        with manifest.open("rb") as handle:
            document = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise CargoPathDependencyError(f"cannot read Cargo manifest {manifest}: {error}") from error
    return document


def _dependency_tables(document: dict[str, object]) -> Iterator[dict[str, object]]:
    for table_name in DEPENDENCY_TABLES:
        table = document.get(table_name)
        if table is not None:
            if not isinstance(table, dict):
                raise CargoPathDependencyError(f"Cargo {table_name} must be a table")
            yield table

    targets = document.get("target", {})
    if not isinstance(targets, dict):
        raise CargoPathDependencyError("Cargo target must be a table")
    for target_name, target in targets.items():
        if not isinstance(target, dict):
            raise CargoPathDependencyError(f"Cargo target {target_name!r} must be a table")
        for table_name in DEPENDENCY_TABLES:
            table = target.get(table_name)
            if table is not None:
                if not isinstance(table, dict):
                    raise CargoPathDependencyError(
                        f"Cargo target {target_name!r} {table_name} must be a table"
                    )
                yield table


def _path_specs(manifest: Path) -> Iterator[str]:
    document = _load_manifest(manifest)
    for table in _dependency_tables(document):
        for dependency_name, specification in table.items():
            if not isinstance(specification, dict) or "path" not in specification:
                continue
            path = specification["path"]
            if not isinstance(path, str) or not path:
                raise CargoPathDependencyError(
                    f"path for Cargo dependency {dependency_name!r} in {manifest} "
                    "must be a non-empty string"
                )
            yield path


def _absolute_lexical(path: Path) -> Path:
    return Path(os.path.abspath(os.fspath(path)))


def _repository_relative(repository: Path, path: Path, *, context: str) -> Path:
    try:
        relative = path.relative_to(repository)
    except ValueError as error:
        raise CargoPathDependencyError(f"{context} escapes repository: {path}") from error
    if not relative.parts:
        raise CargoPathDependencyError(f"{context} resolves to the repository root")
    return relative


def _reject_symlinks(repository: Path, relative: Path, *, context: str) -> None:
    current = repository
    for part in relative.parts:
        current = current / part
        try:
            mode = current.lstat().st_mode
        except OSError as error:
            raise CargoPathDependencyError(f"cannot inspect {context} {current}: {error}") from error
        if stat.S_ISLNK(mode):
            raise CargoPathDependencyError(f"{context} must not contain a symbolic link: {current}")

    for current_root, directory_names, file_names in os.walk(repository / relative):
        root = Path(current_root)
        for name in directory_names + file_names:
            candidate = root / name
            try:
                mode = candidate.lstat().st_mode
            except OSError as error:
                raise CargoPathDependencyError(
                    f"cannot inspect {context} {candidate}: {error}"
                ) from error
            if stat.S_ISLNK(mode):
                raise CargoPathDependencyError(
                    f"{context} must not contain a symbolic link: {candidate}"
                )


def cargo_path_dependency_closure(repository: Path, manifest: Path) -> list[Path]:
    """Return repository-relative package directories in transitive closure order."""
    repository = _absolute_lexical(repository)
    manifest = _absolute_lexical(manifest)
    if not repository.is_dir():
        raise CargoPathDependencyError(f"repository does not exist: {repository}")
    _repository_relative(repository, manifest, context="Cargo manifest")
    if manifest.is_symlink() or not manifest.is_file():
        raise CargoPathDependencyError(f"Cargo manifest must be a regular file: {manifest}")

    pending = [manifest]
    visited_manifests = {manifest}
    dependencies: set[Path] = set()
    while pending:
        current_manifest = pending.pop()
        for raw_path in _path_specs(current_manifest):
            if "\x00" in raw_path or "\n" in raw_path or "\r" in raw_path:
                raise CargoPathDependencyError(
                    f"unsafe Cargo dependency path in {current_manifest}: {raw_path!r}"
                )
            declared = Path(raw_path)
            if declared.is_absolute():
                raise CargoPathDependencyError(
                    f"Cargo dependency path must be relative in {current_manifest}: {raw_path!r}"
                )
            dependency = _absolute_lexical(current_manifest.parent / declared)
            relative = _repository_relative(
                repository,
                dependency,
                context=f"Cargo dependency {raw_path!r} from {current_manifest}",
            )
            if not dependency.is_dir():
                raise CargoPathDependencyError(
                    f"Cargo path dependency is missing or not a directory: {dependency}"
                )
            _reject_symlinks(repository, relative, context="Cargo path dependency")
            dependency_manifest = dependency / "Cargo.toml"
            if dependency_manifest.is_symlink() or not dependency_manifest.is_file():
                raise CargoPathDependencyError(
                    f"Cargo path dependency has no regular Cargo.toml: {dependency}"
                )
            dependencies.add(relative)
            if dependency_manifest not in visited_manifests:
                visited_manifests.add(dependency_manifest)
                pending.append(dependency_manifest)

    return sorted(dependencies, key=lambda path: PurePosixPath(path.as_posix()).parts)


def plugin_dependency_map(repository: Path, plugins: list[str]) -> dict[str, set[str]]:
    """Map each repository-relative dependency root to dependent plugins."""
    mapping: dict[str, set[str]] = {}
    for plugin in plugins:
        manifest = repository / "plugins" / plugin / "Cargo.toml"
        for dependency in cargo_path_dependency_closure(repository, manifest):
            plugin_root = Path("plugins") / plugin
            if dependency == plugin_root or plugin_root in dependency.parents:
                continue
            mapping.setdefault(dependency.as_posix(), set()).add(plugin)
    return mapping


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--plugin", required=True)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        dependencies = cargo_path_dependency_closure(
            args.repository,
            args.repository / "plugins" / args.plugin / "Cargo.toml",
        )
    except CargoPathDependencyError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    for dependency in dependencies:
        print(dependency.as_posix())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
