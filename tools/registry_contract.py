"""Canonical host-facing contracts for plugin registry artifacts."""

import os
import re
import stat
from pathlib import Path

PLUGIN_RELEASE_TAG = "plugins"

# Mirrors src/plugin_registry.rs MAX_PLUGIN_ZIP_BYTES. Packaging enforces this
# value and CI summaries render artifact size against the same source.
MAX_PLUGIN_ZIP_BYTES = 50 * 1024 * 1024
MAX_PLUGIN_EXTRACTED_BYTES = 50 * 1024 * 1024

PLUGIN_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]*$")
SEMVER_NUMERIC_IDENTIFIER = r"(?:0|[1-9][0-9]*)"
SEMVER_PRERELEASE_IDENTIFIER = (
    rf"(?:{SEMVER_NUMERIC_IDENTIFIER}|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)"
)
SEMVER_BUILD_IDENTIFIER = r"[0-9A-Za-z-]+"
PLUGIN_VERSION_RE = re.compile(
    rf"^{SEMVER_NUMERIC_IDENTIFIER}\."
    rf"{SEMVER_NUMERIC_IDENTIFIER}\."
    rf"{SEMVER_NUMERIC_IDENTIFIER}"
    rf"(?:-{SEMVER_PRERELEASE_IDENTIFIER}"
    rf"(?:\.{SEMVER_PRERELEASE_IDENTIFIER})*)?"
    rf"(?:\+{SEMVER_BUILD_IDENTIFIER}(?:\.{SEMVER_BUILD_IDENTIFIER})*)?$"
)
WASM_PATH_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*\.wasm$")


def package_tree_errors(root: Path) -> list[str]:
    """Reject links and non-regular nodes before packaging or artifact upload."""
    if root.is_symlink():
        return [f"package root must not be a symbolic link: {root}"]
    if not root.is_dir():
        return [f"package root must be a directory: {root}"]

    errors = []
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root)
        if path.is_symlink():
            errors.append(f"symbolic links are not allowed in packages: {relative}")
        elif not path.is_dir() and not path.is_file():
            errors.append(f"non-regular package entry is not allowed: {relative}")
    return errors


def read_regular_file(path: Path, *, byte_limit: int) -> bytes:
    """Read one regular file through a no-follow descriptor."""
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, os.O_RDONLY | nofollow)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError(f"not a regular file: {path}")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            contents = handle.read(byte_limit + 1)
        if len(contents) > byte_limit:
            raise ValueError(f"file exceeds {byte_limit}-byte limit: {path}")
        return contents
    finally:
        os.close(descriptor)


def copy_regular_file(source: Path, destination: Path, *, byte_limit: int) -> int:
    """Materialize a no-follow regular-file read at a new exclusive path."""
    contents = read_regular_file(source, byte_limit=byte_limit)
    destination.parent.mkdir(parents=True, exist_ok=True)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(
        destination,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | nofollow,
        0o600,
    )
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as handle:
            handle.write(contents)
    finally:
        os.close(descriptor)
    return len(contents)


def read_package_files(root: Path) -> tuple[dict[str, bytes], list[str]]:
    """Materialize regular package bytes once, without following links."""
    errors = package_tree_errors(root)
    if errors:
        return {}, errors

    files = {}
    total_bytes = 0
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(root).as_posix()
        try:
            remaining = MAX_PLUGIN_EXTRACTED_BYTES - total_bytes
            contents = read_regular_file(path, byte_limit=remaining)
            total_bytes += len(contents)
            files[relative] = contents
        except (OSError, ValueError) as error:
            errors.append(f"cannot read package entry {relative}: {error}")
    return files, errors
