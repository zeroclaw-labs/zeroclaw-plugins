#!/usr/bin/env python3
"""Plan changed-plugin or full component-validation shards."""

from __future__ import annotations

import argparse
import json
import math
import os
import subprocess
import sys
from pathlib import Path, PurePosixPath

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from registry_contract import PLUGIN_NAME_RE

DEFAULT_SHARD_SIZE = 8
DEFAULT_MAX_SHARDS = 4
FULL_SWEEP_PREFIXES = (".github/", "tools/", "wit/")
FULL_SWEEP_FILES = {"registry.json"}
DOC_ONLY_PREFIXES = ("docs/",)
DOC_ONLY_FILES = {"README.md"}


class PlanError(ValueError):
    pass


def plugin_directories(plugins_dir: Path) -> list[str]:
    if not plugins_dir.is_dir():
        raise PlanError(f"plugins directory does not exist: {plugins_dir}")
    plugins = []
    for path in plugins_dir.iterdir():
        if path.is_symlink():
            raise PlanError(f"plugin directory must not be a symbolic link: {path.name!r}")
        if not path.is_dir():
            continue
        if not PLUGIN_NAME_RE.fullmatch(path.name):
            raise PlanError(f"invalid plugin directory name: {path.name!r}")
        plugins.append(path.name)
    return sorted(plugins)


def repository_plugins(repository: Path) -> list[str]:
    return plugin_directories(repository / "plugins")


def _plugin_list(value: object, *, context: str, allow_empty: bool) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise PlanError(f"{context} must be an array of plugin names")
    if not allow_empty and not value:
        raise PlanError(f"{context} must not be empty")
    invalid = sorted({item for item in value if not PLUGIN_NAME_RE.fullmatch(item)})
    if invalid:
        raise PlanError(f"{context} has invalid plugin names: {invalid!r}")
    duplicates = sorted({item for item in value if value.count(item) > 1})
    if duplicates:
        raise PlanError(f"{context} has duplicate plugins: {duplicates!r}")
    return value


def planned_matrix_policies(matrix: object) -> tuple[dict[str, bool], set[str]]:
    """Resolve exact plugin, lint-strictness, and release-input policies."""
    if not isinstance(matrix, dict) or set(matrix) != {"include"}:
        raise PlanError("matrix must contain only an include array")
    includes = matrix["include"]
    if not isinstance(includes, list):
        raise PlanError("matrix include must be an array")

    policy = {}
    release_policy = set()
    shard_ids = []
    flattened = []
    for index, shard in enumerate(includes):
        context = f"matrix include[{index}]"
        if not isinstance(shard, dict) or set(shard) != {
            "id",
            "plugins",
            "release_plugins",
            "strict_plugins",
        }:
            raise PlanError(
                f"{context} must contain exactly id, plugins, release_plugins, "
                "and strict_plugins"
            )
        shard_id = shard["id"]
        if isinstance(shard_id, bool) or not isinstance(shard_id, int) or shard_id < 0:
            raise PlanError(f"{context} id must be a non-negative integer")
        shard_ids.append(shard_id)
        plugins = _plugin_list(
            shard["plugins"], context=f"{context} plugins", allow_empty=False
        )
        strict_plugins = _plugin_list(
            shard["strict_plugins"],
            context=f"{context} strict_plugins",
            allow_empty=True,
        )
        release_plugins = _plugin_list(
            shard["release_plugins"],
            context=f"{context} release_plugins",
            allow_empty=True,
        )
        strict_outside = sorted(set(strict_plugins) - set(plugins))
        if strict_outside:
            raise PlanError(
                f"{context} strict_plugins are outside the shard: {strict_outside!r}"
            )
        release_outside = sorted(set(release_plugins) - set(plugins))
        if release_outside:
            raise PlanError(
                f"{context} release_plugins are outside the shard: "
                f"{release_outside!r}"
            )
        for plugin in plugins:
            if plugin in policy:
                raise PlanError(f"matrix repeats plugin across shards: {plugin!r}")
            policy[plugin] = plugin in strict_plugins
            flattened.append(plugin)
        release_policy.update(release_plugins)

    if shard_ids != list(range(len(includes))):
        raise PlanError("matrix shard ids must be unique and sequential from zero")
    if flattened != sorted(flattened):
        raise PlanError("matrix plugins must be in canonical sorted order")
    return policy, release_policy


def planned_plugin_policy(matrix: object) -> dict[str, bool]:
    """Resolve the canonical matrix into exact plugin/strictness policy."""
    return planned_matrix_policies(matrix)[0]


def _parse_matrix_document(value: str) -> object:
    if not value.strip():
        raise PlanError("matrix JSON must not be empty")
    try:
        return json.loads(value)
    except json.JSONDecodeError as error:
        raise PlanError(f"invalid matrix JSON: {error}") from error


def parse_matrix_json(value: str) -> dict[str, bool]:
    return planned_plugin_policy(_parse_matrix_document(value))


def parse_matrix_policies_json(value: str) -> tuple[dict[str, bool], set[str]]:
    return planned_matrix_policies(_parse_matrix_document(value))


def verify_staged_plugins(staged: Path, policy: dict[str, bool]) -> None:
    """Require staged component directories to match the planned identities."""
    expected = set(policy)
    actual = set(plugin_directories(staged))
    missing = sorted(expected - actual)
    unexpected = sorted(actual - expected)
    if missing or unexpected:
        details = []
        if missing:
            details.append(f"missing staged plugins: {missing!r}")
        if unexpected:
            details.append(f"unexpected staged plugins: {unexpected!r}")
        raise PlanError("; ".join(details))


def git_changed_paths(repository: Path, base: str) -> list[str]:
    try:
        merge_base = subprocess.run(
            ["git", "merge-base", base, "HEAD"],
            cwd=repository,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        if not merge_base:
            raise PlanError(f"git merge-base {base} HEAD returned no object ID")
        raw = subprocess.run(
            [
                "git",
                "diff",
                "--name-only",
                "--diff-filter=ACDMRTUXB",
                "-z",
                merge_base,
                "HEAD",
                "--",
            ],
            cwd=repository,
            check=True,
            capture_output=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError) as error:
        stderr = getattr(error, "stderr", b"")
        if isinstance(stderr, bytes):
            stderr = stderr.decode("utf-8", errors="replace")
        detail = str(stderr).strip()
        raise PlanError(f"cannot compute changes from {base}: {detail or error}") from error
    try:
        return [part.decode("utf-8") for part in raw.split(b"\0") if part]
    except UnicodeDecodeError as error:
        raise PlanError("changed paths must be valid UTF-8") from error


def requires_full_sweep(changed_paths: list[str]) -> bool:
    for raw_path in changed_paths:
        path = PurePosixPath(raw_path).as_posix().removeprefix("./")
        if path in FULL_SWEEP_FILES or path.startswith(FULL_SWEEP_PREFIXES):
            return True
        if path in DOC_ONLY_FILES or path.startswith(DOC_ONLY_PREFIXES):
            continue
        parts = PurePosixPath(path).parts
        if (
            len(parts) >= 2
            and parts[0] == "plugins"
            and PLUGIN_NAME_RE.fullmatch(parts[1])
        ):
            continue
        # Unknown root-level or future build configuration is safety-relevant
        # until it is deliberately classified as documentation-only.
        return True
    return False


def changed_plugins(changed_paths: list[str], available: list[str]) -> list[str]:
    available_set = set(available)
    selected = set()
    for raw_path in changed_paths:
        parts = PurePosixPath(raw_path).parts
        if len(parts) < 2 or parts[0] != "plugins":
            continue
        plugin = parts[1]
        if not PLUGIN_NAME_RE.fullmatch(plugin):
            raise PlanError(f"changed path has invalid plugin name: {raw_path!r}")
        if plugin in available_set:
            selected.add(plugin)
    return sorted(selected)


def shard_plugins(
    plugins: list[str], shard_size: int = DEFAULT_SHARD_SIZE, max_shards: int = DEFAULT_MAX_SHARDS
) -> list[list[str]]:
    if shard_size <= 0:
        raise PlanError("shard size must be positive")
    if max_shards <= 0:
        raise PlanError("maximum shard count must be positive")
    if not plugins:
        return []
    desired = math.ceil(len(plugins) / shard_size)
    shard_count = min(desired, max_shards)
    if desired <= max_shards:
        return [plugins[index : index + shard_size] for index in range(0, len(plugins), shard_size)]

    minimum_size, larger_shards = divmod(len(plugins), shard_count)
    shards = []
    offset = 0
    for shard_index in range(shard_count):
        size = minimum_size + (1 if shard_index < larger_shards else 0)
        shards.append(plugins[offset : offset + size])
        offset += size
    return shards


def make_plan(
    repository: Path,
    event: str,
    base: str,
    shard_size: int = DEFAULT_SHARD_SIZE,
    max_shards: int = DEFAULT_MAX_SHARDS,
) -> dict[str, object]:
    available = repository_plugins(repository)
    paths = []
    if event == "pull_request":
        paths = git_changed_paths(repository, base)
        if requires_full_sweep(paths):
            mode = "full"
            selected = available
        else:
            mode = "changed"
            selected = changed_plugins(paths, available)
    else:
        # Reusable workflows retain the caller's event name. A publish call
        # originates from push/dispatch and therefore intentionally lands here.
        mode = "full"
        selected = available
        if event == "push" and base and base != "0" * 40:
            paths = git_changed_paths(repository, base)

    strict = set(changed_plugins(paths, available))
    release_all = any(
        PurePosixPath(path).as_posix().removeprefix("./").startswith("wit/v0/")
        for path in paths
    )
    release = set(available) if release_all else strict

    shards = shard_plugins(selected, shard_size=shard_size, max_shards=max_shards)
    matrix = {
        "include": [
            {
                "id": shard_id,
                "plugins": shard,
                "release_plugins": [plugin for plugin in shard if plugin in release],
                "strict_plugins": [plugin for plugin in shard if plugin in strict],
            }
            for shard_id, shard in enumerate(shards)
        ]
    }
    return {
        "matrix": matrix,
        "mode": mode,
        "count": len(planned_plugin_policy(matrix)),
    }


def write_github_outputs(path: Path, plan: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(f"matrix={json.dumps(plan['matrix'], separators=(',', ':'))}\n")
        handle.write(f"mode={plan['mode']}\n")
        handle.write(f"count={plan['count']}\n")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, default=Path.cwd())
    parser.add_argument("--event", default=os.environ.get("GITHUB_EVENT_NAME", "workflow_dispatch"))
    parser.add_argument(
        "--base",
        default=os.environ.get("GITHUB_EVENT_BEFORE") or "origin/main",
    )
    parser.add_argument("--shard-size", type=int, default=DEFAULT_SHARD_SIZE)
    parser.add_argument("--max-shards", type=int, default=DEFAULT_MAX_SHARDS)
    parser.add_argument("--matrix-json")
    parser.add_argument("--verify-staged", type=Path)
    parser.add_argument("--output", type=Path, default=None)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    output = args.output
    if output is None and os.environ.get("GITHUB_OUTPUT"):
        output = Path(os.environ["GITHUB_OUTPUT"])
    try:
        if args.verify_staged is not None:
            if args.matrix_json is None:
                raise PlanError("--matrix-json is required with --verify-staged")
            policy = parse_matrix_json(args.matrix_json)
            verify_staged_plugins(args.verify_staged.resolve(), policy)
            print(f"verified {len(policy)} planned staged plugin(s)")
            return 0
        if args.matrix_json is not None:
            raise PlanError("--matrix-json requires --verify-staged")
        plan = make_plan(
            args.repository.resolve(),
            args.event,
            args.base,
            shard_size=args.shard_size,
            max_shards=args.max_shards,
        )
        if output is not None:
            write_github_outputs(output, plan)
    except PlanError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    print(json.dumps(plan, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
