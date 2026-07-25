#!/usr/bin/env python3
"""Build the ZeroClaw plugin registry.

For each staged plugin directory (containing a `manifest.toml` and its built
`.wasm`), this:
  1. validates the staged plugin against the host's install contract,
  2. zips the directory under a top-level `<name>/` folder — reproducibly:
     fixed timestamps and permissions, so identical content always produces
     an identical zip and sha256 across CI runs (the refreshed registry.json
     only changes when plugin content actually changes),
  3. computes the zip's SHA-256,
  4. merges a `registry.json` entry pointing at the release-asset URL into the
     immutable existing registry history.

The zips are uploaded as GitHub Release assets; only `registry.json` (small,
text) is committed to the repo. `zeroclaw plugin install <name>` reads
`registry.json`, downloads the zip, verifies the SHA-256, and installs it.

Entries are sorted by (name, version). The host resolves an unpinned install
to the LAST matching entry in file order, so within a name the newest version
must sort last — the version key below handles numeric dotted versions.

Requires Python 3.11+ (tomllib). Honors SOURCE_DATE_EPOCH for the embedded
zip timestamps (zip cannot represent dates before 1980-01-01).

It can also synchronize or check the checked-in registry metadata against the
canonical source manifests without rebuilding artifacts.

Usage:
  build-registry.py --staged <dir> --release-base <url> --out <dir> \
    --matrix-json <json> [--existing-registry registry.json]
  build-registry.py --source-plugins plugins --check-metadata registry.json
  build-registry.py --source-plugins plugins --sync-metadata registry.json
  build-registry.py --check-history <base-registry.json> <candidate-registry.json>
  build-registry.py --check-publication <base-registry.json> \
    <candidate-registry.json> <dist-dir>
"""
import argparse
import hashlib
import json
import os
import re
import sys
import time
import zipfile
from pathlib import Path
from urllib.parse import urlsplit

from registry_contract import (
    MAX_PLUGIN_EXTRACTED_BYTES,
    MAX_PLUGIN_ZIP_BYTES,
    PLUGIN_NAME_RE,
    PLUGIN_VERSION_RE,
    WASM_PATH_RE,
    read_package_files,
)

sys.path.insert(0, str(Path(__file__).resolve().parent / "ci"))
from plan_matrix import (  # noqa: E402
    PlanError,
    parse_matrix_policies_json,
    verify_staged_plugins,
)

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover
    sys.exit("error: build-registry.py requires Python 3.11+ (tomllib)")

# The host's manifest schema (crates/zeroclaw-plugins/src/lib.rs). An unknown
# value here makes the host reject the whole manifest at parse time, so catch
# it at publish time.
KNOWN_CAPABILITIES = {"tool", "channel", "memory", "observer", "skill"}
KNOWN_PERMISSIONS = {
    "http_client",
    "file_read",
    "file_write",
    "config_read",
    "env_read",  # serde alias for config_read
    "memory_read",
    "memory_write",
    "socket_client",
    "websocket_client",
}
KNOWN_SENDER_MATCH = {"exact", "case_insensitive", "handle", "email"}

# `manifest.toml` is canonical. These are the manifest-owned fields projected
# into registry entries; release-only `url` and `sha256` are added separately.
REGISTRY_METADATA_FIELDS = (
    "name",
    "version",
    "description",
    "author",
    "capabilities",
    "provides",
    "sender_match",
)
REGISTRY_RELEASE_FIELDS = ("url", "sha256")
ZIP_COMPRESSION_LEVEL = 6


def zip_date_time() -> tuple:
    """Fixed timestamp for reproducible zips (SOURCE_DATE_EPOCH or 1980-01-01)."""
    dos_min = 315532800  # 1980-01-01, the earliest zip can represent
    epoch = int(os.environ.get("SOURCE_DATE_EPOCH", dos_min))
    t = time.gmtime(max(epoch, dos_min))
    return (t.tm_year, t.tm_mon, t.tm_mday, t.tm_hour, t.tm_min, t.tm_sec)


def version_key(version: str) -> tuple:
    """Deterministic SemVer-precedence key with stable releases last."""
    without_build = version.split("+", 1)[0]
    core, separator, prerelease = without_build.partition("-")
    major, minor, patch = (int(part) for part in core.split("."))
    prerelease_key = tuple(
        (0, int(identifier)) if identifier.isdigit() else (1, identifier)
        for identifier in prerelease.split(".")
        if identifier
    )
    release_rank = 0 if separator else 1
    # Build metadata has equal SemVer precedence. The original version is the
    # deterministic tie-breaker for the canonical ledger order.
    return (major, minor, patch, release_rank, prerelease_key, version)


def registry_entry_key(entry: dict) -> tuple:
    """Canonical registry ordering key used by checks and generation."""
    return (entry["name"], version_key(entry["version"]))


def validate_known_array(
    meta: dict, field: str, known_values: set[str], *, required: bool
) -> tuple[list[str], list[str]]:
    """Validate one manifest array against its host-owned vocabulary."""
    value = meta.get(field, [])
    if not isinstance(value, list):
        return [], [f"{field} must be an array"]
    if required and not value:
        return [], [f"{field} must be a non-empty array"]
    if any(not isinstance(item, str) for item in value):
        return [], [f"{field} must contain only strings"]
    errors = [
        f"unknown {field} value {item!r} (host rejects the manifest)"
        for item in sorted(set(value) - known_values)
    ]
    return value, errors


def validate_manifest_metadata(meta: dict, expected_name: str) -> list:
    """Check manifest-owned metadata shared by source and registry views."""
    errors = []
    name = meta.get("name")
    if not isinstance(name, str) or not PLUGIN_NAME_RE.fullmatch(name or ""):
        errors.append(f"name {name!r} must be a lowercase slug")
    elif name != expected_name:
        errors.append(f"name {name!r} does not match expected name {expected_name!r}")

    version = meta.get("version")
    if not isinstance(version, str) or not PLUGIN_VERSION_RE.fullmatch(version):
        errors.append(f"version {version!r} must be a safe semantic version")

    for field in ("description", "author", "provides", "sender_match"):
        value = meta.get(field)
        if value is not None and (not isinstance(value, str) or not value.strip()):
            errors.append(f"{field} must be a non-empty string when present")
    sender_match = meta.get("sender_match")
    if isinstance(sender_match, str) and sender_match not in KNOWN_SENDER_MATCH:
        errors.append(
            f"unknown sender_match {sender_match!r}; expected one of "
            f"{sorted(KNOWN_SENDER_MATCH)!r}"
        )

    _, capability_errors = validate_known_array(
        meta, "capabilities", KNOWN_CAPABILITIES, required=True
    )
    errors.extend(capability_errors)

    return errors


def validate(
    pdir: Path,
    meta: dict,
    *,
    require_wasm: bool = True,
    package_files: dict[str, bytes] | None = None,
) -> list:
    """Check a plugin manifest against the host's install contract."""
    errors = validate_manifest_metadata(meta, pdir.name)

    version = meta.get("version")

    # `manifest.toml` owns the release identity. When validating a source tree,
    # fail if Cargo's build metadata would export a different package version.
    # Staged release directories intentionally omit Cargo.toml.
    cargo_manifest = pdir / "Cargo.toml"
    if cargo_manifest.is_file():
        try:
            cargo_meta = tomllib.loads(cargo_manifest.read_text())
            cargo_version = cargo_meta.get("package", {}).get("version")
            if cargo_version != version:
                errors.append(
                    f"Cargo.toml package.version {cargo_version!r} does not match "
                    f"canonical manifest version {version!r}"
                )
        except (OSError, tomllib.TOMLDecodeError) as error:
            errors.append(f"cannot validate Cargo.toml package.version: {error}")

    registry = meta.get("registry", True)
    if not isinstance(registry, bool):
        errors.append("registry must be a boolean when present")

    _, permission_errors = validate_known_array(
        meta, "permissions", KNOWN_PERMISSIONS, required=False
    )
    errors.extend(permission_errors)

    caps = meta.get("capabilities")
    if not isinstance(caps, list):
        caps = []
    else:
        caps = [cap for cap in caps if isinstance(cap, str)]
    wasm_path = meta.get("wasm_path")
    needs_wasm = bool(set(caps) - {"skill"})
    safe_wasm_path = isinstance(wasm_path, str) and bool(
        WASM_PATH_RE.fullmatch(wasm_path)
    )
    if needs_wasm and not wasm_path:
        errors.append("wasm_path is required for non-skill-only plugins")
    elif wasm_path is not None and not safe_wasm_path:
        errors.append("wasm_path must be a safe relative .wasm filename")
    elif needs_wasm and require_wasm:
        if safe_wasm_path:
            if package_files is None:
                package_files, package_errors = read_package_files(pdir)
                errors.extend(package_errors)
            wasm = package_files.get(wasm_path) if package_files is not None else None
            if wasm is None:
                errors.append(f"wasm_path {wasm_path!r} not found in staged dir")
            elif not wasm:
                errors.append(f"wasm_path {wasm_path!r} is empty")

    if require_wasm:
        if package_files is None:
            package_files, package_errors = read_package_files(pdir)
            errors.extend(package_errors)
        extracted = sum(len(contents) for contents in package_files.values())
        if extracted > MAX_PLUGIN_EXTRACTED_BYTES:
            errors.append(
                f"extracted size {extracted} exceeds the host's "
                f"{MAX_PLUGIN_EXTRACTED_BYTES}-byte install cap"
            )
    return errors


def manifest_registry_metadata(meta: dict) -> dict:
    """Project canonical manifest fields into one registry metadata view."""
    return {
        key: meta[key]
        for key in REGISTRY_METADATA_FIELDS
        if key in meta and meta[key] is not None
    }


def registry_metadata_view(entry: dict) -> dict:
    """Return only canonical-manifest metadata from a registry entry."""
    return {
        key: entry[key]
        for key in REGISTRY_METADATA_FIELDS
        if key in entry and entry[key] is not None
    }


def load_registry(path: Path) -> tuple[dict, dict]:
    """Load a registry and index entries by immutable `(name, version)`."""
    try:
        registry = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"cannot read registry {path}: {error}") from error
    if not isinstance(registry, dict) or set(registry) != {"plugins"}:
        raise ValueError(f"registry {path} must contain only a plugins array")
    entries = registry.get("plugins")
    if not isinstance(entries, list):
        raise ValueError(f"registry {path} must contain a plugins array")

    allowed_fields = set(REGISTRY_METADATA_FIELDS) | {"url", "sha256"}
    by_key = {}
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise ValueError(f"registry entry {index} must be an object")
        name = entry.get("name")
        version = entry.get("version")
        if not isinstance(name, str) or not isinstance(version, str):
            raise ValueError(f"registry entry {index} must have string name and version")
        unexpected_fields = set(entry) - allowed_fields
        if unexpected_fields:
            raise ValueError(
                f"registry entry {index} has unknown fields: {sorted(unexpected_fields)!r}"
            )
        null_fields = sorted(key for key, value in entry.items() if value is None)
        if null_fields:
            raise ValueError(
                f"registry entry {index} has null fields that generation omits: "
                f"{null_fields!r}"
            )
        metadata_errors = validate_manifest_metadata(entry, name)
        if metadata_errors:
            raise ValueError(
                f"registry entry {index} is invalid: {'; '.join(metadata_errors)}"
            )
        url = entry.get("url")
        parsed_url = urlsplit(url) if isinstance(url, str) else None
        expected_asset = f"{name}-{version}.zip"
        if (
            parsed_url is None
            or parsed_url.scheme != "https"
            or not parsed_url.netloc
            or parsed_url.username is not None
            or parsed_url.password is not None
            or parsed_url.query
            or parsed_url.fragment
            or Path(parsed_url.path).name != expected_asset
        ):
            raise ValueError(
                f"registry entry {index} must have an HTTPS url ending in {expected_asset}"
            )
        sha256 = entry.get("sha256")
        if not isinstance(sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", sha256):
            raise ValueError(
                f"registry entry {index} must have a lowercase 64-hex sha256"
            )
        key = (name, version)
        if key in by_key:
            raise ValueError(f"registry {path} has duplicate entry {name}@{version}")
        by_key[key] = entry
    return registry, by_key


def check_registry_history(
    base_path: Path, candidate_path: Path, source_plugins: Path | None = None
) -> None:
    """Preserve release history and allow only canonical metadata refreshes."""
    try:
        _, base_by_key = load_registry(base_path)
        candidate, candidate_by_key = load_registry(candidate_path)
    except ValueError as error:
        sys.exit(f"error: {error}")

    failures = []
    canonical_metadata = {}
    if source_plugins is not None:
        canonical_metadata, _, source_failures = source_manifest_metadata(source_plugins)
        failures.extend(source_failures)

    metadata_refreshes = 0
    for (name, version), historical in base_by_key.items():
        current = candidate_by_key.get((name, version))
        if current is None:
            failures.append(f"historical registry entry was deleted: {name}@{version}")
            continue
        if any(current[field] != historical[field] for field in REGISTRY_RELEASE_FIELDS):
            failures.append(f"immutable release fields were changed: {name}@{version}")
            continue
        if current != historical:
            expected = canonical_metadata.get((name, version))
            if expected is None or registry_metadata_view(current) != expected:
                failures.append(f"historical registry entry was changed: {name}@{version}")
            else:
                metadata_refreshes += 1

    for name, version in sorted(candidate_by_key.keys() - base_by_key.keys()):
        failures.append(
            f"registry entry was added outside the publication builder: {name}@{version}"
        )

    expected_order = sorted(candidate["plugins"], key=registry_entry_key)
    if candidate["plugins"] != expected_order:
        failures.append("candidate registry entries are not in canonical name/version order")

    for index, entry in enumerate(candidate["plugins"]):
        expected_fields = [
            field for field in REGISTRY_METADATA_FIELDS if field in entry
        ] + list(REGISTRY_RELEASE_FIELDS)
        if list(entry) != expected_fields:
            failures.append(f"candidate registry entry {index} has non-canonical field order")

    try:
        candidate_text = candidate_path.read_text()
    except OSError as error:
        failures.append(f"cannot reread candidate registry {candidate_path}: {error}")
    else:
        canonical_text = json.dumps(candidate, indent=2) + "\n"
        if candidate_text != canonical_text:
            failures.append("candidate registry does not use canonical JSON formatting")

    if failures:
        for failure in failures:
            print(f"error: {failure}", file=sys.stderr)
        sys.exit(1)

    print(
        f"registry preserves {len(base_by_key)} generated release entries "
        f"with {metadata_refreshes} canonical metadata refresh(es)"
    )


def check_publication_artifacts(
    base_path: Path, candidate_path: Path, dist: Path
) -> None:
    """Require dist files to equal the candidate registry's immutable additions."""
    try:
        _, base_by_key = load_registry(base_path)
        candidate, candidate_by_key = load_registry(candidate_path)
    except ValueError as error:
        sys.exit(f"error: {error}")

    failures = []
    for key, historical in base_by_key.items():
        current = candidate_by_key.get(key)
        if current is None:
            failures.append(
                f"publication candidate deleted {key[0]}@{key[1]}"
            )
        elif current != historical:
            failures.append(
                f"publication candidate changed existing {key[0]}@{key[1]}"
            )

    new_keys = candidate_by_key.keys() - base_by_key.keys()
    expected_archives = {
        f"{name}-{version}.zip": candidate_by_key[(name, version)]["sha256"]
        for name, version in new_keys
    }
    expected_files = {"registry.json", *expected_archives}

    try:
        paths = list(dist.iterdir())
    except OSError as error:
        failures.append(f"cannot inspect publication directory {dist}: {error}")
        paths = []
    actual_files = set()
    for path in paths:
        actual_files.add(path.name)
        if path.is_symlink() or not path.is_file():
            failures.append(
                f"publication entry must be a regular non-symbolic file: {path.name}"
            )

    missing = sorted(expected_files - actual_files)
    unexpected = sorted(actual_files - expected_files)
    if missing:
        failures.append(f"publication files are missing: {missing!r}")
    if unexpected:
        failures.append(f"publication files are unexpected: {unexpected!r}")

    expected_candidate = dist / "registry.json"
    if candidate_path.absolute() != expected_candidate.absolute():
        failures.append("candidate registry must be dist/registry.json")
    try:
        candidate_text = candidate_path.read_text()
    except OSError as error:
        failures.append(f"cannot reread publication candidate: {error}")
    else:
        if candidate_text != json.dumps(candidate, indent=2) + "\n":
            failures.append("publication registry does not use canonical JSON formatting")
        if candidate["plugins"] != sorted(candidate["plugins"], key=registry_entry_key):
            failures.append("publication registry entries are not canonically ordered")

    for archive_name, expected_sha in sorted(expected_archives.items()):
        archive = dist / archive_name
        if archive_name not in actual_files or archive.is_symlink() or not archive.is_file():
            continue
        if archive.stat().st_size > MAX_PLUGIN_ZIP_BYTES:
            failures.append(
                f"publication archive {archive_name} exceeds the host download cap"
            )
            continue
        actual_sha = hashlib.sha256(archive.read_bytes()).hexdigest()
        if actual_sha != expected_sha:
            failures.append(
                f"publication archive {archive_name} sha256 {actual_sha} "
                f"does not match ledger {expected_sha}"
            )

    if failures:
        for failure in failures:
            print(f"error: {failure}", file=sys.stderr)
        sys.exit(1)

    print(
        f"verified exact publication set with {len(expected_archives)} new "
        f"archive{'s' if len(expected_archives) != 1 else ''}"
    )


def source_manifest_metadata(source_plugins: Path) -> tuple[dict, set, list]:
    """Load current canonical source metadata, including registry opt-outs."""
    enabled = {}
    disabled = set()
    failures = []
    for pdir in sorted(source_plugins.iterdir()):
        if pdir.is_symlink():
            failures.append(f"{pdir.name}: plugin directory must not be a symbolic link")
            continue
        if not pdir.is_dir():
            continue
        manifest = pdir / "manifest.toml"
        if not manifest.exists():
            continue
        try:
            meta = tomllib.loads(manifest.read_text())
        except (OSError, tomllib.TOMLDecodeError) as error:
            failures.append(f"{pdir.name}: invalid manifest.toml: {error}")
            continue
        errors = validate(pdir, meta, require_wasm=False)
        if errors:
            failures.extend(f"{pdir.name}: {error}" for error in errors)
            continue
        key = (meta["name"], meta["version"])
        if key in enabled or key in disabled:
            failures.append(f"{pdir.name}: duplicate source entry {key[0]}@{key[1]}")
            continue
        if meta.get("registry") is False:
            disabled.add(key)
        else:
            enabled[key] = manifest_registry_metadata(meta)
    return enabled, disabled, failures


def sync_registry_metadata(source_plugins: Path, registry_path: Path, *, check: bool) -> None:
    """Synchronize current registry metadata from canonical source manifests."""
    try:
        registry, actual_by_key = load_registry(registry_path)
    except ValueError as error:
        sys.exit(f"error: {error}")
    expected, disabled, failures = source_manifest_metadata(source_plugins)
    changed = False
    matched = 0
    pending = []

    for key, metadata in expected.items():
        actual = actual_by_key.get(key)
        if actual is None:
            # A source manifest becomes indexable only after its immutable
            # artifact is built. Missing keys are pending new versions/plugins,
            # not metadata drift; packaging adds them with URL + digest.
            pending.append(key)
            continue
        matched += 1
        actual_metadata = registry_metadata_view(actual)
        if actual_metadata == metadata:
            continue
        if check:
            failures.append(
                f"registry metadata drift for {key[0]}@{key[1]}: "
                f"expected {metadata!r}, found {actual_metadata!r}"
            )
            continue
        release_fields = {
            key: value for key, value in actual.items() if key not in REGISTRY_METADATA_FIELDS
        }
        actual.clear()
        actual.update(metadata)
        actual.update(release_fields)
        changed = True

    disabled_present = disabled & actual_by_key.keys()
    for key in sorted(disabled_present):
        failures.append(
            f"registry=false plugin is already indexed: {key[0]}@{key[1]}; "
            "publish a new source version instead of deleting history"
        )

    if failures:
        for failure in failures:
            print(f"error: {failure}", file=sys.stderr)
        sys.exit(1)

    if check:
        print(f"registry metadata matches {matched} indexed canonical manifest entries")
        for name, version in pending:
            print(f"  pending unpublished source: {name}@{version}")
        return
    if changed:
        tmp = registry_path.with_suffix(f"{registry_path.suffix}.tmp")
        tmp.write_text(json.dumps(registry, indent=2) + "\n")
        os.replace(tmp, registry_path)
        print(f"synchronized registry metadata for {matched} indexed entries")
    else:
        print("registry metadata already synchronized")
    for name, version in pending:
        print(f"  pending unpublished source: {name}@{version}")


def write_zip(zip_path: Path, package_files: dict[str, bytes], name: str) -> None:
    """Zip materialized package bytes under `<name>/`, reproducibly."""
    date_time = zip_date_time()
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as z:
        for relative, contents in sorted(package_files.items()):
            info = zipfile.ZipInfo(
                f"{name}/{relative}", date_time=date_time
            )
            info.create_system = 3
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            z.writestr(
                info,
                contents,
                compress_type=zipfile.ZIP_DEFLATED,
                compresslevel=ZIP_COMPRESSION_LEVEL,
            )


def main() -> None:
    ap = argparse.ArgumentParser(description="Build the ZeroClaw plugin registry")
    ap.add_argument("--staged", help="dir of <plugin>/{manifest.toml,*.wasm}")
    ap.add_argument("--release-base", help="base URL for release assets")
    ap.add_argument("--out", help="output dir for zips + registry.json")
    ap.add_argument(
        "--existing-registry",
        help="immutable registry history to merge; changed name/version pairs fail",
    )
    ap.add_argument("--source-plugins", help="canonical plugins source directory")
    ap.add_argument(
        "--matrix-json",
        help="canonical CI matrix defining exact staged identities and changed plugins",
    )
    ap.add_argument(
        "--check-history",
        nargs=2,
        metavar=("BASE", "CANDIDATE"),
        help="preserve BASE release history in CANDIDATE",
    )
    ap.add_argument(
        "--check-publication",
        nargs=3,
        metavar=("BASE", "CANDIDATE", "DIST"),
        help="verify exact new archive files and digests from BASE to CANDIDATE",
    )
    metadata_mode = ap.add_mutually_exclusive_group()
    metadata_mode.add_argument("--check-metadata", help="fail if registry metadata has drifted")
    metadata_mode.add_argument("--sync-metadata", help="rewrite registry metadata from manifests")
    args = ap.parse_args()

    if args.check_publication:
        if any(
            (
                args.staged,
                args.release_base,
                args.out,
                args.existing_registry,
                args.source_plugins,
                args.check_history,
                args.check_metadata,
                args.sync_metadata,
                args.matrix_json,
            )
        ):
            ap.error("--check-publication cannot be combined with other modes")
        check_publication_artifacts(
            *(Path(path) for path in args.check_publication)
        )
        return

    if args.check_history:
        if any(
            (
                args.staged,
                args.release_base,
                args.out,
                args.existing_registry,
                args.check_metadata,
                args.sync_metadata,
                args.matrix_json,
                args.check_publication,
            )
        ):
            ap.error("--check-history cannot be combined with packaging or metadata modes")
        check_registry_history(
            *(Path(path) for path in args.check_history),
            Path(args.source_plugins) if args.source_plugins else None,
        )
        return

    metadata_registry = args.check_metadata or args.sync_metadata
    if metadata_registry:
        if args.matrix_json:
            ap.error("--matrix-json cannot be combined with metadata modes")
        if not args.source_plugins:
            ap.error("--source-plugins is required with metadata modes")
        sync_registry_metadata(
            Path(args.source_plugins),
            Path(metadata_registry),
            check=bool(args.check_metadata),
        )
        return
    if not args.staged or not args.release_base or not args.out or not args.matrix_json:
        ap.error(
            "--staged, --release-base, --out, and --matrix-json are required "
            "for packaging"
        )

    staged = Path(args.staged)
    out = Path(args.out)
    try:
        planned_policy, release_plugins = parse_matrix_policies_json(args.matrix_json)
        verify_staged_plugins(staged.resolve(), planned_policy)
    except PlanError as error:
        sys.exit(f"error: {error}")
    if out.exists() or out.is_symlink():
        sys.exit(f"error: packaging output path must not already exist: {out}")
    try:
        out.mkdir(parents=True)
    except OSError as error:
        sys.exit(f"error: cannot create packaging output directory {out}: {error}")
    print(f"verified {len(planned_policy)} planned staged plugin(s)")

    entries = []
    existing_by_key = {}
    if args.existing_registry:
        try:
            existing, existing_by_key = load_registry(Path(args.existing_registry))
        except ValueError as error:
            sys.exit(f"error: {error}")
        entries.extend(existing["plugins"])
    failures = []
    seen = set()
    for pdir in sorted(staged.iterdir()):
        if pdir.is_symlink():
            failures.append(f"{pdir.name}: staged plugin must not be a symbolic link")
            continue
        if not pdir.is_dir():
            continue
        package_files, package_errors = read_package_files(pdir)
        if package_errors:
            failures.extend(f"{pdir.name}: {error}" for error in package_errors)
            continue
        manifest_bytes = package_files.get("manifest.toml")
        if manifest_bytes is None:
            failures.append(f"{pdir.name}: staged plugin is missing manifest.toml")
            continue
        try:
            meta = tomllib.loads(manifest_bytes.decode("utf-8"))
        except (UnicodeDecodeError, tomllib.TOMLDecodeError) as e:
            failures.append(f"{pdir.name}: invalid manifest.toml: {e}")
            continue

        # Host-gated / source-only plugins opt out of the install registry with
        # `registry = false`. Their source can land before the required host
        # capability is safe to publish, but stock hosts must not be offered an
        # entry they cannot run.
        if meta.get("registry") is False:
            print(f"  skipping {pdir.name} (registry = false: host-gated source)")
            continue

        errors = validate(pdir, meta, package_files=package_files)
        if errors:
            failures.extend(f"{pdir.name}: {e}" for e in errors)
            continue

        name = meta["name"]
        version = meta["version"]
        if (name, version) in seen:
            failures.append(f"{pdir.name}: duplicate entry {name}@{version}")
            continue
        seen.add((name, version))

        existing_entry = existing_by_key.get((name, version))
        if existing_entry is not None:
            if registry_metadata_view(existing_entry) != manifest_registry_metadata(meta):
                failures.append(
                    f"{pdir.name}: registry metadata drift for existing package "
                    f"{name}@{version}; synchronize metadata before publishing"
                )
                continue
            if name in release_plugins:
                failures.append(
                    f"{pdir.name}: changed release input reuses immutable package identity "
                    f"{name}@{version}; bump the canonical manifest version before "
                    "publishing"
                )
                continue
            print(
                f"  reused immutable {name} v{version}  "
                f"sha256={existing_entry['sha256'][:12]}…"
            )
            continue

        zip_name = f"{name}-{version}.zip"
        zip_path = out / zip_name
        write_zip(zip_path, package_files, name)

        if zip_path.stat().st_size > MAX_PLUGIN_ZIP_BYTES:
            failures.append(
                f"{pdir.name}: zip size {zip_path.stat().st_size} exceeds the "
                f"host's {MAX_PLUGIN_ZIP_BYTES}-byte download cap"
            )
            continue

        sha = hashlib.sha256(zip_path.read_bytes()).hexdigest()
        entry = {
            **manifest_registry_metadata(meta),
            "url": f"{args.release_base.rstrip('/')}/{zip_name}",
            "sha256": sha,
        }
        entries.append(entry)
        print(f"  packaged {name} v{version}  sha256={sha[:12]}…")

    if failures:
        for f in failures:
            print(f"error: {f}", file=sys.stderr)
        sys.exit(1)

    # Host install-by-name takes the last matching entry: newest must sort last.
    entries.sort(key=registry_entry_key)

    tmp = out / "registry.json.tmp"
    tmp.write_text(json.dumps({"plugins": entries}, indent=2) + "\n")
    os.replace(tmp, out / "registry.json")
    print(f"wrote registry.json with {len(entries)} entr{'y' if len(entries) == 1 else 'ies'}")


if __name__ == "__main__":
    main()
