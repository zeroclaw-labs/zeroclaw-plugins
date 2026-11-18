import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
BUILD_REGISTRY = REPOSITORY_ROOT / "tools" / "build-registry.py"
RELEASE_BASE = "https://example.invalid/releases/download/plugins"
sys.path.insert(0, str(REPOSITORY_ROOT / "tools"))

import registry_contract  # noqa: E402
from registry_contract import PLUGIN_VERSION_RE  # noqa: E402
sys.path.insert(0, str(REPOSITORY_ROOT / "tools" / "ci"))
import plan_matrix  # noqa: E402


def write_plugin(
    root: Path,
    *,
    version: str = "0.1.0",
    wasm: bytes = b"wasm-v1",
    provides: str | None = "telegram",
    sender_match: str | None = "exact",
    permissions: tuple[str, ...] = ("config_read",),
    registry: bool | None = None,
    name: str = "bridge",
) -> None:
    plugin = root / name
    plugin.mkdir(parents=True)
    lines = [
        f'name = "{name}"',
        f'version = "{version}"',
        'description = "Bridge messages"',
        'author = "ZeroClaw Labs"',
        f'wasm_path = "{name}.wasm"',
        'capabilities = ["channel"]',
        f"permissions = {json.dumps(list(permissions))}",
    ]
    if registry is not None:
        lines.append(f"registry = {str(registry).lower()}")
    if provides is not None:
        lines.append(f'provides = "{provides}"')
    if sender_match is not None:
        lines.append(f'sender_match = "{sender_match}"')
    (plugin / "manifest.toml").write_text("\n".join(lines) + "\n")
    (plugin / f"{name}.wasm").write_bytes(wasm)


def run_registry(
    *arguments: object,
    environment: dict[str, str] | None = None,
) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(BUILD_REGISTRY), *(str(arg) for arg in arguments)],
        cwd=REPOSITORY_ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )


def write_registry(path: Path, entries: list[dict]) -> None:
    path.write_text(json.dumps({"plugins": entries}, indent=2) + "\n")


def write_retirements(path: Path, entries: list[dict]) -> None:
    path.write_text(json.dumps({"retired": entries}, indent=2) + "\n")


def retirement(entry: dict, reason: str = "does not load on current hosts") -> dict:
    return {
        "name": entry["name"],
        "version": entry["version"],
        "sha256": entry["sha256"],
        "reason": reason,
    }


class BuildRegistryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def build(
        self,
        staged: Path,
        out: Path,
        existing: Path | None = None,
        *,
        changed_plugins: tuple[str, ...] = (),
        environment: dict[str, str] | None = None,
        retirements: Path | None = None,
    ):
        plugins = sorted(path.name for path in staged.iterdir())
        matrix = {
            "include": (
                [
                    {
                        "id": 0,
                        "plugins": plugins,
                        "release_plugins": list(changed_plugins),
                        "strict_plugins": list(changed_plugins),
                    }
                ]
                if plugins
                else []
            )
        }
        arguments = [
            "--staged",
            staged,
            "--release-base",
            RELEASE_BASE,
            "--matrix-json",
            json.dumps(matrix, separators=(",", ":")),
            "--out",
            out,
        ]
        if existing is not None:
            arguments.extend(["--existing-registry", existing])
        if retirements is not None:
            arguments.extend(["--retirements", retirements])
        return run_registry(*arguments, environment=environment)

    def published_history(self) -> tuple[Path, dict, dict]:
        """Publish bridge 0.1.0 and 0.2.0; return the ledger and both entries."""
        staged = self.root / "staged-history"
        write_plugin(staged, version="0.1.0", wasm=b"wasm-v1")
        first = self.build(staged, self.root / "history-1")
        self.assertEqual(first.returncode, 0, first.stderr)
        upgraded = self.root / "staged-history-2"
        write_plugin(upgraded, version="0.2.0", wasm=b"wasm-v2")
        second = self.build(
            upgraded,
            self.root / "history-2",
            self.root / "history-1" / "registry.json",
            changed_plugins=("bridge",),
        )
        self.assertEqual(second.returncode, 0, second.stderr)
        base = self.root / "history-2" / "registry.json"
        old, new = json.loads(base.read_text())["plugins"]
        return base, old, new

    def test_metadata_is_synchronized_from_canonical_manifest(self) -> None:
        source = self.root / "plugins"
        write_plugin(source)
        registry = self.root / "registry.json"
        registry.write_text(
            json.dumps(
                {
                    "plugins": [
                        {
                            "name": "bridge",
                            "version": "0.1.0",
                            "description": "stale",
                            "author": "ZeroClaw Labs",
                            "capabilities": ["channel"],
                            "url": f"{RELEASE_BASE}/bridge-0.1.0.zip",
                            "sha256": "0" * 64,
                        }
                    ]
                }
            )
            + "\n"
        )

        drift = run_registry(
            "--source-plugins", source, "--check-metadata", registry
        )
        self.assertNotEqual(drift.returncode, 0)
        self.assertIn("registry metadata drift", drift.stderr)

        synced = run_registry(
            "--source-plugins", source, "--sync-metadata", registry
        )
        self.assertEqual(synced.returncode, 0, synced.stderr)
        entry = json.loads(registry.read_text())["plugins"][0]
        self.assertEqual(entry["provides"], "telegram")
        self.assertEqual(entry["sender_match"], "exact")
        self.assertEqual(entry["description"], "Bridge messages")

        checked = run_registry(
            "--source-plugins", source, "--check-metadata", registry
        )
        self.assertEqual(checked.returncode, 0, checked.stderr)

    def test_existing_package_is_reused_but_never_overwritten(self) -> None:
        staged = self.root / "staged"
        write_plugin(staged)
        initial = self.root / "initial"
        first = self.build(staged, initial)
        self.assertEqual(first.returncode, 0, first.stderr)

        unchanged = self.root / "unchanged"
        same = self.build(staged, unchanged, initial / "registry.json")
        self.assertEqual(same.returncode, 0, same.stderr)
        self.assertFalse((unchanged / "bridge-0.1.0.zip").exists())
        self.assertEqual(
            json.loads((unchanged / "registry.json").read_text()),
            json.loads((initial / "registry.json").read_text()),
        )

        (staged / "bridge" / "bridge.wasm").write_bytes(b"changed bytes")
        collision = self.root / "collision"
        changed = self.build(
            staged,
            collision,
            initial / "registry.json",
            changed_plugins=("bridge",),
        )
        self.assertNotEqual(changed.returncode, 0)
        self.assertIn(
            "changed release input reuses immutable package identity bridge@0.1.0",
            changed.stderr,
        )
        self.assertIn("bump the canonical manifest version", changed.stderr)
        self.assertFalse((collision / "bridge-0.1.0.zip").exists())

    def test_current_wit_selection_rejects_matrix_identity_reuse_only(self) -> None:
        staged = self.root / "staged"
        write_plugin(staged)
        write_plugin(staged, name="matrix", version="0.3.0", provides="matrix")
        initial = self.root / "initial"
        first = self.build(staged, initial)
        self.assertEqual(first.returncode, 0, first.stderr)
        original = json.loads((initial / "registry.json").read_text())["plugins"]
        repository = self.root / "repository"
        for name in ("bridge", "matrix"):
            (repository / "plugins" / name).mkdir(parents=True)
        with mock.patch.object(plan_matrix, "git_changed_paths", return_value=["wit/CURRENT_REF"]), \
                mock.patch.object(registry_contract, "CURRENT_WIT_CONSUMERS", frozenset({"matrix"})):
            plan = plan_matrix.make_plan(repository, "pull_request", "origin/main")
        matrix = json.dumps(plan["matrix"])

        def publish(source: Path, out: Path):
            return run_registry(
                "--staged", source, "--out", out, "--release-base", RELEASE_BASE,
                "--existing-registry", initial / "registry.json", "--matrix-json", matrix,
            )

        collision = publish(staged, self.root / "collision")
        self.assertNotEqual(collision.returncode, 0)
        self.assertIn("changed release input reuses immutable package identity matrix@0.3.0", collision.stderr)
        self.assertNotIn("changed release input reuses immutable package identity bridge", collision.stderr)
        upgraded = self.root / "upgraded"
        write_plugin(upgraded)
        write_plugin(upgraded, name="matrix", version="0.3.1", provides="matrix", wasm=b"current-wit")
        out = self.root / "published"
        result = publish(upgraded, out)
        self.assertEqual(result.returncode, 0, result.stderr)
        entries = json.loads((out / "registry.json").read_text())["plugins"]
        self.assertTrue(all(entry in entries for entry in original))
        self.assertEqual(len(entries), 3)
        self.assertTrue((out / "matrix-0.3.1.zip").is_file())
        self.assertFalse((out / "bridge-0.1.0.zip").exists())

    def test_archive_bytes_match_golden_packager_contract(self) -> None:
        wasm = (
            b"\x00" * 65_537
            + bytes(range(256)) * 257
            + b'(module (func (export "run")))\n' * 4_097
            + b"".join(
                hashlib.sha256(index.to_bytes(4, "big")).digest()
                for index in range(4_096)
            )
        )
        self.assertEqual(len(wasm), 389_408)

        staged = self.root / "staged"
        write_plugin(staged, wasm=wasm)
        out = self.root / "out"
        environment = os.environ.copy()
        environment.pop("SOURCE_DATE_EPOCH", None)
        result = self.build(staged, out, environment=environment)
        self.assertEqual(result.returncode, 0, result.stderr)

        archive = out / "bridge-0.1.0.zip"
        self.assertEqual(archive.stat().st_size, 133_159)
        self.assertEqual(
            hashlib.sha256(archive.read_bytes()).hexdigest(),
            "9aca4adc50bc7ae03b10d216dfa9206e104c73366c6f98564b9f9a9090b2afa8",
        )

    def test_publication_files_exactly_match_new_ledger_identities(self) -> None:
        base = self.root / "base.json"
        base.write_text('{"plugins": []}\n')
        staged = self.root / "staged"
        write_plugin(staged)
        dist = self.root / "dist"
        built = self.build(staged, dist, base)
        self.assertEqual(built.returncode, 0, built.stderr)

        checked = run_registry(
            "--check-publication", base, dist / "registry.json", dist
        )
        self.assertEqual(checked.returncode, 0, checked.stderr)

        unexpected = dist / "unindexed-9.9.9.zip"
        unexpected.write_bytes(b"not in the ledger")
        polluted = run_registry(
            "--check-publication", base, dist / "registry.json", dist
        )
        self.assertNotEqual(polluted.returncode, 0)
        self.assertIn("publication files are unexpected", polluted.stderr)
        unexpected.unlink()

        archive = dist / "bridge-0.1.0.zip"
        archive.write_bytes(b"changed after generation")
        tampered = run_registry(
            "--check-publication", base, dist / "registry.json", dist
        )
        self.assertNotEqual(tampered.returncode, 0)
        self.assertIn("does not match ledger", tampered.stderr)

    def test_packaging_requires_a_fresh_output_path(self) -> None:
        staged = self.root / "staged"
        write_plugin(staged)
        out = self.root / "out"
        out.mkdir()
        (out / "stale.zip").write_bytes(b"stale")

        result = self.build(staged, out)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("output path must not already exist", result.stderr)
        self.assertTrue((out / "stale.zip").is_file())

    def test_source_manifest_version_is_canonical_for_cargo(self) -> None:
        source = self.root / "plugins"
        write_plugin(source, version="0.2.0")
        (source / "bridge" / "Cargo.toml").write_text(
            '[package]\nname = "bridge"\nversion = "0.1.0"\n'
        )
        registry = self.root / "registry.json"
        registry.write_text('{"plugins": []}\n')

        checked = run_registry(
            "--source-plugins", source, "--check-metadata", registry
        )
        self.assertNotEqual(checked.returncode, 0)
        self.assertIn("does not match canonical manifest version", checked.stderr)

    def test_host_gated_permissions_require_the_registry_opt_out(self) -> None:
        registry = self.root / "registry.json"
        registry.write_text('{"plugins": []}\n')
        gated = ("state_read", "state_write")

        opted_out = self.root / "opted-out"
        write_plugin(opted_out, permissions=gated, registry=False)
        accepted = run_registry(
            "--source-plugins", opted_out, "--check-metadata", registry
        )
        self.assertEqual(accepted.returncode, 0, accepted.stderr)

        published = self.root / "published"
        write_plugin(published, permissions=gated)
        refused = run_registry(
            "--source-plugins", published, "--check-metadata", registry
        )
        self.assertNotEqual(refused.returncode, 0)
        for permission in gated:
            self.assertIn(
                f"permission {permission!r} is rejected by released hosts",
                refused.stderr,
            )

        misspelled = self.root / "misspelled"
        write_plugin(misspelled, permissions=("state_admin",), registry=False)
        unknown = run_registry(
            "--source-plugins", misspelled, "--check-metadata", registry
        )
        self.assertNotEqual(unknown.returncode, 0)
        self.assertIn("unknown permissions value 'state_admin'", unknown.stderr)

    def test_packaging_never_publishes_host_gated_permissions(self) -> None:
        staged = self.root / "staged"
        write_plugin(staged, permissions=("state_read",))
        refused_out = self.root / "refused"
        refused = self.build(staged, refused_out)
        self.assertNotEqual(refused.returncode, 0)
        self.assertIn(
            "permission 'state_read' is rejected by released hosts", refused.stderr
        )
        self.assertFalse((refused_out / "bridge-0.1.0.zip").exists())

        gated = self.root / "gated"
        write_plugin(gated, permissions=("state_read",), registry=False)
        skipped_out = self.root / "skipped"
        skipped = self.build(gated, skipped_out)
        self.assertEqual(skipped.returncode, 0, skipped.stderr)
        self.assertIn("skipping bridge (registry = false", skipped.stdout)
        self.assertFalse((skipped_out / "bridge-0.1.0.zip").exists())

    def test_new_version_is_appended_to_registry_history(self) -> None:
        staged = self.root / "staged"
        write_plugin(staged)
        initial = self.root / "initial"
        first = self.build(staged, initial)
        self.assertEqual(first.returncode, 0, first.stderr)

        staged_v2 = self.root / "staged-v2"
        write_plugin(staged_v2, version="0.2.0", wasm=b"wasm-v2")
        metadata_check = run_registry(
            "--source-plugins",
            staged_v2,
            "--check-metadata",
            initial / "registry.json",
        )
        self.assertEqual(metadata_check.returncode, 0, metadata_check.stderr)
        self.assertIn("pending unpublished source: bridge@0.2.0", metadata_check.stdout)

        updated = self.root / "updated"
        second = self.build(staged_v2, updated, initial / "registry.json")
        self.assertEqual(second.returncode, 0, second.stderr)
        entries = json.loads((updated / "registry.json").read_text())["plugins"]
        self.assertEqual(
            [(entry["name"], entry["version"]) for entry in entries],
            [("bridge", "0.1.0"), ("bridge", "0.2.0")],
        )
        self.assertTrue((updated / "bridge-0.2.0.zip").is_file())

    def test_registry_history_is_append_only_and_canonically_ordered(self) -> None:
        staged = self.root / "staged"
        write_plugin(staged)
        initial = self.root / "initial"
        first = self.build(staged, initial)
        self.assertEqual(first.returncode, 0, first.stderr)
        base = initial / "registry.json"

        unchanged = run_registry("--check-history", base, base)
        self.assertEqual(unchanged.returncode, 0, unchanged.stderr)

        entry = json.loads(base.read_text())["plugins"][0]
        entry_v2 = {
            **entry,
            "version": "0.2.0",
            "url": f"{RELEASE_BASE}/bridge-0.2.0.zip",
            "sha256": "1" * 64,
        }
        write_registry(base, [entry, entry_v2])
        cases = {
            "deleted": {"plugins": []},
            "changed": {
                "plugins": [
                    {
                        **entry,
                        "url": "https://other.invalid/bridge-0.1.0.zip",
                    },
                    entry_v2,
                ]
            },
            "reordered": {
                "plugins": [entry_v2, entry]
            },
        }
        for name, contents in cases.items():
            with self.subTest(name=name):
                candidate = self.root / f"{name}.json"
                write_registry(candidate, contents["plugins"])
                result = run_registry("--check-history", base, candidate)
                self.assertNotEqual(result.returncode, 0)

        appended = self.root / "appended.json"
        entry_v3 = {
            **entry,
            "version": "0.3.0",
            "url": f"{RELEASE_BASE}/bridge-0.3.0.zip",
            "sha256": "2" * 64,
        }
        write_registry(
            appended,
            [entry, entry_v2, entry_v3],
        )
        addition = run_registry("--check-history", base, appended)
        self.assertNotEqual(addition.returncode, 0)
        self.assertIn("added outside the publication builder", addition.stderr)

    def test_registry_loader_rejects_incomplete_or_unsafe_entries(self) -> None:
        base = self.root / "base.json"
        base.write_text('{"plugins": []}\n')

        invalid_entries = {
            "incomplete": {"name": "bridge", "version": "0.1.0"},
            "unsafe-url": {
                "name": "bridge",
                "version": "0.1.0",
                "capabilities": ["channel"],
                "url": "http://example.invalid/bridge-0.1.0.zip",
                "sha256": "0" * 64,
            },
            "unsafe-sha": {
                "name": "bridge",
                "version": "0.1.0",
                "capabilities": ["channel"],
                "url": f"{RELEASE_BASE}/bridge-0.1.0.zip",
                "sha256": "not-a-digest",
            },
            "non-string-capability": {
                "name": "bridge",
                "version": "0.1.0",
                "capabilities": [{"channel": True}],
                "url": f"{RELEASE_BASE}/bridge-0.1.0.zip",
                "sha256": "0" * 64,
            },
            "null-metadata": {
                "name": "bridge",
                "version": "0.1.0",
                "description": None,
                "capabilities": ["channel"],
                "url": f"{RELEASE_BASE}/bridge-0.1.0.zip",
                "sha256": "0" * 64,
            },
        }
        for name, entry in invalid_entries.items():
            with self.subTest(name=name):
                candidate = self.root / f"{name}.json"
                candidate.write_text(json.dumps({"plugins": [entry]}) + "\n")
                result = run_registry("--check-history", base, candidate)
                self.assertNotEqual(result.returncode, 0)

    def test_history_allows_only_manifest_derived_metadata_refresh(self) -> None:
        staged = self.root / "staged"
        write_plugin(staged)
        initial = self.root / "initial"
        first = self.build(staged, initial)
        self.assertEqual(first.returncode, 0, first.stderr)

        manifest = staged / "bridge" / "manifest.toml"
        manifest.write_text(
            manifest.read_text().replace("Bridge messages", "Updated bridge")
        )
        candidate = self.root / "candidate.json"
        entry = json.loads((initial / "registry.json").read_text())["plugins"][0]
        write_registry(candidate, [{**entry, "description": "Updated bridge"}])

        checked = run_registry(
            "--source-plugins",
            staged,
            "--check-history",
            initial / "registry.json",
            candidate,
        )
        self.assertEqual(checked.returncode, 0, checked.stderr)

    def test_semver_order_places_prereleases_before_stable(self) -> None:
        staged = self.root / "staged"
        write_plugin(staged)
        initial = self.root / "initial"
        first = self.build(staged, initial)
        self.assertEqual(first.returncode, 0, first.stderr)
        template = json.loads((initial / "registry.json").read_text())["plugins"][0]
        versions = [
            "1.0.0",
            "1.0.0+build",
            "1.0.0-alpha",
            "1.0.0-alpha.1",
            "1.0.0-beta",
        ]
        existing = self.root / "existing.json"
        write_registry(
            existing,
            [
                {
                    **template,
                    "version": version,
                    "url": f"{RELEASE_BASE}/bridge-{version}.zip",
                }
                for version in versions
            ],
        )
        empty = self.root / "empty"
        empty.mkdir()
        out = self.root / "ordered"
        ordered = self.build(empty, out, existing)
        self.assertEqual(ordered.returncode, 0, ordered.stderr)
        actual = [
            entry["version"]
            for entry in json.loads((out / "registry.json").read_text())["plugins"]
        ]
        self.assertEqual(
            actual,
            [
                "1.0.0-alpha",
                "1.0.0-alpha.1",
                "1.0.0-beta",
                "1.0.0",
                "1.0.0+build",
            ],
        )

    def test_version_contract_enforces_semver_numeric_identifiers(self) -> None:
        valid = (
            "0.0.0",
            "1.2.3-0",
            "1.2.3-alpha.1",
            "1.2.3-alpha-01",
            "1.2.3+001",
        )
        invalid = (
            "01.2.3",
            "1.02.3",
            "1.2.03",
            "1.2.3-01",
            "1.2.3-alpha.01",
        )
        for version in valid:
            with self.subTest(version=version):
                self.assertIsNotNone(PLUGIN_VERSION_RE.fullmatch(version))
        for version in invalid:
            with self.subTest(version=version):
                self.assertIsNone(PLUGIN_VERSION_RE.fullmatch(version))

    def test_package_rejects_symbolic_links(self) -> None:
        staged = self.root / "staged"
        write_plugin(staged)
        skills = staged / "bridge" / "skills"
        skills.mkdir()
        (skills / "outside.md").symlink_to(self.root / "outside.md")
        (self.root / "outside.md").write_text("not package-owned\n")

        result = self.build(staged, self.root / "out")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("symbolic links are not allowed", result.stderr)

    def test_package_rejects_symbolic_plugin_root(self) -> None:
        external = self.root / "external"
        write_plugin(external)
        staged = self.root / "staged"
        staged.mkdir()
        (staged / "bridge").symlink_to(external / "bridge", target_is_directory=True)

        result = self.build(staged, self.root / "out")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("plugin directory must not be a symbolic link", result.stderr)

    def test_package_rejects_wasm_path_traversal(self) -> None:
        staged = self.root / "staged"
        write_plugin(staged)
        manifest = staged / "bridge" / "manifest.toml"
        manifest.write_text(
            manifest.read_text().replace('"bridge.wasm"', '"../../outside.wasm"')
        )
        (self.root / "outside.wasm").write_bytes(b"outside")

        result = self.build(staged, self.root / "out")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("safe relative .wasm filename", result.stderr)

    def test_package_rejects_non_regular_entries(self) -> None:
        staged = self.root / "staged"
        write_plugin(staged)
        os.mkfifo(staged / "bridge" / "named-pipe")

        result = self.build(staged, self.root / "out")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("non-regular package entry", result.stderr)

    def test_package_rejects_staged_directory_without_manifest(self) -> None:
        staged = self.root / "staged"
        plugin = staged / "bridge"
        plugin.mkdir(parents=True)
        (plugin / "bridge.wasm").write_bytes(b"wasm")

        result = self.build(staged, self.root / "out")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("staged plugin is missing manifest.toml", result.stderr)

    def test_listed_retirement_leaves_the_publication_and_passes_history(self) -> None:
        base, old, new = self.published_history()
        ledger = self.root / "retirements.json"
        write_retirements(ledger, [retirement(old)])
        staged = self.root / "staged"
        write_plugin(staged, version="0.2.0", wasm=b"wasm-v2")
        dist = self.root / "dist"

        built = self.build(staged, dist, base, retirements=ledger)
        self.assertEqual(built.returncode, 0, built.stderr)
        self.assertIn("retired bridge v0.1.0", built.stdout)
        self.assertEqual(json.loads((dist / "registry.json").read_text())["plugins"], [new])
        self.assertEqual(sorted(path.name for path in dist.iterdir()), ["registry.json"])

        candidate = dist / "registry.json"
        publication = run_registry(
            "--check-publication", base, candidate, dist, "--retirements", ledger
        )
        self.assertEqual(publication.returncode, 0, publication.stderr)
        history = run_registry("--check-history", base, candidate, "--retirements", ledger)
        self.assertEqual(history.returncode, 0, history.stderr)
        self.assertIn("1 listed retirement(s)", history.stdout)

        # The same removal without the ledger is still a deletion.
        unlisted_publication = run_registry("--check-publication", base, candidate, dist)
        self.assertNotEqual(unlisted_publication.returncode, 0)
        self.assertIn("publication candidate deleted bridge@0.1.0", unlisted_publication.stderr)
        unlisted_history = run_registry("--check-history", base, candidate)
        self.assertNotEqual(unlisted_history.returncode, 0)
        self.assertIn("historical registry entry was deleted: bridge@0.1.0", unlisted_history.stderr)

    def test_removal_outside_the_ledger_still_fails(self) -> None:
        base, old, new = self.published_history()
        ledger = self.root / "retirements.json"
        write_retirements(ledger, [retirement(new)])
        candidate = self.root / "candidate.json"
        write_registry(candidate, [new])

        history = run_registry("--check-history", base, candidate, "--retirements", ledger)
        self.assertNotEqual(history.returncode, 0)
        self.assertIn(
            "historical registry entry was deleted: bridge@0.1.0 "
            "(bridge@0.1.0 is not in the retirement ledger)",
            history.stderr,
        )

        dist = self.root / "dist"
        dist.mkdir()
        write_registry(dist / "registry.json", [new])
        publication = run_registry(
            "--check-publication", base, dist / "registry.json", dist, "--retirements", ledger
        )
        self.assertNotEqual(publication.returncode, 0)
        self.assertIn("publication candidate deleted bridge@0.1.0", publication.stderr)
        # 0.2.0 is listed but still present in this candidate.
        self.assertIn("publication candidate still indexes retired bridge@0.2.0", publication.stderr)

    def test_listed_entry_still_indexed_warns_in_history_and_fails_publication(self) -> None:
        base, old, _ = self.published_history()
        ledger = self.root / "retirements.json"
        write_retirements(ledger, [retirement(old)])

        # A merged ledger change precedes the publication run that rewrites
        # registry.json, so the checked-in index may still hold the entry.
        pending = run_registry("--check-history", base, base, "--retirements", ledger)
        self.assertEqual(pending.returncode, 0, pending.stderr)
        self.assertIn(
            "warning: retired registry entry is still indexed until the next "
            "publication: bridge@0.1.0",
            pending.stderr,
        )

        # A publication candidate must never keep it.
        dist = self.root / "stale-dist"
        dist.mkdir()
        (dist / "registry.json").write_text(base.read_text())
        stale = run_registry(
            "--check-publication", base, dist / "registry.json", dist, "--retirements", ledger
        )
        self.assertNotEqual(stale.returncode, 0)
        self.assertIn("publication candidate still indexes retired bridge@0.1.0", stale.stderr)

    def test_retired_identity_can_never_be_indexed_again(self) -> None:
        base, old, new = self.published_history()
        ledger = self.root / "retirements.json"
        write_retirements(ledger, [retirement(old)])

        staged = self.root / "staged"
        write_plugin(staged, version="0.1.0", wasm=b"rebuilt bytes")
        republished = self.build(staged, self.root / "dist", base, retirements=ledger)
        self.assertNotEqual(republished.returncode, 0)
        self.assertIn("bridge@0.1.0 is retired and can never be indexed again", republished.stderr)

        after = self.root / "after.json"
        write_registry(after, [new])
        readded = run_registry("--check-history", after, base, "--retirements", ledger)
        self.assertNotEqual(readded.returncode, 0)
        self.assertIn("retired registry entry was re-added: bridge@0.1.0", readded.stderr)

        source = self.root / "plugins"
        write_plugin(source, version="0.1.0")
        refused = "bridge@0.1.0 is retired; bump the canonical manifest version"
        metadata = run_registry(
            "--source-plugins", source, "--check-metadata", base, "--retirements", ledger
        )
        self.assertNotEqual(metadata.returncode, 0)
        self.assertIn(refused, metadata.stderr)
        history = run_registry(
            "--source-plugins", source, "--check-history", base, base, "--retirements", ledger
        )
        self.assertNotEqual(history.returncode, 0)
        self.assertIn(refused, history.stderr)

        # An opted-out source at a listed identity is not a hidden second copy,
        # even while the pending entry is still indexed, and packaging skips it.
        opted_out = self.root / "opted-out"
        write_plugin(opted_out, version="0.1.0", registry=False)
        allowed = run_registry(
            "--source-plugins", opted_out, "--check-metadata", base, "--retirements", ledger
        )
        self.assertEqual(allowed.returncode, 0, allowed.stderr)
        unlisted = run_registry("--source-plugins", opted_out, "--check-metadata", base)
        self.assertNotEqual(unlisted.returncode, 0)
        self.assertIn("registry=false plugin is already indexed: bridge@0.1.0", unlisted.stderr)
        skipped = self.build(opted_out, self.root / "dist-opted-out", base, retirements=ledger)
        self.assertEqual(skipped.returncode, 0, skipped.stderr)
        self.assertIn("skipping bridge (registry = false", skipped.stdout)
        self.assertEqual(
            json.loads((self.root / "dist-opted-out" / "registry.json").read_text())["plugins"],
            [new],
        )

    def test_retirement_must_name_the_published_bytes(self) -> None:
        base, old, new = self.published_history()
        ledger = self.root / "retirements.json"
        write_retirements(ledger, [{**retirement(old), "sha256": "f" * 64}])
        mismatch = f"retirement of bridge@0.1.0 names sha256 {'f' * 64}"

        staged = self.root / "staged"
        write_plugin(staged, version="0.2.0", wasm=b"wasm-v2")
        built = self.build(staged, self.root / "dist", base, retirements=ledger)
        self.assertNotEqual(built.returncode, 0)
        self.assertIn(mismatch, built.stderr)

        candidate = self.root / "candidate.json"
        write_registry(candidate, [new])
        history = run_registry("--check-history", base, candidate, "--retirements", ledger)
        self.assertNotEqual(history.returncode, 0)
        self.assertIn(mismatch, history.stderr)

        # The same mismatch while the listed entry is still indexed.
        pending = run_registry("--check-history", base, base, "--retirements", ledger)
        self.assertNotEqual(pending.returncode, 0)
        self.assertIn(mismatch, pending.stderr)

        dist = self.root / "manual-dist"
        dist.mkdir()
        write_registry(dist / "registry.json", [new])
        publication = run_registry(
            "--check-publication", base, dist / "registry.json", dist, "--retirements", ledger
        )
        self.assertNotEqual(publication.returncode, 0)
        self.assertIn(mismatch, publication.stderr)

    def test_retirement_ledger_is_validated(self) -> None:
        base, old, new = self.published_history()
        valid = retirement(old)
        later = retirement(new)
        def ledger(entries: list) -> str:
            return json.dumps({"retired": entries}, indent=2) + "\n"

        fields = "must have exactly the fields ['name', 'version', 'sha256', 'reason']"
        cases = {
            "not an object": ("[]\n", "must contain only a retired array"),
            "extra key": (
                json.dumps({"retired": [], "notes": []}, indent=2) + "\n",
                "must contain only a retired array",
            ),
            "missing field": (
                ledger([{key: value for key, value in valid.items() if key != "reason"}]),
                fields,
            ),
            "field order": (ledger([{"version": valid["version"], **valid}]), fields),
            "bad name": (ledger([{**valid, "name": "Bridge"}]), "name 'Bridge' must be a lowercase slug"),
            "unsafe version": (
                ledger([{**valid, "version": "01.0.0"}]),
                "version '01.0.0' must be a safe semantic version",
            ),
            "bad sha256": (ledger([{**valid, "sha256": "ABC"}]), "must have a lowercase 64-hex sha256"),
            "empty reason": (ledger([{**valid, "reason": " "}]), "must give a non-empty reason"),
            "duplicate": (ledger([valid, valid]), "repeats bridge@0.1.0"),
            "order": (ledger([later, valid]), "is not in canonical name/version order"),
            "formatting": (
                json.dumps({"retired": [valid]}) + "\n",
                "does not use canonical JSON formatting",
            ),
        }
        for name, (contents, expected) in cases.items():
            with self.subTest(name=name):
                path = self.root / f"ledger-{name.replace(' ', '-')}.json"
                path.write_text(contents)
                result = run_registry("--check-history", base, base, "--retirements", path)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(expected, result.stderr)
                self.assertNotIn("Traceback", result.stderr)

        empty = self.root / "empty.json"
        write_retirements(empty, [])
        unchanged = run_registry("--check-history", base, base, "--retirements", empty)
        self.assertEqual(unchanged.returncode, 0, unchanged.stderr)

    def test_repository_retirement_ledger_is_canonical(self) -> None:
        ledger = REPOSITORY_ROOT / "registry-retirements.json"
        result = run_registry(
            "--check-history",
            REPOSITORY_ROOT / "registry.json",
            REPOSITORY_ROOT / "registry.json",
            "--retirements",
            ledger,
            "--base-retirements",
            ledger,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_ledger_is_append_only_against_its_base(self) -> None:
        base, old, new = self.published_history()
        base_ledger = self.root / "base-retirements.json"
        write_retirements(base_ledger, [retirement(old)])
        head = self.root / "retirements.json"

        def history(*entries: dict):
            write_retirements(head, list(entries))
            return run_registry(
                "--check-history", base, base,
                "--retirements", head, "--base-retirements", base_ledger,
            )

        dropped = history()
        self.assertNotEqual(dropped.returncode, 0)
        self.assertIn("retirement ledger entry was removed: bridge@0.1.0", dropped.stderr)

        redigested = history({**retirement(old), "sha256": "e" * 64})
        self.assertNotEqual(redigested.returncode, 0)
        self.assertIn("retirement ledger entry changed its sha256: bridge@0.1.0", redigested.stderr)

        renamed = history({**retirement(old), "version": "0.1.1"})
        self.assertNotEqual(renamed.returncode, 0)
        self.assertIn("retirement ledger entry was removed: bridge@0.1.0", renamed.stderr)

        reworded = history(retirement(old, reason="reworded for reviewers"))
        self.assertEqual(reworded.returncode, 0, reworded.stderr)

        appended = history(retirement(old), retirement(new))
        self.assertEqual(appended.returncode, 0, appended.stderr)

        # A base that predates the ledger: validation writes this empty ledger.
        base_ledger.write_text('{\n  "retired": []\n}\n')
        first = history(retirement(old))
        self.assertEqual(first.returncode, 0, first.stderr)

    def test_new_retirement_must_match_a_published_entry(self) -> None:
        base, old, _ = self.published_history()
        base_ledger = self.root / "base-retirements.json"
        write_retirements(base_ledger, [])
        head = self.root / "retirements.json"

        write_retirements(head, [{**retirement(old), "version": "0.3.1"}])
        typo = run_registry(
            "--check-history", base, base, "--retirements", head, "--base-retirements", base_ledger
        )
        self.assertNotEqual(typo.returncode, 0)
        self.assertIn("new retirement bridge@0.3.1 is not indexed by the base registry", typo.stderr)

        write_retirements(head, [{**retirement(old), "sha256": "d" * 64}])
        wrong = run_registry(
            "--check-history", base, base, "--retirements", head, "--base-retirements", base_ledger
        )
        self.assertNotEqual(wrong.returncode, 0)
        self.assertIn(f"new retirement bridge@0.1.0 names sha256 {'d' * 64}", wrong.stderr)

    def test_ledger_beside_a_registry_must_be_passed(self) -> None:
        _, old, new = self.published_history()
        repo = self.root / "repo"
        repo.mkdir()
        registry = repo / "registry.json"
        write_registry(registry, [old, new])
        ledger = repo / "registry-retirements.json"
        write_retirements(ledger, [])
        source = self.root / "plugins"
        write_plugin(source, version="0.2.0")
        missing = "registry-retirements.json exists; pass it with --retirements"

        for arguments in (
            ("--check-history", registry, registry),
            ("--source-plugins", source, "--check-metadata", registry),
            ("--check-publication", registry, self.root / "dist" / "registry.json", self.root / "dist"),
        ):
            with self.subTest(mode=arguments[0]):
                result = run_registry(*arguments)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(missing, result.stderr)

        staged = self.root / "staged"
        write_plugin(staged, version="0.2.0", wasm=b"wasm-v2")
        packaging = self.build(staged, self.root / "dist-packaging", registry)
        self.assertNotEqual(packaging.returncode, 0)
        self.assertIn(missing, packaging.stderr)

        without_base = run_registry("--check-history", registry, registry, "--retirements", ledger)
        self.assertNotEqual(without_base.returncode, 0)
        self.assertIn("needs the base revision's ledger with --base-retirements", without_base.stderr)

        both = run_registry(
            "--check-history", registry, registry,
            "--retirements", ledger, "--base-retirements", ledger,
        )
        self.assertEqual(both.returncode, 0, both.stderr)

        misplaced = run_registry(
            "--source-plugins", source, "--check-metadata", registry,
            "--retirements", ledger, "--base-retirements", ledger,
        )
        self.assertNotEqual(misplaced.returncode, 0)
        self.assertIn("--base-retirements is only valid with --check-history", misplaced.stderr)


if __name__ == "__main__":
    unittest.main()
