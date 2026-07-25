import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
BUILD_REGISTRY = REPOSITORY_ROOT / "tools" / "build-registry.py"
RELEASE_BASE = "https://example.invalid/releases/download/plugins"
sys.path.insert(0, str(REPOSITORY_ROOT / "tools"))

from registry_contract import PLUGIN_VERSION_RE  # noqa: E402


def write_plugin(
    root: Path,
    *,
    version: str = "0.1.0",
    wasm: bytes = b"wasm-v1",
    provides: str | None = "telegram",
    sender_match: str | None = "exact",
) -> None:
    plugin = root / "bridge"
    plugin.mkdir(parents=True)
    lines = [
        'name = "bridge"',
        f'version = "{version}"',
        'description = "Bridge messages"',
        'author = "ZeroClaw Labs"',
        'wasm_path = "bridge.wasm"',
        'capabilities = ["channel"]',
        'permissions = ["config_read"]',
    ]
    if provides is not None:
        lines.append(f'provides = "{provides}"')
    if sender_match is not None:
        lines.append(f'sender_match = "{sender_match}"')
    (plugin / "manifest.toml").write_text("\n".join(lines) + "\n")
    (plugin / "bridge.wasm").write_bytes(wasm)


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
        return run_registry(*arguments, environment=environment)

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


if __name__ == "__main__":
    unittest.main()
