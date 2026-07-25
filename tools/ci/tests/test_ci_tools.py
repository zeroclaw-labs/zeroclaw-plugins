from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


CI_ROOT = Path(__file__).resolve().parents[1]
REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(CI_ROOT))

import manifest_field  # noqa: E402
import plan_matrix  # noqa: E402
import report_schema  # noqa: E402
import summary  # noqa: E402
import test_counts  # noqa: E402


def valid_row(**overrides: str) -> dict[str, str]:
    row = {
        "stack": "ci",
        "plugin": "bridge",
        "source_head": "a" * 40,
        "registry": "true",
        "strict": "true",
        "name": "bridge",
        "version": "0.1.0",
        "provides": "telegram",
        "capabilities": "channel",
        "permissions": "http_client,config_read",
        "test_rc": "0",
        "tests_passed": "3",
        "tests_failed": "0",
        "tests_ignored": "1",
        "clippy_rc": "0",
        "wasm_clippy_rc": "0",
        "build_rc": "0",
        "artifact": "/tmp/bridge.wasm",
        "artifact_bytes": "1024",
        "log_dir": "logs/bridge",
    }
    row.update(overrides)
    return row


class ReportSchemaTests(unittest.TestCase):
    def test_schema_has_exactly_twenty_columns_and_wasm_clippy_position(self) -> None:
        self.assertEqual(len(report_schema.COLUMNS), 20)
        self.assertEqual(report_schema.COLUMNS[14:17], ("clippy_rc", "wasm_clippy_rc", "build_rc"))

    def test_header_and_row_round_trip_at_equal_width(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "report.tsv"
            report_schema.write_header(path)
            report_schema.append_row(path, valid_row())
            physical_lines = path.read_text().splitlines()
            self.assertEqual(len(physical_lines[0].split("\t")), 20)
            self.assertEqual(len(physical_lines[1].split("\t")), 20)
            self.assertEqual(report_schema.read_report(path), [valid_row()])

    def test_rejects_malformed_row_width_and_separators(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "report.tsv"
            report_schema.write_header(path)
            with path.open("a") as handle:
                handle.write("\t".join(["bad"] * 21) + "\n")
            with self.assertRaisesRegex(report_schema.SchemaError, "wrong column count"):
                report_schema.read_report(path)
            with self.assertRaisesRegex(report_schema.SchemaError, "row separator"):
                report_schema.validate_row(valid_row(provides="bad\tvalue"))

    def test_artifact_path_and_size_must_be_set_together(self) -> None:
        with self.assertRaisesRegex(report_schema.SchemaError, "both be set"):
            report_schema.validate_row(valid_row(artifact_bytes=""))


class ManifestFieldTests(unittest.TestCase):
    def test_normalizes_missing_boolean_and_array_fields(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            manifest = Path(temp) / "manifest.toml"
            manifest.write_text(
                'name = "bridge"\nregistry = false\npermissions = ["http_client", "config_read"]\n'
            )
            self.assertEqual(manifest_field.read_field(manifest, "name"), "bridge")
            self.assertEqual(manifest_field.read_field(manifest, "registry"), "false")
            self.assertEqual(
                manifest_field.read_field(manifest, "permissions"),
                "http_client,config_read",
            )
            self.assertEqual(manifest_field.read_field(manifest, "provides"), "")

    def test_rejects_invalid_toml_and_nested_values(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            manifest = Path(temp) / "manifest.toml"
            manifest.write_text("not valid = [")
            with self.assertRaises(manifest_field.ManifestFieldError):
                manifest_field.read_field(manifest, "name")
            with self.assertRaises(manifest_field.ManifestFieldError):
                manifest_field.normalize({"nested": "value"})


class TestCountTests(unittest.TestCase):
    def test_accumulates_multiple_suites_and_failed_results(self) -> None:
        lines = [
            "test result: ok. 4 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out\n",
            "noise\n",
            "test result: FAILED. 2 passed; 3 failed; 4 ignored; 0 measured\n",
        ]
        self.assertEqual(test_counts.parse_counts(lines), (6, 3, 5))

    def test_no_summaries_is_an_error(self) -> None:
        with self.assertRaisesRegex(ValueError, "no libtest result summary"):
            test_counts.parse_counts(["cargo compilation failed\n"])


class MatrixPlanTests(unittest.TestCase):
    def make_repository(self, count: int) -> tuple[tempfile.TemporaryDirectory, Path]:
        temp = tempfile.TemporaryDirectory()
        root = Path(temp.name)
        for index in range(count):
            (root / "plugins" / f"plugin-{index:02d}").mkdir(parents=True)
        return temp, root

    def test_non_pr_event_is_full_and_never_exceeds_four_shards(self) -> None:
        temp, root = self.make_repository(33)
        self.addCleanup(temp.cleanup)
        with mock.patch.object(plan_matrix, "git_changed_paths", return_value=[]):
            plan = plan_matrix.make_plan(root, "push", "unused")
        shards = [item["plugins"] for item in plan["matrix"]["include"]]
        self.assertEqual(plan["mode"], "full")
        self.assertEqual(plan["count"], 33)
        self.assertEqual([len(shard) for shard in shards], [9, 8, 8, 8])

    def test_pull_request_selects_only_changed_plugin(self) -> None:
        temp, root = self.make_repository(3)
        self.addCleanup(temp.cleanup)
        with mock.patch.object(
            plan_matrix, "git_changed_paths", return_value=["plugins/plugin-01/src/lib.rs", "README.md"]
        ):
            plan = plan_matrix.make_plan(root, "pull_request", "origin/main")
        self.assertEqual(plan["mode"], "changed")
        self.assertEqual(plan["count"], 1)
        self.assertEqual(
            plan["matrix"],
            {
                "include": [
                    {
                        "id": 0,
                        "plugins": ["plugin-01"],
                        "release_plugins": ["plugin-01"],
                        "strict_plugins": ["plugin-01"],
                    }
                ]
            },
        )

    def test_forced_full_sweep_is_strict_only_for_changed_plugins(self) -> None:
        temp, root = self.make_repository(3)
        self.addCleanup(temp.cleanup)
        with mock.patch.object(
            plan_matrix,
            "git_changed_paths",
            return_value=["tools/ci/summary.py", "plugins/plugin-02/src/lib.rs"],
        ):
            plan = plan_matrix.make_plan(root, "pull_request", "origin/main")
        self.assertEqual(plan["mode"], "full")
        self.assertEqual(
            [item["strict_plugins"] for item in plan["matrix"]["include"]],
            [["plugin-02"]],
        )
        self.assertEqual(
            [item["release_plugins"] for item in plan["matrix"]["include"]],
            [["plugin-02"]],
        )

    def test_wit_change_marks_every_plugin_as_a_release_input(self) -> None:
        temp, root = self.make_repository(3)
        self.addCleanup(temp.cleanup)
        with mock.patch.object(
            plan_matrix,
            "git_changed_paths",
            return_value=["wit/v0/channel.wit"],
        ):
            plan = plan_matrix.make_plan(root, "pull_request", "origin/main")
        shard = plan["matrix"]["include"][0]
        self.assertEqual(shard["strict_plugins"], [])
        self.assertEqual(shard["release_plugins"], shard["plugins"])

    def test_wit_pin_alone_does_not_mark_components_as_release_inputs(self) -> None:
        temp, root = self.make_repository(2)
        self.addCleanup(temp.cleanup)
        with mock.patch.object(
            plan_matrix,
            "git_changed_paths",
            return_value=["wit/UPSTREAM_REF"],
        ):
            plan = plan_matrix.make_plan(root, "pull_request", "origin/main")
        self.assertEqual(plan["matrix"]["include"][0]["release_plugins"], [])

    def test_workflow_tools_registry_and_wit_changes_force_full(self) -> None:
        for changed in (
            ".github/workflows/validate.yml",
            "tools/ci/summary.py",
            "registry.json",
            "wit/v0/channel.wit",
        ):
            with self.subTest(changed=changed):
                self.assertTrue(plan_matrix.requires_full_sweep([changed]))

    def test_unknown_root_build_configuration_forces_full(self) -> None:
        self.assertTrue(plan_matrix.requires_full_sweep([".cargo/config.toml"]))
        self.assertTrue(plan_matrix.requires_full_sweep(["rust-toolchain.toml"]))

    def test_doc_only_pull_request_has_empty_matrix(self) -> None:
        temp, root = self.make_repository(2)
        self.addCleanup(temp.cleanup)
        with mock.patch.object(plan_matrix, "git_changed_paths", return_value=["README.md"]):
            plan = plan_matrix.make_plan(root, "pull_request", "origin/main")
        self.assertEqual(plan, {"matrix": {"include": []}, "mode": "changed", "count": 0})

    def test_target_shard_size_is_eight(self) -> None:
        shards = plan_matrix.shard_plugins([f"p{index}" for index in range(17)])
        self.assertEqual([len(shard) for shard in shards], [8, 8, 1])

    def test_matrix_is_the_exact_identity_strictness_and_release_policy(self) -> None:
        matrix = {
            "include": [
                {
                    "id": 0,
                    "plugins": ["alpha", "bridge"],
                    "release_plugins": ["alpha"],
                    "strict_plugins": ["bridge"],
                },
                {
                    "id": 1,
                    "plugins": ["charlie"],
                    "release_plugins": [],
                    "strict_plugins": [],
                },
            ]
        }
        self.assertEqual(
            plan_matrix.planned_plugin_policy(matrix),
            {"alpha": False, "bridge": True, "charlie": False},
        )
        self.assertEqual(
            plan_matrix.planned_matrix_policies(matrix)[1],
            {"alpha"},
        )

    def test_matrix_rejects_duplicate_or_out_of_shard_strict_plugins(self) -> None:
        invalid = (
            {
                "include": [
                    {
                        "id": 0,
                        "plugins": ["bridge"],
                        "release_plugins": [],
                        "strict_plugins": [],
                    },
                    {
                        "id": 1,
                        "plugins": ["bridge"],
                        "release_plugins": [],
                        "strict_plugins": [],
                    },
                ]
            },
            {
                "include": [
                    {
                        "id": 0,
                        "plugins": ["bridge"],
                        "release_plugins": [],
                        "strict_plugins": ["other"],
                    }
                ]
            },
            {
                "include": [
                    {
                        "id": 0,
                        "plugins": ["bridge"],
                        "release_plugins": ["other"],
                        "strict_plugins": [],
                    }
                ]
            },
        )
        for matrix in invalid:
            with self.subTest(matrix=matrix), self.assertRaises(plan_matrix.PlanError):
                plan_matrix.planned_plugin_policy(matrix)

    def test_staged_directories_must_match_the_matrix_exactly(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            staged = Path(temp)
            (staged / "alpha").mkdir()
            (staged / "bridge").mkdir()
            policy = {"alpha": False, "bridge": True}
            plan_matrix.verify_staged_plugins(staged, policy)
            (staged / "bridge").rmdir()
            (staged / "decoy").mkdir()
            with self.assertRaisesRegex(
                plan_matrix.PlanError,
                "missing staged plugins.*bridge.*unexpected staged plugins.*decoy",
            ):
                plan_matrix.verify_staged_plugins(staged, policy)

    def test_matrix_json_fails_closed(self) -> None:
        for value in ("", "not-json", '{"include":"not-an-array"}'):
            with self.subTest(value=value), self.assertRaises(plan_matrix.PlanError):
                plan_matrix.parse_matrix_json(value)


class SummaryTests(unittest.TestCase):
    def test_renders_wasm_clippy_failure_and_large_artifact_warning(self) -> None:
        row = valid_row(
            source_head="b" * 40,
            wasm_clippy_rc="7",
            artifact_bytes=str(summary.SOFT_ARTIFACT_LIMIT + 1),
        )
        rendered = summary.render_summary(
            [row],
            aggregate=True,
            sha="b" * 40,
            event="pull_request",
            mode="changed",
            expected_count=1,
            verdict="auto",
        )
        self.assertIn("Clippy (wasm)", rendered)
        self.assertIn("FAIL (rc 7)", rendered)
        self.assertIn("⚠", rendered)
        self.assertIn("**Verdict: FAIL", rendered)

    def test_rejects_report_from_a_different_source_head(self) -> None:
        with self.assertRaisesRegex(
            report_schema.SchemaError,
            "source_head does not match validated SHA",
        ):
            summary.render_summary(
                [valid_row(source_head="a" * 40)],
                aggregate=True,
                sha="b" * 40,
                event="pull_request",
                mode="changed",
                expected_count=1,
                verdict="auto",
            )

    def test_rejects_missing_and_duplicate_rows(self) -> None:
        with self.assertRaisesRegex(report_schema.SchemaError, "missing report plugins: other"):
            summary.render_summary(
                [valid_row()],
                aggregate=True,
                sha="c" * 40,
                event="push",
                mode="full",
                expected_count=2,
                planned_policy={"bridge": True, "other": False},
                verdict="auto",
            )
        with self.assertRaisesRegex(report_schema.SchemaError, "duplicate plugin"):
            summary.render_summary(
                [valid_row(), valid_row()],
                aggregate=True,
                sha="c" * 40,
                event="push",
                mode="full",
                expected_count=2,
                planned_policy={"bridge": True},
                verdict="auto",
            )

    def test_rejects_equal_count_substitution_and_strictness_downgrade(self) -> None:
        with self.assertRaisesRegex(
            report_schema.SchemaError,
            "missing report plugins: bridge; unexpected report plugins: decoy",
        ):
            summary.render_summary(
                [valid_row(plugin="decoy", name="decoy")],
                aggregate=True,
                sha="a" * 40,
                event="pull_request",
                mode="changed",
                expected_count=1,
                planned_policy={"bridge": True},
                verdict="auto",
            )
        with self.assertRaisesRegex(report_schema.SchemaError, "strictness"):
            summary.render_summary(
                [valid_row(strict="false")],
                aggregate=True,
                sha="a" * 40,
                event="pull_request",
                mode="changed",
                expected_count=1,
                planned_policy={"bridge": True},
                verdict="auto",
            )

    def test_exact_multi_shard_identities_pass_in_any_report_order(self) -> None:
        rendered = summary.render_summary(
            [
                valid_row(plugin="charlie", name="charlie", strict="false"),
                valid_row(plugin="alpha", name="alpha", strict="false"),
                valid_row(plugin="bridge", name="bridge", strict="true"),
            ],
            aggregate=True,
            sha="a" * 40,
            event="workflow_dispatch",
            mode="full",
            expected_count=3,
            planned_policy={"alpha": False, "bridge": True, "charlie": False},
            verdict="auto",
        )
        self.assertIn("**Verdict: PASS", rendered)

    def test_workflow_count_must_match_matrix_identity_count(self) -> None:
        with self.assertRaisesRegex(report_schema.SchemaError, "workflow count 2"):
            summary.render_summary(
                [valid_row()],
                aggregate=True,
                sha="a" * 40,
                event="push",
                mode="full",
                expected_count=2,
                planned_policy={"bridge": True},
                verdict="auto",
            )

    def test_empty_doc_only_aggregate_can_pass(self) -> None:
        rendered = summary.render_summary(
            [],
            aggregate=True,
            sha="d" * 40,
            event="pull_request",
            mode="changed",
            expected_count=0,
            planned_policy={},
            verdict="pass",
        )
        self.assertIn("No plugin components required validation", rendered)
        self.assertIn("**Verdict: PASS", rendered)

    def test_nonzero_failed_test_count_cannot_render_pass(self) -> None:
        rendered = summary.render_summary(
            [valid_row(source_head="c" * 40, test_rc="0", tests_failed="1")],
            aggregate=True,
            sha="c" * 40,
            event="push",
            mode="full",
            expected_count=1,
            verdict="auto",
        )
        self.assertIn("**Verdict: FAIL", rendered)

    def test_baseline_clippy_debt_is_visible_but_does_not_fail(self) -> None:
        rendered = summary.render_summary(
            [
                valid_row(
                    source_head="c" * 40,
                    strict="false",
                    wasm_clippy_rc="101",
                )
            ],
            aggregate=True,
            sha="c" * 40,
            event="push",
            mode="full",
            expected_count=1,
            verdict="auto",
        )
        self.assertIn("WARN baseline (rc 101)", rendered)
        self.assertIn("**Verdict: PASS", rendered)


class ComponentValidatorTests(unittest.TestCase):
    def make_fake_cargo(self, root: Path) -> Path:
        binary = root / "cargo"
        binary.write_text(
            """#!/usr/bin/env bash
set -u
printf '%s\\n' "$*" >> "$FAKE_CARGO_LOG"
if [[ "$1" == "test" ]]; then
  printf '%s\\n' 'test result: ok. 3 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out'
fi
if [[ "$1" == "clippy" && " $* " == *" --all-targets "* ]]; then
  exit "${FAKE_HOST_CLIPPY_RC:-0}"
fi
if [[ "$1" == "build" && "${FAKE_SKIP_ARTIFACT:-0}" != "1" ]]; then
  plugin=$(basename "$PWD")
  wasm=${plugin//-/_}.wasm
  mkdir -p "$CARGO_TARGET_DIR/wasm32-wasip2/release"
  if [[ "${FAKE_SYMLINK_ARTIFACT:-0}" == "1" ]]; then
    ln -s "$FAKE_ARTIFACT_TARGET" \
      "$CARGO_TARGET_DIR/wasm32-wasip2/release/$wasm"
  else
    printf 'wasm' > "$CARGO_TARGET_DIR/wasm32-wasip2/release/$wasm"
  fi
fi
if [[ "$1" == "build" && "${FAKE_MUTATE_SOURCE:-0}" == "1" ]]; then
  printf '%s\n' '# mutation' >> manifest.toml
fi
exit 0
"""
        )
        binary.chmod(0o755)
        return binary

    def run_validator(self, *plugins: str, **extra_env: str):
        temp = tempfile.TemporaryDirectory()
        root = Path(temp.name)
        fake_bin = root / "bin"
        fake_bin.mkdir()
        self.make_fake_cargo(fake_bin)
        report = root / "reports" / "matrix.tsv"
        staged = root / "staged"
        cargo_log = root / "cargo.log"
        env = os.environ.copy()
        env.update(
            {
                "PATH": f"{fake_bin}:{env['PATH']}",
                "REPORT_PATH": str(report),
                "STAGED_DIR": str(staged),
                "LOG_ROOT": str(root / "logs"),
                "CARGO_TARGET_DIR": str(root / "target"),
                "FAKE_CARGO_LOG": str(cargo_log),
            }
        )
        env.update(extra_env)
        result = subprocess.run(
            ["bash", str(CI_ROOT / "validate_components.sh"), *plugins],
            cwd=REPOSITORY_ROOT,
            env=env,
            check=False,
            capture_output=True,
            text=True,
        )
        return temp, root, report, staged, cargo_log, result

    def test_runs_exact_checks_and_stages_every_planned_plugin(self) -> None:
        temp, root, report, staged, cargo_log, result = self.run_validator(
            "redact-text", "amqp"
        )
        self.addCleanup(temp.cleanup)
        self.assertEqual(result.returncode, 0, result.stderr)
        rows = report_schema.read_report(report)
        self.assertEqual([row["plugin"] for row in rows], ["redact-text", "amqp"])
        self.assertEqual(rows[0]["tests_passed"], "3")
        self.assertEqual(rows[0]["wasm_clippy_rc"], "0")
        self.assertTrue((staged / "redact-text" / "redact_text.wasm").is_file())
        self.assertTrue((staged / "amqp" / "amqp.wasm").is_file())
        invocations = cargo_log.read_text().splitlines()
        self.assertIn("test --locked", invocations)
        self.assertIn("clippy --locked --all-targets -- -D warnings", invocations)
        self.assertIn("clippy --locked --target wasm32-wasip2 -- -D warnings", invocations)
        self.assertIn("build --locked --target wasm32-wasip2 --release", invocations)

    def test_records_failure_but_continues_through_wasm_build(self) -> None:
        temp, root, report, staged, cargo_log, result = self.run_validator(
            "redact-text",
            FAKE_HOST_CLIPPY_RC="7",
            SHELLOPTS="braceexpand:errexit:hashall:interactive-comments",
        )
        self.addCleanup(temp.cleanup)
        self.assertNotEqual(result.returncode, 0)
        row = report_schema.read_report(report)[0]
        self.assertEqual(row["clippy_rc"], "7")
        self.assertEqual(row["wasm_clippy_rc"], "0")
        self.assertEqual(row["build_rc"], "0")
        self.assertIn("build --locked --target wasm32-wasip2 --release", cargo_log.read_text())

    def test_untouched_clippy_debt_warns_without_failing_the_component(self) -> None:
        temp, root, report, staged, cargo_log, result = self.run_validator(
            "redact-text",
            FAKE_HOST_CLIPPY_RC="7",
            STRICT_PLUGINS_JSON="[]",
        )
        self.addCleanup(temp.cleanup)
        self.assertEqual(result.returncode, 0, result.stderr)
        row = report_schema.read_report(report)[0]
        self.assertEqual(row["strict"], "false")
        self.assertEqual(row["clippy_rc"], "7")
        self.assertTrue((staged / "redact-text" / "redact_text.wasm").is_file())

    def test_success_without_exact_manifest_artifact_is_a_build_failure(self) -> None:
        temp, root, report, staged, cargo_log, result = self.run_validator(
            "redact-text", FAKE_SKIP_ARTIFACT="1"
        )
        self.addCleanup(temp.cleanup)
        self.assertNotEqual(result.returncode, 0)
        row = report_schema.read_report(report)[0]
        self.assertEqual(row["build_rc"], "125")
        self.assertEqual(row["artifact"], "")
        self.assertFalse((staged / "redact-text").exists())

    def test_source_mutation_is_rejected_and_canonical_inputs_are_not_staged(self) -> None:
        temp, root, report, staged, cargo_log, result = self.run_validator(
            "redact-text", FAKE_MUTATE_SOURCE="1"
        )
        self.addCleanup(temp.cleanup)
        self.assertNotEqual(result.returncode, 0)
        row = report_schema.read_report(report)[0]
        self.assertEqual(row["build_rc"], "125")
        self.assertFalse((staged / "redact-text").exists())
        mutation_log = root / "logs" / "redact-text" / "source-mutation.log"
        self.assertIn("manifest.toml", mutation_log.read_text())

    def test_symlink_build_artifact_is_rejected_without_dereferencing(self) -> None:
        temp, root, report, staged, cargo_log, result = self.run_validator(
            "redact-text",
            FAKE_SYMLINK_ARTIFACT="1",
            FAKE_ARTIFACT_TARGET="/etc/hosts",
        )
        self.addCleanup(temp.cleanup)
        self.assertNotEqual(result.returncode, 0)
        row = report_schema.read_report(report)[0]
        self.assertEqual(row["build_rc"], "125")
        self.assertFalse((staged / "redact-text").exists())


if __name__ == "__main__":
    unittest.main()
