#!/usr/bin/env bash
# Validate plugin workspaces and materialize installable components.

# A caller may export SHELLOPTS with `errexit` enabled. This validator must run
# every check and materialize a row even after one Cargo command fails.
set +e
set -uo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPOSITORY_ROOT=$(cd "$SCRIPT_DIR/../.." && pwd)
cd "$REPOSITORY_ROOT" || exit 125

REPORT_PATH=${REPORT_PATH:-matrix.tsv}
STAGED_DIR=${STAGED_DIR:-staged}
LOG_ROOT=${LOG_ROOT:-logs}
REPORT_STACK=${REPORT_STACK:-ci}
CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-$REPOSITORY_ROOT/target-shared}
CARGO_TERM_COLOR=never
export CARGO_TARGET_DIR CARGO_TERM_COLOR

mkdir -p "$(dirname "$REPORT_PATH")" "$STAGED_DIR" "$LOG_ROOT" "$CARGO_TARGET_DIR"
python3 "$SCRIPT_DIR/report_schema.py" write-header "$REPORT_PATH" || exit 1
# upload-artifact ignores an empty directory. This root marker is not a plugin
# directory, so build-registry.py ignores it while every shard remains downloadable.
printf '%s\n' "staged component artifact" >"$STAGED_DIR/_artifact_marker"

if ! source_head=$(git rev-parse HEAD); then
  echo "error: cannot resolve source HEAD" >&2
  exit 1
fi
if [[ -n ${STRICT_PLUGINS_JSON+x} ]] \
  && ! jq -e 'type == "array" and all(.[]; type == "string")' \
    <<<"$STRICT_PLUGINS_JSON" >/dev/null; then
  echo "error: STRICT_PLUGINS_JSON must be an array of plugin names" >&2
  exit 1
fi

VALIDATION_SNAPSHOT_ROOT=$(mktemp -d) || exit 1
trap 'rm -rf -- "$VALIDATION_SNAPSHOT_ROOT"' EXIT

overall_rc=0

read_manifest_field() {
  local destination=$1
  local field=$2
  local value
  if value=$(python3 "$SCRIPT_DIR/manifest_field.py" "$manifest" "$field" 2>>"$metadata_log"); then
    printf -v "$destination" '%s' "$value"
  else
    manifest_valid=0
  fi
}

run_cargo() {
  local output=$1
  shift
  (
    cd "$plugin_dir" || exit 125
    cargo "$@"
  ) >"$output" 2>&1
}

append_report_row() {
  python3 "$SCRIPT_DIR/report_schema.py" append-row "$REPORT_PATH" \
    "stack=$REPORT_STACK" \
    "plugin=$plugin" \
    "source_head=$source_head" \
    "registry=$registry" \
    "strict=$strict" \
    "name=$name" \
    "version=$version" \
    "provides=$provides" \
    "capabilities=$capabilities" \
    "permissions=$permissions" \
    "test_rc=$test_rc" \
    "tests_passed=$tests_passed" \
    "tests_failed=$tests_failed" \
    "tests_ignored=$tests_ignored" \
    "clippy_rc=$clippy_rc" \
    "wasm_clippy_rc=$wasm_clippy_rc" \
    "build_rc=$build_rc" \
    "artifact=$artifact" \
    "artifact_bytes=$artifact_bytes" \
    "log_dir=$plugin_log_dir"
}

plugin_is_strict() {
  local candidate=$1
  if [[ -z ${STRICT_PLUGINS_JSON+x} ]]; then
    return 0
  fi
  jq -e --arg plugin "$candidate" \
    'type == "array" and index($plugin) != null' \
    <<<"$STRICT_PLUGINS_JSON" >/dev/null
}

for plugin in "$@"; do
  if ! python3 "$SCRIPT_DIR/manifest_field.py" \
    --validate-plugin-name "$plugin" >/dev/null 2>&1; then
    echo "error: unsafe plugin name: $plugin" >&2
    overall_rc=1
    continue
  fi

  checkout_plugin_dir="$REPOSITORY_ROOT/plugins/$plugin"
  plugin_snapshot_root="$VALIDATION_SNAPSHOT_ROOT/$plugin"
  canonical_root="$plugin_snapshot_root/canonical"
  build_root="$plugin_snapshot_root/build"
  canonical_plugin_dir="$canonical_root/plugins/$plugin"
  plugin_dir="$build_root/plugins/$plugin"
  manifest="$canonical_plugin_dir/manifest.toml"
  plugin_log_dir="$LOG_ROOT/$plugin"
  metadata_log="$plugin_log_dir/manifest.log"
  mkdir -p "$plugin_log_dir"
  : >"$metadata_log"

  name=""
  version=""
  provides=""
  capabilities=""
  permissions=""
  wasm_path=""
  registry_raw=""
  registry=true
  if plugin_is_strict "$plugin"; then
    strict=true
  else
    strict=false
  fi
  manifest_valid=1
  test_rc=125
  tests_passed=0
  tests_failed=0
  tests_ignored=0
  clippy_rc=125
  wasm_clippy_rc=125
  build_rc=125
  artifact=""
  artifact_bytes=""

  echo "::group::validate $plugin"
  if [[ -L $checkout_plugin_dir ]]; then
    echo "error: plugin directory must not be a symbolic link: plugins/$plugin" \
      | tee -a "$metadata_log" >&2
    manifest_valid=0
  elif [[ ! -d $checkout_plugin_dir ]]; then
    echo "error: plugin directory not found: plugins/$plugin" | tee -a "$metadata_log" >&2
    manifest_valid=0
  elif [[ -n $(
    git status --porcelain=v1 --untracked-files=all --ignored=matching \
      -- "$checkout_plugin_dir" "$REPOSITORY_ROOT/wit/v0"
  ) ]]; then
    echo "error: checkout is not clean before validating $plugin" \
      | tee -a "$metadata_log" >&2
    manifest_valid=0
  elif ! mkdir -p \
    "$canonical_root/plugins" "$canonical_root/wit" \
    "$build_root/plugins" "$build_root/wit" \
    || ! cp -R "$checkout_plugin_dir" "$canonical_root/plugins/" \
    || ! cp -R "$REPOSITORY_ROOT/wit/v0" "$canonical_root/wit/" \
    || ! cp -R "$checkout_plugin_dir" "$build_root/plugins/" \
    || ! cp -R "$REPOSITORY_ROOT/wit/v0" "$build_root/wit/"; then
    echo "error: could not snapshot committed inputs for $plugin" \
      | tee -a "$metadata_log" >&2
    manifest_valid=0
  elif ! python3 "$SCRIPT_DIR/manifest_field.py" \
    --validate-package-tree "$canonical_plugin_dir" \
    >/dev/null 2>>"$metadata_log"; then
    manifest_valid=0
  elif [[ ! -f $manifest ]]; then
    echo "error: manifest not found: plugins/$plugin/manifest.toml" | tee -a "$metadata_log" >&2
    manifest_valid=0
  else
    read_manifest_field name name
    read_manifest_field version version
    read_manifest_field provides provides
    read_manifest_field capabilities capabilities
    read_manifest_field permissions permissions
    read_manifest_field wasm_path wasm_path
    read_manifest_field registry_raw registry

    if [[ -z $registry_raw ]]; then
      registry=true
    elif [[ $registry_raw == true || $registry_raw == false ]]; then
      registry=$registry_raw
    else
      echo "error: registry must be true or false" >>"$metadata_log"
      manifest_valid=0
    fi
    if [[ $name != "$plugin" ]]; then
      echo "error: manifest name '$name' does not match plugin directory '$plugin'" >>"$metadata_log"
      manifest_valid=0
    fi
    if [[ -z $version ]]; then
      echo "error: manifest version is required" >>"$metadata_log"
      manifest_valid=0
    fi
    if [[ -z $capabilities ]]; then
      echo "error: manifest capabilities are required" >>"$metadata_log"
      manifest_valid=0
    fi
    if ! python3 "$SCRIPT_DIR/manifest_field.py" \
      --validate-wasm-path "$wasm_path" >/dev/null 2>>"$metadata_log"; then
      manifest_valid=0
    fi

    echo "BEGIN $plugin test"
    run_cargo "$plugin_log_dir/test.log" test --locked
    test_rc=$?
    if counts=$(python3 "$SCRIPT_DIR/test_counts.py" "$plugin_log_dir/test.log"); then
      IFS=$'\t' read -r tests_passed tests_failed tests_ignored <<<"$counts"
    else
      echo "error: could not parse test counts" >>"$plugin_log_dir/test.log"
      test_rc=125
    fi
    echo "END $plugin test rc=$test_rc counts=$tests_passed/$tests_failed/$tests_ignored"

    echo "BEGIN $plugin clippy-host"
    run_cargo "$plugin_log_dir/clippy-host.log" clippy --locked --all-targets -- -D warnings
    clippy_rc=$?
    echo "END $plugin clippy-host rc=$clippy_rc"

    echo "BEGIN $plugin clippy-wasm"
    run_cargo "$plugin_log_dir/clippy-wasm.log" clippy --locked --target wasm32-wasip2 -- -D warnings
    wasm_clippy_rc=$?
    echo "END $plugin clippy-wasm rc=$wasm_clippy_rc"

    expected_artifact=""
    if python3 "$SCRIPT_DIR/manifest_field.py" \
      --validate-wasm-path "$wasm_path" >/dev/null 2>&1; then
      expected_artifact="$CARGO_TARGET_DIR/wasm32-wasip2/release/$wasm_path"
      # Prevent an output left by another standalone workspace from satisfying
      # this plugin's build under the shared target directory.
      rm -f -- "$expected_artifact"
    fi

    echo "BEGIN $plugin build-wasm"
    run_cargo "$plugin_log_dir/build-wasm.log" build --locked --target wasm32-wasip2 --release
    build_rc=$?
    if [[ $build_rc -eq 0 ]]; then
      materialized_artifact="$plugin_snapshot_root/artifact/$wasm_path"
      if [[ -z $expected_artifact ]] \
        || ! artifact_bytes=$(python3 "$SCRIPT_DIR/manifest_field.py" \
          --copy-regular-file "$expected_artifact" "$materialized_artifact" \
          2>>"$plugin_log_dir/build-wasm.log"); then
        echo "error: successful build did not produce non-empty $expected_artifact" \
          >>"$plugin_log_dir/build-wasm.log"
        build_rc=125
      elif [[ $artifact_bytes -eq 0 ]]; then
        echo "error: successful build produced an empty $expected_artifact" \
          >>"$plugin_log_dir/build-wasm.log"
        build_rc=125
      else
        artifact=$materialized_artifact
      fi
    fi
    if [[ $manifest_valid -ne 1 && $build_rc -eq 0 ]]; then
      echo "error: component built but manifest validation failed" >>"$plugin_log_dir/build-wasm.log"
      build_rc=125
    fi
    echo "END $plugin build-wasm rc=$build_rc artifact=$artifact bytes=$artifact_bytes"

    if ! diff -qr "$canonical_root" "$build_root" \
      >"$plugin_log_dir/source-mutation.log" 2>&1; then
      echo "error: plugin commands mutated their source snapshot" \
        >>"$plugin_log_dir/build-wasm.log"
      build_rc=125
    fi

    # Stage every planned component so the fresh package job can prove that
    # its directory identities exactly match the canonical shard matrix.
    # build-registry.py still omits registry=false components from releases.
    if [[ $build_rc -eq 0 ]]; then
      plugin_stage="$STAGED_DIR/$plugin"
      if [[ -e $plugin_stage ]]; then
        echo "error: staging path already exists: $plugin_stage" \
          >>"$plugin_log_dir/build-wasm.log"
        build_rc=125
      elif [[ -d $canonical_plugin_dir/skills ]] \
        && ! python3 "$SCRIPT_DIR/manifest_field.py" \
          --validate-package-tree "$canonical_plugin_dir/skills" \
          >/dev/null 2>>"$plugin_log_dir/build-wasm.log"; then
        build_rc=125
      elif ! mkdir -p "$plugin_stage" \
        || ! cp "$manifest" "$plugin_stage/manifest.toml" \
        || ! python3 "$SCRIPT_DIR/manifest_field.py" \
          --copy-regular-file "$artifact" "$plugin_stage/$wasm_path" \
          >/dev/null 2>>"$plugin_log_dir/build-wasm.log"; then
        echo "error: could not stage $plugin" >>"$plugin_log_dir/build-wasm.log"
        build_rc=125
      elif [[ -d $canonical_plugin_dir/skills ]] \
        && ! cp -R "$canonical_plugin_dir/skills" "$plugin_stage/skills"; then
        echo "error: could not stage skills for $plugin" >>"$plugin_log_dir/build-wasm.log"
        build_rc=125
      fi
    fi
  fi

  for rc in "$test_rc" "$build_rc"; do
    if [[ $rc -ne 0 ]]; then
      overall_rc=1
    fi
  done
  for rc in "$clippy_rc" "$wasm_clippy_rc"; do
    if [[ $rc -ne 0 && $strict == true ]]; then
      overall_rc=1
    elif [[ $rc -ne 0 ]]; then
      echo "::warning file=plugins/$plugin/Cargo.toml::Untouched plugin has pre-existing Clippy debt (rc $rc)"
    fi
  done
  if ! append_report_row; then
    overall_rc=1
  fi
  echo "::endgroup::"
done

if ! python3 "$SCRIPT_DIR/report_schema.py" validate "$REPORT_PATH"; then
  overall_rc=1
fi
exit "$overall_rc"
