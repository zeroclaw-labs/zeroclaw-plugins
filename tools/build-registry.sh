#!/usr/bin/env bash
# Build the ZeroClaw plugin registry.
#
# For each staged plugin directory (containing a `manifest.toml` and its built
# `.wasm`), this:
#   1. zips the directory under a top-level `<name>/` folder,
#   2. computes the zip's SHA-256,
#   3. emits a `registry.json` entry pointing at the release-asset URL.
#
# The zips are uploaded as GitHub Release assets; only `registry.json` (small,
# text) is committed to the repo. `zeroclaw plugin install <name>` reads
# `registry.json`, downloads the zip, verifies the SHA-256, and installs it.
#
# Manifest parsing is intentionally minimal, matching what the index needs:
# flat scalar `key = "value"` lines plus string arrays (`capabilities`). Keep
# manifests to that shape or extend this parser.
#
# Dependencies: bash, zip, jq, sha256sum or shasum (no python).
#
# Usage:
#   build-registry.sh --staged <dir> --release-base <url> --out <dir>
set -euo pipefail

STAGED="" RELEASE_BASE="" OUT=""
while [ $# -gt 0 ]; do
  case "$1" in
  --staged) STAGED="${2:?missing value for --staged}"; shift 2 ;;
  --release-base) RELEASE_BASE="${2:?missing value for --release-base}"; shift 2 ;;
  --out) OUT="${2:?missing value for --out}"; shift 2 ;;
  *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
[ -n "$STAGED" ] && [ -n "$RELEASE_BASE" ] && [ -n "$OUT" ] || {
  echo "usage: $0 --staged <dir> --release-base <url> --out <dir>" >&2
  exit 2
}
RELEASE_BASE="${RELEASE_BASE%/}"

command -v zip >/dev/null || { echo "zip not found" >&2; exit 1; }
command -v jq >/dev/null || { echo "jq not found" >&2; exit 1; }
if command -v sha256sum >/dev/null; then
  sha256() { sha256sum "$1" | awk '{print $1}'; }
elif command -v shasum >/dev/null; then
  sha256() { shasum -a 256 "$1" | awk '{print $1}'; }
else
  echo "no sha256sum or shasum available" >&2
  exit 1
fi

# Print the value of a scalar `key = "value"` manifest line, or nothing.
manifest_scalar() { # <manifest> <key>
  awk -F'=' -v key="$2" '
    $1 ~ "^[ \t]*"key"[ \t]*$" {
      val = $0
      sub(/^[^=]*=[ \t]*"/, "", val)
      sub(/"[ \t]*$/, "", val)
      print val
      exit
    }' "$1"
}

# Print a `key = [ ... ]` string-array manifest line as a JSON array (TOML
# string arrays are valid JSON), or nothing.
manifest_array() { # <manifest> <key>
  awk -F'=' -v key="$2" '
    $1 ~ "^[ \t]*"key"[ \t]*$" {
      val = $0
      sub(/^[^=]*=[ \t]*/, "", val)
      print val
      exit
    }' "$1" | jq -c 'if type == "array" then . else empty end' 2>/dev/null || true
}

mkdir -p "$OUT"
OUT_ABS=$(cd "$OUT" && pwd)
entries="[]"
count=0

for pdir in "$STAGED"/*/; do
  [ -f "${pdir}manifest.toml" ] || continue
  manifest="${pdir}manifest.toml"
  name=$(manifest_scalar "$manifest" name)
  version=$(manifest_scalar "$manifest" version)
  version="${version:-0.0.0}"
  [ -n "$name" ] || { echo "  skipping ${pdir}: no name in manifest" >&2; continue; }
  description=$(manifest_scalar "$manifest" description)
  author=$(manifest_scalar "$manifest" author)
  capabilities=$(manifest_array "$manifest" capabilities)

  zip_name="${name}-${version}.zip"
  rm -f "$OUT_ABS/$zip_name"
  # Zip from the staged root so entries live under a top-level `<name>/`
  # folder. -X strips platform extras for reproducibility across runners.
  (cd "$STAGED" && find "$(basename "$pdir")" -type f | sort | zip -q -X "$OUT_ABS/$zip_name" -@)

  sha=$(sha256 "$OUT_ABS/$zip_name")
  entries=$(jq -c \
    --arg name "$name" \
    --arg version "$version" \
    --arg description "$description" \
    --arg author "$author" \
    --argjson capabilities "${capabilities:-[]}" \
    --arg url "$RELEASE_BASE/$zip_name" \
    --arg sha256 "$sha" \
    '. + [{
      name: $name,
      version: $version,
      description: (if $description == "" then null else $description end),
      author: (if $author == "" then null else $author end),
      capabilities: $capabilities,
      url: $url,
      sha256: $sha256
    } | with_entries(select(.value != null))]' <<<"$entries")
  count=$((count + 1))
  echo "  packaged $name v$version  sha256=${sha:0:12}…"
done

jq --argjson plugins "$entries" -n '{plugins: $plugins}' >"$OUT_ABS/registry.json"
plural="ies"; [ "$count" -eq 1 ] && plural="y"
echo "wrote registry.json with $count entr$plural"
