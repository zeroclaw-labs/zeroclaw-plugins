#!/usr/bin/env bash
# Vendor libs/solana-core into each plugin that depends on it.
#
# Why: the repo's PR CI (.github/workflows/validate.yml -> tools/ci/
# validate_components.sh) snapshots ONLY plugins/<name> + wit/v0 into a temp
# dir and runs cargo there. A path dependency pointing outside the plugin
# directory (../../libs/solana-core) does not exist in that snapshot, so the
# build fails hard. Upstream main has no libs/ directory at all.
#
# The vendored copies are kept byte-identical and a test enforces that, so
# "one shared core" stays true in substance: one source of truth, copies that
# cannot drift without turning CI red.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SRC="$REPO/libs/solana-core"
PLUGINS=(spl-transfer-build payment-watch nonce-status)

[[ -d "$SRC" ]] || { echo "error: $SRC not found" >&2; exit 1; }

for p in "${PLUGINS[@]}"; do
  dest="$REPO/plugins/$p/solana-core"
  echo "vendoring -> plugins/$p/solana-core"

  rm -rf "$dest"
  mkdir -p "$dest"

  # Copy only committed sources. No target/, no build artifacts.
  ( cd "$SRC" && tar -cf - \
      Cargo.toml Cargo.lock LICENSE README.md src tests ) \
    | ( cd "$dest" && tar -xf - )

  # The nested crate must not declare its own [workspace]: cargo refuses
  # "multiple workspace roots in the same workspace" when the parent plugin
  # crate already declares one.
  python3 - "$dest/Cargo.toml" <<'PY'
import re, sys
p = sys.argv[1]
s = open(p).read()
out = re.sub(r'\n\[workspace\]\s*\n?', '\n', s).rstrip() + '\n'
open(p, 'w').write(out)
PY

  # A vendored crate carries no lockfile of its own; the plugin's lock governs.
  rm -f "$dest/Cargo.lock"

  # Repoint the dependency at the vendored copy.
  python3 - "$REPO/plugins/$p/Cargo.toml" <<'PY'
import sys
p = sys.argv[1]
s = open(p).read()
old = 'solana-core-wasi = { path = "../../libs/solana-core" }'
new = 'solana-core-wasi = { path = "./solana-core" }'
if old in s:
    s = s.replace(old, new)
    open(p, 'w').write(s)
    print("  repointed path dep")
elif new in s:
    print("  already repointed")
else:
    sys.exit("  error: no solana-core-wasi path dep found in " + p)
PY
done

echo
echo "Now, in each plugin: cargo generate-lockfile && cargo test"
echo "If the core changed, cargo test prints the new digest to pin in each"
echo "plugin's tests/vendored_core.rs (VENDORED_CORE_DIGEST)."
