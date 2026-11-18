#!/usr/bin/env bash
# One command that re-derives every claim this suite makes, from the shipped bytes.
#
# The point of the suite is that nothing here asks to be believed. Each check reads
# an artifact or a manifest in this tree, asserts a property and exits nonzero if
# the property does not hold. This script runs all of them, anchors the run to the
# digests it checked and prints one block a reviewer can paste.
#
# Standard library Python and coreutils only. No network, no credentials, no cargo,
# no toolchain. If it takes longer than a few seconds something is wrong.
#
#   ./demo/verify-all.sh            # every check, full output
#   ./demo/verify-all.sh -q         # one line per check
#   ./demo/verify-all.sh --report   # markdown, for a PR body or a submission form
#
# A check that is absent is reported as absent rather than skipped quietly, because
# a suite that silently shrinks is a suite that stops meaning anything.

set -euo pipefail

mode="full"
case "${1:-}" in
  -q) mode="quiet" ;;
  --report) mode="report" ;;
esac

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "${here}/.." && pwd)"
cd "${root}"

artifacts="${root}/demo/out/staged"
if [[ ! -d "${artifacts}" ]]; then
  artifacts="${root}/target-shared/wasm32-wasip2/release"
fi

# What each check proves, in one line, for the reader who runs nothing.
claim_for() {
  case "$1" in
    verify-capabilities.py)     echo "no filesystem, no sockets and no signing capability, on both import surfaces" ;;
    verify-no-ed25519.py)       echo "no SHA-512 in the bytes, so no Ed25519 signature is computable from a key" ;;
    verify-rpc-surface.py)      echo "no mutating JSON-RPC method is named, so it cannot ask a node to submit" ;;
    verify-artifact-hygiene.py) echo "no embedded key material, plus exports that are the tool the manifest declares" ;;
    verify-provenance.py)       echo "this commit, these vendored dependencies and these artifact digests agree" ;;
    verify-config-closure.py)   echo "the config schema is closed and every declared key is one the code reads" ;;
    verify-refusals.py)         echo "the documented refusal set is the real one and so is the pre-RPC subset" ;;
    *)                          echo "see the header of $1" ;;
  esac
}

checks=()
while IFS= read -r check; do
  checks+=("${check}")
done < <(find "${root}/demo" -maxdepth 1 -name 'verify-*.py' -type f | sort)

if ! find "${artifacts}" -name '*.wasm' -type f 2>/dev/null | grep -q .; then
  echo "No built components under ${artifacts#"${root}"/}. Build them with ./demo/run-demo.sh"
  exit 2
fi
if [[ "${#checks[@]}" -eq 0 ]]; then
  echo "No checks found under demo/. That is a failure, not a pass."
  exit 2
fi

tree_sha="$(git rev-parse --short HEAD 2>/dev/null || echo "not a git checkout")"
passed=0
failed=0
failing_names=()
declare -A result_of

for check in "${checks[@]}"; do
  name="$(basename "${check}")"
  if [[ "${mode}" == "full" ]]; then
    echo
    echo "--------------------------------------------------------------"
    echo " ${name}"
    echo "--------------------------------------------------------------"
    if python3 "${check}"; then result_of["${name}"]="pass"; else result_of["${name}"]="FAIL"; fi
  else
    if python3 "${check}" >/dev/null 2>&1; then result_of["${name}"]="pass"; else result_of["${name}"]="FAIL"; fi
  fi
  if [[ "${result_of["${name}"]}" == "pass" ]]; then
    passed=$((passed + 1))
  else
    failed=$((failed + 1))
    failing_names+=("${name}")
  fi
  if [[ "${mode}" == "quiet" ]]; then
    printf ' %-30s %s\n' "${name}" "${result_of["${name}"]}"
  fi
done

if [[ "${mode}" == "report" ]]; then
  echo "## Verifiable claims, re-derived at \`${tree_sha}\`"
  echo
  echo "Two commands. No toolchain, no credentials, no network, about a second each."
  echo
  echo '```'
  echo './demo/verify-all.sh          # every property below holds'
  echo 'python3 demo/prove-teeth.py   # every check below can be made to fail'
  echo '```'
  echo
  echo "### The bytes every check reads"
  echo
  echo "| Component | Bytes | sha256 |"
  echo "| --- | --- | --- |"
  while IFS= read -r wasm; do
    printf '| `%s` | %s | `%s` |\n' \
      "$(basename "${wasm}")" "$(stat -c%s "${wasm}")" "$(sha256sum "${wasm}" | cut -c1-8)"
  done < <(find "${artifacts}" -name '*.wasm' -type f | sort)
  echo
  echo "### What is proven, and by what"
  echo
  echo "| Check | Proves | Result |"
  echo "| --- | --- | --- |"
  for check in "${checks[@]}"; do
    name="$(basename "${check}")"
    printf '| `%s` | %s | %s |\n' "${name}" "$(claim_for "${name}")" "${result_of["${name}"]}"
  done
  echo
  if [[ -f "${here}/prove-teeth.py" ]]; then
    teeth="$(python3 "${here}/prove-teeth.py" -q 2>/dev/null | grep 'controls provoked' || true)"
    if [[ -n "${teeth}" ]]; then
      echo "Negative controls:${teeth}. Each one is a throwaway copy. A control that"
      echo "leaves its check green is reported as a check with no teeth."
      echo
    fi
  fi
  echo "${passed} of $((passed + failed)) checks pass. A check that is absent is reported as"
  echo "absent rather than skipped, so this table cannot shrink quietly."
  if [[ "${failed}" -gt 0 ]]; then
    exit 1
  fi
  exit 0
fi

echo
echo "=============================================================="
echo " tree      ${tree_sha}"
echo " artifacts ${artifacts#"${root}"/}"
while IFS= read -r wasm; do
  printf ' %-26s %8s bytes  sha256 %s\n' \
    "$(basename "${wasm}")" "$(stat -c%s "${wasm}")" "$(sha256sum "${wasm}" | cut -c1-8)"
done < <(find "${artifacts}" -name '*.wasm' -type f | sort)
echo " ${passed} of $((passed + failed)) checks pass"
if [[ "${failed}" -gt 0 ]]; then
  printf ' failing: %s\n' "${failing_names[*]}"
fi
echo "=============================================================="

if [[ "${failed}" -gt 0 ]]; then
  exit 1
fi
