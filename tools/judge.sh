#!/usr/bin/env bash
#
# Safe Hands — the judge's scorecard.
#
# Runs every check that backs a claim in the README and prints which claim each
# one settles. The point is not that it says PASS; the point is that each row
# names a command you can run yourself to make it say FAIL.
#
#   just judge            offline only
#   just judge --network  also check the log against its on-chain anchor
#
set -uo pipefail
cd "$(dirname "$0")/.."

NETWORK=0
[ "${1:-}" = "--network" ] && NETWORK=1

PASS=0; FAIL=0; SKIP=0
ROWS=()
LOG_DIR="target/judge"
mkdir -p "$LOG_DIR"

run() { # run <claim> <log-name> <command...>
  local claim="$1" name="$2"; shift 2
  local log="$LOG_DIR/$name.log"
  local start; start=$(date +%s)
  if "$@" >"$log" 2>&1; then
    local dur=$(( $(date +%s) - start ))
    ROWS+=("PASS|$claim|$name|${dur}s")
    PASS=$((PASS+1))
    printf '  \033[32mPASS\033[0m  %-52s (%ss)\n' "$claim" "$dur"
  else
    local dur=$(( $(date +%s) - start ))
    ROWS+=("FAIL|$claim|$name|${dur}s")
    FAIL=$((FAIL+1))
    printf '  \033[31mFAIL\033[0m  %-52s (%ss)  -> %s\n' "$claim" "$dur" "$log"
  fi
}

skip() { # skip <claim> <why>
  ROWS+=("SKIP|$1|$2|-")
  SKIP=$((SKIP+1))
  printf '  \033[33mSKIP\033[0m  %-52s  %s\n' "$1" "$2"
}

echo
echo "=============================================================="
echo "  SAFE HANDS — JUDGE SCORECARD"
echo "=============================================================="
printf '  commit    %s\n' "$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
printf '  toolchain %s\n' "$(rustc --version 2>/dev/null || echo unknown)"
printf '  date      %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
echo "--------------------------------------------------------------"
echo "  Each row is a claim and the command that could falsify it."
echo "--------------------------------------------------------------"
echo

run "the logic is tested, not asserted"            test        just test
run "every attack fixture still fails closed"      arena       just conformance
run "a verdict can be re-derived from its receipt" receipt     just verify-receipt
run "the decision log is internally honest"        log         just log-verify
run "no component imports what it never declared"  caps        just verify-capabilities
run "the shipped .wasm refuses in a real runtime"  component   just component-test
run "no known vulnerable dependency ships"         audit       just audit
run "it builds clean for wasm32-wasip2"            wasm        just wasm
run "the source is warning-free on both targets"   clippy      just clippy

if [ "$NETWORK" = "1" ]; then
  run "the log matches its anchor published on Solana" anchor  just log-audit
else
  skip "the log matches its anchor published on Solana" "run: just judge --network"
fi

# Kani has no Windows build, so fall through to WSL when there is one. A judge
# on Windows should still get the proof, not an apology.
if cargo kani --version >/dev/null 2>&1; then
  run "the policy model is machine-checked"        kani        just prove
elif command -v wsl >/dev/null 2>&1 \
     && wsl -e bash -lc 'cargo kani --version' >/dev/null 2>&1; then
  # Git Bash reports /c/Users/...; WSL needs /mnt/c/Users/...
  WSL_PWD="$(pwd | sed -E 's#^/([a-zA-Z])/#/mnt/\1/#')"
  run "the policy model is machine-checked (via WSL)" kani \
      wsl -e bash -lc "cd '$WSL_PWD' && cargo kani --manifest-path libs/safe-hands-core/Cargo.toml"
else
  skip "the policy model is machine-checked" "needs Kani: just prove (see EVIDENCE-proofs.md)"
fi

echo
echo "--------------------------------------------------------------"
echo "  WHERE THE RUBRIC IS ANSWERED"
echo "--------------------------------------------------------------"
cat <<'MAP'
  use case 30%        the 58s run: youtu.be/63E0zhGNnxQ
                      verbatim transcript: demo/live/telegram-2026-08-05.md
  safety/custody 25%  every tier T0 or T1, no signing key anywhere
                      README "What Safe Hands still trusts" names what is left
                      arena + receipt + log rows above
  craft 20%           pure core / thin shim, host tests with mocked RPC,
                      kani + fuzz + mutation + differential decoder tests
  reproducibility 15% REPRODUCE.md, and this scorecard
  showcase 10%        README claims table, EVIDENCE.md on-chain record
MAP

echo
echo "=============================================================="
if [ "$FAIL" -eq 0 ]; then
  printf '  RESULT: %d passed, %d skipped, 0 failed — the guard holds.\n' "$PASS" "$SKIP"
else
  printf '  RESULT: %d passed, %d skipped, \033[31m%d FAILED\033[0m — logs in %s\n' \
         "$PASS" "$SKIP" "$FAIL" "$LOG_DIR"
fi
echo "=============================================================="
echo

exit $(( FAIL > 0 ? 1 : 0 ))
