#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
if grep -qE "allowed_(mints|recipients)|max_amount" src/core.rs; then
  count=$(grep -cE "fn (injection_|.*_fails_closed)" tests/core.rs || true)
  if [ "$count" -lt 1 ]; then
    echo "guardrail present with no injection/fails_closed test" >&2
    exit 1
  fi
fi
echo "ok: $(basename "$(pwd)") guardrail coverage verified"
