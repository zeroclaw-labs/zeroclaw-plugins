#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CFG="$ROOT/demo/zeroclaw-config"
ZC="${ZEROCLAW_BIN:-$HOME/.cargo/bin/zeroclaw-plugins}"
LOG="$ROOT/demo/recording/channel.log"
PIDF="$ROOT/demo/recording/channel.pid"
if [[ -f "$PIDF" ]] && kill -0 "$(cat "$PIDF")" 2>/dev/null; then
  echo "already running pid=$(cat "$PIDF")"
  exit 0
fi
mkdir -p "$(dirname "$LOG")"
: > "$LOG"
python3 - <<PY
import subprocess
from pathlib import Path
root = Path("$ROOT")
log = open(root/"demo/recording/channel.log", "ab", buffering=0)
proc = subprocess.Popen(
    ["$ZC", "--config-dir", "$CFG", "-v", "channel", "start"],
    stdout=log, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
    cwd=str(root), start_new_session=True,
)
(root/"demo/recording/channel.pid").write_text(str(proc.pid))
print("started", proc.pid)
PY
