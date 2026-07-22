#!/usr/bin/env bash
# Wire Telegram + local Ollama for the DePIN ZeroClaw demo.
# Usage:
#   export TELEGRAM_BOT_TOKEN='123:ABC'   # from @BotFather (dedicated demo bot preferred)
#   ./demo/scripts/wire-telegram.sh
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CFG="$ROOT/demo/zeroclaw-config"
ZC="${ZEROCLAW_BIN:-$HOME/.cargo/bin/zeroclaw-plugins}"

if [[ -z "${TELEGRAM_BOT_TOKEN:-}" ]]; then
  if [[ -f "$ROOT/demo/.env" ]]; then
    # shellcheck disable=SC1091
    set -a; source "$ROOT/demo/.env"; set +a
  fi
fi
if [[ -z "${TELEGRAM_BOT_TOKEN:-}" ]]; then
  echo "Set TELEGRAM_BOT_TOKEN (BotFather) or put it in demo/.env" >&2
  exit 1
fi

"$ZC" --config-dir "$CFG" config set plugins.enabled true
"$ZC" --config-dir "$CFG" config set plugins.auto_discover true
"$ZC" --config-dir "$CFG" config set gateway.require_pairing false
"$ZC" --config-dir "$CFG" config set channels.show_tool_calls false

# Ensure ollama provider + agent exist
"$ZC" --config-dir "$CFG" config set providers.models.ollama.local.uri http://127.0.0.1:11434
"$ZC" --config-dir "$CFG" config set providers.models.ollama.local.model "${OLLAMA_MODEL:-llama3.2:3b}"
"$ZC" --config-dir "$CFG" config set providers.models.ollama.local.native_tools true

if ! "$ZC" --config-dir "$CFG" agents list 2>/dev/null | rg -q 'depin'; then
  "$ZC" --config-dir "$CFG" agents create depin
fi
"$ZC" --config-dir "$CFG" config set agents.depin.enabled true
"$ZC" --config-dir "$CFG" config set agents.depin.model_provider ollama.local
"$ZC" --config-dir "$CFG" config set agents.depin.channels '["telegram.depin"]'
"$ZC" --config-dir "$CFG" config set agents.depin.risk_profile demo

"$ZC" --config-dir "$CFG" config set risk_profiles.demo.sandbox_enabled false
"$ZC" --config-dir "$CFG" config set risk_profiles.demo.allowed_tools '[]'
"$ZC" --config-dir "$CFG" config set risk_profiles.demo.auto_approve '["*"]'

# bot_token cannot be set non-interactively via `config set` — write plaintext (accepted)
python3 - <<PY
from pathlib import Path
import os, re
cfg = Path("$CFG/config.toml")
text = cfg.read_text()
token = os.environ["TELEGRAM_BOT_TOKEN"]
section = "[channels.telegram.depin]"
if section not in text:
    text += f"\n{section}\nenabled = true\nbot_token = \"{token}\"\nstream_mode = \"off\"\n"
else:
    parts = text.split(section, 1)
    rest = parts[1]
    m = re.search(r"\n\[", rest)
    body = rest if not m else rest[: m.start()]
    after = "" if not m else rest[m.start() :]
    if re.search(r"(?m)^bot_token\s*=", body):
        body = re.sub(r"(?m)^bot_token\s*=\s*.*$", f'bot_token = "{token}"', body)
    else:
        body = f'\nbot_token = "{token}"' + body
    if "enabled" not in body:
        body = "\nenabled = true" + body
    text = parts[0] + section + body + after
cfg.write_text(text)
print("wrote channels.telegram.depin.bot_token")
PY

"$ZC" --config-dir "$CFG" channel doctor
echo
echo "Next:"
echo "  1) Message @$("$ZC" --config-dir "$CFG" config get channels.telegram.depin 2>/dev/null || true) bot in Telegram"
echo "  2) Send the /bind <code> printed above (if pairing required)"
echo "  3) $ZC --config-dir $CFG channel start"
echo "  4) In Telegram: attest temperature 21.4 for pi-greenhouse-7"
