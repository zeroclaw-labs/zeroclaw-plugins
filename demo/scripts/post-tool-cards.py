#!/usr/bin/env python3
"""Watch channel.log for WASM tool cards and post them to Telegram if the LLM mangles the reply."""
from __future__ import annotations

import json
import os
import re
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CFG = ROOT / "demo/zeroclaw-config/config.toml"
LOG = ROOT / "demo/recording/channel.log"
CHAT_ID = os.environ.get("DEPIN_TG_CHAT_ID", "7339759051")


def bot_token() -> str:
    text = CFG.read_text()
    m = re.search(r'bot_token\s*=\s*"([^"]+)"', text)
    if not m:
        raise SystemExit("bot_token missing")
    return m.group(1)


def send(token: str, text: str) -> None:
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    body = urllib.parse.urlencode(
        {"chat_id": CHAT_ID, "text": text[:4000], "disable_web_page_preview": "true"}
    ).encode()
    req = urllib.request.Request(url, data=body, method="POST")
    with urllib.request.urlopen(req, timeout=30) as resp:
        data = json.loads(resp.read().decode())
    if not data.get("ok"):
        raise RuntimeError(data)


def extract_cards(line: str) -> list[tuple[str, str]]:
    """Return list of (tool, output) from tool_call_result log lines."""
    out: list[tuple[str, str]] = []
    if "tool_call_result" not in line and '"action":"complete"' not in line:
        return out
    if "zc_attrs=" not in line and "zc_attrs" not in line:
        # JSONL style elsewhere; channel.log uses zc_attrs={...}
        pass
    # channel.log format embeds attrs as Rust Debug-ish JSON inside zc_attrs={...}
    m = re.search(r'zc_attrs=(\{.*\}) zc_has_duration=', line)
    if not m:
        return out
    raw = m.group(1)
    # Make it JSON-ish: keys are already JSON in the log
    try:
        # The log uses JSON object for attrs already
        attrs = json.loads(raw)
    except json.JSONDecodeError:
        return out
    tool = attrs.get("tool") or ""
    output = attrs.get("output") or ""
    if tool in {"depin_attest", "depin_uptime_watch"} and output.startswith(("✅", "🟢", "🟡", "🔴")):
        out.append((tool, output))
    return out


def main() -> int:
    token = bot_token()
    timeout = int(sys.argv[1]) if len(sys.argv) > 1 else 180
    seen: set[str] = set()
    # seed seen with existing cards so we only post new ones
    if LOG.exists():
        for line in LOG.read_text(errors="replace").splitlines():
            for tool, output in extract_cards(line):
                seen.add(output[:120])
    print(f"watching {LOG} for new tool cards (timeout={timeout}s)", flush=True)
    start = time.time()
    pos = LOG.stat().st_size if LOG.exists() else 0
    while time.time() - start < timeout:
        if not LOG.exists():
            time.sleep(0.5)
            continue
        size = LOG.stat().st_size
        if size < pos:
            pos = 0
        if size > pos:
            with LOG.open("r", errors="replace") as f:
                f.seek(pos)
                chunk = f.read()
                pos = f.tell()
            for line in chunk.splitlines():
                # also detect mangled IMAGE replies
                if "[IMAGE:" in line and "channel_message_outbound" in line:
                    print("detected mangled IMAGE outbound", flush=True)
                for tool, output in extract_cards(line):
                    key = output[:120]
                    if key in seen:
                        continue
                    seen.add(key)
                    print(f"posting {tool} card ({len(output)} chars)", flush=True)
                    # Prefer full card; Telegram hard limit 4096
                    send(token, output)
                    print("posted ok", flush=True)
        time.sleep(0.4)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
