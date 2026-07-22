#!/usr/bin/env bash
# Record Telegram WINDOW only + terminal + explorer → combined final MP4.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
REC="$ROOT/demo/recording"
SEG="$REC/segments"
mkdir -p "$SEG"
# shellcheck disable=SC1091
source "$ROOT/demo/keys/env.sh"

need() { command -v "$1" >/dev/null || { echo "missing $1"; exit 1; }; }
need ffmpeg; need ffprobe; need swift; need osascript; need python3

win_bounds() {
  local app="$1"
  swift -e '
import Cocoa
import CoreGraphics
let want = "'"$app"'".lowercased()
let opts = CGWindowListOption(arrayLiteral: .optionOnScreenOnly, .excludeDesktopElements)
guard let info = CGWindowListCopyWindowInfo(opts, kCGNullWindowID) as? [[String: Any]] else { exit(1) }
var best: (Int, Int, Int, Int, Int)? = nil
for w in info {
  let owner = (w[kCGWindowOwnerName as String] as? String ?? "").lowercased()
  let layer = w[kCGWindowLayer as String] as? Int ?? -1
  guard layer == 0, owner.contains(want) else { continue }
  let b = w[kCGWindowBounds as String] as? [String: Any] ?? [:]
  let x = Int((b["X"] as? NSNumber)?.doubleValue ?? 0)
  let y = Int((b["Y"] as? NSNumber)?.doubleValue ?? 0)
  let ww = Int((b["Width"] as? NSNumber)?.doubleValue ?? 0)
  let hh = Int((b["Height"] as? NSNumber)?.doubleValue ?? 0)
  let wid = w[kCGWindowNumber as String] as? Int ?? 0
  if ww < 200 || hh < 200 { continue }
  if best == nil || (ww * hh) > (best!.2 * best!.3) {
    best = (x, y, ww, hh, wid)
  }
}
guard let b = best else { exit(2) }
print("\(b.0),\(b.1),\(b.2),\(b.3),\(b.4)")
'
}

even() { echo $(( ($1 / 2) * 2 )); }

activate() { osascript -e "tell application \"$1\" to activate" >/dev/null; sleep 0.5; }

type_send() {
  printf '%s' "$1" | pbcopy
  osascript <<'OSA'
tell application "System Events"
  keystroke "v" using command down
  delay 0.25
  key code 36
end tell
OSA
}

hold_png() {
  local png="$1" out="$2" secs="$3"
  ffmpeg -y -loop 1 -i "$png" -t "$secs" -r 30 \
    -vf "scale=trunc(iw/2)*2:trunc(ih/2)*2" \
    -c:v libx264 -pix_fmt yuv420p -an "$out" >/dev/null 2>&1
}

tg_click_composer() {
  local x="$1" y="$2" w="$3" h="$4"
  osascript <<OSA
tell application "System Events"
  tell process "Telegram"
    set frontmost to true
    delay 0.3
    click at {$((x + w / 2)), $((y + h - 40))}
  end tell
end tell
OSA
}

wait_log() {
  local pat="$1" secs="$2"
  local deadline=$((SECONDS + secs))
  while (( SECONDS < deadline )); do
    if rg -q "$pat" "$REC/channel.log" 2>/dev/null; then return 0; fi
    sleep 1
  done
  return 1
}

echo "== window bounds =="
TG="$(win_bounds Telegram)" || { echo "Open Telegram bot chat first"; exit 1; }
IFS=',' read -r TGX TGY TGW TGH TGID <<<"$TG"
echo "Telegram: $TGX,$TGY ${TGW}x${TGH} id=$TGID"

echo "== refresh channel log + card poster =="
PIDF="$REC/channel.pid"
if [[ -f "$PIDF" ]]; then kill "$(cat "$PIDF")" 2>/dev/null || true; fi
pkill -f 'zeroclaw-plugins --config-dir .*demo/zeroclaw-config .*channel start' 2>/dev/null || true
sleep 1
rm -f "$PIDF"
: > "$REC/channel.log"
"$ROOT/demo/scripts/keep-channel.sh"
sleep 3
python3 "$ROOT/demo/scripts/post-tool-cards.py" 300 >"$SEG/card-poster.log" 2>&1 &
POSTER_PID=$!

echo "== clear chat =="
activate "Telegram"
tg_click_composer "$TGX" "$TGY" "$TGW" "$TGH"
sleep 0.3
type_send "/clear"
wait_log 'Conversation history cleared|Starting fresh|/clear' 20 || true
sleep 2

echo "== start desktop capture (will crop to Telegram window) =="
RAW="$SEG/desktop-raw.mov"
TGVID="$SEG/01-telegram.mp4"
rm -f "$RAW" "$TGVID"
ffmpeg -y -f avfoundation -capture_cursor 1 -framerate 30 -i "1:none" \
  -c:v libx264 -pix_fmt yuv420p -preset ultrafast "$RAW" >/dev/null 2>&1 &
FFPID=$!
sleep 2

echo "== show slash command list briefly =="
activate "Telegram"
tg_click_composer "$TGX" "$TGY" "$TGW" "$TGH"
printf '%s' '/' | pbcopy
osascript -e 'tell application "System Events" to keystroke "v" using command down'
sleep 3
osascript -e 'tell application "System Events" to key code 53'
sleep 0.4

MARK_ATTEST="$(date -u +%Y-%m-%dT%H:%M:%S)"
echo "== attest @ $MARK_ATTEST =="
type_send "Attest device pi-greenhouse-7 metric temperature reading 21.4 unit celsius"
# Wait until tool result exists (card poster will send ✅)
if wait_log 'tool_call_result.*depin_attest|"tool":"depin_attest".*output' 100; then
  echo "attest tool finished"
else
  echo "WARN: attest tool result not seen"
fi
# Give poster + Telegram UI time to paint card
sleep 8

echo "== human sign+submit =="
TERMLOG="$SEG/terminal-live.txt"
{
  echo "=============================================="
  echo " ZeroClaw DePIN — human custody (sign+submit)"
  echo "=============================================="
  echo
  DEPIN_SUBMIT=1 cargo +1.96.1 run --manifest-path "$ROOT/demo/runner/Cargo.toml" --release --quiet
} | tee "$TERMLOG"
EXPLORER="$(rg -o 'https://explorer\.solana\.com/tx/[A-Za-z0-9]+' "$TERMLOG" | head -1 || true)"
if [[ -n "$EXPLORER" ]]; then
  EXPLORER="${EXPLORER}?cluster=devnet"
  echo "$EXPLORER" > "$REC/explorer.url"
  python3 - <<PY
import json,re,urllib.parse,urllib.request
from pathlib import Path
cfg=Path("$ROOT/demo/zeroclaw-config/config.toml").read_text()
token=re.search(r'bot_token\\s*=\\s*"([^"]+)"', cfg).group(1)
text="🌐 On-chain proof (devnet)\\n$EXPLORER\\n✅ Success — human signed + submitted"
body=urllib.parse.urlencode({"chat_id":"7339759051","text":text,"disable_web_page_preview":"false"}).encode()
req=urllib.request.Request(f"https://api.telegram.org/bot{token}/sendMessage", data=body, method="POST")
print(json.loads(urllib.request.urlopen(req, timeout=30).read())["ok"])
PY
fi
sleep 4

echo "== uptime check =="
activate "Telegram"
tg_click_composer "$TGX" "$TGY" "$TGW" "$TGH"
type_send "Check uptime for pi-greenhouse-7"
if wait_log 'tool_call_result.*depin_uptime_watch|"tool":"depin_uptime_watch"' 100; then
  echo "uptime tool finished"
else
  echo "WARN: uptime tool result not seen"
fi
sleep 10

echo "== stop recorder =="
kill -INT "$FFPID" 2>/dev/null || true
wait "$FFPID" 2>/dev/null || true
kill "$POSTER_PID" 2>/dev/null || true
wait "$POSTER_PID" 2>/dev/null || true
sleep 1

TW="$(even "$TGW")"; TH="$(even "$TGH")"
echo "Cropping Telegram window ${TW}x${TH} at ${TGX},${TGY}"
ffmpeg -y -i "$RAW" -vf "crop=${TW}:${TH}:${TGX}:${TGY}" \
  -c:v libx264 -pix_fmt yuv420p -an "$TGVID" >/dev/null 2>&1
ffprobe -v error -show_entries stream=width,height,duration -of default=nw=1 "$TGVID"

echo "== terminal segment =="
python3 - "$TERMLOG" "$SEG/02-terminal.mp4" <<'PY'
import subprocess, sys
from pathlib import Path
log = Path(sys.argv[1]).read_text(errors="replace")
out = Path(sys.argv[2])
lines = []
for line in log.splitlines():
    if len(line) > 100:
        line = line[:88] + "…"
    lines.append(line)
text = "\n".join(lines[-70:])
srt = out.with_suffix(".srt")
body = text.replace("&", "and")
srt.write_text("1\n00:00:00,000 --> 00:00:28,000\n" + "\n".join(body.splitlines()[:55]) + "\n")
subprocess.check_call([
  "ffmpeg","-y","-f","lavfi","-i","color=c=0x0b1220:s=1280x720:d=28",
  "-vf", f"subtitles={srt}:force_style='FontName=Menlo,FontSize=15,PrimaryColour=&H00E6EDF3&,Alignment=7,MarginL=36,MarginV=36'",
  "-c:v","libx264","-pix_fmt","yuv420p","-an",str(out)
], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
print("wrote", out)
PY

echo "== explorer segment =="
if [[ -n "${EXPLORER:-}" ]]; then
  activate "Google Chrome"
  open "$EXPLORER"
  sleep 5
  CH="$(win_bounds "Google Chrome" || true)"
  EXPNG="$SEG/explorer.png"
  if [[ -n "$CH" ]]; then
    IFS=',' read -r CHX CHY CHW CHH CHID <<<"$CH"
    screencapture -x -l "$CHID" "$EXPNG"
  else
    screencapture -x "$EXPNG"
  fi
  hold_png "$EXPNG" "$SEG/03-explorer.mp4" 20
fi

echo "== normalize + concat =="
LIST="$SEG/concat.txt"
: > "$LIST"
for f in "$SEG/01-telegram.mp4" "$SEG/02-terminal.mp4" "$SEG/03-explorer.mp4"; do
  [[ -f "$f" ]] || continue
  nf="${f%.mp4}.norm.mp4"
  ffmpeg -y -i "$f" \
    -vf "scale=1280:720:force_original_aspect_ratio=decrease,pad=1280:720:(ow-iw)/2:(oh-ih)/2:color=0x0b1220,fps=30,setsar=1" \
    -c:v libx264 -pix_fmt yuv420p -an "$nf" >/dev/null 2>&1
  printf "file '%s'\n" "$(basename "$nf")" >> "$LIST"
done
(
  cd "$SEG"
  ffmpeg -y -f concat -safe 0 -i concat.txt -c:v libx264 -pix_fmt yuv420p -movflags +faststart \
    "$REC/zeroclaw-depin-demo-2min.mp4" >/dev/null 2>&1
)
cp "$REC/zeroclaw-depin-demo-2min.mp4" "$HOME/Desktop/zeroclaw-depin-demo.mp4"
cp "$REC/zeroclaw-depin-demo-2min.mp4" "$HOME/Downloads/zeroclaw-depin-demo-2min.mp4"
echo
echo "DONE $(ffprobe -v error -show_entries format=duration -of default=nw=1:nk=1 "$REC/zeroclaw-depin-demo-2min.mp4")s"
echo "  $REC/zeroclaw-depin-demo-2min.mp4"
echo "  ~/Desktop/zeroclaw-depin-demo.mp4"
echo "Telegram crop size:"
ffprobe -v error -show_entries stream=width,height -of default=nw=1 "$TGVID"
