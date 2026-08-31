#!/usr/bin/env bash
#
# Pairs each silent clip with its voiceover track, reconciles the two lengths,
# and concatenates everything into one demo-final.mp4.
#
#   ./demo/merge-vo.sh <clips-dir> [vo-dir]
#
# Clips are NN-name.mp4 (01-intro.mp4, 02-install.mp4, ...). Voiceover files are
# matched by that same leading number: 01.mp3, 01.wav, 01-anything.m4a all work.
# vo-dir defaults to <clips-dir>/vo.
#
# Per segment the shorter side is extended rather than the longer one cut, so no
# narration is ever clipped and no on-screen output is lost:
#   audio longer  -> the clip's last frame is held for the remainder
#   video longer  -> silence is appended to the narration
# A clip with no matching audio is kept as-is with a silent track, so you can
# merge before every voiceover file exists.
#
# See VOICEOVER.md for the recording plan and the script to feed your TTS tool.
set -euo pipefail

CLIPS_DIR="${1:?usage: merge-vo.sh <clips-dir> [vo-dir]}"
VO_DIR="${2:-$CLIPS_DIR/vo}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

bold() { printf '\033[1m%s\033[0m\n' "$*"; }
warn() { printf '\033[33mwarning:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }

command -v ffmpeg  >/dev/null || die "ffmpeg not found"
command -v ffprobe >/dev/null || die "ffprobe not found"
[ -d "$CLIPS_DIR" ] || die "no such directory: $CLIPS_DIR"

dur() { # <media file> -> duration in seconds, 3dp
  ffprobe -v error -show_entries format=duration -of csv=p=0 "$1" \
    | awk '{printf "%.3f", $1}'
}

# An interrupted Spectacle recording leaves a file with no moov atom, which is
# indistinguishable from a valid clip until ffprobe chokes on it. Catch it here
# so the failure names the file instead of surfacing as raw ffprobe noise.
check_readable() { # <media file> <kind>
  ffprobe -v error -show_entries format=duration -of csv=p=0 "$1" >/dev/null 2>&1 \
    || die "$2 is unreadable or truncated: $1
       If this was a recording that got interrupted, re-record it."
}

shopt -s nullglob
CLIPS=("$CLIPS_DIR"/[0-9][0-9]*.mp4 "$CLIPS_DIR"/[0-9][0-9]*.mkv "$CLIPS_DIR"/[0-9][0-9]*.webm)
shopt -u nullglob
[ ${#CLIPS[@]} -gt 0 ] \
  || die "no clips in $CLIPS_DIR. Expected files like 01-intro.mp4 (see VOICEOVER.md)."
IFS=$'\n' CLIPS=($(sort <<<"${CLIPS[*]}")); unset IFS

# Normalise every segment to one geometry so concat cannot fail on a mismatch.
# The target is the LARGEST width and height across all clips, so no clip is
# ever downscaled: each is centred and padded with black instead. Rescaling a
# terminal recording visibly softens the text, and this demo is nothing but
# text, so padding is worth the black bars on an inconsistent capture region.
W=0; H=0
for c in "${CLIPS[@]}"; do
  check_readable "$c" "clip"
  g="$(ffprobe -v error -select_streams v:0 -show_entries stream=width,height \
        -of csv=s=x:p=0 "$c" | head -1)"
  [ "${g%x*}" -gt "$W" ] && W="${g%x*}"
  [ "${g#*x}" -gt "$H" ] && H="${g#*x}"
done
# yuv420p needs even dimensions; odd capture regions are common (Spectacle
# region drags routinely land on an odd height).
W=$(( W + W % 2 )); H=$(( H + H % 2 ))
bold "==> target geometry ${W}x${H} (largest across ${#CLIPS[@]} clips; others are padded, never scaled)"

# How much footage may run past the end of the narration before it is cut.
TAIL="${TAIL:-1.0}"

SEGMENTS=()
TOTAL=0

for clip in "${CLIPS[@]}"; do
  base="$(basename "$clip")"
  num="${base%%[-.]*}"
  check_readable "$clip" "clip"

  # nullglob only drops patterns that contain glob characters, so plain paths
  # like "$VO_DIR/01.mp3" survive as literals whether or not they exist. Test
  # each candidate instead, or a run with only 01.wav present would pick the
  # missing 01.mp3 and die inside ffmpeg.
  vo=()
  shopt -s nullglob
  for cand in "$VO_DIR/$num".mp3 "$VO_DIR/$num".wav "$VO_DIR/$num".m4a "$VO_DIR/$num".ogg \
              "$VO_DIR/$num"-*.mp3 "$VO_DIR/$num"-*.wav "$VO_DIR/$num"-*.m4a "$VO_DIR/$num"-*.ogg; do
    [ -f "$cand" ] && vo+=("$cand")
  done
  shopt -u nullglob

  vdur="$(dur "$clip")"
  seg="$WORK/seg-$num.mp4"

  # Pad to the target rather than scale to it: no resampling, so terminal text
  # stays sharp. Centred, black bars.
  VF="pad=$W:$H:(ow-iw)/2:(oh-ih)/2:color=black,fps=30,format=yuv420p"

  if [ ${#vo[@]} -eq 0 ]; then
    warn "$base: no voiceover found in $VO_DIR for '$num' — keeping it silent"
    ffmpeg -nostdin -v error -y -i "$clip" \
      -f lavfi -i anullsrc=channel_layout=stereo:sample_rate=48000 \
      -vf "$VF" \
      -c:v libx264 -preset medium -crf 20 -c:a aac -b:a 192k \
      -shortest "$seg"
    printf '    %-22s video %6ss  (silent)\n' "$base" "$vdur"
  else
    [ ${#vo[@]} -gt 1 ] && warn "$base: ${#vo[@]} audio files match '$num', using $(basename "${vo[0]}")"
    adur="$(dur "${vo[0]}")"

    # Segment length is the narration plus a short tail, except that footage
    # shorter than the narration is never cut off: then the clip's final frame
    # is held (tpad) to cover the remainder. So:
    #   video longer than audio+TAIL -> trimmed to audio+TAIL, no dead air
    #   video shorter than audio     -> last frame held, no narration lost
    # apad covers the tail seconds with silence in the first case.
    seglen="$(awk -v v="$vdur" -v a="$adur" -v t="$TAIL" \
      'BEGIN{want=a+t; print (v<want ? want : v<a ? a : want)}')"

    ffmpeg -nostdin -v error -y -i "$clip" -i "${vo[0]}" \
      -vf "$VF,tpad=stop_mode=clone:stop_duration=600" \
      -af "apad" \
      -map 0:v:0 -map 1:a:0 \
      -c:v libx264 -preset medium -crf 20 -c:a aac -b:a 192k -ar 48000 -ac 2 \
      -t "$seglen" "$seg"

    delta="$(awk -v v="$vdur" -v a="$adur" 'BEGIN{printf "%+.1f", a-v}')"
    note=""
    if awk -v v="$vdur" -v a="$adur" 'BEGIN{exit !(a-v>3)}'; then
      warn "$base: narration outruns the clip by ${delta}s — that long a frozen frame will read as a stall. Re-record this one a few seconds longer."
      note="holding last frame"
    elif awk -v v="$vdur" -v s="$seglen" 'BEGIN{exit !(v-s>0.5)}'; then
      note="trimmed $(awk -v v="$vdur" -v s="$seglen" 'BEGIN{printf "%.1f", v-s}')s of tail"
    fi
    printf '    %-22s video %6ss  audio %6ss  (%s)%s\n' \
      "$base" "$vdur" "$adur" "$delta" "${note:+  $note}"
  fi

  SEGMENTS+=("$seg")
  TOTAL="$(awk -v t="$TOTAL" -v d="$(dur "$seg")" 'BEGIN{printf "%.3f", t+d}')"
done

bold "==> concatenating ${#SEGMENTS[@]} segments"
: > "$WORK/list.txt"
for s in "${SEGMENTS[@]}"; do printf "file '%s'\n" "$s" >> "$WORK/list.txt"; done

OUT="$CLIPS_DIR/demo-final.mp4"
ffmpeg -nostdin -v error -y -f concat -safe 0 -i "$WORK/list.txt" \
  -c copy -movflags +faststart "$OUT"

FINAL="$(dur "$OUT")"
bold "==> $OUT"
printf '    %s (%dm%02ds)\n' "${FINAL}s" "$(awk -v f="$FINAL" 'BEGIN{print int(f/60)}')" \
                                        "$(awk -v f="$FINAL" 'BEGIN{print int(f)%60}')"
if awk -v f="$FINAL" 'BEGIN{exit !(f>180)}'; then
  warn "over the 3:00 target by $(awk -v f="$FINAL" 'BEGIN{printf "%.0f", f-180}')s. DEMO-SCRIPT.md has a cut-to-2:00 path: drop clip 04."
fi
