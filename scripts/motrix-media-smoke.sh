#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

die() {
  printf 'motrix media smoke: %s\n' "$*" >&2
  exit 1
}

[[ $# -eq 3 ]] \
  || die 'usage: motrix-media-smoke.sh <ffmpeg> <ffprobe> <work-directory>'

FFMPEG=$1
FFPROBE=$2
WORK_DIR=$3

[[ -x "$FFMPEG" && -f "$FFMPEG" ]] \
  || die "ffmpeg is not an executable regular file: ${FFMPEG}"
[[ -x "$FFPROBE" && -f "$FFPROBE" ]] \
  || die "ffprobe is not an executable regular file: ${FFPROBE}"
mkdir -p -- "$WORK_DIR"
[[ -d "$WORK_DIR" && ! -L "$WORK_DIR" ]] \
  || die "work directory is unsafe: ${WORK_DIR}"

export LC_ALL=C TZ=UTC
unset CFLAGS CXXFLAGS CPPFLAGS LDFLAGS CPATH C_INCLUDE_PATH CPLUS_INCLUDE_PATH
unset LIBRARY_PATH PKG_CONFIG_PATH PKG_CONFIG_LIBDIR CONFIG_SITE MAKEFLAGS MFLAGS

assert_equal() {
  local expected=$1
  local actual=$2
  local operation=$3
  [[ "$actual" == "$expected" ]] \
    || die "${operation}: expected ${expected}, got ${actual:-<empty>}"
}

probe_value() {
  local selector=$1
  local entry=$2
  local path=$3
  "$FFPROBE" -v error -select_streams "$selector" \
    -show_entries "stream=${entry}" -of default=nw=1:nk=1 -- "$path"
}

assert_mp4_format() {
  local path=$1
  local format
  format=$(
    "$FFPROBE" -v error -show_entries format=format_name \
      -of default=nw=1:nk=1 -- "$path"
  )
  case ",${format}," in
    *,mp4,*) ;;
    *) die "expected an MP4-family container, got ${format:-<empty>}: ${path}" ;;
  esac
}

require_listing_token() {
  local listing=$1
  local token=$2
  local kind=$3
  grep -Eq "^[[:space:]]*[^[:space:]]*[[:space:]]+${token}([[:space:]]|$)" <<<"$listing" \
    || die "required ${kind} is unavailable: ${token}"
}

version_output=$("$FFMPEG" -version 2>&1)
probe_version_output=$("$FFPROBE" -version 2>&1)
grep -Fq -- '--enable-libx264' <<<"$version_output" \
  || die 'ffmpeg does not report --enable-libx264'
grep -Fq -- '--enable-libmp3lame' <<<"$version_output" \
  || die 'ffmpeg does not report --enable-libmp3lame'
grep -Fq 'ffprobe version' <<<"$probe_version_output" \
  || die 'ffprobe version output is invalid'

muxers_output=$("$FFMPEG" -hide_banner -muxers 2>&1)
for muxer in mp4 ipod mov matroska webm mpegts flv adts mp3 opus; do
  require_listing_token "$muxers_output" "$muxer" muxer
done

bsfs_output=$("$FFMPEG" -hide_banner -bsfs 2>&1)
grep -Eq '^[[:space:]]*aac_adtstoasc[[:space:]]*$' <<<"$bsfs_output" \
  || die 'required bitstream filter is unavailable: aac_adtstoasc'

encoders_output=$("$FFMPEG" -hide_banner -encoders 2>&1)
for encoder in libx264 aac libmp3lame flac pcm_s16le mjpeg; do
  require_listing_token "$encoders_output" "$encoder" encoder
done

filters_output=$("$FFMPEG" -hide_banner -filters 2>&1)
require_listing_token "$filters_output" scale filter

video_only="${WORK_DIR}/video-only.mp4"
audio_only="${WORK_DIR}/audio-only.m4a"
merged="${WORK_DIR}/merged.mp4.motrix"
transport_stream="${WORK_DIR}/mpegts-aac.ts"
ts_remux="${WORK_DIR}/mpegts-remux.mp4.motrix"
mp3_output="${WORK_DIR}/audio.mp3"
flac_output="${WORK_DIR}/audio.flac"
wav_output="${WORK_DIR}/audio.wav"
thumbnail="${WORK_DIR}/thumbnail.jpg"
matroska_output="${WORK_DIR}/remux.mkv"

"$FFMPEG" -hide_banner -loglevel error -nostdin -y \
  -f lavfi -i 'testsrc2=size=128x96:rate=2' \
  -t 1 -an -c:v libx264 -pix_fmt yuv420p -f mp4 "$video_only"
"$FFMPEG" -hide_banner -loglevel error -nostdin -y \
  -f lavfi -i 'sine=frequency=1000:sample_rate=48000' \
  -t 1 -vn -c:a aac -f ipod "$audio_only"

# Mirrors FfmpegService.buildArgs for a separate-video/separate-audio job whose
# temporary `.motrix` output cannot be inferred from its file extension.
"$FFMPEG" -hide_banner -loglevel error -nostdin \
  -i "$video_only" -i "$audio_only" \
  -c copy -map 0:v:0 -map 1:a:0 \
  -movflags +faststart -f mp4 \
  -progress pipe:1 -nostats -y "$merged" >"${WORK_DIR}/merge.progress"
grep -Eq '^progress=end\r?$' "${WORK_DIR}/merge.progress" \
  || die 'dual-input Motrix remux did not report progress=end'
assert_equal h264 "$(probe_value v:0 codec_name "$merged")" 'dual-input video codec'
assert_equal aac "$(probe_value a:0 codec_name "$merged")" 'dual-input audio codec'
assert_mp4_format "$merged"

"$FFMPEG" -hide_banner -loglevel error -nostdin -y \
  -f lavfi -i 'testsrc2=size=128x96:rate=2' \
  -f lavfi -i 'sine=frequency=880:sample_rate=48000' \
  -t 1 -c:v libx264 -pix_fmt yuv420p -c:a aac \
  -f mpegts "$transport_stream"

# Mirrors the fromMpegts path in FfmpegService, including the AAC bitstream
# filter and the explicit muxer required by the `.motrix` placeholder.
"$FFMPEG" -hide_banner -loglevel error -nostdin \
  -i "$transport_stream" -c copy -bsf:a aac_adtstoasc \
  -movflags +faststart -f mp4 \
  -progress pipe:1 -nostats -y "$ts_remux" >"${WORK_DIR}/mpegts.progress"
grep -Eq '^progress=end\r?$' "${WORK_DIR}/mpegts.progress" \
  || die 'MPEG-TS Motrix remux did not report progress=end'
assert_equal h264 "$(probe_value v:0 codec_name "$ts_remux")" 'MPEG-TS remux video codec'
assert_equal aac "$(probe_value a:0 codec_name "$ts_remux")" 'MPEG-TS remux audio codec'
assert_mp4_format "$ts_remux"

"$FFMPEG" -hide_banner -loglevel error -nostdin -y \
  -f lavfi -i 'sine=frequency=440:sample_rate=44100' \
  -t 1 -vn -c:a libmp3lame "$mp3_output"
assert_equal mp3 "$(probe_value a:0 codec_name "$mp3_output")" 'MP3 codec'
"$FFMPEG" -hide_banner -loglevel error -nostdin -i "$mp3_output" -f null -

"$FFMPEG" -hide_banner -loglevel error -nostdin -y \
  -f lavfi -i 'sine=frequency=550:sample_rate=44100' \
  -t 1 -vn -c:a flac "$flac_output"
assert_equal flac "$(probe_value a:0 codec_name "$flac_output")" 'FLAC codec'

"$FFMPEG" -hide_banner -loglevel error -nostdin -y \
  -f lavfi -i 'sine=frequency=660:sample_rate=44100' \
  -t 1 -vn -c:a pcm_s16le "$wav_output"
assert_equal pcm_s16le "$(probe_value a:0 codec_name "$wav_output")" 'PCM WAV codec'

"$FFMPEG" -hide_banner -loglevel error -nostdin -y \
  -ss 0 -i "$merged" -frames:v 1 -vf 'scale=64:48' "$thumbnail"
assert_equal mjpeg "$(probe_value v:0 codec_name "$thumbnail")" 'thumbnail codec'
assert_equal 64 "$(probe_value v:0 width "$thumbnail")" 'thumbnail width'
assert_equal 48 "$(probe_value v:0 height "$thumbnail")" 'thumbnail height'

"$FFMPEG" -hide_banner -loglevel error -nostdin -y \
  -i "$merged" -map 0 -c copy -f matroska "$matroska_output"
matroska_format=$(
  "$FFPROBE" -v error -show_entries format=format_name \
    -of default=nw=1:nk=1 -- "$matroska_output"
)
grep -Fq matroska <<<"$matroska_format" \
  || die "Matroska remux has unexpected format: ${matroska_format:-<empty>}"

printf 'Motrix media smoke passed: %s\n' "$WORK_DIR"
