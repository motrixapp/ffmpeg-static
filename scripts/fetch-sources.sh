#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
umask 077

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
# Script directory is resolved at runtime.
# shellcheck source=common.sh disable=SC1091
source "${SCRIPT_DIR}/common.sh"

TARGET=${1:-}
if (( $# > 1 )); then
  die 'usage: fetch-sources.sh [target]'
fi
if [[ -n "$TARGET" ]]; then
  require_target "$TARGET"
fi

require_command curl tar gpg awk python3
mkdir -p -- "$DOWNLOAD_DIR"
TRANSIENT_SOURCE_DIR=$(mktemp -d "${SOURCE_CACHE_DIR}/source-audit.XXXXXX")
chmod 700 "$TRANSIENT_SOURCE_DIR"
KEYRING_DIR=''
cleanup() {
  rm -rf -- "$TRANSIENT_SOURCE_DIR"
  if [[ -n "$KEYRING_DIR" ]]; then
    rm -rf -- "$KEYRING_DIR"
  fi
}
trap cleanup EXIT

download_verified "$FFMPEG_URL" "${DOWNLOAD_DIR}/${FFMPEG_ARCHIVE}" "$FFMPEG_SHA256"
download_verified "$FFMPEG_SIGNATURE_URL" "${DOWNLOAD_DIR}/${FFMPEG_SIGNATURE_ARCHIVE}" "$FFMPEG_SIGNATURE_SHA256"
download_verified "$X264_URL" "${DOWNLOAD_DIR}/${X264_ARCHIVE}" "$X264_SHA256"
download_verified "$LAME_URL" "${DOWNLOAD_DIR}/${LAME_ARCHIVE}" "$LAME_SHA256"
download_verified "$NASM_URL" "${DOWNLOAD_DIR}/${NASM_ARCHIVE}" "$NASM_SHA256"
download_verified "$MUSL_URL" "${DOWNLOAD_DIR}/${MUSL_ARCHIVE}" "$MUSL_SHA256"
download_verified "$FORTIFY_HEADERS_URL" \
  "${DOWNLOAD_DIR}/${FORTIFY_HEADERS_ARCHIVE}" "$FORTIFY_HEADERS_SHA256"
download_verified "$LLVM_MINGW_RECIPE_URL" \
  "${DOWNLOAD_DIR}/${LLVM_MINGW_RECIPE_ARCHIVE}" "$LLVM_MINGW_RECIPE_SHA256"
download_verified "$LLVM_RUNTIME_URL" \
  "${DOWNLOAD_DIR}/${LLVM_RUNTIME_ARCHIVE}" "$LLVM_RUNTIME_SHA256"
# The full MinGW-w64 tree contains third-party material which is audited for
# provenance but intentionally not mirrored in an Actions artifact, cache, or
# Release. Authenticate it in a private transient directory and delete it on
# every exit path.
download_verified "$MINGW_W64_URL" \
  "${TRANSIENT_SOURCE_DIR}/${MINGW_W64_ARCHIVE}" "$MINGW_W64_SHA256"

if [[ "$TARGET" == win32-* ]]; then
  download_verified "$LLVM_MINGW_URL" "${DOWNLOAD_DIR}/${LLVM_MINGW_ARCHIVE}" "$LLVM_MINGW_SHA256"
fi

KEY_FILE="${FFMPEG_STATIC_ROOT}/keys/ffmpeg-release-signing-key.asc"
[[ -s "$KEY_FILE" ]] || die "missing vendored FFmpeg release key: ${KEY_FILE}"

KEYRING_DIR=$(mktemp -d "${SOURCE_CACHE_DIR}/gnupg.XXXXXX")
chmod 700 "$KEYRING_DIR"

if ! gpg --batch --no-autostart --homedir "$KEYRING_DIR" --quiet \
  --import "$KEY_FILE" >/dev/null 2>&1; then
  die 'failed to import the vendored FFmpeg release key'
fi
IMPORTED_FINGERPRINT=$(gpg --batch --no-autostart --homedir "$KEYRING_DIR" --with-colons \
  --list-keys 2>/dev/null \
  | awk -F: '$1 == "fpr" {print toupper($10); exit}')
[[ "$IMPORTED_FINGERPRINT" == "$FFMPEG_PGP_FINGERPRINT" ]] \
  || die "vendored FFmpeg key fingerprint mismatch: ${IMPORTED_FINGERPRINT:-missing}"

STATUS_FILE="${KEYRING_DIR}/verify.status"
VERIFIED_FFMPEG="${KEYRING_DIR}/ffmpeg-source"
VERIFIED_SIGNATURE="${KEYRING_DIR}/ffmpeg-signature"
cp -- "${DOWNLOAD_DIR}/${FFMPEG_ARCHIVE}" "$VERIFIED_FFMPEG"
cp -- "${DOWNLOAD_DIR}/${FFMPEG_SIGNATURE_ARCHIVE}" "$VERIFIED_SIGNATURE"
chmod 600 "$VERIFIED_FFMPEG" "$VERIFIED_SIGNATURE"
verify_sha256 "$VERIFIED_FFMPEG" "$FFMPEG_SHA256" \
  || die 'FFmpeg source changed before PGP verification'
verify_sha256 "$VERIFIED_SIGNATURE" "$FFMPEG_SIGNATURE_SHA256" \
  || die 'FFmpeg signature changed before PGP verification'
if ! gpg --batch --no-autostart --homedir "$KEYRING_DIR" --status-fd=1 \
  --verify "$VERIFIED_SIGNATURE" "$VERIFIED_FFMPEG" >"$STATUS_FILE"; then
  die 'FFmpeg release PGP signature verification failed'
fi
if ! awk -v expected="$FFMPEG_PGP_FINGERPRINT" '
  $2 == "VALIDSIG" && ($10 == 8 || $10 == 9 || $10 == 10) \
    && (toupper($3) == expected || toupper($NF) == expected) {
    valid++
  }
  $2 == "BADSIG" || $2 == "ERRSIG" || $2 == "NO_PUBKEY" \
    || $2 == "EXPSIG" || $2 == "EXPKEYSIG" || $2 == "REVKEYSIG" \
    || $2 == "KEYEXPIRED" || $2 == "SIGEXPIRED" { invalid = 1 }
  END { exit !(valid == 1 && !invalid) }
' "$STATUS_FILE"; then
  die 'FFmpeg signature was not made by the pinned release key'
fi

validate_tar_archive "${DOWNLOAD_DIR}/${FFMPEG_ARCHIVE}" "$FFMPEG_SHA256"
validate_tar_archive "${DOWNLOAD_DIR}/${X264_ARCHIVE}" "$X264_SHA256"
validate_tar_archive "${DOWNLOAD_DIR}/${LAME_ARCHIVE}" "$LAME_SHA256"
validate_tar_archive "${DOWNLOAD_DIR}/${NASM_ARCHIVE}" "$NASM_SHA256" \
  allow-setgid-directories
validate_tar_archive "${DOWNLOAD_DIR}/${MUSL_ARCHIVE}" "$MUSL_SHA256"
validate_tar_archive "${DOWNLOAD_DIR}/${FORTIFY_HEADERS_ARCHIVE}" "$FORTIFY_HEADERS_SHA256"
validate_tar_archive "${DOWNLOAD_DIR}/${LLVM_MINGW_RECIPE_ARCHIVE}" "$LLVM_MINGW_RECIPE_SHA256"
validate_tar_archive "${DOWNLOAD_DIR}/${LLVM_RUNTIME_ARCHIVE}" "$LLVM_RUNTIME_SHA256"
validate_tar_archive "${TRANSIENT_SOURCE_DIR}/${MINGW_W64_ARCHIVE}" "$MINGW_W64_SHA256"
if [[ "$TARGET" == win32-* ]]; then
  validate_tar_archive "${DOWNLOAD_DIR}/${LLVM_MINGW_ARCHIVE}" "$LLVM_MINGW_SHA256"
fi

log 'all requested inputs passed SHA-256 validation'
log "FFmpeg ${FFMPEG_VERSION} passed PGP verification (${FFMPEG_PGP_FINGERPRINT})"
