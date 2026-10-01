#!/usr/bin/env bash

set -euo pipefail
export LC_ALL=C
export TZ=UTC

usage() {
  echo "usage: $0 <darwin-arm64|darwin-x64> <payload-directory> <public-facts-directory>" >&2
  exit 2
}

[[ $# -eq 3 ]] || usage
target=$1
payload_dir=$2
facts_dir=$3
script_path=${BASH_SOURCE[0]}
script_parent=${script_path%/*}
[[ "$script_parent" != "$script_path" ]] || script_parent=.
script_dir=$(cd -- "$script_parent" && pwd -P)

case "$target" in
  darwin-arm64|darwin-x64) ;;
  *) usage ;;
esac

: "${MAC_CERTS:?MAC_CERTS must contain a base64-encoded Developer ID Application PKCS#12 file}"
: "${MAC_CERTS_PASSWORD:?MAC_CERTS_PASSWORD must contain the PKCS#12 password}"
: "${EXPECTED_MACOS_TEAM_ID:?EXPECTED_MACOS_TEAM_ID must identify the approved Apple team}"
: "${EXPECTED_MACOS_CERT_SHA256:?EXPECTED_MACOS_CERT_SHA256 must identify the approved certificate}"

isolated_python=/usr/bin/python3
[[ -f "$isolated_python" && -x "$isolated_python" ]] || {
  echo "missing trusted system Python: $isolated_python" >&2
  exit 1
}
readonly isolated_python

# GitHub injects step secrets as exported variables. Keep them only as shell
# values so no child process receives either secret implicitly. The decoder
# gets the PKCS#12 bytes exclusively over stdin; security(1) gets the password
# only as its required argument below.
export -n MAC_CERTS MAC_CERTS_PASSWORD

[[ "$EXPECTED_MACOS_TEAM_ID" =~ ^[A-Z0-9]{10}$ ]] || {
  echo "EXPECTED_MACOS_TEAM_ID must be 10 uppercase letters or digits" >&2
  exit 1
}
expected_certificate_sha256=$(printf '%s' "$EXPECTED_MACOS_CERT_SHA256" |
  tr '[:lower:]' '[:upper:]')
[[ "$expected_certificate_sha256" =~ ^[0-9A-F]{64}$ ]] || {
  echo "EXPECTED_MACOS_CERT_SHA256 must be a 64-character SHA-256 digest" >&2
  exit 1
}

for executable in ffmpeg ffprobe; do
  [[ -f "$payload_dir/$executable" && ! -L "$payload_dir/$executable" ]] || {
    echo "missing regular executable: $payload_dir/$executable" >&2
    exit 1
  }
done

[[ ! -e "$facts_dir" ]] || {
  echo "public facts directory already exists: $facts_dir" >&2
  exit 1
}
mkdir -p -- "$facts_dir"

umask 077
signing_dir=$(mktemp -d)
keychain="$signing_dir/motrix-ffmpeg-signing.keychain-db"
certificate="$signing_dir/developer-id.p12"
original_keychains=()
keychain_mutated=0

cleanup() {
  local status=$?
  trap - EXIT
  if [[ "$keychain_mutated" -eq 1 ]]; then
    # create-keychain can itself change the search list. Restore the snapshot
    # on every exit, including import/signing failures, before deleting ours.
    if [[ ${#original_keychains[@]} -gt 0 ]]; then
      if ! security list-keychains -d user -s "${original_keychains[@]}" >/dev/null 2>&1; then
        echo "could not restore the original user keychain search list" >&2
        status=1
      fi
    elif ! security list-keychains -d user -s >/dev/null 2>&1; then
      echo "could not restore the original empty user keychain search list" >&2
      status=1
    fi
    if ! security delete-keychain "$keychain" >/dev/null 2>&1; then
      echo "could not delete the temporary signing keychain" >&2
      status=1
    fi
  fi
  if ! rm -rf -- "$signing_dir"; then
    echo "could not remove temporary signing material" >&2
    status=1
  fi
  exit "$status"
}
trap cleanup EXIT
chmod 700 "$signing_dir"
keychain_password=$(openssl rand -hex 24)

# codesign's --keychain restricts identity selection, but does not replace the
# user search list needed for signing identities and certificate-chain lookup.
# Capture BEFORE create-keychain, preserve order/spaces verbatim, never eval
# security output, and fail before any mutation if the inventory is malformed.
security list-keychains -d user >"$signing_dir/original-keychains.txt"
"$isolated_python" -I -c '
import sys

raw = sys.stdin.buffer.read(65537)
if len(raw) > 65536 or b"\x00" in raw:
    raise SystemExit("invalid user keychain search list")
paths = []
for line in raw.split(b"\n"):
    line = line.strip(b" \t")
    if not line:
        continue
    if not (line.startswith(b"\"") and line.endswith(b"\"")):
        raise SystemExit("invalid user keychain search list")
    path = line[1:-1]
    if (not path.startswith(b"/") or len(path) > 4096
            or any(byte < 32 or byte == 127 for byte in path)
            or path in paths or len(paths) >= 256):
        raise SystemExit("invalid user keychain search list")
    paths.append(path)
sys.stdout.buffer.write(b"".join(path + b"\x00" for path in paths))
' <"$signing_dir/original-keychains.txt" >"$signing_dir/original-keychains.nul"
while IFS= read -r -d '' original_keychain; do
  original_keychains+=("$original_keychain")
done <"$signing_dir/original-keychains.nul"

printf '%s' "$MAC_CERTS" | "$isolated_python" -I -c \
  '
import base64
import binascii
import sys

# Accept conventional wrapped Base64, not arbitrary discarded characters.
# GitHub Secrets are smaller than this raw-input bound, including whitespace.
raw = sys.stdin.buffer.read(65537)
encoded = raw.translate(None, b" \t\r\n")
if len(raw) > 65536 or not encoded:
    raise SystemExit("invalid MAC_CERTS Base64 encoding or size")
try:
    decoded = base64.b64decode(encoded, validate=True)
except binascii.Error:
    raise SystemExit("invalid MAC_CERTS Base64 encoding or size") from None
if not decoded or base64.b64encode(decoded) != encoded:
    raise SystemExit("invalid MAC_CERTS Base64 encoding or size")
sys.stdout.buffer.write(decoded)
' \
  >"$certificate"
unset MAC_CERTS
chmod 600 "$certificate"

keychain_mutated=1
security create-keychain -p "$keychain_password" "$keychain"
security set-keychain-settings -lut 3600 "$keychain"
security unlock-keychain -p "$keychain_password" "$keychain"
security import "$certificate" \
  -k "$keychain" \
  -P "$MAC_CERTS_PASSWORD" \
  -T /usr/bin/codesign \
  -x \
  -f pkcs12
unset MAC_CERTS_PASSWORD
security set-key-partition-list \
  -S apple-tool:,apple:,codesign: \
  -s \
  -k "$keychain_password" \
  "$keychain" >/dev/null

if [[ ${#original_keychains[@]} -gt 0 ]]; then
  security list-keychains -d user -s "$keychain" "${original_keychains[@]}"
else
  security list-keychains -d user -s "$keychain"
fi

identities=$(security find-identity -v -p codesigning "$keychain" |
  awk '/Developer ID Application:/ { print $2 }')
identity_count=$(printf '%s\n' "$identities" | awk 'NF { count += 1 } END { print count + 0 }')
if [[ "$identity_count" -ne 1 ]]; then
  echo "expected exactly one Developer ID Application identity, found $identity_count" >&2
  exit 1
fi
identity=$(printf '%s\n' "$identities" | awk 'NF { print; exit }')
identity_label=$(security find-identity -v -p codesigning "$keychain" |
  awk '/Developer ID Application:/ { sub(/^[^"]*"/, ""); sub(/".*$/, ""); print; exit }')
[[ -n "$identity_label" ]] || {
  echo "could not determine the Developer ID Application certificate label" >&2
  exit 1
}
actual_team_id=$(printf '%s\n' "$identity_label" |
  sed -nE 's/^.*\(([A-Z0-9]{10})\)$/\1/p')
[[ "$actual_team_id" == "$EXPECTED_MACOS_TEAM_ID" ]] || {
  echo "Developer ID team identifier does not match EXPECTED_MACOS_TEAM_ID" >&2
  exit 1
}

certificate_subject=$identity_label
[[ -n "$certificate_subject" ]] || {
  echo "could not determine the Developer ID certificate subject" >&2
  exit 1
}

actual_certificate_sha256=
for executable in ffmpeg ffprobe; do
  binary="$payload_dir/$executable"
  chmod 755 "$binary"
  codesign \
    --force \
    --options runtime \
    --timestamp \
    --keychain "$keychain" \
    --sign "$identity" \
    --identifier "net.agalwood.motrix.$executable" \
    "$binary"
  codesign --verify --strict --verbose=2 "$binary"
  signing_display=$(codesign --display --verbose=4 "$binary" 2>&1)
  signed_team_id=$(printf '%s\n' "$signing_display" |
    awk -F= '$1 == "TeamIdentifier" { print $2; exit }')
  [[ "$signed_team_id" == "$EXPECTED_MACOS_TEAM_ID" ]] || {
    echo "signed binary has an unexpected TeamIdentifier: $binary" >&2
    exit 1
  }
  cd_hash=$(printf '%s\n' "$signing_display" |
    awk -F= '$1 == "CDHash" { print tolower($2); exit }')
  secure_timestamp=$(printf '%s\n' "$signing_display" |
    awk -F= '$1 == "Timestamp" { sub(/^[^=]*=/, ""); print; exit }')
  signed_identifier=$(printf '%s\n' "$signing_display" |
    awk -F= '$1 == "Identifier" { print $2; exit }')
  [[ "$cd_hash" =~ ^[0-9a-f]{40}$|^[0-9a-f]{64}$ ]] || {
    echo "signed binary is missing a valid CDHash: $binary" >&2
    exit 1
  }
  [[ -n "$secure_timestamp" ]] || {
    echo "signed binary is missing a secure timestamp: $binary" >&2
    exit 1
  }
  [[ "$signed_identifier" == "net.agalwood.motrix.$executable" ]] || {
    echo "signed binary has an unexpected identifier: $binary" >&2
    exit 1
  }
  signed_certificate_prefix="$signing_dir/${executable}-signed-certificate"
  codesign --display --extract-certificates="$signed_certificate_prefix" "$binary"
  signed_leaf_certificate="${signed_certificate_prefix}0"
  [[ -f "$signed_leaf_certificate" && ! -L "$signed_leaf_certificate" ]] || {
    echo "signed binary is missing its embedded leaf certificate: $binary" >&2
    exit 1
  }
  signed_certificate_sha256=$(shasum -a 256 -- "$signed_leaf_certificate" |
    awk '{ print toupper($1) }')
  [[ "$signed_certificate_sha256" == "$expected_certificate_sha256" ]] || {
    echo "signed binary certificate does not match EXPECTED_MACOS_CERT_SHA256: $binary" >&2
    exit 1
  }
  if [[ -n "$actual_certificate_sha256" &&
        "$actual_certificate_sha256" != "$signed_certificate_sha256" ]]; then
    echo "ffmpeg and ffprobe were signed by different leaf certificates" >&2
    exit 1
  fi
  actual_certificate_sha256=$signed_certificate_sha256
  if ! printf '%s\n' "$signing_display" | "$isolated_python" -I -c '
import sys
sys.path.insert(0, sys.argv[1])
from pipeline_lib import validate_codesign_hardened_runtime
try:
    validate_codesign_hardened_runtime(sys.stdin.read())
except ValueError as error:
    raise SystemExit(str(error))
' "$script_dir"; then
    echo "signed binary is missing hardened runtime: $binary" >&2
    exit 1
  fi
  printf '%s\n' "$cd_hash" >"$facts_dir/${executable}-cdhash.txt"
  printf '%s\n' "$secure_timestamp" >"$facts_dir/${executable}-timestamp.txt"
  printf '%s\n' "$signed_identifier" >"$facts_dir/${executable}-identifier.txt"
done

[[ -n "$actual_certificate_sha256" ]] || {
  echo "signed certificate identity was not captured" >&2
  exit 1
}

# These files contain public identity material only. They are consumed after the
# secret-bearing signing step has exited and the temporary keychain is deleted.
printf '%s\n' "$actual_team_id" >"$facts_dir/team-id.txt"
printf '%s\n' "$actual_certificate_sha256" | tr '[:upper:]' '[:lower:]' \
  >"$facts_dir/certificate-sha256.txt"
printf '%s\n' "$certificate_subject" >"$facts_dir/certificate-subject.txt"
