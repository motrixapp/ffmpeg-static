#!/usr/bin/env bash

set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo "usage: $0 <signed-zip> <submission-result-json> <developer-log-json>" >&2
  exit 2
fi

archive=$1
result_json=$2
developer_log=$3
script_path=${BASH_SOURCE[0]}
script_parent=${script_path%/*}
[[ "$script_parent" != "$script_path" ]] || script_parent=.
script_dir=$(cd -- "$script_parent" && pwd -P)
isolated_python=/usr/bin/python3
[[ -f "$isolated_python" && -x "$isolated_python" ]] || {
  echo "missing trusted system Python: $isolated_python" >&2
  exit 1
}
readonly isolated_python

: "${API_KEY:?API_KEY must contain the App Store Connect private key contents}"
: "${API_KEY_ID:?API_KEY_ID must contain the App Store Connect key ID}"
: "${API_KEY_ISSUER_ID:?API_KEY_ISSUER_ID must contain the App Store Connect issuer ID}"

[[ "$API_KEY_ID" =~ ^[A-Za-z0-9]{10}$ ]] || {
  echo "API_KEY_ID must be 10 letters or digits" >&2
  exit 1
}
[[ "$API_KEY_ISSUER_ID" =~ ^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$ ]] || {
  echo "API_KEY_ISSUER_ID must be a UUID" >&2
  exit 1
}

# Keep credentials out of every child-process environment. The private key is
# handed to notarytool only through its mode-0600 file; the public identifiers
# are supplied as explicit arguments.
export -n API_KEY API_KEY_ID API_KEY_ISSUER_ID

[[ -f "$archive" && ! -L "$archive" && "$archive" == *.zip ]] || {
  echo "notarization input must be a regular ZIP archive: $archive" >&2
  exit 1
}
[[ ! -e "$result_json" ]] || {
  echo "notarization result path already exists: $result_json" >&2
  exit 1
}
[[ ! -e "$developer_log" ]] || {
  echo "notarization developer log path already exists: $developer_log" >&2
  exit 1
}
[[ "$result_json" != "$developer_log" ]] || {
  echo "submission result and developer log paths must be different" >&2
  exit 1
}
for output_dir in "$(dirname -- "$result_json")" "$(dirname -- "$developer_log")"; do
  [[ -d "$output_dir" && ! -L "$output_dir" ]] || {
    echo "notarization output directory must be a regular directory: $output_dir" >&2
    exit 1
  }
done

notary_dir=$(mktemp -d)
private_key="$notary_dir/AuthKey_${API_KEY_ID}.p8"
temporary_result="$notary_dir/submission-result.json"
temporary_log="$notary_dir/developer-log.json"

cleanup() {
  rm -rf "$notary_dir"
}
trap cleanup EXIT

umask 077
printf '%s' "$API_KEY" >"$private_key"
unset API_KEY

xcrun notarytool submit "$archive" \
  --key "$private_key" \
  --key-id "$API_KEY_ID" \
  --issuer "$API_KEY_ISSUER_ID" \
  --wait \
  --output-format json \
  >"$temporary_result"
[[ -s "$temporary_result" && ! -L "$temporary_result" ]] || {
  echo "notarytool did not produce a regular result JSON file" >&2
  exit 1
}

submission_id=$("$isolated_python" -I "$script_dir/validate-notarization.py" \
  --archive "$archive" \
  --submission-result "$temporary_result" \
  --print-submission-id)

xcrun notarytool log "$submission_id" "$temporary_log" \
  --key "$private_key" \
  --key-id "$API_KEY_ID" \
  --issuer "$API_KEY_ISSUER_ID"
[[ -s "$temporary_log" && ! -L "$temporary_log" ]] || {
  echo "notarytool did not produce a regular developer log JSON file" >&2
  exit 1
}

"$isolated_python" -I "$script_dir/validate-notarization.py" \
  --archive "$archive" \
  --submission-result "$temporary_result" \
  --developer-log "$temporary_log"

[[ ! -e "$result_json" && ! -e "$developer_log" ]] || {
  echo "notarization output path appeared during validation" >&2
  exit 1
}
chmod 0644 "$temporary_result" "$temporary_log"
mv "$temporary_result" "$result_json"
mv "$temporary_log" "$developer_log"
