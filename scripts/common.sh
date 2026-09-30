#!/usr/bin/env bash

# Shared helpers for the standalone FFmpeg build pipeline. This file is meant
# to be sourced by the executable scripts in this directory.

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  printf 'common.sh must be sourced, not executed\n' >&2
  exit 2
fi

FFMPEG_STATIC_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
readonly FFMPEG_STATIC_ROOT
ISOLATED_PYTHON=/usr/bin/python3
[[ -f "$ISOLATED_PYTHON" && -x "$ISOLATED_PYTHON" ]] \
  || { printf 'missing trusted system Python: %s\n' "$ISOLATED_PYTHON" >&2; exit 1; }
readonly ISOLATED_PYTHON

SOURCE_LOCK_KEYS=(
  BUILD_REVISION SOURCE_DATE_EPOCH MACOS_MIN_VERSION
  THIRD_PARTY_NOTICES_SHA256 THIRD_PARTY_NOTICES_SIZE
  FFMPEG_VERSION FFMPEG_ARCHIVE FFMPEG_URL FFMPEG_SHA256
  FFMPEG_SIGNATURE_ARCHIVE FFMPEG_SIGNATURE_URL FFMPEG_SIGNATURE_SHA256
  FFMPEG_PGP_FINGERPRINT FFMPEG_LICENSE_SHA256 FFMPEG_GPLV2_SHA256
  FFMPEG_GPLV3_SHA256 FFMPEG_LGPLV21_SHA256 FFMPEG_IJG_NOTICE_SHA256
  X264_REVISION X264_ARCHIVE X264_URL X264_SHA256 X264_LICENSE_SHA256
  X264_X86INC_ISC_SHA256
  LAME_VERSION LAME_ARCHIVE LAME_URL LAME_SHA256 LAME_COPYING_SHA256
  LAME_LICENSE_SHA256
  NASM_VERSION NASM_ARCHIVE NASM_URL NASM_SHA256
  MUSL_VERSION MUSL_ARCHIVE MUSL_URL MUSL_SHA256 MUSL_COPYRIGHT_SHA256
  MUSL_QSORT_NOTICE_SHA256 MUSL_SUNPRO_NOTICE_SHA256
  MUSL_ICONV_PATCH_SHA256 MUSL_QSORT_PATCH_SHA256 MUSL_PATCHED_ICONV_SHA256
  MUSL_PATCHED_GB18030UTF_SHA256 MUSL_PATCHED_QSORT_SHA256
  GCC_RUNTIME_EXCEPTION_SHA256
  FORTIFY_HEADERS_VERSION FORTIFY_HEADERS_REVISION FORTIFY_HEADERS_ARCHIVE
  FORTIFY_HEADERS_URL FORTIFY_HEADERS_SHA256 FORTIFY_HEADERS_LICENSE_SHA256
  LLVM_MINGW_VERSION LLVM_MINGW_RECIPE_REVISION LLVM_MINGW_RECIPE_ARCHIVE
  LLVM_MINGW_RECIPE_URL LLVM_MINGW_RECIPE_SHA256
  LLVM_RUNTIME_VERSION LLVM_RUNTIME_REVISION
  LLVM_RUNTIME_ARCHIVE LLVM_RUNTIME_URL LLVM_RUNTIME_SHA256
  MINGW_W64_VERSION MINGW_W64_REVISION MINGW_W64_ARCHIVE MINGW_W64_URL
  MINGW_W64_SHA256
  LLVM_MINGW_ARCHIVE LLVM_MINGW_URL LLVM_MINGW_SHA256 LLVM_LICENSE_SHA256
  MINGW_RUNTIME_LICENSE_SHA256
)

validate_source_lock_syntax() {
  local source_path=$1 raw key allowed candidate seen_keys=''
  while IFS= read -r raw || [[ -n "$raw" ]]; do
    [[ -z "$raw" || "$raw" =~ ^[[:space:]]*# ]] && continue
    [[ "$raw" =~ ^[A-Z][A-Z0-9_]*=[A-Za-z0-9._:/+@=-]+$ ]] \
      || return 1
    key=${raw%%=*}
    allowed=0
    for candidate in "${SOURCE_LOCK_KEYS[@]}"; do
      if [[ "$candidate" == "$key" ]]; then
        allowed=1
        break
      fi
    done
    (( allowed )) || return 1
    [[ "$seen_keys" != *$'\n'"${key}"$'\n'* ]] || return 1
    seen_keys+=$'\n'"${key}"$'\n'
  done <"$source_path"
  for candidate in "${SOURCE_LOCK_KEYS[@]}"; do
    [[ "$seen_keys" == *$'\n'"${candidate}"$'\n'* ]] || return 1
  done
}

SOURCES_FILE="${FFMPEG_STATIC_ROOT}/sources.env"
[[ -f "$SOURCES_FILE" && ! -L "$SOURCES_FILE" ]] \
  || { printf 'missing regular sources lock: %s\n' "$SOURCES_FILE" >&2; exit 1; }
validate_source_lock_syntax "$SOURCES_FILE" \
  || { printf 'unsafe or incomplete sources lock: %s\n' "$SOURCES_FILE" >&2; exit 1; }

# The complete lexical allowlist above makes shell sourcing equivalent to
# parsing the documented plain KEY=VALUE format; substitutions are impossible.
# shellcheck source=../sources.env disable=SC1091
source "$SOURCES_FILE"

validate_source_lock_values() {
  local variable value
  for variable in \
    FFMPEG_ARCHIVE FFMPEG_SIGNATURE_ARCHIVE X264_ARCHIVE LAME_ARCHIVE \
    MUSL_ARCHIVE NASM_ARCHIVE FORTIFY_HEADERS_ARCHIVE LLVM_MINGW_RECIPE_ARCHIVE LLVM_RUNTIME_ARCHIVE \
    MINGW_W64_ARCHIVE LLVM_MINGW_ARCHIVE; do
    value=${!variable}
    [[ "$value" =~ ^[A-Za-z0-9][A-Za-z0-9._+-]*$ ]] \
      || die "unsafe archive filename in ${variable}"
  done
  for variable in \
    FFMPEG_URL FFMPEG_SIGNATURE_URL X264_URL LAME_URL NASM_URL MUSL_URL \
    FORTIFY_HEADERS_URL LLVM_MINGW_RECIPE_URL LLVM_RUNTIME_URL MINGW_W64_URL LLVM_MINGW_URL; do
    value=${!variable}
    [[ "$value" == https://* ]] || die "non-HTTPS source URL in ${variable}"
  done
  for variable in "${SOURCE_LOCK_KEYS[@]}"; do
    [[ "$variable" == *_SHA256 ]] || continue
    value=${!variable}
    [[ "$value" =~ ^[0-9a-f]{64}$ ]] || die "invalid SHA-256 lock in ${variable}"
  done
  for variable in X264_REVISION FORTIFY_HEADERS_REVISION LLVM_MINGW_RECIPE_REVISION \
    LLVM_RUNTIME_REVISION MINGW_W64_REVISION; do
    value=${!variable}
    [[ "$value" =~ ^[0-9a-f]{40}$ ]] || die "invalid revision lock in ${variable}"
  done
  [[ "$FFMPEG_PGP_FINGERPRINT" =~ ^[0-9A-F]{40}$ ]] \
    || die 'invalid FFmpeg PGP fingerprint lock'
  [[ "$BUILD_REVISION" =~ ^[1-9][0-9]*$ && "$SOURCE_DATE_EPOCH" =~ ^[1-9][0-9]*$ ]] \
    || die 'invalid build revision or source epoch'
  [[ "$THIRD_PARTY_NOTICES_SIZE" =~ ^[1-9][0-9]*$ ]] \
    || die 'invalid third-party notice size lock'
  [[ "$MACOS_MIN_VERSION" =~ ^[0-9]+[.][0-9]+$ ]] \
    || die 'invalid macOS minimum version lock'
}

validate_source_lock_values
readonly "${SOURCE_LOCK_KEYS[@]}"
readonly SOURCE_LOCK_KEYS SOURCES_FILE

SOURCE_CACHE_DIR="${FFMPEG_STATIC_SOURCE_CACHE_DIR:-${FFMPEG_STATIC_ROOT}/build/source-cache}"
DOWNLOAD_DIR="${SOURCE_CACHE_DIR}/downloads"
# Consumed by scripts which source this file.
# shellcheck disable=SC2034
readonly SOURCE_CACHE_DIR DOWNLOAD_DIR

SUPPORTED_TARGETS=(
  darwin-arm64
  darwin-x64
  linux-arm64
  linux-x64
  win32-arm64
  win32-x64
)
readonly SUPPORTED_TARGETS

log() {
  printf '[ffmpeg-static] %s\n' "$*" >&2
}

die() {
  printf '[ffmpeg-static] ERROR: %s\n' "$*" >&2
  exit 1
}

require_command() {
  local command_name
  for command_name in "$@"; do
    command -v "$command_name" >/dev/null 2>&1 || die "required command not found: ${command_name}"
  done
}

# musl derives the default stack for newly created threads from PT_GNU_STACK.
# Accept exactly one non-executable 2 MiB header so an omitted, weakened, or
# ambiguous linker stack-size contract fails closed.
verify_linux_gnu_stack_header() {
  local program_headers=$1
  awk '
    $1 == "GNU_STACK" {
      count++
      if (NF != 8 || $5 != "0x000000" || tolower($6) != "0x200000" || $7 != "RW") {
        bad = 1
      }
    }
    END { exit !(count == 1 && !bad) }
  ' <<<"$program_headers"
}

is_supported_target() {
  local wanted=$1
  local candidate
  for candidate in "${SUPPORTED_TARGETS[@]}"; do
    [[ "$candidate" == "$wanted" ]] && return 0
  done
  return 1
}

require_target() {
  local target=${1:-}
  [[ -n "$target" ]] || die "target is required (${SUPPORTED_TARGETS[*]})"
  is_supported_target "$target" || die "unsupported target '${target}' (${SUPPORTED_TARGETS[*]})"
}

host_os() {
  case "$(uname -s)" in
    Darwin) printf 'darwin\n' ;;
    Linux) printf 'linux\n' ;;
    *) printf 'unsupported\n' ;;
  esac
}

host_arch() {
  case "$(uname -m)" in
    arm64 | aarch64) printf 'arm64\n' ;;
    x86_64 | amd64) printf 'x64\n' ;;
    *) uname -m ;;
  esac
}

build_jobs() {
  local jobs
  if command -v nproc >/dev/null 2>&1; then
    jobs=$(nproc)
  elif command -v sysctl >/dev/null 2>&1; then
    jobs=$(sysctl -n hw.logicalcpu 2>/dev/null || printf '2')
  else
    jobs=2
  fi
  [[ "$jobs" =~ ^[1-9][0-9]*$ ]] || jobs=2
  printf '%s\n' "$jobs"
}

sha256_file() {
  local path=$1
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum -- "$path" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 -- "$path" | awk '{print $1}'
  else
    die 'neither sha256sum nor shasum is available'
  fi
}

verify_sha256() {
  local path=$1
  local expected=$2
  local actual
  actual=$(sha256_file "$path")
  [[ "$actual" == "$expected" ]] || {
    log "SHA-256 mismatch for ${path}: expected ${expected}, got ${actual}"
    return 1
  }
}

verify_utf8_file_size() {
  local path=$1 expected_size=$2
  [[ "$expected_size" =~ ^[1-9][0-9]*$ ]] \
    || die "invalid expected UTF-8 file size: ${expected_size}"
  "$ISOLATED_PYTHON" -I - "$path" "$expected_size" <<'PY'
import os
import stat
import sys

path = sys.argv[1]
expected_size = int(sys.argv[2])
metadata = os.lstat(path)
if not stat.S_ISREG(metadata.st_mode):
    raise SystemExit(f"not a regular non-symlink file: {path}")
flags = os.O_RDONLY
if hasattr(os, "O_CLOEXEC"):
    flags |= os.O_CLOEXEC
if hasattr(os, "O_NOFOLLOW"):
    flags |= os.O_NOFOLLOW
descriptor = os.open(path, flags)
try:
    opened = os.fstat(descriptor)
    if (
        not stat.S_ISREG(opened.st_mode)
        or (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino)
        or opened.st_size != expected_size
    ):
        raise SystemExit(f"file identity or size mismatch: {path}")
    chunks = []
    remaining = expected_size + 1
    while remaining:
        chunk = os.read(descriptor, min(1024 * 1024, remaining))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
finally:
    os.close(descriptor)
data = b"".join(chunks)
if len(data) != expected_size:
    raise SystemExit(f"file size changed while reading: {path}")
try:
    data.decode("utf-8")
except UnicodeDecodeError as error:
    raise SystemExit(f"file is not UTF-8: {path}: {error}") from error
PY
}

download_verified() {
  local url=$1
  local destination=$2
  local expected_sha256=$3
  local destination_directory temporary

  destination_directory=$(dirname -- "$destination")
  mkdir -p -- "$destination_directory"
  chmod 700 "$destination_directory"
  [[ ! -L "$destination" ]] || die "refusing symlinked download destination: ${destination}"
  if [[ -f "$destination" ]] && verify_sha256 "$destination" "$expected_sha256"; then
    chmod 600 "$destination"
    log "using cached $(basename -- "$destination")"
    return 0
  fi

  temporary=$(mktemp "${destination_directory}/.$(basename -- "$destination").part.XXXXXX")
  chmod 600 "$temporary"
  log "downloading $(basename -- "$destination")"
  if ! curl --fail --location --silent --show-error \
    --retry 4 --connect-timeout 30 --proto '=https' --proto-redir '=https' --tlsv1.2 \
    --output "$temporary" "$url"; then
    rm -f -- "$temporary"
    die "download failed: ${url}"
  fi
  if ! verify_sha256 "$temporary" "$expected_sha256"; then
    rm -f -- "$temporary"
    die "refusing unverified download: ${url}"
  fi
  [[ ! -L "$destination" ]] || {
    rm -f -- "$temporary"
    die "download destination became a symlink: ${destination}"
  }
  mv -f -- "$temporary" "$destination"
  chmod 600 "$destination"
}

validate_tar_archive() {
  local archive=$1
  local expected_sha256=${2:-}
  local permission_policy=${3:-strict}
  local maximum_total_size=2147483648

  case "$permission_policy" in
    strict | allow-setgid-directories) ;;
    *) die "unknown archive permission policy: ${permission_policy}" ;;
  esac

  [[ -f "$archive" && ! -L "$archive" ]] \
    || die "archive is not a regular non-symlink file: ${archive}"

  if [[ -n "$expected_sha256" ]]; then
    verify_sha256 "$archive" "$expected_sha256" \
      || die "archive changed after authentication: ${archive}"
  fi

  # LLVM 23.1.2 has 2,246,337,223 regular-file bytes. A hash-bound exception
  # permits this reviewed source-compliance asset up to 2304 MiB; all other
  # archives retain the 2 GiB ceiling and every other safety check.
  if [[ "$expected_sha256" == "$LLVM_RUNTIME_SHA256" ]]; then
    maximum_total_size=2415919104
  fi

  # Python's tar reader gives us structured member and link metadata. System
  # tar listings are ambiguous for control characters and do not expose link
  # targets portably. Extraction remains delegated to the platform tar only
  # after this complete manifest validation succeeds.
  "$ISOLATED_PYTHON" -I - "$archive" "$permission_policy" "$maximum_total_size" <<'PY' \
    || die "unsafe tar archive: ${archive}"
import os
import posixpath
import stat
import sys
import tarfile

archive = sys.argv[1]
permission_policy = sys.argv[2]
maximum_archive_size = 1024 * 1024 * 1024
# llvm-project is intentionally published as one source-compliance asset and
# currently contains about 198k entries. Keep a finite ceiling above that
# authenticated input while retaining strict per-member and aggregate limits.
maximum_members = 250_000
maximum_member_size = 256 * 1024 * 1024
maximum_total_size = int(sys.argv[3])
maximum_path_size = 4096

archive_stat = os.lstat(archive)
if not stat.S_ISREG(archive_stat.st_mode) or archive_stat.st_size > maximum_archive_size:
    raise SystemExit("archive file type or compressed size is invalid")


def unsafe_text(value: str) -> bool:
    return len(value.encode("utf-8", "surrogatepass")) > maximum_path_size or any(
        ord(character) < 32 or ord(character) == 127 for character in value
    )

names: set[str] = set()
stripped_names: set[str] = set()
symlinks: set[str] = set()
symlink_targets: dict[str, str] = {}
top_levels: set[str] = set()
total_size = 0

with tarfile.open(archive, mode="r:*") as handle:
    members = handle.getmembers()
    if not members or len(members) > maximum_members:
        raise SystemExit("archive has an invalid member count")

    for member in members:
        raw_name = member.name
        name = raw_name.rstrip("/")
        if (
            not name
            or unsafe_text(name)
            or "\\" in name
            or name.startswith("/")
            or posixpath.normpath(name) != name
            or any(component in ("", ".", "..") for component in name.split("/"))
        ):
            raise SystemExit(f"unsafe member path: {raw_name!r}")
        if name in names:
            raise SystemExit(f"duplicate member path: {name!r}")
        names.add(name)

        components = name.split("/")
        top_levels.add(components[0])
        stripped_name = "/".join(components[1:])
        if stripped_name:
            stripped_names.add(stripped_name)

        special_permissions = member.mode & 0o7000
        if special_permissions and not (
            permission_policy == "allow-setgid-directories"
            and member.isdir()
            and special_permissions == 0o2000
        ):
            raise SystemExit(f"special permission bits are forbidden: {name!r}")
        if member.isreg():
            if member.size < 0 or member.size > maximum_member_size:
                raise SystemExit(f"oversized archive member: {name!r}")
            total_size += member.size
            if total_size > maximum_total_size:
                raise SystemExit("archive expands beyond the safety limit")
        elif member.isdir():
            pass
        elif member.issym():
            if not stripped_name:
                raise SystemExit("the top-level archive member cannot be a symlink")
            target = member.linkname
            if (
                not target
                or unsafe_text(target)
                or "\\" in target
                or target.startswith("/")
                or posixpath.normpath(target) != target
            ):
                raise SystemExit(f"unsafe symlink target for {name!r}: {target!r}")
            resolved = posixpath.normpath(
                posixpath.join(posixpath.dirname(stripped_name), target)
            )
            if resolved == ".." or resolved.startswith("../") or resolved.startswith("/"):
                raise SystemExit(f"escaping symlink target for {name!r}: {target!r}")
            symlinks.add(stripped_name)
            symlink_targets[stripped_name] = resolved
        else:
            # Hard links, devices, FIFOs and implementation-specific member
            # types are not needed by any locked input and are rejected.
            raise SystemExit(f"unsupported archive member type: {name!r}")

if len(top_levels) != 1:
    raise SystemExit("archive must have exactly one top-level directory")

for name, target in symlink_targets.items():
    if target not in stripped_names:
        raise SystemExit(f"symlink target is not present in archive: {name!r} -> {target!r}")

# Do not let tar create a later member through a symlink it extracted earlier,
# even when the link itself resolves within the destination.
for name in stripped_names:
    parent = posixpath.dirname(name)
    while parent and parent != ".":
        if parent in symlinks:
            raise SystemExit(f"archive member traverses symlink parent: {name!r}")
        parent = posixpath.dirname(parent)
PY
}

extract_tar_strip_one() {
  local archive=$1
  local destination=$2
  local expected_sha256=$3
  local permission_policy=${4:-strict}

  [[ ! -e "$destination" && ! -L "$destination" ]] \
    || die "extraction destination already exists: ${destination}"
  mkdir -p -- "$(dirname -- "$destination")"

  (
    local private_archive temporary_directory temporary_output
    umask 077
    temporary_directory=$(mktemp -d "${destination}.extract.XXXXXX")
    trap 'rm -rf -- "$temporary_directory"' EXIT
    private_archive="${temporary_directory}/input.tar"
    temporary_output="${temporary_directory}/output"
    mkdir -p -- "$temporary_output"

    # Hash the private snapshot which is actually passed to tar. This closes
    # the verification/extraction race on shared or self-hosted runners.
    cp -- "$archive" "$private_archive"
    chmod 600 "$private_archive"
    verify_sha256 "$private_archive" "$expected_sha256" \
      || die "archive changed before extraction: ${archive}"
    validate_tar_archive "$private_archive" "$expected_sha256" "$permission_policy"
    tar --no-same-owner --no-same-permissions -xf "$private_archive" \
      -C "$temporary_output" --strip-components=1
    "$ISOLATED_PYTHON" -I - "$temporary_output" <<'PY' \
      || die "extracted archive permissions or types are unsafe: ${archive}"
import os
import stat
import sys

root = os.path.abspath(sys.argv[1])
pending = [root]
while pending:
    current = pending.pop()
    metadata = os.lstat(current)
    if not stat.S_ISDIR(metadata.st_mode):
        raise SystemExit(f"extraction root is not a directory: {current}")
    permissions = stat.S_IMODE(metadata.st_mode)
    if permissions & (stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX | stat.S_IWGRP | stat.S_IWOTH):
        raise SystemExit(f"unsafe extracted directory permissions: {current}")
    with os.scandir(current) as entries:
        for entry in entries:
            metadata = entry.stat(follow_symlinks=False)
            mode = metadata.st_mode
            if stat.S_ISLNK(mode):
                continue
            if not (stat.S_ISDIR(mode) or stat.S_ISREG(mode)):
                raise SystemExit(f"unsafe extracted member type: {entry.path}")
            permissions = stat.S_IMODE(mode)
            if permissions & (stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX | stat.S_IWGRP | stat.S_IWOTH):
                raise SystemExit(f"unsafe extracted member permissions: {entry.path}")
            if stat.S_ISDIR(mode):
                pending.append(entry.path)
PY
    mv -- "$temporary_output" "$destination"
  )
}

json_quote() {
  awk '
    BEGIN { ORS = ""; printf "\"" }
    {
      if (NR > 1) printf "\\n"
      gsub(/\\/, "\\\\")
      gsub(/\"/, "\\\"")
      gsub(/\r/, "\\r")
      gsub(/\t/, "\\t")
      printf "%s", $0
    }
    END { printf "\"" }
  '
}

quote_value() {
  printf '%s\n' "$1" | json_quote
}

first_line() {
  awk 'NR == 1 {print; exit}'
}

verify_windows_cephes_absence() {
  local trace_path=$1 map_path=$2 cephes
  cephes='(cbrt|cbrtf|cbrtl|coshl|erfl|hypotl|lgamma|lgammaf|lgammal|sinhl|tanhl|tgamma|tgammaf|tgammal)'
  [[ -f "$trace_path" && ! -L "$trace_path" && -s "$trace_path" ]] \
    || die "missing final Windows linker trace: ${trace_path}"
  [[ -f "$map_path" && ! -L "$map_path" && -s "$map_path" ]] \
    || die "missing final Windows linker map: ${map_path}"
  if grep -Eq -- \
    "(Reading|Loaded) libmingwex[.]a[(][^)]*-${cephes}[.]o[)]" "$trace_path"; then
    die "Cephes/Moshier-derived MinGW runtime object found in linker trace: ${trace_path}"
  fi
  if grep -Eq -- \
    "lib(64|arm64)_libmingwex_a-${cephes}[.]o:" "$map_path"; then
    die "Cephes/Moshier-derived MinGW runtime object found in linker map: ${map_path}"
  fi
}
