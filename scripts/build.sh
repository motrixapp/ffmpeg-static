#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
umask 077

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=common.sh disable=SC1091
source "${SCRIPT_DIR}/common.sh"

if (( $# != 1 )); then
  die 'usage: build.sh <target>'
fi
TARGET=$1
require_target "$TARGET"

TARGET_PLATFORM=${TARGET%%-*}
TARGET_NODE_ARCH=${TARGET#*-}
BUILD_PARENT="${FFMPEG_STATIC_ROOT}/build"
BUILD_ROOT="${BUILD_PARENT}/${TARGET}"
WORK_DIR="${BUILD_ROOT}/work"
PREFIX_DIR="${BUILD_ROOT}/prefix"
PAYLOAD_DIR="${BUILD_ROOT}/payload"
LICENSE_DIR="${PAYLOAD_DIR}/LICENSES"
BUILD_INFO="${BUILD_ROOT}/build-info.json"
ARTIFACT_LICENSE=$("$ISOLATED_PYTHON" -I - "$SCRIPT_DIR" "$TARGET" <<'PY'
import sys

sys.path.insert(0, sys.argv[1])
import pipeline_lib

print(pipeline_lib.artifact_license(sys.argv[2]))
PY
) || die 'could not resolve the canonical artifact license profile'

[[ "$FFMPEG_STATIC_ROOT" != *[$'\n\r\t ']* ]] \
  || die 'the checkout path must not contain whitespace'
[[ ! -L "$BUILD_PARENT" && ! -L "$BUILD_ROOT" ]] \
  || die 'refusing a symbolic-link build directory'

# Resolve every implicit tool through a small, fixed system path. The build
# never inherits compiler/linker flags or make configuration from the runner.
SYSTEM_PATH=/usr/bin:/bin:/usr/sbin:/sbin
DISCOVERY_PATH=$SYSTEM_PATH
if [[ "$(/usr/bin/uname -s)" == Darwin ]]; then
  DISCOVERY_PATH="/opt/homebrew/bin:/usr/local/bin:${SYSTEM_PATH}"
fi
PATH=$DISCOVERY_PATH
export PATH

FORMAL_BUILD=0
if [[ "${GITHUB_ACTIONS:-}" == true ]]; then
  FORMAL_BUILD=1
fi
ALLOW_TOOL_OVERRIDES=${FFMPEG_STATIC_ALLOW_TOOL_OVERRIDES:-0}
[[ "$ALLOW_TOOL_OVERRIDES" == 0 || "$ALLOW_TOOL_OVERRIDES" == 1 ]] \
  || die 'FFMPEG_STATIC_ALLOW_TOOL_OVERRIDES must be 0 or 1'
if (( FORMAL_BUILD )) && (( ALLOW_TOOL_OVERRIDES )); then
  die 'tool overrides are forbidden in GitHub Actions builds'
fi
[[ -z "${FFMPEG_STATIC_NASM:-}" ]] \
  || die 'FFMPEG_STATIC_NASM is forbidden; NASM is always built from the locked source'

POLLUTION_VARIABLES=(
  CC CXX CPPFLAGS CFLAGS CXXFLAGS OBJCFLAGS LDFLAGS LIBS
  CPATH C_INCLUDE_PATH CPLUS_INCLUDE_PATH OBJC_INCLUDE_PATH LIBRARY_PATH
  PKG_CONFIG_PATH PKG_CONFIG_LIBDIR CONFIG_SITE MAKEFLAGS MFLAGS
  AR AS LD NM RANLIB STRIP SDKROOT MACOSX_DEPLOYMENT_TARGET DEVELOPER_DIR
)
for pollution_name in "${POLLUTION_VARIABLES[@]}"; do
  if [[ -n "${!pollution_name-}" ]]; then
    if (( FORMAL_BUILD )); then
      die "inherited build setting is forbidden: ${pollution_name}"
    fi
    log "ignoring inherited build setting: ${pollution_name}"
  fi
  unset "$pollution_name"
done
unset GCC_EXEC_PREFIX COMPILER_PATH DEPENDENCIES_OUTPUT SUNPRO_DEPENDENCIES

export LC_ALL=C
export TZ=UTC
export SOURCE_DATE_EPOCH
export ZERO_AR_DATE=1
export CCACHE_DISABLE=1

check_build_host() {
  local actual_os actual_arch
  actual_os=$(host_os)
  actual_arch=$(host_arch)
  case "$TARGET" in
    darwin-arm64)
      [[ "$actual_os" == darwin && "$actual_arch" == arm64 ]] \
        || die 'darwin-arm64 must be built natively on Apple Silicon'
      ;;
    darwin-x64)
      [[ "$actual_os" == darwin && "$actual_arch" == x64 ]] \
        || die 'darwin-x64 must be built natively on Intel macOS'
      ;;
    linux-arm64)
      [[ "$actual_os" == linux && "$actual_arch" == arm64 ]] \
        || die 'linux-arm64 must be built natively on arm64 Linux'
      ;;
    linux-x64)
      [[ "$actual_os" == linux && "$actual_arch" == x64 ]] \
        || die 'linux-x64 must be built natively on x64 Linux'
      ;;
    win32-arm64 | win32-x64)
      [[ "$actual_os" == linux && "$actual_arch" == x64 ]] \
        || die 'Windows targets must be cross-built on x64 Linux'
      ;;
  esac
}

select_tool() {
  local default_value=$1 selected='' variable value
  shift
  for variable in "$@"; do
    value=${!variable-}
    [[ -n "$value" ]] || continue
    if (( ! ALLOW_TOOL_OVERRIDES )); then
      die "${variable} requires FFMPEG_STATIC_ALLOW_TOOL_OVERRIDES=1"
    fi
    [[ "$value" =~ ^(/[-A-Za-z0-9_./+]+|[-A-Za-z0-9_.+]+)$ ]] \
      || die "unsafe tool override in ${variable}"
    [[ -z "$selected" || "$selected" == "$value" ]] \
      || die "conflicting tool overrides for ${variable}"
    selected=$value
  done
  printf '%s\n' "${selected:-$default_value}"
}

resolve_tool_path() {
  local requested=$1 resolved
  if [[ "$requested" == /* ]]; then
    resolved=$requested
  elif [[ "$requested" == */* ]]; then
    die "tool path must be absolute or a simple command name: ${requested}"
  else
    resolved=$(PATH="$DISCOVERY_PATH" command -v "$requested") \
      || die "required command not found: ${requested}"
  fi
  [[ -f "$resolved" && -x "$resolved" ]] || die "tool is not executable: ${resolved}"
  printf '%s\n' "$resolved"
}

install_tool_alias() {
  local requested=$1 alias_name=$2 resolved
  resolved=$(resolve_tool_path "$requested")
  [[ ! -e "${TOOL_BIN}/${alias_name}" && ! -L "${TOOL_BIN}/${alias_name}" ]] \
    || die "duplicate tool alias: ${alias_name}"
  ln -s -- "$resolved" "${TOOL_BIN}/${alias_name}"
}

run_clean() {
  if [[ -n "${DEPLOYMENT_TARGET:-}" ]]; then
    env -i \
      "HOME=${SAFE_HOME}" \
      "TMPDIR=${SAFE_TMP}" \
      "PATH=${BUILD_PATH}" \
      LC_ALL=C TZ=UTC \
      "SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}" ZERO_AR_DATE=1 CCACHE_DISABLE=1 \
      "MACOSX_DEPLOYMENT_TARGET=${DEPLOYMENT_TARGET}" "$@"
    return
  fi
  env -i \
    "HOME=${SAFE_HOME}" \
    "TMPDIR=${SAFE_TMP}" \
    "PATH=${BUILD_PATH}" \
    LC_ALL=C TZ=UTC \
    "SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}" ZERO_AR_DATE=1 CCACHE_DISABLE=1 \
    "$@"
}

run_with_x264_assembler() {
  if [[ "$TARGET_NODE_ARCH" == x64 ]]; then
    run_clean AS=nasm "$@"
  else
    run_clean "$@"
  fi
}

capture_version() {
  local output
  if ! output=$(run_clean "$@" 2>&1); then
    die "could not record tool version: $*"
  fi
  printf '%s\n' "$output" | first_line
}

check_build_host
require_command curl tar gpg awk python3 make pkg-config
JOBS=$(build_jobs)
"${SCRIPT_DIR}/fetch-sources.sh" "$TARGET"
# Source acquisition may discover Homebrew's GnuPG/curl on macOS. All build,
# extraction, and provenance-sensitive operations after authentication use the
# fixed system path or explicit aliases created below.
PATH=$SYSTEM_PATH
export PATH

log "preparing ${TARGET} build directories"
rm -rf -- "$WORK_DIR" "$PREFIX_DIR" "$PAYLOAD_DIR"
rm -f -- "$BUILD_INFO"
mkdir -p -- "$WORK_DIR/src" \
  "$WORK_DIR/tools" "$WORK_DIR/tmp" "$WORK_DIR/home" "$PREFIX_DIR" "$LICENSE_DIR"
chmod 700 "$BUILD_ROOT" "$WORK_DIR" "$WORK_DIR/tools" "$WORK_DIR/tmp" "$WORK_DIR/home"
TOOL_BIN="${WORK_DIR}/tools"
SAFE_TMP="${WORK_DIR}/tmp"
SAFE_HOME="${WORK_DIR}/home"
BUILD_PATH="${TOOL_BIN}:${SYSTEM_PATH}"

extract_tar_strip_one "${DOWNLOAD_DIR}/${FFMPEG_ARCHIVE}" \
  "$WORK_DIR/src/ffmpeg" "$FFMPEG_SHA256"
extract_tar_strip_one "${DOWNLOAD_DIR}/${X264_ARCHIVE}" \
  "$WORK_DIR/src/x264" "$X264_SHA256"
extract_tar_strip_one "${DOWNLOAD_DIR}/${LAME_ARCHIVE}" \
  "$WORK_DIR/src/lame" "$LAME_SHA256"
NASM_SOURCE="${WORK_DIR}/src/nasm"
NASM_BINARY=''
NASM_BINARY_SHA256=''
if [[ "$TARGET_NODE_ARCH" == x64 ]]; then
  extract_tar_strip_one "${DOWNLOAD_DIR}/${NASM_ARCHIVE}" \
    "$NASM_SOURCE" "$NASM_SHA256" allow-setgid-directories
  NASM_BUILD="${WORK_DIR}/nasm-build"
  NASM_PREFIX="${WORK_DIR}/nasm"
  mkdir -p -- "$NASM_BUILD" "${NASM_PREFIX}/bin"
  case "$(host_os)" in
    darwin)
      NASM_HOST_CC=/usr/bin/clang
      NASM_HOST_LDFLAGS='-Wl,-dead_strip'
      ;;
    linux)
      NASM_HOST_CC=/usr/bin/gcc
      NASM_HOST_LDFLAGS='-Wl,--as-needed'
      ;;
    *) die 'unsupported NASM build host' ;;
  esac
  [[ -x "$NASM_HOST_CC" && -x /usr/bin/strip ]] \
    || die 'missing controlled host compiler or strip for NASM'
  NASM_HOST_CFLAGS="-O2 -fno-ident -ffile-prefix-map=${WORK_DIR}=/usr/src/ffmpeg-static/build/work -fdebug-prefix-map=${WORK_DIR}=/usr/src/ffmpeg-static/build/work -fmacro-prefix-map=${WORK_DIR}=/usr/src/ffmpeg-static/build/work"
  log "building authenticated NASM ${NASM_VERSION} (x86-64 build tool)"
  (
    cd "$NASM_BUILD"
    run_clean CC="$NASM_HOST_CC" CFLAGS="$NASM_HOST_CFLAGS" \
      LDFLAGS="$NASM_HOST_LDFLAGS" PERL=false PYTHON3=false \
      "$NASM_SOURCE/configure" "--prefix=${NASM_PREFIX}"
    run_clean make dirs
    run_clean make -j"$JOBS" nasm
    # Source archives enable debug information by default. Strip it so the
    # private host tool's hash is stable across the independent clean rebuild.
    run_clean /usr/bin/strip -S nasm
  )
  NASM_BINARY="${NASM_PREFIX}/bin/nasm"
  install -m 0755 "${NASM_BUILD}/nasm" "$NASM_BINARY"
  [[ -f "$NASM_BINARY" && ! -L "$NASM_BINARY" && -x "$NASM_BINARY" ]] \
    || die 'source-built NASM is not a regular executable'
  install_tool_alias "$NASM_BINARY" nasm
  NASM_BINARY_SHA256=$(sha256_file "$NASM_BINARY")
fi
MUSL_SOURCE="${WORK_DIR}/src/musl"
FORTIFY_SOURCE="${WORK_DIR}/src/fortify-headers"
extract_tar_strip_one "${DOWNLOAD_DIR}/${MUSL_ARCHIVE}" \
  "$MUSL_SOURCE" "$MUSL_SHA256"
extract_tar_strip_one "${DOWNLOAD_DIR}/${FORTIFY_HEADERS_ARCHIVE}" \
  "$FORTIFY_SOURCE" "$FORTIFY_HEADERS_SHA256"
LLVM_MINGW_RECIPE_SOURCE="${WORK_DIR}/src/llvm-mingw-recipe"
extract_tar_strip_one "${DOWNLOAD_DIR}/${LLVM_MINGW_RECIPE_ARCHIVE}" \
  "$LLVM_MINGW_RECIPE_SOURCE" "$LLVM_MINGW_RECIPE_SHA256"

# Bind the source recipe that produced the pinned prebuilt llvm-mingw archive.
# The authenticated recipe must select the exact LLVM and MinGW-w64 inputs and
# its upstream workflow must build and package the Linux UCRT toolchain shape
# consumed below.  This is provenance validation only; no untrusted recipe is
# executed by this project.
"$ISOLATED_PYTHON" -I - \
  "$LLVM_MINGW_RECIPE_SOURCE" "$LLVM_RUNTIME_VERSION" "$MINGW_W64_REVISION" <<'PY'
import pathlib
import re
import stat
import sys

root = pathlib.Path(sys.argv[1])
llvm_version = sys.argv[2]
mingw_revision = sys.argv[3]


def read_recipe(relative: str) -> str:
    path = root / relative
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
        raise SystemExit(f"llvm-mingw recipe file is not regular: {relative}")
    if metadata.st_size <= 0 or metadata.st_size > 2 * 1024 * 1024:
        raise SystemExit(f"llvm-mingw recipe file has an invalid size: {relative}")
    return path.read_text(encoding="utf-8")


llvm_recipe = read_recipe("build-llvm.sh")
llvm_defaults = re.findall(
    r"^:\s+\$\{LLVM_VERSION:=([^}\s]+)\}\s*$", llvm_recipe, re.MULTILINE
)
if llvm_defaults != [f"llvmorg-{llvm_version}"]:
    raise SystemExit("llvm-mingw recipe does not select the locked LLVM release")

mingw_recipe = read_recipe("build-mingw-w64.sh")
mingw_defaults = re.findall(
    r"^:\s+\$\{MINGW_W64_VERSION:=([0-9a-f]{40})\}\s*$",
    mingw_recipe,
    re.MULTILINE,
)
if mingw_defaults != [mingw_revision]:
    raise SystemExit("llvm-mingw recipe does not select the locked MinGW-w64 revision")

build_workflow = read_recipe(".github/workflows/build.yml")
linux_job = re.search(
    r"^  linux:\s*$\n(?P<body>.*?)(?=^  [A-Za-z0-9_-]+:\s*$)",
    build_workflow,
    re.MULTILINE | re.DOTALL,
)
if linux_job is None:
    raise SystemExit("llvm-mingw Linux toolchain workflow job is missing")
linux_job_body = linux_job.group("body")
for evidence in (
    "runs-on: ubuntu-22.04",
    "./build-all.sh /opt/llvm-mingw $(pwd)/install/llvm-mingw --thinlto --pgo --llvm-only",
    "NAME=llvm-mingw-$TAG-ucrt-$DISTRO",
    "tar -Jcf ../$NAME.tar.xz --format=ustar --numeric-owner --owner=0 --group=0 --sort=name --mtime=\"$BUILD_DATE\" $NAME",
    "name: linux-ucrt-x86_64-toolchain",
):
    if linux_job_body.count(evidence) != 1:
        raise SystemExit(f"llvm-mingw Linux UCRT build evidence is missing or ambiguous: {evidence}")

release_workflow = read_recipe(".github/workflows/release.yml")
for evidence in (
    "mv *-toolchain/*.zip *-toolchain/*.tar.xz .",
    'if [ "$TAG" != "${{inputs.tag}}" ]; then',
):
    if release_workflow.count(evidence) != 1:
        raise SystemExit(f"llvm-mingw release packaging evidence is missing or ambiguous: {evidence}")
if release_workflow.count("*.tar.xz *.zip") != 2:
    raise SystemExit("llvm-mingw release upload evidence is missing or ambiguous")
PY

# musl's aggregate COPYRIGHT file does not reproduce every per-file notice.
# Bind the exact MIT and SunPro comment blocks which are compiled into libc.a
# before any configure or build step can modify the authenticated tree.
"$ISOLATED_PYTHON" -I - \
  "$MUSL_SOURCE/src/stdlib/qsort.c" "$MUSL_QSORT_NOTICE_SHA256" \
  "$MUSL_SOURCE/src/math/cos.c" "$MUSL_SUNPRO_NOTICE_SHA256" <<'PY'
import hashlib
import pathlib
import re
import stat
import sys

checks = (
    (pathlib.Path(sys.argv[1]), 0, sys.argv[2], "qsort MIT"),
    (pathlib.Path(sys.argv[3]), 1, sys.argv[4], "cos SunPro"),
)
for path, block_index, expected, label in checks:
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
        raise SystemExit(f"musl {label} source is not a regular file")
    blocks = re.findall(rb"/\*.*?\*/", path.read_bytes(), flags=re.S)
    if len(blocks) <= block_index:
        raise SystemExit(f"musl {label} notice block is missing")
    actual = hashlib.sha256(blocks[block_index]).hexdigest()
    if actual != expected:
        raise SystemExit(f"musl {label} notice block does not match its lock")
PY

NOTICE_GENERATOR="${SCRIPT_DIR}/generate-third-party-notices.py"
THIRD_PARTY_NOTICE="${WORK_DIR}/THIRD-PARTY-NOTICES.txt"
[[ -f "$NOTICE_GENERATOR" && ! -L "$NOTICE_GENERATOR" ]] \
  || die 'missing regular third-party notice generator'
if ! run_clean "$ISOLATED_PYTHON" -I "$NOTICE_GENERATOR" \
  --ffmpeg "$WORK_DIR/src/ffmpeg" \
  --x264 "$WORK_DIR/src/x264" \
  --lame "$WORK_DIR/src/lame" \
  --musl "$MUSL_SOURCE" \
  --fortify-headers "$FORTIFY_SOURCE" \
  --output "$THIRD_PARTY_NOTICE" \
  >"${WORK_DIR}/third-party-notices.summary.json"; then
  die 'could not generate the locked third-party notice bundle'
fi
verify_utf8_file_size "$THIRD_PARTY_NOTICE" "$THIRD_PARTY_NOTICES_SIZE"
verify_sha256 "$THIRD_PARTY_NOTICE" "$THIRD_PARTY_NOTICES_SHA256" \
  || die 'generated third-party notice bundle does not match its lock'

TOOLCHAIN_NAME=native
TOOLCHAIN_VERSION=native
TOOLCHAIN_URL=''
TOOLCHAIN_SHA256=''
CROSS_PREFIX=''
DEPLOYMENT_TARGET=''
SDK_VERSION=''
GCC_RUNTIME_VERSION=''
DEPENDENCIES_JSON='[]'
FORTIFY_INCLUDE=''
FORTIFY_PROVENANCE=not-applicable
LINK_PROVENANCE=platform-system
ARCH_HARDENING_FLAGS=()
TARGET_LDFLAGS_FLAGS=()

case "$TARGET" in
  darwin-arm64 | darwin-x64)
    if [[ "$TARGET" == darwin-arm64 ]]; then
      TARGET_ARCH=aarch64
      HOST_TRIPLET=aarch64-apple-darwin
      MAC_BREW_PREFIX=/opt/homebrew
      MAC_ARCH=arm64
    else
      TARGET_ARCH=x86_64
      HOST_TRIPLET=x86_64-apple-darwin
      MAC_BREW_PREFIX=/usr/local
      MAC_ARCH=x86_64
    fi
    install_tool_alias "$(select_tool /usr/bin/clang FFMPEG_STATIC_CC MACOS_CC)" clang
    install_tool_alias "$(select_tool /usr/bin/clang++ FFMPEG_STATIC_CXX MACOS_CXX)" clang++
    install_tool_alias "$(select_tool /usr/bin/ar FFMPEG_STATIC_AR MACOS_AR)" ar
    install_tool_alias "$(select_tool /usr/bin/ranlib FFMPEG_STATIC_RANLIB MACOS_RANLIB)" ranlib
    install_tool_alias "$(select_tool /usr/bin/strip FFMPEG_STATIC_STRIP MACOS_STRIP)" strip
    install_tool_alias "$(select_tool /usr/bin/nm FFMPEG_STATIC_NM MACOS_NM)" nm
    install_tool_alias "$(select_tool /usr/bin/strings FFMPEG_STATIC_STRINGS MACOS_STRINGS)" strings
    install_tool_alias "$(select_tool "${MAC_BREW_PREFIX}/bin/pkg-config" FFMPEG_STATIC_PKG_CONFIG)" pkg-config
    install_tool_alias "$(select_tool /usr/bin/make FFMPEG_STATIC_MAKE)" make
    CC=clang CXX=clang++ AR=ar RANLIB=ranlib STRIP=strip NM=nm STRINGS=strings
    MAKE=make PKG_CONFIG=pkg-config
    DEPLOYMENT_TARGET=$MACOS_MIN_VERSION
    TARGET_CFLAGS="-O2 -fPIC -fstack-protector-strong -D_FORTIFY_SOURCE=2 -arch ${MAC_ARCH} -mmacosx-version-min=${DEPLOYMENT_TARGET}"
    # Apple's linker derives LC_UUID from output content. Keep that default:
    # current dyld rejects executable Mach-O files with LC_UUID suppressed.
    TARGET_LDFLAGS="-arch ${MAC_ARCH} -mmacosx-version-min=${DEPLOYMENT_TARGET} -Wl,-dead_strip"
    SDK_VERSION=$(/usr/bin/xcrun --sdk macosx --show-sdk-version) \
      || die 'could not determine the macOS SDK version'
    TOOLCHAIN_NAME=apple-clang-sdk
    TOOLCHAIN_VERSION=$SDK_VERSION
    FORTIFY_PROVENANCE=system-headers-level-2
    ;;
  linux-arm64 | linux-x64)
    [[ -z "${MUSL_CC:-}" && -z "${MUSL_CXX:-}" ]] \
      || die 'external musl compiler wrappers are forbidden; musl is source-built'
    if [[ "$TARGET" == linux-arm64 ]]; then
      TARGET_ARCH=aarch64
      HOST_TRIPLET=aarch64-linux-musl
      ARCH_HARDENING='-mbranch-protection=standard -mno-outline-atomics'
      ARCH_HARDENING_FLAGS=(-mbranch-protection=standard -mno-outline-atomics)
    else
      TARGET_ARCH=x86_64
      HOST_TRIPLET=x86_64-linux-musl
      ARCH_HARDENING='-fcf-protection=full'
      ARCH_HARDENING_FLAGS=(-fcf-protection=full)
    fi
    install_tool_alias "$(select_tool /usr/bin/gcc FFMPEG_STATIC_BOOTSTRAP_CC LINUX_BOOTSTRAP_CC)" gcc
    install_tool_alias "$(select_tool /usr/bin/ar FFMPEG_STATIC_AR MUSL_AR)" ar
    install_tool_alias "$(select_tool /usr/bin/ranlib FFMPEG_STATIC_RANLIB MUSL_RANLIB)" ranlib
    install_tool_alias "$(select_tool /usr/bin/strip FFMPEG_STATIC_STRIP MUSL_STRIP)" strip
    install_tool_alias "$(select_tool /usr/bin/nm FFMPEG_STATIC_NM MUSL_NM)" nm
    install_tool_alias "$(select_tool /usr/bin/strings FFMPEG_STATIC_STRINGS MUSL_STRINGS)" strings
    install_tool_alias "$(select_tool /usr/bin/pkg-config FFMPEG_STATIC_PKG_CONFIG)" pkg-config
    install_tool_alias "$(select_tool /usr/bin/make FFMPEG_STATIC_MAKE)" make
    MAKE=make PKG_CONFIG=pkg-config AR=ar RANLIB=ranlib STRIP=strip NM=nm STRINGS=strings

    MUSL_BUILD="${WORK_DIR}/musl-build"
    MUSL_PREFIX="${WORK_DIR}/musl"
    mkdir -p -- "$MUSL_BUILD" "$MUSL_PREFIX"

    log "building authenticated musl ${MUSL_VERSION}"
    (
      cd "$MUSL_BUILD"
      run_clean CC=gcc AR=ar RANLIB=ranlib \
        "$MUSL_SOURCE/configure" \
        "--prefix=${MUSL_PREFIX}" "--syslibdir=${MUSL_PREFIX}/lib" --disable-shared
      run_clean make -j"$JOBS"
      run_clean make install
    )
    MUSL_SPECS="${MUSL_PREFIX}/lib/musl-gcc.specs"
    [[ -f "$MUSL_SPECS" && ! -L "$MUSL_SPECS" ]] || die 'musl-gcc specs were not installed'
    "$ISOLATED_PYTHON" -I - "$MUSL_SPECS" <<'PY'
import pathlib
import re
import sys

path = pathlib.Path(sys.argv[1])
text = path.read_text(encoding="utf-8")
start_pattern = re.compile(r"^%\{!shared: ([^\n ]+)/Scrt1[.]o\} (.+)$", re.M)
start_match = start_pattern.search(text)
if start_match is None:
    raise SystemExit("unexpected musl startfile specs template")
libdir, suffix = start_match.groups()
start_replacement = (
    f"%{{static-pie: {libdir}/rcrt1.o}} "
    f"%{{!static-pie:%{{!shared: {libdir}/Scrt1.o}}}} {suffix}"
)
text, count = start_pattern.subn(start_replacement, text, count=1)
if count != 1:
    raise SystemExit("musl startfile specs replacement was ambiguous")

link_pattern = re.compile(
    r"^-dynamic-linker ([^\n ]+) -nostdlib "
    r"%\{shared:-shared\} %\{static:-static\}(.*)$",
    re.M,
)
link_match = link_pattern.search(text)
if link_match is None:
    raise SystemExit("unexpected musl link specs template")
ldso, suffix = link_match.groups()
link_replacement = (
    "-nostdlib %{shared:-shared} %{static:-static} "
    "%{static-pie:-static -pie --no-dynamic-linker -z text} "
    f"%{{!shared:%{{!static:%{{!static-pie:-dynamic-linker {ldso}}}}}}}{suffix}"
)
text, count = link_pattern.subn(link_replacement, text, count=1)
if count != 1:
    raise SystemExit("musl link specs replacement was ambiguous")
path.write_text(text, encoding="utf-8")
PY
    BUILD_PATH="${MUSL_PREFIX}/bin:${TOOL_BIN}:${SYSTEM_PATH}"
    CC=musl-gcc CXX=musl-gcc
    FORTIFY_INCLUDE="${FORTIFY_SOURCE}/include"
    TARGET_CFLAGS="-O2 -fPIE -fstack-protector-strong -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3 -Wformat -Wformat-security -Werror=format-security ${ARCH_HARDENING}"
    TARGET_LDFLAGS='-static-pie -Wl,-z,relro,-z,now,-z,noexecstack,-z,separate-code,--build-id=sha1 -Wl,-z,stack-size=2097152'
    TARGET_LDFLAGS_FLAGS=(
      -static-pie
      '-Wl,-z,relro,-z,now,-z,noexecstack,-z,separate-code,--build-id=sha1'
      '-Wl,-z,stack-size=2097152'
    )
    TOOLCHAIN_NAME=source-built-musl
    TOOLCHAIN_VERSION=$MUSL_VERSION
    TOOLCHAIN_URL=$MUSL_URL
    TOOLCHAIN_SHA256=$MUSL_SHA256
    FORTIFY_PROVENANCE="${FORTIFY_HEADERS_VERSION}@${FORTIFY_HEADERS_REVISION}"
    LINK_PROVENANCE=validated-private-musl-link-maps
    GCC_RUNTIME_VERSION=$(run_clean gcc -dumpfullversion -dumpversion)
    [[ "$GCC_RUNTIME_VERSION" =~ ^[0-9]+([.][0-9]+)*$ ]] \
      || die 'could not determine the GCC runtime version'
    GCC_RUNTIME_ARCHIVE=$(run_clean gcc -print-libgcc-file-name)
    GCC_EH_RUNTIME_ARCHIVE=$(run_clean gcc -print-file-name=libgcc_eh.a)
    for runtime_archive in "$GCC_RUNTIME_ARCHIVE" "$GCC_EH_RUNTIME_ARCHIVE"; do
      runtime_archive=$("$ISOLATED_PYTHON" -I - "$runtime_archive" <<'PY'
import pathlib
import stat
import sys

path = pathlib.Path(sys.argv[1]).resolve(strict=True)
metadata = path.stat()
if not stat.S_ISREG(metadata.st_mode):
    raise SystemExit("GCC runtime is not a regular file")
print(path)
PY
) || die 'could not resolve a GCC runtime archive'
      [[ "$runtime_archive" == /usr/lib/gcc/* ]] \
        || die "GCC runtime is outside the controlled system toolchain: ${runtime_archive}"
      case "$(basename -- "$runtime_archive")" in
        libgcc.a) GCC_RUNTIME_ARCHIVE=$runtime_archive ;;
        libgcc_eh.a) GCC_EH_RUNTIME_ARCHIVE=$runtime_archive ;;
        *) die "unexpected GCC runtime archive: ${runtime_archive}" ;;
      esac
    done
    ;;
  win32-arm64 | win32-x64)
    TOOLCHAIN_DIR="${WORK_DIR}/toolchain"
    extract_tar_strip_one "${DOWNLOAD_DIR}/${LLVM_MINGW_ARCHIVE}" \
      "$TOOLCHAIN_DIR" "$LLVM_MINGW_SHA256"
    BUILD_PATH="${TOOL_BIN}:${TOOLCHAIN_DIR}/bin:${SYSTEM_PATH}"
    install_tool_alias "$(select_tool /usr/bin/pkg-config FFMPEG_STATIC_PKG_CONFIG)" pkg-config
    install_tool_alias "$(select_tool /usr/bin/make FFMPEG_STATIC_MAKE)" make
    MAKE=make PKG_CONFIG=pkg-config
    TOOLCHAIN_NAME=llvm-mingw-ucrt
    TOOLCHAIN_VERSION=$LLVM_MINGW_VERSION
    TOOLCHAIN_URL=$LLVM_MINGW_URL
    TOOLCHAIN_SHA256=$LLVM_MINGW_SHA256
    if [[ "$TARGET" == win32-arm64 ]]; then
      TARGET_ARCH=aarch64
      HOST_TRIPLET=aarch64-w64-mingw32
    else
      TARGET_ARCH=x86_64
      HOST_TRIPLET=x86_64-w64-mingw32
    fi
    CROSS_PREFIX="${HOST_TRIPLET}-"
    CC="${CROSS_PREFIX}clang"
    CXX="${CROSS_PREFIX}clang++"
    AR=llvm-ar RANLIB=llvm-ranlib STRIP=llvm-strip NM=llvm-nm STRINGS=llvm-strings
    TARGET_CFLAGS='-O2 -fPIC -fstack-protector-strong -mguard=cf -D_WIN32_WINNT=0x0A00 -DWINVER=0x0A00'
    TARGET_LDFLAGS='-static -mguard=cf -Wl,--nxcompat,--dynamicbase,--high-entropy-va,--major-os-version,10,--minor-os-version,0,--major-subsystem-version,10,--minor-subsystem-version,0'
    LINK_PROVENANCE=validated-ucrt-system-import-allowlist
    CLANG_VERSION_OUTPUT=$(env -i PATH="$BUILD_PATH" LC_ALL=C "$CC" --version)
    ACTUAL_LLVM_RUNTIME_VERSION=$(awk '
      match($0, /clang version [0-9]+[.][0-9]+[.][0-9]+/) {
        value = substr($0, RSTART, RLENGTH)
        sub(/^clang version /, "", value)
        print value
        exit
      }
    ' <<<"$CLANG_VERSION_OUTPUT")
    [[ "$ACTUAL_LLVM_RUNTIME_VERSION" == "$LLVM_RUNTIME_VERSION" ]] \
      || die "pinned compiler runtime version mismatch: ${ACTUAL_LLVM_RUNTIME_VERSION:-missing}"
    grep -Fq -- "clang version ${LLVM_RUNTIME_VERSION} (https://github.com/llvm/llvm-project.git ${LLVM_RUNTIME_REVISION})" \
      <<<"$CLANG_VERSION_OUTPUT" \
      || die 'pinned compiler runtime revision is not reported by clang'
    MINGW_VERSION_HEADER="${TOOLCHAIN_DIR}/${HOST_TRIPLET}/include/_mingw_mac.h"
    [[ -f "$MINGW_VERSION_HEADER" && ! -L "$MINGW_VERSION_HEADER" ]] \
      || die 'missing MinGW-w64 version header'
    ACTUAL_MINGW_W64_VERSION=$("$ISOLATED_PYTHON" -I - "$MINGW_VERSION_HEADER" <<'PY'
import pathlib
import re
import sys

text = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
values = []
for name in ("MAJOR", "MINOR", "BUGFIX"):
    match = re.search(rf"^#define\s+__MINGW64_VERSION_{name}\s+([0-9]+)\s*$", text, re.M)
    if match is None:
        raise SystemExit(f"missing MinGW-w64 {name} version macro")
    values.append(match.group(1))
state = re.search(r'^#define\s+__MINGW64_VERSION_STATE\s+"([a-z0-9.-]+)"\s*$', text, re.M)
if state is None:
    raise SystemExit("missing MinGW-w64 version state macro")
print(".".join(values) + "-" + state.group(1))
PY
)
    [[ "$ACTUAL_MINGW_W64_VERSION" == "$MINGW_W64_VERSION" ]] \
      || die "pinned MinGW-w64 runtime version mismatch: ${ACTUAL_MINGW_W64_VERSION}"
    ;;
esac

NORMALIZE_CFLAGS="-ffile-prefix-map=${FFMPEG_STATIC_ROOT}=/usr/src/ffmpeg-static -fdebug-prefix-map=${FFMPEG_STATIC_ROOT}=/usr/src/ffmpeg-static -fmacro-prefix-map=${FFMPEG_STATIC_ROOT}=/usr/src/ffmpeg-static"
DEPENDENCY_CFLAGS="${TARGET_CFLAGS} ${NORMALIZE_CFLAGS}"
if [[ -n "$FORTIFY_INCLUDE" ]]; then
  DEPENDENCY_CFLAGS="-I${FORTIFY_INCLUDE} ${DEPENDENCY_CFLAGS}"
fi

for tool in "$CC" "$AR" "$RANLIB" "$STRIP" "$NM" "$STRINGS" "$MAKE" "$PKG_CONFIG"; do
  PATH="$BUILD_PATH" command -v "$tool" >/dev/null 2>&1 \
    || die "required controlled tool not found: ${tool}"
done
if [[ "$TARGET_NODE_ARCH" == x64 ]]; then
  RESOLVED_NASM=$(PATH="$BUILD_PATH" command -v nasm) \
    || die 'required controlled tool not found: nasm'
  [[ "$RESOLVED_NASM" == "${TOOL_BIN}/nasm" && -L "$RESOLVED_NASM" ]] \
    || die 'NASM did not resolve through the controlled private tool directory'
  [[ "$(readlink -- "$RESOLVED_NASM")" == "$NASM_BINARY" ]] \
    || die 'controlled NASM alias does not point to the source-built executable'
  verify_sha256 "$NASM_BINARY" "$NASM_BINARY_SHA256" \
    || die 'source-built NASM changed before dependency compilation'
fi

verify_fortify_overlay() {
  local safe_source unsafe_source dependencies safe_binary unsafe_binary
  safe_source="${WORK_DIR}/fortify-safe.c"
  unsafe_source="${WORK_DIR}/fortify-unsafe.c"
  dependencies="${WORK_DIR}/fortify-unsafe.d"
  safe_binary="${WORK_DIR}/fortify-safe"
  unsafe_binary="${WORK_DIR}/fortify-unsafe"
  printf '%s\n' '#if !defined(_FORTIFY_SOURCE) || _FORTIFY_SOURCE != 3' \
    '#error "the locked fortify-headers overlay requires _FORTIFY_SOURCE=3"' \
    '#endif' \
    '#include <stdio.h>' \
    'int main(void) { char b[2]; return fgets(b, sizeof b, stdin) != 0; }' >"$safe_source"
  printf '%s\n' '#if !defined(_FORTIFY_SOURCE) || _FORTIFY_SOURCE != 3' \
    '#error "the locked fortify-headers overlay requires _FORTIFY_SOURCE=3"' \
    '#endif' \
    '#include <stdio.h>' \
    'int main(void) { char b[1]; return fgets(b, sizeof b + 1, stdin) != 0; }' >"$unsafe_source"
  run_clean "$CC" -I"$FORTIFY_INCLUDE" -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3 -O2 \
    -fPIE -fstack-protector-strong "${ARCH_HARDENING_FLAGS[@]}" \
    -M "$unsafe_source" >"$dependencies"
  grep -Fq -- "${FORTIFY_INCLUDE}/stdio.h" "$dependencies" \
    || die 'the locked fortify-headers overlay was not selected by the compiler'
  run_clean "$CC" -I"$FORTIFY_INCLUDE" -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3 -O2 \
    -fPIE -fstack-protector-strong "${ARCH_HARDENING_FLAGS[@]}" "$safe_source" \
    "${TARGET_LDFLAGS_FLAGS[@]}" -o "$safe_binary"
  run_clean "$CC" -I"$FORTIFY_INCLUDE" -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3 -O2 \
    -fPIE -fstack-protector-strong "${ARCH_HARDENING_FLAGS[@]}" "$unsafe_source" \
    "${TARGET_LDFLAGS_FLAGS[@]}" -o "$unsafe_binary"
  run_clean "$safe_binary" </dev/null \
    || die 'safe fortify-headers control probe failed'
  if run_clean "$unsafe_binary" </dev/null >/dev/null 2>&1; then
    die 'fortify-headers did not trap a known out-of-bounds operation'
  fi
  FORTIFY_PROVENANCE="${FORTIFY_PROVENANCE}:runtime-trap-verified"
}

if [[ "$TARGET_PLATFORM" == linux ]]; then
  verify_fortify_overlay
fi

build_lame() {
  local configure_args=(
    "--prefix=${PREFIX_DIR}"
    --disable-shared
    --enable-static
    --disable-frontend
    --disable-decoder
    --disable-dependency-tracking
    --enable-pic
  )
  if [[ "$TARGET_PLATFORM" == win32 ]]; then
    configure_args+=("--host=${HOST_TRIPLET}")
  fi
  # Loaded from the authenticated sources.env via common.sh.
  # shellcheck disable=SC2153
  log "building LAME ${LAME_VERSION} (library only)"
  (
    cd "$WORK_DIR/src/lame"
    run_clean CC="$CC" CXX="$CXX" AR="$AR" RANLIB="$RANLIB" NM="$NM" \
      CFLAGS="$DEPENDENCY_CFLAGS" CXXFLAGS="$DEPENDENCY_CFLAGS" \
      LDFLAGS="$TARGET_LDFLAGS" ./configure "${configure_args[@]}"
    run_clean CC="$CC" CXX="$CXX" AR="$AR" RANLIB="$RANLIB" NM="$NM" \
      CFLAGS="$DEPENDENCY_CFLAGS" CXXFLAGS="$DEPENDENCY_CFLAGS" \
      LDFLAGS="$TARGET_LDFLAGS" "$MAKE" -j"$JOBS"
    run_clean "$MAKE" install
  )
}

build_x264() {
  local configure_args=(
    "--prefix=${PREFIX_DIR}"
    "--host=${HOST_TRIPLET}"
    --enable-static
    --disable-cli
    --enable-pic
    --disable-opencl
    --disable-avs
    --disable-lavf
    --disable-ffms
    --disable-gpac
    --disable-lsmash
  )
  if [[ -n "$CROSS_PREFIX" ]]; then
    configure_args+=("--cross-prefix=${CROSS_PREFIX}")
  fi
  log "building x264 ${X264_REVISION}"
  (
    cd "$WORK_DIR/src/x264"
    run_with_x264_assembler CC="$CC" AR="$AR" RANLIB="$RANLIB" STRIP="$STRIP" \
      CFLAGS="$DEPENDENCY_CFLAGS" LDFLAGS="$TARGET_LDFLAGS" PKGCONFIG=false \
      ./configure "${configure_args[@]}"
    run_with_x264_assembler CC="$CC" AR="$AR" RANLIB="$RANLIB" STRIP="$STRIP" \
      CFLAGS="$DEPENDENCY_CFLAGS" LDFLAGS="$TARGET_LDFLAGS" \
      "$MAKE" -j"$JOBS"
    run_clean "$MAKE" install
  )
}

FFMPEG_PUBLIC_CFLAGS=$TARGET_CFLAGS
if [[ "$TARGET_PLATFORM" == linux ]]; then
  FFMPEG_PUBLIC_CFLAGS="-I../src/fortify-headers/include ${FFMPEG_PUBLIC_CFLAGS}"
fi
FFMPEG_CONFIGURE_ARGS=(
  --prefix=/usr/local
  --datadir=/usr/local/share/ffmpeg
  --disable-shared
  --enable-static
  --disable-autodetect
  --enable-gpl
  --enable-libx264
  --enable-libmp3lame
  --enable-ffmpeg
  --enable-ffprobe
  --disable-ffplay
  --disable-doc
  --disable-debug
  --enable-pic
  --enable-runtime-cpudetect
  --pkg-config-flags=--static
  "--pkg-config=${PKG_CONFIG}"
  "--cc=${CC}"
  "--cxx=${CXX}"
  "--ar=${AR}"
  "--ranlib=${RANLIB}"
  "--strip=${STRIP}"
  "--nm=${NM}"
  "--arch=${TARGET_ARCH}"
  "--extra-cflags=${FFMPEG_PUBLIC_CFLAGS}"
  "--extra-ldflags=${TARGET_LDFLAGS}"
  --extra-libs=-lm
)
if [[ "$TARGET_NODE_ARCH" == x64 ]]; then
  FFMPEG_CONFIGURE_ARGS+=(--x86asmexe=nasm)
fi

case "$TARGET_PLATFORM" in
  darwin)
    FFMPEG_CONFIGURE_ARGS+=(--target-os=darwin --enable-videotoolbox --enable-audiotoolbox)
    ;;
  linux)
    # FFmpeg executes small build-time generators.  Keep those on the native,
    # controlled host compiler: the target musl sysroot intentionally has no
    # dynamic loader because only static-PIE deliverables are permitted.
    FFMPEG_CONFIGURE_ARGS+=(--target-os=linux --host-cc=gcc)
    ;;
  win32)
    FFMPEG_CONFIGURE_ARGS+=(--target-os=mingw32 --enable-cross-compile "--cross-prefix=${CROSS_PREFIX}")
    ;;
esac

write_configure_record() {
  local argument
  {
    printf './configure'
    for argument in "${FFMPEG_CONFIGURE_ARGS[@]}"; do
      printf ' \\\n  %q' "$argument"
    done
    printf '\n'
  } >"${PAYLOAD_DIR}/configure.txt"
}

write_configure_json_array() {
  local index
  for (( index = 0; index < ${#FFMPEG_CONFIGURE_ARGS[@]}; index++ )); do
    printf '    %s' "$(quote_value "${FFMPEG_CONFIGURE_ARGS[$index]}")"
    if (( index + 1 < ${#FFMPEG_CONFIGURE_ARGS[@]} )); then
      printf ','
    fi
    printf '\n'
  done
}

build_lame
build_x264

FFMPEG_BUILD_DIR="${WORK_DIR}/ffmpeg-build"
MAP_DIR="${WORK_DIR}/link-maps"
mkdir -p -- "$FFMPEG_BUILD_DIR" "$MAP_DIR"
if [[ "$TARGET_PLATFORM" == win32 ]]; then
  BINARY_NAME=ffmpeg.exe
  PROBE_NAME=ffprobe.exe
else
  BINARY_NAME=ffmpeg
  PROBE_NAME=ffprobe
fi
if [[ "$TARGET_PLATFORM" == darwin ]]; then
  FFMPEG_MAP_FLAG="-Wl,-map,${MAP_DIR}/ffmpeg.map"
  FFPROBE_MAP_FLAG="-Wl,-map,${MAP_DIR}/ffprobe.map"
else
  FFMPEG_MAP_FLAG="-Wl,-Map,${MAP_DIR}/ffmpeg.map"
  FFPROBE_MAP_FLAG="-Wl,-Map,${MAP_DIR}/ffprobe.map"
fi
log "building FFmpeg ${FFMPEG_VERSION}"
(
  cd "$FFMPEG_BUILD_DIR"
  run_clean \
    CC="$CC" CXX="$CXX" AR="$AR" RANLIB="$RANLIB" STRIP="$STRIP" NM="$NM" \
    CPPFLAGS="-I${PREFIX_DIR}/include" CFLAGS="$NORMALIZE_CFLAGS" \
    CXXFLAGS="$NORMALIZE_CFLAGS" LDFLAGS="-L${PREFIX_DIR}/lib" \
    PKG_CONFIG_PATH="${PREFIX_DIR}/lib/pkgconfig" \
    PKG_CONFIG_LIBDIR="${PREFIX_DIR}/lib/pkgconfig" \
    "$WORK_DIR/src/ffmpeg/configure" "${FFMPEG_CONFIGURE_ARGS[@]}"
  run_clean "$MAKE" -j"$JOBS" \
    "LDFLAGS-ffmpeg=${FFMPEG_MAP_FLAG}" \
    "LDFLAGS-ffprobe=${FFPROBE_MAP_FLAG}"
)

verify_windows_link_trace() {
  local trace_path=$1 program=$2 runtime_arch runtime_major runtime_archive
  runtime_arch=$TARGET_ARCH
  runtime_major=${LLVM_RUNTIME_VERSION%%.*}
  runtime_archive="libclang_rt.builtins-${runtime_arch}.a"
  [[ -s "$trace_path" ]] || die "missing Windows linker trace: ${trace_path}"
  grep -Fq -- "Reading ${TOOLCHAIN_DIR}/${HOST_TRIPLET}/lib/crt2.o" "$trace_path" \
    || die "${program} did not use the pinned MinGW-w64 CRT startup"
  grep -Fq -- "Reading ${TOOLCHAIN_DIR}/lib/clang/${runtime_major}/lib/windows/${runtime_archive}" \
    "$trace_path" || die "${program} did not read the pinned compiler-rt archive"
  grep -Fq -- "Loaded ${runtime_archive}(" "$trace_path" \
    || die "${program} did not extract any compiler-rt builtins"
  grep -Fq -- "Loaded libmingw32.a(" "$trace_path" \
    || die "${program} did not extract the MinGW-w64 CRT"
  grep -Fq -- "Loaded libmingwex.a(" "$trace_path" \
    || die "${program} did not extract the MinGW-w64 extended runtime"
  if grep -Eq -- \
    'Loaded (libunwind|libwinpthread|libwinstorecompat|libc[+][+]|libc[+][+]abi|libssp)[.]a[(]' \
    "$trace_path"; then
    die "${program} extracted an undeclared static runtime archive"
  fi
  if awk -v wanted="Loaded ${runtime_archive}(" '
    /Loaded libclang_rt[.]/ && index($0, wanted) == 0 { bad = 1 }
    END { exit bad }
  ' "$trace_path"; then
    :
  else
    die "${program} extracted an undeclared compiler-rt archive"
  fi
  verify_windows_cephes_absence "$trace_path" "${MAP_DIR}/${program}.map"
}

if [[ "$TARGET_PLATFORM" == win32 ]]; then
  # COFF map files omit archive provenance for extracted members. Relink each
  # program serially with lld's verbose diagnostics and retain a separate trace
  # so the declared static runtime closure is proven rather than inferred.
  for program in ffmpeg ffprobe; do
    trace_path="${MAP_DIR}/${program}.link-trace.txt"
    rm -f -- "${FFMPEG_BUILD_DIR}/${program}.exe" \
      "${FFMPEG_BUILD_DIR}/${program}_g.exe"
    if ! (
      cd "$FFMPEG_BUILD_DIR"
      run_clean "$MAKE" -j1 "${program}.exe" \
        "LDFLAGS-${program}=-Wl,-Map,${MAP_DIR}/${program}.map -Wl,/verbose"
    ) >"$trace_path" 2>&1; then
      tail -n 120 "$trace_path" >&2
      die "failed to relink ${program} with static-runtime provenance"
    fi
    verify_windows_link_trace "$trace_path" "$program"
  done
fi

if [[ "$TARGET_PLATFORM" == linux ]]; then
  for map_name in ffmpeg ffprobe; do
    map_path="${MAP_DIR}/${map_name}.map"
    [[ -s "$map_path" ]] || die "missing linker map: ${map_path}"
    grep -Fq -- "${MUSL_PREFIX}/lib/libc.a" "$map_path" \
      || die "${map_name} was not linked to the source-built musl libc.a"
    if ! awk -v wanted="${MUSL_PREFIX}/lib/libc.a" '
      /libc[.]a/ && index($0, wanted) == 0 { bad = 1 }
      END { exit bad }
    ' "$map_path"; then
      die "${map_name} linker map contains an untrusted libc.a"
    fi
    if ! grep -Fq -- "${GCC_RUNTIME_ARCHIVE}(" "$map_path" \
      && ! grep -Fq -- "${GCC_EH_RUNTIME_ARCHIVE}(" "$map_path"; then
      die "${map_name} did not extract any object from the controlled GCC runtime"
    fi
    if ! awk -v gcc="${GCC_RUNTIME_ARCHIVE}(" -v gcc_eh="${GCC_EH_RUNTIME_ARCHIVE}(" '
      /libgcc(_eh)?[.]a[(]/ && index($0, gcc) == 0 && index($0, gcc_eh) == 0 {
        bad = 1
      }
      END { exit bad }
    ' "$map_path"; then
      die "${map_name} linker map contains an untrusted GCC runtime archive"
    fi
    if grep -Eq -- \
      'libgcc_s[.]so|/(libstdc[+][+]|libatomic|libgomp|libssp)[.]a[(]' "$map_path"; then
      die "${map_name} extracted an undeclared compiler runtime"
    fi
  done
fi

if [[ "$TARGET_PLATFORM" == win32 ]]; then
  if ! run_clean "$NM" "${FFMPEG_BUILD_DIR}/ffmpeg_g.exe" \
    | awk '/ff_libx264_encoder/ {x264=1} /ff_libmp3lame_encoder/ {lame=1} END {exit !(x264 && lame)}'; then
    die 'cross-built ffmpeg is missing the requested encoder symbols'
  fi
fi

install -m 0755 "${FFMPEG_BUILD_DIR}/${BINARY_NAME}" "${PAYLOAD_DIR}/${BINARY_NAME}"
install -m 0755 "${FFMPEG_BUILD_DIR}/${PROBE_NAME}" "${PAYLOAD_DIR}/${PROBE_NAME}"
case "$TARGET_PLATFORM" in
  darwin) run_clean "$STRIP" -x "${PAYLOAD_DIR}/${BINARY_NAME}" "${PAYLOAD_DIR}/${PROBE_NAME}" ;;
  linux) run_clean "$STRIP" --strip-debug "${PAYLOAD_DIR}/${BINARY_NAME}" "${PAYLOAD_DIR}/${PROBE_NAME}" ;;
  win32) run_clean "$STRIP" --strip-all "${PAYLOAD_DIR}/${BINARY_NAME}" "${PAYLOAD_DIR}/${PROBE_NAME}" ;;
esac

write_configure_record
verify_sha256 "$WORK_DIR/src/ffmpeg/LICENSE.md" "$FFMPEG_LICENSE_SHA256" \
  || die 'FFmpeg LICENSE.md does not match its lock'
verify_sha256 "$WORK_DIR/src/ffmpeg/COPYING.GPLv2" "$FFMPEG_GPLV2_SHA256" \
  || die 'FFmpeg GPLv2 notice does not match its lock'
verify_sha256 "$WORK_DIR/src/ffmpeg/COPYING.GPLv3" "$FFMPEG_GPLV3_SHA256" \
  || die 'FFmpeg GPLv3 notice does not match its lock'
verify_sha256 "$WORK_DIR/src/x264/COPYING" "$X264_LICENSE_SHA256" \
  || die 'x264 license notice does not match its lock'
verify_sha256 "$WORK_DIR/src/lame/COPYING" "$LAME_COPYING_SHA256" \
  || die 'LAME COPYING notice does not match its lock'
verify_sha256 "$WORK_DIR/src/lame/LICENSE" "$LAME_LICENSE_SHA256" \
  || die 'LAME LICENSE notice does not match its lock'
install -m 0644 "$WORK_DIR/src/ffmpeg/LICENSE.md" "$LICENSE_DIR/FFmpeg-LICENSE.md"
install -m 0644 "$WORK_DIR/src/ffmpeg/COPYING.GPLv2" "$LICENSE_DIR/FFmpeg-COPYING.GPLv2"
install -m 0644 "$WORK_DIR/src/ffmpeg/COPYING.GPLv3" "$LICENSE_DIR/FFmpeg-COPYING.GPLv3"
install -m 0644 "$WORK_DIR/src/x264/COPYING" "$LICENSE_DIR/x264-COPYING"
if [[ "$TARGET_NODE_ARCH" == x64 ]]; then
  X264_ISC_NOTICE="${FFMPEG_STATIC_ROOT}/licenses/x264-x86inc-ISC.txt"
  [[ -f "$X264_ISC_NOTICE" && ! -L "$X264_ISC_NOTICE" ]] \
    || die 'missing controlled x264 x86inc ISC notice'
  verify_sha256 "$X264_ISC_NOTICE" "$X264_X86INC_ISC_SHA256" \
    || die 'the x264 x86inc ISC notice does not match its lock'
  install -m 0644 "$X264_ISC_NOTICE" "$LICENSE_DIR/x264-x86inc-ISC.txt"
fi
install -m 0644 "$WORK_DIR/src/lame/COPYING" "$LICENSE_DIR/LAME-COPYING"
install -m 0644 "$WORK_DIR/src/lame/LICENSE" "$LICENSE_DIR/LAME-LICENSE"
verify_sha256 "$WORK_DIR/src/ffmpeg/COPYING.LGPLv2.1" "$FFMPEG_LGPLV21_SHA256" \
  || die 'the authenticated LGPL-2.1 notice does not match its lock'
install -m 0644 "$WORK_DIR/src/ffmpeg/COPYING.LGPLv2.1" "$LICENSE_DIR/FFmpeg-COPYING.LGPLv2.1"
IJG_NOTICE="${FFMPEG_STATIC_ROOT}/licenses/FFmpeg-IJG-NOTICE.txt"
[[ -f "$IJG_NOTICE" && ! -L "$IJG_NOTICE" ]] || die 'missing controlled FFmpeg IJG notice'
verify_sha256 "$IJG_NOTICE" "$FFMPEG_IJG_NOTICE_SHA256" \
  || die 'the FFmpeg IJG notice does not match its lock'
install -m 0644 "$IJG_NOTICE" "$LICENSE_DIR/FFmpeg-IJG-NOTICE.txt"
install -m 0644 "$THIRD_PARTY_NOTICE" "$LICENSE_DIR/THIRD-PARTY-NOTICES.txt"

case "$TARGET_PLATFORM" in
  linux)
    GCC_NOTICE="${FFMPEG_STATIC_ROOT}/licenses/GCC-RUNTIME-LIBRARY-EXCEPTION-3.1.txt"
    [[ -f "$GCC_NOTICE" && ! -L "$GCC_NOTICE" ]] \
      || die "missing GCC runtime exception notice: ${GCC_NOTICE}"
    verify_sha256 "$GCC_NOTICE" "$GCC_RUNTIME_EXCEPTION_SHA256" \
      || die 'the GCC runtime exception notice does not match its lock'
    grep -Fqi 'GCC RUNTIME LIBRARY EXCEPTION' "$GCC_NOTICE" \
      || die 'the GCC notice does not contain the runtime library exception'
    verify_sha256 "$MUSL_SOURCE/COPYRIGHT" "$MUSL_COPYRIGHT_SHA256" \
      || die 'musl copyright notice does not match its lock'
    verify_sha256 "$FORTIFY_SOURCE/LICENSE" "$FORTIFY_HEADERS_LICENSE_SHA256" \
      || die 'fortify-headers license notice does not match its lock'
    install -m 0644 "$MUSL_SOURCE/COPYRIGHT" "$LICENSE_DIR/musl-COPYRIGHT"
    install -m 0644 "$FORTIFY_SOURCE/LICENSE" "$LICENSE_DIR/fortify-headers-LICENSE"
    install -m 0644 "$GCC_NOTICE" "$LICENSE_DIR/GCC-RUNTIME-LIBRARY-EXCEPTION.txt"
    DEPENDENCIES_JSON=$(printf \
      '[{"name":"musl","version":%s,"license":"MIT AND SunPro","relationship":"static-link"},{"name":"gcc-runtime","version":%s,"license":"GPL-3.0-or-later WITH GCC-exception-3.1","relationship":"static-link"},{"name":"fortify-headers","version":%s,"license":"0BSD","relationship":"header-inline"}]' \
      "$(quote_value "$MUSL_VERSION")" "$(quote_value "$GCC_RUNTIME_VERSION")" \
      "$(quote_value "$FORTIFY_HEADERS_REVISION")")
    ;;
  win32)
    LLVM_NOTICE="${TOOLCHAIN_DIR}/LICENSE.TXT"
    MINGW_NOTICE="${TOOLCHAIN_DIR}/${HOST_TRIPLET}/share/mingw32/COPYING.MinGW-w64-runtime.txt"
    [[ -f "$LLVM_NOTICE" && ! -L "$LLVM_NOTICE" ]] || die 'missing LLVM license notice'
    [[ -f "$MINGW_NOTICE" && ! -L "$MINGW_NOTICE" ]] || die 'missing MinGW-w64 runtime notice'
    verify_sha256 "$LLVM_NOTICE" "$LLVM_LICENSE_SHA256" \
      || die 'LLVM license notice does not match its lock'
    verify_sha256 "$MINGW_NOTICE" "$MINGW_RUNTIME_LICENSE_SHA256" \
      || die 'MinGW-w64 runtime notice does not match its lock'
    install -m 0644 "$LLVM_NOTICE" "$LICENSE_DIR/LLVM-LICENSE.TXT"
    install -m 0644 "$MINGW_NOTICE" "$LICENSE_DIR/MinGW-w64-runtime-COPYING.txt"
    DEPENDENCIES_JSON=$(printf \
      '[{"name":"llvm-compiler-rt","version":%s,"license":"Apache-2.0 WITH LLVM-exception","relationship":"static-link"},{"name":"mingw-w64-runtime","version":%s,"license":"LicenseRef-MinGW-w64-runtime","relationship":"static-link"}]' \
      "$(quote_value "$LLVM_RUNTIME_VERSION")" "$(quote_value "$MINGW_W64_VERSION")")
    ;;
esac

COMPILER_VERSION=$(capture_version "$CC" --version)
PKG_CONFIG_VERSION=$(capture_version "$PKG_CONFIG" --version)
MAKE_VERSION=$(capture_version "$MAKE" --version)
PYTHON_VERSION=$(capture_version "$ISOLATED_PYTHON" --version)
TAR_VERSION=$(capture_version tar --version)
if [[ "$TARGET_PLATFORM" == darwin ]]; then
  LINKER_COMMAND=ld
  LINKER_VERSION=$(capture_version ld -v)
  BINUTILS_VERSION=$(capture_version ranlib -V)
elif [[ "$TARGET_PLATFORM" == win32 ]]; then
  LINKER_COMMAND=ld.lld
  LINKER_VERSION=$(capture_version ld.lld --version)
  BINUTILS_VERSION=$(capture_version llvm-ar --version)
else
  LINKER_COMMAND=ld
  LINKER_VERSION=$(capture_version ld --version)
  BINUTILS_VERSION=$(capture_version ar --version)
fi
NASM_JSON=null
if [[ "$TARGET_NODE_ARCH" == x64 ]]; then
  NASM_OBSERVED_VERSION=$(capture_version nasm -v)
  EXPECTED_NASM_VERSION=$("$ISOLATED_PYTHON" -I - "$NASM_VERSION" "$SOURCE_DATE_EPOCH" <<'PY'
import datetime
import sys

version = sys.argv[1]
moment = datetime.datetime.fromtimestamp(int(sys.argv[2]), tz=datetime.timezone.utc)
months = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
print(f"NASM version {version} compiled on {months[moment.month - 1]} {moment.day:2d} {moment.year}")
PY
)
  [[ "$NASM_OBSERVED_VERSION" == "$EXPECTED_NASM_VERSION" ]] \
    || die "source-built NASM version/date mismatch: ${NASM_OBSERVED_VERSION}"
  verify_sha256 "$NASM_BINARY" "$NASM_BINARY_SHA256" \
    || die 'source-built NASM changed before provenance capture'
  NASM_JSON=$(printf '{"binarySha256":%s,"command":"nasm","sourceSha256":%s,"sourceUrl":%s,"sourceVersion":%s,"version":%s}' \
    "$(quote_value "$NASM_BINARY_SHA256")" "$(quote_value "$NASM_SHA256")" \
    "$(quote_value "$NASM_URL")" "$(quote_value "$NASM_VERSION")" \
    "$(quote_value "$NASM_OBSERVED_VERSION")")
fi

MINIMUM_OS_JSON=$(
  "$ISOLATED_PYTHON" -I - "$SCRIPT_DIR" "$TARGET" "$SOURCES_FILE" <<'PY'
import json
import pathlib
import sys

sys.path.insert(0, sys.argv[1])
import pipeline_lib

sources = pipeline_lib.load_sources(pathlib.Path(sys.argv[3]))
print(json.dumps(
    pipeline_lib.minimum_os(sys.argv[2], sources),
    separators=(",", ":"),
    sort_keys=True,
))
PY
) || die 'could not resolve the target-specific minimum OS contract'

TOOLCHAIN_JSON=$(printf '{"name":%s,"version":%s,"url":%s,"sha256":%s}' \
  "$(quote_value "$TOOLCHAIN_NAME")" "$(quote_value "$TOOLCHAIN_VERSION")" \
  "$(quote_value "$TOOLCHAIN_URL")" "$(quote_value "$TOOLCHAIN_SHA256")")

{
  printf '{\n'
  printf '  "schemaVersion": 1,\n'
  printf '  "target": %s,\n' "$(quote_value "$TARGET")"
  printf '  "platform": %s,\n' "$(quote_value "$TARGET_PLATFORM")"
  printf '  "arch": %s,\n' "$(quote_value "$TARGET_NODE_ARCH")"
  printf '  "license": %s,\n' "$(quote_value "$ARTIFACT_LICENSE")"
  printf '  "minimumOs": %s,\n' "$MINIMUM_OS_JSON"
  printf '  "compiler": {"command": %s, "version": %s},\n' \
    "$(quote_value "$CC")" "$(quote_value "$COMPILER_VERSION")"
  printf '  "toolchain": %s,\n' "$TOOLCHAIN_JSON"
  printf '  "tools": {\n'
  printf '    "linker": {"command": %s, "version": %s},\n' \
    "$(quote_value "$LINKER_COMMAND")" "$(quote_value "$LINKER_VERSION")"
  printf '    "binutils": {"ar": %s, "ranlib": %s, "strip": %s, "nm": %s, "strings": %s, "version": %s},\n' \
    "$(quote_value "$AR")" "$(quote_value "$RANLIB")" "$(quote_value "$STRIP")" \
    "$(quote_value "$NM")" "$(quote_value "$STRINGS")" "$(quote_value "$BINUTILS_VERSION")"
  printf '    "nasm": %s,\n' "$NASM_JSON"
  printf '    "pkgConfig": {"command": %s, "version": %s},\n' \
    "$(quote_value "$PKG_CONFIG")" "$(quote_value "$PKG_CONFIG_VERSION")"
  printf '    "make": {"command": %s, "version": %s},\n' \
    "$(quote_value "$MAKE")" "$(quote_value "$MAKE_VERSION")"
  printf '    "python": {"command": "python3", "version": %s},\n' "$(quote_value "$PYTHON_VERSION")"
  printf '    "tar": {"command": "tar", "version": %s},\n' "$(quote_value "$TAR_VERSION")"
  printf '    "macosSdkVersion": %s\n' "$(quote_value "$SDK_VERSION")"
  printf '  },\n'
  printf '  "hardening": {"fortify": %s, "linkProvenance": %s},\n' \
    "$(quote_value "$FORTIFY_PROVENANCE")" "$(quote_value "$LINK_PROVENANCE")"
  printf '  "configure": [\n'
  write_configure_json_array
  printf '  ],\n'
  printf '  "sources": {\n'
  printf '    "ffmpeg": {"version": %s, "url": %s, "sha256": %s},\n' \
    "$(quote_value "$FFMPEG_VERSION")" "$(quote_value "$FFMPEG_URL")" "$(quote_value "$FFMPEG_SHA256")"
  printf '    "x264": {"revision": %s, "url": %s, "sha256": %s},\n' \
    "$(quote_value "$X264_REVISION")" "$(quote_value "$X264_URL")" "$(quote_value "$X264_SHA256")"
  printf '    "lame": {"version": %s, "url": %s, "sha256": %s},\n' \
    "$(quote_value "$LAME_VERSION")" "$(quote_value "$LAME_URL")" "$(quote_value "$LAME_SHA256")"
  printf '    "musl": {"version": %s, "url": %s, "sha256": %s},\n' \
    "$(quote_value "$MUSL_VERSION")" "$(quote_value "$MUSL_URL")" "$(quote_value "$MUSL_SHA256")"
  printf '    "nasm": {"version": %s, "url": %s, "sha256": %s},\n' \
    "$(quote_value "$NASM_VERSION")" "$(quote_value "$NASM_URL")" "$(quote_value "$NASM_SHA256")"
  printf '    "fortifyHeaders": {"version": %s, "revision": %s, "url": %s, "sha256": %s},\n' \
    "$(quote_value "$FORTIFY_HEADERS_VERSION")" "$(quote_value "$FORTIFY_HEADERS_REVISION")" \
    "$(quote_value "$FORTIFY_HEADERS_URL")" "$(quote_value "$FORTIFY_HEADERS_SHA256")"
  printf '    "llvmMingwRecipe": {"revision": %s, "url": %s, "sha256": %s},\n' \
    "$(quote_value "$LLVM_MINGW_RECIPE_REVISION")" "$(quote_value "$LLVM_MINGW_RECIPE_URL")" \
    "$(quote_value "$LLVM_MINGW_RECIPE_SHA256")"
  printf '    "llvmCompilerRt": {"version": %s, "revision": %s, "url": %s, "sha256": %s},\n' \
    "$(quote_value "$LLVM_RUNTIME_VERSION")" "$(quote_value "$LLVM_RUNTIME_REVISION")" \
    "$(quote_value "$LLVM_RUNTIME_URL")" "$(quote_value "$LLVM_RUNTIME_SHA256")"
  printf '    "mingwW64Runtime": {"version": %s, "revision": %s, "url": %s, "sha256": %s}\n' \
    "$(quote_value "$MINGW_W64_VERSION")" "$(quote_value "$MINGW_W64_REVISION")" \
    "$(quote_value "$MINGW_W64_URL")" "$(quote_value "$MINGW_W64_SHA256")"
  printf '  },\n'
  printf '  "dependencies": %s\n' "$DEPENDENCIES_JSON"
  printf '}\n'
} >"$BUILD_INFO"

for binary_path in "${PAYLOAD_DIR}/${BINARY_NAME}" "${PAYLOAD_DIR}/${PROBE_NAME}"; do
  binary_strings=$(run_clean "$STRINGS" "$binary_path")
  if grep -Fq -- "$FFMPEG_STATIC_ROOT" <<<"$binary_strings"; then
    die "absolute checkout path is embedded in ${binary_path}"
  fi
done

chmod 0755 "${PAYLOAD_DIR}/${BINARY_NAME}" "${PAYLOAD_DIR}/${PROBE_NAME}"
find "$LICENSE_DIR" -type f -exec chmod 0644 {} +
chmod 0644 "${PAYLOAD_DIR}/configure.txt" "$BUILD_INFO"
log "build complete: ${PAYLOAD_DIR}"
log "build metadata: ${BUILD_INFO}"
