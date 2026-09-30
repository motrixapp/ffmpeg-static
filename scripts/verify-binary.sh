#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
umask 077

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=common.sh disable=SC1091
source "${SCRIPT_DIR}/common.sh"

FINAL_BINARY_MODE=0
case $# in
  1) TARGET=$1 ;;
  2)
    [[ "$1" == --final-binary ]] \
      || die 'usage: verify-binary.sh [--final-binary] <target>'
    FINAL_BINARY_MODE=1
    TARGET=$2
    ;;
  *) die 'usage: verify-binary.sh [--final-binary] <target>' ;;
esac
require_target "$TARGET"

TARGET_PLATFORM=${TARGET%%-*}
TARGET_ARCH=${TARGET#*-}
if (( FINAL_BINARY_MODE )) && [[ "$TARGET_PLATFORM" != win32 ]]; then
  die '--final-binary is only valid for signed Windows candidates'
fi
BUILD_ROOT="${FFMPEG_STATIC_ROOT}/build/${TARGET}"
PAYLOAD_DIR="${BUILD_ROOT}/payload"
LICENSE_DIR="${PAYLOAD_DIR}/LICENSES"
BUILD_INFO="${BUILD_ROOT}/build-info.json"
if [[ "$TARGET_PLATFORM" == win32 ]]; then
  BINARY_NAME=ffmpeg.exe
  PROBE_NAME=ffprobe.exe
else
  BINARY_NAME=ffmpeg
  PROBE_NAME=ffprobe
fi
BINARY_PATH="${PAYLOAD_DIR}/${BINARY_NAME}"
PROBE_PATH="${PAYLOAD_DIR}/${PROBE_NAME}"

SYSTEM_PATH=/usr/bin:/bin:/usr/sbin:/sbin
PATH=$SYSTEM_PATH
export PATH LC_ALL=C TZ=UTC
unset CFLAGS CXXFLAGS CPPFLAGS LDFLAGS CPATH C_INCLUDE_PATH CPLUS_INCLUDE_PATH
unset LIBRARY_PATH PKG_CONFIG_PATH PKG_CONFIG_LIBDIR CONFIG_SITE MAKEFLAGS MFLAGS

require_command file grep awk python3 strings

VERIFY_TMP=$(mktemp -d "${BUILD_ROOT}/verify.XXXXXX")
chmod 700 "$VERIFY_TMP"
cleanup() {
  rm -rf -- "$VERIFY_TMP"
}
trap cleanup EXIT

required_files=(
  "$BINARY_PATH"
  "$PROBE_PATH"
  "${PAYLOAD_DIR}/configure.txt"
  "$BUILD_INFO"
  "${PAYLOAD_DIR}/LICENSES/FFmpeg-LICENSE.md"
  "${PAYLOAD_DIR}/LICENSES/FFmpeg-COPYING.GPLv2"
  "${PAYLOAD_DIR}/LICENSES/FFmpeg-COPYING.GPLv3"
  "${PAYLOAD_DIR}/LICENSES/x264-COPYING"
  "${PAYLOAD_DIR}/LICENSES/LAME-COPYING"
  "${PAYLOAD_DIR}/LICENSES/LAME-LICENSE"
  "${PAYLOAD_DIR}/LICENSES/FFmpeg-COPYING.LGPLv2.1"
  "${PAYLOAD_DIR}/LICENSES/FFmpeg-IJG-NOTICE.txt"
  "${PAYLOAD_DIR}/LICENSES/THIRD-PARTY-NOTICES.txt"
)
if [[ "$TARGET_ARCH" == x64 ]]; then
  required_files+=("${PAYLOAD_DIR}/LICENSES/x264-x86inc-ISC.txt")
fi
ARTIFACT_LICENSE=$("$ISOLATED_PYTHON" -I - "$SCRIPT_DIR" "$TARGET" <<'PY'
import sys

sys.path.insert(0, sys.argv[1])
import pipeline_lib

print(pipeline_lib.artifact_license(sys.argv[2]))
PY
) || die 'could not resolve the canonical artifact license profile'
case "$TARGET_PLATFORM" in
  linux)
    required_files+=(
      "${PAYLOAD_DIR}/LICENSES/musl-COPYRIGHT"
      "${PAYLOAD_DIR}/LICENSES/fortify-headers-LICENSE"
      "${PAYLOAD_DIR}/LICENSES/GCC-RUNTIME-LIBRARY-EXCEPTION.txt"
    )
    ;;
  win32)
    required_files+=(
      "${PAYLOAD_DIR}/LICENSES/LLVM-LICENSE.TXT"
      "${PAYLOAD_DIR}/LICENSES/MinGW-w64-runtime-COPYING.txt"
    )
    ;;
esac
for required_file in "${required_files[@]}"; do
  [[ -f "$required_file" && ! -L "$required_file" && -s "$required_file" ]] \
    || die "missing non-empty regular output file: ${required_file}"
done
[[ -x "$BINARY_PATH" && -x "$PROBE_PATH" ]] \
  || die 'ffmpeg and ffprobe must be executable'

"$ISOLATED_PYTHON" -I - "$LICENSE_DIR" "$TARGET_PLATFORM" "$TARGET_ARCH" <<'PY'
import pathlib
import sys

directory = pathlib.Path(sys.argv[1])
platform = sys.argv[2]
arch = sys.argv[3]
expected = {
    "FFmpeg-LICENSE.md",
    "FFmpeg-COPYING.GPLv2",
    "FFmpeg-COPYING.GPLv3",
    "FFmpeg-IJG-NOTICE.txt",
    "THIRD-PARTY-NOTICES.txt",
    "x264-COPYING",
    "LAME-COPYING",
    "LAME-LICENSE",
    "FFmpeg-COPYING.LGPLv2.1",
}
if arch == "x64":
    expected.add("x264-x86inc-ISC.txt")
if platform == "linux":
    expected.update({
        "musl-COPYRIGHT",
        "fortify-headers-LICENSE",
        "GCC-RUNTIME-LIBRARY-EXCEPTION.txt",
    })
elif platform == "win32":
    expected.update({"LLVM-LICENSE.TXT", "MinGW-w64-runtime-COPYING.txt"})
entries = list(directory.iterdir())
actual = {entry.name for entry in entries}
if actual != expected:
    raise SystemExit(
        f"payload license set mismatch; missing={sorted(expected - actual)}, "
        f"extra={sorted(actual - expected)}"
    )
if any(not entry.is_file() or entry.is_symlink() for entry in entries):
    raise SystemExit("payload license directory contains a non-regular entry")
PY

verify_payload_notice() {
  local name=$1 expected=$2
  verify_sha256 "${PAYLOAD_DIR}/LICENSES/${name}" "$expected" \
    || die "payload license notice does not match its lock: ${name}"
}

verify_payload_notice FFmpeg-LICENSE.md "$FFMPEG_LICENSE_SHA256"
verify_payload_notice FFmpeg-COPYING.GPLv2 "$FFMPEG_GPLV2_SHA256"
verify_payload_notice FFmpeg-COPYING.GPLv3 "$FFMPEG_GPLV3_SHA256"
verify_payload_notice FFmpeg-IJG-NOTICE.txt "$FFMPEG_IJG_NOTICE_SHA256"
verify_payload_notice THIRD-PARTY-NOTICES.txt "$THIRD_PARTY_NOTICES_SHA256"
verify_utf8_file_size \
  "${PAYLOAD_DIR}/LICENSES/THIRD-PARTY-NOTICES.txt" "$THIRD_PARTY_NOTICES_SIZE"
verify_payload_notice x264-COPYING "$X264_LICENSE_SHA256"
if [[ "$TARGET_ARCH" == x64 ]]; then
  verify_payload_notice x264-x86inc-ISC.txt "$X264_X86INC_ISC_SHA256"
fi
verify_payload_notice LAME-COPYING "$LAME_COPYING_SHA256"
verify_payload_notice LAME-LICENSE "$LAME_LICENSE_SHA256"
verify_payload_notice FFmpeg-COPYING.LGPLv2.1 "$FFMPEG_LGPLV21_SHA256"
case "$TARGET_PLATFORM" in
  linux)
    verify_payload_notice musl-COPYRIGHT "$MUSL_COPYRIGHT_SHA256"
    verify_payload_notice fortify-headers-LICENSE "$FORTIFY_HEADERS_LICENSE_SHA256"
    verify_payload_notice GCC-RUNTIME-LIBRARY-EXCEPTION.txt "$GCC_RUNTIME_EXCEPTION_SHA256"
    ;;
  win32)
    verify_payload_notice LLVM-LICENSE.TXT "$LLVM_LICENSE_SHA256"
    verify_payload_notice MinGW-w64-runtime-COPYING.txt "$MINGW_RUNTIME_LICENSE_SHA256"
    ;;
esac

# Parse shell quoting and validate provenance without assert: optimized Python
# must enforce exactly the same checks as normal Python.
"$ISOLATED_PYTHON" -I - \
  "$BUILD_INFO" "${PAYLOAD_DIR}/configure.txt" "${FFMPEG_STATIC_ROOT}/sources.env" \
  "$TARGET" "$ARTIFACT_LICENSE" "$SCRIPT_DIR" <<'PY'
import datetime
import hashlib
import json
import pathlib
import re
import shlex
import sys

build_path = pathlib.Path(sys.argv[1])
configure_path = pathlib.Path(sys.argv[2])
sources_path = pathlib.Path(sys.argv[3])
target = sys.argv[4]
artifact_license = sys.argv[5]
sys.path.insert(0, sys.argv[6])
import pipeline_lib


def fail(message: str) -> None:
    raise SystemExit(message)


try:
    data = json.loads(build_path.read_text(encoding="utf-8"))
except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
    fail(f"invalid build info: {error}")
if not isinstance(data, dict):
    fail("build info must be an object")
expected_top_level = {
    "schemaVersion", "target", "platform", "arch", "license", "minimumOs",
    "compiler", "toolchain", "tools", "hardening", "configure", "sources",
    "dependencies",
}
if set(data) != expected_top_level:
    fail("build info has an unexpected top-level schema")

sources: dict[str, str] = {}
for raw in sources_path.read_text(encoding="utf-8").splitlines():
    line = raw.strip()
    if not line or line.startswith("#"):
        continue
    if "=" not in line:
        fail("invalid sources.env record")
    key, value = line.split("=", 1)
    if not re.fullmatch(r"[A-Z][A-Z0-9_]*", key) or not value:
        fail("unsafe sources.env record")
    sources[key] = value

target_contract = pipeline_lib.require_target(target)
platform = target_contract["platform"]
arch = target_contract["arch"]
minimum_os = pipeline_lib.minimum_os(target, sources)
if data.get("schemaVersion") != 1:
    fail("unexpected build info schema")
if (data.get("target"), data.get("platform"), data.get("arch")) != (target, platform, arch):
    fail("build info target tuple is inconsistent")
if data.get("license") != artifact_license:
    fail("unexpected license profile")
if data.get("minimumOs") != minimum_os:
    fail("unexpected minimum OS contract")

try:
    configure_text = configure_path.read_text(encoding="utf-8")
except (OSError, UnicodeDecodeError) as error:
    fail(f"invalid configure record: {error}")
try:
    tokens = shlex.split(configure_text.replace("\\\r\n", "").replace("\\\n", ""), posix=True)
except ValueError as error:
    fail(f"invalid configure quoting: {error}")
if not tokens or tokens[0] != "./configure":
    fail("configure record must start with ./configure")
arguments = tokens[1:]
if data.get("configure") != arguments:
    fail("build info and configure.txt arguments differ")
required_flags = {
    "--prefix=/usr/local",
    "--datadir=/usr/local/share/ffmpeg",
    "--disable-shared",
    "--enable-static",
    "--disable-autodetect",
    "--enable-gpl",
    "--enable-libx264",
    "--enable-libmp3lame",
}
missing_flags = sorted(required_flags - set(arguments))
if missing_flags:
    fail(f"configure record is missing exact flags: {missing_flags}")
for argument in arguments:
    option = argument.split("=", 1)[0]
    if option in {"--enable-nonfree", "--enable-version3", "--disable-gpl"}:
        fail(f"forbidden license option: {argument}")
    if re.search(r"(?:/home/|/Users/|/private/var/|/tmp/|[A-Za-z]:\\\\)", argument):
        fail(f"host path leaked into configure record: {argument}")

expected_sources = {
    "ffmpeg": {
        "version": sources["FFMPEG_VERSION"],
        "url": sources["FFMPEG_URL"],
        "sha256": sources["FFMPEG_SHA256"],
    },
    "x264": {
        "revision": sources["X264_REVISION"],
        "url": sources["X264_URL"],
        "sha256": sources["X264_SHA256"],
    },
    "lame": {
        "version": sources["LAME_VERSION"],
        "url": sources["LAME_URL"],
        "sha256": sources["LAME_SHA256"],
    },
    "musl": {
        "version": sources["MUSL_VERSION"],
        "url": sources["MUSL_URL"],
        "sha256": sources["MUSL_SHA256"],
    },
    "nasm": {
        "version": sources["NASM_VERSION"],
        "url": sources["NASM_URL"],
        "sha256": sources["NASM_SHA256"],
    },
    "fortifyHeaders": {
        "version": sources["FORTIFY_HEADERS_VERSION"],
        "revision": sources["FORTIFY_HEADERS_REVISION"],
        "url": sources["FORTIFY_HEADERS_URL"],
        "sha256": sources["FORTIFY_HEADERS_SHA256"],
    },
    "llvmMingwRecipe": {
        "revision": sources["LLVM_MINGW_RECIPE_REVISION"],
        "url": sources["LLVM_MINGW_RECIPE_URL"],
        "sha256": sources["LLVM_MINGW_RECIPE_SHA256"],
    },
    "llvmCompilerRt": {
        "version": sources["LLVM_RUNTIME_VERSION"],
        "revision": sources["LLVM_RUNTIME_REVISION"],
        "url": sources["LLVM_RUNTIME_URL"],
        "sha256": sources["LLVM_RUNTIME_SHA256"],
    },
    "mingwW64Runtime": {
        "version": sources["MINGW_W64_VERSION"],
        "revision": sources["MINGW_W64_REVISION"],
        "url": sources["MINGW_W64_URL"],
        "sha256": sources["MINGW_W64_SHA256"],
    },
}
if data.get("sources") != expected_sources:
    fail("build source provenance does not match the lock")

expected_dependency_names = {
    "darwin": set(),
    "linux": {"musl", "gcc-runtime", "fortify-headers"},
    "win32": {"llvm-compiler-rt", "mingw-w64-runtime"},
}[platform]
dependencies = data.get("dependencies")
if not isinstance(dependencies, list):
    fail("dependencies must be an array")
dependency_names: set[str] = set()
for item in dependencies:
    if not isinstance(item, dict) or set(item) != {"name", "version", "license", "relationship"}:
        fail("invalid dependency record")
    if not all(isinstance(value, str) and value for value in item.values()):
        fail("empty runtime dependency field")
    expected_relationship = "header-inline" if item["name"] == "fortify-headers" else "static-link"
    if item["relationship"] != expected_relationship:
        fail("dependency relationship is incorrect")
    dependency_names.add(item["name"])
    expected = {
        "musl": (sources["MUSL_VERSION"], "MIT AND SunPro"),
        "gcc-runtime": (None, "GPL-3.0-or-later WITH GCC-exception-3.1"),
        "fortify-headers": (sources["FORTIFY_HEADERS_REVISION"], "0BSD"),
        "llvm-compiler-rt": (sources["LLVM_RUNTIME_VERSION"], "Apache-2.0 WITH LLVM-exception"),
        "mingw-w64-runtime": (sources["MINGW_W64_VERSION"], "LicenseRef-MinGW-w64-runtime"),
    }.get(item["name"])
    if expected is None or item["license"] != expected[1]:
        fail(f"unexpected dependency: {item['name']}")
    if expected[0] is not None and item["version"] != expected[0]:
        fail(f"runtime version is not locked: {item['name']}")
if dependency_names != expected_dependency_names:
    fail("dependency set is incomplete or contains extras")

compiler = data.get("compiler")
if not isinstance(compiler, dict) or set(compiler) != {"command", "version"}:
    fail("invalid compiler provenance")
if not re.fullmatch(r"[A-Za-z0-9_.+-]+", compiler.get("command", "")):
    fail("compiler provenance contains a path or unsafe command")
if not isinstance(compiler.get("version"), str) or not compiler["version"]:
    fail("compiler version is missing")
expected_compiler = {
    "darwin": "clang",
    "linux": "musl-gcc",
    "win32": f"{'aarch64' if arch == 'arm64' else 'x86_64'}-w64-mingw32-clang",
}[platform]
if compiler["command"] != expected_compiler:
    fail("unexpected compiler driver")

tools = data.get("tools")
if not isinstance(tools, dict) or set(tools) != {
    "linker", "binutils", "nasm", "pkgConfig", "make", "python", "tar",
    "macosSdkVersion",
}:
    fail("tool provenance is missing")
for name in ("linker", "pkgConfig", "make", "python", "tar"):
    record = tools.get(name)
    if not isinstance(record, dict) or not record.get("command") or not record.get("version"):
        fail(f"incomplete {name} provenance")
    if "/" in record["command"] or "\\" in record["command"]:
        fail(f"absolute {name} command provenance is forbidden")
binutils = tools.get("binutils")
if not isinstance(binutils, dict) or not binutils.get("version"):
    fail("binutils provenance is missing")
for key in ("ar", "ranlib", "strip", "nm", "strings"):
    if not re.fullmatch(r"[A-Za-z0-9_.+-]+", str(binutils.get(key, ""))):
        fail(f"unsafe binutils command: {key}")
if arch == "x64":
    nasm = tools.get("nasm")
    if not isinstance(nasm, dict) or set(nasm) != {
        "binarySha256", "command", "sourceSha256", "sourceUrl",
        "sourceVersion", "version",
    }:
        fail("x64 NASM provenance is missing or malformed")
    moment = datetime.datetime.fromtimestamp(
        int(sources["SOURCE_DATE_EPOCH"]), tz=datetime.timezone.utc
    )
    months = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
    expected_version = (
        f"NASM version {sources['NASM_VERSION']} compiled on "
        f"{months[moment.month - 1]} {moment.day:2d} {moment.year}"
    )
    if nasm != {
        "binarySha256": nasm["binarySha256"],
        "command": "nasm",
        "sourceSha256": sources["NASM_SHA256"],
        "sourceUrl": sources["NASM_URL"],
        "sourceVersion": sources["NASM_VERSION"],
        "version": expected_version,
    }:
        fail("x64 NASM provenance does not match the source lock")
    if not re.fullmatch(r"[0-9a-f]{64}", nasm["binarySha256"]):
        fail("x64 NASM executable hash is invalid")
    nasm_binary = build_path.parent / "work" / "nasm" / "bin" / "nasm"
    if not nasm_binary.is_file() or nasm_binary.is_symlink():
        fail("source-built NASM executable is missing during verification")
    if hashlib.sha256(nasm_binary.read_bytes()).hexdigest() != nasm["binarySha256"]:
        fail("source-built NASM executable does not match BUILD-INFO")
elif tools.get("nasm") is not None:
    fail("NASM must be null when it is not used")

toolchain = data.get("toolchain")
if not isinstance(toolchain, dict) or not toolchain.get("name") or not toolchain.get("version"):
    fail("toolchain provenance is missing")
if platform == "linux" and toolchain != {
    "name": "source-built-musl",
    "version": sources["MUSL_VERSION"],
    "url": sources["MUSL_URL"],
    "sha256": sources["MUSL_SHA256"],
}:
    fail("Linux toolchain is not the source-authenticated musl toolchain")
if platform == "win32" and toolchain != {
    "name": "llvm-mingw-ucrt",
    "version": sources["LLVM_MINGW_VERSION"],
    "url": sources["LLVM_MINGW_URL"],
    "sha256": sources["LLVM_MINGW_SHA256"],
}:
    fail("Windows toolchain does not match the lock")

hardening = data.get("hardening")
if not isinstance(hardening, dict) or set(hardening) != {"fortify", "linkProvenance"}:
    fail("hardening provenance is missing")
if platform == "linux":
    expected_prefix = f"{sources['FORTIFY_HEADERS_VERSION']}@{sources['FORTIFY_HEADERS_REVISION']}"
    if hardening["fortify"] != expected_prefix + ":runtime-trap-verified":
        fail("fortify-headers runtime proof is missing")
    if hardening["linkProvenance"] != "validated-private-musl-link-maps":
        fail("private musl linker-map proof is missing")
    cflag = next((item for item in arguments if item.startswith("--extra-cflags=")), "")
    ldflag = next((item for item in arguments if item.startswith("--extra-ldflags=")), "")
    for flag in ("-I../src/fortify-headers/include", "-D_FORTIFY_SOURCE=3", "-fstack-protector-strong"):
        if flag not in cflag:
            fail(f"Linux hardening flag is missing: {flag}")
    if "-static-pie" not in ldflag:
        fail("Linux static PIE link flag is missing")
    if "-Wl,-z,stack-size=2097152" not in ldflag:
        fail("Linux musl thread-stack size flag is missing")
elif platform == "win32":
    cflag = next((item for item in arguments if item.startswith("--extra-cflags=")), "")
    ldflag = next((item for item in arguments if item.startswith("--extra-ldflags=")), "")
    if "-mguard=cf" not in cflag or "-mguard=cf" not in ldflag:
        fail("Windows CFG compiler/linker flags are missing")
else:
    if hardening["fortify"] != "system-headers-level-2":
        fail("macOS system-header fortify provenance is missing")
    if hardening["linkProvenance"] != "platform-system":
        fail("macOS link provenance is unexpected")
    if not {"--enable-videotoolbox", "--enable-audiotoolbox"}.issubset(arguments):
        fail("macOS native media frameworks were not enabled")
PY

verify_file_architecture() {
  local path=$1 description
  description=$(file -b "$path")
  case "$TARGET" in
    darwin-arm64)
      [[ "$description" == *Mach-O*64-bit*arm64* ]] \
        || die "unexpected darwin-arm64 file type: ${description}"
      ;;
    darwin-x64)
      [[ "$description" == *Mach-O*64-bit*x86_64* ]] \
        || die "unexpected darwin-x64 file type: ${description}"
      ;;
    linux-arm64)
      [[ "$description" == *ELF*64-bit*ARM*aarch64* || "$description" == *ELF*64-bit*ARM64* ]] \
        || die "unexpected linux-arm64 file type: ${description}"
      [[ "$description" == *static-pie* || "$description" == *static*PIE* ]] \
        || die "Linux binary is not static PIE: ${description}"
      ;;
    linux-x64)
      [[ "$description" == *ELF*64-bit*x86-64* ]] \
        || die "unexpected linux-x64 file type: ${description}"
      [[ "$description" == *static-pie* || "$description" == *static*PIE* ]] \
        || die "Linux binary is not static PIE: ${description}"
      ;;
    win32-arm64)
      [[ "$description" == *PE32+*Aarch64* || "$description" == *PE32+*ARM64* ]] \
        || die "unexpected win32-arm64 file type: ${description}"
      ;;
    win32-x64)
      [[ "$description" == *PE32+*x86-64* ]] \
        || die "unexpected win32-x64 file type: ${description}"
      ;;
  esac
}

verify_file_architecture "$BINARY_PATH"
verify_file_architecture "$PROBE_PATH"

run_native() {
  env -i HOME="$VERIFY_TMP" TMPDIR="$VERIFY_TMP" PATH="$SYSTEM_PATH" \
    LC_ALL=C TZ=UTC "$@"
}

require_listing_token() {
  local listing=$1
  local token=$2
  local kind=$3
  grep -Eq "^[[:space:]]*[^[:space:]]*[[:space:]]+${token}([[:space:]]|$)" <<<"$listing" \
    || die "required Motrix ${kind} is unavailable: ${token}"
}

verify_native_features() {
  local version_output probe_output encoders_output license_output video_codec audio_codec
  local muxers_output bsfs_output filters_output muxer encoder
  version_output=$(run_native "$BINARY_PATH" -version 2>&1)
  probe_output=$(run_native "$PROBE_PATH" -version 2>&1)
  encoders_output=$(run_native "$BINARY_PATH" -hide_banner -encoders 2>&1)
  license_output=$(run_native "$BINARY_PATH" -hide_banner -L 2>&1)
  grep -Fq "ffmpeg version ${FFMPEG_VERSION}" <<<"$version_output" \
    || die "ffmpeg version is not ${FFMPEG_VERSION}"
  grep -Fq "ffprobe version ${FFMPEG_VERSION}" <<<"$probe_output" \
    || die "ffprobe version is not ${FFMPEG_VERSION}"
  grep -Eq '[[:space:]]libx264([[:space:]]|$)' <<<"$encoders_output" \
    || die 'libx264 encoder is missing'
  grep -Eq '[[:space:]]libmp3lame([[:space:]]|$)' <<<"$encoders_output" \
    || die 'libmp3lame encoder is missing'
  grep -Fq 'GNU General Public License' <<<"$license_output" \
    || die 'binary does not report the GNU GPL'
  grep -Fq 'version 2' <<<"$license_output" \
    || die 'binary does not report GPL version 2-or-later terms'

  muxers_output=$(run_native "$BINARY_PATH" -hide_banner -muxers 2>&1)
  for muxer in mp4 ipod mov matroska webm mpegts flv adts mp3 opus; do
    require_listing_token "$muxers_output" "$muxer" muxer
  done
  bsfs_output=$(run_native "$BINARY_PATH" -hide_banner -bsfs 2>&1)
  grep -Eq '^[[:space:]]*aac_adtstoasc[[:space:]]*$' <<<"$bsfs_output" \
    || die 'required Motrix bitstream filter is unavailable: aac_adtstoasc'
  for encoder in libx264 aac libmp3lame flac pcm_s16le mjpeg; do
    require_listing_token "$encoders_output" "$encoder" encoder
  done
  filters_output=$(run_native "$BINARY_PATH" -hide_banner -filters 2>&1)
  require_listing_token "$filters_output" scale filter

  run_native "$BINARY_PATH" -nostdin -v error \
    -f lavfi -i 'testsrc=size=64x64:rate=1' -frames:v 1 \
    -c:v libx264 -pix_fmt yuv420p -f matroska "${VERIFY_TMP}/h264.mkv"
  run_native "$BINARY_PATH" -nostdin -v error \
    -f lavfi -i 'sine=frequency=1000:duration=0.1' \
    -c:a libmp3lame -f mp3 "${VERIFY_TMP}/audio.mp3"
  video_codec=$(run_native "$PROBE_PATH" -v error -select_streams v:0 \
    -show_entries stream=codec_name -of default=noprint_wrappers=1:nokey=1 \
    "${VERIFY_TMP}/h264.mkv")
  audio_codec=$(run_native "$PROBE_PATH" -v error -select_streams a:0 \
    -show_entries stream=codec_name -of default=noprint_wrappers=1:nokey=1 \
    "${VERIFY_TMP}/audio.mp3")
  [[ "$video_codec" == h264 ]] || die "libx264 smoke output is invalid: ${video_codec}"
  [[ "$audio_codec" == mp3 ]] || die "libmp3lame smoke output is invalid: ${audio_codec}"
}

verify_darwin_linkage() {
  local path=$1 minimum_version actual_dependencies expected_dependencies headers uuid_count uuid
  require_command otool lipo
  [[ "$(lipo -archs "$path")" == "${TARGET_ARCH/x64/x86_64}" ]] \
    || die "macOS binary is not a single ${TARGET_ARCH} slice: ${path}"
  minimum_version=$(otool -l "$path" | awk '
    $1 == "cmd" {
      build_version = ($2 == "LC_BUILD_VERSION")
      legacy_version = ($2 == "LC_VERSION_MIN_MACOSX")
      next
    }
    build_version && $1 == "minos" { print $2; exit }
    legacy_version && $1 == "version" { print $2; exit }
  ')
  [[ "$minimum_version" == "$MACOS_MIN_VERSION" ]] \
    || die "unexpected macOS minimum version in ${path}: ${minimum_version:-missing}"
  uuid_count=$(otool -l "$path" | awk '$1 == "cmd" && $2 == "LC_UUID" { count++ } END { print count + 0 }')
  [[ "$uuid_count" == 1 ]] \
    || die "Mach-O must contain exactly one LC_UUID command: ${path}"
  uuid=$(otool -l "$path" | awk '
    $1 == "cmd" { in_uuid = ($2 == "LC_UUID"); next }
    in_uuid && $1 == "uuid" { print $2; exit }
  ')
  [[ "$uuid" =~ ^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$ ]] \
    || die "Mach-O LC_UUID value is invalid: ${path}"
  actual_dependencies=$(otool -L "$path" | awk 'NR > 1 {print $1}' | LC_ALL=C sort)
  expected_dependencies=$(printf '%s\n' \
    /System/Library/Frameworks/AudioToolbox.framework/Versions/A/AudioToolbox \
    /System/Library/Frameworks/CoreAudio.framework/Versions/A/CoreAudio \
    /System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation \
    /System/Library/Frameworks/CoreMedia.framework/Versions/A/CoreMedia \
    /System/Library/Frameworks/CoreServices.framework/Versions/A/CoreServices \
    /System/Library/Frameworks/CoreVideo.framework/Versions/A/CoreVideo \
    /System/Library/Frameworks/VideoToolbox.framework/Versions/A/VideoToolbox \
    /usr/lib/libSystem.B.dylib | LC_ALL=C sort)
  [[ "$actual_dependencies" == "$expected_dependencies" ]] \
    || die "macOS dylib/framework set differs from the exact allowlist: ${path}"
  headers=$(otool -hv "$path")
  grep -Eq '([[:space:]]|^)PIE([[:space:]]|$)' <<<"$headers" \
    || die "Mach-O PIE flag is missing: ${path}"
  if otool -l "$path" | awk '$1 == "initprot" && ($2 == "0x00000007" || $2 == "rwx") {bad=1} END {exit !bad}'; then
    die "Mach-O segment is writable and executable: ${path}"
  fi
}

verify_linux_stack_protector() {
  local path=$1 disassembly_file=$2 program map_path unstripped_path expected_runtime fail_address
  program=$(basename -- "$path")
  map_path="${BUILD_ROOT}/work/link-maps/${program}.map"
  unstripped_path="${BUILD_ROOT}/work/ffmpeg-build/${program}_g"
  expected_runtime="${BUILD_ROOT}/work/musl/lib/libc.a(__stack_chk_fail.lo)"
  [[ -f "$map_path" && ! -L "$map_path" && -s "$map_path" ]] \
    || die "missing regular Linux linker map for stack-protector proof: ${map_path}"
  [[ -f "$unstripped_path" && ! -L "$unstripped_path" && -s "$unstripped_path" ]] \
    || die "missing regular unstripped Linux binary for stack-protector proof: ${unstripped_path}"
  grep -Fq -- "$expected_runtime" "$map_path" \
    || die "the pinned musl stack-protector runtime was not linked: ${path}"

  fail_address=$(
    "$ISOLATED_PYTHON" -I - "$map_path" "$unstripped_path" <<'PY'
import pathlib
import re
import subprocess
import sys

map_path = pathlib.Path(sys.argv[1])
unstripped = pathlib.Path(sys.argv[2])
addresses: set[int] = set()
pattern = re.compile(r"^\s*(0x[0-9a-fA-F]+)\s+__stack_chk_fail\s*$")
with map_path.open("r", encoding="utf-8", errors="strict") as stream:
    for line in stream:
        match = pattern.match(line)
        if match is not None:
            addresses.add(int(match.group(1), 16))
if len(addresses) != 1:
    raise SystemExit("linker map does not contain one unambiguous __stack_chk_fail definition")
address = next(iter(addresses))

result = subprocess.run(
    ["/usr/bin/readelf", "-W", "-s", str(unstripped)],
    check=True,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    encoding="utf-8",
    errors="strict",
    env={"LC_ALL": "C", "PATH": "/usr/bin:/bin"},
)
symbol_addresses: set[int] = set()
for line in result.stdout.splitlines():
    fields = line.split()
    if len(fields) >= 8 and fields[-1] == "__stack_chk_fail" and fields[6] != "UND":
        try:
            symbol_addresses.add(int(fields[1], 16))
        except ValueError as error:
            raise SystemExit("invalid __stack_chk_fail symbol address") from error
if symbol_addresses != {address}:
    raise SystemExit("unstripped binary and linker map disagree on __stack_chk_fail")
print(f"{address:x}")
PY
  ) || die "could not bind the stack-protector runtime to the unstripped binary: ${path}"

  "$ISOLATED_PYTHON" -I - \
    "$disassembly_file" "$fail_address" "$TARGET_ARCH" <<'PY' \
    || die "final binary lacks fail-closed stack-protector machine-code evidence: ${path}"
import pathlib
import re
import sys

disassembly = pathlib.Path(sys.argv[1])
expected_address = int(sys.argv[2], 16)
architecture = sys.argv[3]
direct_fail_calls = 0
x64_guard_loads = 0
x64_guard_checks = 0
call_pattern = re.compile(r"\b(?:callq?|bl)\s+(?:0x)?([0-9a-fA-F]+)(?:\s|$|\s*<)")
load_pattern = re.compile(r"\bmov[a-z]*\b.*%fs:0x28")
check_pattern = re.compile(r"\b(?:sub|xor)[a-z]*\b.*%fs:0x28")

with disassembly.open("r", encoding="utf-8", errors="strict") as stream:
    for line in stream:
        match = call_pattern.search(line)
        if match is not None and int(match.group(1), 16) == expected_address:
            direct_fail_calls += 1
        if architecture == "x64" and "%fs:0x28" in line:
            if load_pattern.search(line) is not None:
                x64_guard_loads += 1
            if check_pattern.search(line) is not None:
                x64_guard_checks += 1

# Requiring multiple independent paths prevents a single synthetic reference
# from masquerading as compiler-inserted coverage.  Calls are tied above to
# the exact __stack_chk_fail definition extracted from the pinned musl libc.
if direct_fail_calls < 5:
    raise SystemExit("too few direct calls to the pinned stack-protector failure path")
if architecture == "x64" and (x64_guard_loads < 5 or x64_guard_checks < 5):
    raise SystemExit("too few x86-64 TLS canary load/check instruction pairs")
PY
}

verify_linux_linkage() {
  local path=$1 elf_type program_headers dynamic binary_strings notes disassembly_file
  require_command readelf objdump
  elf_type=$(readelf -h "$path" | awk -F: '/^[[:space:]]*Type:/ {sub(/^[[:space:]]+/, "", $2); print $2}')
  [[ "$elf_type" == DYN* ]] || die "Linux static PIE must be ET_DYN: ${path} (${elf_type})"
  dynamic=$(readelf -W -d "$path" 2>&1 || true)
  grep -q '(NEEDED)' <<<"$dynamic" && die "DT_NEEDED found in static PIE: ${path}"
  grep -Eq '\((RPATH|RUNPATH)\)' <<<"$dynamic" && die "runtime search path found: ${path}"
  program_headers=$(readelf -W -l "$path")
  grep -q 'INTERP' <<<"$program_headers" && die "PT_INTERP found in static PIE: ${path}"
  grep -q 'GNU_RELRO' <<<"$program_headers" || die "GNU_RELRO is missing: ${path}"
  grep -q 'GNU_STACK' <<<"$program_headers" || die "GNU_STACK is missing: ${path}"
  verify_linux_gnu_stack_header "$program_headers" \
    || die "GNU_STACK must be unique, RW-only, and exactly 2 MiB: ${path}"
  if awk '
    $1 == "LOAD" || $1 == "GNU_STACK" {
      writable = executable = 0
      for (i = 7; i < NF; i++) {
        if ($i ~ /W/) writable = 1
        if ($i ~ /E/) executable = 1
      }
      if (writable && executable) bad = 1
    }
    END { exit !bad }
  ' <<<"$program_headers"; then
    die "writable/executable ELF segment or stack found: ${path}"
  fi
  binary_strings=$(strings "$path")
  if grep -Eq 'GLIBC_[0-9]|/lib(64)?/ld-linux|ld-musl-' <<<"$binary_strings"; then
    die "dynamic libc loader/version evidence found in static PIE: ${path}"
  fi
  disassembly_file="${VERIFY_TMP}/$(basename -- "$path").disassembly.txt"
  objdump -d "$path" >"$disassembly_file"
  verify_linux_stack_protector "$path" "$disassembly_file"
  if [[ "$TARGET" == linux-x64 ]]; then
    grep -q 'endbr64' "$disassembly_file" || die "x86 CET instructions are absent: ${path}"
  else
    grep -Eq '(^|[[:space:]])(bti|paciasp)([[:space:]]|$)' "$disassembly_file" \
      || die "AArch64 branch-protection instructions are absent: ${path}"
  fi
  notes=$(readelf -n "$path")
  grep -q 'Build ID:' <<<"$notes" || die "ELF build ID is missing: ${path}"
}

find_llvm_tool() {
  local tool_name=$1 bundled resolved
  bundled="${BUILD_ROOT}/work/toolchain/bin/${tool_name}"
  [[ -f "$bundled" && -x "$bundled" ]] \
    || die "pinned LLVM inspection tool is missing: ${bundled}"
  resolved=$("$ISOLATED_PYTHON" -I - "$bundled" "${BUILD_ROOT}/work/toolchain" <<'PY'
import pathlib
import sys

tool = pathlib.Path(sys.argv[1]).resolve(strict=True)
root = pathlib.Path(sys.argv[2]).resolve(strict=True)
if tool != root and root not in tool.parents:
    raise SystemExit("inspection tool symlink escapes the pinned toolchain")
print(tool)
PY
) || die "pinned LLVM inspection tool is unsafe: ${bundled}"
  [[ -f "$resolved" && -x "$resolved" ]] \
    || die "resolved LLVM inspection tool is not executable: ${resolved}"
  printf '%s\n' "$resolved"
}

verify_windows_linkage() {
  local path=$1 readobj_tool headers sections sections_file imports_text imports dependency expected_machine
  readobj_tool=$(find_llvm_tool llvm-readobj)
  headers=$($readobj_tool --file-headers --coff-load-config "$path")
  if [[ "$TARGET" == win32-arm64 ]]; then
    expected_machine='IMAGE_FILE_MACHINE_ARM64'
  else
    expected_machine='IMAGE_FILE_MACHINE_AMD64'
  fi
  grep -Fq "Machine: ${expected_machine}" <<<"$headers" \
    || die "PE machine is incorrect: ${path}"
  for field in \
    'MajorOperatingSystemVersion: 10' \
    'MinorOperatingSystemVersion: 0' \
    'MajorSubsystemVersion: 6' \
    'MinorSubsystemVersion: 2' \
    'DYNAMIC_BASE' 'HIGH_ENTROPY_VA' 'NX_COMPAT' 'GUARD_CF' \
    'CF_INSTRUMENTED' 'CF_FUNCTION_TABLE_PRESENT'; do
    grep -Fq "$field" <<<"$headers" || die "PE hardening field is missing (${field}): ${path}"
  done
  grep -Eq 'GuardCFFunctionCount: [1-9][0-9]*' <<<"$headers" \
    || die "PE CFG function table is empty: ${path}"
  grep -Fq 'IMAGE_FILE_RELOCS_STRIPPED' <<<"$headers" \
    && die "PE relocations were stripped, disabling ASLR: ${path}"

  sections=$($readobj_tool --sections "$path")
  sections_file="${VERIFY_TMP}/$(basename -- "$path").sections.txt"
  printf '%s\n' "$sections" >"$sections_file"
  "$ISOLATED_PYTHON" -I - "$path" "$sections_file" <<'PY'
import sys

path = sys.argv[1]
with open(sys.argv[2], encoding="utf-8") as handle:
    text = handle.read()
for section in text.split("Section {")[1:]:
    block = section.split("}\n", 1)[0]
    if "IMAGE_SCN_MEM_WRITE" in block and "IMAGE_SCN_MEM_EXECUTE" in block:
        raise SystemExit(f"writable/executable PE section found: {path}")
PY

  imports_text=$($readobj_tool --coff-imports "$path")
  imports=$(printf '%s\n' "$imports_text" \
    | "$ISOLATED_PYTHON" -I "$SCRIPT_DIR/parse_pe_imports.py") \
    || die "could not parse the complete PE import table: ${path}"
  while IFS= read -r dependency; do
    case "$dependency" in
      api-ms-win-crt-conio-l1-1-0.dll | api-ms-win-crt-convert-l1-1-0.dll | \
      api-ms-win-crt-environment-l1-1-0.dll | api-ms-win-crt-filesystem-l1-1-0.dll | \
      api-ms-win-crt-heap-l1-1-0.dll | api-ms-win-crt-locale-l1-1-0.dll | \
      api-ms-win-crt-math-l1-1-0.dll | api-ms-win-crt-multibyte-l1-1-0.dll | \
      api-ms-win-crt-private-l1-1-0.dll | api-ms-win-crt-process-l1-1-0.dll | \
      api-ms-win-crt-runtime-l1-1-0.dll | api-ms-win-crt-stdio-l1-1-0.dll | \
      api-ms-win-crt-string-l1-1-0.dll | api-ms-win-crt-time-l1-1-0.dll | \
      api-ms-win-crt-utility-l1-1-0.dll | \
      advapi32.dll | avicap32.dll | bcrypt.dll | cfgmgr32.dll | crypt32.dll | gdi32.dll | \
      kernel32.dll | mf.dll | mfplat.dll | mfreadwrite.dll | mfuuid.dll | \
      ole32.dll | oleaut32.dll | secur32.dll | shell32.dll | shlwapi.dll | user32.dll | \
      ucrtbase.dll | version.dll | vfw32.dll | winmm.dll | ws2_32.dll) ;;
      *) die "DLL import is outside the exact system allowlist (${dependency}): ${path}" ;;
    esac
  done <<<"$imports"
}

verify_windows_features() {
  local strings_tool path output
  strings_tool=$(find_llvm_tool llvm-strings)
  for path in "$BINARY_PATH" "$PROBE_PATH"; do
    output=$($strings_tool "$path")
    for flag in --enable-gpl --enable-libx264 --enable-libmp3lame -mguard=cf; do
      grep -Fq -- "$flag" <<<"$output" || die "embedded build feature is missing (${flag}): ${path}"
    done
    grep -Eq -- '--enable-(nonfree|version3)' <<<"$output" \
      && die "forbidden license configuration embedded in ${path}"
  done
  return 0
}

case "$TARGET_PLATFORM" in
  darwin)
    verify_darwin_linkage "$BINARY_PATH"
    verify_darwin_linkage "$PROBE_PATH"
    verify_native_features
    ;;
  linux)
    verify_linux_linkage "$BINARY_PATH"
    verify_linux_linkage "$PROBE_PATH"
    verify_native_features
    ;;
  win32)
    if (( ! FINAL_BINARY_MODE )); then
      for program in ffmpeg ffprobe; do
        verify_windows_cephes_absence \
          "${BUILD_ROOT}/work/link-maps/${program}.link-trace.txt" \
          "${BUILD_ROOT}/work/link-maps/${program}.map"
      done
    fi
    verify_windows_linkage "$BINARY_PATH"
    verify_windows_linkage "$PROBE_PATH"
    verify_windows_features
    ;;
esac

for path in "$BINARY_PATH" "$PROBE_PATH"; do
  output=$(strings "$path")
  grep -Fq -- "$FFMPEG_STATIC_ROOT" <<<"$output" \
    && die "absolute checkout path is embedded in ${path}"
done

log "verified ${TARGET}: ${BINARY_NAME} $(sha256_file "$BINARY_PATH")"
log "verified ${TARGET}: ${PROBE_NAME} $(sha256_file "$PROBE_PATH")"
