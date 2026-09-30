#!/usr/bin/env python3
"""Shared, dependency-free helpers for the FFmpeg release pipeline."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import re
import shlex
import stat
import urllib.parse
from pathlib import Path
from typing import Any, Optional


ROOT = Path(__file__).resolve().parents[1]
MAX_LICENSE_FILE_BYTES = 8 * 1024 * 1024
MAX_NOTARIZATION_JSON_BYTES = 8 * 1024 * 1024
MAX_SOURCES_FILE_BYTES = 64 * 1024
BASE_ARTIFACT_LICENSE = (
    "GPL-2.0-or-later AND LGPL-2.1-or-later AND IJG AND ISC AND MIT AND "
    "BSD-1-Clause AND BSD-2-Clause AND BSD-3-Clause AND Zlib AND BSL-1.0"
)
PLATFORM_ARTIFACT_LICENSES = {
    "darwin": BASE_ARTIFACT_LICENSE,
    "linux": (
        f"{BASE_ARTIFACT_LICENSE} AND 0BSD AND SunPro AND "
        "(GPL-3.0-or-later WITH GCC-exception-3.1)"
    ),
    "win32": (
        f"{BASE_ARTIFACT_LICENSE} AND "
        "(Apache-2.0 WITH LLVM-exception) AND LicenseRef-MinGW-w64-runtime"
    ),
}
PACKAGE_README = (
    "Motrix static FFmpeg build.\n"
    "\n"
    "This package is installed separately by the user; it is not bundled\n"
    "inside the Motrix application. The ffmpeg executable is the runtime\n"
    "consumed by Motrix, while ffprobe is included for diagnostics. Exact\n"
    "source inputs, flags, checksums, and license terms are recorded here.\n"
    "The FFmpeg, x264, and LAME corresponding-source archives, additional\n"
    "redistributable source inputs, exact build scripts, and a lock of every\n"
    "input URL/revision/hash are published beside this archive in the same\n"
    "motrixapp/ffmpeg-static GitHub Release. See LICENSES.json and LICENSES/\n"
    "for every notice, and the Release manifest/SBOM for source provenance.\n"
    "this software is based in part on the work of the Independent JPEG Group.\n"
).encode("utf-8")
TARGETS: dict[str, dict[str, str]] = {
    "darwin-arm64": {"platform": "darwin", "arch": "arm64", "extension": "zip"},
    "darwin-x64": {"platform": "darwin", "arch": "x64", "extension": "zip"},
    "linux-arm64": {"platform": "linux", "arch": "arm64", "extension": "tar.gz"},
    "linux-x64": {"platform": "linux", "arch": "x64", "extension": "tar.gz"},
    "win32-arm64": {"platform": "win32", "arch": "arm64", "extension": "zip"},
    "win32-x64": {"platform": "win32", "arch": "x64", "extension": "zip"},
}
STATIC_MINIMUM_OS: dict[str, tuple[str, str]] = {
    # AArch64 first entered the mainline Linux kernel in 3.7.  The older
    # musl baseline therefore applies only to the x86-64 Linux artifact.
    "linux-arm64": ("linux", "3.7.0"),
    "linux-x64": ("linux", "2.6.39"),
    "win32-arm64": ("windows", "10.0"),
    "win32-x64": ("windows", "10.0"),
}

COMMON_LICENSE_FILES: dict[str, tuple[str, str, str, str]] = {
    "FFmpeg-COPYING.GPLv2": (
        "FFmpeg", "GPL-2.0-only", "NOASSERTION", "FFMPEG_GPLV2_SHA256"
    ),
    "FFmpeg-COPYING.GPLv3": (
        "FFmpeg", "GPL-3.0-only", "NOASSERTION", "FFMPEG_GPLV3_SHA256"
    ),
    "FFmpeg-LICENSE.md": (
        "FFmpeg", "NOASSERTION", "NOASSERTION", "FFMPEG_LICENSE_SHA256"
    ),
    "FFmpeg-IJG-NOTICE.txt": (
        "FFmpeg IJG-derived code", "IJG", "IJG", "FFMPEG_IJG_NOTICE_SHA256"
    ),
    "LAME-COPYING": (
        "LAME", "LGPL-2.0-only", "LGPL-2.1-or-later", "LAME_COPYING_SHA256"
    ),
    "FFmpeg-COPYING.LGPLv2.1": (
        "FFmpeg/LAME LGPL-2.1-covered code",
        "LGPL-2.1-only",
        "LGPL-2.1-or-later",
        "FFMPEG_LGPLV21_SHA256",
    ),
    "LAME-LICENSE": (
        "LAME", "NOASSERTION", "LGPL-2.1-or-later", "LAME_LICENSE_SHA256"
    ),
    "THIRD-PARTY-NOTICES.txt": (
        "Locked upstream source-tree notices",
        "NOASSERTION",
        "NOASSERTION",
        "THIRD_PARTY_NOTICES_SHA256",
    ),
    "x264-COPYING": (
        "x264", "GPL-2.0-only", "GPL-2.0-or-later", "X264_LICENSE_SHA256"
    ),
}

PLATFORM_LICENSE_FILES: dict[str, dict[str, tuple[str, str, str, str]]] = {
    "darwin": {},
    "linux": {
        "fortify-headers-LICENSE": (
            "fortify-headers", "0BSD", "0BSD", "FORTIFY_HEADERS_LICENSE_SHA256"
        ),
        "musl-COPYRIGHT": (
            "musl",
            "NOASSERTION",
            "MIT AND SunPro",
            "MUSL_COPYRIGHT_SHA256",
        ),
        "GCC-RUNTIME-LIBRARY-EXCEPTION.txt": (
            "gcc-runtime",
            "GPL-3.0-or-later WITH GCC-exception-3.1",
            "GPL-3.0-or-later WITH GCC-exception-3.1",
            "GCC_RUNTIME_EXCEPTION_SHA256",
        ),
    },
    "win32": {
        "LLVM-LICENSE.TXT": (
            "llvm-compiler-rt",
            "Apache-2.0 WITH LLVM-exception",
            "Apache-2.0 WITH LLVM-exception",
            "LLVM_LICENSE_SHA256",
        ),
        "MinGW-w64-runtime-COPYING.txt": (
            "mingw-w64-runtime",
            "LicenseRef-MinGW-w64-runtime",
            "LicenseRef-MinGW-w64-runtime",
            "MINGW_RUNTIME_LICENSE_SHA256",
        ),
    },
}

X64_LICENSE_FILES: dict[str, tuple[str, str, str, str]] = {
    "x264-x86inc-ISC.txt": (
        "x264 x86 assembly helper",
        "ISC",
        "ISC",
        "X264_X86INC_ISC_SHA256",
    )
}

DEPENDENCIES: dict[str, dict[str, tuple[str, str]]] = {
    "linux": {
        "fortify-headers": ("0BSD", "header-inline"),
        "musl": ("MIT AND SunPro", "static-link"),
        "gcc-runtime": (
            "GPL-3.0-or-later WITH GCC-exception-3.1",
            "static-link",
        ),
    },
    "win32": {
        "llvm-compiler-rt": (
            "Apache-2.0 WITH LLVM-exception",
            "static-link",
        ),
        "mingw-w64-runtime": (
            "LicenseRef-MinGW-w64-runtime",
            "static-link",
        ),
    },
    "darwin": {},
}

REQUIRED_CONFIGURE_FLAGS = frozenset(
    {
        "--disable-autodetect",
        "--disable-shared",
        "--enable-static",
        "--enable-gpl",
        "--enable-libx264",
        "--enable-libmp3lame",
        "--enable-ffmpeg",
        "--enable-ffprobe",
    }
)
FORBIDDEN_CONFIGURE_FLAGS = frozenset(
    {
        "--disable-gpl",
        "--disable-libx264",
        "--disable-libmp3lame",
        "--enable-nonfree",
        "--enable-version3",
        "--enable-shared",
        "--disable-static",
        "--enable-autodetect",
        "--disable-ffmpeg",
        "--disable-ffprobe",
    }
)

ALLOWED_CONFIGURE_OPTIONS = frozenset(
    {
        "--prefix",
        "--datadir",
        "--disable-shared",
        "--enable-static",
        "--disable-autodetect",
        "--enable-gpl",
        "--enable-libx264",
        "--enable-libmp3lame",
        "--enable-ffmpeg",
        "--enable-ffprobe",
        "--disable-ffplay",
        "--disable-doc",
        "--disable-debug",
        "--enable-pic",
        "--enable-runtime-cpudetect",
        "--pkg-config-flags",
        "--pkg-config",
        "--cc",
        "--cxx",
        "--ar",
        "--ranlib",
        "--strip",
        "--nm",
        "--x86asmexe",
        "--arch",
        "--extra-cflags",
        "--extra-ldflags",
        "--extra-libs",
        "--target-os",
        "--host-cc",
        "--enable-videotoolbox",
        "--enable-audiotoolbox",
        "--enable-cross-compile",
        "--cross-prefix",
    }
)

SAFE_VALUE = re.compile(r"^[A-Za-z0-9._:/+@=-]+$")
LOWER_SHA256 = re.compile(r"^[0-9a-f]{64}$")
RFC3339_UTC = re.compile(
    r"^[0-9]{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])"
    r"T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z$"
)


def validate_codesign_hardened_runtime(display: str) -> None:
    """Require one unambiguous primary CodeDirectory with the runtime bit."""

    code_directories = [
        line for line in display.splitlines() if line.startswith("CodeDirectory ")
    ]
    if len(code_directories) != 1:
        raise ValueError("codesign output must contain exactly one CodeDirectory line")
    matches = list(
        re.finditer(
            r"(?:^| )flags=(0x[0-9A-Fa-f]+)\(([^()]*)\)(?= |$)",
            code_directories[0],
        )
    )
    if len(matches) != 1:
        raise ValueError("CodeDirectory must contain exactly one valid flags field")
    numeric_flags, raw_tokens = matches[0].groups()
    tokens = [token.strip() for token in raw_tokens.split(",")]
    if (
        not tokens
        or any(not re.fullmatch(r"[A-Za-z0-9_-]+", token) for token in tokens)
        or len(tokens) != len(set(tokens))
    ):
        raise ValueError("CodeDirectory flags contain invalid or duplicate tokens")
    if "runtime" not in tokens or int(numeric_flags, 16) & 0x10000 == 0:
        raise ValueError("CodeDirectory does not carry the hardened-runtime flag")


def validate_github_release_identity(
    value: object,
    *,
    repository: str,
    release_id: int,
    tag: str,
    target_commitish: str,
    title: str,
    body: str,
    state: str,
) -> dict[str, Any]:
    """Bind a draft or immutable Release to the trusted workflow identity."""

    if not isinstance(value, dict):
        raise ValueError("GitHub Release response must be an object")
    if type(release_id) is not int or release_id <= 0:
        raise ValueError("GitHub Release ID must be a positive integer")
    if state not in {"draft", "publishing", "published"}:
        raise ValueError("GitHub Release state expectation is invalid")
    api_url = f"https://api.github.com/repos/{repository}/releases/{release_id}"
    author = value.get("author")
    if (
        type(value.get("id")) is not int
        or value.get("id") != release_id
        or value.get("url") != api_url
        or value.get("assets_url") != f"{api_url}/assets"
        or value.get("upload_url")
        != f"https://uploads.github.com/repos/{repository}/releases/{release_id}/assets{{?name,label}}"
        or value.get("tag_name") != tag
        or value.get("target_commitish") != target_commitish
        or value.get("name") != title
        or value.get("body") != body
        or value.get("prerelease") is not False
        or value.get("discussion_url") not in (None, "")
        or not isinstance(author, dict)
        or author.get("login") != "github-actions[bot]"
        or author.get("type") != "Bot"
    ):
        raise ValueError("GitHub Release identity does not match the trusted workflow")
    if state == "published":
        if (
            value.get("draft") is not False
            or value.get("immutable") is not True
        ):
            raise ValueError("GitHub Release is not published and immutable")
        _require_timestamp(value.get("published_at"), "GitHub Release published_at")
    elif state == "publishing":
        if (
            value.get("draft") is not False
            or type(value.get("immutable")) is not bool
        ):
            raise ValueError("GitHub Release did not enter the published state")
        _require_timestamp(value.get("published_at"), "GitHub Release published_at")
    else:
        if (
            value.get("draft") is not True
            or value.get("immutable") is not False
            or value.get("published_at") not in (None, "")
        ):
            raise ValueError("GitHub Release is not an unpublished mutable draft")
    return value


def _read_bounded_regular_file(
    path: Path, context: str, maximum: int
) -> bytes:
    if maximum < 0:
        raise ValueError(f"{context} has an invalid size limit")
    try:
        before = path.lstat()
    except OSError as error:
        raise ValueError(f"{context} is not a regular file: {path}") from error
    if not stat.S_ISREG(before.st_mode):
        raise ValueError(f"{context} is not a regular file: {path}")

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_NONBLOCK", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ValueError(f"{context} cannot be opened safely: {path}") from error
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or (before.st_dev, before.st_ino) != (metadata.st_dev, metadata.st_ino)
        ):
            raise ValueError(f"{context} changed before it could be opened: {path}")
        if metadata.st_size > maximum:
            raise ValueError(f"{context} exceeds {maximum} bytes")
        with os.fdopen(descriptor, "rb") as source:
            descriptor = -1
            data = source.read(maximum + 1)
            final_metadata = os.fstat(source.fileno())
            if (
                metadata.st_dev,
                metadata.st_ino,
                metadata.st_mode,
                metadata.st_size,
                metadata.st_mtime_ns,
                metadata.st_ctime_ns,
            ) != (
                final_metadata.st_dev,
                final_metadata.st_ino,
                final_metadata.st_mode,
                final_metadata.st_size,
                final_metadata.st_mtime_ns,
                final_metadata.st_ctime_ns,
            ):
                raise ValueError(f"{context} changed while it was being read: {path}")
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if len(data) > maximum:
        raise ValueError(f"{context} exceeds {maximum} bytes")
    if len(data) != metadata.st_size:
        raise ValueError(f"{context} changed while it was being read: {path}")
    return data


def load_sources(path: Optional[Path] = None) -> dict[str, str]:
    source_path = path or ROOT / "sources.env"
    values: dict[str, str] = {}
    source_data = _read_bounded_regular_file(
        source_path, "source lock", MAX_SOURCES_FILE_BYTES
    )
    try:
        source_text = source_data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError(f"{source_path}: source lock is not UTF-8") from error
    for line_number, raw_line in enumerate(source_text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise ValueError(f"{source_path}:{line_number}: expected KEY=VALUE")
        key, value = line.split("=", 1)
        if not re.fullmatch(r"[A-Z][A-Z0-9_]*", key):
            raise ValueError(f"{source_path}:{line_number}: unsafe key {key!r}")
        if not value or not SAFE_VALUE.fullmatch(value):
            raise ValueError(f"{source_path}:{line_number}: unsafe value for {key}")
        if key in values:
            raise ValueError(f"{source_path}:{line_number}: duplicate key {key}")
        values[key] = value

    required = {
        "BUILD_REVISION",
        "FFMPEG_ARCHIVE",
        "FFMPEG_PGP_FINGERPRINT",
        "FFMPEG_GPLV2_SHA256",
        "FFMPEG_GPLV3_SHA256",
        "FFMPEG_LICENSE_SHA256",
        "FFMPEG_IJG_NOTICE_SHA256",
        "FFMPEG_SHA256",
        "FFMPEG_SIGNATURE_ARCHIVE",
        "FFMPEG_SIGNATURE_SHA256",
        "FFMPEG_SIGNATURE_URL",
        "FFMPEG_URL",
        "FFMPEG_VERSION",
        "FORTIFY_HEADERS_ARCHIVE",
        "FORTIFY_HEADERS_REVISION",
        "FORTIFY_HEADERS_SHA256",
        "FORTIFY_HEADERS_URL",
        "FORTIFY_HEADERS_VERSION",
        "FORTIFY_HEADERS_LICENSE_SHA256",
        "GCC_RUNTIME_EXCEPTION_SHA256",
        "LAME_ARCHIVE",
        "LAME_SHA256",
        "LAME_URL",
        "LAME_VERSION",
        "LAME_COPYING_SHA256",
        "LAME_LICENSE_SHA256",
        "FFMPEG_LGPLV21_SHA256",
        "MACOS_MIN_VERSION",
        "MUSL_ARCHIVE",
        "MUSL_SHA256",
        "MUSL_URL",
        "MUSL_VERSION",
        "MUSL_COPYRIGHT_SHA256",
        "MUSL_QSORT_NOTICE_SHA256",
        "MUSL_SUNPRO_NOTICE_SHA256",
        "MUSL_ICONV_PATCH_SHA256",
        "MUSL_QSORT_PATCH_SHA256",
        "MUSL_PATCHED_ICONV_SHA256",
        "MUSL_PATCHED_GB18030UTF_SHA256",
        "MUSL_PATCHED_QSORT_SHA256",
        "NASM_ARCHIVE",
        "NASM_SHA256",
        "NASM_URL",
        "NASM_VERSION",
        "LLVM_MINGW_ARCHIVE",
        "LLVM_MINGW_RECIPE_ARCHIVE",
        "LLVM_MINGW_RECIPE_REVISION",
        "LLVM_MINGW_RECIPE_SHA256",
        "LLVM_MINGW_RECIPE_URL",
        "LLVM_MINGW_SHA256",
        "LLVM_MINGW_URL",
        "LLVM_MINGW_VERSION",
        "LLVM_LICENSE_SHA256",
        "LLVM_RUNTIME_ARCHIVE",
        "LLVM_RUNTIME_REVISION",
        "LLVM_RUNTIME_SHA256",
        "LLVM_RUNTIME_URL",
        "LLVM_RUNTIME_VERSION",
        "MINGW_W64_ARCHIVE",
        "MINGW_RUNTIME_LICENSE_SHA256",
        "MINGW_W64_REVISION",
        "MINGW_W64_SHA256",
        "MINGW_W64_URL",
        "MINGW_W64_VERSION",
        "SOURCE_DATE_EPOCH",
        "THIRD_PARTY_NOTICES_SHA256",
        "THIRD_PARTY_NOTICES_SIZE",
        "X264_ARCHIVE",
        "X264_REVISION",
        "X264_SHA256",
        "X264_URL",
        "X264_LICENSE_SHA256",
        "X264_X86INC_ISC_SHA256",
    }
    missing = sorted(required - values.keys())
    if missing:
        raise ValueError(f"{source_path}: missing keys: {', '.join(missing)}")
    unknown = sorted(values.keys() - required)
    if unknown:
        raise ValueError(f"{source_path}: unknown keys: {', '.join(unknown)}")
    for key in (
        "FFMPEG_SHA256",
        "FFMPEG_SIGNATURE_SHA256",
        "FFMPEG_GPLV2_SHA256",
        "FFMPEG_GPLV3_SHA256",
        "FFMPEG_LICENSE_SHA256",
        "FFMPEG_IJG_NOTICE_SHA256",
        "FORTIFY_HEADERS_SHA256",
        "FORTIFY_HEADERS_LICENSE_SHA256",
        "GCC_RUNTIME_EXCEPTION_SHA256",
        "LAME_COPYING_SHA256",
        "LAME_LICENSE_SHA256",
        "FFMPEG_LGPLV21_SHA256",
        "LAME_SHA256",
        "LLVM_LICENSE_SHA256",
        "LLVM_MINGW_SHA256",
        "LLVM_MINGW_RECIPE_SHA256",
        "LLVM_RUNTIME_SHA256",
        "MINGW_RUNTIME_LICENSE_SHA256",
        "MINGW_W64_SHA256",
        "MUSL_COPYRIGHT_SHA256",
        "MUSL_QSORT_NOTICE_SHA256",
        "MUSL_SHA256",
        "MUSL_SUNPRO_NOTICE_SHA256",
        "MUSL_ICONV_PATCH_SHA256",
        "MUSL_QSORT_PATCH_SHA256",
        "MUSL_PATCHED_ICONV_SHA256",
        "MUSL_PATCHED_GB18030UTF_SHA256",
        "MUSL_PATCHED_QSORT_SHA256",
        "NASM_SHA256",
        "THIRD_PARTY_NOTICES_SHA256",
        "X264_LICENSE_SHA256",
        "X264_X86INC_ISC_SHA256",
        "X264_SHA256",
    ):
        if not re.fullmatch(r"[0-9a-f]{64}", values[key]):
            raise ValueError(f"{source_path}: {key} must be lowercase SHA-256")
    if not re.fullmatch(r"[0-9A-F]{40}", values["FFMPEG_PGP_FINGERPRINT"]):
        raise ValueError(f"{source_path}: FFMPEG_PGP_FINGERPRINT must be 40 uppercase hex characters")
    for key in (
        "FORTIFY_HEADERS_REVISION",
        "LLVM_MINGW_RECIPE_REVISION",
        "LLVM_RUNTIME_REVISION",
        "MINGW_W64_REVISION",
        "X264_REVISION",
    ):
        if not re.fullmatch(r"[0-9a-f]{40}", values[key]):
            raise ValueError(f"{source_path}: {key} must be a lowercase Git commit")
    if not re.fullmatch(r"[1-9][0-9]*", values["BUILD_REVISION"]):
        raise ValueError(f"{source_path}: BUILD_REVISION must be positive")
    upstream_version = re.compile(
        r"[0-9]+(?:\.[0-9]+){1,3}(?:[-._][A-Za-z0-9]+)*"
    )
    for key in (
        "FFMPEG_VERSION",
        "FORTIFY_HEADERS_VERSION",
        "LAME_VERSION",
        "MUSL_VERSION",
        "NASM_VERSION",
        "LLVM_RUNTIME_VERSION",
        "MINGW_W64_VERSION",
    ):
        if not upstream_version.fullmatch(values[key]):
            raise ValueError(f"{source_path}: {key} has an unsafe version format")
    if not re.fullmatch(r"[0-9]{8}", values["LLVM_MINGW_VERSION"]):
        raise ValueError(
            f"{source_path}: LLVM_MINGW_VERSION must be an eight-digit release date"
        )
    if not re.fullmatch(r"[1-9][0-9]{8,}", values["SOURCE_DATE_EPOCH"]):
        raise ValueError(f"{source_path}: SOURCE_DATE_EPOCH must be a Unix timestamp")
    source_epoch = int(values["SOURCE_DATE_EPOCH"])
    if source_epoch % 2 or not 315532800 <= source_epoch <= 4354819198:
        raise ValueError(
            f"{source_path}: SOURCE_DATE_EPOCH must be an even timestamp in the "
            "ZIP DOS range 1980-01-01 through 2107-12-31 23:59:58 UTC"
        )
    if not re.fullmatch(r"[1-9][0-9]*", values["THIRD_PARTY_NOTICES_SIZE"]):
        raise ValueError(
            f"{source_path}: THIRD_PARTY_NOTICES_SIZE must be a positive byte count"
        )
    if int(values["THIRD_PARTY_NOTICES_SIZE"]) > MAX_LICENSE_FILE_BYTES:
        raise ValueError(
            f"{source_path}: THIRD_PARTY_NOTICES_SIZE exceeds the license file limit"
        )
    if not re.fullmatch(r"[1-9][0-9]*\.[0-9]+", values["MACOS_MIN_VERSION"]):
        raise ValueError(f"{source_path}: MACOS_MIN_VERSION must be major.minor")
    archive_keys = (
        "FFMPEG_ARCHIVE",
        "FFMPEG_SIGNATURE_ARCHIVE",
        "FORTIFY_HEADERS_ARCHIVE",
        "LAME_ARCHIVE",
        "LLVM_MINGW_ARCHIVE",
        "LLVM_MINGW_RECIPE_ARCHIVE",
        "LLVM_RUNTIME_ARCHIVE",
        "MINGW_W64_ARCHIVE",
        "MUSL_ARCHIVE",
        "NASM_ARCHIVE",
        "X264_ARCHIVE",
    )
    archives = [values[key] for key in archive_keys]
    folded_archives = [name.casefold() for name in archives]
    if len(set(folded_archives)) != len(folded_archives):
        raise ValueError(
            f"{source_path}: archive names must be unique across case-insensitive filesystems"
        )
    for key in archive_keys:
        try:
            safe_basename(values[key])
        except ValueError as error:
            raise ValueError(f"{source_path}: unsafe archive name for {key}") from error
    release = f"{values['FFMPEG_VERSION']}-motrix.{values['BUILD_REVISION']}"
    reserved_release_names = {
        "LICENSE",
        "SHA256SUMS",
        "ffmpeg-manifest.json",
        "ffmpeg-manifest.json.sig",
        "ffmpeg-release-signing-key.asc",
        "sbom.spdx.json",
        "sources.env",
        f"ffmpeg-{release}-build-scripts.tar.gz",
    }
    for target_name, target in TARGETS.items():
        archive = f"ffmpeg-{release}-{target_name}.{target['extension']}"
        reserved_release_names.add(archive)
        reserved_release_names.add(f"{archive}.metadata.json")
        if target["platform"] == "darwin":
            reserved_release_names.add(
                f"ffmpeg-{release}-{target_name}.notarization-log.json"
            )
    reserved_folded = {name.casefold() for name in reserved_release_names}
    collisions = sorted(
        name for name in archives if name.casefold() in reserved_folded
    )
    if collisions:
        raise ValueError(
            f"{source_path}: archive names collide with reserved release assets: "
            f"{', '.join(collisions)}"
        )
    for key in (
        "FFMPEG_SIGNATURE_URL",
        "FFMPEG_URL",
        "FORTIFY_HEADERS_URL",
        "LAME_URL",
        "LLVM_MINGW_RECIPE_URL",
        "LLVM_MINGW_URL",
        "LLVM_RUNTIME_URL",
        "MINGW_W64_URL",
        "MUSL_URL",
        "NASM_URL",
        "X264_URL",
    ):
        url = urllib.parse.urlsplit(values[key])
        if (
            url.scheme != "https"
            or not url.hostname
            or url.username is not None
            or url.password is not None
            or url.query
            or url.fragment
        ):
            raise ValueError(
                f"{source_path}: {key} must be a credential-free HTTPS URL "
                "without a query or fragment"
            )
    return values


def release_version(sources: dict[str, str]) -> str:
    return safe_basename(
        f"{sources['FFMPEG_VERSION']}-motrix.{sources['BUILD_REVISION']}"
    )


def release_tag(sources: dict[str, str]) -> str:
    return f"v{release_version(sources)}"


def artifact_stem(sources: dict[str, str], target: str) -> str:
    require_target(target)
    return safe_basename(f"ffmpeg-{release_version(sources)}-{target}")


def artifact_license(target: str) -> str:
    return PLATFORM_ARTIFACT_LICENSES[require_target(target)["platform"]]


def require_target(target: str) -> dict[str, str]:
    try:
        return TARGETS[target]
    except KeyError as error:
        raise ValueError(f"unsupported target: {target}") from error


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, allow_nan=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")


def load_json_bytes(
    data: bytes, context: str, *, maximum: int = 512 * 1024
) -> Any:
    """Decode strict JSON, rejecting duplicate names and non-finite numbers."""

    if len(data) > maximum:
        raise ValueError(f"{context} exceeds {maximum} bytes")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError(f"{context} is not UTF-8") from error

    def object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"{context} contains duplicate key {key!r}")
            result[key] = value
        return result

    def reject_constant(value: str) -> None:
        raise ValueError(f"{context} contains non-finite number {value}")

    try:
        return json.loads(
            text,
            object_pairs_hook=object_pairs,
            parse_constant=reject_constant,
        )
    except json.JSONDecodeError as error:
        raise ValueError(f"invalid {context}: {error}") from error


def load_json_file(
    path: Path, context: str, *, maximum: int = 512 * 1024
) -> Any:
    data = _read_bounded_regular_file(path, context, maximum)
    return load_json_bytes(data, context, maximum=maximum)


def write_json(path: Path, value: Any) -> None:
    path.write_bytes(canonical_json(value))


def safe_basename(value: str) -> str:
    windows_stem = value.split(".", 1)[0].upper() if value else ""
    windows_devices = {
        "CON",
        "PRN",
        "AUX",
        "NUL",
        *(f"COM{number}" for number in range(1, 10)),
        *(f"LPT{number}" for number in range(1, 10)),
    }
    if (
        not value
        or value != os.path.basename(value)
        or value.endswith(".")
        or windows_stem in windows_devices
        or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]*", value)
    ):
        raise ValueError(f"unsafe file name: {value!r}")
    return value


def required_license_files(target: str) -> dict[str, tuple[str, str, str, str]]:
    target_info = require_target(target)
    architecture_notices = X64_LICENSE_FILES if target_info["arch"] == "x64" else {}
    return (
        COMMON_LICENSE_FILES
        | PLATFORM_LICENSE_FILES[target_info["platform"]]
        | architecture_notices
    )


def minimum_os(target: str, sources: dict[str, str]) -> dict[str, str]:
    platform = require_target(target)["platform"]
    if platform == "darwin":
        return {"name": "macos", "version": sources["MACOS_MIN_VERSION"]}
    try:
        name, version = STATIC_MINIMUM_OS[target]
    except KeyError as error:
        raise ValueError(f"minimum OS contract is not defined for {target}") from error
    return {"name": name, "version": version}


def expected_configure_args(target: str, sources: dict[str, str]) -> list[str]:
    target_info = require_target(target)
    platform = target_info["platform"]
    arch = target_info["arch"]
    configure_arch = "aarch64" if arch == "arm64" else "x86_64"
    common = [
        "--prefix=/usr/local",
        "--datadir=/usr/local/share/ffmpeg",
        "--disable-shared",
        "--enable-static",
        "--disable-autodetect",
        "--enable-gpl",
        "--enable-libx264",
        "--enable-libmp3lame",
        "--enable-ffmpeg",
        "--enable-ffprobe",
        "--disable-ffplay",
        "--disable-doc",
        "--disable-debug",
        "--enable-pic",
        "--enable-runtime-cpudetect",
        "--pkg-config-flags=--static",
        "--pkg-config=pkg-config",
    ]
    if platform == "darwin":
        mac_arch = "arm64" if arch == "arm64" else "x86_64"
        cflags = (
            "-O2 -fPIC -fstack-protector-strong -D_FORTIFY_SOURCE=2 "
            f"-arch {mac_arch} -mmacosx-version-min={sources['MACOS_MIN_VERSION']}"
        )
        ldflags = (
            f"-arch {mac_arch} -mmacosx-version-min={sources['MACOS_MIN_VERSION']} "
            "-Wl,-dead_strip"
        )
        commands = ("clang", "clang++", "ar", "ranlib", "strip", "nm")
        tail = [
            "--target-os=darwin",
            "--enable-videotoolbox",
            "--enable-audiotoolbox",
        ]
    elif platform == "linux":
        arch_flags = (
            "-mbranch-protection=standard -mno-outline-atomics"
            if arch == "arm64"
            else "-fcf-protection=full"
        )
        cflags = (
            "-I../src/fortify-headers/include -O2 -fPIE "
            "-fstack-protector-strong -U_FORTIFY_SOURCE "
            "-D_FORTIFY_SOURCE=3 -Wformat "
            f"-Wformat-security -Werror=format-security {arch_flags}"
        )
        ldflags = (
            "-static-pie "
            "-Wl,-z,relro,-z,now,-z,noexecstack,-z,separate-code,--build-id=sha1 "
            "-Wl,-z,stack-size=2097152"
        )
        commands = ("musl-gcc", "musl-gcc", "ar", "ranlib", "strip", "nm")
        tail = ["--target-os=linux", "--host-cc=gcc"]
    else:
        triplet = f"{configure_arch}-w64-mingw32"
        cflags = (
            "-O2 -fPIC -fstack-protector-strong -mguard=cf "
            "-D_WIN32_WINNT=0x0A00 -DWINVER=0x0A00"
        )
        ldflags = (
            "-static -mguard=cf "
            "-Wl,--nxcompat,--dynamicbase,--high-entropy-va,--major-os-version,10,"
            "--minor-os-version,0,--major-subsystem-version,6,"
            "--minor-subsystem-version,2"
        )
        commands = (
            f"{triplet}-clang",
            f"{triplet}-clang++",
            "llvm-ar",
            "llvm-ranlib",
            "llvm-strip",
            "llvm-nm",
        )
        tail = [
            "--target-os=mingw32",
            "--enable-cross-compile",
            f"--cross-prefix={triplet}-",
        ]
    cc, cxx, ar, ranlib, strip, nm = commands
    arguments = common + [
        f"--cc={cc}",
        f"--cxx={cxx}",
        f"--ar={ar}",
        f"--ranlib={ranlib}",
        f"--strip={strip}",
        f"--nm={nm}",
        f"--arch={configure_arch}",
        f"--extra-cflags={cflags}",
        f"--extra-ldflags={ldflags}",
        "--extra-libs=-lm",
    ]
    if arch == "x64":
        arguments.append("--x86asmexe=nasm")
    return arguments + list(tail)


def parse_configure_record(data: bytes) -> list[str]:
    """Parse the shell-escaped configure record into exact argument tokens."""

    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("configure record is not UTF-8") from error
    # build.sh emits one escaped argument per continued line. Remove only shell
    # line continuations before shlex parsing; literal newlines inside arguments
    # are not valid pipeline input.
    normalized = text.replace("\\\r\n", "").replace("\\\n", "")
    try:
        tokens = shlex.split(normalized, comments=False, posix=True)
    except ValueError as error:
        raise ValueError(f"invalid configure record: {error}") from error
    if not tokens or tokens[0] not in ("./configure", "configure"):
        raise ValueError("configure record must start with ./configure")
    arguments = tokens[1:]
    if not arguments or any("\n" in argument or "\r" in argument for argument in arguments):
        raise ValueError("configure record contains invalid arguments")
    for required in sorted(REQUIRED_CONFIGURE_FLAGS):
        if required not in arguments:
            raise ValueError(f"configure record is missing exact flag {required}")
    options: set[str] = set()
    for argument in arguments:
        option = argument.split("=", 1)[0]
        if option in FORBIDDEN_CONFIGURE_FLAGS:
            raise ValueError(f"configure record contains forbidden flag {argument}")
        if option not in ALLOWED_CONFIGURE_OPTIONS:
            raise ValueError(f"configure record contains unapproved option {argument}")
        if option in options:
            raise ValueError(f"configure record contains duplicate option {option}")
        options.add(option)
    return arguments


def validate_dependencies(
    value: object, target: str, sources: dict[str, str]
) -> list[dict[str, str]]:
    platform = require_target(target)["platform"]
    expected = DEPENDENCIES[platform]
    if not isinstance(value, list):
        raise ValueError("build info dependencies must be an array")
    normalized: list[dict[str, str]] = []
    names: set[str] = set()
    for item in value:
        if not isinstance(item, dict) or set(item) != {
            "name",
            "version",
            "license",
            "relationship",
        }:
            raise ValueError("invalid dependency record")
        if not all(isinstance(item[key], str) and item[key] for key in item):
            raise ValueError("dependency fields must be non-empty strings")
        name = item["name"]
        if name in names:
            raise ValueError(f"duplicate dependency: {name}")
        names.add(name)
        if name not in expected:
            raise ValueError(f"unexpected dependency: {name}")
        license_expression, relationship = expected[name]
        if (
            item["license"] != license_expression
            or item["relationship"] != relationship
        ):
            raise ValueError(f"dependency contract mismatch: {name}")
        if name == "musl" and item["version"] != sources["MUSL_VERSION"]:
            raise ValueError("musl runtime version does not match the lock")
        if (
            name == "fortify-headers"
            and item["version"] != sources["FORTIFY_HEADERS_REVISION"]
        ):
            raise ValueError("fortify-headers revision does not match the lock")
        if name == "llvm-compiler-rt" and item["version"] != sources["LLVM_RUNTIME_VERSION"]:
            raise ValueError("LLVM compiler runtime version does not match the lock")
        if name == "mingw-w64-runtime" and item["version"] != sources["MINGW_W64_VERSION"]:
            raise ValueError("MinGW-w64 runtime version does not match the lock")
        if name == "gcc-runtime" and not re.fullmatch(
            r"[0-9]+(?:[.][0-9]+){1,3}", item["version"]
        ):
            raise ValueError("GCC runtime version is invalid")
        normalized.append(
            {
                key: item[key]
                for key in ("name", "version", "license", "relationship")
            }
        )
    if names != set(expected):
        missing = sorted(set(expected) - names)
        extra = sorted(names - set(expected))
        raise ValueError(f"dependency set mismatch; missing={missing}, extra={extra}")
    return sorted(normalized, key=lambda item: item["name"])


def _require_exact_keys(value: object, keys: set[str], context: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise ValueError(f"{context} must contain exactly {sorted(keys)}")
    return value


def _require_text(value: object, context: str, *, maximum: int = 512) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum or "\n" in value or "\r" in value:
        raise ValueError(f"{context} must be a non-empty single-line string")
    return value


def _require_sha256(value: object, context: str) -> str:
    if not isinstance(value, str) or not LOWER_SHA256.fullmatch(value):
        raise ValueError(f"{context} must be a lowercase SHA-256")
    return value


def _require_timestamp(value: object, context: str) -> str:
    if not isinstance(value, str) or not RFC3339_UTC.fullmatch(value):
        raise ValueError(f"{context} must be an RFC3339 UTC timestamp")
    try:
        parsed = dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as error:
        raise ValueError(f"{context} must be a real RFC3339 UTC timestamp") from error
    if parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != value:
        raise ValueError(f"{context} must use canonical RFC3339 UTC formatting")
    return value


def validate_timestamp(value: object, context: str = "timestamp") -> str:
    return _require_timestamp(value, context)


def notarization_log_asset_name(target: str, sources: dict[str, str]) -> str:
    """Return the only accepted public Apple developer-log asset name."""

    target_info = require_target(target)
    if target_info["platform"] != "darwin":
        raise ValueError("notarization logs are only defined for macOS targets")
    return safe_basename(f"{artifact_stem(sources, target)}.notarization-log.json")


def validate_notarization_submission(value: object) -> str:
    """Validate the acceptance response and return its canonical job UUID."""

    if not isinstance(value, dict):
        raise ValueError("notarization submission result must be an object")
    submission = value.get("id")
    if not isinstance(submission, str) or not re.fullmatch(
        r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-"
        r"[89aAbB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}",
        submission,
    ):
        raise ValueError("notarization submission result has an invalid job ID")
    if value.get("status") != "Accepted":
        raise ValueError("notarization submission result is not Accepted")
    return submission.lower()


def validate_notarization_log(
    value: object,
    *,
    submission_id: str,
    archive_name: str,
    archive_sha256: str,
) -> None:
    """Fail closed unless an Apple developer log proves the exact accepted ZIP."""

    if not isinstance(value, dict):
        raise ValueError("notarization developer log must be an object")
    required = {
        "logFormatVersion",
        "jobId",
        "status",
        "statusCode",
        "archiveFilename",
        "sha256",
    }
    missing = sorted(required - set(value))
    if missing:
        raise ValueError(
            f"notarization developer log is missing required fields: {missing}"
        )
    if type(value["logFormatVersion"]) is not int or value["logFormatVersion"] != 1:
        raise ValueError("notarization developer log format is not version 1")
    canonical_submission = validate_notarization_submission(
        {"id": submission_id, "status": "Accepted"}
    )
    job_id = value["jobId"]
    if not isinstance(job_id, str) or job_id.lower() != canonical_submission:
        raise ValueError("notarization developer log job ID does not match submission")
    if value["status"] != "Accepted":
        raise ValueError("notarization developer log status is not Accepted")
    if type(value["statusCode"]) is not int or value["statusCode"] != 0:
        raise ValueError("notarization developer log status code is not zero")
    expected_archive_name = safe_basename(archive_name)
    if value["archiveFilename"] != expected_archive_name:
        raise ValueError("notarization developer log archive name does not match")
    expected_archive_sha = _require_sha256(
        archive_sha256, "notarized archive digest"
    )
    if value["sha256"] != expected_archive_sha:
        raise ValueError("notarization developer log archive digest does not match")
    if "issues" in value and value["issues"] not in (None, []):
        raise ValueError("notarization developer log contains issues")


def _validate_command_version(
    value: object, command: str, context: str
) -> dict[str, str]:
    record = _require_exact_keys(value, {"command", "version"}, context)
    if record["command"] != command:
        raise ValueError(f"{context} command must be {command}")
    return {
        "command": command,
        "version": _require_text(record["version"], f"{context} version"),
    }


def validate_build_info(
    value: object,
    target_name: str,
    sources: dict[str, str],
    configure_args: list[str],
) -> tuple[dict[str, Any], list[dict[str, str]]]:
    """Validate the complete, target-specific BUILD-INFO contract."""

    target = require_target(target_name)
    info = _require_exact_keys(
        value,
        {
            "schemaVersion",
            "target",
            "platform",
            "arch",
            "license",
            "minimumOs",
            "compiler",
            "toolchain",
            "tools",
            "hardening",
            "configure",
            "sources",
            "dependencies",
        },
        "build info",
    )
    if (
        info["schemaVersion"] != 1
        or info["target"] != target_name
        or info["platform"] != target["platform"]
        or info["arch"] != target["arch"]
    ):
        raise ValueError(f"build info does not describe {target_name}")
    if info["license"] != artifact_license(target_name):
        raise ValueError("build info has an unexpected license profile")
    if info["minimumOs"] != minimum_os(target_name, sources):
        raise ValueError("build info has an unexpected minimum OS contract")
    if info["configure"] != configure_args:
        raise ValueError("build info configure array does not match configure.txt")
    if configure_args != expected_configure_args(target_name, sources):
        raise ValueError("configure record does not match the locked target profile")

    platform = target["platform"]
    arch = target["arch"]
    configure_arch = "aarch64" if arch == "arm64" else "x86_64"
    if platform == "darwin":
        compiler_command = "clang"
        toolchain_expected = {
            "name": "apple-clang-sdk",
            "url": "",
            "sha256": "",
        }
        linker_command = "ld"
        binutils_commands = ("ar", "ranlib", "strip", "nm", "strings")
        fortify = "system-headers-level-2"
        link_provenance = "platform-system"
    elif platform == "linux":
        compiler_command = "musl-gcc"
        toolchain_expected = {
            "name": "source-built-musl",
            "version": sources["MUSL_VERSION"],
            "url": sources["MUSL_URL"],
            "sha256": sources["MUSL_SHA256"],
        }
        linker_command = "ld"
        binutils_commands = ("ar", "ranlib", "strip", "nm", "strings")
        fortify = (
            f"{sources['FORTIFY_HEADERS_VERSION']}@"
            f"{sources['FORTIFY_HEADERS_REVISION']}:runtime-trap-verified"
        )
        link_provenance = "validated-private-musl-link-maps"
    else:
        compiler_command = f"{configure_arch}-w64-mingw32-clang"
        toolchain_expected = {
            "name": "llvm-mingw-ucrt",
            "version": sources["LLVM_MINGW_VERSION"],
            "url": sources["LLVM_MINGW_URL"],
            "sha256": sources["LLVM_MINGW_SHA256"],
        }
        linker_command = "ld.lld"
        binutils_commands = (
            "llvm-ar",
            "llvm-ranlib",
            "llvm-strip",
            "llvm-nm",
            "llvm-strings",
        )
        fortify = "not-applicable"
        link_provenance = "validated-ucrt-system-import-allowlist"

    compiler = _validate_command_version(
        info["compiler"], compiler_command, "build compiler"
    )
    toolchain = _require_exact_keys(
        info["toolchain"], {"name", "version", "url", "sha256"}, "build toolchain"
    )
    for key, expected in toolchain_expected.items():
        if toolchain[key] != expected:
            raise ValueError(f"build toolchain {key} does not match the lock")
    if platform == "darwin":
        _require_text(toolchain["version"], "Apple SDK version")
    else:
        _require_sha256(toolchain["sha256"], "build toolchain checksum")

    tools = _require_exact_keys(
        info["tools"],
        {
            "linker",
            "binutils",
            "nasm",
            "pkgConfig",
            "make",
            "python",
            "tar",
            "macosSdkVersion",
        },
        "build tools",
    )
    _validate_command_version(tools["linker"], linker_command, "linker")
    binutils = _require_exact_keys(
        tools["binutils"],
        {"ar", "ranlib", "strip", "nm", "strings", "version"},
        "binutils",
    )
    for key, command in zip(
        ("ar", "ranlib", "strip", "nm", "strings"),
        binutils_commands,
    ):
        if binutils[key] != command:
            raise ValueError(f"binutils {key} command must be {command}")
    _require_text(binutils["version"], "binutils version")
    _validate_command_version(tools["pkgConfig"], "pkg-config", "pkg-config")
    _validate_command_version(tools["make"], "make", "make")
    _validate_command_version(tools["python"], "python3", "Python")
    _validate_command_version(tools["tar"], "tar", "tar")
    if arch == "x64":
        nasm = _require_exact_keys(
            tools["nasm"],
            {
                "command",
                "version",
                "sourceVersion",
                "sourceUrl",
                "sourceSha256",
                "binarySha256",
            },
            "NASM",
        )
        if nasm["command"] != "nasm":
            raise ValueError("NASM command must be nasm")
        moment = dt.datetime.fromtimestamp(
            int(sources["SOURCE_DATE_EPOCH"]), tz=dt.timezone.utc
        )
        months = (
            "Jan", "Feb", "Mar", "Apr", "May", "Jun",
            "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
        )
        expected_version = (
            f"NASM version {sources['NASM_VERSION']} compiled on "
            f"{months[moment.month - 1]} {moment.day:2d} {moment.year}"
        )
        if nasm["version"] != expected_version:
            raise ValueError("NASM observed version/date does not match the lock")
        if nasm["sourceVersion"] != sources["NASM_VERSION"]:
            raise ValueError("NASM source version does not match the lock")
        if nasm["sourceUrl"] != sources["NASM_URL"]:
            raise ValueError("NASM source URL does not match the lock")
        if nasm["sourceSha256"] != sources["NASM_SHA256"]:
            raise ValueError("NASM source checksum does not match the lock")
        _require_sha256(nasm["sourceSha256"], "NASM source checksum")
        _require_sha256(nasm["binarySha256"], "NASM executable checksum")
    elif tools["nasm"] is not None:
        raise ValueError("ARM64 build info must not claim a NASM tool")
    if platform == "darwin":
        if tools["macosSdkVersion"] != toolchain["version"]:
            raise ValueError("macOS SDK records disagree")
    elif tools["macosSdkVersion"] != "":
        raise ValueError("non-macOS build claims a macOS SDK")

    hardening = _require_exact_keys(
        info["hardening"], {"fortify", "linkProvenance"}, "hardening record"
    )
    if hardening != {"fortify": fortify, "linkProvenance": link_provenance}:
        raise ValueError("build hardening record does not match the target contract")

    expected_sources = {
        "ffmpeg": {
            "version": sources["FFMPEG_VERSION"],
            "url": sources["FFMPEG_URL"],
            "sha256": sources["FFMPEG_SHA256"],
        },
        "fortifyHeaders": {
            "version": sources["FORTIFY_HEADERS_VERSION"],
            "revision": sources["FORTIFY_HEADERS_REVISION"],
            "url": sources["FORTIFY_HEADERS_URL"],
            "sha256": sources["FORTIFY_HEADERS_SHA256"],
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
        "llvmCompilerRt": {
            "version": sources["LLVM_RUNTIME_VERSION"],
            "revision": sources["LLVM_RUNTIME_REVISION"],
            "url": sources["LLVM_RUNTIME_URL"],
            "sha256": sources["LLVM_RUNTIME_SHA256"],
        },
        "llvmMingwRecipe": {
            "revision": sources["LLVM_MINGW_RECIPE_REVISION"],
            "url": sources["LLVM_MINGW_RECIPE_URL"],
            "sha256": sources["LLVM_MINGW_RECIPE_SHA256"],
        },
        "mingwW64Runtime": {
            "version": sources["MINGW_W64_VERSION"],
            "revision": sources["MINGW_W64_REVISION"],
            "url": sources["MINGW_W64_URL"],
            "sha256": sources["MINGW_W64_SHA256"],
        },
    }
    if info["sources"] != expected_sources:
        raise ValueError("build info has unexpected source provenance")

    dependencies = validate_dependencies(info["dependencies"], target_name, sources)
    if platform == "linux":
        gcc_version = next(
            item["version"] for item in dependencies if item["name"] == "gcc-runtime"
        )
        if gcc_version not in compiler["version"]:
            raise ValueError("GCC runtime version is not bound to the compiler record")

    normalized = dict(info)
    normalized["dependencies"] = dependencies
    return normalized, dependencies


def validate_signing_evidence(
    value: object,
    target: str,
    binary_hashes: dict[str, str],
    *,
    expected_notarization_log_name: Optional[str] = None,
) -> dict[str, Any]:
    """Validate structured evidence bound to both exact packaged binaries."""

    target_info = require_target(target)
    platform = target_info["platform"]
    if platform == "linux":
        raise ValueError("Linux artifacts do not accept code-signing evidence")
    evidence = _require_exact_keys(
        value,
        {"schemaVersion", "target", "platform", "kind", "identity", "binaries"}
        | ({"notarization"} if platform == "darwin" else {"tool"}),
        "signing evidence",
    )
    if evidence["schemaVersion"] != 3 or evidence["target"] != target or evidence["platform"] != platform:
        raise ValueError("signing evidence identity does not match the target")
    binaries = _require_exact_keys(
        evidence["binaries"], set(binary_hashes), "signing evidence binaries"
    )

    normalized_binaries: dict[str, dict[str, str]] = {}
    if platform == "darwin":
        if evidence["kind"] != "apple-developer-id":
            raise ValueError("macOS signing evidence has the wrong kind")
        identity = _require_exact_keys(
            evidence["identity"],
            {"teamId", "subject", "certificateSha256"},
            "macOS signing identity",
        )
        team_id = identity["teamId"]
        if not isinstance(team_id, str) or not re.fullmatch(r"[A-Z0-9]{10}", team_id):
            raise ValueError("macOS Team ID must be ten uppercase alphanumeric characters")
        subject = _require_text(identity["subject"], "macOS certificate subject")
        if not subject.startswith("Developer ID Application:") or f"({team_id})" not in subject:
            raise ValueError("macOS certificate subject does not match the Team ID")
        certificate_sha = _require_sha256(
            identity["certificateSha256"], "macOS certificate fingerprint"
        )
        for name, expected_sha in binary_hashes.items():
            record = _require_exact_keys(
                binaries[name],
                {"sha256", "cdHash", "timestamp", "hardenedRuntime"},
                f"{name} signing record",
            )
            if _require_sha256(record["sha256"], f"{name} signed hash") != expected_sha:
                raise ValueError(f"signing evidence is not bound to {name}")
            cd_hash = record["cdHash"]
            if not isinstance(cd_hash, str) or not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", cd_hash):
                raise ValueError(f"{name} CDHash is invalid")
            normalized_binaries[name] = {
                "sha256": expected_sha,
                "cdHash": cd_hash,
                "timestamp": _require_timestamp(record["timestamp"], f"{name} timestamp"),
                "hardenedRuntime": True,
            }
            if record["hardenedRuntime"] is not True:
                raise ValueError(f"{name} does not record hardened runtime")
        notary = _require_exact_keys(
            evidence["notarization"],
            {
                "submissionId",
                "status",
                "submissionResultSha256",
                "developerLog",
            },
            "notarization evidence",
        )
        submission = notary["submissionId"]
        if not isinstance(submission, str) or not re.fullmatch(
            r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89aAbB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}",
            submission,
        ):
            raise ValueError("notarization submission ID is invalid")
        if notary["status"] != "Accepted":
            raise ValueError("notarization status is not Accepted")
        log = _require_exact_keys(
            notary["developerLog"],
            {"name", "sha256", "size"},
            "notarization developer log asset",
        )
        log_name = safe_basename(
            _require_text(log["name"], "notarization developer log name")
        )
        if not log_name.endswith(".notarization-log.json"):
            raise ValueError("notarization developer log has an invalid name")
        if (
            expected_notarization_log_name is not None
            and log_name != expected_notarization_log_name
        ):
            raise ValueError("notarization developer log name does not match the target")
        if (
            type(log["size"]) is not int
            or log["size"] <= 0
            or log["size"] > MAX_NOTARIZATION_JSON_BYTES
        ):
            raise ValueError("notarization developer log has an invalid size")
        normalized: dict[str, Any] = {
            "schemaVersion": 3,
            "target": target,
            "platform": platform,
            "kind": "apple-developer-id",
            "identity": {
                "teamId": team_id,
                "subject": subject,
                "certificateSha256": certificate_sha,
            },
            "binaries": normalized_binaries,
            "notarization": {
                "submissionId": submission.lower(),
                "status": "Accepted",
                "submissionResultSha256": _require_sha256(
                    notary["submissionResultSha256"],
                    "notarization submission result digest",
                ),
                "developerLog": {
                    "name": log_name,
                    "sha256": _require_sha256(
                        log["sha256"], "notarization developer log digest"
                    ),
                    "size": log["size"],
                },
            },
        }
        return normalized

    if evidence["kind"] != "authenticode":
        raise ValueError("Windows signing evidence has the wrong kind")
    identity = _require_exact_keys(
        evidence["identity"],
        {"subject", "thumbprint", "thumbprintAlgorithm"},
        "Authenticode signing identity",
    )
    subject = _require_text(identity["subject"], "Authenticode subject")
    if identity["thumbprintAlgorithm"] != "SHA256":
        raise ValueError("Authenticode thumbprint algorithm must be SHA256")
    thumbprint = _require_sha256(identity["thumbprint"], "Authenticode thumbprint")
    tool = _require_exact_keys(
        evidence["tool"],
        {"name", "version", "architecture", "sha256", "signerSubject"},
        "Authenticode signing tool",
    )
    if tool["name"] != "Microsoft SignTool":
        raise ValueError("Authenticode signing tool name is not Microsoft SignTool")
    version = tool["version"]
    if not isinstance(version, str) or not re.fullmatch(
        r"[0-9]+(?:\.[0-9]+){3}", version
    ):
        raise ValueError("SignTool version must contain four numeric components")
    if tool["architecture"] != target_info["arch"]:
        raise ValueError("SignTool architecture does not match the target")
    tool_sha = _require_sha256(tool["sha256"], "SignTool executable digest")
    tool_signer = _require_text(tool["signerSubject"], "SignTool signer subject")
    if "Microsoft" not in tool_signer:
        raise ValueError("SignTool signer subject is not a Microsoft identity")
    for name, expected_sha in binary_hashes.items():
        record = _require_exact_keys(
            binaries[name],
            {
                "sha256",
                "status",
                "timestamped",
                "timestampAuthorityCertificateSha256",
            },
            f"{name} signing record",
        )
        if _require_sha256(record["sha256"], f"{name} signed hash") != expected_sha:
            raise ValueError(f"signing evidence is not bound to {name}")
        normalized_binaries[name] = {
            "sha256": expected_sha,
            "status": "Valid",
            "timestamped": True,
            "timestampAuthorityCertificateSha256": _require_sha256(
                record["timestampAuthorityCertificateSha256"],
                f"{name} timestamp authority certificate fingerprint",
            ),
        }
        if record["status"] != "Valid":
            raise ValueError(f"{name} Authenticode status is not Valid")
        if record["timestamped"] is not True:
            raise ValueError(f"{name} Authenticode signature is not timestamped")
    return {
        "schemaVersion": 3,
        "target": target,
        "platform": platform,
        "kind": "authenticode",
        "identity": {
            "subject": subject,
            "thumbprint": thumbprint,
            "thumbprintAlgorithm": "SHA256",
        },
        "tool": {
            "name": "Microsoft SignTool",
            "version": version,
            "architecture": target_info["arch"],
            "sha256": tool_sha,
            "signerSubject": tool_signer,
        },
        "binaries": normalized_binaries,
    }
