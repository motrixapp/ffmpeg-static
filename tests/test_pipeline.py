from __future__ import annotations

import hashlib
import gzip
import importlib.util
import io
import json
import os
import shlex
import shutil
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import unittest
import warnings
import zipfile
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

import pipeline_lib  # noqa: E402


def load_script_module(name: str, file_name: str):  # type: ignore[no-untyped-def]
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / file_name)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {file_name}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


assemble_release = load_script_module("assemble_release", "assemble-release.py")
finalize_signing_grant = load_script_module(
    "finalize_signing_grant", "finalize_signing_grant.py"
)
validate_signing_input = load_script_module(
    "validate_signing_input", "validate_signing_input.py"
)

EXPECTED_TARGETS = (
    "darwin-arm64",
    "darwin-x64",
    "linux-arm64",
    "linux-x64",
    "win32-arm64",
    "win32-x64",
)

MAC_TEAM_ID = "ABCDE12345"
MAC_CERT_SHA256 = "a" * 64
WINDOWS_SUBJECT = "CN=Motrix Test Signing"
WINDOWS_CERT_SHA256 = "b" * 64
EVENT_SHA = "c" * 40
CONTROL_SHA = EVENT_SHA
DIFFERENT_CONTROL_SHA = "d" * 40
TAG_OBJECT_SHA = "e" * 40


class PipelineTest(unittest.TestCase):
    maxDiff = None

    def run_script(
        self, script: str, *arguments: object, check: bool = True
    ) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(
            [sys.executable, str(SCRIPTS / script), *(str(arg) for arg in arguments)],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        if check and result.returncode != 0:
            self.fail(
                f"{script} failed with {result.returncode}\n"
                f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
            )
        return result

    @staticmethod
    def _digest(data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    def make_sources(self, base: Path) -> tuple[Path, dict[str, bytes]]:
        assets = {
            "ffmpeg-fixture.tar.xz": b"fixture ffmpeg source\n",
            "ffmpeg-fixture.tar.xz.asc": b"fixture detached signature\n",
            "x264-fixture.tar.bz2": b"fixture x264 source\n",
            "lame-fixture.tar.gz": b"fixture lame source\n",
            "musl-fixture.tar.gz": b"fixture musl source\n",
            "nasm-fixture.tar.xz": b"fixture nasm source\n",
            "fortify-headers-fixture.tar.gz": b"fixture fortify headers source\n",
            "llvm-mingw-recipe-fixture.tar.gz": b"fixture llvm-mingw recipe source\n",
            "llvm-project-fixture.tar.gz": b"fixture llvm-project source\n",
            "mingw-w64-fixture.tar.gz": b"fixture mingw-w64 source\n",
        }
        values = {
            "BUILD_REVISION": "7",
            "SOURCE_DATE_EPOCH": "1700000000",
            "MACOS_MIN_VERSION": "12.0",
            "FFMPEG_VERSION": "9.0.1",
            "FFMPEG_ARCHIVE": "ffmpeg-fixture.tar.xz",
            "FFMPEG_URL": "https://example.invalid/ffmpeg-fixture.tar.xz",
            "FFMPEG_SHA256": self._digest(assets["ffmpeg-fixture.tar.xz"]),
            "FFMPEG_SIGNATURE_ARCHIVE": "ffmpeg-fixture.tar.xz.asc",
            "FFMPEG_SIGNATURE_URL": "https://example.invalid/ffmpeg-fixture.tar.xz.asc",
            "FFMPEG_SIGNATURE_SHA256": self._digest(
                assets["ffmpeg-fixture.tar.xz.asc"]
            ),
            "FFMPEG_PGP_FINGERPRINT": "A" * 40,
            "FFMPEG_LICENSE_SHA256": self._digest(b"fixture for FFmpeg-LICENSE.md\n"),
            "FFMPEG_GPLV2_SHA256": self._digest(b"fixture for FFmpeg-COPYING.GPLv2\n"),
            "FFMPEG_GPLV3_SHA256": self._digest(b"fixture for FFmpeg-COPYING.GPLv3\n"),
            "FFMPEG_IJG_NOTICE_SHA256": self._digest(
                b"fixture for FFmpeg-IJG-NOTICE.txt\n"
            ),
            "X264_REVISION": "b" * 40,
            "X264_ARCHIVE": "x264-fixture.tar.bz2",
            "X264_URL": "https://example.invalid/x264-fixture.tar.bz2",
            "X264_SHA256": self._digest(assets["x264-fixture.tar.bz2"]),
            "X264_LICENSE_SHA256": self._digest(b"fixture for x264-COPYING\n"),
            "X264_X86INC_ISC_SHA256": self._digest(
                b"fixture for x264-x86inc-ISC.txt\n"
            ),
            "LAME_VERSION": "4.0",
            "LAME_ARCHIVE": "lame-fixture.tar.gz",
            "LAME_URL": "https://example.invalid/lame-fixture.tar.gz",
            "LAME_SHA256": self._digest(assets["lame-fixture.tar.gz"]),
            "LAME_COPYING_SHA256": self._digest(b"fixture for LAME-COPYING\n"),
            "LAME_LICENSE_SHA256": self._digest(b"fixture for LAME-LICENSE\n"),
            "FFMPEG_LGPLV21_SHA256": self._digest(
                b"fixture for FFmpeg-COPYING.LGPLv2.1\n"
            ),
            "THIRD_PARTY_NOTICES_SHA256": self._digest(
                b"fixture for THIRD-PARTY-NOTICES.txt\n"
            ),
            "THIRD_PARTY_NOTICES_SIZE": str(
                len(b"fixture for THIRD-PARTY-NOTICES.txt\n")
            ),
            "MUSL_VERSION": "1.2.6",
            "MUSL_ARCHIVE": "musl-fixture.tar.gz",
            "MUSL_URL": "https://example.invalid/musl-fixture.tar.gz",
            "MUSL_SHA256": self._digest(assets["musl-fixture.tar.gz"]),
            "MUSL_COPYRIGHT_SHA256": self._digest(b"fixture for musl-COPYRIGHT\n"),
            "MUSL_QSORT_NOTICE_SHA256": "a" * 64,
            "MUSL_SUNPRO_NOTICE_SHA256": "b" * 64,
            "MUSL_ICONV_PATCH_SHA256": pipeline_lib.sha256_file(
                ROOT / "patches/musl-CVE-2026-6042.patch"
            ),
            "MUSL_QSORT_PATCH_SHA256": pipeline_lib.sha256_file(
                ROOT / "patches/musl-CVE-2026-40200.patch"
            ),
            "MUSL_PATCHED_ICONV_SHA256": "c" * 64,
            "MUSL_PATCHED_GB18030UTF_SHA256": "d" * 64,
            "MUSL_PATCHED_QSORT_SHA256": "e" * 64,
            "GCC_RUNTIME_EXCEPTION_SHA256": self._digest(
                b"fixture for GCC-RUNTIME-LIBRARY-EXCEPTION.txt\n"
            ),
            "NASM_VERSION": "2.16.03",
            "NASM_ARCHIVE": "nasm-fixture.tar.xz",
            "NASM_URL": "https://example.invalid/nasm-fixture.tar.xz",
            "NASM_SHA256": self._digest(assets["nasm-fixture.tar.xz"]),
            "FORTIFY_HEADERS_VERSION": "3.0.2",
            "FORTIFY_HEADERS_REVISION": "e7c86620bb0c0f8b868d3e4c8dcdebeeffb99631",
            "FORTIFY_HEADERS_ARCHIVE": "fortify-headers-fixture.tar.gz",
            "FORTIFY_HEADERS_URL": "https://example.invalid/fortify-headers-fixture.tar.gz",
            "FORTIFY_HEADERS_SHA256": self._digest(
                assets["fortify-headers-fixture.tar.gz"]
            ),
            "FORTIFY_HEADERS_LICENSE_SHA256": self._digest(
                b"fixture for fortify-headers-LICENSE\n"
            ),
            "LLVM_MINGW_VERSION": "20260616",
            "LLVM_MINGW_RECIPE_REVISION": "f" * 40,
            "LLVM_MINGW_RECIPE_ARCHIVE": "llvm-mingw-recipe-fixture.tar.gz",
            "LLVM_MINGW_RECIPE_URL": "https://example.invalid/llvm-mingw-recipe-fixture.tar.gz",
            "LLVM_MINGW_RECIPE_SHA256": self._digest(
                assets["llvm-mingw-recipe-fixture.tar.gz"]
            ),
            "LLVM_MINGW_ARCHIVE": "llvm-mingw-fixture.tar.xz",
            "LLVM_MINGW_URL": "https://example.invalid/llvm-mingw-fixture.tar.xz",
            "LLVM_MINGW_SHA256": "d" * 64,
            "LLVM_RUNTIME_VERSION": "22.1.8",
            "LLVM_RUNTIME_REVISION": "c" * 40,
            "LLVM_RUNTIME_ARCHIVE": "llvm-project-fixture.tar.gz",
            "LLVM_RUNTIME_URL": "https://example.invalid/llvm-project-fixture.tar.gz",
            "LLVM_RUNTIME_SHA256": self._digest(
                assets["llvm-project-fixture.tar.gz"]
            ),
            "MINGW_W64_VERSION": "15.0.0-alpha",
            "MINGW_W64_REVISION": "e" * 40,
            "MINGW_W64_ARCHIVE": "mingw-w64-fixture.tar.gz",
            "MINGW_W64_URL": "https://example.invalid/mingw-w64-fixture.tar.gz",
            "MINGW_W64_SHA256": self._digest(
                assets["mingw-w64-fixture.tar.gz"]
            ),
            "LLVM_LICENSE_SHA256": self._digest(b"fixture for LLVM-LICENSE.TXT\n"),
            "MINGW_RUNTIME_LICENSE_SHA256": self._digest(
                b"fixture for MinGW-w64-runtime-COPYING.txt\n"
            ),
        }
        lock = base / "sources.env"
        lock.parent.mkdir(parents=True, exist_ok=True)
        lock.write_text(
            "\n".join(f"{key}={value}" for key, value in values.items()) + "\n",
            encoding="utf-8",
        )
        return lock, assets

    def stage_source_assets(
        self, base: Path, lock: Path, assets: dict[str, bytes]
    ) -> Path:
        source_dir = base / "release-sources"
        (source_dir / "keys").mkdir(parents=True)
        sources = pipeline_lib.load_sources(lock)
        for name, data in assets.items():
            if name == sources["MINGW_W64_ARCHIVE"]:
                continue
            (source_dir / name).write_bytes(data)
        shutil.copyfile(lock, source_dir / "sources.env")
        shutil.copyfile(ROOT / "LICENSE", source_dir / "LICENSE")
        shutil.copyfile(
            ROOT / "keys/ffmpeg-release-signing-key.asc",
            source_dir / "keys/ffmpeg-release-signing-key.asc",
        )
        for name in assemble_release.BUILD_PIPELINE_FILES:
            if name in {"LICENSE", "sources.env", "keys/ffmpeg-release-signing-key.asc"}:
                continue
            destination = source_dir / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, destination)
        return source_dir

    def dependencies(
        self, target: str, sources: dict[str, str]
    ) -> list[dict[str, str]]:
        platform = pipeline_lib.TARGETS[target]["platform"]
        if platform == "linux":
            return [
                {
                    "name": "fortify-headers",
                    "version": sources["FORTIFY_HEADERS_REVISION"],
                    "license": "0BSD",
                    "relationship": "header-inline",
                },
                {
                    "name": "gcc-runtime",
                    "version": "13.2.0",
                    "license": "GPL-3.0-or-later WITH GCC-exception-3.1",
                    "relationship": "static-link",
                },
                {
                    "name": "musl",
                    "version": sources["MUSL_VERSION"],
                    "license": "MIT AND SunPro",
                    "relationship": "static-link",
                },
            ]
        if platform == "win32":
            return [
                {
                    "name": "llvm-compiler-rt",
                    "version": sources["LLVM_RUNTIME_VERSION"],
                    "license": "Apache-2.0 WITH LLVM-exception",
                    "relationship": "static-link",
                },
                {
                    "name": "mingw-w64-runtime",
                    "version": sources["MINGW_W64_VERSION"],
                    "license": "LicenseRef-MinGW-w64-runtime",
                    "relationship": "static-link",
                },
            ]
        return []

    def build_contract(
        self, target: str, sources: dict[str, str], configure: list[str]
    ) -> dict[str, object]:
        target_info = pipeline_lib.TARGETS[target]
        platform = target_info["platform"]
        arch = target_info["arch"]
        configure_arch = "aarch64" if arch == "arm64" else "x86_64"
        if platform == "darwin":
            compiler = "clang"
            compiler_version = "Apple clang version 18.0.0"
            toolchain = {
                "name": "apple-clang-sdk",
                "version": "15.0",
                "url": "",
                "sha256": "",
            }
            linker = "ld"
            commands = ("ar", "ranlib", "strip", "nm", "strings")
            fortify = "system-headers-level-2"
            link_provenance = "platform-system"
            sdk = "15.0"
        elif platform == "linux":
            compiler = "musl-gcc"
            compiler_version = "gcc (fixture) 13.2.0"
            toolchain = {
                "name": "source-built-musl",
                "version": sources["MUSL_VERSION"],
                "url": sources["MUSL_URL"],
                "sha256": sources["MUSL_SHA256"],
            }
            linker = "ld"
            commands = ("ar", "ranlib", "strip", "nm", "strings")
            fortify = (
                f"{sources['FORTIFY_HEADERS_VERSION']}@"
                f"{sources['FORTIFY_HEADERS_REVISION']}:runtime-trap-verified"
            )
            link_provenance = "validated-private-musl-link-maps"
            sdk = ""
        else:
            compiler = f"{configure_arch}-w64-mingw32-clang"
            compiler_version = "clang version 22.1.8 (fixture)"
            toolchain = {
                "name": "llvm-mingw-ucrt",
                "version": sources["LLVM_MINGW_VERSION"],
                "url": sources["LLVM_MINGW_URL"],
                "sha256": sources["LLVM_MINGW_SHA256"],
            }
            linker = "ld.lld"
            commands = (
                "llvm-ar",
                "llvm-ranlib",
                "llvm-strip",
                "llvm-nm",
                "llvm-strings",
            )
            fortify = "not-applicable"
            link_provenance = "validated-ucrt-system-import-allowlist"
            sdk = ""
        ar, ranlib, strip, nm, strings = commands
        return {
            "schemaVersion": 1,
            "target": target,
            "platform": platform,
            "arch": arch,
            "minimumOs": pipeline_lib.minimum_os(target, sources),
            "license": pipeline_lib.artifact_license(target),
            "compiler": {"command": compiler, "version": compiler_version},
            "toolchain": toolchain,
            "tools": {
                "linker": {"command": linker, "version": "fixture linker 1.0"},
                "binutils": {
                    "ar": ar,
                    "ranlib": ranlib,
                    "strip": strip,
                    "nm": nm,
                    "strings": strings,
                    "version": "fixture binutils 1.0",
                },
                "nasm": (
                    {
                        "binarySha256": "9" * 64,
                        "command": "nasm",
                        "sourceSha256": sources["NASM_SHA256"],
                        "sourceUrl": sources["NASM_URL"],
                        "sourceVersion": sources["NASM_VERSION"],
                        "version": "NASM version 2.16.03 compiled on Nov 14 2023",
                    }
                    if arch == "x64"
                    else None
                ),
                "pkgConfig": {"command": "pkg-config", "version": "2.0"},
                "make": {"command": "make", "version": "GNU Make 4.4"},
                "python": {"command": "python3", "version": "Python 3.12"},
                "tar": {"command": "tar", "version": "tar 1.35"},
                "macosSdkVersion": sdk,
            },
            "hardening": {
                "fortify": fortify,
                "linkProvenance": link_provenance,
            },
            "configure": configure,
            "dependencies": self.dependencies(target, sources),
            "sources": {
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
            },
        }

    def make_payload(
        self, base: Path, target: str, lock: Path
    ) -> tuple[Path, Path]:
        target_info = pipeline_lib.TARGETS[target]
        sources = pipeline_lib.load_sources(lock)
        payload = base / f"payload-{target}"
        licenses = payload / "LICENSES"
        licenses.mkdir(parents=True)
        suffix = ".exe" if target_info["platform"] == "win32" else ""
        for program in (f"ffmpeg{suffix}", f"ffprobe{suffix}"):
            path = payload / program
            path.write_bytes(f"fake {target} {program}\n".encode())
            path.chmod(0o755)
        configure = pipeline_lib.expected_configure_args(target, sources)
        (payload / "configure.txt").write_text(
            "./configure " + shlex.join(configure) + "\n", encoding="utf-8"
        )
        for name in pipeline_lib.required_license_files(target):
            (licenses / name).write_text(f"fixture for {name}\n", encoding="utf-8")

        build_info = base / f"build-info-{target}.json"
        build_info.write_text(
            json.dumps(
                self.build_contract(target, sources, configure),
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        return payload, build_info

    def make_signing_input(self, base: Path, target: str, lock: Path) -> Path:
        payload, build_info = self.make_payload(base, target, lock)
        input_root = base / f"signing-input-{target}"
        shutil.copytree(payload, input_root / "payload")
        shutil.copyfile(build_info, input_root / "build-info.json")
        shutil.copyfile(lock, input_root / "sources.env")
        if target.endswith("-x64"):
            nasm = input_root / "work/nasm/bin/nasm"
            nasm.parent.mkdir(parents=True)
            nasm.write_bytes(b"fixture NASM build evidence\r\n\x1a\xff\0")
            info = json.loads((input_root / "build-info.json").read_bytes())
            info["tools"]["nasm"]["binarySha256"] = pipeline_lib.sha256_file(nasm)
            (input_root / "build-info.json").write_text(
                json.dumps(info, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
        if target.startswith("win32-"):
            maps = input_root / "work/link-maps"
            maps.mkdir(parents=True)
            for program in ("ffmpeg", "ffprobe"):
                (maps / f"{program}.map").write_text(
                    f"fixture map for {program}\n", encoding="utf-8"
                )
                (maps / f"{program}.link-trace.txt").write_text(
                    f"fixture trace for {program}\n", encoding="utf-8"
                )
        return input_root

    def signing_evidence(
        self,
        payload: Path,
        target: str,
        *,
        submission_result: Path | None = None,
        developer_log: Path | None = None,
        archive: Path | None = None,
    ) -> dict[str, object]:
        platform = pipeline_lib.TARGETS[target]["platform"]
        suffix = ".exe" if platform == "win32" else ""
        binaries = {
            f"ffmpeg{suffix}": {
                "sha256": pipeline_lib.sha256_file(payload / f"ffmpeg{suffix}"),
                "timestamp": "2026-08-29T00:00:00Z",
            },
            f"ffprobe{suffix}": {
                "sha256": pipeline_lib.sha256_file(payload / f"ffprobe{suffix}"),
                "timestamp": "2026-08-29T00:00:00Z",
            },
        }
        if platform == "darwin":
            for record in binaries.values():
                record["cdHash"] = "e" * 40
                record["hardenedRuntime"] = True
            return {
                "schemaVersion": 3,
                "target": target,
                "platform": "darwin",
                "kind": "apple-developer-id",
                "identity": {
                    "teamId": MAC_TEAM_ID,
                    "subject": f"Developer ID Application: Motrix Test ({MAC_TEAM_ID})",
                    "certificateSha256": MAC_CERT_SHA256,
                },
                "binaries": binaries,
                "notarization": {
                    "submissionId": "123e4567-e89b-42d3-a456-426614174000",
                    "status": "Accepted",
                    "submissionResultSha256": (
                        pipeline_lib.sha256_file(submission_result)
                        if submission_result is not None
                        else "f" * 64
                    ),
                    "developerLog": {
                        "name": (
                            f"{archive.stem}.notarization-log.json"
                            if archive is not None
                            else f"ffmpeg-9.0.1-motrix.7-{target}.notarization-log.json"
                        ),
                        "sha256": (
                            pipeline_lib.sha256_file(developer_log)
                            if developer_log is not None
                            else "e" * 64
                        ),
                        "size": (
                            developer_log.stat().st_size
                            if developer_log is not None
                            else 1
                        ),
                    },
                },
            }
        if platform == "win32":
            for record in binaries.values():
                del record["timestamp"]
                record["status"] = "Valid"
                record["timestamped"] = True
                record["timestampAuthorityCertificateSha256"] = "9" * 64
            return {
                "schemaVersion": 3,
                "target": target,
                "platform": "win32",
                "kind": "authenticode",
                "identity": {
                    "subject": WINDOWS_SUBJECT,
                    "thumbprint": WINDOWS_CERT_SHA256,
                    "thumbprintAlgorithm": "SHA256",
                },
                "tool": {
                    "name": "Microsoft SignTool",
                    "version": "10.0.26100.0",
                    "architecture": pipeline_lib.TARGETS[target]["arch"],
                    "sha256": "8" * 64,
                    "signerSubject": "CN=Microsoft Corporation",
                },
                "binaries": binaries,
            }
        raise ValueError("Linux fixtures do not use signing evidence")

    def package_target(
        self,
        base: Path,
        output: Path,
        target: str,
        lock: Path,
        *,
        signed: bool = False,
    ) -> Path:
        payload, build_info = self.make_payload(base, target, lock)
        arguments: list[object] = [
            "--target",
            target,
            "--payload",
            payload,
            "--build-info",
            build_info,
            "--output-dir",
            output,
            "--sources-file",
            lock,
        ]
        if signed and target.startswith("darwin-"):
            self.run_script("package-artifact.py", *arguments)
            sources = pipeline_lib.load_sources(lock)
            archive = output / (
                f"{pipeline_lib.artifact_stem(sources, target)}."
                f"{pipeline_lib.TARGETS[target]['extension']}"
            )
            submission_result = base / f"notarization-submission-{target}.json"
            submission_result.write_text(
                json.dumps(
                    {
                        "id": "123e4567-e89b-42d3-a456-426614174000",
                        "status": "Accepted",
                    },
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )
            developer_log = base / f"notarization-log-{target}.json"
            developer_log.write_text(
                json.dumps(
                    {
                        "logFormatVersion": 1,
                        "jobId": "123e4567-e89b-42d3-a456-426614174000",
                        "status": "Accepted",
                        "statusCode": 0,
                        "archiveFilename": archive.name,
                        "sha256": pipeline_lib.sha256_file(archive),
                        "issues": None,
                    },
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )
            evidence = base / f"signing-{target}.json"
            evidence.write_text(
                json.dumps(
                    self.signing_evidence(
                        payload,
                        target,
                        submission_result=submission_result,
                        developer_log=developer_log,
                        archive=archive,
                    )
                ),
                encoding="utf-8",
            )
            arguments.extend(
                [
                    "--signing-evidence",
                    evidence,
                    "--notarization-submission-result",
                    submission_result,
                    "--notarization-log",
                    developer_log,
                ]
            )
        elif signed and not target.startswith("linux-"):
            evidence = base / f"signing-{target}.json"
            evidence.write_text(
                json.dumps(self.signing_evidence(payload, target)), encoding="utf-8"
            )
            arguments.extend(["--signing-evidence", evidence])
        self.run_script("package-artifact.py", *arguments)
        sources = pipeline_lib.load_sources(lock)
        target_info = pipeline_lib.TARGETS[target]
        return output / (
            f"{pipeline_lib.artifact_stem(sources, target)}."
            f"{target_info['extension']}"
        )

    def make_release_inputs(
        self,
        base: Path,
        lock: Path,
        targets: tuple[str, ...] = EXPECTED_TARGETS,
        *,
        signed: bool,
    ) -> Path:
        inputs = base / "inputs"
        inputs.mkdir()
        fixtures = base / "fixtures"
        fixtures.mkdir()
        for target in targets:
            self.package_target(
                fixtures,
                inputs,
                target,
                lock,
                signed=signed,
            )
        return inputs

    def assemble_arguments(
        self,
        inputs: Path,
        source_dir: Path,
        output: Path,
        lock: Path,
        *,
        formal: bool = False,
    ) -> list[object]:
        arguments: list[object] = [
            "--input-dir",
            inputs,
            "--source-dir",
            source_dir,
            "--output-dir",
            output,
            "--sources-file",
            lock,
            "--document-created",
            "2026-08-29T00:00:00Z",
        ]
        if formal:
            sources = pipeline_lib.load_sources(lock)
            arguments.extend(
                [
                    "--release-tag",
                    pipeline_lib.release_tag(sources),
                    "--event-sha",
                    EVENT_SHA,
                    "--control-sha",
                    CONTROL_SHA,
                    "--tag-object-sha",
                    TAG_OBJECT_SHA,
                    "--expected-macos-team-id",
                    MAC_TEAM_ID,
                    "--expected-macos-cert-sha256",
                    MAC_CERT_SHA256,
                    "--expected-windows-subject",
                    WINDOWS_SUBJECT,
                    "--expected-windows-thumbprint",
                    WINDOWS_CERT_SHA256,
                ]
            )
        return arguments

    def test_target_matrix_is_exactly_the_six_motrix_targets(self) -> None:
        self.assertEqual(tuple(pipeline_lib.TARGETS), EXPECTED_TARGETS)
        self.assertEqual(
            pipeline_lib.TARGETS["win32-arm64"],
            {"platform": "win32", "arch": "arm64", "extension": "zip"},
        )

    def test_linux_minimum_os_is_architecture_specific_and_fail_closed(self) -> None:
        expected = {
            "linux-arm64": {"name": "linux", "version": "3.7.0"},
            "linux-x64": {"name": "linux", "version": "2.6.39"},
        }
        swapped = {
            "linux-arm64": expected["linux-x64"],
            "linux-x64": expected["linux-arm64"],
        }
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            lock, _assets = self.make_sources(base)
            sources = pipeline_lib.load_sources(lock)
            for target in expected:
                with self.subTest(target=target):
                    self.assertEqual(
                        pipeline_lib.minimum_os(target, sources), expected[target]
                    )

                    correct = base / f"correct-{target}"
                    archive = self.package_target(
                        correct, correct / "out", target, lock
                    )
                    metadata = json.loads(
                        archive.with_name(
                            archive.name + ".metadata.json"
                        ).read_text(encoding="utf-8")
                    )
                    archived_build_info = json.loads(
                        assemble_release.archive_files(archive)["BUILD-INFO.json"]
                    )
                    self.assertEqual(metadata["minimumOs"], expected[target])
                    self.assertEqual(
                        archived_build_info["minimumOs"], expected[target]
                    )

                    wrong = base / f"wrong-{target}"
                    payload, build_info = self.make_payload(wrong, target, lock)
                    info = json.loads(build_info.read_text(encoding="utf-8"))
                    info["minimumOs"] = swapped[target]
                    build_info.write_text(json.dumps(info), encoding="utf-8")
                    result = self.run_script(
                        "package-artifact.py",
                        "--target",
                        target,
                        "--payload",
                        payload,
                        "--build-info",
                        build_info,
                        "--output-dir",
                        wrong / "out",
                        "--sources-file",
                        lock,
                        check=False,
                    )
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(
                        "unexpected minimum OS contract", result.stderr
                    )

                    metadata["minimumOs"] = swapped[target]
                    metadata_path = archive.with_name(
                        archive.name + ".metadata.json"
                    )
                    metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
                    with self.assertRaisesRegex(
                        ValueError, "minimum OS contract mismatch"
                    ):
                        assemble_release.verify_target(metadata_path, sources)

            with mock.patch.dict(
                pipeline_lib.TARGETS,
                {
                    "linux-riscv64": {
                        "platform": "linux",
                        "arch": "riscv64",
                        "extension": "tar.gz",
                    }
                },
            ):
                with self.assertRaisesRegex(
                    ValueError,
                    "minimum OS contract is not defined for linux-riscv64",
                ):
                    pipeline_lib.minimum_os("linux-riscv64", sources)

            for script in ("build.sh", "verify-binary.sh"):
                script_text = (SCRIPTS / script).read_text(encoding="utf-8")
                self.assertIn("pipeline_lib.minimum_os", script_text)
                self.assertNotIn('"version":"3.7.0"', script_text)
                self.assertNotIn('"version":"2.6.39"', script_text)

    def test_protected_file_readers_preserve_windows_binary_bytes_and_flags(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "binary"
            data = b"MZ\r\n\x1a\xff\0\r\nlast bytes"
            path.write_bytes(data)
            actual_open = os.open
            binary_flag = getattr(os, "O_BINARY", 0x8000)

            def binary_open(name, flags):
                self.assertTrue(flags & binary_flag)
                native_flags = flags if os.name == "nt" else flags & ~binary_flag
                return actual_open(name, native_flags)

            with mock.patch.object(os, "O_BINARY", binary_flag, create=True), mock.patch.object(
                os, "open", side_effect=binary_open
            ):
                for reader in (
                    validate_signing_input._read_regular,
                    finalize_signing_grant._read_regular,
                ):
                    self.assertEqual(reader(path, len(data)), data)
                    with self.assertRaises(ValueError):
                        reader(path, len(data) - 1)

    def test_x64_presign_nasm_evidence_is_exact_bounded_and_hash_bound(self) -> None:
        for target in ("darwin-x64", "win32-x64"):
            with self.subTest(target=target), tempfile.TemporaryDirectory() as temporary:
                base = Path(temporary)
                lock, _assets = self.make_sources(base)
                input_root = self.make_signing_input(base, target, lock)
                rebuild_root = base / "independent-rebuild"
                shutil.copytree(input_root, rebuild_root)
                evidence = input_root / "work/nasm/bin/nasm"
                kwargs = dict(
                    target=target, input_root=input_root, rebuild_root=rebuild_root,
                    artifact_id=1, artifact_digest="a" * 64,
                    rebuild_artifact_id=2, rebuild_artifact_digest="b" * 64,
                    control_sha="c" * 40, run_id=3,
                )
                with mock.patch.object(validate_signing_input, "ROOT", base):
                    validate_signing_input.signing_approval(**kwargs)
                    original = evidence.read_bytes()
                    evidence.unlink()
                    with self.assertRaisesRegex(ValueError, "file set mismatch"):
                        validate_signing_input.signing_approval(**kwargs)
                    evidence.write_bytes(b"tampered NASM")
                    with self.assertRaisesRegex(ValueError, "NASM evidence differs"):
                        validate_signing_input.signing_approval(**kwargs)
                    evidence.write_bytes(original)
                    with mock.patch.object(validate_signing_input, "MAX_INPUT_BYTES", 1):
                        with self.assertRaisesRegex(ValueError, "total size limit"):
                            validate_signing_input.signing_approval(**kwargs)
                    info_path = rebuild_root / "build-info.json"
                    info = json.loads(info_path.read_bytes())
                    replacement = rebuild_root / "work/nasm/bin/nasm"
                    replacement.write_bytes(b"different independently built NASM")
                    info["tools"]["nasm"]["binarySha256"] = pipeline_lib.sha256_file(replacement)
                    info_path.write_text(json.dumps(info), encoding="utf-8")
                    with self.assertRaisesRegex(ValueError, "not byte-for-byte reproducible"):
                        validate_signing_input.signing_approval(**kwargs)
                self.assertNotIn(
                    "work/nasm/bin/nasm", validate_signing_input._expected_files("win32-arm64")
                )

    def test_presign_approval_binds_exact_tree_and_binary_hashes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            lock, _assets = self.make_sources(base)
            input_root = self.make_signing_input(base, "darwin-arm64", lock)
            rebuild_root = base / "rebuild-darwin-arm64"
            shutil.copytree(input_root, rebuild_root)
            with mock.patch.object(validate_signing_input, "ROOT", base):
                approval = validate_signing_input.signing_approval(
                    target="darwin-arm64",
                    input_root=input_root,
                    rebuild_root=rebuild_root,
                    artifact_id=41,
                    artifact_digest="a" * 64,
                    rebuild_artifact_id=42,
                    rebuild_artifact_digest="e" * 64,
                    control_sha="b" * 40,
                    run_id=99,
                )
                self.assertEqual(approval["schemaVersion"], 2)
                self.assertEqual(approval["inputArtifactId"], 41)
                self.assertEqual(
                    approval["binaries"]["ffmpeg"],
                    pipeline_lib.sha256_file(input_root / "payload/ffmpeg"),
                )
                before = approval["inputTreeSha256"]
                (input_root / "payload/ffmpeg").write_bytes(b"different binary\n")
                with self.assertRaisesRegex(ValueError, "not byte-for-byte reproducible"):
                    validate_signing_input.signing_approval(
                        target="darwin-arm64",
                        input_root=input_root,
                        rebuild_root=rebuild_root,
                        artifact_id=41,
                        artifact_digest="a" * 64,
                        rebuild_artifact_id=42,
                        rebuild_artifact_digest="e" * 64,
                        control_sha="b" * 40,
                        run_id=99,
                    )
                (rebuild_root / "payload/ffmpeg").write_bytes(b"different binary\n")
                changed = validate_signing_input.signing_approval(
                    target="darwin-arm64",
                    input_root=input_root,
                    rebuild_root=rebuild_root,
                    artifact_id=41,
                    artifact_digest="a" * 64,
                    rebuild_artifact_id=42,
                    rebuild_artifact_digest="e" * 64,
                    control_sha="b" * 40,
                    run_id=99,
                )
                self.assertNotEqual(before, changed["inputTreeSha256"])
                self.assertNotEqual(
                    approval["binaries"]["ffmpeg"], changed["binaries"]["ffmpeg"]
                )

    def test_presign_approval_rejects_extra_or_missing_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            lock, _assets = self.make_sources(base)
            darwin = self.make_signing_input(base, "darwin-x64", lock)
            darwin_rebuild = base / "rebuild-darwin-x64"
            shutil.copytree(darwin, darwin_rebuild)
            (darwin / "unexpected").write_text("no\n", encoding="utf-8")
            windows = self.make_signing_input(base, "win32-arm64", lock)
            windows_rebuild = base / "rebuild-win32-arm64"
            shutil.copytree(windows, windows_rebuild)
            (windows / "work/link-maps/ffprobe.link-trace.txt").unlink()
            with mock.patch.object(validate_signing_input, "ROOT", base):
                for target, input_root, rebuild_root in (
                    ("darwin-x64", darwin, darwin_rebuild),
                    ("win32-arm64", windows, windows_rebuild),
                ):
                    with self.subTest(target=target), self.assertRaisesRegex(
                        ValueError, "file set mismatch"
                    ):
                        validate_signing_input.signing_approval(
                            target=target,
                            input_root=input_root,
                            rebuild_root=rebuild_root,
                            artifact_id=1,
                            artifact_digest="c" * 64,
                            rebuild_artifact_id=3,
                            rebuild_artifact_digest="e" * 64,
                            control_sha="d" * 40,
                            run_id=2,
                        )

    def test_presign_validator_starts_under_isolated_python(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            lock, _assets = self.make_sources(base)
            input_root = self.make_signing_input(base, "darwin-arm64", lock)
            rebuild_root = base / "rebuild-darwin-arm64"
            shutil.copytree(input_root, rebuild_root)
            isolated_scripts = base / "scripts"
            isolated_scripts.mkdir()
            for name in ("pipeline_lib.py", "validate_signing_input.py"):
                shutil.copyfile(SCRIPTS / name, isolated_scripts / name)
            approval = base / "approval.json"
            common = [
                sys.executable,
                "-I",
                str(isolated_scripts / "validate_signing_input.py"),
                "--target",
                "darwin-arm64",
                "--input-dir",
                str(input_root),
                "--rebuild-dir",
                str(rebuild_root),
                "--artifact-id",
                "7",
                "--artifact-digest",
                "a" * 64,
                "--rebuild-artifact-id",
                "9",
                "--rebuild-artifact-digest",
                "e" * 64,
                "--control-sha",
                "b" * 40,
                "--run-id",
                "8",
            ]
            written = subprocess.run(
                [*common, "--write-approval", str(approval)],
                cwd=base,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(written.returncode, 0, written.stderr)
            verified = subprocess.run(
                [*common, "--verify-approval", str(approval)],
                cwd=base,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(verified.returncode, 0, verified.stderr)

    def test_final_signing_grant_is_canonical_and_tamper_evident(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            lock, _assets = self.make_sources(base)
            input_root = self.make_signing_input(base, "win32-arm64", lock)
            rebuild_root = base / "rebuild-win32-arm64"
            shutil.copytree(input_root, rebuild_root)
            with mock.patch.object(validate_signing_input, "ROOT", base):
                approval = validate_signing_input.signing_approval(
                    target="win32-arm64",
                    input_root=input_root,
                    rebuild_root=rebuild_root,
                    artifact_id=31,
                    artifact_digest="a" * 64,
                    rebuild_artifact_id=32,
                    rebuild_artifact_digest="b" * 64,
                    control_sha="c" * 40,
                    run_id=33,
                )
            approval_path = base / "approval.json"
            approval_path.write_bytes(pipeline_lib.canonical_json(approval))
            grant = finalize_signing_grant.signing_grant(
                approval_kind="windows-native",
                target="win32-arm64",
                approval_file=approval_path,
                approval_artifact_id=34,
                approval_artifact_digest="d" * 64,
                candidate_artifact_id=31,
                candidate_artifact_digest="a" * 64,
                rebuild_artifact_id=32,
                rebuild_artifact_digest="b" * 64,
                control_sha="c" * 40,
                run_id=33,
            )
            self.assertEqual(grant["schemaVersion"], 1)
            self.assertEqual(grant["approvalKind"], "windows-native")
            self.assertEqual(
                grant["approvalArtifact"],
                {
                    "name": "presign-native-approval-win32-arm64",
                    "id": 34,
                    "digest": "d" * 64,
                },
            )
            self.assertEqual(grant["candidateArtifact"]["id"], 31)
            self.assertEqual(grant["rebuildArtifact"]["id"], 32)

            isolated_scripts = base / "scripts"
            isolated_scripts.mkdir()
            for name in ("pipeline_lib.py", "finalize_signing_grant.py"):
                shutil.copyfile(SCRIPTS / name, isolated_scripts / name)
            grant_path = base / "grant.json"
            common = [
                sys.executable,
                "-I",
                str(isolated_scripts / "finalize_signing_grant.py"),
                "--approval-kind",
                "windows-native",
                "--target",
                "win32-arm64",
                "--approval-file",
                str(approval_path),
                "--approval-artifact-id",
                "34",
                "--approval-artifact-digest",
                "d" * 64,
                "--candidate-artifact-id",
                "31",
                "--candidate-artifact-digest",
                "a" * 64,
                "--rebuild-artifact-id",
                "32",
                "--rebuild-artifact-digest",
                "b" * 64,
                "--control-sha",
                "c" * 40,
                "--run-id",
                "33",
            ]
            written = subprocess.run(
                [*common, "--write-grant", str(grant_path)],
                cwd=base,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(written.returncode, 0, written.stderr)
            self.assertEqual(grant_path.read_bytes(), pipeline_lib.canonical_json(grant))
            verified = subprocess.run(
                [*common, "--verify-grant", str(grant_path)],
                cwd=base,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(verified.returncode, 0, verified.stderr)

            tampered = dict(grant)
            tampered["approvalKind"] = "windows-static"
            grant_path.write_bytes(pipeline_lib.canonical_json(tampered))
            rejected = subprocess.run(
                [*common, "--verify-grant", str(grant_path)],
                cwd=base,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(rejected.returncode, 0)

    def test_sources_parser_accepts_complete_lock_and_rejects_bad_input(self) -> None:
        production = pipeline_lib.load_sources()
        self.assertEqual(production["MUSL_VERSION"], "1.2.6")
        self.assertEqual(production["FORTIFY_HEADERS_VERSION"], "3.0.2")
        self.assertEqual(
            production["FORTIFY_HEADERS_REVISION"],
            "e7c86620bb0c0f8b868d3e4c8dcdebeeffb99631",
        )
        self.assertEqual(
            production["FORTIFY_HEADERS_URL"],
            "https://github.com/jvoisin/fortify-headers/archive/refs/tags/3.0.2.tar.gz",
        )
        self.assertEqual(
            production["FORTIFY_HEADERS_SHA256"],
            "a4aab14c56eb00239cbd61ac65b3e778cf29ec82f06116ba343a50552882f587",
        )
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            lock, _assets = self.make_sources(base)
            sources = pipeline_lib.load_sources(lock)
            self.assertEqual(sources["MUSL_VERSION"], "1.2.6")
            self.assertRegex(sources["FFMPEG_SHA256"], r"^[0-9a-f]{64}$")
            with mock.patch.object(pipeline_lib, "MAX_SOURCES_FILE_BYTES", 4):
                with self.assertRaisesRegex(ValueError, "source lock exceeds 4 bytes"):
                    pipeline_lib.load_sources(lock)

            missing = base / "missing.env"
            missing.write_text(
                "\n".join(
                    line
                    for line in lock.read_text(encoding="utf-8").splitlines()
                    if not line.startswith("MUSL_SHA256=")
                )
                + "\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "missing keys: MUSL_SHA256"):
                pipeline_lib.load_sources(missing)

            unsafe = base / "unsafe.env"
            unsafe.write_text(
                lock.read_text(encoding="utf-8").replace(
                    "https://example.invalid/ffmpeg-fixture.tar.xz",
                    "https://example.invalid/source;touch-bad",
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "unsafe value for FFMPEG_URL"):
                pipeline_lib.load_sources(unsafe)

            duplicate = base / "duplicate.env"
            duplicate.write_text(
                lock.read_text(encoding="utf-8") + "BUILD_REVISION=8\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "duplicate key BUILD_REVISION"):
                pipeline_lib.load_sources(duplicate)

            unknown = base / "unknown.env"
            unknown.write_text(
                lock.read_text(encoding="utf-8") + "PATH=.\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "unknown keys: PATH"):
                pipeline_lib.load_sources(unknown)

            insecure = base / "insecure.env"
            insecure.write_text(
                lock.read_text(encoding="utf-8").replace(
                    "https://example.invalid/musl-fixture.tar.gz",
                    "http://example.invalid/musl-fixture.tar.gz",
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "MUSL_URL must be a credential-free HTTPS URL"):
                pipeline_lib.load_sources(insecure)

            traversal = base / "traversal.env"
            traversal.write_text(
                lock.read_text(encoding="utf-8").replace(
                    "FFMPEG_VERSION=9.0.1",
                    "FFMPEG_VERSION=x/../../../escaped",
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "FFMPEG_VERSION has an unsafe"):
                pipeline_lib.load_sources(traversal)

            credential_url = base / "credential-url.env"
            credential_url.write_text(
                lock.read_text(encoding="utf-8").replace(
                    "https://example.invalid/musl-fixture.tar.gz",
                    "https://user@example.invalid/musl-fixture.tar.gz",
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "credential-free HTTPS URL"):
                pipeline_lib.load_sources(credential_url)

            recipe_credential_url = base / "recipe-credential-url.env"
            recipe_credential_url.write_text(
                lock.read_text(encoding="utf-8").replace(
                    "https://example.invalid/llvm-mingw-recipe-fixture.tar.gz",
                    "https://user@example.invalid/llvm-mingw-recipe-fixture.tar.gz",
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                ValueError,
                "LLVM_MINGW_RECIPE_URL must be a credential-free HTTPS URL",
            ):
                pipeline_lib.load_sources(recipe_credential_url)

            for epoch, label in (
                ("1700000001", "odd"),
                ("315532798", "before-zip-range"),
                ("4354819200", "after-zip-range"),
            ):
                with self.subTest(source_epoch=label):
                    invalid_epoch = base / f"{label}.env"
                    invalid_epoch.write_text(
                        lock.read_text(encoding="utf-8").replace(
                            "SOURCE_DATE_EPOCH=1700000000",
                            f"SOURCE_DATE_EPOCH={epoch}",
                        ),
                        encoding="utf-8",
                    )
                    with self.assertRaisesRegex(ValueError, "ZIP DOS range"):
                        pipeline_lib.load_sources(invalid_epoch)

            reserved_archive = base / "reserved-archive.env"
            reserved_archive.write_text(
                lock.read_text(encoding="utf-8").replace(
                    "FFMPEG_ARCHIVE=ffmpeg-fixture.tar.xz",
                    "FFMPEG_ARCHIVE=SHA256SUMS",
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                ValueError, "archive names collide with reserved release assets"
            ):
                pipeline_lib.load_sources(reserved_archive)

            casefold_collision = base / "casefold-collision.env"
            casefold_collision.write_text(
                lock.read_text(encoding="utf-8").replace(
                    "FFMPEG_ARCHIVE=ffmpeg-fixture.tar.xz",
                    "FFMPEG_ARCHIVE=FFMPEG-MANIFEST.JSON",
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                ValueError, "archive names collide with reserved release assets"
            ):
                pipeline_lib.load_sources(casefold_collision)

            for unsafe_name in ("NUL.txt", "source."):
                with self.subTest(unsafe_name=unsafe_name):
                    unsafe_archive = base / f"unsafe-{unsafe_name.replace('.', '-')}.env"
                    unsafe_archive.write_text(
                        lock.read_text(encoding="utf-8").replace(
                            "FFMPEG_ARCHIVE=ffmpeg-fixture.tar.xz",
                            f"FFMPEG_ARCHIVE={unsafe_name}",
                        ),
                        encoding="utf-8",
                    )
                    with self.assertRaisesRegex(ValueError, "unsafe archive name"):
                        pipeline_lib.load_sources(unsafe_archive)

    def test_configure_parser_requires_exact_tokens_and_rejects_nonfree(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            lock, _assets = self.make_sources(Path(temporary))
            sources = pipeline_lib.load_sources(lock)
            build_script = (SCRIPTS / "build.sh").read_text(encoding="utf-8")
            self.assertIn(
                'TARGET_CFLAGS="-O2 -fPIE -fstack-protector-strong '
                '-U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3 -Wformat '
                '-Wformat-security -Werror=format-security ${ARCH_HARDENING}"',
                build_script,
            )
            self.assertIn(
                "FFMPEG_CONFIGURE_ARGS+=(--target-os=linux --host-cc=gcc)",
                build_script,
            )
            expected_cflags = {
                "linux-x64": (
                    "-I../src/fortify-headers/include -O2 -fPIE "
                    "-fstack-protector-strong -U_FORTIFY_SOURCE "
                    "-D_FORTIFY_SOURCE=3 -Wformat -Wformat-security "
                    "-Werror=format-security -fcf-protection=full"
                ),
                "linux-arm64": (
                    "-I../src/fortify-headers/include -O2 -fPIE "
                    "-fstack-protector-strong -U_FORTIFY_SOURCE "
                    "-D_FORTIFY_SOURCE=3 -Wformat -Wformat-security "
                    "-Werror=format-security -mbranch-protection=standard "
                    "-mno-outline-atomics"
                ),
            }
            expected_ldflags = (
                "-static-pie "
                "-Wl,-z,relro,-z,now,-z,noexecstack,-z,separate-code,"
                "--build-id=sha1 -Wl,-z,stack-size=2097152"
            )
            for target, cflags in expected_cflags.items():
                with self.subTest(target=target):
                    arguments = pipeline_lib.expected_configure_args(target, sources)
                    self.assertEqual(
                        arguments[-2:], ["--target-os=linux", "--host-cc=gcc"]
                    )
                    self.assertIn(f"--extra-cflags={cflags}", arguments)
                    self.assertIn(f"--extra-ldflags={expected_ldflags}", arguments)
                    valid = ("./configure " + shlex.join(arguments)).encode()
                    self.assertEqual(
                        pipeline_lib.parse_configure_record(valid), arguments
                    )
                    pipeline_lib.validate_build_info(
                        self.build_contract(target, sources, arguments),
                        target,
                        sources,
                        arguments,
                    )
            arguments = pipeline_lib.expected_configure_args("linux-x64", sources)
        valid = ("./configure " + shlex.join(arguments)).encode()
        self.assertEqual(pipeline_lib.parse_configure_record(valid), arguments)
        deceptive = valid.replace(b"--enable-gpl", b"--enable-gpl=false")
        with self.assertRaisesRegex(ValueError, "missing exact flag --enable-gpl"):
            pipeline_lib.parse_configure_record(deceptive)
        with self.assertRaisesRegex(ValueError, "forbidden flag --enable-nonfree=yes"):
            pipeline_lib.parse_configure_record(valid + b" --enable-nonfree=yes")
        for conflicting in (
            b" --enable-shared",
            b" --disable-static",
            b" --enable-autodetect",
            b" --disable-ffmpeg",
            b" --disable-ffprobe",
        ):
            with self.subTest(conflicting=conflicting):
                with self.assertRaisesRegex(ValueError, "forbidden flag"):
                    pipeline_lib.parse_configure_record(valid + conflicting)
        with self.assertRaisesRegex(ValueError, "duplicate option --enable-gpl"):
            pipeline_lib.parse_configure_record(valid + b" --enable-gpl")
        with self.assertRaisesRegex(ValueError, "unapproved option"):
            pipeline_lib.parse_configure_record(valid + b" --enable-openssl")

    def test_linux_gnu_stack_header_contract_is_fail_closed(self) -> None:
        verifier = (SCRIPTS / "verify-binary.sh").read_text(encoding="utf-8")
        self.assertIn(
            'verify_linux_gnu_stack_header "$program_headers"', verifier
        )
        good = (
            "  GNU_STACK      0x000000 0x0000000000000000 "
            "0x0000000000000000 0x000000 0x200000 RW  0x10"
        )

        def check(headers: str) -> subprocess.CompletedProcess[str]:
            return subprocess.run(
                [
                    "bash",
                    "-c",
                    'source "$1"; verify_linux_gnu_stack_header "$2"',
                    "bash",
                    str(SCRIPTS / "common.sh"),
                    headers,
                ],
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
            )

        self.assertEqual(check(good).returncode, 0)
        for malformed in (
            good.replace("0x200000", "0x020000"),
            good.replace(" RW  ", " RWE "),
            good + "\n" + good,
            "  LOAD 0x000000 0x0 0x0 0x0 0x200000 RW 0x10",
        ):
            with self.subTest(malformed=malformed):
                self.assertNotEqual(check(malformed).returncode, 0)

    def test_codesign_runtime_parser_requires_one_exact_codedirectory(self) -> None:
        valid = (
            "Executable=/tmp/ffmpeg\n"
            "Identifier=net.agalwood.motrix.ffmpeg\n"
            "CodeDirectory v=20500 size=123 flags=0x10000(runtime) "
            "hashes=1+7 location=embedded\n"
            "CDHash=" + "a" * 40 + "\n"
        )
        self.assertIsNone(pipeline_lib.validate_codesign_hardened_runtime(valid))
        for invalid in (
            "flags=0x10000(runtime)\n",
            valid.replace("0x10000(runtime)", "0x0(runtime)"),
            valid.replace("0x10000(runtime)", "0x10000(notruntime)"),
            valid.replace("0x10000(runtime)", "0x10000(runtime,runtime)"),
            valid + "CodeDirectory v=20500 flags=0x10000(runtime) location=embedded\n",
            valid.replace(
                "hashes=1+7",
                "flags=0x10000(runtime) hashes=1+7",
            ),
        ):
            with self.subTest(invalid=invalid):
                with self.assertRaises(ValueError):
                    pipeline_lib.validate_codesign_hardened_runtime(invalid)

    def test_github_release_identity_is_exact_and_fail_closed(self) -> None:
        repository = "motrixapp/ffmpeg-static"
        release_id = 123
        tag = "v9.0.1-motrix.1"
        target_commitish = "main"
        title = "FFmpeg 9.0.1 for Motrix"
        body = "Motrix static FFmpeg 9.0.1\n\nVerified release."
        api_url = f"https://api.github.com/repos/{repository}/releases/{release_id}"
        draft = {
            "id": release_id,
            "url": api_url,
            "assets_url": f"{api_url}/assets",
            "upload_url": (
                f"https://uploads.github.com/repos/{repository}/releases/"
                f"{release_id}/assets{{?name,label}}"
            ),
            "tag_name": tag,
            "target_commitish": target_commitish,
            "name": title,
            "body": body,
            "prerelease": False,
            "discussion_url": None,
            "author": {"login": "github-actions[bot]", "type": "Bot"},
            "draft": True,
            "immutable": False,
            "published_at": None,
        }
        arguments = {
            "repository": repository,
            "release_id": release_id,
            "tag": tag,
            "target_commitish": target_commitish,
            "title": title,
            "body": body,
        }
        self.assertIs(
            pipeline_lib.validate_github_release_identity(
                draft, **arguments, state="draft"
            ),
            draft,
        )

        published = dict(
            draft,
            draft=False,
            immutable=True,
            published_at="2026-08-29T10:20:30Z",
        )
        self.assertIs(
            pipeline_lib.validate_github_release_identity(
                published, **arguments, state="published"
            ),
            published,
        )
        self.assertIs(
            pipeline_lib.validate_github_release_identity(
                dict(published, immutable=False), **arguments, state="publishing"
            )["immutable"],
            False,
        )

        mutations = (
            {"body": body + "\nattacker text"},
            {"name": "forged"},
            {"tag_name": "v0"},
            {"target_commitish": "attacker-branch"},
            {"upload_url": "https://evil.invalid/upload{?name,label}"},
            {"url": "https://evil.invalid/release"},
            {"discussion_url": "https://github.com/motrixapp/ffmpeg-static/discussions/1"},
            {"author": {"login": "attacker", "type": "User"}},
            {"prerelease": True},
            {"id": True},
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                pipeline_lib.validate_github_release_identity(
                    dict(draft, **mutation), **arguments, state="draft"
                )

        for malformed in (
            dict(published, immutable=False),
            dict(published, published_at="2026-02-31T10:20:30Z"),
            dict(published, published_at=True),
        ):
            with self.subTest(malformed=malformed), self.assertRaises(ValueError):
                pipeline_lib.validate_github_release_identity(
                    malformed, **arguments, state="published"
                )
        with self.assertRaises(ValueError):
            pipeline_lib.validate_github_release_identity(
                draft, **arguments, state="unexpected"
            )

    def test_packaging_is_reproducible_for_identical_payloads(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            lock, _assets = self.make_sources(base)
            for target in ("linux-x64", "win32-arm64"):
                with self.subTest(target=target):
                    first = base / target / "first"
                    second = base / target / "second"
                    first.mkdir(parents=True)
                    second.mkdir(parents=True)
                    first_archive = self.package_target(
                        base / target / "a", first, target, lock
                    )
                    second_archive = self.package_target(
                        base / target / "b", second, target, lock
                    )
                    self.assertEqual(first_archive.read_bytes(), second_archive.read_bytes())
                    self.assertEqual(
                        first_archive.with_name(
                            first_archive.name + ".metadata.json"
                        ).read_bytes(),
                        second_archive.with_name(
                            second_archive.name + ".metadata.json"
                        ).read_bytes(),
                    )

    def test_platform_runtime_notices_and_license_manifest_are_exact(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            lock, _assets = self.make_sources(base)
            for target in ("darwin-arm64", "linux-x64", "win32-arm64"):
                with self.subTest(target=target):
                    output = base / f"out-{target}"
                    archive = self.package_target(base / target, output, target, lock)
                    files = assemble_release.archive_files(archive)
                    expected = {
                        f"LICENSES/{name}"
                        for name in pipeline_lib.required_license_files(target)
                    }
                    self.assertEqual(
                        {name for name in files if name.startswith("LICENSES/")},
                        expected,
                    )
                    license_manifest = json.loads(files["LICENSES.json"])
                    self.assertEqual(license_manifest["target"], target)
                    self.assertEqual(
                        {entry["path"] for entry in license_manifest["files"]},
                        expected,
                    )

    def test_missing_runtime_notice_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            lock, _assets = self.make_sources(base)
            for target, notice in (
                ("linux-x64", "musl-COPYRIGHT"),
                ("linux-arm64", "fortify-headers-LICENSE"),
                ("win32-arm64", "LLVM-LICENSE.TXT"),
                ("win32-x64", "MinGW-w64-runtime-COPYING.txt"),
            ):
                with self.subTest(target=target, notice=notice):
                    case = base / target
                    payload, build_info = self.make_payload(case, target, lock)
                    (payload / "LICENSES" / notice).unlink()
                    result = self.run_script(
                        "package-artifact.py",
                        "--target",
                        target,
                        "--payload",
                        payload,
                        "--build-info",
                        build_info,
                        "--output-dir",
                        case / "out",
                        "--sources-file",
                        lock,
                        check=False,
                    )
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("missing license file", result.stderr)
                    self.assertIn(notice, result.stderr)

    def test_license_bytes_are_bound_to_locks_and_architecture(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            lock, _assets = self.make_sources(base)
            payload, build_info = self.make_payload(base / "bad", "linux-x64", lock)
            notice = payload / "LICENSES/x264-x86inc-ISC.txt"
            notice.write_text("forged ISC notice\n", encoding="utf-8")
            result = self.run_script(
                "package-artifact.py",
                "--target",
                "linux-x64",
                "--payload",
                payload,
                "--build-info",
                build_info,
                "--output-dir",
                base / "out",
                "--sources-file",
                lock,
                check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("does not match its source lock", result.stderr)

            arm_payload, _arm_info = self.make_payload(
                base / "arm", "linux-arm64", lock
            )
            self.assertFalse(
                (arm_payload / "LICENSES/x264-x86inc-ISC.txt").exists()
            )
            x64_payload, _x64_info = self.make_payload(
                base / "x64", "win32-x64", lock
            )
            self.assertTrue(
                (x64_payload / "LICENSES/x264-x86inc-ISC.txt").is_file()
            )

    def test_strict_json_rejects_duplicates_and_nonfinite_numbers(self) -> None:
        with self.assertRaisesRegex(ValueError, "duplicate key 'target'"):
            pipeline_lib.load_json_bytes(
                b'{"target":"one","target":"two"}', "fixture JSON"
            )
        with self.assertRaisesRegex(ValueError, "non-finite number NaN"):
            pipeline_lib.load_json_bytes(b'{"value":NaN}', "fixture JSON")
        with self.assertRaises(ValueError):
            pipeline_lib.canonical_json({"value": float("nan")})
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            oversized = base / "oversized.json"
            oversized.write_bytes(b'{"value":true}')
            with self.assertRaisesRegex(ValueError, "exceeds 4 bytes"):
                pipeline_lib.load_json_file(
                    oversized, "oversized JSON", maximum=4
                )
            linked = base / "linked.json"
            linked.symlink_to(oversized)
            with self.assertRaisesRegex(ValueError, "not a regular file"):
                pipeline_lib.load_json_file(linked, "linked JSON")

            stable = base / "stable.json"
            stable.write_bytes(b'{"value":true}')
            real_fstat = os.fstat
            fstat_calls = 0

            def changed_fstat(descriptor: int):  # type: ignore[no-untyped-def]
                nonlocal fstat_calls
                metadata = real_fstat(descriptor)
                fstat_calls += 1
                if fstat_calls == 2:
                    fields = list(metadata)
                    fields[8] = metadata.st_mtime + 1
                    return os.stat_result(fields)
                return metadata

            with mock.patch.object(
                pipeline_lib.os, "fstat", side_effect=changed_fstat
            ):
                with self.assertRaisesRegex(ValueError, "changed while"):
                    pipeline_lib.load_json_file(stable, "changing JSON")

            observed_flags: list[int] = []
            real_open = os.open

            def checked_open(path: object, flags: int, *args: object) -> int:
                observed_flags.append(flags)
                return real_open(path, flags, *args)

            with mock.patch.object(
                pipeline_lib.os, "open", side_effect=checked_open
            ):
                pipeline_lib.load_json_file(stable, "stable JSON")
            if hasattr(os, "O_NONBLOCK"):
                self.assertTrue(observed_flags[0] & os.O_NONBLOCK)

    def test_package_rejects_wrong_target_source_version_and_config(self) -> None:
        mutations = {
            "target": lambda info: info.__setitem__("target", "linux-arm64"),
            "extra-field": lambda info: info.__setitem__("untrusted", True),
            "source": lambda info: info["sources"]["ffmpeg"].__setitem__(
                "sha256", "0" * 64
            ),
            "version": lambda info: info["sources"]["ffmpeg"].__setitem__(
                "version", "0.0.0"
            ),
            "minimum": lambda info: info["minimumOs"].__setitem__("version", "0.0"),
            "dependency": lambda info: info["dependencies"][0].__setitem__(
                "relationship", "dynamic-link"
            ),
            "compiler": lambda info: info["compiler"].__setitem__(
                "command", "attacker-cc"
            ),
            "toolchain": lambda info: info["toolchain"].__setitem__(
                "sha256", "0" * 64
            ),
            "tool": lambda info: info["tools"]["python"].__setitem__(
                "command", "python"
            ),
            "nasm-source": lambda info: info["tools"]["nasm"].__setitem__(
                "sourceSha256", "0" * 64
            ),
            "nasm-binary": lambda info: info["tools"]["nasm"].__setitem__(
                "binarySha256", "not-a-sha256"
            ),
            "nasm-version": lambda info: info["tools"]["nasm"].__setitem__(
                "version", "NASM version 2.16.03 compiled on an unknown date"
            ),
            "hardening": lambda info: info["hardening"].__setitem__(
                "fortify", "disabled"
            ),
        }
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            lock, _assets = self.make_sources(base)
            for name, mutate in mutations.items():
                with self.subTest(name=name):
                    case = base / name
                    payload, build_info = self.make_payload(case, "linux-x64", lock)
                    info = json.loads(build_info.read_text(encoding="utf-8"))
                    mutate(info)
                    build_info.write_text(json.dumps(info), encoding="utf-8")
                    result = self.run_script(
                        "package-artifact.py",
                        "--target",
                        "linux-x64",
                        "--payload",
                        payload,
                        "--build-info",
                        build_info,
                        "--output-dir",
                        case / "out",
                        "--sources-file",
                        lock,
                        check=False,
                    )
                    self.assertNotEqual(result.returncode, 0)

            config_case = base / "config"
            payload, build_info = self.make_payload(config_case, "linux-x64", lock)
            info = json.loads(build_info.read_text(encoding="utf-8"))
            deceptive = [
                "--enable-gpl=false" if arg == "--enable-gpl" else arg
                for arg in info["configure"]
            ]
            (payload / "configure.txt").write_text(
                "./configure " + shlex.join(deceptive), encoding="utf-8"
            )
            info["configure"] = deceptive
            build_info.write_text(json.dumps(info), encoding="utf-8")
            result = self.run_script(
                "package-artifact.py",
                "--target",
                "linux-x64",
                "--payload",
                payload,
                "--build-info",
                build_info,
                "--output-dir",
                config_case / "out",
                "--sources-file",
                lock,
                check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("missing exact flag --enable-gpl", result.stderr)

    def test_signing_evidence_must_bind_both_exact_binaries(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            lock, _assets = self.make_sources(base)
            payload, build_info = self.make_payload(base, "darwin-arm64", lock)
            evidence = self.signing_evidence(payload, "darwin-arm64")
            evidence["binaries"]["ffmpeg"]["sha256"] = "0" * 64
            evidence_path = base / "evidence.json"
            evidence_path.write_text(json.dumps(evidence), encoding="utf-8")
            result = self.run_script(
                "package-artifact.py",
                "--target",
                "darwin-arm64",
                "--payload",
                payload,
                "--build-info",
                build_info,
                "--output-dir",
                base / "out",
                "--sources-file",
                lock,
                "--signing-evidence",
                evidence_path,
                check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("not bound to ffmpeg", result.stderr)

            windows_payload, windows_info = self.make_payload(
                base / "windows", "win32-arm64", lock
            )
            windows_evidence = self.signing_evidence(
                windows_payload, "win32-arm64"
            )
            windows_evidence["binaries"]["ffmpeg.exe"]["timestamped"] = False
            windows_evidence_path = base / "windows-evidence.json"
            windows_evidence_path.write_text(
                json.dumps(windows_evidence), encoding="utf-8"
            )
            windows_result = self.run_script(
                "package-artifact.py",
                "--target",
                "win32-arm64",
                "--payload",
                windows_payload,
                "--build-info",
                windows_info,
                "--output-dir",
                base / "windows-out",
                "--sources-file",
                lock,
                "--signing-evidence",
                windows_evidence_path,
                check=False,
            )
            self.assertNotEqual(windows_result.returncode, 0)
            self.assertIn("is not timestamped", windows_result.stderr)

    def test_notarization_log_must_prove_the_exact_accepted_archive(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            archive = base / "ffmpeg-test-darwin-arm64.zip"
            archive.write_bytes(b"exact notarized ZIP fixture\n")
            submission = base / "submission.json"
            submission.write_text(
                json.dumps(
                    {
                        "id": "123e4567-e89b-42d3-a456-426614174000",
                        "status": "Accepted",
                    }
                ),
                encoding="utf-8",
            )
            valid_log = {
                "logFormatVersion": 1,
                "jobId": "123e4567-e89b-42d3-a456-426614174000",
                "status": "Accepted",
                "statusCode": 0,
                "archiveFilename": archive.name,
                "sha256": pipeline_lib.sha256_file(archive),
                "issues": [],
            }

            def validate(value: dict[str, object]) -> subprocess.CompletedProcess[str]:
                developer_log = base / "developer-log.json"
                developer_log.write_text(json.dumps(value), encoding="utf-8")
                return subprocess.run(
                    [
                        sys.executable,
                        "-I",
                        str(SCRIPTS / "validate-notarization.py"),
                        "--archive",
                        str(archive),
                        "--submission-result",
                        str(submission),
                        "--developer-log",
                        str(developer_log),
                    ],
                    cwd=base,
                    check=False,
                    capture_output=True,
                    text=True,
                )

            self.assertEqual(validate(valid_log).returncode, 0)
            mutations = {
                "logFormatVersion": 2,
                "jobId": "223e4567-e89b-42d3-a456-426614174000",
                "status": "Invalid",
                "statusCode": 1,
                "archiveFilename": "different.zip",
                "sha256": "0" * 64,
                "issues": [{"message": "rejected"}],
            }
            for field, replacement in mutations.items():
                with self.subTest(field=field):
                    tampered = dict(valid_log)
                    tampered[field] = replacement
                    self.assertNotEqual(validate(tampered).returncode, 0)

            missing_issues = dict(valid_log)
            del missing_issues["issues"]
            self.assertEqual(validate(missing_issues).returncode, 0)
            null_issues = dict(valid_log)
            null_issues["issues"] = None
            self.assertEqual(validate(null_issues).returncode, 0)

    def test_notarization_helper_fetches_and_validates_the_developer_log(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            archive = base / "ffmpeg-test-darwin-arm64.zip"
            archive.write_bytes(b"exact notarized ZIP fixture\n")
            submission_id = "123e4567-e89b-42d3-a456-426614174000"
            submission = json.dumps(
                {"id": submission_id, "status": "Accepted"}, sort_keys=True
            )
            developer_log = json.dumps(
                {
                    "logFormatVersion": 1,
                    "jobId": submission_id,
                    "status": "Accepted",
                    "statusCode": 0,
                    "archiveFilename": archive.name,
                    "sha256": pipeline_lib.sha256_file(archive),
                    "issues": None,
                },
                sort_keys=True,
            )
            fake_bin = base / "bin"
            fake_bin.mkdir()
            fake_xcrun = fake_bin / "xcrun"
            fake_xcrun.write_text(
                "#!/bin/sh\n"
                "set -eu\n"
                "if [ \"$1\" = notarytool ] && [ \"$2\" = submit ]; then\n"
                f"  printf '%s\\n' '{submission}'\n"
                "elif [ \"$1\" = notarytool ] && [ \"$2\" = log ]; then\n"
                f"  printf '%s\\n' '{developer_log}' >\"$4\"\n"
                "else\n"
                "  exit 91\n"
                "fi\n",
                encoding="utf-8",
            )
            fake_xcrun.chmod(0o755)
            result_path = base / "submission-result.json"
            log_path = base / "developer-log.json"
            environment = {
                **os.environ,
                "API_KEY": "-----BEGIN PRIVATE KEY-----\nfixture\n-----END PRIVATE KEY-----\n",
                "API_KEY_ID": "ABCDEF1234",
                "API_KEY_ISSUER_ID": "123e4567-e89b-42d3-a456-426614174000",
                "PATH": f"{fake_bin}:{Path(sys.executable).parent}:/usr/bin:/bin",
            }
            result = subprocess.run(
                [
                    "/bin/bash",
                    str(SCRIPTS / "notarize-macos.sh"),
                    str(archive),
                    str(result_path),
                    str(log_path),
                ],
                cwd=base,
                env=environment,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result_path.read_text()), json.loads(submission))
            self.assertEqual(json.loads(log_path.read_text()), json.loads(developer_log))

    def test_complete_dispatch_assemble_requires_sources_and_is_reproducible(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            lock, assets = self.make_sources(base)
            inputs = self.make_release_inputs(base, lock, signed=False)
            source_dir = self.stage_source_assets(base, lock, assets)
            first = base / "release-first"
            second = base / "release-second"
            self.run_script(
                "assemble-release.py",
                *self.assemble_arguments(inputs, source_dir, first, lock),
            )
            self.run_script(
                "assemble-release.py",
                *self.assemble_arguments(inputs, source_dir, second, lock),
            )
            manifest = json.loads(
                (first / "ffmpeg-manifest.json").read_text(encoding="utf-8")
            )
            self.assertFalse(manifest["formalRelease"])
            self.assertIsNone(manifest["releaseTagObjectSha"])
            self.assertNotIn("releaseTagSignerFingerprint", manifest)
            self.assertEqual(
                [entry["target"] for entry in manifest["targets"]],
                list(EXPECTED_TARGETS),
            )
            minimum_os_by_target = {
                entry["target"]: entry["minimumOs"]
                for entry in manifest["targets"]
            }
            self.assertEqual(
                minimum_os_by_target["linux-arm64"],
                {"name": "linux", "version": "3.7.0"},
            )
            self.assertEqual(
                minimum_os_by_target["linux-x64"],
                {"name": "linux", "version": "2.6.39"},
            )
            self.assertEqual(
                (first / "sbom.spdx.json").read_bytes(),
                (second / "sbom.spdx.json").read_bytes(),
            )
            script_asset = next(
                entry["name"]
                for entry in manifest["sourceAssets"]
                if entry["role"] == "build-scripts"
            )
            self.assertEqual(
                (first / script_asset).read_bytes(),
                (second / script_asset).read_bytes(),
            )
            with tarfile.open(first / script_asset, "r:gz") as archive:
                self.assertEqual(
                    set(archive.getnames()), set(assemble_release.BUILD_PIPELINE_FILES)
                )
            self.assertTrue((first / "ffmpeg-release-signing-key.asc").is_file())
            self.assertTrue((first / "ffmpeg-fixture.tar.xz.asc").is_file())
            source_assets = {
                entry["name"]: entry for entry in manifest["sourceAssets"]
            }
            sources = pipeline_lib.load_sources(lock)
            for archive_key, hash_key in (
                ("NASM_ARCHIVE", "NASM_SHA256"),
                ("LLVM_MINGW_RECIPE_ARCHIVE", "LLVM_MINGW_RECIPE_SHA256"),
                ("LLVM_RUNTIME_ARCHIVE", "LLVM_RUNTIME_SHA256"),
            ):
                asset = source_assets[sources[archive_key]]
                self.assertEqual(asset["role"], "corresponding-source")
                self.assertEqual(asset["sha256"], sources[hash_key])
            self.assertNotIn(sources["MINGW_W64_ARCHIVE"], source_assets)

    def test_formal_release_accepts_structured_pinned_signing_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            lock, assets = self.make_sources(base)
            inputs = self.make_release_inputs(base, lock, signed=True)
            source_dir = self.stage_source_assets(base, lock, assets)
            output = base / "release"
            self.run_script(
                "assemble-release.py",
                *self.assemble_arguments(
                    inputs, source_dir, output, lock, formal=True
                ),
            )
            manifest = json.loads(
                (output / "ffmpeg-manifest.json").read_text(encoding="utf-8")
            )
            self.assertTrue(manifest["formalRelease"])
            self.assertEqual(manifest["releaseCommit"], EVENT_SHA)
            self.assertEqual(manifest["controlCommit"], CONTROL_SHA)
            self.assertEqual(manifest["releaseTagObjectSha"], TAG_OBJECT_SHA)
            self.assertNotIn("releaseTagSignerFingerprint", manifest)
            signed = {
                entry["target"]: entry["signing"]["kind"]
                for entry in manifest["targets"]
                if entry["signing"] is not None
            }
            self.assertEqual(
                signed,
                {
                    "darwin-arm64": "apple-developer-id",
                    "darwin-x64": "apple-developer-id",
                    "win32-arm64": "authenticode",
                    "win32-x64": "authenticode",
                },
            )
            checksum_names = {
                line.split("  ", 1)[1]
                for line in (output / "SHA256SUMS").read_text(encoding="utf-8").splitlines()
            }
            for target in ("darwin-arm64", "darwin-x64"):
                target_record = next(
                    entry for entry in manifest["targets"] if entry["target"] == target
                )
                self.assertEqual(target_record["signing"]["schemaVersion"], 3)
                log_record = target_record["signing"]["notarization"]["developerLog"]
                log_path = output / log_record["name"]
                self.assertTrue(log_path.is_file())
                self.assertEqual(log_path.stat().st_size, log_record["size"])
                self.assertEqual(pipeline_lib.sha256_file(log_path), log_record["sha256"])
                self.assertIn(log_record["name"], checksum_names)
            sbom = json.loads(
                (output / "sbom.spdx.json").read_text(encoding="utf-8")
            )
            sbom_files = {entry["fileName"]: entry for entry in sbom["files"]}
            for target in ("darwin-arm64", "darwin-x64"):
                target_record = next(
                    entry for entry in manifest["targets"] if entry["target"] == target
                )
                log_record = target_record["signing"]["notarization"]["developerLog"]
                self.assertEqual(
                    sbom_files[f"./{log_record['name']}"]["checksums"][0]["checksumValue"],
                    log_record["sha256"],
                )
            windows_package = next(
                package
                for package in sbom["packages"]
                if package["SPDXID"] == "SPDXRef-Artifact-win32-arm64"
            )
            self.assertIn(
                "timestamp authority certificate SHA-256",
                windows_package["packageComment"],
            )
            self.assertIn("9" * 64, windows_package["packageComment"])

    def test_formal_release_rejects_different_subject_and_control_commits(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            lock, assets = self.make_sources(base)
            inputs = self.make_release_inputs(base, lock, signed=True)
            source_dir = self.stage_source_assets(base, lock, assets)
            arguments = self.assemble_arguments(
                inputs, source_dir, base / "release", lock, formal=True
            )
            control_index = arguments.index("--control-sha") + 1
            arguments[control_index] = DIFFERENT_CONTROL_SHA
            result = self.run_script(
                "assemble-release.py", *arguments, check=False
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "subject and protected control commits must be identical",
                result.stderr,
            )

    def test_formal_release_rejects_legacy_self_reported_signing_flags(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            lock, assets = self.make_sources(base)
            inputs = self.make_release_inputs(base, lock, signed=False)
            source_dir = self.stage_source_assets(base, lock, assets)
            metadata_path = next(inputs.glob("*darwin-arm64*.metadata.json"))
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            metadata.update(
                {"codesigned": True, "notarized": True, "notarizationId": "fake"}
            )
            metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
            result = self.run_script(
                "assemble-release.py",
                *self.assemble_arguments(
                    inputs, source_dir, base / "release", lock, formal=True
                ),
                check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("legacy self-reported signing field", result.stderr)

    def test_formal_release_rejects_wrong_pinned_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            lock, assets = self.make_sources(base)
            inputs = self.make_release_inputs(base, lock, signed=True)
            source_dir = self.stage_source_assets(base, lock, assets)
            arguments = self.assemble_arguments(
                inputs, source_dir, base / "release", lock, formal=True
            )
            index = arguments.index("--expected-macos-team-id") + 1
            arguments[index] = "ZZZZZ99999"
            result = self.run_script(
                "assemble-release.py", *arguments, check=False
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("macOS signing identity mismatch", result.stderr)

            repository_result = self.run_script(
                "assemble-release.py",
                *self.assemble_arguments(
                    inputs, source_dir, base / "repository-release", lock, formal=True
                ),
                "--repository",
                "attacker/ffmpeg-static",
                check=False,
            )
            self.assertNotEqual(repository_result.returncode, 0)
            self.assertIn(
                "formal releases are restricted to motrixapp/ffmpeg-static",
                repository_result.stderr,
            )

    def test_assemble_rejects_release_without_windows_arm64(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            lock, assets = self.make_sources(base)
            targets = tuple(
                target for target in EXPECTED_TARGETS if target != "win32-arm64"
            )
            inputs = self.make_release_inputs(
                base, lock, targets, signed=False
            )
            source_dir = self.stage_source_assets(base, lock, assets)
            result = self.run_script(
                "assemble-release.py",
                *self.assemble_arguments(
                    inputs, source_dir, base / "release", lock
                ),
                check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("incomplete target set", result.stderr)
            self.assertIn("win32-arm64", result.stderr)

    def test_source_dir_is_required_and_missing_or_tampered_inputs_fail(self) -> None:
        result = self.run_script(
            "assemble-release.py",
            "--input-dir",
            "unused",
            "--output-dir",
            "unused",
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("--source-dir", result.stderr)

        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            lock, assets = self.make_sources(base)
            inputs = self.make_release_inputs(base, lock, signed=False)
            for mode in ("missing", "tampered", "signature", "lock", "workflow"):
                with self.subTest(mode=mode):
                    case = base / mode
                    source_dir = self.stage_source_assets(case, lock, assets)
                    ffmpeg_source = source_dir / "ffmpeg-fixture.tar.xz"
                    if mode == "missing":
                        ffmpeg_source.unlink()
                    elif mode == "tampered":
                        ffmpeg_source.write_bytes(b"tampered")
                    elif mode == "signature":
                        (source_dir / "ffmpeg-fixture.tar.xz.asc").write_bytes(
                            b"forged signature"
                        )
                    elif mode == "lock":
                        (source_dir / "sources.env").write_text(
                            lock.read_text(encoding="utf-8") + "# changed\n",
                            encoding="utf-8",
                        )
                    else:
                        (source_dir / ".github/workflows/release.yml").write_text(
                            "name: forged\n", encoding="utf-8"
                        )
                    result = self.run_script(
                        "assemble-release.py",
                        *self.assemble_arguments(
                            inputs, source_dir, case / "release", lock
                        ),
                        check=False,
                    )
                    self.assertNotEqual(result.returncode, 0)
                    self.assertRegex(
                        result.stderr,
                        "source asset (set|checksum) mismatch|does not match the checkout",
                    )

    def test_assemble_rejects_tampered_metadata_archive_and_build_contract(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            lock, _assets = self.make_sources(base)
            output = base / "input"
            archive = self.package_target(base / "fixture", output, "linux-x64", lock)
            metadata_path = archive.with_name(archive.name + ".metadata.json")
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            metadata["ffmpegVersion"] = "0.0.0"
            metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "FFmpeg version mismatch"):
                assemble_release.verify_target(metadata_path, pipeline_lib.load_sources(lock))

            metadata["ffmpegVersion"] = pipeline_lib.load_sources(lock)["FFMPEG_VERSION"]
            metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
            archive.write_bytes(archive.read_bytes() + b"tamper")
            with self.assertRaisesRegex(ValueError, "checksum mismatch"):
                assemble_release.verify_target(metadata_path, pipeline_lib.load_sources(lock))

    def test_archive_reader_rejects_duplicate_unsafe_link_and_bombs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            duplicate = base / "duplicate.zip"
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                with zipfile.ZipFile(duplicate, "w") as archive:
                    archive.writestr("file", b"one")
                    archive.writestr("file", b"two")
            with self.assertRaisesRegex(ValueError, "duplicate archive member"):
                assemble_release.archive_files(duplicate)

            unsafe = base / "unsafe.zip"
            with zipfile.ZipFile(unsafe, "w") as archive:
                archive.writestr("../escape", b"bad")
            with self.assertRaisesRegex(ValueError, "unsafe archive member"):
                assemble_release.archive_files(unsafe)

            symlink = base / "symlink.zip"
            with zipfile.ZipFile(symlink, "w") as archive:
                info = zipfile.ZipInfo("link")
                info.create_system = 3
                info.external_attr = (stat.S_IFLNK | 0o777) << 16
                archive.writestr(info, b"target")
            with self.assertRaisesRegex(ValueError, "non-regular zip member"):
                assemble_release.archive_files(symlink)

            hardlink = base / "hardlink.tar.gz"
            with tarfile.open(hardlink, "w:gz") as archive:
                info = tarfile.TarInfo("link")
                info.type = tarfile.LNKTYPE
                info.linkname = "target"
                archive.addfile(info)
            with self.assertRaisesRegex(ValueError, "non-regular tar member"):
                assemble_release.archive_files(hardlink)

            oversized = base / "oversized.zip"
            with zipfile.ZipFile(oversized, "w") as archive:
                archive.writestr("large", b"12345")
            with mock.patch.object(assemble_release, "MAX_ARCHIVE_MEMBER_BYTES", 4):
                with self.assertRaisesRegex(ValueError, "member is too large"):
                    assemble_release.archive_files(oversized)

            too_many = base / "many.zip"
            with zipfile.ZipFile(too_many, "w") as archive:
                archive.writestr("one", b"1")
                archive.writestr("two", b"2")
            with mock.patch.object(assemble_release, "MAX_ARCHIVE_MEMBERS", 1):
                with self.assertRaisesRegex(ValueError, "more than 1 members"):
                    assemble_release.archive_files(too_many)

            total = base / "total.zip"
            with zipfile.ZipFile(total, "w") as archive:
                archive.writestr("one", b"123")
                archive.writestr("two", b"456")
            with mock.patch.object(assemble_release, "MAX_ARCHIVE_TOTAL_BYTES", 5):
                with self.assertRaisesRegex(ValueError, "uncompressed size"):
                    assemble_release.archive_files(total)

            setuid = base / "setuid.zip"
            with zipfile.ZipFile(setuid, "w") as archive:
                info = zipfile.ZipInfo("ffmpeg", (2023, 11, 14, 22, 13, 20))
                info.create_system = 3
                info.external_attr = (stat.S_IFREG | 0o4755) << 16
                info.compress_type = zipfile.ZIP_DEFLATED
                archive.writestr(info, b"binary")
            with self.assertRaisesRegex(ValueError, "not normalized"):
                assemble_release.archive_files(setuid, 1700000000)

            writable = base / "writable.tar.gz"
            with writable.open("wb") as output:
                with gzip.GzipFile(
                    fileobj=output, mode="wb", filename="", mtime=1700000000
                ) as zipped:
                    with tarfile.open(fileobj=zipped, mode="w") as archive:
                        info = tarfile.TarInfo("README.txt")
                        info.size = 4
                        info.mode = 0o666
                        info.mtime = 1700000000
                        info.uid = 0
                        info.gid = 0
                        info.uname = "root"
                        info.gname = "root"
                        archive.addfile(info, io.BytesIO(b"text"))
            with self.assertRaisesRegex(ValueError, "not normalized"):
                assemble_release.archive_files(writable, 1700000000)

    def test_archive_reader_rejects_container_overlays_and_ambiguous_framing(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            valid_zip = base / "valid.zip"
            with zipfile.ZipFile(
                valid_zip,
                "w",
                compression=zipfile.ZIP_DEFLATED,
                compresslevel=9,
            ) as archive:
                archive.writestr("file", b"payload")
            valid_zip_bytes = valid_zip.read_bytes()

            bounded_gzip = base / "bounded.gz"
            bounded_payload = b"bounded payload"
            bounded_gzip.write_bytes(gzip.compress(bounded_payload, mtime=0))
            descriptor = os.open(bounded_gzip, os.O_RDONLY)
            try:
                opened_size = os.fstat(descriptor).st_size
                with bounded_gzip.open("ab") as destination:
                    destination.write(b"growth that is outside the opened snapshot")
                stream, stream_size = assemble_release._decompress_single_gzip(
                    descriptor, opened_size
                )
                try:
                    self.assertEqual(stream_size, len(bounded_payload))
                    self.assertEqual(stream.read(), bounded_payload)
                finally:
                    stream.close()
            finally:
                os.close(descriptor)

            raced = base / "raced.zip"
            raced.write_bytes(valid_zip_bytes)
            original_reader = assemble_release._archive_files_from_open_archive

            def append_after_parse(
                path: Path,
                archive_source: object,
                archive_size: int,
                epoch: object,
            ) -> dict[str, bytes]:
                files = original_reader(path, archive_source, archive_size, epoch)
                with path.open("ab") as destination:
                    destination.write(b"SECRET-TRAILER")
                    destination.flush()
                    os.fsync(destination.fileno())
                return files

            with mock.patch.object(
                assemble_release,
                "_archive_files_from_open_archive",
                side_effect=append_after_parse,
            ):
                with self.assertRaisesRegex(ValueError, "changed while"):
                    assemble_release.archive_files(raced)

            observed_archive_flags: list[int] = []
            real_archive_open = os.open

            def checked_archive_open(
                path: object, flags: int, *args: object
            ) -> int:
                observed_archive_flags.append(flags)
                return real_archive_open(path, flags, *args)

            with mock.patch.object(
                assemble_release.os,
                "open",
                side_effect=checked_archive_open,
            ):
                assemble_release.archive_files(valid_zip)
            if hasattr(os, "O_NONBLOCK"):
                self.assertTrue(observed_archive_flags[0] & os.O_NONBLOCK)

            prefixed = base / "prefixed.zip"
            prefixed.write_bytes(b"prefix" + valid_zip_bytes)
            with self.assertRaisesRegex(ValueError, "central directory|prefix|gap"):
                assemble_release.archive_files(prefixed)

            trailed = base / "trailed.zip"
            trailed.write_bytes(valid_zip_bytes + b"trailer")
            with self.assertRaisesRegex(ValueError, "EOCD"):
                assemble_release.archive_files(trailed)

            duplicate_eocd = base / "duplicate-eocd.zip"
            duplicate_eocd.write_bytes(
                valid_zip_bytes + valid_zip_bytes[-assemble_release.ZIP_EOCD.size :]
            )
            with self.assertRaisesRegex(ValueError, "central directory"):
                assemble_release.archive_files(duplicate_eocd)

            local_extra = bytearray(valid_zip_bytes)
            struct.pack_into("<H", local_extra, 28, 1)
            local_extra_path = base / "local-extra.zip"
            local_extra_path.write_bytes(local_extra)
            with self.assertRaisesRegex(ValueError, "local/central mismatch"):
                assemble_release.archive_files(local_extra_path)

            (
                _signature,
                _disk,
                _central_disk,
                _disk_entries,
                _entries,
                _central_size,
                central_offset,
                _comment_size,
            ) = assemble_release.ZIP_EOCD.unpack(
                valid_zip_bytes[-assemble_release.ZIP_EOCD.size :]
            )

            descriptor = bytearray(valid_zip_bytes)
            local_flags = struct.unpack_from("<H", descriptor, 6)[0] | 0x8
            central_flags = (
                struct.unpack_from("<H", descriptor, central_offset + 8)[0] | 0x8
            )
            struct.pack_into("<H", descriptor, 6, local_flags)
            struct.pack_into("<H", descriptor, central_offset + 8, central_flags)
            descriptor_path = base / "descriptor.zip"
            descriptor_path.write_bytes(descriptor)
            with self.assertRaisesRegex(ValueError, "general-purpose flags"):
                assemble_release.archive_files(descriptor_path)

            zip64 = bytearray(valid_zip_bytes)
            struct.pack_into("<L", zip64, central_offset + 24, 0xFFFFFFFF)
            zip64_path = base / "zip64.zip"
            zip64_path.write_bytes(zip64)
            with self.assertRaisesRegex(ValueError, "ZIP64"):
                assemble_release.archive_files(zip64_path)

            normalized_zip = base / "normalized.zip"
            with zipfile.ZipFile(
                normalized_zip,
                "w",
                compression=zipfile.ZIP_DEFLATED,
                compresslevel=9,
            ) as archive:
                info = zipfile.ZipInfo(
                    "ffmpeg.exe", (2023, 11, 14, 22, 13, 20)
                )
                info.compress_type = zipfile.ZIP_DEFLATED
                info.create_system = 3
                info.external_attr = (stat.S_IFREG | 0o755) << 16
                archive.writestr(info, b"payload")
            assemble_release.archive_files(normalized_zip, 1700000000)
            hidden_external = bytearray(normalized_zip.read_bytes())
            normalized_central = assemble_release.ZIP_EOCD.unpack(
                hidden_external[-assemble_release.ZIP_EOCD.size :]
            )[6]
            external_attr = struct.unpack_from(
                "<L", hidden_external, normalized_central + 38
            )[0]
            struct.pack_into(
                "<L",
                hidden_external,
                normalized_central + 38,
                external_attr | 0xBEEF,
            )
            hidden_external_path = base / "hidden-external.zip"
            hidden_external_path.write_bytes(hidden_external)
            with self.assertRaisesRegex(ValueError, "structure is not normalized"):
                assemble_release.archive_files(hidden_external_path, 1700000000)

            hidden_deflate = bytearray(valid_zip_bytes)
            name_size = struct.unpack_from("<H", hidden_deflate, 26)[0]
            extra_size = struct.unpack_from("<H", hidden_deflate, 28)[0]
            compressed_size = struct.unpack_from("<L", hidden_deflate, 18)[0]
            data_end = 30 + name_size + extra_size + compressed_size
            hidden_deflate[data_end:data_end] = b"\x00"
            struct.pack_into("<L", hidden_deflate, 18, compressed_size + 1)
            shifted_central = central_offset + 1
            struct.pack_into(
                "<L", hidden_deflate, shifted_central + 20, compressed_size + 1
            )
            shifted_eocd = len(hidden_deflate) - assemble_release.ZIP_EOCD.size
            struct.pack_into("<L", hidden_deflate, shifted_eocd + 16, shifted_central)
            hidden_deflate_path = base / "hidden-deflate.zip"
            hidden_deflate_path.write_bytes(hidden_deflate)
            with self.assertRaisesRegex(ValueError, "trailing compressed data"):
                assemble_release.archive_files(hidden_deflate_path)

            valid_tar = base / "valid.tar.gz"
            with valid_tar.open("wb") as output:
                with gzip.GzipFile(
                    fileobj=output, mode="wb", filename="", mtime=1700000000
                ) as compressed:
                    with tarfile.open(fileobj=compressed, mode="w") as archive:
                        info = tarfile.TarInfo("file")
                        info.size = len(b"payload")
                        archive.addfile(info, io.BytesIO(b"payload"))
            valid_tar_bytes = valid_tar.read_bytes()

            gzip_trailer = base / "gzip-trailer.tar.gz"
            gzip_trailer.write_bytes(valid_tar_bytes + b"trailer")
            with self.assertRaisesRegex(ValueError, "trailing data|another member"):
                assemble_release.archive_files(gzip_trailer)

            concatenated = base / "concatenated.tar.gz"
            concatenated.write_bytes(valid_tar_bytes + valid_tar_bytes)
            with self.assertRaisesRegex(ValueError, "trailing data|another member"):
                assemble_release.archive_files(concatenated)

            tar_bytes = bytearray(gzip.decompress(valid_tar_bytes))
            tar_bytes[-1] = 1
            tar_overlay = base / "tar-overlay.tar.gz"
            with tar_overlay.open("wb") as output:
                with gzip.GzipFile(
                    fileobj=output, mode="wb", filename="", mtime=1700000000
                ) as compressed:
                    compressed.write(tar_bytes)
            with self.assertRaisesRegex(ValueError, "after its end blocks"):
                assemble_release.archive_files(tar_overlay)

            normalized_tar = base / "normalized.tar.gz"
            with normalized_tar.open("wb") as output:
                with gzip.GzipFile(
                    fileobj=output,
                    mode="wb",
                    filename="",
                    mtime=1700000000,
                    compresslevel=9,
                ) as compressed:
                    with tarfile.open(
                        fileobj=compressed,
                        mode="w",
                        format=tarfile.PAX_FORMAT,
                    ) as archive:
                        info = tarfile.TarInfo("README.txt")
                        info.size = len(b"payload")
                        info.mode = 0o644
                        info.mtime = 1700000000
                        info.uid = 0
                        info.gid = 0
                        info.uname = "root"
                        info.gname = "root"
                        archive.addfile(info, io.BytesIO(b"payload"))
            assemble_release.archive_files(normalized_tar, 1700000000)

            def write_mutated_tar(name: str, raw_tar: bytearray) -> Path:
                raw_tar[148:156] = b" " * 8
                checksum = sum(raw_tar[: tarfile.BLOCKSIZE])
                raw_tar[148:156] = f"{checksum:06o}\0 ".encode("ascii")
                path = base / name
                with path.open("wb") as output:
                    with gzip.GzipFile(
                        fileobj=output,
                        mode="wb",
                        filename="",
                        mtime=1700000000,
                        compresslevel=9,
                    ) as compressed:
                        compressed.write(raw_tar)
                return path

            hidden_uname = bytearray(gzip.decompress(normalized_tar.read_bytes()))
            hidden_uname[270] = ord("X")
            hidden_uname_path = write_mutated_tar(
                "hidden-uname.tar.gz", hidden_uname
            )
            with self.assertRaisesRegex(ValueError, "structure is not normalized"):
                assemble_release.archive_files(hidden_uname_path, 1700000000)

            noncanonical_mode = bytearray(
                gzip.decompress(normalized_tar.read_bytes())
            )
            noncanonical_mode[100:108] = b" 000644\0"
            noncanonical_mode_path = write_mutated_tar(
                "noncanonical-mode.tar.gz", noncanonical_mode
            )
            with self.assertRaisesRegex(ValueError, "structure is not normalized"):
                assemble_release.archive_files(noncanonical_mode_path, 1700000000)

            extra_zero_record = bytearray(
                gzip.decompress(normalized_tar.read_bytes())
            )
            extra_zero_record.extend(b"\x00" * tarfile.RECORDSIZE)
            extra_zero_record_path = write_mutated_tar(
                "extra-zero-record.tar.gz", extra_zero_record
            )
            with self.assertRaisesRegex(ValueError, "non-canonical end padding"):
                assemble_release.archive_files(extra_zero_record_path, 1700000000)

    def test_release_checksum_writer_requires_exact_regular_asset_set(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            valid = base / "valid"
            valid.mkdir()
            (valid / "a").write_bytes(b"a")
            (valid / "b").write_bytes(b"b")
            checksums = assemble_release.write_release_checksums(
                valid, {"a", "b"}
            )
            self.assertEqual(
                checksums.read_text(encoding="utf-8").splitlines(),
                [
                    f"{hashlib.sha256(b'a').hexdigest()}  a",
                    f"{hashlib.sha256(b'b').hexdigest()}  b",
                ],
            )

            extra = base / "extra"
            extra.mkdir()
            (extra / "a").write_bytes(b"a")
            (extra / "unexpected").write_bytes(b"bad")
            with self.assertRaisesRegex(ValueError, "asset set mismatch"):
                assemble_release.write_release_checksums(extra, {"a"})

            linked = base / "linked"
            linked.mkdir()
            (linked / "target").write_bytes(b"target")
            (linked / "asset").symlink_to("target")
            with self.assertRaisesRegex(ValueError, "not a regular file"):
                assemble_release.write_release_checksums(
                    linked, {"asset", "target"}
                )

    def test_nasm_archive_policy_allows_only_normalized_setgid_directories(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)

            def make_archive(path: Path, directory_mode: int, file_mode: int) -> str:
                with tarfile.open(path, "w:xz") as archive:
                    directory = tarfile.TarInfo("nasm-fixture")
                    directory.type = tarfile.DIRTYPE
                    directory.mode = directory_mode
                    archive.addfile(directory)
                    file_info = tarfile.TarInfo("nasm-fixture/configure")
                    file_info.mode = file_mode
                    file_info.size = len(b"#!/bin/sh\n")
                    archive.addfile(file_info, io.BytesIO(b"#!/bin/sh\n"))
                return hashlib.sha256(path.read_bytes()).hexdigest()

            def run_common(command: str, archive: Path, digest: str) -> subprocess.CompletedProcess[str]:
                environment = os.environ.copy()
                environment.update(
                    {
                        "TEST_ARCHIVE": str(archive),
                        "TEST_DIGEST": digest,
                        "TEST_DESTINATION": str(base / "extracted"),
                    }
                )
                return subprocess.run(
                    ["bash", "-c", f"set -Eeuo pipefail; source scripts/common.sh; {command}"],
                    cwd=ROOT,
                    env=environment,
                    check=False,
                    capture_output=True,
                    text=True,
                )

            official_shape = base / "official-shape.tar.xz"
            digest = make_archive(official_shape, 0o2775, 0o775)
            strict = run_common(
                'validate_tar_archive "$TEST_ARCHIVE" "$TEST_DIGEST" strict',
                official_shape,
                digest,
            )
            self.assertNotEqual(strict.returncode, 0)
            allowed = run_common(
                'validate_tar_archive "$TEST_ARCHIVE" "$TEST_DIGEST" allow-setgid-directories',
                official_shape,
                digest,
            )
            self.assertEqual(allowed.returncode, 0, allowed.stderr)

            destination = base / "extracted"
            extracted = run_common(
                'extract_tar_strip_one "$TEST_ARCHIVE" "$TEST_DESTINATION" "$TEST_DIGEST" allow-setgid-directories',
                official_shape,
                digest,
            )
            self.assertEqual(extracted.returncode, 0, extracted.stderr)
            for path in (destination, *destination.rglob("*")):
                if path.is_symlink():
                    continue
                mode = stat.S_IMODE(path.lstat().st_mode)
                self.assertEqual(mode & 0o7022, 0, path)

            malicious = base / "setgid-file.tar.xz"
            malicious_digest = make_archive(malicious, 0o755, 0o2755)
            rejected = run_common(
                'validate_tar_archive "$TEST_ARCHIVE" "$TEST_DIGEST" allow-setgid-directories',
                malicious,
                malicious_digest,
            )
            self.assertNotEqual(rejected.returncode, 0)

            unknown = run_common(
                'validate_tar_archive "$TEST_ARCHIVE" "$TEST_DIGEST" allow-everything',
                official_shape,
                digest,
            )
            self.assertNotEqual(unknown.returncode, 0)

    def test_sbom_describes_six_archives_binaries_and_static_dependencies(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            lock, assets = self.make_sources(base)
            inputs = self.make_release_inputs(base, lock, signed=False)
            source_dir = self.stage_source_assets(base, lock, assets)
            output = base / "release"
            self.run_script(
                "assemble-release.py",
                *self.assemble_arguments(inputs, source_dir, output, lock),
            )
            sbom = json.loads(
                (output / "sbom.spdx.json").read_text(encoding="utf-8")
            )
            self.assertEqual(sbom["spdxVersion"], "SPDX-2.3")
            self.assertEqual(len(sbom["documentDescribes"]), 6)
            artifact_packages = [
                package
                for package in sbom["packages"]
                if package["SPDXID"].startswith("SPDXRef-Artifact-")
            ]
            self.assertEqual(len(artifact_packages), 6)
            licenses_by_id = {
                package["SPDXID"]: package["licenseConcluded"]
                for package in artifact_packages
            }
            self.assertIn("ISC", licenses_by_id["SPDXRef-Artifact-linux-x64"])
            self.assertIn("ISC", licenses_by_id["SPDXRef-Artifact-linux-arm64"])
            self.assertIn("SunPro", licenses_by_id["SPDXRef-Artifact-linux-arm64"])
            self.assertIn(
                "Apache-2.0 WITH LLVM-exception",
                licenses_by_id["SPDXRef-Artifact-win32-arm64"],
            )
            archive_files = [
                file
                for file in sbom["files"]
                if file["SPDXID"].startswith("SPDXRef-File-Archive-")
            ]
            binary_files = [
                file
                for file in sbom["files"]
                if "SPDXRef-File-ffmpeg-" in file["SPDXID"]
                or "SPDXRef-File-ffprobe-" in file["SPDXID"]
            ]
            self.assertEqual(len(archive_files), 6)
            self.assertEqual(len(binary_files), 12)
            static_links = {
                relation["relatedSpdxElement"]
                for relation in sbom["relationships"]
                if relation["relationshipType"] == "STATIC_LINK"
            }
            self.assertIn("SPDXRef-Compiled-x264-core", static_links)
            self.assertIn("SPDXRef-Compiled-LAME", static_links)
            self.assertTrue(any("Dependency-musl" in item for item in static_links))
            self.assertTrue(
                any("Dependency-mingw-w64-runtime" in item for item in static_links)
            )
            self.assertIn("SPDXRef-Embedded-IJG-DCT", static_links)
            self.assertIn("SPDXRef-Embedded-Glumpy-Filters", static_links)
            self.assertIn("SPDXRef-Embedded-x264-x86inc", static_links)
            generated_from = {
                relation["relatedSpdxElement"]
                for relation in sbom["relationships"]
                if relation["relationshipType"] == "GENERATED_FROM"
            }
            self.assertTrue(
                any("Dependency-fortify-headers" in item for item in generated_from)
            )
            generated_pairs = {
                (relation["spdxElementId"], relation["relatedSpdxElement"])
                for relation in sbom["relationships"]
                if relation["relationshipType"] == "GENERATED_FROM"
            }
            self.assertTrue(
                any(
                    element.startswith("SPDXRef-Dependency-llvm-compiler-rt-")
                    and origin == "SPDXRef-Source-llvm-compiler-rt"
                    for element, origin in generated_pairs
                )
            )
            self.assertTrue(
                any(
                    element.startswith("SPDXRef-Dependency-mingw-w64-runtime-")
                    and origin == "SPDXRef-Source-mingw-w64-runtime"
                    for element, origin in generated_pairs
                )
            )
            build_tools = [
                relation
                for relation in sbom["relationships"]
                if relation["relationshipType"] == "BUILD_TOOL_OF"
                and relation["spdxElementId"] == "SPDXRef-Toolchain-llvm-mingw"
            ]
            self.assertEqual(len(build_tools), 4)
            self.assertEqual(
                sbom["hasExtractedLicensingInfos"][0]["licenseId"],
                "LicenseRef-MinGW-w64-runtime",
            )

if __name__ == "__main__":
    unittest.main()
