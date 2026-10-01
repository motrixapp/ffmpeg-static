#!/usr/bin/env python3
"""Create one normalized Motrix FFmpeg archive and its machine manifest."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import shutil
import stat
import sys
import tarfile
import zipfile
from pathlib import Path
from typing import Optional

# Resolve helpers only from the protected recipe, including under python -I.
# Never obtain executable Python modules from downloaded payload directories.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from pipeline_lib import (
    MAX_LICENSE_FILE_BYTES,
    MAX_NOTARIZATION_JSON_BYTES,
    PACKAGE_README,
    artifact_license,
    artifact_stem,
    canonical_json,
    load_sources,
    load_json_file,
    minimum_os,
    notarization_log_asset_name,
    parse_configure_record,
    require_target,
    required_license_files,
    sha256_file,
    validate_build_info,
    validate_notarization_log,
    validate_notarization_submission,
    validate_signing_evidence,
    write_json,
)


def digest_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _load_build_info(
    path: Path, target_name: str, sources: dict[str, str], configure_args: list[str]
) -> tuple[dict[str, object], list[dict[str, str]]]:
    info = load_json_file(path, "build info", maximum=256 * 1024)
    normalized, dependencies = validate_build_info(
        info, target_name, sources, configure_args
    )
    return normalized, dependencies


def _license_entries(
    payload: Path, target_name: str, sources: dict[str, str]
) -> tuple[list[tuple[str, bytes, int]], list[dict[str, str]]]:
    entries: list[tuple[str, bytes, int]] = []
    records: list[dict[str, str]] = []
    for name, (
        component,
        document_license,
        effective_component_license,
        hash_key,
    ) in sorted(
        required_license_files(target_name).items()
    ):
        path = payload / "LICENSES" / name
        if not path.is_file() or path.is_symlink():
            raise ValueError(f"missing license file: {path}")
        data = path.read_bytes()
        # The generated, hash-locked source notice inventory is intentionally
        # comprehensive and currently a little over 4 MiB. Keep a tight bound
        # above that known size while still rejecting accidental source dumps.
        if not data or len(data) > MAX_LICENSE_FILE_BYTES:
            raise ValueError(f"license file has an invalid size: {path}")
        if name == "THIRD-PARTY-NOTICES.txt" and len(data) != int(
            sources["THIRD_PARTY_NOTICES_SIZE"]
        ):
            raise ValueError(f"generated notice file has an unexpected size: {path}")
        try:
            data.decode("utf-8")
        except UnicodeDecodeError as error:
            raise ValueError(f"license file is not UTF-8: {path}") from error
        digest = digest_bytes(data)
        if digest != sources[hash_key]:
            raise ValueError(f"license file does not match its source lock: {path}")
        archive_path = f"LICENSES/{name}"
        entries.append((archive_path, data, 0o644))
        records.append(
            {
                "component": component,
                "documentLicense": document_license,
                "effectiveComponentLicense": effective_component_license,
                "path": archive_path,
                "sha256": digest,
            }
        )
    license_manifest = {
        "schemaVersion": 2,
        "target": target_name,
        "files": records,
    }
    entries.append(("LICENSES.json", canonical_json(license_manifest), 0o644))
    return entries, records


def archive_entries(
    payload: Path,
    build_info: Path,
    executable: str,
    target_name: str,
    sources: dict[str, str],
) -> tuple[list[tuple[str, bytes, int]], list[dict[str, str]], list[dict[str, str]]]:
    entries: list[tuple[str, bytes, int]] = []
    for name in (executable, executable.replace("ffmpeg", "ffprobe")):
        path = payload / name
        if not path.is_file() or path.is_symlink():
            raise ValueError(f"missing regular binary: {path}")
        data = path.read_bytes()
        if not data or len(data) > 256 * 1024 * 1024:
            raise ValueError(f"binary has an invalid size: {path}")
        entries.append((name, data, 0o755))

    configure = payload / "configure.txt"
    if not configure.is_file() or configure.is_symlink():
        raise ValueError(f"missing configure record: {configure}")
    configure_data = configure.read_bytes()
    if not configure_data or len(configure_data) > 256 * 1024:
        raise ValueError("configure record has an invalid size")
    configure_args = parse_configure_record(configure_data)
    entries.append(("configure.txt", configure_data, 0o644))

    info, dependencies = _load_build_info(
        build_info, target_name, sources, configure_args
    )
    entries.append(("BUILD-INFO.json", canonical_json(info), 0o644))
    entries.append(("README.txt", PACKAGE_README, 0o644))
    license_entries, license_records = _license_entries(
        payload, target_name, sources
    )
    entries.extend(license_entries)
    return sorted(entries, key=lambda item: item[0]), license_records, dependencies


def make_zip(path: Path, entries: list[tuple[str, bytes, int]], epoch: int) -> None:
    import datetime

    timestamp = datetime.datetime.fromtimestamp(epoch, tz=datetime.timezone.utc)
    zip_time = (
        timestamp.year,
        timestamp.month,
        timestamp.day,
        timestamp.hour,
        timestamp.minute,
        timestamp.second,
    )
    with zipfile.ZipFile(
        path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9
    ) as archive:
        for name, data, mode in entries:
            info = zipfile.ZipInfo(name, zip_time)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | mode) << 16
            info.flag_bits |= 0x800
            archive.writestr(
                info,
                data,
                compress_type=zipfile.ZIP_DEFLATED,
                compresslevel=9,
            )


def make_tar_gz(path: Path, entries: list[tuple[str, bytes, int]], epoch: int) -> None:
    with path.open("wb") as output:
        with gzip.GzipFile(
            fileobj=output,
            mode="wb",
            filename="",
            mtime=epoch,
            compresslevel=9,
        ) as compressed:
            with tarfile.open(
                fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT
            ) as archive:
                for name, data, mode in entries:
                    info = tarfile.TarInfo(name)
                    info.size = len(data)
                    info.mode = mode
                    info.mtime = epoch
                    info.uid = 0
                    info.gid = 0
                    info.uname = "root"
                    info.gname = "root"
                    archive.addfile(info, io.BytesIO(data))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True)
    parser.add_argument("--payload", required=True, type=Path)
    parser.add_argument("--build-info", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--sources-file", type=Path)
    parser.add_argument("--signing-evidence", type=Path)
    parser.add_argument("--notarization-submission-result", type=Path)
    parser.add_argument("--notarization-log", type=Path)
    args = parser.parse_args()

    target = require_target(args.target)
    sources = load_sources(args.sources_file)
    executable = "ffmpeg.exe" if target["platform"] == "win32" else "ffmpeg"
    if not args.payload.is_dir() or args.payload.is_symlink():
        raise SystemExit("payload must be a regular directory")
    if args.build_info.is_symlink():
        raise SystemExit("build info must not be a symbolic link")
    payload = args.payload.resolve()
    entries, license_records, dependencies = archive_entries(
        payload,
        args.build_info.resolve(),
        executable,
        args.target,
        sources,
    )
    if args.output_dir.is_symlink():
        raise SystemExit("output directory must not be a symbolic link")
    args.output_dir.mkdir(parents=True, exist_ok=True)
    if not args.output_dir.is_dir() or args.output_dir.is_symlink():
        raise SystemExit("output directory must be a regular directory")
    stem = artifact_stem(sources, args.target)
    archive_path = args.output_dir / f"{stem}.{target['extension']}"
    metadata_path = args.output_dir / f"{archive_path.name}.metadata.json"
    for output_path in (archive_path, metadata_path):
        if output_path.is_symlink() or (
            output_path.exists() and not output_path.is_file()
        ):
            raise SystemExit(f"unsafe existing output path: {output_path}")
    epoch = int(sources["SOURCE_DATE_EPOCH"])
    if target["extension"] == "zip":
        make_zip(archive_path, entries, epoch)
    else:
        make_tar_gz(archive_path, entries, epoch)

    if target["platform"] == "win32" and archive_path.stat().st_size > 256 * 1024 * 1024:
        raise SystemExit("Windows archive exceeds the Motrix verified-downloader limit")
    binary_names = (executable, executable.replace("ffmpeg", "ffprobe"))
    binary_hashes = {name: sha256_file(payload / name) for name in binary_names}
    signing: Optional[dict[str, object]] = None
    if args.signing_evidence:
        if not args.signing_evidence.is_file() or args.signing_evidence.is_symlink():
            raise SystemExit("signing evidence must be a regular file")
        raw_signing = load_json_file(
            args.signing_evidence, "signing evidence", maximum=256 * 1024
        )
        expected_log_name = (
            notarization_log_asset_name(args.target, sources)
            if target["platform"] == "darwin"
            else None
        )
        signing = validate_signing_evidence(
            raw_signing,
            args.target,
            binary_hashes,
            expected_notarization_log_name=expected_log_name,
        )

    notarization_inputs = (
        args.notarization_submission_result,
        args.notarization_log,
    )
    if target["platform"] == "darwin" and signing is not None:
        if any(path is None for path in notarization_inputs):
            raise SystemExit(
                "signed macOS packaging requires the submission result and developer log"
            )
        submission_path = args.notarization_submission_result
        log_path = args.notarization_log
        assert submission_path is not None and log_path is not None
        submission = load_json_file(
            submission_path,
            "notarization submission result",
            maximum=MAX_NOTARIZATION_JSON_BYTES,
        )
        submission_id = validate_notarization_submission(submission)
        notary = signing["notarization"]
        assert isinstance(notary, dict)
        if (
            submission_id != notary["submissionId"]
            or sha256_file(submission_path) != notary["submissionResultSha256"]
        ):
            raise ValueError("notarization submission result does not match signing evidence")
        developer_log = load_json_file(
            log_path,
            "notarization developer log",
            maximum=MAX_NOTARIZATION_JSON_BYTES,
        )
        validate_notarization_log(
            developer_log,
            submission_id=submission_id,
            archive_name=archive_path.name,
            archive_sha256=sha256_file(archive_path),
        )
        log_record = notary["developerLog"]
        assert isinstance(log_record, dict)
        if (
            log_path.stat().st_size != log_record["size"]
            or sha256_file(log_path) != log_record["sha256"]
        ):
            raise ValueError("notarization developer log does not match signing evidence")
        log_destination = args.output_dir / str(log_record["name"])
        if log_path.resolve() != log_destination.resolve():
            if log_destination.exists() or log_destination.is_symlink():
                raise ValueError(
                    f"notarization developer log output already exists: {log_destination}"
                )
            shutil.copyfile(log_path, log_destination)
    elif any(path is not None for path in notarization_inputs):
        raise SystemExit(
            "notarization inputs are accepted only with signed macOS evidence"
        )

    archived = {name: data for name, data, _mode in entries}
    metadata = {
        "schemaVersion": 2,
        "releaseVersion": stem.removeprefix("ffmpeg-").removesuffix(
            f"-{args.target}"
        ),
        "ffmpegVersion": sources["FFMPEG_VERSION"],
        "target": args.target,
        "platform": target["platform"],
        "arch": target["arch"],
        "archive": archive_path.name,
        "archiveSha256": sha256_file(archive_path),
        "archiveSize": archive_path.stat().st_size,
        "binaryPath": executable,
        "binarySha256": binary_hashes[executable],
        "ffprobePath": executable.replace("ffmpeg", "ffprobe"),
        "ffprobeSha256": binary_hashes[executable.replace("ffmpeg", "ffprobe")],
        "buildInfoSha256": digest_bytes(archived["BUILD-INFO.json"]),
        "configureSha256": digest_bytes(archived["configure.txt"]),
        "licensesSha256": digest_bytes(archived["LICENSES.json"]),
        "licenseFiles": license_records,
        "dependencies": dependencies,
        "minimumOs": minimum_os(args.target, sources),
        "license": artifact_license(args.target),
        "signing": signing,
        "signingEvidenceSha256": digest_bytes(canonical_json(signing))
        if signing is not None
        else None,
        "sourceDateEpoch": epoch,
    }
    write_json(metadata_path, metadata)
    print(archive_path)


if __name__ == "__main__":
    main()
