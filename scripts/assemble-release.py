#!/usr/bin/env python3
"""Assemble and verify the complete, all-target release asset set."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import os
import re
import shutil
import stat
import struct
import tarfile
import tempfile
import zipfile
import zlib
from pathlib import Path, PurePosixPath
from typing import BinaryIO, NamedTuple, Optional

from pipeline_lib import (
    MAX_LICENSE_FILE_BYTES,
    MAX_NOTARIZATION_JSON_BYTES,
    PACKAGE_README,
    TARGETS,
    artifact_license,
    artifact_stem,
    canonical_json,
    load_json_bytes,
    load_json_file,
    load_sources,
    minimum_os,
    notarization_log_asset_name,
    parse_configure_record,
    release_tag,
    release_version,
    required_license_files,
    safe_basename,
    sha256_file,
    validate_build_info,
    validate_notarization_log,
    validate_signing_evidence,
    validate_timestamp,
    write_json,
)


MAX_ARCHIVE_MEMBERS = 128
MAX_ARCHIVE_MEMBER_BYTES = 256 * 1024 * 1024
MAX_ARCHIVE_TOTAL_BYTES = 600 * 1024 * 1024
MAX_ARCHIVE_FILE_BYTES = 640 * 1024 * 1024
MAX_TAR_STREAM_BYTES = 640 * 1024 * 1024
CANONICAL_REPOSITORY = "motrixapp/ffmpeg-static"

ZIP_EOCD = struct.Struct("<4s4H2LH")
ZIP_CENTRAL_HEADER = struct.Struct("<4s6H3L5H2L")
ZIP_LOCAL_HEADER = struct.Struct("<4s5H3L2H")


class ZipMemberRecord(NamedTuple):
    name: str
    raw_name: bytes
    version_made: int
    version_needed: int
    flags: int
    method: int
    modified_time: int
    modified_date: int
    crc32: int
    compressed_size: int
    file_size: int
    internal_attr: int
    external_attr: int
    local_offset: int

BASE_ARCHIVE_ENTRIES = {
    "BUILD-INFO.json",
    "LICENSES.json",
    "README.txt",
    "configure.txt",
}

BUILD_PIPELINE_FILES = (
    "LICENSE",
    ".gitattributes",
    "sources.env",
    ".github/actionlint.yaml",
    ".github/workflows/ci.yml",
    ".github/workflows/dependency-audit.yml",
    ".github/workflows/release.yml",
    "keys/ffmpeg-release-signing-key.asc",
    "keys/manifest-ed25519.pub",
    "licenses/FFmpeg-IJG-NOTICE.txt",
    "licenses/GCC-RUNTIME-LIBRARY-EXCEPTION-3.1.txt",
    "licenses/x264-x86inc-ISC.txt",
    "patches/musl-CVE-2026-6042.patch",
    "patches/musl-CVE-2026-40200.patch",
    "scripts/apply_musl_patches.py",
    "scripts/audit_workflow_actions.py",
    "scripts/audit_action_dependencies.py",
    "scripts/assemble-release.py",
    "scripts/build.sh",
    "scripts/common.sh",
    "scripts/fetch-sources.sh",
    "scripts/finalize_signing_grant.py",
    "scripts/generate-third-party-notices.py",
    "scripts/motrix-media-smoke.ps1",
    "scripts/motrix-media-smoke.sh",
    "scripts/notarize-macos.sh",
    "scripts/package-artifact.py",
    "scripts/parse_pe_imports.py",
    "scripts/pipeline_lib.py",
    "scripts/resolve-signtool.ps1",
    "scripts/sign-macos.sh",
    "scripts/sign_release_manifest.py",
    "scripts/validate_signing_input.py",
    "scripts/validate-notarization.py",
    "scripts/verify_authenticode_delta.py",
    "scripts/verify_macho_codesign_delta.py",
    "scripts/verify-binary.sh",
    "scripts/validate_action_review.py",
    "scripts/validate_release_tag.py",
    "security/action-risk-review.json",
    "security/action-reachability-review.json",
    "security/action-dependency-audit.json",
)


def digest_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def validate_member(name: str) -> str:
    path = PurePosixPath(name)
    if (
        not name
        or "\x00" in name
        or "\\" in name
        or path.is_absolute()
        or any(part in ("", ".", "..") for part in path.parts)
        or str(path) != name
    ):
        raise ValueError(f"unsafe archive member: {name!r}")
    return name


def _check_archive_size(
    name: str, size: int, count: int, total: int
) -> int:
    if count > MAX_ARCHIVE_MEMBERS:
        raise ValueError(
            f"archive has more than {MAX_ARCHIVE_MEMBERS} members"
        )
    if size < 0 or size > MAX_ARCHIVE_MEMBER_BYTES:
        raise ValueError(f"archive member is too large: {name}")
    total += size
    if total > MAX_ARCHIVE_TOTAL_BYTES:
        raise ValueError("archive uncompressed size exceeds the release limit")
    return total


def _expected_member_mode(name: str) -> int:
    return 0o755 if PurePosixPath(name).name in {
        "ffmpeg",
        "ffprobe",
        "ffmpeg.exe",
        "ffprobe.exe",
    } else 0o644


def _archive_stat_fingerprint(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _open_archive(path: Path) -> tuple[BinaryIO, os.stat_result]:
    try:
        before = path.lstat()
    except OSError as error:
        raise ValueError(f"cannot stat archive: {path}") from error
    if not stat.S_ISREG(before.st_mode):
        raise ValueError(f"archive is not a regular file: {path.name}")
    if before.st_size > MAX_ARCHIVE_FILE_BYTES:
        raise ValueError("archive compressed size exceeds the release limit")

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_NONBLOCK", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ValueError(f"cannot open archive safely: {path}") from error
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or (before.st_dev, before.st_ino) != (metadata.st_dev, metadata.st_ino)
        ):
            raise ValueError(f"archive changed before it could be opened: {path.name}")
        if metadata.st_size > MAX_ARCHIVE_FILE_BYTES:
            raise ValueError("archive compressed size exceeds the release limit")
        handle = os.fdopen(descriptor, "rb")
        descriptor = -1
        return handle, metadata
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _read_exact(handle: BinaryIO, size: int, description: str) -> bytes:
    data = handle.read(size)
    if len(data) != size:
        raise ValueError(f"truncated {description}")
    return data


def _decode_zip_name(raw_name: bytes, flags: int) -> str:
    encoding = "utf-8" if flags & 0x800 else "cp437"
    try:
        return raw_name.decode(encoding)
    except UnicodeDecodeError as error:
        raise ValueError("invalid zip member encoding") from error


def _validate_zip_payload(
    handle: BinaryIO, record: ZipMemberRecord, data_offset: int
) -> None:
    handle.seek(data_offset)
    remaining = record.compressed_size
    output_size = 0
    checksum = 0
    decompressor = (
        zlib.decompressobj(-zlib.MAX_WBITS)
        if record.method == zipfile.ZIP_DEFLATED
        else None
    )
    while remaining:
        chunk = _read_exact(
            handle,
            min(1024 * 1024, remaining),
            f"zip payload for {record.name}",
        )
        remaining -= len(chunk)
        if decompressor is None:
            output = chunk
        else:
            try:
                output = decompressor.decompress(
                    chunk, record.file_size - output_size + 1
                )
            except zlib.error as error:
                raise ValueError(
                    f"invalid deflate stream for zip member: {record.name}"
                ) from error
            if decompressor.unconsumed_tail:
                raise ValueError(
                    f"zip member expands past its declared size: {record.name}"
                )
            if decompressor.unused_data or (decompressor.eof and remaining):
                raise ValueError(
                    f"zip member contains trailing compressed data: {record.name}"
                )
        output_size += len(output)
        if output_size > record.file_size:
            raise ValueError(
                f"zip member expands past its declared size: {record.name}"
            )
        checksum = zlib.crc32(output, checksum)

    if decompressor is not None:
        try:
            output = decompressor.flush()
        except zlib.error as error:
            raise ValueError(
                f"invalid deflate stream for zip member: {record.name}"
            ) from error
        if decompressor.unused_data or decompressor.unconsumed_tail:
            raise ValueError(
                f"zip member contains trailing compressed data: {record.name}"
            )
        output_size += len(output)
        checksum = zlib.crc32(output, checksum)
        if not decompressor.eof:
            raise ValueError(f"truncated deflate stream for zip member: {record.name}")

    if output_size != record.file_size or checksum & 0xFFFFFFFF != record.crc32:
        raise ValueError(f"zip member size or CRC mismatch: {record.name}")


def _validate_zip_container(
    descriptor: int, archive_size: int, normalized: bool
) -> list[ZipMemberRecord]:
    if archive_size < ZIP_EOCD.size:
        raise ValueError("truncated zip end-of-central-directory record")
    with os.fdopen(os.dup(descriptor), "rb") as handle:
        handle.seek(archive_size - ZIP_EOCD.size)
        (
            signature,
            disk_number,
            central_disk,
            disk_entries,
            total_entries,
            central_size,
            central_offset,
            comment_size,
        ) = ZIP_EOCD.unpack(
            _read_exact(handle, ZIP_EOCD.size, "zip end-of-central-directory record")
        )
        if signature != b"PK\x05\x06" or comment_size != 0:
            raise ValueError("zip EOCD must be the final comment-free record")
        if disk_number != 0 or central_disk != 0 or disk_entries != total_entries:
            raise ValueError("multi-disk zip archives are not allowed")
        if (
            total_entries == 0xFFFF
            or central_size == 0xFFFFFFFF
            or central_offset == 0xFFFFFFFF
        ):
            raise ValueError("ZIP64 archives are not allowed")
        if total_entries > MAX_ARCHIVE_MEMBERS:
            raise ValueError(
                f"archive has more than {MAX_ARCHIVE_MEMBERS} members"
            )
        eocd_offset = archive_size - ZIP_EOCD.size
        if central_offset + central_size != eocd_offset:
            raise ValueError("zip central directory is not contiguous with EOCD")

        handle.seek(central_offset)
        records: list[ZipMemberRecord] = []
        names: set[str] = set()
        total_size = 0
        for count in range(1, total_entries + 1):
            (
                central_signature,
                version_made,
                version_needed,
                flags,
                method,
                modified_time,
                modified_date,
                crc32,
                compressed_size,
                file_size,
                name_size,
                extra_size,
                member_comment_size,
                member_disk,
                internal_attr,
                external_attr,
                local_offset,
            ) = ZIP_CENTRAL_HEADER.unpack(
                _read_exact(handle, ZIP_CENTRAL_HEADER.size, "zip central header")
            )
            if central_signature != b"PK\x01\x02":
                raise ValueError("invalid zip central-directory record")
            if (
                name_size == 0
                or extra_size != 0
                or member_comment_size != 0
                or member_disk != 0
            ):
                raise ValueError(
                    "zip extra fields, comments, and split members are not allowed"
                )
            if (
                compressed_size == 0xFFFFFFFF
                or file_size == 0xFFFFFFFF
                or local_offset == 0xFFFFFFFF
                or version_needed >= 45
            ):
                raise ValueError("ZIP64 archives are not allowed")
            if flags & ~0x800 or flags & 0x8:
                raise ValueError("unsupported zip general-purpose flags")
            allowed_methods = {zipfile.ZIP_DEFLATED}
            if not normalized:
                allowed_methods.add(zipfile.ZIP_STORED)
            if method not in allowed_methods:
                raise ValueError("unsupported zip compression method")
            raw_name = _read_exact(handle, name_size, "zip member name")
            name = validate_member(_decode_zip_name(raw_name, flags))
            if normalized and (
                flags != 0
                or version_made != 0x0314
                or version_needed != 20
                or internal_attr != 0
                or external_attr
                != (
                    stat.S_IFREG | _expected_member_mode(name)
                )
                << 16
                or any(byte >= 0x80 for byte in raw_name)
            ):
                raise ValueError(f"zip member structure is not normalized: {name}")
            if name in names:
                raise ValueError(f"duplicate archive member: {name}")
            names.add(name)
            total_size = _check_archive_size(name, file_size, count, total_size)
            records.append(
                ZipMemberRecord(
                    name,
                    raw_name,
                    version_made,
                    version_needed,
                    flags,
                    method,
                    modified_time,
                    modified_date,
                    crc32,
                    compressed_size,
                    file_size,
                    internal_attr,
                    external_attr,
                    local_offset,
                )
            )
        if handle.tell() != central_offset + central_size:
            raise ValueError("zip central-directory size mismatch")
        if normalized and [record.name for record in records] != sorted(
            record.name for record in records
        ):
            raise ValueError("zip members are not in canonical order")

        cursor = 0
        for record in records:
            if record.local_offset != cursor:
                raise ValueError("zip local records contain a prefix or gap")
            handle.seek(cursor)
            (
                local_signature,
                version_needed,
                flags,
                method,
                modified_time,
                modified_date,
                crc32,
                compressed_size,
                file_size,
                name_size,
                extra_size,
            ) = ZIP_LOCAL_HEADER.unpack(
                _read_exact(handle, ZIP_LOCAL_HEADER.size, "zip local header")
            )
            raw_name = _read_exact(handle, name_size, "zip local member name")
            if (
                local_signature != b"PK\x03\x04"
                or version_needed != record.version_needed
                or flags != record.flags
                or method != record.method
                or modified_time != record.modified_time
                or modified_date != record.modified_date
                or crc32 != record.crc32
                or compressed_size != record.compressed_size
                or file_size != record.file_size
                or raw_name != record.raw_name
                or extra_size != 0
            ):
                raise ValueError(f"zip local/central mismatch: {record.name}")
            data_offset = handle.tell()
            if data_offset + record.compressed_size > central_offset:
                raise ValueError(f"zip member overlaps central directory: {record.name}")
            _validate_zip_payload(handle, record, data_offset)
            cursor = data_offset + record.compressed_size
        if cursor != central_offset:
            raise ValueError("zip local records do not end at the central directory")
    return records


def _decompress_single_gzip(
    descriptor: int, compressed_size: int
) -> tuple[BinaryIO, int]:
    output = tempfile.TemporaryFile(mode="w+b")
    decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
    output_size = 0
    try:
        with os.fdopen(os.dup(descriptor), "rb") as compressed:
            compressed.seek(0)
            remaining = compressed_size
            while remaining:
                chunk = _read_exact(
                    compressed,
                    min(1024 * 1024, remaining),
                    "gzip stream",
                )
                remaining -= len(chunk)
                if decompressor.eof:
                    raise ValueError("gzip stream contains trailing data or another member")
                try:
                    data = decompressor.decompress(
                        chunk, MAX_TAR_STREAM_BYTES - output_size + 1
                    )
                except zlib.error as error:
                    raise ValueError("invalid gzip stream") from error
                output.write(data)
                output_size += len(data)
                if output_size > MAX_TAR_STREAM_BYTES:
                    raise ValueError("decompressed tar stream exceeds the release limit")
                if decompressor.unconsumed_tail:
                    raise ValueError("decompressed tar stream exceeds the release limit")
                if decompressor.unused_data:
                    raise ValueError("gzip stream contains trailing data or another member")
        if not decompressor.eof:
            raise ValueError("truncated gzip stream")
        data = decompressor.flush()
        output.write(data)
        output_size += len(data)
        if (
            output_size > MAX_TAR_STREAM_BYTES
            or decompressor.unused_data
            or decompressor.unconsumed_tail
        ):
            raise ValueError("gzip stream is not a single bounded member")
        output.seek(0)
        return output, output_size
    except Exception:
        output.close()
        raise


def _tar_octal(field: bytes, description: str) -> int:
    if not field or field[0] & 0x80:
        raise ValueError(f"unsupported tar {description}")
    digits = field.strip(b"\x00 ")
    if not digits:
        return 0
    if any(byte < ord("0") or byte > ord("7") for byte in digits):
        raise ValueError(f"invalid tar {description}")
    return int(digits, 8)


def _tar_text(field: bytes, description: str) -> str:
    nul = field.find(b"\x00")
    if nul >= 0:
        if any(field[nul:]):
            raise ValueError(f"non-canonical tar {description}")
        field = field[:nul]
    try:
        return field.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError(f"invalid tar {description}") from error


def _validate_tar_container(
    handle: BinaryIO, stream_size: int, epoch: Optional[int]
) -> list[tuple[str, int]]:
    normalized = epoch is not None
    if stream_size < 1024 or stream_size % tarfile.RECORDSIZE != 0:
        raise ValueError("tar stream does not have canonical record padding")
    handle.seek(0)
    records: list[tuple[str, int]] = []
    names: set[str] = set()
    total_size = 0
    while handle.tell() < stream_size:
        header = _read_exact(handle, tarfile.BLOCKSIZE, "tar header")
        if header == b"\x00" * tarfile.BLOCKSIZE:
            second = _read_exact(handle, tarfile.BLOCKSIZE, "second tar end block")
            if second != b"\x00" * tarfile.BLOCKSIZE:
                raise ValueError("tar stream has only one end block")
            remaining = stream_size - handle.tell()
            expected_padding = (-handle.tell()) % tarfile.RECORDSIZE
            if remaining != expected_padding:
                raise ValueError("tar stream has non-canonical end padding")
            padding = _read_exact(handle, remaining, "tar end padding")
            if any(padding):
                raise ValueError("tar stream contains data after its end blocks")
            break

        stored_checksum = _tar_octal(header[148:156], "checksum")
        checksum_header = header[:148] + b" " * 8 + header[156:]
        if sum(checksum_header) != stored_checksum:
            raise ValueError("invalid tar header checksum")
        name = _tar_text(header[:100], "member name")
        prefix = _tar_text(header[345:500], "member prefix")
        if prefix:
            name = f"{prefix}/{name}"
        name = validate_member(name)
        type_flag = header[156:157]
        if type_flag not in (b"\x00", b"0"):
            raise ValueError(f"non-regular tar member: {name}")
        if any(header[157:257]):
            raise ValueError(f"tar regular member has link data: {name}")
        if any(header[500:512]):
            raise ValueError(f"tar header reserved bytes are nonzero: {name}")
        size = _tar_octal(header[124:136], "member size")
        count = len(records) + 1
        total_size = _check_archive_size(name, size, count, total_size)
        if name in names:
            raise ValueError(f"duplicate archive member: {name}")
        names.add(name)
        if normalized:
            expected_info = tarfile.TarInfo(name)
            expected_info.size = size
            expected_info.mode = _expected_member_mode(name)
            expected_info.mtime = epoch
            expected_info.uid = 0
            expected_info.gid = 0
            expected_info.uname = "root"
            expected_info.gname = "root"
            expected_header = expected_info.tobuf(
                format=tarfile.PAX_FORMAT, encoding="utf-8", errors="strict"
            )
            if len(expected_header) != tarfile.BLOCKSIZE or header != expected_header:
                raise ValueError(f"tar member structure is not normalized: {name}")
        data_end = handle.tell() + size
        padded_end = handle.tell() + ((size + 511) // 512) * 512
        if padded_end > stream_size:
            raise ValueError(f"truncated tar member: {name}")
        handle.seek(data_end)
        padding = _read_exact(handle, padded_end - data_end, "tar member padding")
        if any(padding):
            raise ValueError(f"tar member padding is nonzero: {name}")
        records.append((name, size))
    else:
        raise ValueError("tar stream has no end blocks")

    if normalized and [name for name, _size in records] != sorted(
        name for name, _size in records
    ):
        raise ValueError("tar members are not in canonical order")
    handle.seek(0)
    return records


def _archive_files_from_open_archive(
    path: Path,
    archive_source: BinaryIO,
    archive_size: int,
    epoch: Optional[int],
) -> dict[str, bytes]:
    files: dict[str, bytes] = {}
    total = 0
    if path.name.endswith(".tar.gz"):
        if epoch is not None:
            archive_source.seek(0)
            header = archive_source.read(10)
            if (
                len(header) != 10
                or header[:3] != b"\x1f\x8b\x08"
                or header[3] != 0
                or int.from_bytes(header[4:8], "little") != epoch
                or header[8:] != b"\x02\xff"
            ):
                raise ValueError("gzip header is not normalized")
        tar_stream, tar_size = _decompress_single_gzip(
            archive_source.fileno(), archive_size
        )
        try:
            raw_records = _validate_tar_container(
                tar_stream, tar_size, epoch
            )
            with tarfile.open(fileobj=tar_stream, mode="r:") as archive:
                members = archive.getmembers()
                if [(member.name, member.size) for member in members] != raw_records:
                    raise ValueError("tar parser view does not match physical records")
                for count, member in enumerate(members, start=1):
                    validate_member(member.name)
                    if not member.isfile() or member.issym() or member.islnk():
                        raise ValueError(f"non-regular tar member: {member.name}")
                    if member.name in files:
                        raise ValueError(f"duplicate archive member: {member.name}")
                    total = _check_archive_size(
                        member.name, member.size, count, total
                    )
                    if epoch is not None and (
                        member.mode != _expected_member_mode(member.name)
                        or member.uid != 0
                        or member.gid != 0
                        or member.uname != "root"
                        or member.gname != "root"
                        or member.mtime != epoch
                        or member.pax_headers
                    ):
                        raise ValueError(
                            f"tar member metadata is not normalized: {member.name}"
                        )
                    handle = archive.extractfile(member)
                    if handle is None:
                        raise ValueError(f"unreadable tar member: {member.name}")
                    data = handle.read(member.size + 1)
                    if len(data) != member.size:
                        raise ValueError(f"tar member size mismatch: {member.name}")
                    files[member.name] = data
        finally:
            tar_stream.close()
    elif path.suffix == ".zip":
        raw_records = _validate_zip_container(
            archive_source.fileno(), archive_size, epoch is not None
        )
        archive_source.seek(0)
        with zipfile.ZipFile(archive_source) as archive:
            if archive.comment:
                raise ValueError("zip archive comment is not allowed")
            members = archive.infolist()
            if [member.filename for member in members] != [
                record.name for record in raw_records
            ]:
                raise ValueError("zip parser view does not match physical records")
            if len(members) > MAX_ARCHIVE_MEMBERS:
                raise ValueError(
                    f"archive has more than {MAX_ARCHIVE_MEMBERS} members"
                )
            for count, member in enumerate(members, start=1):
                validate_member(member.filename)
                if member.is_dir():
                    raise ValueError(
                        f"unexpected zip directory entry: {member.filename}"
                    )
                if member.filename in files:
                    raise ValueError(f"duplicate archive member: {member.filename}")
                mode = (member.external_attr >> 16) & 0o170000
                if mode not in (0, 0o100000):
                    raise ValueError(f"non-regular zip member: {member.filename}")
                if member.flag_bits & 0x1:
                    raise ValueError(f"encrypted zip member: {member.filename}")
                total = _check_archive_size(
                    member.filename, member.file_size, count, total
                )
                if epoch is not None:
                    timestamp = dt_from_epoch(epoch)
                    if (
                        member.create_system != 3
                        or member.external_attr
                        != (
                            stat.S_IFREG
                            | _expected_member_mode(member.filename)
                        )
                        << 16
                        or member.date_time != timestamp
                        or member.extra
                        or member.comment
                        or member.compress_type != zipfile.ZIP_DEFLATED
                    ):
                        raise ValueError(
                            f"zip member metadata is not normalized: {member.filename}"
                        )
                with archive.open(member, "r") as handle:
                    data = handle.read(member.file_size + 1)
                if len(data) != member.file_size:
                    raise ValueError(f"zip member size mismatch: {member.filename}")
                files[member.filename] = data
    else:
        raise ValueError(f"unsupported archive: {path.name}")
    return files


def archive_files(path: Path, epoch: Optional[int] = None) -> dict[str, bytes]:
    archive_source, initial_metadata = _open_archive(path)
    try:
        files = _archive_files_from_open_archive(
            path, archive_source, initial_metadata.st_size, epoch
        )
        final_metadata = os.fstat(archive_source.fileno())
        if _archive_stat_fingerprint(final_metadata) != _archive_stat_fingerprint(
            initial_metadata
        ):
            raise ValueError(f"archive changed while it was being read: {path.name}")
        return files
    finally:
        archive_source.close()


def dt_from_epoch(epoch: int) -> tuple[int, int, int, int, int, int]:
    import datetime

    timestamp = datetime.datetime.fromtimestamp(epoch, tz=datetime.timezone.utc)
    return (
        timestamp.year,
        timestamp.month,
        timestamp.day,
        timestamp.hour,
        timestamp.minute,
        timestamp.second,
    )


def _validate_license_manifest(
    files: dict[str, bytes],
    metadata: dict[str, object],
    target_name: str,
    sources: dict[str, str],
) -> None:
    manifest_data = files["LICENSES.json"]
    if digest_bytes(manifest_data) != metadata.get("licensesSha256"):
        raise ValueError("license manifest checksum mismatch")
    manifest = load_json_bytes(
        manifest_data, "LICENSES.json", maximum=256 * 1024
    )
    expected_descriptors = required_license_files(target_name)
    expected_records = []
    for name, (
        component,
        document_license,
        effective_component_license,
        hash_key,
    ) in sorted(
        expected_descriptors.items()
    ):
        archive_path = f"LICENSES/{name}"
        data = files[archive_path]
        if not data or len(data) > MAX_LICENSE_FILE_BYTES:
            raise ValueError(f"license file has an invalid size: {archive_path}")
        if name == "THIRD-PARTY-NOTICES.txt" and len(data) != int(
            sources["THIRD_PARTY_NOTICES_SIZE"]
        ):
            raise ValueError(
                f"generated notice file has an unexpected size: {archive_path}"
            )
        try:
            data.decode("utf-8")
        except UnicodeDecodeError as error:
            raise ValueError(f"license file is not UTF-8: {archive_path}") from error
        digest = digest_bytes(data)
        if digest != sources[hash_key]:
            raise ValueError(
                f"license file does not match its source lock: {archive_path}"
            )
        expected_records.append(
            {
                "component": component,
                "documentLicense": document_license,
                "effectiveComponentLicense": effective_component_license,
                "path": archive_path,
                "sha256": digest,
            }
        )
    expected_manifest = {
        "schemaVersion": 2,
        "target": target_name,
        "files": expected_records,
    }
    if manifest != expected_manifest:
        raise ValueError("license manifest does not match required platform notices")
    if metadata.get("licenseFiles") != expected_records:
        raise ValueError("metadata license list does not match LICENSES.json")


def verify_target(
    metadata_path: Path,
    sources: dict[str, str],
    *,
    require_signing: str = "none",
) -> dict[str, object]:
    metadata = load_json_file(
        metadata_path, "artifact metadata", maximum=512 * 1024
    )
    if not isinstance(metadata, dict):
        raise ValueError(f"{metadata_path}: metadata must be an object")
    if metadata.get("schemaVersion") != 2:
        raise ValueError(f"{metadata_path}: unsupported schema")
    for legacy in ("codesigned", "notarized", "notarizationId"):
        if legacy in metadata:
            raise ValueError(f"{metadata_path}: legacy self-reported signing field {legacy}")
    expected_metadata_keys = {
        "schemaVersion",
        "releaseVersion",
        "ffmpegVersion",
        "target",
        "platform",
        "arch",
        "archive",
        "archiveSha256",
        "archiveSize",
        "binaryPath",
        "binarySha256",
        "ffprobePath",
        "ffprobeSha256",
        "buildInfoSha256",
        "configureSha256",
        "licensesSha256",
        "licenseFiles",
        "dependencies",
        "minimumOs",
        "license",
        "signing",
        "signingEvidenceSha256",
        "sourceDateEpoch",
    }
    if set(metadata) != expected_metadata_keys:
        raise ValueError(f"{metadata_path}: metadata fields do not match schema 2")
    for key in (
        "archiveSha256",
        "binarySha256",
        "ffprobeSha256",
        "buildInfoSha256",
        "configureSha256",
        "licensesSha256",
    ):
        if not isinstance(metadata[key], str) or not re.fullmatch(
            r"[0-9a-f]{64}", metadata[key]
        ):
            raise ValueError(f"{metadata_path}: invalid {key}")
    if type(metadata["archiveSize"]) is not int or metadata["archiveSize"] <= 0:
        raise ValueError(f"{metadata_path}: invalid archive size")
    target_name = metadata.get("target")
    if target_name not in TARGETS:
        raise ValueError(f"{metadata_path}: unsupported target {target_name!r}")
    target_name = str(target_name)
    target = TARGETS[target_name]
    for key in ("platform", "arch"):
        if metadata.get(key) != target[key]:
            raise ValueError(f"{metadata_path}: {key} mismatch")
    if metadata.get("releaseVersion") != release_version(sources):
        raise ValueError(f"{metadata_path}: release version mismatch")
    if metadata.get("ffmpegVersion") != sources["FFMPEG_VERSION"]:
        raise ValueError(f"{metadata_path}: FFmpeg version mismatch")

    expected_archive = f"{artifact_stem(sources, target_name)}.{target['extension']}"
    archive_name = safe_basename(str(metadata.get("archive", "")))
    if archive_name != expected_archive:
        raise ValueError(
            f"{metadata_path}: unexpected archive name {archive_name!r}"
        )
    archive_path = metadata_path.parent / archive_name
    if not archive_path.is_file() or archive_path.is_symlink():
        raise ValueError(f"missing regular archive: {archive_path}")
    if sha256_file(archive_path) != metadata.get("archiveSha256"):
        raise ValueError(f"{archive_path}: checksum mismatch")
    if archive_path.stat().st_size != metadata.get("archiveSize"):
        raise ValueError(f"{archive_path}: size mismatch")

    files = archive_files(archive_path, int(sources["SOURCE_DATE_EPOCH"]))
    binary = "ffmpeg.exe" if target["platform"] == "win32" else "ffmpeg"
    ffprobe = "ffprobe.exe" if target["platform"] == "win32" else "ffprobe"
    if metadata.get("binaryPath") != binary or metadata.get("ffprobePath") != ffprobe:
        raise ValueError(f"{metadata_path}: unexpected executable paths")
    expected = (
        BASE_ARCHIVE_ENTRIES
        | {f"LICENSES/{name}" for name in required_license_files(target_name)}
        | {binary, ffprobe}
    )
    if set(files) != expected:
        missing = sorted(expected - files.keys())
        extra = sorted(files.keys() - expected)
        raise ValueError(
            f"{archive_path}: members mismatch; missing={missing}, extra={extra}"
        )
    if files["README.txt"] != PACKAGE_README:
        raise ValueError(f"{archive_path}: package README contract mismatch")
    for name in ("BUILD-INFO.json", "configure.txt", "LICENSES.json"):
        if not files[name] or len(files[name]) > 256 * 1024:
            raise ValueError(f"{archive_path}: invalid size for {name}")
    for name in (binary, ffprobe):
        if not files[name] or len(files[name]) > 256 * 1024 * 1024:
            raise ValueError(f"{archive_path}: invalid binary size for {name}")
    binary_hashes = {
        binary: digest_bytes(files[binary]),
        ffprobe: digest_bytes(files[ffprobe]),
    }
    if binary_hashes[binary] != metadata.get("binarySha256"):
        raise ValueError(f"{archive_path}: ffmpeg checksum mismatch")
    if binary_hashes[ffprobe] != metadata.get("ffprobeSha256"):
        raise ValueError(f"{archive_path}: ffprobe checksum mismatch")
    if digest_bytes(files["BUILD-INFO.json"]) != metadata.get("buildInfoSha256"):
        raise ValueError(f"{archive_path}: build info checksum mismatch")
    if digest_bytes(files["configure.txt"]) != metadata.get("configureSha256"):
        raise ValueError(f"{archive_path}: configure checksum mismatch")

    build_info = load_json_bytes(
        files["BUILD-INFO.json"], "BUILD-INFO.json", maximum=256 * 1024
    )
    configure_args = parse_configure_record(files["configure.txt"])
    _normalized_info, dependencies = validate_build_info(
        build_info, target_name, sources, configure_args
    )
    if metadata.get("dependencies") != dependencies:
        raise ValueError(f"{metadata_path}: dependency mismatch")
    _validate_license_manifest(files, metadata, target_name, sources)

    if metadata.get("license") != artifact_license(target_name):
        raise ValueError(f"{metadata_path}: license mismatch")
    if metadata.get("sourceDateEpoch") != int(sources["SOURCE_DATE_EPOCH"]):
        raise ValueError(f"{metadata_path}: source date epoch mismatch")
    if metadata.get("minimumOs") != minimum_os(target_name, sources):
        raise ValueError(f"{metadata_path}: minimum OS contract mismatch")

    signing = metadata.get("signing")
    if signing is None:
        if metadata.get("signingEvidenceSha256") is not None:
            raise ValueError(f"{metadata_path}: unexpected signing evidence digest")
    else:
        normalized_signing = validate_signing_evidence(
            signing,
            target_name,
            binary_hashes,
            expected_notarization_log_name=(
                notarization_log_asset_name(target_name, sources)
                if target["platform"] == "darwin"
                else None
            ),
        )
        if signing != normalized_signing:
            raise ValueError(
                f"{metadata_path}: signing evidence is not in canonical form"
            )
        signing = normalized_signing
        metadata["signing"] = normalized_signing
        if metadata.get("signingEvidenceSha256") != digest_bytes(
            canonical_json(normalized_signing)
        ):
            raise ValueError(f"{metadata_path}: signing evidence checksum mismatch")
        if target["platform"] == "darwin":
            notary = normalized_signing["notarization"]
            log_record = notary["developerLog"]
            log_path = metadata_path.parent / safe_basename(str(log_record["name"]))
            if (
                not log_path.is_file()
                or log_path.is_symlink()
                or log_path.stat().st_size != log_record["size"]
                or sha256_file(log_path) != log_record["sha256"]
            ):
                raise ValueError(
                    f"{metadata_path}: notarization developer log asset mismatch"
                )
            developer_log = load_json_file(
                log_path,
                "notarization developer log",
                maximum=MAX_NOTARIZATION_JSON_BYTES,
            )
            validate_notarization_log(
                developer_log,
                submission_id=str(notary["submissionId"]),
                archive_name=archive_name,
                archive_sha256=str(metadata["archiveSha256"]),
            )
    needs_signing = require_signing == "all" and target["platform"] in {
        "darwin",
        "win32",
    }
    needs_signing = needs_signing or (
        require_signing == "macos" and target["platform"] == "darwin"
    )
    if needs_signing and signing is None:
        raise ValueError(f"{metadata_path}: release artifact lacks signing evidence")
    if target["platform"] == "linux" and signing is not None:
        raise ValueError(f"{metadata_path}: Linux artifact has unexpected signing evidence")
    return metadata


def _spdx_id(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9.-]", "-", value)


def _component_packages(
    sources: dict[str, str], targets: dict[str, dict[str, object]]
) -> list[dict[str, object]]:
    packages: list[dict[str, object]] = [
        {
            "name": "FFmpeg",
            "SPDXID": "SPDXRef-Source-FFmpeg",
            "versionInfo": sources["FFMPEG_VERSION"],
            "downloadLocation": sources["FFMPEG_URL"],
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": "NOASSERTION",
            "checksums": [
                {"algorithm": "SHA256", "checksumValue": sources["FFMPEG_SHA256"]}
            ],
            "filesAnalyzed": False,
        },
        {
            "name": "Independent JPEG Group DCT code embedded in FFmpeg",
            "SPDXID": "SPDXRef-Embedded-IJG-DCT",
            "versionInfo": sources["FFMPEG_VERSION"],
            "downloadLocation": "NOASSERTION",
            "licenseConcluded": "IJG",
            "licenseDeclared": "IJG",
            "filesAnalyzed": False,
            "packageComment": (
                "Embedded unchanged from authenticated FFmpeg sources: "
                "libavcodec/jfdctfst.c, libavcodec/jfdctint_template.c, and "
                "libavcodec/jrevdct.c."
            ),
        },
        {
            "name": "Glumpy-derived filters embedded in FFmpeg",
            "SPDXID": "SPDXRef-Embedded-Glumpy-Filters",
            "versionInfo": sources["FFMPEG_VERSION"],
            "downloadLocation": "NOASSERTION",
            "licenseConcluded": "BSD-3-Clause",
            "licenseDeclared": "BSD-3-Clause",
            "filesAnalyzed": False,
            "packageComment": (
                "Glumpy-derived filter code and the Nicolas P. Rougier "
                "attribution are embedded in authenticated FFmpeg "
                "libswscale/filters.c."
            ),
        },
        {
            "name": "x264 x86inc assembly abstraction embedded in x86-64 builds",
            "SPDXID": "SPDXRef-Embedded-x264-x86inc",
            "versionInfo": sources["X264_REVISION"],
            "downloadLocation": "NOASSERTION",
            "licenseConcluded": "ISC",
            "licenseDeclared": "ISC",
            "filesAnalyzed": False,
            "packageComment": (
                "common/x86/x86inc.asm from the authenticated x264 source; "
                "only x86-64 target binaries include this assembly helper."
            ),
        },
        {
            "name": "x264",
            "SPDXID": "SPDXRef-Source-x264",
            "versionInfo": sources["X264_REVISION"],
            "downloadLocation": sources["X264_URL"],
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": "NOASSERTION",
            "checksums": [
                {"algorithm": "SHA256", "checksumValue": sources["X264_SHA256"]}
            ],
            "filesAnalyzed": False,
        },
        {
            "name": "LAME",
            "SPDXID": "SPDXRef-Source-LAME",
            "versionInfo": sources["LAME_VERSION"],
            "downloadLocation": sources["LAME_URL"],
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": "NOASSERTION",
            "checksums": [
                {"algorithm": "SHA256", "checksumValue": sources["LAME_SHA256"]}
            ],
            "filesAnalyzed": False,
        },
        {
            "name": "musl",
            "SPDXID": "SPDXRef-Source-musl",
            "packageComment": (
                "Upstream 1.2.6 plus official CVE-2026-6042 and CVE-2026-40200 "
                "backports. Both patch files and the application script are in "
                "the published build-pipeline archive; patch/result hashes are "
                "bound by sources.env. The upstream archive remains unmodified."
            ),
            "versionInfo": sources["MUSL_VERSION"],
            "downloadLocation": sources["MUSL_URL"],
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": "NOASSERTION",
            "checksums": [
                {"algorithm": "SHA256", "checksumValue": sources["MUSL_SHA256"]}
            ],
            "filesAnalyzed": False,
        },
        {
            "name": "NASM source-built assembler",
            "SPDXID": "SPDXRef-BuildTool-NASM",
            "versionInfo": sources["NASM_VERSION"],
            "downloadLocation": sources["NASM_URL"],
            "licenseConcluded": "BSD-2-Clause",
            "licenseDeclared": "BSD-2-Clause",
            "checksums": [
                {"algorithm": "SHA256", "checksumValue": sources["NASM_SHA256"]}
            ],
            "filesAnalyzed": False,
            "packageComment": (
                "Build-only assembler compiled from this checksum-bound source "
                "on each x86-64 build host; no runner NASM is accepted."
            ),
        },
        {
            "name": "x264 compiled core",
            "SPDXID": "SPDXRef-Compiled-x264-core",
            "versionInfo": sources["X264_REVISION"],
            "downloadLocation": "NOASSERTION",
            "licenseConcluded": "GPL-2.0-or-later",
            "licenseDeclared": "GPL-2.0-or-later",
            "filesAnalyzed": False,
        },
        {
            "name": "LAME compiled library",
            "SPDXID": "SPDXRef-Compiled-LAME",
            "versionInfo": sources["LAME_VERSION"],
            "downloadLocation": "NOASSERTION",
            "licenseConcluded": "LGPL-2.1-or-later",
            "licenseDeclared": "LGPL-2.1-or-later",
            "filesAnalyzed": False,
            "packageComment": (
                "The effective compiled component includes gain_analysis code "
                "under LGPL-2.1-or-later."
            ),
        },
        {
            "name": "fortify-headers",
            "SPDXID": "SPDXRef-Source-fortify-headers",
            "versionInfo": sources["FORTIFY_HEADERS_VERSION"],
            "downloadLocation": sources["FORTIFY_HEADERS_URL"],
            "licenseConcluded": "0BSD",
            "licenseDeclared": "0BSD",
            "checksums": [
                {
                    "algorithm": "SHA256",
                    "checksumValue": sources["FORTIFY_HEADERS_SHA256"],
                }
            ],
            "filesAnalyzed": False,
            "packageComment": (
                "Pinned peeled Git revision: "
                f"{sources['FORTIFY_HEADERS_REVISION']}"
            ),
        },
        {
            "name": "llvm-mingw toolchain",
            "SPDXID": "SPDXRef-Toolchain-llvm-mingw",
            "versionInfo": sources["LLVM_MINGW_VERSION"],
            "downloadLocation": sources["LLVM_MINGW_URL"],
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": "NOASSERTION",
            "checksums": [
                {
                    "algorithm": "SHA256",
                    "checksumValue": sources["LLVM_MINGW_SHA256"],
                }
            ],
            "filesAnalyzed": False,
            "packageComment": (
                "Checksum-bound composite toolchain archive. Its upstream "
                "release recipe identifies LLVM revision "
                f"{sources['LLVM_RUNTIME_REVISION']}; mingw-w64 revision "
                f"{sources['MINGW_W64_REVISION']}. The pipeline also verifies "
                "the exact LLVM commit reported by the packaged clang binary."
            ),
        },
        {
            "name": "llvm-mingw release build recipe",
            "SPDXID": "SPDXRef-Source-llvm-mingw-recipe",
            "versionInfo": sources["LLVM_MINGW_RECIPE_REVISION"],
            "downloadLocation": sources["LLVM_MINGW_RECIPE_URL"],
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": "NOASSERTION",
            "checksums": [
                {
                    "algorithm": "SHA256",
                    "checksumValue": sources["LLVM_MINGW_RECIPE_SHA256"],
                }
            ],
            "filesAnalyzed": False,
            "packageComment": (
                "Checksum-bound upstream recipe used to machine-verify the "
                "declared LLVM and mingw-w64 inputs of release 20260616."
            ),
        },
        {
            "name": "llvm-project source archive for compiler-rt provenance",
            "SPDXID": "SPDXRef-Source-llvm-compiler-rt",
            "versionInfo": sources["LLVM_RUNTIME_REVISION"],
            "downloadLocation": sources["LLVM_RUNTIME_URL"],
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": "NOASSERTION",
            "checksums": [
                {
                    "algorithm": "SHA256",
                    "checksumValue": sources["LLVM_RUNTIME_SHA256"],
                }
            ],
            "filesAnalyzed": False,
            "packageComment": (
                "The release publishes this immutable llvm-project archive "
                "for the compiler-rt revision statically linked by llvm-mingw."
            ),
        },
        {
            "name": "MinGW-w64 runtime upstream provenance",
            "SPDXID": "SPDXRef-Source-mingw-w64-runtime",
            "versionInfo": sources["MINGW_W64_REVISION"],
            "downloadLocation": sources["MINGW_W64_URL"],
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": "NOASSERTION",
            "checksums": [
                {
                    "algorithm": "SHA256",
                    "checksumValue": sources["MINGW_W64_SHA256"],
                }
            ],
            "filesAnalyzed": False,
            "packageComment": (
                "Pinned upstream provenance claimed by the checksum-bound "
                "llvm-mingw release recipe. The authenticated upstream tree "
                "contains disputed Cephes/Moshier-derived material, so its full "
                "archive is intentionally not republished as a Motrix Release "
                "asset. Final ffmpeg/ffprobe link maps and traces for both "
                "Windows architectures prove that none of the 14 prohibited "
                "objects is linked."
            ),
        },
    ]
    seen = {package["SPDXID"] for package in packages}
    for target_name in TARGETS:
        for dependency in targets[target_name]["dependencies"]:  # type: ignore[index]
            dependency_id = (
                f"SPDXRef-Dependency-{_spdx_id(dependency['name'])}-"
                f"{_spdx_id(dependency['version'])}"
            )
            if dependency_id in seen:
                continue
            seen.add(dependency_id)
            comments = {
                "fortify-headers": (
                    "Header-inline build dependency generated from the locked "
                    f"fortify-headers revision {sources['FORTIFY_HEADERS_REVISION']}."
                ),
                "musl": (
                    "Compiled from locked musl 1.2.6 with official CVE-2026-6042 "
                    "and CVE-2026-40200 backports. Patch and post-patch source "
                    "hashes are locked in sources.env; exact patches are in "
                    "the corresponding build-pipeline source archive."
                ),
                "gcc-runtime": (
                    "Static GCC runtime selected from the controlled Linux compiler; "
                    "the build record binds its measured version to that compiler."
                ),
                "llvm-compiler-rt": (
                    "Runtime from the locked llvm-mingw toolchain; LLVM revision "
                    f"{sources['LLVM_RUNTIME_REVISION']}."
                ),
                "mingw-w64-runtime": (
                    "Runtime from the locked llvm-mingw toolchain; mingw-w64 revision "
                    f"{sources['MINGW_W64_REVISION']}."
                ),
            }
            package: dict[str, object] = {
                "name": dependency["name"],
                "SPDXID": dependency_id,
                "versionInfo": dependency["version"],
                "downloadLocation": "NOASSERTION",
                "licenseConcluded": dependency["license"],
                "licenseDeclared": dependency["license"],
                "filesAnalyzed": False,
                "packageComment": comments[dependency["name"]],
            }
            packages.append(package)
    return packages


def spdx_document(
    sources: dict[str, str],
    namespace: str,
    repository: str,
    targets: dict[str, dict[str, object]],
    artifacts_dir: Path,
    created: str,
) -> dict[str, object]:
    created = validate_timestamp(created, "SPDX document creation time")
    packages = _component_packages(sources, targets)
    files: list[dict[str, object]] = []
    relationships: list[dict[str, str]] = []
    described: list[str] = []
    release_url = f"https://github.com/{repository}/releases/download/{release_tag(sources)}"

    relationships.append(
        {
            "spdxElementId": "SPDXRef-Embedded-IJG-DCT",
            "relationshipType": "GENERATED_FROM",
            "relatedSpdxElement": "SPDXRef-Source-FFmpeg",
        }
    )
    relationships.append(
        {
            "spdxElementId": "SPDXRef-Embedded-Glumpy-Filters",
            "relationshipType": "GENERATED_FROM",
            "relatedSpdxElement": "SPDXRef-Source-FFmpeg",
        }
    )
    relationships.append(
        {
            "spdxElementId": "SPDXRef-Embedded-x264-x86inc",
            "relationshipType": "GENERATED_FROM",
            "relatedSpdxElement": "SPDXRef-Source-x264",
        }
    )
    relationships.extend(
        [
            {
                "spdxElementId": "SPDXRef-Compiled-x264-core",
                "relationshipType": "GENERATED_FROM",
                "relatedSpdxElement": "SPDXRef-Source-x264",
            },
            {
                "spdxElementId": "SPDXRef-Compiled-LAME",
                "relationshipType": "GENERATED_FROM",
                "relatedSpdxElement": "SPDXRef-Source-LAME",
            },
            {
                "spdxElementId": "SPDXRef-Toolchain-llvm-mingw",
                "relationshipType": "GENERATED_FROM",
                "relatedSpdxElement": "SPDXRef-Source-llvm-mingw-recipe",
            },
            {
                "spdxElementId": "SPDXRef-Toolchain-llvm-mingw",
                "relationshipType": "GENERATED_FROM",
                "relatedSpdxElement": "SPDXRef-Source-llvm-compiler-rt",
            },
            {
                "spdxElementId": "SPDXRef-Toolchain-llvm-mingw",
                "relationshipType": "GENERATED_FROM",
                "relatedSpdxElement": "SPDXRef-Source-mingw-w64-runtime",
            },
        ]
    )
    dependency_origins: set[tuple[str, str]] = set()
    for target_name in TARGETS:
        for dependency in targets[target_name]["dependencies"]:  # type: ignore[index]
            dependency_id = (
                f"SPDXRef-Dependency-{_spdx_id(dependency['name'])}-"
                f"{_spdx_id(dependency['version'])}"
            )
            if dependency["name"] == "musl":
                origin_id = "SPDXRef-Source-musl"
            elif dependency["name"] == "fortify-headers":
                origin_id = "SPDXRef-Source-fortify-headers"
            elif dependency["name"] == "llvm-compiler-rt":
                origin_id = "SPDXRef-Source-llvm-compiler-rt"
            elif dependency["name"] == "mingw-w64-runtime":
                origin_id = "SPDXRef-Source-mingw-w64-runtime"
            else:
                continue
            pair = (dependency_id, origin_id)
            if pair not in dependency_origins:
                dependency_origins.add(pair)
                relationships.append(
                    {
                        "spdxElementId": dependency_id,
                        "relationshipType": "GENERATED_FROM",
                        "relatedSpdxElement": origin_id,
                    }
                )

    for target_name in TARGETS:
        metadata = targets[target_name]
        target_license = artifact_license(target_name)
        artifact_id = f"SPDXRef-Artifact-{_spdx_id(target_name)}"
        archive_id = f"SPDXRef-File-Archive-{_spdx_id(target_name)}"
        ffmpeg_id = f"SPDXRef-File-ffmpeg-{_spdx_id(target_name)}"
        ffprobe_id = f"SPDXRef-File-ffprobe-{_spdx_id(target_name)}"
        described.append(artifact_id)
        if TARGETS[target_name]["arch"] == "x64":
            relationships.append(
                {
                    "spdxElementId": "SPDXRef-BuildTool-NASM",
                    "relationshipType": "BUILD_TOOL_OF",
                    "relatedSpdxElement": artifact_id,
                }
            )
        signing = metadata.get("signing")
        if isinstance(signing, dict) and signing.get("kind") == "apple-developer-id":
            developer_log = signing["notarization"]["developerLog"]
            signing_comment = (
                f"Apple Developer ID Team {signing['identity']['teamId']}, "
                f"certificate SHA-256 {signing['identity']['certificateSha256']}, "
                f"notarization {signing['notarization']['submissionId']}, "
                f"developer log {developer_log['name']} SHA-256 "
                f"{developer_log['sha256']}."
            )
        elif isinstance(signing, dict) and signing.get("kind") == "authenticode":
            timestamp_authorities = sorted(
                {
                    record["timestampAuthorityCertificateSha256"]
                    for record in signing["binaries"].values()
                }
            )
            signing_comment = (
                f"Authenticode subject {signing['identity']['subject']}, "
                f"certificate SHA-256 {signing['identity']['thumbprint']}, "
                f"SignTool {signing['tool']['version']} "
                f"{signing['tool']['architecture']} SHA-256 "
                f"{signing['tool']['sha256']}, "
                "timestamp authority certificate SHA-256 "
                f"{', '.join(timestamp_authorities)}."
            )
        elif TARGETS[target_name]["platform"] == "linux":
            signing_comment = (
                "Linux authenticity is supplied by the release attestations; "
                "there is no platform code signature."
            )
        else:
            signing_comment = "Unsigned workflow_dispatch test artifact."
        packages.append(
            {
                "name": metadata["archive"],
                "SPDXID": artifact_id,
                "versionInfo": release_version(sources),
                "downloadLocation": f"{release_url}/{metadata['archive']}",
                "licenseConcluded": target_license,
                "licenseDeclared": target_license,
                "filesAnalyzed": False,
                "primaryPackagePurpose": "APPLICATION",
                "packageComment": (
                    f"Standalone Motrix FFmpeg target: {target_name}. "
                    f"{signing_comment}"
                ),
                "checksums": [
                    {
                        "algorithm": "SHA256",
                        "checksumValue": metadata["archiveSha256"],
                    }
                ],
            }
        )
        files.extend(
            [
                {
                    "fileName": f"./{metadata['archive']}",
                    "SPDXID": archive_id,
                    "checksums": [
                        {
                            "algorithm": "SHA256",
                            "checksumValue": metadata["archiveSha256"],
                        }
                    ],
                    "fileTypes": ["ARCHIVE"],
                    "licenseConcluded": target_license,
                    "licenseInfoInFiles": ["NOASSERTION"],
                    "copyrightText": "NOASSERTION",
                },
                {
                    "fileName": f"./{metadata['archive']}#{metadata['binaryPath']}",
                    "SPDXID": ffmpeg_id,
                    "checksums": [
                        {
                            "algorithm": "SHA256",
                            "checksumValue": metadata["binarySha256"],
                        }
                    ],
                    "fileTypes": ["BINARY"],
                    "licenseConcluded": target_license,
                    "licenseInfoInFiles": ["NOASSERTION"],
                    "copyrightText": "NOASSERTION",
                },
                {
                    "fileName": f"./{metadata['archive']}#{metadata['ffprobePath']}",
                    "SPDXID": ffprobe_id,
                    "checksums": [
                        {
                            "algorithm": "SHA256",
                            "checksumValue": metadata["ffprobeSha256"],
                        }
                    ],
                    "fileTypes": ["BINARY"],
                    "licenseConcluded": target_license,
                    "licenseInfoInFiles": ["NOASSERTION"],
                    "copyrightText": "NOASSERTION",
                },
            ]
        )
        if isinstance(signing, dict) and signing.get("kind") == "apple-developer-id":
            log_record = signing["notarization"]["developerLog"]
            log_id = f"SPDXRef-File-NotarizationLog-{_spdx_id(target_name)}"
            files.append(
                {
                    "fileName": f"./{log_record['name']}",
                    "SPDXID": log_id,
                    "checksums": [
                        {
                            "algorithm": "SHA256",
                            "checksumValue": log_record["sha256"],
                        }
                    ],
                    "fileTypes": ["OTHER"],
                    "licenseConcluded": "NOASSERTION",
                    "licenseInfoInFiles": ["NOASSERTION"],
                    "copyrightText": "NOASSERTION",
                    "comment": (
                        "Apple notary service developer log for the exact "
                        f"{metadata['archive']} archive."
                    ),
                }
            )
            relationships.append(
                {
                    "spdxElementId": log_id,
                    "relationshipType": "OTHER",
                    "relatedSpdxElement": archive_id,
                    "comment": "Apple notarization evidence for this exact archive.",
                }
            )
        relationships.extend(
            [
                {
                    "spdxElementId": "SPDXRef-DOCUMENT",
                    "relationshipType": "DESCRIBES",
                    "relatedSpdxElement": artifact_id,
                },
                {
                    "spdxElementId": artifact_id,
                    "relationshipType": "CONTAINS",
                    "relatedSpdxElement": archive_id,
                },
                {
                    "spdxElementId": artifact_id,
                    "relationshipType": "CONTAINS",
                    "relatedSpdxElement": ffmpeg_id,
                },
                {
                    "spdxElementId": artifact_id,
                    "relationshipType": "CONTAINS",
                    "relatedSpdxElement": ffprobe_id,
                },
            ]
        )
        for binary_id in (ffmpeg_id, ffprobe_id):
            if TARGETS[target_name]["platform"] == "win32":
                relationships.append(
                    {
                        "spdxElementId": "SPDXRef-Toolchain-llvm-mingw",
                        "relationshipType": "BUILD_TOOL_OF",
                        "relatedSpdxElement": binary_id,
                    }
                )
            relationships.append(
                {
                    "spdxElementId": binary_id,
                    "relationshipType": "GENERATED_FROM",
                    "relatedSpdxElement": "SPDXRef-Source-FFmpeg",
                }
            )
            for dependency_id in (
                "SPDXRef-Compiled-x264-core",
                "SPDXRef-Compiled-LAME",
                "SPDXRef-Embedded-IJG-DCT",
                "SPDXRef-Embedded-Glumpy-Filters",
            ):
                relationships.append(
                    {
                        "spdxElementId": binary_id,
                        "relationshipType": "STATIC_LINK",
                        "relatedSpdxElement": dependency_id,
                    }
                )
            if TARGETS[target_name]["arch"] == "x64":
                relationships.append(
                    {
                        "spdxElementId": binary_id,
                        "relationshipType": "STATIC_LINK",
                        "relatedSpdxElement": "SPDXRef-Embedded-x264-x86inc",
                    }
                )
            for dependency in metadata["dependencies"]:  # type: ignore[index]
                dependency_id = (
                    f"SPDXRef-Dependency-{_spdx_id(dependency['name'])}-"
                    f"{_spdx_id(dependency['version'])}"
                )
                relationships.append(
                    {
                        "spdxElementId": binary_id,
                        "relationshipType": (
                            "STATIC_LINK"
                            if dependency["relationship"] == "static-link"
                            else "GENERATED_FROM"
                        ),
                        "relatedSpdxElement": dependency_id,
                    }
                )

    for package in packages:
        package.setdefault("copyrightText", "NOASSERTION")
    windows_notice = archive_files(
        artifacts_dir / str(targets["win32-arm64"]["archive"]),
        int(sources["SOURCE_DATE_EPOCH"]),
    )["LICENSES/MinGW-w64-runtime-COPYING.txt"]
    try:
        windows_notice_text = windows_notice.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("MinGW-w64 runtime notice is not UTF-8") from error

    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"motrix-ffmpeg-{release_version(sources)}",
        "documentNamespace": namespace,
        "documentDescribes": described,
        "creationInfo": {
            "created": created,
            "creators": ["Tool: motrix-ffmpeg-pipeline"],
        },
        "packages": packages,
        "files": files,
        "relationships": relationships,
        "hasExtractedLicensingInfos": [
            {
                "licenseId": "LicenseRef-MinGW-w64-runtime",
                "name": "MinGW-w64 runtime composite notices",
                "extractedText": windows_notice_text,
            }
        ],
    }


def _make_source_scripts_archive(
    path: Path, source: Path, epoch: int
) -> None:
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
                for name in BUILD_PIPELINE_FILES:
                    data = (source / name).read_bytes()
                    info = tarfile.TarInfo(name)
                    info.size = len(data)
                    info.mode = 0o755 if name.startswith("scripts/") else 0o644
                    info.mtime = epoch
                    info.uid = 0
                    info.gid = 0
                    info.uname = "root"
                    info.gname = "root"
                    archive.addfile(info, io.BytesIO(data))


def copy_source_assets(
    source: Path,
    destination: Path,
    sources: dict[str, str],
    sources_file: Path,
) -> list[dict[str, object]]:
    if not source.is_dir() or source.is_symlink():
        raise ValueError(f"source directory is missing or unsafe: {source}")
    root = Path(__file__).resolve().parents[1]
    expected_hashes = {
        sources["FFMPEG_ARCHIVE"]: sources["FFMPEG_SHA256"],
        sources["FFMPEG_SIGNATURE_ARCHIVE"]: sources["FFMPEG_SIGNATURE_SHA256"],
        sources["X264_ARCHIVE"]: sources["X264_SHA256"],
        sources["LAME_ARCHIVE"]: sources["LAME_SHA256"],
        sources["MUSL_ARCHIVE"]: sources["MUSL_SHA256"],
        sources["NASM_ARCHIVE"]: sources["NASM_SHA256"],
        sources["FORTIFY_HEADERS_ARCHIVE"]: sources["FORTIFY_HEADERS_SHA256"],
        sources["LLVM_MINGW_RECIPE_ARCHIVE"]: sources["LLVM_MINGW_RECIPE_SHA256"],
        sources["LLVM_RUNTIME_ARCHIVE"]: sources["LLVM_RUNTIME_SHA256"],
    }
    expected_files = set(expected_hashes) | set(BUILD_PIPELINE_FILES)
    expected_dirs = {
        parent.as_posix()
        for name in expected_files
        for parent in PurePosixPath(name).parents
        if parent.as_posix() not in (".", "")
    }
    actual_files: set[str] = set()
    actual_dirs: set[str] = set()
    for path in source.rglob("*"):
        relative = path.relative_to(source).as_posix()
        validate_member(relative)
        if path.is_symlink():
            raise ValueError(f"source asset is a symbolic link: {relative}")
        if path.is_dir():
            actual_dirs.add(relative)
        elif path.is_file():
            actual_files.add(relative)
        else:
            raise ValueError(f"source asset is not a regular file: {relative}")
    if actual_files != expected_files or actual_dirs != expected_dirs:
        missing = sorted(expected_files - actual_files)
        extra = sorted(actual_files - expected_files)
        extra_dirs = sorted(actual_dirs - expected_dirs)
        raise ValueError(
            "source asset set mismatch; "
            f"missing={missing}, extra={extra}, extraDirs={extra_dirs}"
        )

    repository_files = {
        name: sources_file if name == "sources.env" else root / name
        for name in BUILD_PIPELINE_FILES
    }
    for name, expected_path in repository_files.items():
        path = source / name
        if path.read_bytes() != expected_path.read_bytes():
            raise ValueError(f"release build input does not match the checkout: {name}")
    for name, expected_hash in expected_hashes.items():
        if sha256_file(source / name) != expected_hash:
            raise ValueError(f"source asset checksum mismatch: {name}")
    for name, key in (
        ("patches/musl-CVE-2026-6042.patch", "MUSL_ICONV_PATCH_SHA256"),
        ("patches/musl-CVE-2026-40200.patch", "MUSL_QSORT_PATCH_SHA256"),
    ):
        if sha256_file(source / name) != sources[key]:
            raise ValueError(f"source security patch checksum mismatch: {name}")

    copied: list[dict[str, object]] = []
    scripts_name = f"ffmpeg-{release_version(sources)}-build-scripts.tar.gz"
    future_assets = {
        "SHA256SUMS",
        "ffmpeg-manifest.json",
        "ffmpeg-manifest.json.sig",
        "ffmpeg-release-signing-key.asc",
        "sbom.spdx.json",
        scripts_name,
    }
    roles = {
        sources["FFMPEG_SIGNATURE_ARCHIVE"]: "pgp-signature",
        "sources.env": "source-lock",
    }
    direct_assets = [*expected_hashes, "sources.env"]
    future_folded = {name.casefold() for name in future_assets}
    collisions = sorted(
        name for name in direct_assets if name.casefold() in future_folded
    )
    if collisions:
        raise ValueError(
            f"source assets use reserved release names: {', '.join(collisions)}"
        )
    for name in sorted(direct_assets):
        target = destination / safe_basename(name)
        if target.exists():
            raise ValueError(f"duplicate release asset: {name}")
        shutil.copyfile(source / name, target)
        copied.append(
            {
                "name": name,
                "role": roles.get(name, "corresponding-source"),
                "sha256": sha256_file(target),
                "size": target.stat().st_size,
            }
        )

    public_key_name = "ffmpeg-release-signing-key.asc"
    public_key = destination / public_key_name
    if public_key.exists() or public_key.is_symlink():
        raise ValueError(f"duplicate release asset: {public_key_name}")
    shutil.copyfile(
        source / "keys/ffmpeg-release-signing-key.asc", public_key
    )
    copied.append(
        {
            "name": public_key_name,
            "role": "pgp-public-key",
            "sha256": sha256_file(public_key),
            "size": public_key.stat().st_size,
        }
    )

    scripts_archive = destination / scripts_name
    if scripts_archive.exists() or scripts_archive.is_symlink():
        raise ValueError(f"duplicate release asset: {scripts_name}")
    _make_source_scripts_archive(
        scripts_archive, source, int(sources["SOURCE_DATE_EPOCH"])
    )
    copied.append(
        {
            "name": scripts_name,
            "role": "build-scripts",
            "sha256": sha256_file(scripts_archive),
            "size": scripts_archive.stat().st_size,
        }
    )
    return sorted(copied, key=lambda item: str(item["name"]))


def write_release_checksums(
    output_dir: Path, expected_names: set[str]
) -> Path:
    checksum_name = "SHA256SUMS"
    if checksum_name in expected_names:
        raise ValueError("SHA256SUMS must not checksum itself")
    actual_names: set[str] = set()
    paths: dict[str, Path] = {}
    for path in output_dir.iterdir():
        if path.name == checksum_name:
            raise ValueError("duplicate release asset: SHA256SUMS")
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError(f"release asset is not a regular file: {path.name}")
        actual_names.add(path.name)
        paths[path.name] = path
    if actual_names != expected_names:
        raise ValueError(
            "release checksum asset set mismatch; "
            f"missing={sorted(expected_names - actual_names)}, "
            f"extra={sorted(actual_names - expected_names)}"
        )
    lines = [
        f"{sha256_file(paths[name])}  {name}" for name in sorted(expected_names)
    ]
    checksums_path = output_dir / checksum_name
    with checksums_path.open("x", encoding="utf-8", newline="\n") as output:
        output.write("\n".join(lines) + "\n")
    return checksums_path


def _validate_release_identities(
    targets: dict[str, dict[str, object]], args: argparse.Namespace
) -> None:
    required_values = {
        "--expected-macos-team-id": args.expected_macos_team_id,
        "--expected-macos-cert-sha256": args.expected_macos_cert_sha256,
        "--expected-windows-subject": args.expected_windows_subject,
        "--expected-windows-thumbprint": args.expected_windows_thumbprint,
    }
    project_signature = getattr(args, "windows_project_signature", False)
    if project_signature:
        required_values.pop("--expected-windows-subject")
        required_values.pop("--expected-windows-thumbprint")
    missing = [name for name, value in required_values.items() if not value]
    if missing:
        raise ValueError(
            f"formal release is missing pinned signing identities: {', '.join(missing)}"
        )
    if not re.fullmatch(r"[A-Z0-9]{10}", args.expected_macos_team_id):
        raise ValueError("expected macOS Team ID is invalid")
    expected_macos_cert = args.expected_macos_cert_sha256.lower()
    expected_windows_thumbprint = (args.expected_windows_thumbprint or "").lower()
    for name, value in (
        ("macOS certificate", expected_macos_cert),
        ("Windows certificate", expected_windows_thumbprint),
    ):
        if name == "Windows certificate" and project_signature:
            continue
        if not re.fullmatch(r"[0-9a-f]{64}", value):
            raise ValueError(f"expected {name} SHA-256 is invalid")

    for target_name in TARGETS:
        target = TARGETS[target_name]
        if target["platform"] not in {"darwin", "win32"}:
            continue
        signing = targets[target_name]["signing"]
        if target["platform"] == "win32" and project_signature:
            if signing is not None:
                raise ValueError(f"{target_name}: project-signature policy requires unsigned Windows binaries")
            continue
        if not isinstance(signing, dict):
            raise ValueError(f"{target_name}: missing structured signing evidence")
        identity = signing["identity"]
        if target["platform"] == "darwin":
            if (
                identity["teamId"] != args.expected_macos_team_id
                or identity["certificateSha256"]
                != expected_macos_cert
            ):
                raise ValueError(f"{target_name}: macOS signing identity mismatch")
        elif (
            identity["subject"] != args.expected_windows_subject
            or identity["thumbprint"] != expected_windows_thumbprint
        ):
            raise ValueError(f"{target_name}: Authenticode identity mismatch")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input-dir", required=True, type=Path)
    parser.add_argument("--source-dir", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--sources-file", type=Path)
    parser.add_argument("--document-created", required=True)
    parser.add_argument("--require-macos-signing", action="store_true")
    parser.add_argument("--windows-project-signature", action="store_true")
    parser.add_argument("--release-tag")
    parser.add_argument("--event-sha")
    parser.add_argument("--control-sha")
    parser.add_argument("--tag-object-sha")
    parser.add_argument("--expected-macos-team-id")
    parser.add_argument("--expected-macos-cert-sha256")
    parser.add_argument("--expected-windows-subject")
    parser.add_argument("--expected-windows-thumbprint")
    parser.add_argument("--repository", default="motrixapp/ffmpeg-static")
    args = parser.parse_args()

    for path, label in (
        (args.input_dir, "input directory"),
        (args.source_dir, "source directory"),
        (args.output_dir, "output directory"),
    ):
        if path.is_symlink():
            raise SystemExit(f"{label} must not be a symbolic link")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", args.repository):
        raise SystemExit("repository must be an owner/name pair")
    sources_file = (args.sources_file or Path(__file__).resolve().parents[1] / "sources.env").resolve()
    sources = load_sources(sources_file)
    document_created = validate_timestamp(
        args.document_created, "SPDX document creation time"
    )
    formal_release = args.release_tag is not None
    if formal_release:
        if args.repository != CANONICAL_REPOSITORY:
            raise SystemExit(
                f"formal releases are restricted to {CANONICAL_REPOSITORY}"
            )
        if args.release_tag != release_tag(sources):
            raise SystemExit("formal release tag does not match the source lock")
        if not isinstance(args.event_sha, str) or not re.fullmatch(
            r"[0-9a-f]{40}|[0-9a-f]{64}", args.event_sha
        ):
            raise SystemExit("formal release requires a lowercase event commit SHA")
        if not isinstance(args.control_sha, str) or not re.fullmatch(
            r"[0-9a-f]{40}|[0-9a-f]{64}", args.control_sha
        ):
            raise SystemExit("formal release requires a lowercase control commit SHA")
        if args.event_sha != args.control_sha:
            raise SystemExit(
                "formal release subject and protected control commits must be identical"
            )
        if not isinstance(args.tag_object_sha, str) or not re.fullmatch(
            r"[0-9a-f]{40}|[0-9a-f]{64}", args.tag_object_sha
        ):
            raise SystemExit("formal release requires a lowercase tag object SHA")
    elif any(
        value is not None
        for value in (
            args.event_sha,
            args.control_sha,
            args.tag_object_sha,
        )
    ):
        raise SystemExit("formal release identity arguments require --release-tag")

    signing_requirement = (
        "macos" if formal_release and args.windows_project_signature
        else "all" if formal_release else "macos" if args.require_macos_signing else "none"
    )
    metadata_paths = sorted(args.input_dir.glob("*.metadata.json"))
    targets: dict[str, dict[str, object]] = {}
    for path in metadata_paths:
        metadata = verify_target(
            path, sources, require_signing=signing_requirement
        )
        target = str(metadata["target"])
        if target in targets:
            raise SystemExit(f"duplicate target metadata: {target}")
        targets[target] = metadata
    if set(targets) != set(TARGETS):
        missing = sorted(set(TARGETS) - targets.keys())
        extra = sorted(targets.keys() - set(TARGETS))
        raise SystemExit(f"incomplete target set; missing={missing}, extra={extra}")
    if formal_release:
        _validate_release_identities(targets, args)

    if args.output_dir.exists() and not args.output_dir.is_dir():
        raise SystemExit(f"output path is not a directory: {args.output_dir}")
    if args.output_dir.exists() and any(args.output_dir.iterdir()):
        raise SystemExit(f"output directory must be empty: {args.output_dir}")
    args.output_dir.mkdir(parents=True, exist_ok=True)
    for target_name in TARGETS:
        metadata = targets[target_name]
        names = [
            str(metadata["archive"]),
            f"{metadata['archive']}.metadata.json",
        ]
        signing = metadata.get("signing")
        if isinstance(signing, dict) and signing.get("kind") == "apple-developer-id":
            names.append(str(signing["notarization"]["developerLog"]["name"]))
        for name in names:
            source = args.input_dir / name
            if not source.is_file() or source.is_symlink():
                raise ValueError(f"candidate is not a regular file: {source}")
            destination = args.output_dir / safe_basename(name)
            if destination.exists() or destination.is_symlink():
                raise ValueError(f"duplicate candidate release asset: {name}")
            shutil.copyfile(source, destination)
    copied_targets: dict[str, dict[str, object]] = {}
    for target_name in TARGETS:
        archive_name = str(targets[target_name]["archive"])
        copied_metadata = verify_target(
            args.output_dir / f"{archive_name}.metadata.json",
            sources,
            require_signing=signing_requirement,
        )
        if canonical_json(copied_metadata) != canonical_json(targets[target_name]):
            raise ValueError(f"{target_name}: copied artifact metadata changed")
        copied_targets[target_name] = copied_metadata
    targets = copied_targets
    source_assets = copy_source_assets(
        args.source_dir.resolve(), args.output_dir, sources, sources_file
    )

    manifest = {
        "schemaVersion": 3,
        "repository": args.repository,
        "windowsTrust": "motrix-ed25519" if args.windows_project_signature else "authenticode",
        "releaseVersion": release_version(sources),
        "releaseTag": release_tag(sources),
        "releaseCommit": args.event_sha,
        "controlCommit": args.control_sha,
        "releaseTagObjectSha": args.tag_object_sha,
        "formalRelease": formal_release,
        "ffmpegVersion": sources["FFMPEG_VERSION"],
        "profile": "motrix-full-gpl",
        "licenses": {name: artifact_license(name) for name in TARGETS},
        "ffmpegPgpFingerprint": sources["FFMPEG_PGP_FINGERPRINT"],
        "sourceAssets": source_assets,
        "targets": [targets[name] for name in TARGETS],
    }
    manifest_path = args.output_dir / "ffmpeg-manifest.json"
    sbom_path = args.output_dir / "sbom.spdx.json"
    checksums_path = args.output_dir / "SHA256SUMS"
    for path in (manifest_path, sbom_path, checksums_path):
        if path.exists() or path.is_symlink():
            raise ValueError(f"duplicate release asset: {path.name}")
    write_json(manifest_path, manifest)
    namespace = (
        f"https://github.com/{args.repository}/releases/tag/"
        f"{release_tag(sources)}/sbom"
    )
    write_json(
        sbom_path,
        spdx_document(
            sources,
            namespace,
            args.repository,
            targets,
            args.output_dir,
            document_created,
        ),
    )

    for source_asset in source_assets:
        asset_path = args.output_dir / safe_basename(str(source_asset["name"]))
        if (
            not asset_path.is_file()
            or asset_path.is_symlink()
            or asset_path.stat().st_size != source_asset["size"]
            or sha256_file(asset_path) != source_asset["sha256"]
        ):
            raise ValueError(
                f"source asset changed during assembly: {source_asset['name']}"
            )

    expected_checksum_names = {
        "ffmpeg-manifest.json",
        "sbom.spdx.json",
        *(str(asset["name"]) for asset in source_assets),
    }
    for metadata in targets.values():
        archive_name = str(metadata["archive"])
        expected_checksum_names.update(
            {archive_name, f"{archive_name}.metadata.json"}
        )
        signing = metadata.get("signing")
        if isinstance(signing, dict) and signing.get("kind") == "apple-developer-id":
            expected_checksum_names.add(
                str(signing["notarization"]["developerLog"]["name"])
            )
    write_release_checksums(args.output_dir, expected_checksum_names)
    print(args.output_dir / "ffmpeg-manifest.json")


if __name__ == "__main__":
    main()
