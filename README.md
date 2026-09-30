# Motrix static FFmpeg

English | [简体中文](./README.zh-CN.md)

Standalone FFmpeg builds for Motrix v2 on macOS, Linux, and Windows.

FFmpeg is **not bundled with Motrix**. You decide whether to install it, and
you can replace or remove it without changing the Motrix application. In
Motrix, choose **Settings → Integration → Media tools → Download FFmpeg** to
download and verify the Windows build in supported Motrix versions; on macOS
and Linux, the action opens this project's Releases.

> [!IMPORTANT]
> These are third-party binaries maintained for Motrix. They are **not official
> FFmpeg builds**. Read the [FFmpeg disclaimer](#ffmpeg-disclaimer) before use.

## Download

Open [motrixapp/ffmpeg-static Releases](https://github.com/motrixapp/ffmpeg-static/releases),
choose a published version, and download the archive matching your system.

Release archives use this naming pattern:

```text
ffmpeg-<FFmpeg version>-motrix.<build>-<target>.<extension>
```

| System | Target | Archive | Declared minimum OS |
| --- | --- | --- | --- |
| Apple silicon Mac | `darwin-arm64` | `...-darwin-arm64.zip` | macOS 12.0 |
| Intel Mac | `darwin-x64` | `...-darwin-x64.zip` | macOS 12.0 |
| ARM64 Linux | `linux-arm64` | `...-linux-arm64.tar.gz` | Linux kernel 3.7.0 |
| x86-64 Linux | `linux-x64` | `...-linux-x64.tar.gz` | Linux kernel 2.6.39 |
| Windows on ARM | `win32-arm64` | `...-win32-arm64.zip` | Windows 10.0 |
| x86-64 Windows | `win32-x64` | `...-win32-x64.zip` | Windows 10.0 |

The minimum versions are build targets, not a promise that every distribution,
device, driver, or Motrix package supports the same configuration. The Windows
ARM64 FFmpeg archive is available independently of whether a particular Motrix
release has a native Windows ARM64 application package.

## Verify the download

Download `SHA256SUMS` from the **same tagged Release** as the archive. Select
the one line whose filename field equals the complete archive name exactly
(not the similarly named `.metadata.json` file), calculate the local SHA-256,
and make sure the two values match exactly.

macOS:

```sh
shasum -a 256 ffmpeg-<FFmpeg-version>-motrix.<build>-darwin-<arch>.zip
```

Linux:

```sh
sha256sum ffmpeg-<FFmpeg-version>-motrix.<build>-linux-<arch>.tar.gz
```

Windows PowerShell:

```powershell
Get-FileHash .\ffmpeg-<FFmpeg-version>-motrix.<build>-win32-<arch>.zip -Algorithm SHA256
```

Replace the placeholders with the complete filename from the Release. A
SHA-256 match detects corruption but does not, by itself, prove who published
the file. The signed manifest authenticates the hashes with a public key pinned
in Motrix. For project signature, Release, attestation, tag, and macOS verification, follow [SECURITY.md](SECURITY.md#verify-a-download).

If any check fails, **do not install or run the archive**. Platform-signature
verification requires extracting only `ffmpeg` and `ffprobe` into a fresh
temporary directory after the common checks pass; follow the safe procedure in
`SECURITY.md`. Download the archive again from this repository's tagged Release
and report a possible security issue. Never bypass Gatekeeper, SmartScreen, or
a failed verification.

## Install in Motrix

On Windows, use **Download FFmpeg → Download and verify** in a Motrix version
with project-signature verification. Motrix selects x64/ARM64, verifies the signed
manifest and archive, and installs it without a public code-signing certificate.
Failures keep the previous verified version. Custom paths take precedence;
restart Motrix after installation to refresh cached plugin capabilities.

For manual installations, the Media settings page shows and can copy the path.
The preferred manual location is:

```text
<userData>/binaries/ffmpeg
<userData>/binaries/ffmpeg.exe       # Windows
```

1. Verify the archive using [the complete procedure](SECURITY.md#verify-a-download).
2. In Motrix **Settings → Integration → Media tools**, expand the detection
   details and copy **Motrix FFmpeg path**. Create its parent `binaries`
   directory if it does not exist.
3. Extract the archive and copy `ffmpeg` (or `ffmpeg.exe`) to that path.
4. Optionally copy `ffprobe` (or `ffprobe.exe`) beside it for diagnostics.
5. On macOS or Linux, preserve executable permission. Run `chmod 755 ffmpeg`;
   if you copied `ffprobe`, also run `chmod 755 ffprobe`.
6. Return to **Media tools** and refresh FFmpeg detection.

Motrix checks a custom path from Media settings first, then
`<userData>/binaries/ffmpeg[.exe]`, `MOTRIX_FFMPEG_BIN`, and finally the system
`PATH`. You may therefore use a trusted system package or your own compatible
build instead.

## What is included

Each archive contains:

- `ffmpeg` and `ffprobe` (`.exe` on Windows);
- the exact build configuration and build metadata;
- `LICENSES.json`, third-party notices, and component license texts.

The `motrix-full-gpl` profile is intentionally limited to features Motrix v2
uses. It includes native FFmpeg AAC, FLAC, PCM, probing, filtering, scaling,
and common container support, plus H.264 encoding with x264 and MP3 encoding
with LAME. macOS builds also enable Apple's VideoToolbox and AudioToolbox. It
does not enable every optional codec, hardware SDK, or FFmpeg library.

“Static” is platform-specific:

| Platform | Distribution model |
| --- | --- |
| Linux | A musl-linked static executable with no runtime loader or shared-library dependency. |
| macOS | x264 and LAME are statically linked; Apple system libraries and frameworks remain system dependencies. |
| Windows | x264, LAME, and compiler runtimes are statically linked; only Windows system DLLs are imported. |

Each Release publishes authenticated source archives for FFmpeg, x264, LAME,
musl, fortify-headers, NASM, the llvm-mingw build recipe, and the LLVM runtime,
plus the exact build scripts, source lock, checksums, metadata, and SPDX SBOM.
The complete mingw-w64 upstream tree is referenced rather than mirrored; its
immutable URL, revision, and SHA-256 remain recorded in `sources.env` and the
SBOM.

## Platform trust

Every platform must first pass the common Release, annotated-tag, attestation,
manifest, size, and SHA-256 procedure in
[SECURITY.md](SECURITY.md#verify-a-download). The manifest has an Ed25519 project
signature whose public key is bundled independently in Motrix. Platform policy:

- **macOS:** formal executables published in this project's Releases are
  signed with a Developer ID Application identity, hardened runtime, and a
  secure timestamp. The exact released ZIP must also be accepted by Apple's
  notarization service.
- **Windows x64 and ARM64:** executables have no public Authenticode signature.
  Motrix authenticates the release manifest with its pinned Ed25519 key and
  verifies the archive and executable hashes. This does not establish Windows
  publisher reputation or remove SmartScreen/antivirus warnings. Never install
  a self-signed root certificate or disable system protections.
- **Linux:** verify the tagged Release, attestations, manifest, and SHA-256 as
  described in [SECURITY.md](SECURITY.md#verify-a-download).

A platform warning is a stop signal. Do not remove macOS quarantine attributes,
apply an ad-hoc signature, click through SmartScreen, or suppress a failed
signature check.

## FAQ

### Does the macOS download need signing?

The executables do. FFmpeg is downloaded separately after Motrix is installed,
so it does not inherit the Motrix application signature. The ZIP container is
not code-signed: its `ffmpeg` and `ffprobe` members are Developer ID signed,
and the exact final ZIP is submitted to Apple's notarization service. This
plain ZIP layout does not claim a stapled ticket.

### Is Windows ARM64 supported?

Yes. Choose `win32-arm64` for native Windows on ARM. Choose `win32-x64` for an
x86-64 Windows system.

### Do users need Python?

No. Python is used only by the build and release pipeline. The downloaded
`ffmpeg` and `ffprobe` programs have no Python runtime dependency.

### Must I install this build?

No. FFmpeg remains optional and separate from Motrix. A compatible system
package or custom build can be selected through Motrix Media settings.

### What should I do if Gatekeeper, SmartScreen, or verification reports a problem?

Stop. Do not bypass the warning and do not run the file. Re-download from the
tagged Release, follow [the complete verification procedure](SECURITY.md#verify-a-download),
and use [private vulnerability reporting](https://github.com/motrixapp/ffmpeg-static/security/advisories/new)
if the failure persists.

## FFmpeg disclaimer

This repository provides third-party FFmpeg binaries maintained for use with
Motrix. It is independent from the FFmpeg project and is not affiliated with,
sponsored by, approved by, or endorsed by FFmpeg or its contributors. These
files are not builds distributed by the FFmpeg project. The name **FFmpeg** is
a trademark of Fabrice Bellard; all other names and trademarks belong to their
respective owners.

The current build enables GPL code and `libx264`. The resulting `ffmpeg` and
`ffprobe` executables are distributed under **GPL-2.0-or-later**, while their
statically linked components retain their own additional license terms. Each
archive's `LICENSES.json` and `LICENSES/` are the complete effective license
record for those binaries. The FFmpeg, x264, and LAME corresponding-source
archives and the other redistributable source materials listed above are
published in the same Release. The root [LICENSE](LICENSE) primarily covers
this project's original build scripts and repository content. See also the
[official FFmpeg download page](https://ffmpeg.org/download.html) and
[FFmpeg's legal information](https://ffmpeg.org/legal.html).

Codec, format, patent, export, and commercial-use rules vary by jurisdiction
and use case. This information is not legal advice. You are responsible
for determining which laws and license obligations apply to you and for having
the rights or permissions needed for media you process, download, encode,
decode, convert, or distribute.

These builds are provided **as is**, without warranties or guarantees of any
kind. To the extent permitted by applicable law, the maintainers disclaim
liability for their use, inability to use them, data loss, compatibility
problems, or third-party claims.

For Motrix packaging, download, or integration issues, use this repository—not
FFmpeg's upstream support channels. Report an upstream-reproducible FFmpeg bug
upstream only after confirming it is not specific to this build.

## Project links

- Security policy and complete verification: [SECURITY.md](SECURITY.md)
- Contributions and release requirements: [CONTRIBUTING.md](CONTRIBUTING.md)
- General packaging issues: [GitHub Issues](https://github.com/motrixapp/ffmpeg-static/issues)
