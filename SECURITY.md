# Security policy

## Supported releases

Only the latest published Motrix FFmpeg release receives security updates.
Older archives remain available for historical investigation but should be
considered unsupported after a replacement release is published.

| Version | Supported |
| --- | --- |
| Latest GitHub Release | Yes |
| Older releases and workflow artifacts | No |
| Unsigned tag-push or empty-`release_tag` dispatch artifacts | Never supported for distribution |

## Report a vulnerability privately

Do not open a public issue for a suspected vulnerability in a released binary,
source lock, CI workflow, GitHub Action, signing/notarization path, checksum,
provenance record, or archive parser.

Use [GitHub private vulnerability reporting](https://github.com/motrixapp/ffmpeg-static/security/advisories/new).
Include, when available:

- The release tag, exact asset name, and SHA-256.
- Operating system and architecture.
- A minimal reproduction and the observed impact.
- Whether the issue also affects upstream FFmpeg, x264, LAME, musl,
  fortify-headers, LLVM runtime, mingw-w64, or llvm-mingw.
- Relevant logs with credentials, local paths, signing identities, and private
  media removed.
- A safe way to obtain any necessary proof-of-concept file. Do not attach
  sensitive or copyrighted media without permission.

The maintainers will coordinate validation, upstream disclosure when needed,
and a replacement release. Please allow time for a private assessment before
publishing details.

## Current release engineering hold

As of 2026-09-30, official immutable GitHub Actions still have vulnerable
runtime npm lock entries. Updating an Action tag is not evidence that its
transitive dependencies are all fixed. The conservative, development-dependency
excluded inventory is recorded in
[`security/action-dependency-audit.json`](security/action-dependency-audit.json).
It is a package inventory, not a claim that every advisory is exploitable in
this workflow or included in the Action's executed bundle.

Formal releases are currently **blocked** by
[`security/action-risk-review.json`](security/action-risk-review.json).
The protected-main prepare job checks this gate before cache restoration,
source compilation, environment approvals, or signing/publishing credentials.
An approval must bind every exact Action commit, the SHA-256 of the complete
advisory evidence, every inventoried advisory, and a same-day refreshed scan.
Reviews expire after at most 14 days. No dispatch input or environment variable
can override the gate. Unsigned CI/test builds remain available for validation,
not distribution. Do not interpret this hold as a new released binary.

The weekly dependency audit queries GitHub's advisory database for all runtime
package versions and fails on High/Critical findings or API errors. A red audit
must be assessed separately from ordinary build CI; a green compilation test
does not resolve a dependency advisory.

## Verify a download

Download only from this repository's immutable GitHub Releases. For an explicit
tag and local archive, use Bash, a current GitHub CLI, and `jq` to verify all three
trust layers before extraction. Obtain both the release-tag signer fingerprint
and public key from a trusted Motrix channel outside this repository and
Release; using material from the manifest or tag as its own trust anchor is
forbidden. The same independently deployed Motrix-controlled HTTPS trust page
must publish the Apple Team ID and certificate SHA-256 plus the Ed25519 manifest public key and SPKI-DER SHA-256 key ID. The first public Release remains blocked until
that page is live, linked from an official Motrix site or application, and its
exact URL replaces this first-release notice. Set the public-key path in
`MOTRIX_RELEASE_TAG_SIGNING_PUBLIC_KEY`; the commands require GnuPG. Replace
the example `tag` and `asset` assignments below with the exact Release tag and
local archive name. Start in a fresh working directory containing the archive,
but no pre-existing `ffmpeg-manifest.json`, `SHA256SUMS`, or notarization log;
the commands download those files and intentionally refuse overwrite prompts.

```bash
set -euo pipefail
repo=motrixapp/ffmpeg-static
tag=v9.0.2-motrix.1
asset=ffmpeg-9.0.2-motrix.1-linux-x64.tar.gz
manifest=ffmpeg-manifest.json
expected_tag_signer_fingerprint=${MOTRIX_RELEASE_TAG_SIGNER_FINGERPRINT:?export the trusted Motrix release-tag signer fingerprint}
printf '%s\n' "$expected_tag_signer_fingerprint" \
  | grep -Eq '^([0-9A-F]{40}|[0-9A-F]{64})$'

gh release verify "$tag" -R "$repo"
gh release download "$tag" -R "$repo" -p "$manifest" -p "$manifest.sig" -p SHA256SUMS
# Use a separately trusted checkout whose keys/manifest-ed25519.pub matches
# the key pinned in your official Motrix application, not a downloaded verifier.
trusted_verifier=${MOTRIX_MANIFEST_VERIFIER:?path to independently trusted scripts/sign_release_manifest.py}
python3 "$trusted_verifier" verify-manifest --directory . --tag "$tag"
gh release verify-asset "$tag" "$manifest" -R "$repo"
gh release verify-asset "$tag" "$asset" -R "$repo"
control_commit=$(jq -er --arg tag "$tag" \
  --arg signer "$expected_tag_signer_fingerprint" '
  select(.schemaVersion == 3 and .formalRelease == true and .releaseTag == $tag)
  | select((.releaseCommit | type) == "string"
      and (.controlCommit | type) == "string"
      and (.releaseTagObjectSha | type) == "string"
      and (.releaseTagSignerFingerprint | type) == "string")
  | select((.releaseCommit | test("^[0-9a-f]{40}$"))
      and (.controlCommit | test("^[0-9a-f]{40}$"))
      and (.releaseTagObjectSha | test("^[0-9a-f]{40}$"))
      and (.releaseTagSignerFingerprint | test("^([0-9A-F]{40}|[0-9A-F]{64})$")))
  | select(.releaseCommit == .controlCommit)
  | select(.releaseTagSignerFingerprint == $signer)
  | .controlCommit
' "$manifest")
asset_record=$(jq -cer --arg asset "$asset" '
  [.targets[] | select(.archive == $asset)] as $matches
  | select(($matches | length) == 1)
  | $matches[0]
  | select((.archiveSha256 | type) == "string"
      and (.archiveSha256 | test("^[0-9a-f]{64}$"))
      and (.archiveSize | type) == "number"
      and .archiveSize > 0
      and .archiveSize == (.archiveSize | floor))
' "$manifest")
manifest_asset_sha=$(printf '%s' "$asset_record" | jq -er '.archiveSha256')
manifest_asset_size=$(printf '%s' "$asset_record" | jq -er '.archiveSize')
actual_asset_size=$(wc -c < "$asset" | tr -d '[:space:]')
test "$actual_asset_size" = "$manifest_asset_size"
tag_object=$(jq -er '.releaseTagObjectSha' "$manifest")
remote_tag_object=$(gh api "repos/$repo/git/ref/tags/$tag" \
  --jq '.object | select(.type == "tag") | .sha')
test "$remote_tag_object" = "$tag_object"
tag_record=$(gh api "repos/$repo/git/tags/$tag_object")
test "$(printf '%s' "$tag_record" | jq -r '.tag')" = "$tag"
test "$(printf '%s' "$tag_record" | jq -r '.object.type')" = commit
test "$(printf '%s' "$tag_record" | jq -r '.object.sha')" = "$control_commit"
test "$(printf '%s' "$tag_record" | jq -r '.verification.verified')" = true
test "$(printf '%s' "$tag_record" | jq -r '.verification.reason')" = valid
trusted_tag_key=${MOTRIX_RELEASE_TAG_SIGNING_PUBLIC_KEY:?export the trusted Motrix release-tag public-key file}
test -f "$trusted_tag_key" && test ! -L "$trusted_tag_key"
test "$(wc -c < "$trusted_tag_key" | tr -d '[:space:]')" -le 131072
tag_verify_dir=$(mktemp -d "${TMPDIR:-/tmp}/motrix-tag-verify.XXXXXX")
chmod 700 "$tag_verify_dir"
cleanup_tag_verify() { rm -rf -- "$tag_verify_dir"; }
trap cleanup_tag_verify EXIT HUP INT TERM
printf '%s' "$tag_record" | jq -ej '
  .verification.signature
  | select(type == "string" and length > 0 and length <= 131072)
' > "$tag_verify_dir/signature.asc"
printf '%s' "$tag_record" | jq -ej '
  .verification.payload
  | select(type == "string" and length > 0 and length <= 1048576)
' > "$tag_verify_dir/payload.txt"
awk -v object="$control_commit" -v tag="$tag" '
  NR == 1 { valid = ($0 == "object " object); next }
  NR == 2 { valid = valid && ($0 == "type commit"); next }
  NR == 3 { valid = valid && ($0 == "tag " tag); next }
  NR == 4 { valid = valid && ($0 ~ /^tagger /); next }
  NR == 5 { valid = valid && ($0 == ""); next }
  END { exit !(NR >= 5 && valid) }
' "$tag_verify_dir/payload.txt"
gpg --no-options --batch --no-autostart --homedir "$tag_verify_dir" \
  --quiet --import "$trusted_tag_key" >/dev/null 2>&1
tag_key_fingerprints=$(gpg --no-options --batch --no-autostart \
  --homedir "$tag_verify_dir" --with-colons --list-keys 2>/dev/null \
  | awk -F: '$1 == "pub" { want=1; next }
      want && $1 == "fpr" { print toupper($10); want=0 }')
test "$(printf '%s\n' "$tag_key_fingerprints" | awk 'NF { count++ } END { print count + 0 }')" -eq 1
test "$tag_key_fingerprints" = "$expected_tag_signer_fingerprint"
gpg --no-options --batch --no-autostart --no-auto-key-retrieve \
  --homedir "$tag_verify_dir" --status-fd=1 \
  --verify "$tag_verify_dir/signature.asc" "$tag_verify_dir/payload.txt" \
  > "$tag_verify_dir/verify.status" 2>/dev/null
awk -v expected="$expected_tag_signer_fingerprint" '
  $2 == "VALIDSIG" && ($10 == 8 || $10 == 9 || $10 == 10) \
    && (toupper($3) == expected || toupper($NF) == expected) { valid++ }
  $2 == "BADSIG" || $2 == "ERRSIG" || $2 == "NO_PUBKEY" \
    || $2 == "EXPSIG" || $2 == "EXPKEYSIG" || $2 == "REVKEYSIG" \
    || $2 == "KEYEXPIRED" || $2 == "SIGEXPIRED" { invalid = 1 }
  END { exit !(valid == 1 && !invalid) }
' "$tag_verify_dir/verify.status"
for subject in "$manifest" "$asset"; do
  gh attestation verify "$subject" -R "$repo" \
    --source-ref refs/heads/main \
    --source-digest "$control_commit" \
    --signer-workflow "$repo/.github/workflows/release.yml"
done
checksum_line=$(awk -v name="$asset" '
  /^[0-9a-f]{64}  / && substr($0, 67) == name { print; matches++ }
  END { exit !(matches == 1) }
' SHA256SUMS)
test "${checksum_line%%  *}" = "$manifest_asset_sha"
printf '%s\n' "$checksum_line" | sha256sum -c -
cleanup_tag_verify
trap - EXIT HUP INT TERM
```

On macOS, replace the final `sha256sum -c -` with `shasum -a 256 -c -`.
The block above is the common Release, tag, provenance, manifest, size, and
checksum verification. It is **not sufficient by itself** for macOS or
Windows: continue with the matching platform section below before installing
or running either executable. Linux has no platform code-signing layer, so the
common block is the complete pre-extraction publisher check for Linux.

On Windows, first change the common block's `asset` assignment to the exact
`win32-x64` or `win32-arm64` ZIP, then run it in Git Bash or WSL from the fresh
directory containing that archive. Install `gh`, `jq`, and GnuPG in that
environment first. The short `Get-FileHash` example in the README is only a
corruption check and does not replace the common block. After it succeeds,
continue with the project-signature policy below. No Authenticode check applies.

### macOS Developer ID and notarization

Use a `darwin-arm64` or `darwin-x64` archive in the common block. Obtain the
expected Team ID and Developer ID leaf-certificate DER SHA-256 from a trusted
Motrix channel outside this repository and Release, then export them as
`MOTRIX_MACOS_TEAM_ID` and `MOTRIX_MACOS_CERT_SHA256`. Continue in the same
Bash shell after the common block:

```bash
expected_team_id=${MOTRIX_MACOS_TEAM_ID:?export the trusted Motrix Apple Team ID}
expected_certificate_sha256=$(printf '%s' \
  "${MOTRIX_MACOS_CERT_SHA256:?export the trusted Motrix Developer ID certificate SHA-256}" \
  | tr '[:upper:]' '[:lower:]')
printf '%s\n' "$expected_team_id" | grep -Eq '^[A-Z0-9]{10}$'
printf '%s\n' "$expected_certificate_sha256" | grep -Eq '^[0-9a-f]{64}$'

signing_record=$(printf '%s' "$asset_record" | jq -cer \
  --arg team "$expected_team_id" --arg certificate "$expected_certificate_sha256" '
  .signing
  | select(.schemaVersion == 3 and .platform == "darwin"
      and .kind == "apple-developer-id")
  | select(.identity.teamId == $team
      and .identity.certificateSha256 == $certificate)
  | select(.notarization.status == "Accepted")
')
notary_name=$(printf '%s' "$signing_record" | jq -er \
  '.notarization.developerLog.name')
expected_notary_name=${asset%.zip}.notarization-log.json
test "$expected_notary_name" != "$asset"
test "$notary_name" = "$expected_notary_name"
notary_sha=$(printf '%s' "$signing_record" | jq -er \
  '.notarization.developerLog.sha256 | select(test("^[0-9a-f]{64}$"))')
notary_size=$(printf '%s' "$signing_record" | jq -er \
  '.notarization.developerLog.size | select(type == "number" and . > 0 and . == floor)')
submission_id=$(printf '%s' "$signing_record" | jq -er \
  '.notarization.submissionId')
gh release download "$tag" -R "$repo" -p "$notary_name"
gh release verify-asset "$tag" "$notary_name" -R "$repo"
test "$(wc -c < "$notary_name" | tr -d '[:space:]')" = "$notary_size"
test "$(shasum -a 256 -- "$notary_name" | awk '{print $1}')" = "$notary_sha"
jq -e --arg job "$submission_id" --arg archive "$asset" \
  --arg sha "$manifest_asset_sha" '
  select(.logFormatVersion == 1 and .jobId == $job
      and .status == "Accepted" and .statusCode == 0
      and .archiveFilename == $archive and .sha256 == $sha)
  | select(.issues == null
      or ((.issues | type) == "array" and (.issues | length) == 0))
' "$notary_name" >/dev/null

mac_verify_dir=$(mktemp -d "${TMPDIR:-/tmp}/motrix-macos-verify.XXXXXX")
chmod 700 "$mac_verify_dir"
cleanup_mac_verify() { rm -rf -- "$mac_verify_dir"; }
trap cleanup_mac_verify EXIT HUP INT TERM
for binary in ffmpeg ffprobe; do
  test "$(unzip -Z1 "$asset" | awk -v name="$binary" \
    '$0 == name { matches++ } END { print matches + 0 }')" -eq 1
  uncompressed_size=$(LC_ALL=C unzip -l "$asset" "$binary" \
    | awk -v name="$binary" '
        $4 == name && $1 ~ /^[0-9]+$/ { print $1; matches++ }
        END { exit !(matches == 1) }
      ')
  test "$uncompressed_size" -gt 0
  test "$uncompressed_size" -le 268435456
  if ! unzip -p "$asset" "$binary" \
    | head -c 268435457 > "$mac_verify_dir/$binary"; then
    echo "archive member is corrupt or exceeds the extraction limit: $binary" >&2
    exit 1
  fi
  actual_uncompressed_size=$(wc -c < "$mac_verify_dir/$binary" \
    | tr -d '[:space:]')
  test "$actual_uncompressed_size" = "$uncompressed_size"
  test "$actual_uncompressed_size" -le 268435456
  chmod 755 "$mac_verify_dir/$binary"
  path="$mac_verify_dir/$binary"
  codesign --verify --strict --verbose=4 "$path"
  signing_display=$(LC_ALL=C TZ=UTC codesign --display --verbose=4 "$path" 2>&1)
  test "$(printf '%s\n' "$signing_display" \
    | awk -F= '$1 == "TeamIdentifier" { print $2; exit }')" = "$expected_team_id"
  test "$(printf '%s\n' "$signing_display" \
    | awk -F= '$1 == "Identifier" { print $2; exit }')" \
    = "net.agalwood.motrix.$binary"
  test -n "$(printf '%s\n' "$signing_display" \
    | awk -F= '$1 == "Timestamp" { sub(/^[^=]*=/, ""); print; exit }')"
  test "$(printf '%s\n' "$signing_display" \
    | awk '/^CodeDirectory / { count++ } END { print count + 0 }')" -eq 1
  printf '%s\n' "$signing_display" \
    | grep -Eq '^CodeDirectory .* flags=0x[0-9A-Fa-f]+\([^)]*runtime[^)]*\)'
  certificate_prefix="$mac_verify_dir/$binary-certificate"
  codesign --display --extract-certificates="$certificate_prefix" "$path"
  test -f "${certificate_prefix}0" && test ! -L "${certificate_prefix}0"
  actual_certificate_sha256=$(shasum -a 256 -- "${certificate_prefix}0" \
    | awk '{print $1}')
  test "$actual_certificate_sha256" = "$expected_certificate_sha256"
  actual_binary_sha256=$(shasum -a 256 -- "$path" | awk '{print $1}')
  recorded_binary_sha256=$(printf '%s' "$signing_record" \
    | jq -er --arg binary "$binary" \
      '.binaries[$binary]
       | select(.hardenedRuntime == true and (.timestamp | type) == "string"
           and (.timestamp | length) > 0)
       | .sha256')
  test "$actual_binary_sha256" = "$recorded_binary_sha256"
  codesign -vvvv -R="notarized" --check-notarization "$path"
done
cleanup_mac_verify
trap - EXIT HUP INT TERM
```

The ZIP container itself is not code-signed. The commands verify the
Developer ID signatures on the two executables and the Apple developer log
that binds an accepted notarization submission to the exact final ZIP. Do not
remove quarantine attributes, apply an ad-hoc signature, or treat a different
ZIP with the same inner files as the notarized asset.

### Windows project signature (x64 and ARM64)

Prefer **Settings → Integration → Media tools → Download FFmpeg → Download and verify**
in a Motrix release that includes the pinned FFmpeg public key. Motrix fetches the
latest tag only for discovery, then constructs fixed-repository, explicit-tag
asset URLs. It authenticates the exact manifest bytes with its bundled Ed25519
key before parsing the manifest, checks the selected archive's size/SHA-256,
rejects unsafe or unexpected ZIP entries, and checks both executable hashes and
PE architectures. Installation activates an immutable version directory with an
atomic pointer update; failed downloads retain the previous verified version.
Older signed versions and changed manifests under the same installed version
are rejected. Managed executables are rehashed before detection and execution.
Manual external installations remain user-managed, not project-signature verified.

For manual downloads, run the common verification block above, including the
Ed25519 step, before extraction. The Windows metadata must have `signing: null`
and the manifest must have `windowsTrust: "motrix-ed25519"`. No Windows SDK,
PFX, public code-signing certificate, or certificate-store installation is needed.

This is **not Authenticode** and does not establish Microsoft publisher reputation.
SmartScreen, antivirus, organizational policy, or Mark-of-the-Web warnings may
remain. Do not clear those marks, install a self-signed root, disable protections,
or suppress a warning. If policy blocks execution, stop and use an approved
FFmpeg source or ask your administrator. A valid project signature proves
publisher-key possession and byte integrity, not that a binary or media parser
is free of vulnerabilities. A compromised Motrix application, signing key, or
process with access to the user's data directory is outside the downloader's
remote-tampering boundary.

Pull-request, tag-push, and empty-`release_tag` workflow artifacts are unsigned
test output, never official releases. They cannot enter signing or publishing
Environments and cannot pass the Motrix project-signature verifier.

## Supply-chain boundaries

The release pipeline is expected to fail closed when:

- A locked source or toolchain checksum changes.
- A target's minimum-OS declaration changes or disagrees between its build
  information, per-asset metadata, and release manifest. In particular,
  Linux ARM64 requires kernel `3.7.0`; Linux x86-64 remains `2.6.39`.
- The FFmpeg detached signature does not match the pinned release-key
  fingerprint.
- A build enables `nonfree`, changes the principal GPL profile, lacks
  x264/LAME, or reports GPL-2.0-or-later as the only applicable target license.
- A target's canonical effective license, generated notices, `LICENSES.json`,
  or SPDX record disagrees; the five-source notice omits IJG, ISC, the complete
  Glumpy BSD-3-Clause terms, or any locked source-tree notice; or its byte
  count/SHA-256 differs from the `sources.env` lock.
- A Windows link includes any of the 14 prohibited Cephes/Moshier-derived
  `libmingwex.a` object families, or either final `ffmpeg.exe`/`ffprobe.exe`
  linker trace or map is absent.
- A binary has the wrong architecture or an unexpected dynamic dependency.
- A production signing candidate and its independent clean rebuild differ in
  any staged byte; an approval/final grant is missing, non-canonical, created
  before all required secret-free jobs succeeded, or does not bind the exact
  candidate/rebuild/approval artifact IDs, digests, run, and control commit.
- An archive is malformed, its metadata disagrees, or any of the six targets
  is absent.
- A production macOS asset lacks the expected Team ID/certificate, hardened
  runtime, timestamp, or accepted notarization.
- A production Windows candidate differs from its approved unsigned input, or
  the complete formal manifest lacks the pinned Ed25519 project signature.
- A formal request's tag does not match `sources.env`, is lightweight, lacks a
  GitHub-verified valid signature, does not point directly to the exact
  protected-`main` dispatch commit, has a tagger email different from
  `EXPECTED_RELEASE_TAGGER_EMAIL`, or fails local verification with
  `RELEASE_TAG_SIGNING_PUBLIC_KEY` and the exact
  `EXPECTED_RELEASE_TAG_SIGNER_FINGERPRINT`.
- A formal run is not executing in the hard-coded canonical repository
  `motrixapp/ffmpeg-static`; a repository name taken from fork-controlled event
  context is not a trust anchor.
- Repository Release immutability cannot be confirmed as enabled before the
  draft Release is created.

The Windows Motrix downloader uses the independently bundled public key as its trust
root. It requires formal manifest schema 3 and target metadata schema 2, the fixed
repository/tag and exact target, bounded archive/member sizes, hashes, unsigned PE64
architecture, and an atomic install. It refuses remote-provided keys, unsigned
manifests, mirrors, Actions artifacts, rollback, same-version substitution,
unexpected ZIP entries, and checksum-only trust. GitHub Release/attestation checks
remain additional manual/audit evidence; the app does not execute GitHub CLI or
verify OIDC attestations. macOS and Linux use the external Release/manual-install
path.
`GPL-2.0-or-later` is the principal copyleft profile, not the complete license
expression. Define `BASE` as
`GPL-2.0-or-later AND LGPL-2.1-or-later AND IJG AND ISC AND MIT AND BSD-1-Clause AND BSD-2-Clause AND BSD-3-Clause AND Zlib AND BSL-1.0`.
Both Darwin architectures use `BASE`; both Linux architectures use
`BASE AND 0BSD AND SunPro AND (GPL-3.0-or-later WITH GCC-exception-3.1)`;
both Windows architectures use
`BASE AND (Apache-2.0 WITH LLVM-exception) AND LicenseRef-MinGW-w64-runtime`.
ISC applies to every target through FFmpeg portable sources; x64 additionally
compiles x264 and FFmpeg x86inc assembly. The IJG-derived DCT sources are
unmodified and must retain the Independent JPEG Group credit, and the
Glumpy-derived filter code must retain its complete BSD-3-Clause terms. LAME's
effective component license is `LGPL-2.1-or-later`; compiled musl is
`MIT AND SunPro`. Reducing any target to GPL alone is invalid.

`THIRD-PARTY-NOTICES.txt` is generated from fresh locked FFmpeg, x264, LAME,
musl, and fortify-headers trees and must be exactly 4,469,033 bytes with the
SHA-256 locked in `sources.env`. A formal Release publishes eight corresponding
source archives: FFmpeg, x264, LAME, musl, fortify-headers, NASM, the llvm-mingw
build recipe, and LLVM runtime. NASM is build-only: every x64 build compiles it
from the locked source, records the source and executable hashes, and rejects
any system fallback. It
is the only archive allowed to carry upstream setgid directory metadata, and
only because the exact locked NASM archive uses mode `02775` on directories.
The exception never permits special bits on files or any other archive; tar
extracts without inherited permissions, then a non-following `lstat` walk
proves that no special or group/world-write bit reached disk. It
does not republish the complete mingw-w64 audit tree because
that upstream tree includes disputed Cephes/Moshier material excluded from the
linked binaries; the upstream revision, URL, and archive SHA-256 remain locked
and represented in provenance/SBOM records.

musl 1.2.6 remains the latest stable upstream release, but our compiled Linux
libc includes the official CVE-2026-6042 (`iconv`) and CVE-2026-40200 (`qsort`)
backports. Their exact patch bytes and application script are distributed in
the build-pipeline source archive; both patch hashes and all three patched
source-file hashes are locked in `sources.env`. Application rejects fuzz,
offsets, changed patch bytes, and changed result bytes. The upstream source
archive is kept byte-for-byte unchanged, and notices are generated only after
the backports have passed validation.

The consumer schemas are also security boundaries: `BUILD-INFO.json` is
schema 1, `LICENSES.json` schema 2, per-asset metadata schema 2, and
`ffmpeg-manifest.json` schema 3. An unknown or downgraded schema fails closed.
Nested macOS platform-signing evidence is schema 3. Windows metadata has null
signing evidence. The separate manifest signature envelope is schema 1, algorithm
Ed25519, with a pinned SPKI-DER SHA-256 key ID and canonical Base64 signature.
macOS evidence binds the notarization submission-result digest and the exact
target-specific Apple developer-log asset name, size, and SHA-256. The log is
published beside the archive, covered by `SHA256SUMS`, the manifest, and SPDX,
and is parsed again during secret-free assembly. Its format version, job ID,
accepted/zero status, archive basename/SHA-256, and empty issues must all match
the exact released ZIP. The plain standalone CLI ZIP is not a stapling target
and is never rewritten after submission.

Formal CI requires Python 3.9 or later, using only the standard library for
build and validation orchestration. Python is neither a compiler identity nor
a runtime dependency of `ffmpeg`/`ffprobe`; its observed version belongs only
to build provenance. Formal SPDX `creationInfo.created` uses the verified
signed annotated tagger timestamp, while control/test output uses the trusted
control-commit timestamp. `SOURCE_DATE_EPOCH` is only the normalized archive
timestamp.

macOS signing/notarization credentials belong only in the protected
`macos-release-signing` Environment. The Ed25519 private key belongs only in
`release-manifest-signing` as `FFMPEG_MANIFEST_PRIVATE_KEY`. `RELEASE_ADMIN_TOKEN` belongs only in the protected
`github-release` Environment, has repository-scoped **Administration: read**,
and is used only to confirm Immutable Releases are enabled. Expected Team ID,
certificate subject, and certificate fingerprints are protected
repository/organization variables and are bound into release metadata; changing
one is a security-sensitive identity rotation requiring review.
The manifest signer revalidates all six artifacts without running their executables,
derives the private key's public SPKI and checks it against keys/manifest-ed25519.pub,
and signs the domain bytes `Motrix FFmpeg release manifest v1\n` followed by the exact
manifest bytes. Only the public key is committed or bundled in Motrix. Key rotation
requires an independently reviewed Motrix update before new-key releases are usable.
`EXPECTED_RELEASE_TAGGER_EMAIL`, `EXPECTED_RELEASE_TAG_SIGNER_FINGERPRINT`,
and `RELEASE_TAG_SIGNING_PUBLIC_KEY` are protected tag-identity pins. The
public key is not secret, but its value is privileged policy: any change to
the email, key, or uppercase primary fingerprint requires the same independent
release-authority review.

If any code-signing, notarization, or release-administration credential may
have leaked, revoke or rotate it with Apple or GitHub, or rotate the project signing key
as appropriate, pause publication, and report the incident privately. Never
paste secrets into issues, pull requests, build logs, artifacts, or chat
transcripts. A replacement release needs a new build revision and new tag; do
not mutate an existing immutable Release.

## Repository controls are part of the boundary

Workflow files cannot configure GitHub's own control plane. Before the first
public release, maintainers must enable Immutable Releases, protect matching
release tags with an active tag ruleset, protect `main` with required CI and
a catch-all `* @agalwood` CODEOWNERS rule, and required `agalwood` manual
confirmation/no-admin-bypass on all three release Environments, with deployment
restricted to protected `main`. Self-review is allowed for this single-maintainer
project; this does not provide independent two-person human review. Pull requests
require passing CI, not self-impossible approving reviews. Repository, organization, and enterprise Actions
artifact-retention limits must allow the workflow's 36-day retention request,
which covers GitHub's 30-day approval and 35-day workflow limits. The pinned
release-tag signer public key/fingerprint, Apple Team ID/leaf certificate
SHA-256, and the Ed25519 manifest public key/key ID must also be published
together through a stable Motrix-controlled HTTPS trust page outside this
repository and its Releases, linked from an official Motrix site or
application, so download verification has an independent trust root. Preserve
an append-only identity history with effective Release ranges when any pin
rotates. The exact deployed URL must replace the first-release notice in the
verification section before publication. The catch-all CODEOWNERS rule names the actual release maintainer, `agalwood`.
The GitHub account and its recovery/MFA credentials are part of the trust boundary;
a single compromised maintainer account cannot be mitigated by a second-person
approval in this profile. Treat any missing or weakened control as a
release blocker, not a documentation warning. The auditable checklist is in
[CONTRIBUTING.md](CONTRIBUTING.md#first-release-repository-checklist).
Every human, App, deploy key, token, workflow, or ruleset-bypass identity with
push or `contents: write` capability is part of the release-authority boundary;
keep that set minimal and monitor Release and tag events for unexpected use.
