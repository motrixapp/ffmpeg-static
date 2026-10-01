# Contributing

Thank you for improving the standalone FFmpeg builds used by Motrix. Changes
to this repository can affect executable code that users download, so the
source lock, license profile, target matrix, and release gates are treated as
security boundaries.

## Scope

Good contributions include:

- Fixes to one of the six supported target builds.
- Stronger source, archive, binary, linkage, or feature validation.
- Reproducibility and provenance improvements.
- Documentation and tests.
- Carefully reviewed FFmpeg, x264, LAME, NASM, musl, fortify-headers,
  llvm-mingw build-recipe, LLVM runtime, mingw-w64, or toolchain updates.

Do not add optional libraries merely to make a “larger” FFmpeg. A new
dependency needs a concrete Motrix capability requirement, a license and
patent review, pinned upstream source, reviewable repeat-build instructions, and
verification on every affected target.

## Non-negotiable release invariants

- The exact matrix is `darwin-arm64`, `darwin-x64`, `linux-arm64`,
  `linux-x64`, `win32-arm64`, and `win32-x64`.
- Minimum-OS metadata is a target-specific release contract: Linux ARM64 is
  kernel `3.7.0`, Linux x86-64 is kernel `2.6.39`, both Windows targets are
  `10.0`, and both macOS targets use the locked `MACOS_MIN_VERSION`. Preserve
  the exact value in `BUILD-INFO.json`, per-asset metadata, and the manifest;
  never substitute one Linux architecture's floor for the other.
- Windows uses PE OS version `10.0` and `_WIN32_WINNT`/`WINVER=0x0A00`,
  but PE subsystem version `6.2` for MinGW loader compatibility. Subsystem
  `6.3` or later requires an MSVC-style load-config SecurityCookie that this
  CRT does not provide ([upstream issue](https://github.com/mstorsjo/llvm-mingw/issues/511)).
  Do not equate that field with the supported OS floor or disable CFG/SSP to
  work around startup failures. Both Windows architectures require native tests.
- The `motrix-full-gpl` profile keeps `GPL-2.0-or-later` as its principal
  copyleft license, with `--enable-gpl`, `--enable-libx264`, and
  `--enable-libmp3lame`. That profile value is not the complete effective
  target license. `BASE` is
  `GPL-2.0-or-later AND LGPL-2.1-or-later AND IJG AND ISC AND MIT AND BSD-1-Clause AND BSD-2-Clause AND BSD-3-Clause AND Zlib AND BSL-1.0`.
  Darwin is `BASE`; Linux is
  `BASE AND 0BSD AND SunPro AND (GPL-3.0-or-later WITH GCC-exception-3.1)`;
  Windows is
  `BASE AND (Apache-2.0 WITH LLVM-exception) AND LicenseRef-MinGW-w64-runtime`.
  Both architectures on each platform use its exact expression.
- Never enable `--enable-nonfree` or `--enable-version3` in this profile.
- Preserve the full generated third-party notices and target-specific
  `LICENSES.json`. The notice must be generated from fresh locked FFmpeg, x264,
  LAME, musl, and fortify-headers trees and match its exact byte count and hash
  lock. The IJG-derived DCT sources are currently unmodified and require the
  Independent JPEG Group credit; any future change must be declared. Preserve
  the complete Glumpy BSD-3-Clause terms. ISC applies to every target; x64
  additionally compiles x264 and FFmpeg x86inc assembly. LAME's effective
  component license is `LGPL-2.1-or-later`, and compiled musl is
  `MIT AND SunPro`.
- Linux releases are genuinely static musl ELF binaries. macOS and Windows
  may dynamically link only their documented system-library allowlists.
- FFmpeg, x264, LAME, NASM, Linux musl, fortify-headers, the llvm-mingw
  build-recipe source, LLVM runtime source, the audited mingw-w64 source
  revision, and the Windows toolchain are immutable and SHA-256-locked. FFmpeg
  also passes verification with the pinned upstream PGP key fingerprint.
- The Release source set is FFmpeg, x264, LAME, musl, fortify-headers, NASM,
  llvm-mingw build recipe, and LLVM runtime, accompanied by the standalone
  `sources.env` source lock and vendored FFmpeg release public key. Every x64
  target must build NASM from the same locked source, explicitly select it for
  x264/FFmpeg assembly, and record both source and
  executable hashes; package-manager or runner NASM fallbacks are forbidden.
  Formal x64 signing inputs and independent rebuilds also carry the exact NASM
  executable as bounded, read-only hash evidence. Verification must compare its
  bytes and recorded digest; signing jobs must never execute it, and it is not
  part of a user payload archive.
  NASM's exact official archive is the sole narrow exception for setgid bits on
  directories; extracted permissions are stripped and revalidated. Never
  broaden that policy to files, other special bits, or another archive.
  Never republish the complete mingw-w64 audit tree: it contains
  disputed upstream Cephes/Moshier-derived material. Lock its revision, URL,
  and hash, and require the final linker traces/maps for `ffmpeg.exe` and
  `ffprobe.exe` to reject all 14 prohibited object families.
- Production macOS binaries match the pinned DER certificate SHA-256 and one
  concrete Apple Team ID, are Developer ID Application signed with hardened
  runtime and secure timestamps, and have an accepted notarization submission
  for the exact released ZIP. The corresponding Apple developer log must be a
  target-specific Release asset bound by name, size, and SHA-256 in signing
  evidence schema 3, metadata, manifest, checksums, and SPDX. It must prove log
  format 1, the same job ID, Accepted/status code 0, the exact archive basename
  and SHA-256, and no issues. Do not claim stapling for the plain CLI ZIP or
  rewrite it after submission.
- Windows x64 and ARM64 payloads remain unsigned PE executables and identical
  to the approved, independently rebuilt inputs. A separate Ed25519 signature
  authenticates the complete release manifest; Motrix pins that public key.
- A formal release cannot publish with a missing target, missing/incorrect
  platform signature, malformed archive, checksum mismatch,
  source-provenance mismatch, or disabled/unverifiable Immutable Releases.
- “Deterministic packaging” means identical payload/metadata bytes make an
  identical archive with the same packaging implementation/runtime. Do not
  call the complete compiler build reproducible
  unless two independent clean builds match and every compiler, linker,
  SDK/sysroot, host-tool, environment, and signing input is covered.
- `SOURCE_DATE_EPOCH` controls normalized archive timestamps only. A formal
  SPDX `creationInfo.created` value comes from the hash-bound annotated
  tagger timestamp; unsigned control/test output uses the trusted
  control-commit timestamp.
- Keep schema versions exact: `BUILD-INFO.json` 1, `LICENSES.json` 2,
  per-asset metadata 2, nested signing evidence 3, and `ffmpeg-manifest.json`
  3. Consumers must fail
  closed on any other version.

## Set up and run fast checks

Formal CI and the local unit suite require Python 3.9 or later. These scripts
use only the standard library to parse the lock, validate/assemble metadata and
the SBOM, and write normalized archives. Python is orchestration only: it does
not compile or link FFmpeg and is not embedded in the released executables.
Compiler identity means the platform's Apple Clang, Clang/LLD, or GCC—not the
Python implementation. Record Python separately as build-tool provenance.
Source fetching requires curl 7.71 or later for bounded all-error retries.
CI may restore same-target/runner-OS source-download caches across build
revisions, but every file is rechecked against the current source lock and
FFmpeg's upstream signature before compilation. A cache is not a trust root,
and compiled payloads or signing inputs are never restored from it.

```sh
python3 -m unittest discover -s tests -v
python3 -m compileall -q scripts tests
```

When changing shell or workflow files, also run:

```sh
shellcheck scripts/*.sh
actionlint
```

The unit tests deliberately use fake executables. They test pipeline logic,
not FFmpeg itself. The required real-binary gates are:

| Target | Build/structural verification | Native functional verification |
| --- | --- | --- |
| `darwin-arm64` | Apple silicon macOS; architecture, deployment target, feature/license flags, system-library allowlist | Native H.264/AAC and MP3 encode/probe, scale filter, remux, and `ffprobe` |
| `darwin-x64` | Intel macOS; same contract | Same tests on Intel macOS |
| `linux-arm64` | ARM64 Linux; static musl ELF, architecture, hardening, feature/license flags | Same tests on ARM64 Linux |
| `linux-x64` | x86-64 Linux; same contract | Same tests on x86-64 Linux |
| `win32-arm64` | Cross-build plus PE architecture/import/feature inspection | Same tests on native GitHub `windows-11-vs2026-arm` |
| `win32-x64` | Cross-build plus PE architecture/import/feature inspection | Same tests on native Windows x64 |

CI also packages each target twice and compares hashes. For a formal release,
the final macOS and Windows payloads pass additional secret-free native
verification before the complete six-target set is assembled. A change is not
validated merely because it cross-compiles successfully.

## Build hosts

The scripts reject unsupported host/target pairs:

- `darwin-arm64`: native Apple silicon macOS runner.
- `darwin-x64`: native Intel macOS runner.
- `linux-arm64`: native ARM64 Linux runner.
- `linux-x64`: native x86-64 Linux runner.
- `win32-arm64` and `win32-x64`: x86-64 Ubuntu using the locked UCRT
  llvm-mingw cross-toolchain.

Build and inspect one target with:

```sh
./scripts/build.sh <target>
./scripts/verify-binary.sh <target>
```

Docker or OrbStack can provide a clean Linux x86-64 environment. It does not
turn an x86-64 host into a release-quality ARM64 or macOS verification host.
Use the GitHub Actions matrix for the complete release candidate.

## Updating a locked source

1. Use an official upstream release or an explicit reviewed revision. Avoid
   moving branches and floating URLs.
2. Download the source independently and calculate its SHA-256. For FFmpeg,
   also obtain its detached upstream signature and verify the signer
   fingerprint before changing the lock.
3. Update every related field in `sources.env`, including the archive name,
   URL, checksum, minimum-OS value where applicable, and
   `SOURCE_DATE_EPOCH`. Keep the file as plain `KEY=VALUE`; shell expansion,
   quoting, spaces, and commands are intentionally rejected.
4. Do not replace the vendored FFmpeg release key simply because a signature
   fails. Verify any real upstream key rotation through multiple official
   channels and call it out prominently in the pull request.
5. Increment `BUILD_REVISION` for a packaging, flag, or toolchain change at the
   same FFmpeg version. A new FFmpeg version normally starts a new Motrix build
   revision series.
6. Re-check upstream license files and the effective aggregate license. Verify
   the platform expressions above, preserve the IJG DCT credit and no-change
   statement, complete Glumpy BSD-3-Clause terms, all-target ISC sources plus
   x264/FFmpeg x86inc ISC on x64, LAME `LGPL-2.1-or-later`, and compiled musl
   `MIT AND SunPro`. Regenerate the complete five-tree notice on fresh source
   trees, update its expected byte count and SHA-256 only after independent
   review, and update `LICENSES.json`, the SPDX component BOM, and
   build-material records for every new source, sysroot, runtime, compiler,
   linker, SDK, assembler, or packaging tool.
7. If the mingw-w64 revision changes, audit its complete upstream archive but
   do not add that archive to the Release. Revalidate the exact 14 prohibited
   Cephes/Moshier-derived object families against all four final Windows linker
   trace/map records. Update and publish the matching LLVM runtime source when
   llvm-mingw/compiler-rt changes.
8. Build and verify all six targets, including native Windows ARM64. Attach
   sanitized logs, build records, and hashes to the pull request; do not commit
   generated archives or build directories.

musl's latest stable release currently requires official security backports.
Keep `patches/musl-CVE-2026-6042.patch` byte-identical to the
[upstream iconv patch](https://www.openwall.com/lists/musl/2026/04/03/2/1),
and `patches/musl-CVE-2026-40200.patch` byte-identical to the
[upstream three-part qsort patch](https://www.openwall.com/lists/musl/2026/04/10/3/1).
The patch application and post-patch source hashes must pass in source audit
and each clean build, before notice generation or compilation. Never silently
drop a backport when changing the musl version. Include the patches and
application script in the build-pipeline source archive.

LLVM 23.1.2's corresponding-source archive expands to 2,246,337,223 regular-file
bytes. Only an archive verified against `LLVM_RUNTIME_SHA256` receives the
2304 MiB aggregate limit; every other source retains the 2 GiB limit. Member,
compressed-size, path, type, permission, symlink, and count checks still apply.

## Reviewing Action dependency risks

Use the latest reviewed official release pinned to a verified full commit SHA;
do not add a floating tag, arbitrary fork, or locally rebuilt Action as an
unreviewed workaround. `audit_action_dependencies.py` reads runtime npm lock
entries at each exact workflow commit, including nested package versions,
excludes development-only packages, and queries current GitHub advisories.
Run it with an authenticated `gh` session:

```sh
python3 -I scripts/audit_action_dependencies.py .github/workflows
```

Exit 1 means High/Critical inventory findings; exit 2 means the audit could not
complete. Neither is a clean security result. Optional runtime packages can
produce conservative findings; investigate the Action's bundled code and this
workflow's inputs before making any reachability claim.

Formal publication is controlled by `security/action-risk-review.json`.
Do not set it to approved just to make a workflow green. Refresh the complete
evidence on the review date, assess every advisory (including remaining
High/Critical items), bind its SHA-256 and every exact Action reference, and
record the explicit maintainer decision in a protected-main change. If no
adequate fix or defensible, specifically reviewed exception exists, keep the
hold. Approval validity is at most 14 days; a changed Action commit, release tag,
source lock, workflow, assessment, or advisory evidence invalidates it. Schema 2
checks the exact scope, not merely the Action references. Recheck the gate
after protected-environment waits, before signing/attestation/publishing work,
and immediately before making a draft public; the UTC expiry must still hold.
Existing signing-environment approvals remain required.

On 2026-10-01, maintainer `agalwood` explicitly accepted the documented residual
risks solely for `v9.0.2-motrix.1` through 2026-10-15. The refreshed inventory
from run `36807648066` is unchanged. This is a short-lived exception, not a
vulnerability fix, unrestricted permission for future releases, or confirmation
of any signing Environment.
That run (`36810616718`) failed closed on an incorrect step-output reference
before source preparation. Preserve its immutable tag, correct the reference,
and advance to `v9.0.2-motrix.2`. After all nine checks passed in CI run
`36812820986`, `agalwood` explicitly approved that new exact scope on
2026-10-01 through 2026-10-15 UTC, including bounded same-URL retries and
same-target/runner-OS source-cache fallback. Build sources, toolchains,
Action references and all 42 advisories are unchanged. This separate
single-version exception does not confirm any protected Environment or
claim a public Release already exists.
Formal `.2` run `36819481774` failed closed at secret-free pre-sign checks after
all six candidate and four independent builds completed. Candidate `.3` fixes
Windows binary-mode reads, requires a deterministic linker ad-hoc baseline on
both macOS architectures, and carries exact read-only x64 NASM evidence through
verification. Neither immutable tag is replaced. The changed release tag,
source lock and workflows require a new explicit risk decision; the prior
single-version `.2` exception cannot authorize `.3` publication. On 2026-10-01,
`agalwood` explicitly authorized that fully disclosed `.3` scope and all 42
residual advisories solely for this version through 2026-10-15 UTC, conditional
on all exact-commit CI checks and unchanged protected release gates. This
separate recorded exception neither fixes an advisory nor confirms an Environment.

Formal `.3` run `36831228925` passed all six candidate builds, four independent
rebuilds, six secret-free pre-sign approvals and final input grants. The Windows
finalizer then failed closed because its risk recheck used POSIX shell syntax
under PowerShell; macOS jobs were cancelled while awaiting protected approval.
No signing credentials or Release were reached. Preserve all three immutable
tags. Candidate `.4` uses native PowerShell argument arrays, explicitly propagates
validator failures, corrects Windows packaging's `--payload` argument, and tests
the actual workflow bodies on both native Windows architectures before signing.
On 2026-10-01, `agalwood` authorized corrective revisions until the first formal
Release succeeds, in response to the disclosed `.4` scope and unchanged 42
residual advisories. The current record binds only `.4` and its exact new hashes,
with the existing 2026-10-15 UTC deadline. Any further revision needs its own
scope record; this authorization does not cover new advisories, expiry extensions,
unrelated source/Action updates, or protected-Environment approval. All nine
exact-commit checks, independent rebuilds, signing and publication gates remain.

Formal `.4` run `36840700978` passed all six candidate builds, four independent
rebuilds, six secret-free approvals and final grants. Both Windows finalizers
then rejected the isolated packaging entrypoint: `python -I` correctly removes
ambient module paths, but the packaging script had not anchored its adjacent
`pipeline_lib` helper. macOS remained at the required-reviewer gate; the run was
cancelled without signing credentials or a Release. Preserve all four tags.
Candidate `.5` imports helpers only from the protected script directory, executes
every native Python CLI entrypoint under isolation, and runs the exact final
packaging command in required Windows CI and before native pre-sign approval
upload. Tests ensure the three command copies cannot drift. The continuing
maintainer authorization above is freshly bound only to `.5` and its new scope,
retaining the same 42 advisories and 2026-10-15 UTC deadline. It does not reuse
the `.4` hashes, approve an Environment, or widen the risk acceptance.

Formal `.5` run `36848365270` passed all candidate/rebuild and secret-free
approval/grant checks and both Windows final packaging jobs. After the maintainer
confirmed the macOS Environment, both signing jobs failed closed while decoding
`MAC_CERTS`: strict Base64 rejected an invalid character. Credentials had reached
that step, but certificate import, code signing and notarization had not begun.
The Secret was not inspected; wrapped/trailing-newline Base64 is a common possible
cause, not a confirmed diagnosis of its contents. Candidate `.6` accepts only
ASCII space, tab, CR and LF around canonical standard Base64, bounds raw input to
64 KiB and rejects malformed padding, other alphabets/characters and empty data
without printing input. Actual production-pipeline fake fixtures run under the
signer's isolated system Python in both native macOS CI and secret-free pre-sign
jobs. Identity pins, PKCS#12 import, timestamps, signing, notarization and every
other release gate are unchanged. The continuing authorization is freshly bound
only to `.6`, retaining all 42 advisories and the same 2026-10-15 UTC deadline.
No earlier hash record or Environment confirmation is reused; all five previous
tags remain immutable. If decoding still fails, the maintainer must privately
replace the malformed Secret rather than weakening validation or disclosing it.

The supporting [call-path assessment](security/action-reachability-review.json)
binds the current workflow, source lock, exact upstream bundles, and all 42
inventoried advisories. It records input limitations and residual risk, including
active Azure XML processing and Sigstore DSSE signing code. Static inspection is
not proof of non-reachability or a fix. Its assessment-only status neither
approves an exception nor changes the formal publication gate. A maintainer
considering a short-lived exception must explicitly accept these residual
risks in a protected-main change; merging the assessment alone is not approval.

## Pull request checklist

- Explain the user-visible Motrix capability or security reason for the
  change.
- List affected targets and the real builds that were run.
- Include test output without secrets or local signing identities.
- Keep every action and downloaded tool pinned to an immutable commit or hash.
- Update both READMEs when behavior, installation, features, targets, secrets,
  or release assets change.
- Update the downloader schema/consumer contract and minimum-OS declaration
  together; never add a permissive fallback for an unknown schema, target,
  signature state, or repository identity.
- Keep the target effective-license expression, generated notices,
  `LICENSES.json`, asset metadata, manifest, and SPDX SBOM mutually consistent;
  never shorten the executable license to the principal GPL profile alone.
- Describe packaging determinism and compiler reproducibility separately. If
  claiming a reproducible build, attach hashes from two independent clean
  builders and enumerate the full build BOM that was held constant.
- Preserve unrelated work and keep generated `build/`, `release/`, signing
  keys, certificates, and notarization responses out of commits.

Do not submit third-party binaries in a pull request. If a binary is needed to
reproduce a security problem, coordinate a private transfer through the
process in [SECURITY.md](SECURITY.md).

## Manifest key management

The public root is `keys/manifest-ed25519.pub`; Motrix independently bundles the
same key and its SPKI-DER SHA-256 key ID. The algorithm is Ed25519, not a
self-signed Authenticode certificate. The signature covers UTF-8 domain
`Motrix FFmpeg release manifest v1\\n` followed by the exact manifest bytes.

Keep the private PEM outside Git in an access-restricted, backed-up store.
Local provisioning uses the ignored `.signing-private/` directory; never upload
it as an artifact, include it in a source archive, print it, or copy it into Motrix.
After required-reviewer/branch/no-bypass protections are configured, upload it
with `gh secret set FFMPEG_MANIFEST_PRIVATE_KEY --env release-manifest-signing`
using standard input, not a command-line value. Do not add it as a repository secret.
Rotate through a reviewed Motrix public-key update before publishing with the
new key. Retain old-key release history, document effective version ranges, and
revoke compromised keys in a new Motrix release; never silently accept keys
advertised by a download.

## First-release repository checklist

The workflow cannot configure GitHub's control plane. Every item below blocks
the first public Release and must be re-audited after repository transfer,
plan/visibility change, or credential rotation.

- [ ] Enable [Immutable Releases](https://docs.github.com/en/code-security/how-tos/secure-your-supply-chain/establish-provenance-and-integrity/prevent-release-changes)
  under repository settings. It applies only to future Releases. Confirm the
  API reports `enabled: true`; keep `RELEASE_ADMIN_TOKEN` in `github-release`
  as a repository-only fine-grained PAT or GitHub App installation token with
  **Administration: read** and no content-write permission.
- [ ] Create an active [tag ruleset](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/creating-rulesets-for-a-repository)
  for `v*-motrix.*`. Restrict tag creation to the release-maintainer role and
  block update/deletion after creation; grant no routine bypass and record any
  break-glass actor. Release tags must be annotated tags that point
  directly to a commit on protected `main`; lightweight tags are forbidden.
  The workflow's API checks are not a substitute for this server-side rule.
- [ ] Protect `main`: pull requests only, required six-target CI/status checks,
  resolved conversations, no force-push/deletion, and no administrator bypass.
  This is a single-maintainer project: require zero human PR approvals because
  GitHub does not allow authors to approve their own pull requests. CODEOWNERS
  is ownership metadata, not a claim of independent review.
- [ ] Keep the catch-all `.github/CODEOWNERS` rule `* @agalwood` covering every
  path, including the ownership file itself. Audit permissions and account MFA.
- [ ] Create protected `macos-release-signing`,
  `release-manifest-signing`, and `github-release`
  [Environments](https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments).
  Restrict deployment to the protected default branch (`main`), require
  the required reviewer `agalwood`, allow self-review, and disable administrator
  bypass. Manual confirmation is mandatory, but is not independent two-person review.
  Do not select a tag pattern: the formal control ref is the protected-main
  dispatch and the subject tag is independently verified from the input.
  Signing credentials live only in their designated Environment; no signing
  secret is available to build, assembly, verification, pull-request, tag-push,
  unsigned-dispatch, or fork jobs.
- [ ] Set the repository and every controlling organization/enterprise Actions
  artifact-retention limit to at least **36 days**. Every upload in the release
  workflow explicitly requests 36 days so inputs remain available across
  GitHub's 30-day Environment approval limit and 35-day total workflow limit.
  A lower server-side maximum blocks formal releases and must not be treated as
  an acceptable approval SLA.
- [ ] Set `EXPECTED_MACOS_TEAM_ID` and `EXPECTED_MACOS_CERT_SHA256` to
  independently reviewed production identities; placeholders and “accept
  whatever is in the PFX” are forbidden. No project OpenPGP/tagger-email
  variables are required. Keep Apple identity pins as internal release policy;
  do not require an independent public announcement of them. They remain
  inspectable in code signatures and signed evidence, not confidential.
  Before the first public Release, publish only the Ed25519 manifest public key/key ID on a
  stable Motrix-controlled HTTPS trust page outside this repository and its
  Releases. Link it from an official Motrix site or application, record its
  exact canonical URL in `SECURITY.md`, and retain append-only identity history.
  Until this independent trust root is available, keep the first release blocked.
  The initial key is now published in the installation section of the manual at
  `https://motrix.app/manual/ffmpeg/`
  (Chinese: `https://motrix.app/zh/manual/ffmpeg/`). Re-check the live PEM and
  its SPKI-DER key ID before release; website publication is not approval of
  the separately enforced Action dependency review.
  Consumers authenticate the manifest with that root before using its Apple
  identity fields, then compare them against actual code signatures. This
  intentionally drops the separate out-of-band Apple identity trust anchor;
  producer-side Team/certificate checks, code signing and notarization stay mandatory.
- [ ] Populate macOS Environment secrets `MAC_CERTS`,
  `MAC_CERTS_PASSWORD`, `API_KEY`, `API_KEY_ID`, and
  `API_KEY_ISSUER_ID`; put the PEM Ed25519 private key in
  `release-manifest-signing` as `FFMPEG_MANIFEST_PRIVATE_KEY`; and put only
  `RELEASE_ADMIN_TOKEN` in
  `github-release`. Verify least privilege, expiry monitoring, revocation
  ownership, and secret redaction.
  `MAC_CERTS` must be standard Base64 of the binary Developer ID Application
  PKCS#12 export, not PEM, a path, quoted text or literal `\\n` escape sequences.
  Conventional ASCII spaces/tabs/CR/LF are accepted; other characters,
  noncanonical padding and raw input over 64 KiB fail closed. Provision the
  Secret privately via standard input; never paste its value into logs or chat.
  Signing snapshots the user keychain search list before creating its isolated
  keychain, registers that keychain ahead of the original entries, and restores
  the exact original list before deletion on every exit. Cleanup failures fail
  the job, even if signing completed. This follows the search-list handling in
  [electron-builder's macOS implementation](https://github.com/electron-userland/electron-builder/blob/master/packages/app-builder-lib/src/codeSign/mac/macCodeSign.ts)
  and Motrix's release workflow, without importing their broader application
  entitlements, extra signing-tool permissions or bundled trust stores.
  `--keychain` and the unique Developer ID identity plus internal certificate
  pins remain mandatory; no default keychain or trust settings are changed.
  Public fake-command tests exercise the actual production script on native
  macOS CI and secret-free approval runners. They prove lifecycle/error handling,
  not an actual Developer ID signature; only the protected formal job tests that.
- [ ] Review GitHub Actions policy and every `uses:` reference. Permit only the
  intended actions, keep full commit-SHA pins, disable write tokens by default,
  and retain OIDC/attestation permissions only on the attestation job. Confirm
  the formal gate hard-codes `motrixapp/ffmpeg-static` as the canonical
  repository instead of trusting a fork-derived event value. Inventory every
  human, App, deploy key, token, and workflow able to push, obtain
  `contents: write`, publish Releases, or bypass the tag ruleset; remove
  unnecessary authority, record break-glass ownership, and enable monitoring
  for Release and tag changes. There must be no routine bypass actor.
- [ ] Confirm the downloader and release review process never treat the
  GitHub Release display title or notes as authenticated metadata. GitHub
  permits those fields to change after an immutable Release is published;
  security decisions must use the hash-bound tag, immutable assets, signed manifest,
  attestations, hashes, and platform signatures.
- [ ] Confirm each target's declared minimum OS is encoded in the lock or
  versioned pipeline contract, build record, and asset metadata; tested on an
  appropriate compatibility host; and
  documented identically in both READMEs. A latest-OS smoke test does not by
  itself prove the minimum-OS claim.
- [ ] Run an empty-`release_tag` dispatch and a tag-push rehearsal. Confirm both
  produce only unsigned artifacts and cannot enter a signing/release
  Environment. Then dispatch a reviewed formal candidate from protected `main`
  with its verified existing annotated tag and verify all six archives, both
  macOS signing identity/timestamps and pinned Ed25519 manifest signature,
  exact source assets, SBOM,
  `SHA256SUMS`, Release immutability, and GitHub attestations with the consumer
  commands in the README.

## Maintainer release checklist

`BUILD-INFO.json` in an archive must retain the exact approved `build-info.json`
bytes after complete bounded schema/provenance validation. Do not re-serialize
that record, change dependency order, or replace final byte comparison with
semantic JSON equality. Canonical metadata/SBOM descriptions are separate from
the bound original build record.

1. Review `sources.env`, its diff history, upstream signatures, checksums, and
   source/toolchain BOM, minimum-OS declarations, and the derived
   `v<FFMPEG_VERSION>-motrix.<BUILD_REVISION>` tag. Confirm the intended current
   protected-`main` commit passed all required six-target
   checks and the maintainer inspected the pull request.
2. Re-audit the first-release controls above: active tag ruleset, Immutable
   Releases, the actual single CODEOWNER, expected Team/certificate identity
   variables, the pinned Ed25519 manifest public key, the stable
   out-of-band Motrix HTTPS trust page and its effective identity history, and
   protected `macos-release-signing`, `release-manifest-signing`, and
   `github-release` Environments. The same maintainer may initiate and confirm
   the release; do not describe this as independent human review.
3. Create the matching **annotated tag** directly on that exact protected-main
   commit using `git -c tag.gpgSign=false tag -a <tag> <commit> -m <message>`.
   OpenPGP is not required; lightweight and tag-to-tag references are forbidden.
   Push it through the restricted ruleset. The automatic tag-push run is an
   unsigned test build, not a published release. Keep main at the tagged commit
   until formal dispatch starts.
4. Manually run `Build and release` from main with `release_tag` set to the
   existing tag. Require the canonical repository, protected main, exact direct
   target/control commit, and raw Git tag-object SHA/API binding. Publish checks
   repeat that binding before and after final publication. A tagger name/email
   is not identity proof; this policy relies more heavily on protected GitHub
   authority than the former independent offline OpenPGP tag-key policy.
5. Approve each signing Environment only after all unsigned builds, structural
   verification, native functional tests, deterministic-package checks, source
   authentication, and license gates pass. Confirm the exact platform effective
   expressions, all-target ISC, IJG, complete Glumpy BSD-3-Clause terms, LAME
   LGPL-2.1-or-later, musl `MIT AND SunPro`, and the locked five-tree notice
   byte count/hash. Check signing identity values against an independent record
   before approval. Confirm that the downstream secret-free coordinator
   completed and emitted canonical, exact-ID final grants for the required
   macOS approval or both Windows static/native approvals.
6. Require secret-free final verification of macOS code signing, hardened runtime,
   secure timestamp and notary acceptance; Windows x64/ARM64 must pass native
   smoke, PE/import/link-policy inspection and exact unsigned-input byte comparison.
   Approve `release-manifest-signing` only after assembly and every native smoke pass.
   Its job independently downloads all six candidate IDs and source-reference ID,
   revalidates identities, exact byte bindings and source locks, then signs only
   the manifest with a private key matching `keys/manifest-ed25519.pub`.
7. Before approving `github-release`, inspect the assembled candidate: exactly
   six target archives, six metadata files, and two target-specific macOS
   notarization developer logs; safe archive member sets; the
   authenticated FFmpeg source/signature, plus x264, LAME, musl,
   fortify-headers, NASM, llvm-mingw build-recipe, and LLVM runtime sources; no
   complete mingw-w64 source archive; the standalone `sources.env` source lock;
   the vendored `ffmpeg-release-signing-key.asc`; the deterministic
   corresponding `*-build-scripts.tar.gz`; `ffmpeg-manifest.json` and its `.sig`;
   `SHA256SUMS`; SPDX SBOM;
   and recorded full build BOM, including the llvm-mingw version/URL/SHA-256,
   LLVM runtime source, and mingw-w64 audit revision/URL/SHA-256. Confirm all
   four final Windows trace/map records reject the 14 prohibited object
   families. Confirm every signature identity, minimum-OS field, effective
   target license, and generated notice set agrees across binary evidence,
   metadata, manifest, and SPDX; verify schema versions 1/2/2/signing-3/manifest-3 and that SPDX
   creation time is anchored to the hash-bound annotated tagger timestamp rather than
   `SOURCE_DATE_EPOCH`.
8. Confirm the workflow's independent API check reports Immutable Releases
   enabled. The publish job must create a draft, upload and compare the exact
   checked asset set, attest it, and only then publish. Never use asset clobber
   or edit an immutable Release; issue a higher `BUILD_REVISION` instead.
9. From clean consumer hosts, run `gh release verify`,
   `gh release verify-asset`, `gh attestation verify`, and SHA-256 verification.
   Install through the Motrix downloader/manual path and run a final smoke test
   on all six target/architecture combinations, including Windows ARM64.
