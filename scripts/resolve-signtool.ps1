param(
  [Parameter(Mandatory = $true)][ValidateSet('x64', 'arm64')][string] $Architecture,
  [Parameter(Mandatory = $true)][string] $Version,
  [Parameter(Mandatory = $true)][string] $ExpectedSha256,
  [Parameter(Mandatory = $true)][string] $ExpectedSignerSubject
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if ($Version -notmatch '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$') {
  throw 'Windows SDK SignTool version must contain exactly four numeric components'
}
if ($ExpectedSha256 -notmatch '^[0-9A-Fa-f]{64}$') {
  throw 'Expected SignTool SHA-256 must contain exactly 64 hexadecimal characters'
}
if ([string]::IsNullOrWhiteSpace($ExpectedSignerSubject) -or
    $ExpectedSignerSubject.Contains("`n") -or
    $ExpectedSignerSubject.Contains("`r")) {
  throw 'Expected SignTool signer subject must be a non-empty single line'
}

$kitsRoot = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\bin'
$path = Join-Path $kitsRoot "$Version\$Architecture\signtool.exe"
$item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
  throw "Pinned SignTool is not a regular, non-reparse file: $path"
}
$resolved = [IO.Path]::GetFullPath($item.FullName)
$expectedRoot = [IO.Path]::GetFullPath((Join-Path $kitsRoot "$Version\$Architecture"))
if (-not $resolved.StartsWith($expectedRoot + [IO.Path]::DirectorySeparatorChar,
    [StringComparison]::OrdinalIgnoreCase)) {
  throw "Pinned SignTool escaped the expected SDK directory: $resolved"
}
$actualSha = (Get-FileHash -LiteralPath $resolved -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actualSha -cne $ExpectedSha256.ToLowerInvariant()) {
  throw "Pinned SignTool SHA-256 does not match for $Architecture"
}
$signature = Get-AuthenticodeSignature -LiteralPath $resolved
if ($signature.Status -ne 'Valid' -or $null -eq $signature.SignerCertificate) {
  throw "Pinned SignTool does not have a valid Microsoft Authenticode signature: $resolved"
}
if ($signature.SignerCertificate.Subject -cne $ExpectedSignerSubject) {
  throw 'Pinned SignTool signer subject does not match the protected expectation'
}

Write-Output $resolved
