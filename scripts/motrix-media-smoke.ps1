param(
  [Parameter(Mandatory = $true)]
  [string] $FFmpegPath,

  [Parameter(Mandatory = $true)]
  [string] $FFprobePath,

  [Parameter(Mandatory = $true)]
  [string] $WorkDir
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

foreach ($binary in @($FFmpegPath, $FFprobePath)) {
  if (-not (Test-Path -LiteralPath $binary -PathType Leaf)) {
    throw "Required media binary is missing: $binary"
  }
}
New-Item -ItemType Directory -Path $WorkDir -Force -ErrorAction Stop | Out-Null

function Invoke-FFmpeg {
  param(
    [Parameter(Mandatory = $true)]
    [string] $Operation,

    [Parameter(Mandatory = $true)]
    [string[]] $Arguments
  )

  & $FFmpegPath @Arguments
  if ($LASTEXITCODE -ne 0) {
    throw "$Operation failed with exit code $LASTEXITCODE"
  }
}

function Invoke-ProgressFFmpeg {
  param(
    [Parameter(Mandatory = $true)]
    [string] $Operation,

    [Parameter(Mandatory = $true)]
    [string[]] $Arguments
  )

  $output = (& $FFmpegPath @Arguments 2>&1 | Out-String)
  if ($LASTEXITCODE -ne 0) {
    throw "$Operation failed with exit code $LASTEXITCODE`n$output"
  }
  if ($output -notmatch '(?m)^progress=end\r?$') {
    throw "$Operation did not report progress=end"
  }
}

function Get-ProbeValue {
  param(
    [Parameter(Mandatory = $true)]
    [string] $Selector,

    [Parameter(Mandatory = $true)]
    [string] $Entry,

    [Parameter(Mandatory = $true)]
    [string] $Path
  )

  $output = (& $FFprobePath -v error -select_streams $Selector `
    -show_entries "stream=$Entry" -of default=nw=1:nk=1 -- $Path |
    Out-String).Trim()
  if ($LASTEXITCODE -ne 0) {
    throw "FFprobe failed for $Path with exit code $LASTEXITCODE"
  }
  return $output
}

function Assert-Equal {
  param(
    [Parameter(Mandatory = $true)]
    [string] $Expected,

    [AllowEmptyString()]
    [Parameter(Mandatory = $true)]
    [string] $Actual,

    [Parameter(Mandatory = $true)]
    [string] $Operation
  )

  if ($Actual -cne $Expected) {
    throw "$Operation expected $Expected, got $Actual"
  }
}

function Assert-Mp4Format {
  param(
    [Parameter(Mandatory = $true)]
    [string] $Path
  )

  $format = (& $FFprobePath -v error -show_entries format=format_name `
    -of default=nw=1:nk=1 -- $Path | Out-String).Trim()
  if ($LASTEXITCODE -ne 0) {
    throw "FFprobe format inspection failed for $Path"
  }
  if (($format -split ',') -cnotcontains 'mp4') {
    throw "Expected an MP4-family container, got ${format}: $Path"
  }
}

function Assert-ListingToken {
  param(
    [Parameter(Mandatory = $true)]
    [string] $Listing,

    [Parameter(Mandatory = $true)]
    [string] $Token,

    [Parameter(Mandatory = $true)]
    [string] $Kind
  )

  $escaped = [Regex]::Escape($Token)
  if ($Listing -notmatch "(?m)^\s*\S*\s+$escaped(?:\s|$)") {
    throw "Required $Kind is unavailable: $Token"
  }
}

$versionOutput = (& $FFmpegPath -version 2>&1 | Out-String)
if ($LASTEXITCODE -ne 0) {
  $exitCode = $LASTEXITCODE
  $exitHex = '{0:X8}' -f ($exitCode -band 0xFFFFFFFFL)
  throw "ffmpeg -version failed with exit code $exitCode (0x$exitHex)`n$versionOutput"
}
$probeVersionOutput = (& $FFprobePath -version 2>&1 | Out-String)
if ($LASTEXITCODE -ne 0) {
  $exitCode = $LASTEXITCODE
  $exitHex = '{0:X8}' -f ($exitCode -band 0xFFFFFFFFL)
  throw "ffprobe -version failed with exit code $exitCode (0x$exitHex)`n$probeVersionOutput"
}
if ($versionOutput -notmatch '--enable-libx264' -or
    $versionOutput -notmatch '--enable-libmp3lame' -or
    $probeVersionOutput -notmatch 'ffprobe version') {
  throw 'Required Motrix build features are not reported'
}

$muxersOutput = (& $FFmpegPath -hide_banner -muxers 2>&1 | Out-String)
if ($LASTEXITCODE -ne 0) {
  throw 'ffmpeg -muxers failed'
}
foreach ($muxer in @('mp4', 'ipod', 'mov', 'matroska', 'webm', 'mpegts',
    'flv', 'adts', 'mp3', 'opus')) {
  Assert-ListingToken -Listing $muxersOutput -Token $muxer -Kind 'muxer'
}

$bsfsOutput = (& $FFmpegPath -hide_banner -bsfs 2>&1 | Out-String)
if ($LASTEXITCODE -ne 0) {
  throw 'ffmpeg -bsfs failed'
}
if ($bsfsOutput -notmatch '(?m)^\s*aac_adtstoasc\s*$') {
  throw 'Required bitstream filter is unavailable: aac_adtstoasc'
}

$encodersOutput = (& $FFmpegPath -hide_banner -encoders 2>&1 | Out-String)
if ($LASTEXITCODE -ne 0) {
  throw 'ffmpeg -encoders failed'
}
foreach ($encoder in @('libx264', 'aac', 'libmp3lame', 'flac', 'pcm_s16le', 'mjpeg')) {
  Assert-ListingToken -Listing $encodersOutput -Token $encoder -Kind 'encoder'
}

$filtersOutput = (& $FFmpegPath -hide_banner -filters 2>&1 | Out-String)
if ($LASTEXITCODE -ne 0) {
  throw 'ffmpeg -filters failed'
}
Assert-ListingToken -Listing $filtersOutput -Token 'scale' -Kind 'filter'

$videoOnly = Join-Path $WorkDir 'video-only.mp4'
$audioOnly = Join-Path $WorkDir 'audio-only.m4a'
$merged = Join-Path $WorkDir 'merged.mp4.motrix'
$transportStream = Join-Path $WorkDir 'mpegts-aac.ts'
$tsRemux = Join-Path $WorkDir 'mpegts-remux.mp4.motrix'
$mp3Output = Join-Path $WorkDir 'audio.mp3'
$flacOutput = Join-Path $WorkDir 'audio.flac'
$wavOutput = Join-Path $WorkDir 'audio.wav'
$thumbnail = Join-Path $WorkDir 'thumbnail.jpg'
$matroskaOutput = Join-Path $WorkDir 'remux.mkv'

Invoke-FFmpeg -Operation 'video-only fixture encode' -Arguments @(
  '-hide_banner', '-loglevel', 'error', '-nostdin', '-y',
  '-f', 'lavfi', '-i', 'testsrc2=size=128x96:rate=2',
  '-t', '1', '-an', '-c:v', 'libx264', '-pix_fmt', 'yuv420p',
  '-f', 'mp4', $videoOnly
)
Invoke-FFmpeg -Operation 'audio-only fixture encode' -Arguments @(
  '-hide_banner', '-loglevel', 'error', '-nostdin', '-y',
  '-f', 'lavfi', '-i', 'sine=frequency=1000:sample_rate=48000',
  '-t', '1', '-vn', '-c:a', 'aac', '-f', 'ipod', $audioOnly
)

# Mirrors FfmpegService.buildArgs for a separate-video/separate-audio job whose
# temporary `.motrix` output cannot be inferred from its file extension.
Invoke-ProgressFFmpeg -Operation 'dual-input Motrix remux' -Arguments @(
  '-hide_banner', '-loglevel', 'error', '-nostdin',
  '-i', $videoOnly, '-i', $audioOnly,
  '-c', 'copy', '-map', '0:v:0', '-map', '1:a:0',
  '-movflags', '+faststart', '-f', 'mp4',
  '-progress', 'pipe:1', '-nostats', '-y', $merged
)
Assert-Equal -Expected 'h264' -Actual (Get-ProbeValue 'v:0' 'codec_name' $merged) `
  -Operation 'dual-input video codec'
Assert-Equal -Expected 'aac' -Actual (Get-ProbeValue 'a:0' 'codec_name' $merged) `
  -Operation 'dual-input audio codec'
Assert-Mp4Format $merged

Invoke-FFmpeg -Operation 'MPEG-TS AAC fixture encode' -Arguments @(
  '-hide_banner', '-loglevel', 'error', '-nostdin', '-y',
  '-f', 'lavfi', '-i', 'testsrc2=size=128x96:rate=2',
  '-f', 'lavfi', '-i', 'sine=frequency=880:sample_rate=48000',
  '-t', '1', '-c:v', 'libx264', '-pix_fmt', 'yuv420p', '-c:a', 'aac',
  '-f', 'mpegts', $transportStream
)

# Mirrors the fromMpegts path in FfmpegService, including the AAC bitstream
# filter and the explicit muxer required by the `.motrix` placeholder.
Invoke-ProgressFFmpeg -Operation 'MPEG-TS Motrix remux' -Arguments @(
  '-hide_banner', '-loglevel', 'error', '-nostdin',
  '-i', $transportStream, '-c', 'copy', '-bsf:a', 'aac_adtstoasc',
  '-movflags', '+faststart', '-f', 'mp4',
  '-progress', 'pipe:1', '-nostats', '-y', $tsRemux
)
Assert-Equal -Expected 'h264' -Actual (Get-ProbeValue 'v:0' 'codec_name' $tsRemux) `
  -Operation 'MPEG-TS remux video codec'
Assert-Equal -Expected 'aac' -Actual (Get-ProbeValue 'a:0' 'codec_name' $tsRemux) `
  -Operation 'MPEG-TS remux audio codec'
Assert-Mp4Format $tsRemux

Invoke-FFmpeg -Operation 'MP3 encode' -Arguments @(
  '-hide_banner', '-loglevel', 'error', '-nostdin', '-y',
  '-f', 'lavfi', '-i', 'sine=frequency=440:sample_rate=44100',
  '-t', '1', '-vn', '-c:a', 'libmp3lame', $mp3Output
)
Assert-Equal -Expected 'mp3' -Actual (Get-ProbeValue 'a:0' 'codec_name' $mp3Output) `
  -Operation 'MP3 codec'
Invoke-FFmpeg -Operation 'MP3 decode' -Arguments @(
  '-hide_banner', '-loglevel', 'error', '-nostdin', '-i', $mp3Output,
  '-f', 'null', 'NUL'
)

Invoke-FFmpeg -Operation 'FLAC encode' -Arguments @(
  '-hide_banner', '-loglevel', 'error', '-nostdin', '-y',
  '-f', 'lavfi', '-i', 'sine=frequency=550:sample_rate=44100',
  '-t', '1', '-vn', '-c:a', 'flac', $flacOutput
)
Assert-Equal -Expected 'flac' -Actual (Get-ProbeValue 'a:0' 'codec_name' $flacOutput) `
  -Operation 'FLAC codec'

Invoke-FFmpeg -Operation 'PCM WAV encode' -Arguments @(
  '-hide_banner', '-loglevel', 'error', '-nostdin', '-y',
  '-f', 'lavfi', '-i', 'sine=frequency=660:sample_rate=44100',
  '-t', '1', '-vn', '-c:a', 'pcm_s16le', $wavOutput
)
Assert-Equal -Expected 'pcm_s16le' -Actual (Get-ProbeValue 'a:0' 'codec_name' $wavOutput) `
  -Operation 'PCM WAV codec'

Invoke-FFmpeg -Operation 'JPEG thumbnail generation' -Arguments @(
  '-hide_banner', '-loglevel', 'error', '-nostdin', '-y',
  '-ss', '0', '-i', $merged, '-frames:v', '1',
  '-vf', 'scale=64:48', $thumbnail
)
Assert-Equal -Expected 'mjpeg' -Actual (Get-ProbeValue 'v:0' 'codec_name' $thumbnail) `
  -Operation 'thumbnail codec'
Assert-Equal -Expected '64' -Actual (Get-ProbeValue 'v:0' 'width' $thumbnail) `
  -Operation 'thumbnail width'
Assert-Equal -Expected '48' -Actual (Get-ProbeValue 'v:0' 'height' $thumbnail) `
  -Operation 'thumbnail height'

Invoke-FFmpeg -Operation 'Matroska remux' -Arguments @(
  '-hide_banner', '-loglevel', 'error', '-nostdin', '-y',
  '-i', $merged, '-map', '0', '-c', 'copy', '-f', 'matroska', $matroskaOutput
)
$matroskaFormat = (& $FFprobePath -v error -show_entries format=format_name `
  -of default=nw=1:nk=1 -- $matroskaOutput | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or $matroskaFormat -notmatch 'matroska') {
  throw "Matroska remux has unexpected format: $matroskaFormat"
}

Write-Host "Motrix media smoke passed: $WorkDir"
