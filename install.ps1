#!/usr/bin/env pwsh
# Install keyshim from GitHub releases.
#
#   irm https://raw.githubusercontent.com/waldemarsson/keyshim/main/install.ps1 | iex
#
# Environment:
#   KEYSHIM_VERSION      release tag to install, e.g. v0.2.0 (default: latest)
#   KEYSHIM_INSTALL_DIR  target directory (default: $env:LOCALAPPDATA\keyshim)
#   KEYSHIM_VERIFY_ATTESTATION=1
#                         also verify the GitHub build provenance attestation
#                         with `gh attestation verify` (requires the gh CLI)
#   KEYSHIM_BASE_URL     download from another location; for mirrors and tests
#
# The archive is always checked against the release's SHA256SUMS.

$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

$repo = 'waldemarsson/keyshim'
$version = if ($env:KEYSHIM_VERSION) { $env:KEYSHIM_VERSION } else { 'latest' }
$installDir = if ($env:KEYSHIM_INSTALL_DIR) { $env:KEYSHIM_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA 'keyshim' }

function Fail($message) {
  throw "keyshim install: $message"
}

switch ([System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture) {
  'X64' { $arch = 'amd64' }
  'Arm64' { $arch = 'arm64' }
  default { Fail "unsupported architecture $([System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture)" }
}
$asset = "keyshim_windows_${arch}.zip"

if ($env:KEYSHIM_BASE_URL) {
  $baseUrl = $env:KEYSHIM_BASE_URL
} elseif ($version -eq 'latest') {
  $baseUrl = "https://github.com/$repo/releases/latest/download"
} else {
  $baseUrl = "https://github.com/$repo/releases/download/$version"
}

$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ([System.IO.Path]::GetRandomFileName())
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
  $assetPath = Join-Path $tmp $asset
  $sumsPath = Join-Path $tmp 'SHA256SUMS'

  Write-Host "Downloading $asset ($version)"
  try {
    Invoke-WebRequest -UseBasicParsing -Uri "$baseUrl/$asset" -OutFile $assetPath
    Invoke-WebRequest -UseBasicParsing -Uri "$baseUrl/SHA256SUMS" -OutFile $sumsPath
  } catch {
    Fail "download failed: $_"
  }

  $sumsLine = Select-String -Path $sumsPath -Pattern $asset -SimpleMatch | Select-Object -First 1
  if (-not $sumsLine) {
    Fail "$asset is not listed in SHA256SUMS"
  }
  $expected = ($sumsLine.Line -split '\s+')[0]
  $actual = (Get-FileHash -Path $assetPath -Algorithm SHA256).Hash
  if ($expected.ToLower() -ne $actual.ToLower()) {
    Fail "checksum mismatch for $asset (expected $expected, got $actual)"
  }
  Write-Host "Checksum verified"

  if ($env:KEYSHIM_VERIFY_ATTESTATION -eq '1') {
    if (-not (Get-Command gh -ErrorAction SilentlyContinue)) {
      Fail "KEYSHIM_VERIFY_ATTESTATION=1 needs the gh CLI"
    }
    & gh attestation verify $assetPath --repo $repo | Out-Null
    if ($LASTEXITCODE -ne 0) {
      Fail "attestation verification failed for $asset"
    }
    Write-Host "Build provenance attestation verified"
  }

  $extractDir = Join-Path $tmp 'extracted'
  Expand-Archive -Path $assetPath -DestinationPath $extractDir -Force

  New-Item -ItemType Directory -Path $installDir -Force | Out-Null
  # Windows cannot overwrite a running .exe but can rename it, so move the
  # current binary aside before putting the new one in place.
  $newPath = Join-Path $installDir 'keyshim.new.exe'
  $oldPath = Join-Path $installDir 'keyshim.old.exe'
  $finalPath = Join-Path $installDir 'keyshim.exe'
  Copy-Item (Join-Path $extractDir 'keyshim.exe') $newPath -Force
  try {
    Remove-Item $oldPath -Force -ErrorAction SilentlyContinue
    if (Test-Path $finalPath) {
      Move-Item $finalPath $oldPath
    }
    try {
      Move-Item $newPath $finalPath
    } catch {
      if (Test-Path $oldPath) { Move-Item $oldPath $finalPath }
      throw
    }
  } catch {
    Remove-Item $newPath -Force -ErrorAction SilentlyContinue
    Fail "could not replace ${finalPath}: $_"
  }
  # Still locked if the old binary is running; it is removed on the next install.
  Remove-Item $oldPath -Force -ErrorAction SilentlyContinue

  $installedVersion = & $finalPath version
  Write-Host "Installed $installedVersion to $finalPath"
  if (($env:Path -split ';') -notcontains $installDir) {
    Write-Host "Add $installDir to your PATH to run keyshim directly."
  }
} finally {
  Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}
