#!/usr/bin/env pwsh
# Build the native guard and hook, then stage them into native/bin/win32-x64.
#
# Requires the Rust toolchain with the x86_64-pc-windows-msvc target and the
# MSVC linker (Visual Studio Build Tools with the C++ workload). No CMake and
# no vendored C library are needed.
#
# Usage:
#   pwsh -NoProfile -File scripts/build-native.ps1 [-Offline]
#
#   -Offline   use only the local cargo registry cache (no network)

[CmdletBinding()]
param(
    [switch]$Offline
)

$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
$outDir = Join-Path $root 'native/bin/win32-x64'

if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
    throw 'cargo was not found on PATH. Install Rust (rustup) first.'
}

$cargoArgs = @('build', '--release')
if ($Offline) {
    $cargoArgs += '--offline'
}

Write-Host "building native artifacts in $root" -ForegroundColor Cyan
Push-Location $root
try {
    & cargo @cargoArgs
    if ($LASTEXITCODE -ne 0) {
        throw "cargo build failed with exit code $LASTEXITCODE"
    }
} finally {
    Pop-Location
}

$artifacts = @(
    @{ Source = 'target/release/msys-token-guard.exe';          Name = 'msys-token-guard.exe' },
    @{ Source = 'target/release/msys_token_guard_hook.dll';     Name = 'msys_token_guard_hook.dll' }
)

New-Item -ItemType Directory -Path $outDir -Force | Out-Null
foreach ($artifact in $artifacts) {
    $source = Join-Path $root $artifact.Source
    if (-not (Test-Path $source)) {
        throw "missing build output: $source"
    }
    Copy-Item $source (Join-Path $outDir $artifact.Name) -Force
    Write-Host ("staged {0}" -f $artifact.Name) -ForegroundColor Green
}

Write-Host "done: $outDir" -ForegroundColor Cyan
