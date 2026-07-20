# Package Track A Solana payment plugins: test, wasm build, stage for install.
# Usage (from zeroclaw-plugins repo root):
#   .\scripts\package-solana-payments.ps1
#   .\scripts\package-solana-payments.ps1 -SkipTests
#   .\scripts\package-solana-payments.ps1 -Toolchain "stable-x86_64-pc-windows-gnu"

param(
    [string]$Toolchain = "stable-x86_64-pc-windows-gnu",
    [switch]$SkipTests,
    [switch]$SkipBuild
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $Root

$Plugins = @(
    "solana-pay-request",
    "payment-watch",
    "spl-transfer-build",
    "x402-settle"
)

$Stage = Join-Path $Root "dist\solana-payments-suite"
if (Test-Path $Stage) { Remove-Item $Stage -Recurse -Force }
New-Item -ItemType Directory -Path $Stage | Out-Null

Copy-Item (Join-Path $Root "docs\solana-payments-suite.md") $Stage
Copy-Item (Join-Path $Root "docs\solana-payments-config.example.toml") $Stage

$cargoPlus = if ($Toolchain) { "+$Toolchain" } else { "" }

foreach ($name in $Plugins) {
    $dir = Join-Path $Root "plugins\$name"
    if (-not (Test-Path $dir)) { throw "Missing plugin: $dir" }
    Write-Host "`n======== $name ========" -ForegroundColor Cyan
    Push-Location $dir
    try {
        if (-not $SkipTests) {
            Write-Host "cargo $cargoPlus test"
            if ($cargoPlus) {
                & cargo $cargoPlus test
            } else {
                & cargo test
            }
            if ($LASTEXITCODE -ne 0) { throw "tests failed for $name" }
        }

        if (-not $SkipBuild) {
            Write-Host "cargo $cargoPlus build --target wasm32-wasip2 --release"
            if ($cargoPlus) {
                & cargo $cargoPlus build --target wasm32-wasip2 --release
            } else {
                & cargo build --target wasm32-wasip2 --release
            }
            if ($LASTEXITCODE -ne 0) { throw "wasm build failed for $name" }
        }

        $wasm = Get-ChildItem "target\wasm32-wasip2\release\*.wasm" -ErrorAction SilentlyContinue | Select-Object -First 1
        if (-not $wasm) { throw "no wasm artifact for $name (build first)" }
        Copy-Item $wasm.FullName -Destination (Join-Path $dir $wasm.Name) -Force
        Write-Host "Copied $($wasm.Name) -> plugin dir ($($wasm.Length) bytes)"

        $out = Join-Path $Stage $name
        New-Item -ItemType Directory -Path $out | Out-Null
        Copy-Item (Join-Path $dir "manifest.toml") $out
        Copy-Item (Join-Path $dir "README.md") $out
        Copy-Item (Join-Path $dir "LICENSE") $out
        Copy-Item (Join-Path $dir $wasm.Name) $out
        Write-Host "Staged $out"
    }
    finally {
        Pop-Location
    }
}

Write-Host "`nDone. Installable bundle: $Stage" -ForegroundColor Green
Get-ChildItem $Stage -Recurse | ForEach-Object {
    if (-not $_.PSIsContainer) {
        "{0}`t{1}" -f $_.Length, $_.FullName.Substring($Stage.Length + 1)
    }
}
