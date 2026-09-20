param(
    [string]$InputDir = ".\datasets\ror_dataset_flat",
    [string]$OutputDir = ".\results\slither_ror_dataset_flat"
)

$ErrorActionPreference = "Continue"
$fail = Join-Path $OutputDir "slither_failures.txt"
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$SolcSelect = Join-Path $RepoRoot "venv\Scripts\solc-select.exe"
$Slither = Join-Path $RepoRoot "venv\Scripts\slither.exe"
$Solc = Join-Path $RepoRoot "venv\Scripts\solc.exe"

New-Item -ItemType Directory -Force $OutputDir | Out-Null
Remove-Item (Join-Path $OutputDir "*.json") -ErrorAction SilentlyContinue
Remove-Item $fail -ErrorAction SilentlyContinue

function Use-SolcForPragma {
    param([string]$PragmaLine)

    if ($PragmaLine -match "0\.5\.16") {
        & $SolcSelect use 0.5.17 | Out-Null
    } elseif ($PragmaLine -match "0\.8\.20") {
        & $SolcSelect use 0.8.20 | Out-Null
    } elseif ($PragmaLine -match "0\.8\.17") {
        & $SolcSelect use 0.8.17 | Out-Null
    } elseif ($PragmaLine -match "0\.8") {
        & $SolcSelect use 0.8.20 | Out-Null
    } else {
        & $SolcSelect use 0.8.17 | Out-Null
    }
}

$files = @(Get-ChildItem $InputDir -Filter *.sol | Sort-Object Name)
$total = $files.Count
$index = 0

foreach ($file in $files) {
    $index += 1
    $name = [IO.Path]::GetFileNameWithoutExtension($file.Name)
    $json = Join-Path $OutputDir "$name.json"
    $pragma = (Select-String -Path $file.FullName -Pattern "pragma solidity" | Select-Object -First 1).Line

    Use-SolcForPragma $pragma

    Write-Host "[$index/$total] run $($file.Name) [$pragma]"

    & $Slither $file.FullName `
        --detect reentrancy-eth,reentrancy-no-eth,reentrancy-benign,reentrancy-events `
        --fail-none `
        --solc $Solc `
        --json $json

    if ($LASTEXITCODE -ne 0) {
        Add-Content $fail $file.Name
        Remove-Item $json -ErrorAction SilentlyContinue
        Write-Host "    failed"
    }
}

$count = @(Get-ChildItem $OutputDir -Filter *.json -ErrorAction SilentlyContinue).Count
Write-Host "Done. JSON count: $count / $total"
if (Test-Path $fail) {
    Write-Host "Failures saved to $fail"
}
