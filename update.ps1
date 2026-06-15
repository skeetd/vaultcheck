# Pull the latest vaultcheck + vulnscan and refresh dependencies.
#     powershell -ExecutionPolicy Bypass -File .\update.ps1
$ErrorActionPreference = "Stop"

$vault = $PSScriptRoot
$vuln  = Join-Path (Split-Path $vault -Parent) "vulnscan"

Write-Host "==> pulling vaultcheck"
git -C $vault pull
if (Test-Path $vuln) {
    Write-Host "==> pulling vulnscan"
    git -C $vuln pull
}

$py = Join-Path $vault ".venv\Scripts\python.exe"
if (Test-Path $py) {
    & $py -m pip install -q -r (Join-Path $vault "requirements.txt")
    if (Test-Path $vuln) { & $py -m pip install -q -r (Join-Path $vuln "requirements.txt") }
}
Write-Host "Up to date."
