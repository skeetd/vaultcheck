# One-shot setup for vaultcheck + vulnscan on a new Windows PC.
# Run from inside the cloned vaultcheck folder:
#     powershell -ExecutionPolicy Bypass -File .\setup.ps1
$ErrorActionPreference = "Stop"

$vault  = $PSScriptRoot
$parent = Split-Path $vault -Parent
$vuln   = Join-Path $parent "vulnscan"

Write-Host "==> vaultcheck: $vault"

# 1. Clone vulnscan (repo name: norsec) next to vaultcheck, if not already there.
if (-not (Test-Path $vuln)) {
    Write-Host "==> cloning vulnscan -> $vuln"
    git clone https://github.com/skeetd/norsec.git $vuln
} else {
    Write-Host "==> vulnscan already present: $vuln"
}

# 2. One shared virtualenv, both requirement sets (so vulnscan can import vaultcheck).
$venv = Join-Path $vault ".venv"
if (-not (Test-Path $venv)) { python -m venv $venv }
$py = Join-Path $venv "Scripts\python.exe"
& $py -m pip install --upgrade pip
& $py -m pip install -r (Join-Path $vault "requirements.txt")
& $py -m pip install -r (Join-Path $vuln  "requirements.txt")

# 3. Point vulnscan's repo-audit at THIS vaultcheck (works on any username/path).
[Environment]::SetEnvironmentVariable("VAULTCHECK_DIR", $vault, "User")
Write-Host "==> set VAULTCHECK_DIR = $vault (user env)"

# 4. Create .env from the template if missing.
$envFile = Join-Path $vault ".env"
$tmpl    = Join-Path $vault ".env.example"
if ((-not (Test-Path $envFile)) -and (Test-Path $tmpl)) {
    Copy-Item $tmpl $envFile
    Write-Host "==> created .env from .env.example"
}

Write-Host ""
Write-Host "Done. Next:"
Write-Host "  1) Edit $envFile with your tokens (GITHUB_TOKEN, ADMIN_PASSWORD, SECRET_KEY, ...)"
Write-Host "  2) Open a NEW terminal (so VAULTCHECK_DIR is loaded), then:"
Write-Host "       .\.venv\Scripts\Activate.ps1"
Write-Host "       python run.py scan examples\vulnerable-demo --phase code --phase secrets"
Write-Host "       cd ..\vulnscan; python run.py audit ..\vaultcheck\examples\vulnerable-demo --phase code"
Write-Host ""
Write-Host "Later, to sync this PC with new changes:  .\update.ps1"
