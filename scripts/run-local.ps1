# Start the server locally on Windows. Reads .env (see .env.example) and OIC_CONFIG_FILE.
#   .\scripts\run-local.ps1
$ErrorActionPreference = "Stop"
Set-Location (Split-Path -Parent $PSScriptRoot)

if (-not (Test-Path ".venv")) {
    py -3 -m venv .venv
}
& ".\.venv\Scripts\python.exe" -m pip install -q -r requirements.txt
& ".\.venv\Scripts\python.exe" -m oic_mcp
