# Run APIGuard Scanner Backend on Port 8000
$Host.UI.RawUI.WindowTitle = "APIGuard - Scanner Backend (Port 8000)"
Write-Host "Starting APIGuard Scanner Backend on http://127.0.0.1:8000..." -ForegroundColor Cyan
$projectRoot = Split-Path -Parent $PSScriptRoot
Set-Location "$projectRoot\backend"
$env:PYTHONPATH = "$projectRoot;$projectRoot\backend"
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
