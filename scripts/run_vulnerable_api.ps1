# Run Vulnerable Demo API on Port 8001
$Host.UI.RawUI.WindowTitle = "APIGuard - Vulnerable Demo API (Port 8001)"
Write-Host "Starting Vulnerable Demo API on http://127.0.0.1:8001..." -ForegroundColor Yellow
$projectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $projectRoot
$env:PYTHONPATH = "$projectRoot;$projectRoot\demo_api"
python -m demo_api.app.main --mode vulnerable --port 8001
