# Run Secured Demo API on Port 8002
$Host.UI.RawUI.WindowTitle = "APIGuard - Secured Demo API (Port 8002)"
Write-Host "Starting Secured Demo API on http://127.0.0.1:8002..." -ForegroundColor Green
$projectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $projectRoot
$env:PYTHONPATH = "$projectRoot;$projectRoot\demo_api"
python -m demo_api.app.main --mode secure --port 8002
