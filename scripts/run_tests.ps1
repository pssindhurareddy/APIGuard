# Run full test suite with coverage
Write-Host "Executing APIGuard Automated Security and Detection Test Suite..." -ForegroundColor Cyan
$projectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $projectRoot
$env:PYTHONPATH = "$projectRoot;$projectRoot\backend;$projectRoot\demo_api"
python -m pytest "backend/tests" "demo_api/tests" -v
