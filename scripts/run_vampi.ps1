# Run the bundled third-party VAmPI benchmark API.
# Usage: run_vampi.ps1 -Mode vulnerable|secure   (ports 8003 / 8004)
param([ValidateSet("vulnerable", "secure")][string]$Mode = "vulnerable")
$port = if ($Mode -eq "vulnerable") { 8003 } else { 8004 }
$Host.UI.RawUI.WindowTitle = "APIGuard - VAmPI $Mode (Port $port)"
Write-Host "Starting third-party VAmPI ($Mode) on http://127.0.0.1:$port..." -ForegroundColor Magenta
$projectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $projectRoot
python third_party\run_vampi.py --mode $Mode --port $port
