# Run APIGuard Frontend on Port 5173
$Host.UI.RawUI.WindowTitle = "APIGuard - Frontend (Port 5173)"
Write-Host "Starting APIGuard React Frontend on http://127.0.0.1:5173..." -ForegroundColor Cyan
$projectRoot = Split-Path -Parent $PSScriptRoot
Set-Location "$projectRoot\frontend"
npm run dev -- --host 127.0.0.1
