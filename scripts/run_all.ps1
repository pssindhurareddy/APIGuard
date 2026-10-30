# Launch APIGuard: demo APIs (8001/8002), VAmPI benchmark (8003/8004), and the
# scanner backend on 8000, which also serves the dashboard.
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  Launching APIGuard Framework" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

$scriptDir = $PSScriptRoot

# Clean up any existing instances on ports 8000, 8001, 8002, 5173
$ports = @(8000, 8001, 8002, 8003, 8004, 5173)
foreach ($port in $ports) {
    $conns = Get-NetTCPConnection -LocalPort $port -ErrorAction SilentlyContinue
    if ($conns) {
        $pids = $conns | Select-Object -ExpandProperty OwningProcess -Unique
        foreach ($p in $pids) {
            Stop-Process -Id $p -Force -ErrorAction SilentlyContinue
        }
    }
}
Start-Sleep -Seconds 1

Write-Host "[1/5] Starting Vulnerable Demo API (Port 8001)..." -ForegroundColor Yellow
Start-Process powershell -ArgumentList "-NoExit", "-ExecutionPolicy", "Bypass", "-Command", "& '$scriptDir\run_vulnerable_api.ps1'"

Start-Sleep -Seconds 1

Write-Host "[2/5] Starting Secured Demo API (Port 8002)..." -ForegroundColor Green
Start-Process powershell -ArgumentList "-NoExit", "-ExecutionPolicy", "Bypass", "-Command", "& '$scriptDir\run_secure_api.ps1'"

Start-Sleep -Seconds 1

Write-Host "[3/5] Starting third-party VAmPI - vulnerable (Port 8003)..." -ForegroundColor Magenta
Start-Process powershell -ArgumentList "-NoExit", "-ExecutionPolicy", "Bypass", "-Command", "& '$scriptDir\run_vampi.ps1' -Mode vulnerable"

Start-Sleep -Seconds 1

Write-Host "[4/5] Starting third-party VAmPI - secure mode (Port 8004)..." -ForegroundColor Magenta
Start-Process powershell -ArgumentList "-NoExit", "-ExecutionPolicy", "Bypass", "-Command", "& '$scriptDir\run_vampi.ps1' -Mode secure"

Start-Sleep -Seconds 1

Write-Host "[5/5] Starting APIGuard Scanner Backend + Dashboard (Port 8000)..." -ForegroundColor Cyan
Start-Process powershell -ArgumentList "-NoExit", "-ExecutionPolicy", "Bypass", "-Command", "& '$scriptDir\run_backend.ps1'"

Start-Sleep -Seconds 1

Write-Host "`nWaiting for the scanner backend to come up..." -ForegroundColor Green
$ready = $false
for ($i = 0; $i -lt 40; $i++) {
    try {
        Invoke-WebRequest -Uri "http://127.0.0.1:8000/api/health" -UseBasicParsing -TimeoutSec 2 | Out-Null
        $ready = $true; break
    } catch { Start-Sleep -Milliseconds 500 }
}
if ($ready) {
    Write-Host "Dashboard ready: http://127.0.0.1:8000" -ForegroundColor Green
} else {
    Write-Host "Backend did not respond yet - check the 'Backend' window for errors, then open http://127.0.0.1:8000" -ForegroundColor Red
}
Start-Process "http://127.0.0.1:8000"
