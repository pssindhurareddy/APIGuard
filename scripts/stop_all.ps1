# Stop all APIGuard services running on ports 8000, 8001, 8002, 8003, 8004, 5173
Write-Host "Stopping all APIGuard services..." -ForegroundColor Yellow

$ports = @(8000, 8001, 8002, 8003, 8004, 5173)
foreach ($port in $ports) {
    $conns = Get-NetTCPConnection -LocalPort $port -ErrorAction SilentlyContinue
    if ($conns) {
        $pids = $conns | Select-Object -ExpandProperty OwningProcess -Unique
        foreach ($p in $pids) {
            try {
                Stop-Process -Id $p -Force -ErrorAction SilentlyContinue
                Write-Host "Killed process $p on port $port" -ForegroundColor Green
            } catch {
                # ignore
            }
        }
    }
}
Write-Host "All APIGuard ports cleared." -ForegroundColor Green
