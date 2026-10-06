$ErrorActionPreference = "Stop"
$repoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$exePath = Join-Path $repoRoot "dist\Sentinal.exe"
if (-not (Test-Path -LiteralPath $exePath)) { throw "Build Sentinal.exe first." }
$smokeRoot = Join-Path $repoRoot "build\release-smoke"
New-Item -ItemType Directory -Path $smokeRoot -Force | Out-Null
$logPath = Join-Path $smokeRoot "logs\events.jsonl"
if (Test-Path -LiteralPath $logPath) { Remove-Item -LiteralPath $logPath }
$app = Start-Process -FilePath $exePath -WorkingDirectory $smokeRoot -WindowStyle Hidden -PassThru
$deadline = [DateTime]::UtcNow.AddSeconds(45)
$window = $null
do {
    Start-Sleep -Milliseconds 500
    # Onefile bootloader launches a child; find the actual native GUI process.
    $window = Get-Process -Name Sentinal -ErrorAction SilentlyContinue |
        Where-Object { $_.MainWindowHandle -ne 0 -and $_.StartTime -ge $app.StartTime.AddSeconds(-1) } |
        Select-Object -First 1
    $app.Refresh()
    if ($app.HasExited -and -not $window) { throw "Executable exited before opening its GUI." }
} until (($window -and (Test-Path -LiteralPath $logPath)) -or [DateTime]::UtcNow -gt $deadline)
if (-not $window -or -not (Test-Path -LiteralPath $logPath)) { throw "GUI/monitoring startup timed out." }
$records = @(Get-Content -LiteralPath $logPath | ForEach-Object { $_ | ConvertFrom-Json })
if (-not ($records | Where-Object { $_.event_type -in @("NEW", "NEW_LISTENER") })) {
    throw "No live socket events recorded."
}
if (-not $window.CloseMainWindow()) { throw "Could not send normal window close." }
if (-not $window.WaitForExit(15000) -or -not $app.WaitForExit(15000)) { throw "Clean shutdown timed out." }
if ($app.ExitCode -ne 0) { throw "Executable exited with $($app.ExitCode)." }
Write-Output "EXE smoke passed: native GUI window, monitoring started ($($records.Count) JSONL events), normal close, exit 0."
