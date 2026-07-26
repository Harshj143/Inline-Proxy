param(
    [int]$Port = 8123,
    [string]$Audit = "audit.log",
    [string]$Policy = "policies.json"
)

$ErrorActionPreference = "Stop"
$DashboardRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Split-Path -Parent $DashboardRoot

$PythonCandidates = @(
    (Join-Path $RepoRoot "jac\.jac\venv\Scripts\python.exe"),
    (Join-Path $RepoRoot ".venv\Scripts\python.exe"),
    (Join-Path $RepoRoot "references\Inline-Proxy-Public\Jac files\jac\.venv\Scripts\python.exe")
)

$Python = $PythonCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $Python) {
    $PythonCommand = Get-Command python -ErrorAction SilentlyContinue
    if ($PythonCommand) {
        $Python = $PythonCommand.Source
    }
}
if (-not $Python) {
    throw "Python was not found. Install Python 3.12 or run 'jac install' first."
}

Set-Location $RepoRoot
Write-Host ""
Write-Host "Attack Lab is ready at http://localhost:$Port" -ForegroundColor Green
Write-Host "Press Ctrl+C when the presentation is finished." -ForegroundColor DarkGray
Write-Host ""

& $Python "dashboard\server.py" --audit $Audit --policy $Policy --port $Port
exit $LASTEXITCODE
