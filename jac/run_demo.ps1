param(
    [ValidateSet("all", "github", "slack")]
    [string]$Scenario = "all",
    [switch]$Pause,
    [string]$Output
)

$ErrorActionPreference = "Stop"
$JacRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Split-Path -Parent $JacRoot

$PythonCandidates = @(
    (Join-Path $JacRoot ".jac\venv\Scripts\python.exe"),
    (Join-Path $JacRoot ".venv\Scripts\python.exe"),
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
    throw "Python was not found. Run 'jac install' from the jac folder first."
}

$DemoArgs = @(
    (Join-Path $JacRoot "demo\hackathon_demo.py"),
    "--scenario",
    $Scenario
)
if ($Pause) {
    $DemoArgs += "--pause"
}
if ($Output) {
    $DemoArgs += @("--output", $Output)
}

& $Python @DemoArgs
exit $LASTEXITCODE
