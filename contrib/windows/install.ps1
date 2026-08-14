# Install pkgwatch on Windows and leave it running.
#
#   powershell -ExecutionPolicy Bypass -File contrib\windows\install.ps1
#   powershell -ExecutionPolicy Bypass -File contrib\windows\install.ps1 -BinaryPath C:\path\pkgwatch.exe
#   powershell -ExecutionPolicy Bypass -File contrib\windows\install.ps1 -NoService
#
# There are no published releases yet, so nothing is downloaded: this builds
# from the checkout it is run in, or installs a binary you point it at. A
# supply-chain tool whose installer fetched an unsigned build over the network
# would be a poor advertisement for itself.
#
# ASCII only, deliberately, matching install-task.ps1: Windows PowerShell 5.1
# reads a .ps1 with no byte order mark using the system ANSI code page, so a
# stray em dash in a comment becomes mojibake and the file fails to parse.

param(
    [string]$BinaryPath = "",
    [switch]$NoService,
    [string]$InstallDir = "$env:LOCALAPPDATA\pkgwatch\bin"
)

$ErrorActionPreference = "Stop"

# $PSScriptRoot is contrib\windows, so the repo root is two directories up.
$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)

# ---------------------------------------------------------------- the binary

if ($BinaryPath -ne "") {
    if (-not (Test-Path $BinaryPath)) { throw "no such file: $BinaryPath" }
    $source = $BinaryPath
} else {
    if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
        throw "Go is not installed, so there is nothing to build from. Install Go, or build elsewhere and pass -BinaryPath."
    }
    $source = Join-Path $env:TEMP "pkgwatch-install.exe"
    Write-Host "building from $repoRoot"
    Push-Location $repoRoot
    try {
        $env:CGO_ENABLED = "0"
        & go build -trimpath -ldflags="-s -w" -o $source ./cmd/pkgwatch
        if ($LASTEXITCODE -ne 0) { throw "go build failed" }
    } finally {
        Pop-Location
    }
}

New-Item -ItemType Directory -Force $InstallDir | Out-Null
$target = Join-Path $InstallDir "pkgwatch.exe"

# A running agent holds its own executable open, so the copy fails while the
# task is up. Stop it first and start it again below - the same dance the
# documented deploy uses.
$taskName = "pkgwatch-agent"
$existing = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
if ($existing) {
    Write-Host "stopping the running task first"
    try { Stop-ScheduledTask -TaskName $taskName } catch {}
    Start-Sleep -Milliseconds 1500
    Get-Process pkgwatch -ErrorAction SilentlyContinue | Stop-Process -Force
    Start-Sleep -Milliseconds 500
}

Copy-Item $source $target -Force
if ($source -like "*pkgwatch-install.exe") { Remove-Item $source -Force }
Write-Host "installed $target"

if ($NoService) {
    Write-Host ""
    Write-Host "Skipped the service. Start it with: $target agent"
    exit 0
}

# --------------------------------------------------------------- the service

& (Join-Path $PSScriptRoot "install-task.ps1") -BinaryPath $target -TaskName $taskName

# ------------------------------------------------------------------ verified

# Registered is not serving, and this project has been bitten by exactly that:
# a task reading Ready with LastTaskResult 0 while the gate had been down for
# seven hours. Ask the socket.
Start-Sleep -Seconds 4
& $target health
if ($LASTEXITCODE -ne 0) {
    Write-Host ""
    Write-Host "The task was registered but nothing is answering /health."
    Write-Host "Look at what it did:"
    Write-Host "  Get-ScheduledTaskInfo -TaskName $taskName"
    exit 1
}

Write-Host ""
Write-Host "Next:"
Write-Host "  pkgwatch scan                     take the first inventory"
Write-Host "  pkgwatch sync --file <bundle>     install an advisory bundle"
Write-Host "  pkgwatch shell-init               gate npm and pip in this shell"
Write-Host ""
Write-Host "NOTE: $InstallDir may not be on your PATH. Add it if 'pkgwatch' is not found."
