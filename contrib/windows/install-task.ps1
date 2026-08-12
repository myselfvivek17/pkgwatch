# Registers the pkgwatch agent as a Scheduled Task that starts at logon.
#
# A Scheduled Task rather than a Windows service on purpose: a service would
# pull in golang.org/x/sys/windows/svc, and the direct dependency budget has no
# room for a ninth. A logon task also runs as the user whose packages are being
# watched, which is what the inventory and credential checks actually need.
#
#   powershell -ExecutionPolicy Bypass -File contrib\windows\install-task.ps1
#
# ASCII only, deliberately. Windows PowerShell 5.1 reads a .ps1 with no byte
# order mark using the system ANSI code page, so a stray em dash in a comment
# becomes mojibake and the file fails to parse. An install script that breaks on
# the shell most people have is not much of an install script.
#
# Note: unsigned binaries trip SmartScreen and may be flagged by Defender.
# A security tool that gets quarantined by antivirus is dead on arrival -
# expect to add an exclusion, or an Authenticode certificate if this goes public.

param(
    [string]$BinaryPath = "$env:LOCALAPPDATA\pkgwatch\bin\pkgwatch.exe",
    [string]$TaskName   = "pkgwatch-agent"
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $BinaryPath)) {
    throw "pkgwatch.exe not found at $BinaryPath. Pass -BinaryPath to point at it."
}

$action = New-ScheduledTaskAction -Execute $BinaryPath -Argument "agent"
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME

# Repeat the logon trigger forever, every five minutes.
#
# This is not belt and braces, it is the only thing that restarts the agent
# after a clean exit. Windows restarts a task that FAILS; a task whose action
# exits 0 is a task that completed successfully, so nothing happens and the
# state stays "Ready" with LastTaskResult 0 - which reads as perfectly healthy
# in Task Scheduler while the gate is wide open. That is exactly how this agent
# was found down for seven hours.
#
# MultipleInstances defaults to IgnoreNew, so a repetition that fires while the
# agent is already running is discarded rather than starting a second one that
# would fight for the same ports.
$trigger.Repetition = (New-CimInstance -ClassName MSFT_TaskRepetitionPattern `
    -Namespace Root/Microsoft/Windows/TaskScheduler -ClientOnly `
    -Property @{ Interval = "PT5M"; Duration = ""; StopAtDurationEnd = $false })

# Never stop it for running too long or being on battery: a watchdog that quits
# after 72 hours is a watchdog you stop trusting. RestartCount covers a crash;
# the repetition above covers everything else.
$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -StartWhenAvailable `
    -ExecutionTimeLimit ([TimeSpan]::Zero) `
    -RestartCount 3 `
    -RestartInterval (New-TimeSpan -Minutes 1)

Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger `
    -Settings $settings -Description "pkgwatch supply-chain agent" -Force | Out-Null

Start-ScheduledTask -TaskName $TaskName

Write-Host "Registered and started '$TaskName'."
Write-Host "Health check: curl http://127.0.0.1:4875/health"
Write-Host "Remove with:  Unregister-ScheduledTask -TaskName $TaskName -Confirm:`$false"
