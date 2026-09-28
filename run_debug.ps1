<#
    run_debug.ps1 - launch a payload with CYB_DEBUG enabled and tail its log.

    The implant is a GUI-subsystem process, so it has no console: its dbg()
    output goes to a file, not stderr. Without this you get no feedback at all
    and a failed connection looks identical to a working one.

    Usage (from the folder containing the payload):
        .\run_debug.ps1
        .\run_debug.ps1 -Exe .\da.exe
        .\run_debug.ps1 -Exe .\da.exe -Timeout 30

    Press Ctrl+C to stop tailing. The payload keeps running; close it separately.
#>
[CmdletBinding()]
param(
    [string]$Exe,
    [int]$Timeout = 0,          # 0 = tail until you Ctrl+C
    [switch]$NoTail,
    [string]$LogPath            # defaults to $env:TEMP\cybdbg.log
)

$ErrorActionPreference = 'Stop'

function Resolve-Payload {
    param([string]$Hint)

    if ($Hint) {
        if (-not (Test-Path -LiteralPath $Hint)) {
            throw "not found: $Hint"
        }
        return (Resolve-Path -LiteralPath $Hint).Path
    }

    # An explicit name wins, so a renamed payload does not get shadowed by a
    # leftover payload.exe sitting next to it.
    foreach ($name in 'payload.exe', 'da.exe') {
        if (Test-Path -LiteralPath $name) { return (Resolve-Path -LiteralPath $name).Path }
    }

    $found = @(Get-ChildItem -Path $PSScriptRoot -Filter *.exe -File -ErrorAction SilentlyContinue)
    if ($found.Count -eq 1) { return $found[0].FullName }
    if ($found.Count -gt 1) {
        Write-Host "More than one .exe here, pick one with -Exe:" -ForegroundColor Yellow
        $found | ForEach-Object { Write-Host "    $($_.Name)" }
        throw 'ambiguous payload'
    }
    throw "no .exe found in $PSScriptRoot"
}

if (-not $LogPath) { $LogPath = Join-Path $env:TEMP 'cybdbg.log' }

$target = Resolve-Payload -Hint $Exe

# The implant appends to this file, so a stale log from a previous run would
# otherwise scroll past and be mistaken for current output.
if (Test-Path -LiteralPath $LogPath) {
    Remove-Item -LiteralPath $LogPath -Force
    Write-Host "cleared old log: $LogPath" -ForegroundColor DarkGray
}

$env:CYB_DEBUG = '1'
$env:CYB_DEBUG_LOG = $LogPath

Write-Host ''
Write-Host '  CYBERDEMONS payload debug launcher' -ForegroundColor Cyan
Write-Host "  payload : $target" -ForegroundColor Gray
Write-Host "  log     : $LogPath" -ForegroundColor Gray
Write-Host '  press Ctrl+C to stop tailing' -ForegroundColor DarkGray
Write-Host ''

$proc = Start-Process -FilePath $target -PassThru

if ($NoTail) {
    Write-Host "started (pid $($proc.Id)), not tailing." -ForegroundColor Green
    return
}

# Surface a dead-on-arrival payload instead of tailing an empty file forever.
$deadline = if ($Timeout -gt 0) { (Get-Date).AddSeconds($Timeout) } else { $null }
$shown = 0

while ($true) {
    Start-Sleep -Milliseconds 500

    if ($proc.HasExited -and -not (Test-Path -LiteralPath $LogPath)) {
        Write-Host ''
        Write-Host "payload exited immediately (code $($proc.ExitCode)) and wrote no log." -ForegroundColor Red
        Write-Host 'It probably never started - check SmartScreen / "Windows protected your PC".' -ForegroundColor Yellow
        break
    }

    if (Test-Path -LiteralPath $LogPath) {
        $all = @(Get-Content -LiteralPath $LogPath -Encoding UTF8 -ErrorAction SilentlyContinue)
        if ($all.Count -gt $shown) {
            # Print only what is new, so earlier lines are never reprinted as
            # the log grows.
            foreach ($line in $all[$shown..($all.Count - 1)]) {
                if ($line -match 'connect\(\) failed|handshake failed|feed failed|protocol violation|send failed|out of memory|seal refused') {
                    Write-Host $line -ForegroundColor Red
                } elseif ($line -match 'TCP connected|handshake ok|session ended') {
                    Write-Host $line -ForegroundColor Green
                } else {
                    Write-Host $line -ForegroundColor Gray
                }
            }
            $shown = $all.Count
        }
    }

    if ($proc.HasExited) {
        Write-Host ''
        Write-Host "payload exited (code $($proc.ExitCode))." -ForegroundColor Yellow
        Write-Host "final log: $LogPath" -ForegroundColor DarkGray
        break
    }

    if ($deadline -and (Get-Date) -gt $deadline) {
        Write-Host ''
        Write-Host "timeout after $Timeout s; payload still running." -ForegroundColor Yellow
        break
    }
}
