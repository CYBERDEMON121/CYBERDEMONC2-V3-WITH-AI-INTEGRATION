@echo off
REM ===========================================================================
REM  run_debug.bat - double-click to run the payload with CYB_DEBUG enabled
REM  and watch its log in this window.
REM
REM  Keep this file in the same folder as the payload .exe.
REM  The PowerShell execution policy blocks .ps1 by default on many systems, so
REM  this launcher passes -ExecutionPolicy Bypass for this one process only.
REM ===========================================================================
setlocal

cd /d "%~dp0"

where powershell >nul 2>&1
if errorlevel 1 (
    echo [x] PowerShell not found on PATH.
    echo     Windows PowerShell ships with Windows; try:
    echo       C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
    pause
    exit /b 1
)

REM Drop a drag-and-dropped .exe onto this .bat to target it specifically.
set "TARGET=%~1"

if "%TARGET%"=="" (
    powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0run_debug.ps1"
) else (
    powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0run_debug.ps1" -Exe "%TARGET%"
)

echo.
echo [i] Log kept at: %TEMP%\cybdbg.log
echo     ^> type "%TEMP%\cybdbg.log"
pause
