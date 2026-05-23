@echo off
REM install.bat - double-click wrapper for install.ps1
REM
REM Why this exists:
REM   .ps1 files open in Notepad when double-clicked or run from cmd.exe
REM   because Windows refuses to execute PowerShell scripts directly for
REM   security. This .bat file forwards to PowerShell explicitly, which
REM   bypasses that and triggers a UAC prompt via install.ps1's self-elevation.
REM
REM Usage:
REM   1. Double-click install.bat, OR
REM   2. From cmd:        install.bat
REM   3. From PowerShell: .\install.bat
REM
REM Optional arguments are forwarded to install.ps1. Examples:
REM   install.bat -ServerIP 192.168.100.24
REM   install.bat -ServerIP 192.168.100.24 -Token "my-token"
REM   install.bat -Uninstall

setlocal
set "SCRIPT_DIR=%~dp0"

REM Log everything to file so we can see what happened even if all windows close.
set "LOG_DIR=%ProgramData%\SentinelAgent\install-logs"
if not exist "%LOG_DIR%" mkdir "%LOG_DIR%" >nul 2>&1
set "LOG_FILE=%LOG_DIR%\install-%date:~-4%%date:~3,2%%date:~0,2%-%time:~0,2%%time:~3,2%%time:~6,2%.log"
set "LOG_FILE=%LOG_FILE: =0%"

echo === Sentinel Agent Installer ===
echo Log file: %LOG_FILE%
echo.

REM Forward to PowerShell and tee everything into the log file.
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command ^
  "& {& '%SCRIPT_DIR%install.ps1' %* *>&1 | Tee-Object -FilePath '%LOG_FILE%'; exit $LASTEXITCODE}"
set "EXIT_CODE=%ERRORLEVEL%"

echo.
if "%EXIT_CODE%"=="0" (
    echo [SUCCESS] Installer completed. Log saved to:
) else (
    echo [FAILED]  Installer exited with code %EXIT_CODE%. Log saved to:
)
echo   %LOG_FILE%
echo.
echo Press any key to close this window...
pause >nul
exit /b %EXIT_CODE%
