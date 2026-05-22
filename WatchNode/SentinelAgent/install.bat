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
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%install.ps1" %*
set "EXIT_CODE=%ERRORLEVEL%"

if not "%EXIT_CODE%"=="0" (
    echo.
    echo Installer exited with code %EXIT_CODE%.
    echo Press any key to close this window...
    pause >nul
)
exit /b %EXIT_CODE%
