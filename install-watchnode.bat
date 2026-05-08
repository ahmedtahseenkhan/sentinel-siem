@echo off
REM install-watchnode.bat
REM Simple batch script to install WatchNode on a single Windows machine

setlocal enabledelayedexpansion

REM Configuration
set INSTALL_DIR=C:\Sentinel\WatchNode
set SERVER_IP=%1
set AGENT_NAME=%COMPUTERNAME%

if "%SERVER_IP%"=="" (
    echo Usage: install-watchnode.bat SERVER_IP
    echo Example: install-watchnode.bat 192.168.1.100
    exit /b 1
)

echo.
echo ========================================
echo Sentinel WatchNode Installation
echo ========================================
echo Server IP: %SERVER_IP%
echo Agent Name: %AGENT_NAME%
echo Install Dir: %INSTALL_DIR%
echo.

REM Create directory
if not exist "%INSTALL_DIR%" (
    mkdir "%INSTALL_DIR%"
    echo [OK] Created directory
) else (
    echo [OK] Directory already exists
)

REM Check if watchnode.exe exists in current directory
if not exist "watchnode.exe" (
    echo [ERROR] watchnode.exe not found in current directory
    echo Please copy watchnode.exe to the same folder as this script
    exit /b 1
)

REM Copy executable
copy watchnode.exe "%INSTALL_DIR%\watchnode.exe"
echo [OK] Copied watchnode.exe

REM Create agent.yaml
(
echo agent:
echo   id: ""
echo   name: "%AGENT_NAME%"
echo   labels:
echo     environment: production
echo     team: security
echo.
echo manager:
echo   url: "%SERVER_IP%:50051"
echo   tls: {}
echo.
echo collectors:
echo   system:
echo     enabled: true
echo     interval: "30s"
echo     metrics: ["cpu", "memory", "disk", "network", "processes"]
echo.
echo   process:
echo     enabled: true
echo     interval: "5s"
echo.
echo   network:
echo     enabled: true
echo     interval: "5s"
echo.
echo   logs:
echo     enabled: true
echo     sources:
echo       - type: eventlog
echo         channel: "Security"
echo         tags: ["security"]
) > "%INSTALL_DIR%\agent.yaml"
echo [OK] Created agent.yaml

REM Allow Windows Firewall for agent
netsh advfirewall firewall add rule name="SentinelWatchNode" dir=out action=allow protocol=tcp remoteport=50051 program="%INSTALL_DIR%\watchnode.exe" >nul 2>&1
echo [OK] Updated Windows Firewall

REM Create shortcut to run at startup (alternative to service)
set STARTUP_DIR=%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup
if not exist "%STARTUP_DIR%\start-watchnode.bat" (
    (
        echo @echo off
        echo cd "%INSTALL_DIR%"
        echo start watchnode.exe -c agent.yaml
    ) > "%STARTUP_DIR%\start-watchnode.bat"
    echo [OK] Created startup shortcut
)

echo.
echo ========================================
echo Installation Complete!
echo ========================================
echo.
echo To start the agent now, run:
echo   cd %INSTALL_DIR%
echo   watchnode.exe -c agent.yaml
echo.
echo To stop the agent, press Ctrl+C
echo.
echo The agent will auto-start on next reboot.
echo.
pause
