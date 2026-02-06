@echo off
:: ============================================================================
:: SYSTEM CLEANER PRO - Launcher
:: Auto-elevates to Administrator and launches the PowerShell engine
:: Double-click to run. No manual right-click needed.
:: ============================================================================

:: Check for Admin privileges
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo Requesting Administrator privileges...
    powershell -Command "Start-Process -Verb RunAs -FilePath '%~f0' -ArgumentList '%*'"
    exit /b
)

:: Set window title
title System Cleaner Pro

:: Get the directory where this .bat file lives
set "SCRIPT_DIR=%~dp0"

:: Launch the PowerShell engine
:: -ExecutionPolicy Bypass: allows the script to run without changing system policy
:: -NoProfile: skips loading user profile for faster startup
:: -File: runs the .ps1 script
powershell.exe -ExecutionPolicy Bypass -NoProfile -File "%SCRIPT_DIR%SystemCleaner.ps1" %*

:: Keep window open if there was an error
if %errorLevel% neq 0 (
    echo.
    echo  [ERROR] The cleaner encountered an issue. See above for details.
    pause
)

exit /b
