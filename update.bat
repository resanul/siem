@echo off
setlocal enabledelayedexpansion
title OpenSOC Forge - 1-Click Git Update & Deploy
color 0A
cls

echo ================================================================================
echo   OpenSOC Forge -- 1-Click Universal Git Sync and Deploy
echo ================================================================================
echo.

echo [1/3] Pulling latest code locally from GitHub (master)...
where git >nul 2>nul
if %errorlevel% neq 0 (
    echo [WARN] Git is not found in PATH. Skipping local git pull...
) else (
    git pull origin master
    if %errorlevel% neq 0 (
        echo [WARN] Local git pull failed or has merge conflicts. Proceeding with VM sync...
    ) else (
        echo [OK] Local repository is up to date!
    )
)
echo.

echo [2/3] Connecting to Target VM (192.168.10.177) and updating services...
where python >nul 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] Python is required to run the automated deployer.
    echo Please ensure Python is installed and added to PATH.
    pause
    exit /b 1
)

python scripts\deploy_vm.py
if %errorlevel% neq 0 (
    echo.
    echo [ERROR] VM update failed! Please check VM network connectivity or SSH credentials.
    pause
    exit /b %errorlevel%
)

echo.
echo [3/3] Opening Web Console in default browser...
start http://192.168.10.177:7070/console/

echo.
echo ================================================================================
echo   SUCCESS: OpenSOC Forge is fully updated from Git and running!
echo   Web Console: http://192.168.10.177:7070/console/
echo ================================================================================
echo.
pause
