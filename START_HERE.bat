@echo off
REM ========================================
REM Security Monitor - Quick Start Script
REM ========================================

echo.
echo ====================================================================
echo         Security Monitor Dashboard - Secure Version
echo ====================================================================
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python is not installed or not in PATH
    echo Please install Python 3.8 or higher from https://www.python.org/
    pause
    exit /b 1
)

echo [OK] Python found
echo.

REM Check if dependencies are installed
echo Checking dependencies...
python -c "import fastapi" >nul 2>&1
if errorlevel 1 (
    echo [!] Dependencies not installed. Installing now...
    echo.
    pip install -r requirements.txt
    if errorlevel 1 (
        echo [ERROR] Failed to install dependencies
        pause
        exit /b 1
    )
    echo.
    echo [OK] Dependencies installed
) else (
    echo [OK] Dependencies found
)

echo.
echo ====================================================================
echo Starting Secure Dashboard...
echo ====================================================================
echo.
echo Dashboard will be available at:
echo   - Main Dashboard: http://localhost:8081
echo   - API Documentation: http://localhost:8081/docs
echo.
echo Default Login:
echo   - Username: admin
echo   - Password: ChangeMe123! (change this immediately!)
echo.
echo Press Ctrl+C to stop the server
echo ====================================================================
echo.

REM Change to parent directory if we're in scripts folder
cd /d "%~dp0\.."

REM Start the secure dashboard
python scripts\start_dashboard_simple.py

pause
