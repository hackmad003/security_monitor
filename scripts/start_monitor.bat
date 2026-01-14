@echo off
echo ============================================================
echo    Security Monitor - Command Line Interface
echo ============================================================
echo.

REM Change to project root directory
cd /d "%~dp0\.."

REM Check if in correct directory
if not exist "main.py" (
    echo ERROR: main.py not found!
    echo Please check the installation.
    pause
    exit /b 1
)

echo Select monitoring mode:
echo.
echo   1. Single Analysis (100 events)
echo   2. Real-time Monitoring (continuous)
echo   3. Multi-Target Check (one-time)
echo   4. View Statistics (last 7 days)
echo.

set /p choice="Enter your choice (1-4): "

if "%choice%"=="1" (
    echo.
    echo Starting single analysis...
    python main.py --mode single --events 100
) else if "%choice%"=="2" (
    echo.
    echo Starting real-time monitoring...
    echo Press Ctrl+C to stop
    python main.py --mode realtime --interval 60 --events 100
) else if "%choice%"=="3" (
    echo.
    echo Starting multi-target check...
    python main.py --mode multi
) else if "%choice%"=="4" (
    echo.
    echo Displaying statistics...
    python main.py --mode stats --days 7
) else (
    echo.
    echo Invalid choice!
)

echo.
pause
