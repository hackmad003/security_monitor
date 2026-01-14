@echo off
echo ============================================================
echo    Security Monitor Dashboard Launcher
echo ============================================================
echo.

REM Change to project root directory
cd /d "%~dp0\.."

REM Check if in correct directory
if not exist "security_monitor\dashboard\web_dashboard_secure.py" (
    echo ERROR: Dashboard files not found!
    echo Please run this script from the scripts directory.
    pause
    exit /b 1
)

echo Starting Web Dashboard...
echo.
echo Dashboard will be available at:
echo   http://localhost:8081
echo.
echo API Documentation at:
echo   http://localhost:8081/docs
echo.
echo Press Ctrl+C to stop the server
echo.
echo ============================================================
echo.

python -m security_monitor.dashboard.web_dashboard_secure

pause
