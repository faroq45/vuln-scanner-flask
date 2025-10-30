@echo off
REM Production Deployment Script for Windows
REM Uses Waitress WSGI Server

echo ====================================================================
echo   Vulnerability Scanner - Production Mode
echo ====================================================================
echo.

REM Activate virtual environment if it exists
if exist "env\Scripts\activate.bat" (
    call env\Scripts\activate.bat
    echo Virtual environment activated
) else (
    echo Warning: No virtual environment found
)

echo.
echo Starting Waitress WSGI Server...
echo Press CTRL+C to stop the server
echo.

REM Start with Waitress
python run_waitress.py

pause
