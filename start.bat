@echo off
title Our Secret - Cybersecurity Platform
cd /d "%~dp0"

echo ===================================================================
echo     OUR SECRET - Defense-Grade Image Steganography Tool
echo ===================================================================
echo.
echo [*] Checking database and sample data...
python -c "from seed_data import seed_database; seed_database()"

echo.
echo [*] Opening application in your browser at http://127.0.0.1:5000 ...
start http://127.0.0.1:5000

echo.
echo [*] Default Login Credentials:
echo     - Admin:     admin    / Admin@123456
echo     - Operator:  testuser / User@123456
echo     - Operative: agent2   / User@123456
echo.
echo [*] Server is running below. Do not close this window!
echo     (Press Ctrl+C to stop the server)
echo ===================================================================
echo.

python run.py
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [!] Server encountered an error.
    pause
)

