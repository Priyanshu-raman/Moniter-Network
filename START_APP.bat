@echo off
set PYTHON=C:\Users\priya\miniconda3\envs\networkk\python.exe

echo ==========================================
echo   Monitor OS - Local Server Startup
echo ==========================================
echo.

echo [1/2] Starting Flask API on port 5000...
start "Flask API" cmd /k "%PYTHON% app.py"

timeout /t 2 /nobreak >nul

echo [2/2] Starting Django on port 8080...
start "Django Server" cmd /k "%PYTHON% manage.py runserver"

timeout /t 4 /nobreak >nul

echo.
echo Both servers started!
echo Opening browser...
start http://127.0.0.1:8080

echo.
echo Press any key to close this window...
pause >nul
