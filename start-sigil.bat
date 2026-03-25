@echo off
title SIGIL DFIR - Launcher
echo.
echo  ========================================
echo   SIGIL - DFIR Compromise Assessment Tool
echo  ========================================
echo.

:: Start the Python backend in a new window
echo [*] Starting EVTX Parser Backend on port 8001...
start "SIGIL Backend" cmd /k "cd /d %~dp0backend && python -m uvicorn main:app --reload --port 8001"

:: Give backend a moment to start
timeout /t 2 /nobreak >nul

:: Start the frontend in a new window
echo [*] Starting SIGIL Frontend...
start "SIGIL Frontend" cmd /k "cd /d %~dp0frontend && npm run dev"

:: Wait for frontend to be ready
timeout /t 3 /nobreak >nul

echo.
echo [+] SIGIL is running!
echo     Frontend: http://localhost:5173
echo     Backend:  http://localhost:8001
echo.
echo [*] Close this window or press any key to stop both services.
pause >nul

:: Kill both processes when this window is closed
taskkill /FI "WINDOWTITLE eq SIGIL Backend*" /F >nul 2>&1
taskkill /FI "WINDOWTITLE eq SIGIL Frontend*" /F >nul 2>&1
