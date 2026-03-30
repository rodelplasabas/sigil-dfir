@echo off
title SIGIL DFIR - Launcher
echo.
echo  ========================================
echo   SIGIL - DFIR Compromise Assessment Tool
echo   v2.1.0
echo  ========================================
echo.

:: Clear Python bytecode cache to prevent stale code issues
echo [*] Clearing Python cache...
cd /d %~dp0backend
if exist "__pycache__" rd /s /q "__pycache__"
if exist "detection\__pycache__" rd /s /q "detection\__pycache__"
if exist "parser\__pycache__" rd /s /q "parser\__pycache__"
cd /d %~dp0
echo     Done.
echo.

:: Record PIDs of any existing python/node on these ports so we don't kill them later
:: (in case user has other projects running)

:: Start the Python backend in a new window
echo [*] Starting SIGIL Backend on port 8001...
start "SIGIL Backend" cmd /c "cd /d %~dp0backend && python -m uvicorn main:app --reload --port 8001"

:: Give backend a moment to start
timeout /t 3 /nobreak >nul

:: Start the frontend in a new window
echo [*] Starting SIGIL Frontend on port 5173...
start "SIGIL Frontend" cmd /c "cd /d %~dp0frontend && npm run dev"

:: Wait for frontend to be ready
timeout /t 3 /nobreak >nul

echo.
echo [+] SIGIL is running!
echo     Frontend: http://localhost:5173
echo     Backend:  http://localhost:8001
echo.
echo [*] Press any key to stop SIGIL...
pause >nul

echo.
echo [*] Shutting down SIGIL...

:: 1. Kill cmd windows by title
taskkill /FI "WINDOWTITLE eq SIGIL Backend*" /F >nul 2>&1
taskkill /FI "WINDOWTITLE eq SIGIL Frontend*" /F >nul 2>&1

:: 2. Kill any process listening on port 8001 (uvicorn + reloader workers)
for /f "tokens=5" %%a in ('netstat -aon 2^>nul ^| findstr ":8001" ^| findstr "LISTENING"') do (
    if not "%%a"=="0" taskkill /PID %%a /T /F >nul 2>&1
)

:: 3. Kill any process listening on port 5173 (vite dev server)
for /f "tokens=5" %%a in ('netstat -aon 2^>nul ^| findstr ":5173" ^| findstr "LISTENING"') do (
    if not "%%a"=="0" taskkill /PID %%a /T /F >nul 2>&1
)

:: 4. Small delay then verify
timeout /t 1 /nobreak >nul

:: Check if ports are freed
set "STILL_RUNNING=0"
netstat -aon 2>nul | findstr ":8001.*LISTENING" >nul 2>&1 && set "STILL_RUNNING=1"
netstat -aon 2>nul | findstr ":5173.*LISTENING" >nul 2>&1 && set "STILL_RUNNING=1"

if "%STILL_RUNNING%"=="1" (
    echo [!] Some processes may still be running. Forcing cleanup...
    for /f "tokens=5" %%a in ('netstat -aon 2^>nul ^| findstr ":8001" ^| findstr "LISTENING"') do taskkill /PID %%a /T /F >nul 2>&1
    for /f "tokens=5" %%a in ('netstat -aon 2^>nul ^| findstr ":5173" ^| findstr "LISTENING"') do taskkill /PID %%a /T /F >nul 2>&1
)

echo [+] SIGIL stopped.
timeout /t 2 >nul