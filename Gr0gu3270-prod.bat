@echo off
title Gr0gu3270 - Production
echo [1/4] Killing previous Gr0gu3270 if running...
taskkill /f /im python.exe /fi "WINDOWTITLE eq Gr0gu3270*" >nul 2>&1
timeout /t 1 /nobreak >nul
echo [2/4] Activating Anaconda environment...
call "%USERPROFILE%\anaconda3\condabin\conda.bat" activate >nul 2>&1
echo [3/4] Launching Web UI + Quick3270...
start http://localhost:1337
timeout /t 1 /nobreak >nul
start "" "C:\PATH\TO\Quick3270.exe"
echo [4/4] Starting Gr0gu3270 proxy...
echo.
echo   Web UI:   http://localhost:1337
echo   Terminal: Quick3270 on localhost:3271
echo.
python "%~dp0Gr0gu3270.py" MAINFRAME_HOST 23 -n prod -p 3271 --web-port 1337
pause
