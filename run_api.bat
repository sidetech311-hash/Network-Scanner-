@echo off
title Network Scanner REST API Server
echo ===================================================
echo   🔌 STARTING NETWORK SCANNER REST API SERVER (FASTAPI)
echo ===================================================
echo.
cd /d "%~dp0"
echo [1/2] Activating Python Virtual Environment...
call venv\Scripts\activate.bat
echo [2/2] Launching Uvicorn Server...
echo.
echo API will be live at: http://127.0.0.1:8000
echo API docs available at: http://127.0.0.1:8000/docs
echo.
uvicorn api:app --reload --host 127.0.0.1 --port 8000
pause
