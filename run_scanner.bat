@echo off
title Network Scanner Daemon
echo ===================================================
echo   🔍 STARTING PROFESSIONAL NETWORK SCANNER TOOLKIT  
echo ===================================================
echo.
cd /d "%~dp0"
echo [1/2] Activating Python Virtual Environment...
call venv\Scripts\activate.bat
echo [2/2] Launching Streamlit Web Interface...
echo.
streamlit run ui.py
pause
