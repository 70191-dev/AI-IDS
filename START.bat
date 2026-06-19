@echo off
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo.
    echo *** WARNING: START.bat is NOT running as administrator. ***
    echo *** netsh firewall add/delete will FAIL in the API. ***
    echo *** Close this window, right-click START.bat, "Run as administrator", and try again. ***
    echo.
    pause
    exit /b 1
)
echo [START.bat] Running elevated. Proceeding...
title AI-IDS Intrusion Detection System
cd /d "%~dp0"

echo.
echo   AI-IDS Intrusion Detection System
echo   ===================================
echo.

:: ── Step 1: Virtual environment ──
if exist ".venv\Scripts\python.exe" goto :venv_ok
echo [1/3] Creating virtual environment...
python -m venv .venv
if errorlevel 1 goto :no_python
echo       Done.
goto :check_deps

:venv_ok
echo [1/3] Virtual environment ... OK

:check_deps
:: ── Step 2: Dependencies ──
".venv\Scripts\python.exe" -c "import sklearn, pandas, joblib, fastapi, streamlit, plotly" 2>nul
if not errorlevel 1 goto :deps_ok
echo [2/3] Installing dependencies (first time only)...
".venv\Scripts\python.exe" -m pip install --upgrade pip >nul 2>&1
".venv\Scripts\pip.exe" install -r env\requirements.txt
if errorlevel 1 goto :deps_fail
:: Verify
".venv\Scripts\python.exe" -c "import sklearn, pandas, joblib, fastapi, streamlit, plotly" 2>nul
if errorlevel 1 goto :deps_fail
echo       Done.
goto :check_models

:deps_ok
echo [2/3] Dependencies ......... OK

:check_models
:: ── Step 3: Models ──
if exist "models\model_meta.json" goto :models_ok
echo [3/3] Generating training data and building models...
".venv\Scripts\python.exe" src\data\mock_data.py
".venv\Scripts\python.exe" src\models\train.py
if not exist "models\model_meta.json" goto :train_fail
echo       Done.
goto :launch

:models_ok
echo [3/3] Models ............... OK

:launch
echo.
echo   Launching services...
echo     - FastAPI backend     (port 8000)
echo     - Traffic simulator   (replay)
echo     - Streamlit dashboard (port 8501)
echo     - Desktop window      (pywebview, opens after dashboard is up)
echo.
echo   The SOC dashboard will open in a native desktop window.
echo   Browser fallback: http://localhost:8501
echo   Close this console window to stop everything.
echo.
REM DEV/LAB ONLY: allows blocking the Kali attacker on the private subnet 192.168.142.0/24. Remove in production.
set MITIGATION_ALLOW_PRIVATE=true
".venv\Scripts\python.exe" launch.py
goto :end

:no_python
echo.
echo   ERROR: Python not found!
echo   Download from: https://www.python.org/downloads/
echo   Make sure "Add Python to PATH" is checked during install.
pause
goto :end

:deps_fail
echo.
echo   ERROR: Failed to install dependencies.
echo   Try manually: .venv\Scripts\pip.exe install -r env\requirements.txt
pause
goto :end

:train_fail
echo.
echo   ERROR: Model training failed. Check the errors above.
pause
goto :end

:end
