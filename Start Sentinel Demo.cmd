@echo off
setlocal
cd /d "%~dp0"

if not exist ".venv\Scripts\python.exe" (
  echo First-time setup: creating Sentinel's local Python environment...
  py -3 -m venv .venv
  if errorlevel 1 (
    echo Python 3 is required. Install Python, then run this launcher again.
    pause
    exit /b 1
  )
  .venv\Scripts\python.exe -m pip install -r requirements.txt
  if errorlevel 1 (
    echo Setup could not install the local packages. Check your connection and run this launcher again.
    pause
    exit /b 1
  )
)

.venv\Scripts\python.exe -m sentinel.demo_mode start %*
set "sentinel_exit_code=%ERRORLEVEL%"

if not "%sentinel_exit_code%"=="0" pause
endlocal & exit /b %sentinel_exit_code%
