@echo off
setlocal
rem AdLeak Detector - local Windows launcher.
rem First run: creates .venv, installs packages and downloads Chromium (about 400 MB) into this folder.
cd /d "%~dp0"

set "PLAYWRIGHT_BROWSERS_PATH=%~dp0.browsers"
rem Keep installer temp files on this drive (helps when C: is nearly full).
if not exist ".tmp" mkdir ".tmp"
set "TMP=%~dp0.tmp"
set "TEMP=%~dp0.tmp"

if exist ".venv\Scripts\python.exe" goto :have_venv
set "PY="
where py >nul 2>nul
if not errorlevel 1 set "PY=py -3"
if not defined PY (
  where python >nul 2>nul
  if not errorlevel 1 set "PY=python"
)
if not defined PY goto :nopython
echo Creating the Python virtual environment...
%PY% -m venv .venv
if errorlevel 1 goto :fail

:have_venv
".venv\Scripts\python.exe" -c "import playwright" >nul 2>nul
if not errorlevel 1 goto :have_packages
echo Installing Python packages...
".venv\Scripts\python.exe" -m pip install --disable-pip-version-check --no-cache-dir -r requirements.txt
if errorlevel 1 goto :fail

:have_packages
dir /b ".browsers\chromium_headless_shell-*" >nul 2>nul
if not errorlevel 1 goto :run
echo Downloading the Chromium browser used for scanning...
".venv\Scripts\python.exe" -m playwright install chromium chromium-headless-shell
if errorlevel 1 goto :fail

:run
echo.
echo Starting AdLeak Detector (close this window to stop it)...
".venv\Scripts\python.exe" run.py %*
goto :end

:nopython
echo Python 3.10 or newer was not found. Install it from https://www.python.org/downloads/windows/
echo and tick "Add python.exe to PATH" during setup, then run this file again.
goto :end

:fail
echo.
echo Setup failed. Scroll up for the error message. Check your internet connection and free disk space, then try again.

:end
pause
endlocal
