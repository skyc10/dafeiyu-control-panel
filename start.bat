@echo off
setlocal
cd /d "%~dp0"
where py >nul 2>nul
if not errorlevel 1 (
  py -3 "%~dp0server.py"
  exit /b
)
where python >nul 2>nul
if not errorlevel 1 (
  python "%~dp0server.py"
  exit /b
)
if exist "%LOCALAPPDATA%\Programs\Python\Python312\python.exe" (
  "%LOCALAPPDATA%\Programs\Python\Python312\python.exe" "%~dp0server.py"
  exit /b
)
echo Python 3.10+ is required. Install Python and enable the launcher or PATH.
pause
exit /b 1
