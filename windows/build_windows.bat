@echo on
cd /d "%~dp0"
set "LOG=%~dp0build_log.txt"
echo === Scorpion VPN Build Log === > "%LOG%"
echo ============================================
echo   Scorpion VPN - Windows Build
echo ============================================

echo Checking required files...
set MISSING=0
for %%F in (scorpion_vpn.py xray.exe geoip.dat geosite.dat scorpion.ico scorpion_icon.png) do (
  if not exist "%%F" (
    echo   MISSING: %%F
    echo MISSING FILE: %%F >> "%LOG%"
    set MISSING=1
  )
)
if %MISSING%==1 (
  echo.
  echo ERROR: some files are missing in this folder!
  echo All these files must be beside the bat:
  echo   scorpion_vpn.py, xray.exe, geoip.dat, geosite.dat, scorpion.ico, scorpion_icon.png
  pause
  exit /b 1
)

set PY=
if exist "C:\Users\Hamid\PyCharmMiscProject\.venv\Scripts\python.exe" (
  set "PY=C:\Users\Hamid\PyCharmMiscProject\.venv\Scripts\python.exe"
)
if not defined PY (
  python -c "print(1)" >nul 2>&1
  if not errorlevel 1 set PY=python
)
if not defined PY (
  echo ERROR: Python not found >> "%LOG%"
  echo ERROR: Python peyda nashod.
  pause
  exit /b 1
)
echo Python: %PY%
echo Python: %PY% >> "%LOG%"
"%PY%" --version >> "%LOG%" 2>&1

echo.
echo [1/2] Installing PyInstaller...
"%PY%" -m pip install pyinstaller >> "%LOG%" 2>&1
if errorlevel 1 (
  echo ERROR: pip install failed - send build_log.txt
  pause
  exit /b 1
)

echo [2/2] Building Scorpion VPN (1-2 minutes)...
"%PY%" -m PyInstaller --noconfirm --onedir --windowed --name "Scorpion VPN" --icon=scorpion.ico --add-data "xray.exe;." --add-data "geoip.dat;." --add-data "geosite.dat;." --add-data "scorpion_icon.png;." scorpion_vpn.py >> "%LOG%" 2>&1
if errorlevel 1 (
  echo.
  echo BUILD FAILED. Last lines of log:
  echo ----------------------------------------
  powershell -command "Get-Content '%LOG%' | Select-Object -Last 25"
  echo ----------------------------------------
  echo Please send build_log.txt or a screenshot of this window
  pause
  exit /b 1
)

echo.
echo ============================================
echo   OK! Output: dist\Scorpion VPN
echo   Next: installer.iss in Inno Setup, press F9
echo ============================================
pause
