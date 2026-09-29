@echo on
cd /d "%~dp0"
set "LOG=%~dp0build_log.txt"
echo === Scorpion VPN Build Log 1.4.1 Icon Fix === > "%LOG%"

echo Checking essential files...
set MISSING=0
for %%F in (scorpion_vpn.py scorpion.ico scorpion_icon.png) do (
  if not exist "%%F" (
    echo   MISSING ESSENTIAL: %%F
    echo MISSING ESSENTIAL: %%F >> "%LOG%"
    set MISSING=1
  )
)
if %MISSING%==1 (
  echo.
  echo ERROR: essential files missing! Must have scorpion_vpn.py, scorpion.ico, scorpion_icon.png beside bat
  pause
  exit /b 1
)

REM Check xray and geo — try to auto-download if missing
if not exist "xray.exe" (
  echo   WARNING: xray.exe not found, trying to download...
  echo WARNING xray.exe missing >> "%LOG%"
  powershell -Command "try { Invoke-WebRequest -Uri 'https://github.com/XTLS/Xray-core/releases/latest/download/Xray-windows-64.zip' -OutFile 'xray.zip' -UseBasicParsing; Expand-Archive -Path 'xray.zip' -DestinationPath '.' -Force; Remove-Item 'xray.zip' -Force; } catch { Write-Host 'Download failed, please put xray.exe manually' }" >> "%LOG%" 2>&1
)
if not exist "geoip.dat" (
  echo   WARNING: geoip.dat missing, creating empty or downloading...
  powershell -Command "try { Invoke-WebRequest -Uri 'https://github.com/v2fly/geoip/releases/latest/download/geoip.dat' -OutFile 'geoip.dat' -UseBasicParsing; } catch { }" >> "%LOG%" 2>&1
)
if not exist "geosite.dat" (
  echo   WARNING: geosite.dat missing, downloading...
  powershell -Command "try { Invoke-WebRequest -Uri 'https://github.com/v2fly/domain-list-community/releases/latest/download/dlc.dat' -OutFile 'geosite.dat' -UseBasicParsing; } catch { }" >> "%LOG%" 2>&1
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
"%PY%" --version >> "%LOG%" 2>&1

echo.
echo [1/2] Installing PyInstaller...
"%PY%" -m pip install pyinstaller pillow PyQt6 cryptography >> "%LOG%" 2>&1

echo [2/2] Building Scorpion VPN 1.4.1 Icon Fix...
set ADD=
if exist "xray.exe" set ADD=%ADD% --add-data "xray.exe;."
if exist "geoip.dat" set ADD=%ADD% --add-data "geoip.dat;."
if exist "geosite.dat" set ADD=%ADD% --add-data "geosite.dat;."
if exist "scorpion_icon.png" set ADD=%ADD% --add-data "scorpion_icon.png;."
if exist "scorpion.ico" set ADD=%ADD% --add-data "scorpion.ico;."

"%PY%" -m PyInstaller --noconfirm --onedir --windowed --name "Scorpion VPN" --icon=scorpion.ico --hidden-import scorpion_i18n --hidden-import scorpion_update --hidden-import cryptography %ADD% scorpion_vpn.py >> "%LOG%" 2>&1
if errorlevel 1 (
  echo.
  echo BUILD FAILED. Last lines:
  powershell -Command "Get-Content '%LOG%' | Select-Object -Last 40"
  pause
  exit /b 1
)

echo.
echo ============================================
echo   OK! Output: dist\Scorpion VPN\Scorpion VPN.exe
echo   Icon fix included: taskbar icon should now show
echo   Next: installer.iss in Inno Setup F9 -> ScorpionVPN-Setup-1.4.1.exe
echo ============================================
pause
