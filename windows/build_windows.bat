@echo on
cd /d "%~dp0"
set "LOG=%~dp0build_log.txt"
echo === Scorpion VPN Build Log 1.4.5 TUN === > "%LOG%"

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
REM sing-box + WinTun for TUN mode (pinned versions, SHA256 checked)
if not exist "sing-box.exe" (
  echo   sing-box.exe missing, downloading pinned v1.14.4...
  powershell -NoProfile -Command "try { Invoke-WebRequest -Uri 'https://github.com/SagerNet/sing-box/releases/download/v1.14.4/sing-box-1.14.4-windows-amd64.zip' -OutFile 'sb.zip' -UseBasicParsing; if ((Get-FileHash 'sb.zip' -Algorithm SHA256).Hash -ne '99185D75D314A07DBBA4A130C8AD986CBEB629A07927975636B341CA61F991DF') { throw 'sing-box hash mismatch' }; Expand-Archive -Path 'sb.zip' -DestinationPath 'sb_tmp' -Force; Copy-Item 'sb_tmp\sing-box-1.14.4-windows-amd64\sing-box.exe' '.' -Force; Remove-Item 'sb.zip','sb_tmp' -Recurse -Force } catch { Write-Host ('sing-box download failed: ' + $_) }" >> "%LOG%" 2>&1
)
if not exist "wintun.dll" (
  echo   wintun.dll missing, downloading pinned 0.14.1...
  powershell -NoProfile -Command "try { Invoke-WebRequest -Uri 'https://www.wintun.net/builds/wintun-0.14.1.zip' -OutFile 'wt.zip' -UseBasicParsing; if ((Get-FileHash 'wt.zip' -Algorithm SHA256).Hash -ne '07C256185D6EE3652E09FA55C0B673E2624B565E02C4B9091C79CA7D2F24EF51') { throw 'wintun hash mismatch' }; Expand-Archive -Path 'wt.zip' -DestinationPath 'wt_tmp' -Force; Copy-Item 'wt_tmp\wintun\bin\amd64\wintun.dll' '.' -Force; Remove-Item 'wt.zip','wt_tmp' -Recurse -Force } catch { Write-Host ('wintun download failed: ' + $_) }" >> "%LOG%" 2>&1
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

echo [2/2] Building Scorpion VPN 1.4.5 TUN...
set ADD=
if exist "xray.exe" set ADD=%ADD% --add-data "xray.exe;."
if exist "geoip.dat" set ADD=%ADD% --add-data "geoip.dat;."
if exist "geosite.dat" set ADD=%ADD% --add-data "geosite.dat;."
if exist "scorpion_icon.png" set ADD=%ADD% --add-data "scorpion_icon.png;."
if exist "sing-box.exe" set ADD=%ADD% --add-data "sing-box.exe;."
if exist "wintun.dll" set ADD=%ADD% --add-data "wintun.dll;."
if exist "scorpion.ico" set ADD=%ADD% --add-data "scorpion.ico;."

"%PY%" -m PyInstaller --noconfirm --onedir --windowed --uac-admin --name "Scorpion VPN" --icon=scorpion.ico --hidden-import scorpion_i18n --hidden-import scorpion_update --hidden-import cryptography %ADD% scorpion_vpn.py >> "%LOG%" 2>&1
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
echo   Next: installer.iss in Inno Setup F9 -> ScorpionVPN-Setup-1.4.5.exe
echo ============================================
pause
