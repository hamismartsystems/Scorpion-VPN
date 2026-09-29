; Scorpion VPN - Inno Setup installer script
; 1) Install Inno Setup: https://jrsoftware.org/isdl.php
; 2) First run build_windows.bat so dist\Scorpion VPN exists
; 3) Open this file in Inno Setup and press Compile

[Setup]
AppName=Scorpion VPN
AppVersion=1.4.1
AppPublisher=HamiDesigns (حمیدیزاینز)
AppComments=Scorpion VPN - Secure Proxy Client - Icon Fix
AppSupportURL=https://hamidesigns.shop
AppUpdatesURL=https://hamidesigns.shop/apps/
DefaultDirName={autopf}\ScorpionVPN
DefaultGroupName=Scorpion VPN
OutputBaseFilename=ScorpionVPN-Setup-1.4.1
SetupIconFile=scorpion.ico
VersionInfoVersion=1.4.1
VersionInfoCompany=HAMI SMART SYSTEMS
VersionInfoDescription=Scorpion VPN 1.4.1 - Taskbar Icon Root Fix
VersionInfoCopyright=Copyright (c) 2026 HAMI SMART SYSTEMS
VersionInfoProductName=Scorpion VPN
VersionInfoProductVersion=1.4.1
UninstallDisplayIcon={app}\Scorpion VPN.exe
UninstallDisplayName=Scorpion VPN
ArchitecturesAllowed=x64
ArchitecturesInstallIn64BitMode=x64
PrivilegesRequired=lowest
WizardStyle=modern
Compression=lzma2
SolidCompression=yes

[Languages]
Name: "en"; MessagesFile: "compiler:Default.isl"

[Files]
Source: "dist\Scorpion VPN\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
; آیکون میانبر خود exe است، نه یک فایل جدا که بعد از آپدیت گم شود.
Name: "{group}\Scorpion VPN"; Filename: "{app}\Scorpion VPN.exe"; IconFilename: "{app}\Scorpion VPN.exe"; IconIndex: 0
Name: "{group}\Uninstall Scorpion VPN"; Filename: "{uninstallexe}"
Name: "{autodesktop}\Scorpion VPN"; Filename: "{app}\Scorpion VPN.exe"; IconFilename: "{app}\Scorpion VPN.exe"; IconIndex: 0

[Run]
Filename: "{app}\Scorpion VPN.exe"; Description: "Launch Scorpion VPN"; Flags: nowait postinstall skipifsilent
