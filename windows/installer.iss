; Scorpion VPN - Inno Setup installer script
; 1) Install Inno Setup: https://jrsoftware.org/isdl.php
; 2) First run build_windows.bat so dist\Scorpion VPN exists
; 3) Open this file in Inno Setup and press Compile

[Setup]
AppName=Scorpion VPN
AppVersion=1.0
AppPublisher=Hami Smart Systems
AppComments=Scorpion VPN - Secure Proxy Client
DefaultDirName={autopf}\ScorpionVPN
DefaultGroupName=Scorpion VPN
OutputBaseFilename=ScorpionVPN-Setup-1.0
SetupIconFile=scorpion.ico
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
Name: "{group}\Scorpion VPN"; Filename: "{app}\Scorpion VPN.exe"
Name: "{group}\Uninstall Scorpion VPN"; Filename: "{uninstallexe}"
Name: "{autodesktop}\Scorpion VPN"; Filename: "{app}\Scorpion VPN.exe"

[Run]
Filename: "{app}\Scorpion VPN.exe"; Description: "Launch Scorpion VPN"; Flags: nowait postinstall skipifsilent
