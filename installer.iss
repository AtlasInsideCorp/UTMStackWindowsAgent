#define MyAppName "UTMStack Agent"
#define MyAppVersion "6.0.0"
#define MyAppPublisher "Atlas Inside Technology LLC"
#define MyAppURL "http://www.utmvault.com"
#define FilebeatService "filebeat"
#define MetricbeatService "metricbeat"
#define WinlogbeatService "winlogbeat"
#define UTMSService "utmstack"
#define AppLauncher "-m utm_agent --gui"
#define AppReset "-m utm_agent --reset"
#define AppService "-m utm_agent.service"
#define PyExe "Python37\pythonw.exe"
#define PyCli "Python37\python.exe"
#define AppIcon "app.ico"


[Setup]
ArchitecturesInstallIn64BitMode="x64 arm64"
; NOTE: The value of AppId uniquely identifies this application. Do not use the same AppId value in installers for other applications.
; (To generate a new GUID, click Tools | Generate GUID inside the IDE.)
AppId={{73D1A060-EB12-4C88-BF85-4E0B03677CA8}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
;AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
DefaultDirName={autopf}\{#MyAppName}
DisableDirPage=yes
DisableProgramGroupPage=yes
OutputDir=dist
OutputBaseFilename="{#MyAppName}-Installer-{#MyAppVersion}"
SetupIconFile="branding\app.ico"
WizardImageFile="branding\wizard.bmp"
;WizardImageStretch=no
Compression=lzma
SolidCompression=yes
WizardStyle=modern
LicenseFile=LICENSE


[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"


[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"


[Files]
Source: "branding\{#AppIcon}"; DestDir: "{app}"
Source: "assets\wazuh-agent-3.11.3-1.msi"; DestDir: "{tmp}"
Source: "assets\*"; DestDir: "{app}"; Excludes: ".mypy_cache,*~,__pycache__,\wazuh-agent-3.11.3-1.msi"; Flags: ignoreversion recursesubdirs createallsubdirs


[Icons]
; Start Menu launcher:
Name: "{autoprograms}\{#MyAppName}"; Filename: "{app}\{#PyExe}"; WorkingDir: "{app}"; Parameters: "{#AppLauncher}"; IconFilename: "{app}\{#AppIcon}"

; Desktop launcher:
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#PyExe}"; WorkingDir: "{app}"; Parameters: "{#AppLauncher}"; IconFilename: "{app}\{#AppIcon}"; Tasks: desktopicon


[Run]
; Install Filebeat service:
Filename: "{sys}\sc.exe"; StatusMsg: "Installing Filebeat service..."; Parameters: "create {#FilebeatService} start= auto displayName= ""UTMS Filebeat"" binPath= ""\""{app}\Filebeat\filebeat.exe\"" -c \""{app}\Filebeat\filebeat.yml\"" -path.home \""{app}\Filebeat\"" -path.data C:\ProgramData\filebeat -path.logs C:\ProgramData\filebeat\logs"""; Flags: runhidden

; Install Metricbeat service:
Filename: "{sys}\sc.exe"; StatusMsg: "Installing Metricbeat service..."; Parameters: "create {#MetricbeatService} start= auto displayName= ""UTMS Metricbeat"" binPath= ""\""{app}\Metricbeat\metricbeat.exe\"" -c \""{app}\Metricbeat\metricbeat.yml\"" -path.home \""{app}\Metricbeat\"" -path.data C:\ProgramData\metricbeat -path.logs C:\ProgramData\metricbeat\logs -E logging.files.redirect_stderr=true"""; Flags: runhidden

; Install Winlogbeat service:
Filename: "{sys}\sc.exe"; StatusMsg: "Installing Winlogbeat service..."; Parameters: "create {#WinlogbeatService} start= auto displayName= ""UTMS Winlogbeat"" binPath= ""\""{app}\Winlogbeat\winlogbeat.exe\"" -c \""{app}\Winlogbeat\winlogbeat.yml\"" -path.home \""{app}\Winlogbeat\"" -path.data C:\ProgramData\winlogbeat -path.logs C:\ProgramData\winlogbeat\logs""" ; Flags: runhidden

; Install Wazuh agent:
Filename: "{sys}\msiexec.exe"; Parameters: "/package ""{tmp}\wazuh-agent-3.11.3-1.msi"" /qn"; StatusMsg: "Installing HIDS..."; Flags: runhidden

; Install UTMS service:
Filename: "{app}\nssm.exe"; StatusMsg: "Installing UTMS service..."; Parameters: "install {#UTMSService} ""{app}\{#PyCli}"" {#AppService}" ; Flags: runhidden
Filename: "{app}\nssm.exe"; StatusMsg: "Installing UTMS service..."; Parameters: "set {#UTMSService} AppDirectory ""{app}"""; Flags: runhidden
Filename: "{app}\nssm.exe"; StatusMsg: "Installing UTMS service..."; Parameters: "set {#UTMSService} DisplayName UTMStack"; Flags: runhidden
Filename: "{app}\nssm.exe"; StatusMsg: "Installing UTMS service..."; Parameters: "set {#UTMSService} AppExit Default Restart"; Flags: runhidden
Filename: "{app}\nssm.exe"; StatusMsg: "Installing UTMS service..."; Parameters: "set {#UTMSService} Start SERVICE_AUTO_START"; Flags: runhidden
Filename: "{app}\nssm.exe"; StatusMsg: "Installing UTMS service..."; Parameters: "set {#UTMSService} ObjectName LocalSystem"; Flags: runhidden
Filename: "{app}\nssm.exe"; StatusMsg: "Starting UTMS service..."; Parameters: "start {#UTMSService}"; Flags: runhidden

; Offer to launch app after install:
Filename: "{app}\{#PyExe}"; WorkingDir: "{app}"; Parameters: "{#AppLauncher}"; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent


[UninstallRun]
; Stop and delete UTMS service:
Filename: "{sys}\sc.exe"; Parameters: "stop {#UTMSService}"; Flags: runhidden
Filename: "{sys}\sc.exe"; Parameters: "delete {#UTMSService}"; Flags: runhidden
; Clear configuration:
Filename: "{app}\{#PyCli}"; WorkingDir: "{app}"; Parameters: "{#AppReset}"; Flags: runhidden

; Stop and delete Filebeat service:
Filename: "{sys}\sc.exe"; Parameters: "stop {#FilebeatService}"; Flags: runhidden
Filename: "{sys}\sc.exe"; Parameters: "delete {#FilebeatService}"; Flags: runhidden

; Stop and delete Metricbeat service:
Filename: "{sys}\sc.exe"; Parameters: "stop {#MetricbeatService}"; Flags: runhidden
Filename: "{sys}\sc.exe"; Parameters: "delete {#MetricbeatService}"; Flags: runhidden

; Stop and delete Winlogbeat service:
Filename: "{sys}\sc.exe"; Parameters: "stop {#WinlogbeatService}"; Flags: runhidden
Filename: "{sys}\sc.exe"; Parameters: "delete {#WinlogbeatService}"; Flags: runhidden

; Uninstall Wazuh:
Filename: "{sys}\msiexec.exe"; Parameters: "/x {{800017F9-14E5-4B3E-ADFC-AA77BBC53631} /qn"; Flags: runhidden


[UninstallDelete]
Type: filesandordirs; Name: "{app}\Filebeat"
Type: filesandordirs; Name: "{app}\Metricbeat"
Type: filesandordirs; Name: "{app}\Winlogbeat"
Type: filesandordirs; Name: "{app}\Python37"
Type: files; Name: "{app}\appdata.db"


[Code]
procedure CurStepChanged(CurStep: TSetupStep);
var
  Arg: String;
  Args: String;
  ResultCode: Integer;
  Configurate: Boolean;
begin
  if CurStep = ssPostInstall then begin
     Configurate := False;
     Args := '-m utm_agent';

     Arg := ExpandConstant('{param:host}');
     if Arg <> '' then begin
        Args := Args + ' --host=' + Arg;
	Configurate := True;
     end;

     Arg := ExpandConstant('{param:acl}');
     if Arg <> '' then begin
        Args := Args + ' --acl=' + Arg;
	Configurate := True;
     end;

     Arg := ExpandConstant('{param:antivirus}');
     if Arg <> '' then begin
        Args := Args + ' --antivirus=' + Arg;
	Configurate := True;
     end;

     if Configurate = True then begin
        Exec(ExpandConstant('{app}\{#PyCli}'), Args, '', SW_HIDE,
             ewWaitUntilTerminated, ResultCode);
     end;
  end;
end;
