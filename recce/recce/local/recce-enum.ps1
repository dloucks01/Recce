<#
  recce-enum.ps1 - thorough, READ-ONLY local enumeration for Windows.

  The on-target companion to recce: run this once you have a shell on a Windows
  host to surface privilege-escalation vectors and sensitive exposure (a
  winPEAS-style sweep). It changes NOTHING - only reads system state with
  built-in cmdlets / reg queries - so it is safe to run and does not behave like
  malware. No exploit code, no download, no obfuscation, no AMSI/Defender
  tampering. Being a plain read-only Get-* script is exactly why it does not
  match malware signatures; if an EDR still false-positives in an authorized
  engagement, coordinate an exclusion with the client rather than evading it.

  Usage:
    powershell -ep bypass -File .\recce-enum.ps1 [-Quiet] [-OutFile report.txt]
      -Quiet     findings only (skip the raw dumps)
      -OutFile   also write everything to a file

  Authorized testing only. Lines marked [!] are worth a closer look.
#>
[CmdletBinding()]
param([switch]$Quiet, [string]$OutFile)

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
  Finding "   SharpEfsPotato / EfsPotato (MS-EFSR), JuicyPotatoNG. e.g.  GodPotato -cmd \"cmd /c whoami\""
}
if($priv -match 'SeBackupPrivilege\s+.*Enabled'){ Finding "SeBackupPrivilege -> read any file (SAM/SYSTEM/NTDS) -> hash dump" }
if($priv -match 'SeRestorePrivilege\s+.*Enabled'){ Finding "SeRestorePrivilege -> write any file / service hijack -> SYSTEM" }
if($priv -match 'SeTakeOwnershipPrivilege\s+.*Enabled'){ Finding "SeTakeOwnershipPrivilege -> take ownership of protected objects" }
if($priv -match 'SeLoadDriverPrivilege\s+.*Enabled'){ Finding "SeLoadDriverPrivilege -> load a vulnerable driver (BYOVD) -> kernel" }
if($priv -match 'SeDebugPrivilege\s+.*Enabled'){ Finding "SeDebugPrivilege -> inject into SYSTEM processes" }
Info "Group membership:"
whoami /groups 2>$null | Where-Object { $_ -match 'S-1-|Administrators|BUILTIN' } | ForEach-Object { Info $_.Trim() }
if((whoami /groups) -match 'S-1-5-32-544'){ Finding "Current token is in the local Administrators group (may need UAC bypass to use it)" }

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

# ============================================================ processes / misc
Sec "Processes running as SYSTEM / other users"
Get-CimInstance Win32_Process | ForEach-Object {
  $o = $_.GetOwner(); if($o.User){ "{0,-28} pid={1,-6} {2}\{3}" -f $_.Name,$_.ProcessId,$o.Domain,$o.User }
} 2>$null | Sort-Object -Unique | Select-Object -First 60 | ForEach-Object { Info $_ }

Sec "Environment variables"
Get-ChildItem Env: | ForEach-Object { Info ($_.Name + "=" + $_.Value) }

Emit ""
Emit "Done. Review every [!] line. Nothing was changed on this host."
if($OutFile){ Emit ("Full report written to: " + $OutFile) }
