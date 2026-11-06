$ErrorActionPreference = 'Stop'
$base = Join-Path $env:ProgramData 'ClaudeIpGuard'
New-Item -ItemType Directory -Path $base -Force | Out-Null
$backupPath = Join-Path $base 'privacy-settings-backup.json'
$logPath = Join-Path $base 'privacy-actions.log'
function Log([string]$m) { Add-Content -LiteralPath $logPath -Value ("[{0}] {1}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $m) }
function Assert-Admin {
 $id=[Security.Principal.WindowsIdentity]::GetCurrent()
 if (-not ([Security.Principal.WindowsPrincipal]::new($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Administrator permission is required.' }
}
function Read-RegState([string]$hive,[string]$path,[string]$name) {
 $root=if($hive -eq 'HKLM'){[Microsoft.Win32.RegistryHive]::LocalMachine}else{[Microsoft.Win32.RegistryHive]::CurrentUser}
 $b=[Microsoft.Win32.RegistryKey]::OpenBaseKey($root,[Microsoft.Win32.RegistryView]::Default)
 try {
  $k=$b.OpenSubKey($path,$false)
  if($null -eq $k){return [pscustomobject]@{Hive=$hive;Path=$path;Name=$name;Exists=$false;Value=$null;Kind='String'}}
  try {
   if($name -notin $k.GetValueNames()){return [pscustomobject]@{Hive=$hive;Path=$path;Name=$name;Exists=$false;Value=$null;Kind='String'}}
   return [pscustomobject]@{Hive=$hive;Path=$path;Name=$name;Exists=$true;Value=$k.GetValue($name,$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames);Kind=$k.GetValueKind($name).ToString()}
  } finally {$k.Dispose()}
 } finally {$b.Dispose()}
}
Assert-Admin
if (-not (Test-Path $backupPath)) {
 $svc=Get-CimInstance Win32_Service -Filter "Name='lfsvc'" -ErrorAction SilentlyContinue
 $snapshot=[pscustomobject]@{
  CreatedAt=(Get-Date).ToString('o')
  ServiceExists=($null -ne $svc)
  ServiceStartMode=if($svc){[string]$svc.StartMode}else{''}
  ServiceWasRunning=if($svc){$svc.State -eq 'Running'}else{$false}
  Registry=@(
   (Read-RegState 'HKLM' 'SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors' 'DisableLocation'),
   (Read-RegState 'HKLM' 'SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors' 'DisableWindowsLocationProvider'),
   (Read-RegState 'HKLM' 'SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' 'LetAppsAccessLocation'),
   (Read-RegState 'HKCU' 'Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location' 'Value')
  )
 }
 $snapshot | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $backupPath -Encoding UTF8
 Log 'Saved the original Windows location settings.'
}
# Disable Windows location access with a restorable backup.
$p1='HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors'
$p2='HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'
New-Item -Path $p1 -Force | Out-Null
New-Item -Path $p2 -Force | Out-Null
New-ItemProperty -Path $p1 -Name DisableLocation -PropertyType DWord -Value 1 -Force | Out-Null
New-ItemProperty -Path $p1 -Name DisableWindowsLocationProvider -PropertyType DWord -Value 1 -Force | Out-Null
New-ItemProperty -Path $p2 -Name LetAppsAccessLocation -PropertyType DWord -Value 2 -Force | Out-Null
$consent='HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location'
New-Item -Path $consent -Force | Out-Null
Set-ItemProperty -Path $consent -Name Value -Value 'Deny'
$svc=Get-Service -Name lfsvc -ErrorAction SilentlyContinue
if($svc){ if($svc.Status -eq 'Running'){Stop-Service -Name lfsvc -Force -ErrorAction SilentlyContinue}; Set-Service -Name lfsvc -StartupType Disabled }
Log 'Windows location access blocked by machine policy and service settings.'

# Clear the local DNS resolver cache. This does not remove data held by DNS providers or websites.
try { & ipconfig.exe /flushdns | Out-Null; Log 'Flushed the Windows DNS resolver cache.' } catch { Log ("DNS cache flush failed: " + $_.Exception.Message) }

# Only clear temporary Claude cache directories, never account/session stores.
$claudeProcesses=@(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object {
 $_.Name -ieq 'Claude.exe' -or ($_.Name -ieq 'node.exe' -and $_.CommandLine -match '@anthropic-ai[\\/]claude-code')
})
if($claudeProcesses.Count -gt 0){
 Log 'Skipped Claude cache cleanup because Claude Desktop or Claude Code is running.'
}else{
 $roots=@((Join-Path $env:APPDATA 'Claude'))
 $packages=Join-Path $env:LOCALAPPDATA 'Packages'
 if(Test-Path $packages){foreach($pkg in (Get-ChildItem $packages -Directory -Filter 'Claude_*' -ErrorAction SilentlyContinue)){$roots += (Join-Path $pkg.FullName 'LocalCache\Roaming\Claude')}}
 $backupDir=Join-Path $base ('Claude-cache-backup-'+(Get-Date -Format 'yyyyMMdd-HHmmss'))
 $removed=0
 foreach($root in ($roots | Select-Object -Unique)){
  if(-not(Test-Path $root)){continue}
  foreach($name in @('Cache','Code Cache','GPUCache','DawnCache')){
   $src=Join-Path $root $name
   if(-not(Test-Path $src)){continue}
   try{
    New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
    $dest=Join-Path $backupDir ((Split-Path $root -Leaf)+'_'+$name)
    Copy-Item -LiteralPath $src -Destination $dest -Recurse -Force
    Remove-Item -LiteralPath $src -Recurse -Force
    $removed++
   }catch{Log ("Cache cleanup failed for $src : "+$_.Exception.Message)}
  }
 }
 Log "Backed up and cleared $removed temporary Claude cache folder(s). Cookies, Local Storage, IndexedDB, credentials, tokens and session databases were not touched."
}
Write-Output "Privacy remediation finished. Log: $logPath"
