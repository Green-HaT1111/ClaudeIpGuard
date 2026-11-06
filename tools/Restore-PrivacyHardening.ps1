$ErrorActionPreference='Stop'
$base=Join-Path $env:ProgramData 'ClaudeIpGuard'
$backupPath=Join-Path $base 'privacy-settings-backup.json'
if(-not(Test-Path $backupPath)){throw 'No Windows location settings backup was found.'}
$id=[Security.Principal.WindowsIdentity]::GetCurrent()
if(-not([Security.Principal.WindowsPrincipal]::new($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Administrator permission is required.'}
$backup=Get-Content -LiteralPath $backupPath -Raw | ConvertFrom-Json
foreach($item in $backup.Registry){
 $hive=if($item.Hive -eq 'HKLM'){[Microsoft.Win32.RegistryHive]::LocalMachine}else{[Microsoft.Win32.RegistryHive]::CurrentUser}
 $b=[Microsoft.Win32.RegistryKey]::OpenBaseKey($hive,[Microsoft.Win32.RegistryView]::Default)
 try{
  $k=$b.CreateSubKey([string]$item.Path)
  try{
   if($item.Exists){
    $kind=[System.Enum]::Parse([Microsoft.Win32.RegistryValueKind],[string]$item.Kind)
    $k.SetValue([string]$item.Name,$item.Value,$kind)
   }else{$k.DeleteValue([string]$item.Name,$false)}
  }finally{$k.Dispose()}
 }finally{$b.Dispose()}
}
if($backup.ServiceExists){
 $mode=switch([string]$backup.ServiceStartMode){'Auto'{'Automatic'} 'Manual'{'Manual'} 'Disabled'{'Disabled'} default{'Manual'}}
 Set-Service -Name lfsvc -StartupType $mode -ErrorAction SilentlyContinue
 if($backup.ServiceWasRunning){Start-Service -Name lfsvc -ErrorAction SilentlyContinue}else{Stop-Service -Name lfsvc -Force -ErrorAction SilentlyContinue}
}
Move-Item -LiteralPath $backupPath -Destination ($backupPath+'.restored-'+(Get-Date -Format 'yyyyMMdd-HHmmss')) -Force
Write-Output 'Previous Windows location settings were restored.'
