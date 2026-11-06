$ErrorActionPreference='Stop'
$base=Join-Path $env:ProgramData 'ClaudeIpGuard'
$backupPath=Join-Path $base 'firewall-backup.json'
$logPath=Join-Path $base 'kill-switch.log'
$id=[Security.Principal.WindowsIdentity]::GetCurrent()
if(-not([Security.Principal.WindowsPrincipal]::new($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Administrator permission is required.'}
if(-not(Test-Path $backupPath)){throw 'No firewall backup was found. Claude IP Guard may not have enabled the kill switch.'}
$backup=Get-Content -LiteralPath $backupPath -Raw | ConvertFrom-Json
foreach($p in $backup.Profiles){Set-NetFirewallProfile -Profile $p.Name -DefaultOutboundAction $p.DefaultOutboundAction -ErrorAction Stop}
foreach($r in $backup.Rules){Set-NetFirewallRule -PolicyStore PersistentStore -Name $r.Name -Enabled ([bool]$r.Enabled) -ErrorAction SilentlyContinue}
Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object {$_.Name -like 'CIG_KS_*'} | Remove-NetFirewallRule -ErrorAction SilentlyContinue
Move-Item -LiteralPath $backupPath -Destination ($backupPath+'.restored-'+(Get-Date -Format 'yyyyMMdd-HHmmss')) -Force
Add-Content -LiteralPath $logPath -Value ("[{0}] Original Windows Firewall outbound settings restored." -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))
Write-Output 'Previous Windows Firewall outbound settings were restored.'
