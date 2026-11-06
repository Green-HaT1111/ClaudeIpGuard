param([Parameter(Mandatory=$true)][string]$VpnInterfaceAlias,[Parameter(Mandatory=$true)][string]$ConfigPath)
$ErrorActionPreference='Stop'
$base=Join-Path $env:ProgramData 'ClaudeIpGuard'
New-Item -ItemType Directory -Path $base -Force | Out-Null
$backupPath=Join-Path $base 'firewall-backup.json'
$logPath=Join-Path $base 'kill-switch.log'
function Log([string]$m){Add-Content -LiteralPath $logPath -Value ("[{0}] {1}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'),$m)}
$id=[Security.Principal.WindowsIdentity]::GetCurrent()
if(-not([Security.Principal.WindowsPrincipal]::new($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Administrator permission is required.'}
if(Test-Path $backupPath){throw 'A firewall backup already exists. Restore it before enabling the kill switch again.'}
if(-not(Test-Path -LiteralPath $ConfigPath)){throw 'The selected OpenVPN profile does not exist.'}
$adapter=Get-NetAdapter -Name $VpnInterfaceAlias -ErrorAction Stop
if($adapter.Status -ne 'Up' -or ("$($adapter.Name) $($adapter.InterfaceDescription)" -notmatch 'OpenVPN|TAP-Windows|Wintun|DCO')){throw 'The selected interface is not an active OpenVPN tunnel adapter.'}
$physical=@(Get-NetAdapter -Physical -ErrorAction SilentlyContinue | Where-Object {$_.Status -eq 'Up'})
if($physical.Count -eq 0){throw 'No active physical network adapter was found.'}
$lines=Get-Content -LiteralPath $ConfigPath -ErrorAction Stop
if(-not($lines | Where-Object {$_ -match '^\s*redirect-gateway\b'} | Select-Object -First 1)){throw 'The profile has no redirect-gateway directive. No firewall changes were made.'}

# Strict mode requires numeric server IPs so the VPN can reconnect without physical DNS.
$endpoints=@()
foreach($line in ($lines | Where-Object {$_ -match '^\s*remote\s+'})){
 $parts=@($line.Trim() -split '\s+')
 if($parts.Count -lt 2){continue}
 $remoteHost=$parts[1]; $parsed=$null
 if (-not [System.Net.IPAddress]::TryParse($remoteHost,[ref]$parsed)){throw "Remote endpoint '$remoteHost' is a hostname. Strict mode requires numeric remote IPs; no firewall changes were made."}
 $port=1194
 if($parts.Count -ge 3 -and $parts[2] -match '^\d+$'){$port=[int]$parts[2]}
 $protoText=if($parts.Count -ge 4){$parts[3].ToLowerInvariant()}elseif($parts.Count -ge 3 -and $parts[2] -match '^(tcp|udp)'){$parts[2].ToLowerInvariant()}else{'udp'}
 $protocol=if($protoText -match '^tcp'){'TCP'}elseif($protoText -match '^udp'){'UDP'}else{throw "Unsupported remote protocol '$protoText'."}
 $endpoints += [pscustomobject]@{Address=$parsed.IPAddressToString;Port=$port;Protocol=$protocol}
}
$endpoints=@($endpoints | Sort-Object Address,Port,Protocol -Unique)
if($endpoints.Count -eq 0){throw 'No numeric OpenVPN remote endpoint was found.'}

$routes=@(Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object {$_.InterfaceIndex -eq $adapter.ifIndex})
$vpnRoute=@($routes | Where-Object {$_.DestinationPrefix -in @('0.0.0.0/0','0.0.0.0/1','128.0.0.0/1')})
if($vpnRoute.Count -eq 0){throw 'No default or split-default IPv4 route uses the selected VPN interface. Connect a verified full-tunnel VPN first.'}
$profiles=@(Get-NetFirewallProfile)
if($profiles.Count -lt 3){throw 'Could not inspect all Windows Firewall profiles.'}
$gpoAllow=@(Get-NetFirewallRule -PolicyStore ActiveStore -Direction Outbound -Action Allow -Enabled True -ErrorAction SilentlyContinue | Where-Object {$_.PolicyStoreSourceType -eq 'GroupPolicy'})
if($gpoAllow.Count -gt 0){throw 'Group Policy manages outbound allow rules. Safe enforcement cannot be guaranteed; no firewall changes were made.'}
$allowRules=@(Get-NetFirewallRule -PolicyStore PersistentStore -Direction Outbound -Action Allow -Enabled True -ErrorAction Stop | Where-Object {$_.Name -notlike 'CIG_KS_*'})
if(@($profiles | Where-Object {$_.Enabled -ne 'True'}).Count -gt 0){throw 'One or more Windows Firewall profiles are disabled. Enable Windows Firewall before proceeding.'}

$backup=[pscustomobject]@{
 CreatedAt=(Get-Date).ToString('o')
 Profiles=@($profiles | ForEach-Object {[pscustomobject]@{Name=$_.Name.ToString();DefaultOutboundAction=$_.DefaultOutboundAction.ToString()}})
 Rules=@($allowRules | ForEach-Object {[pscustomobject]@{Name=$_.Name;Enabled=$true}})
 VpnInterface=$VpnInterfaceAlias
 PhysicalInterfaces=@($physical | ForEach-Object {$_.Name})
 ConfigPath=$ConfigPath
 Endpoints=$endpoints
}
$backup | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $backupPath -Encoding UTF8

try{
 # Windows Firewall has no transaction API. Default block is set first, then old allow rules are disabled.
 Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultOutboundAction Block -ErrorAction Stop
 foreach($rule in $allowRules){Set-NetFirewallRule -PolicyStore PersistentStore -Name $rule.Name -Enabled False -ErrorAction Stop}
 New-NetFirewallRule -Name 'CIG_KS_VPN_INTERFACE' -DisplayName 'Claude IP Guard - VPN tunnel only' -Direction Outbound -Action Allow -InterfaceAlias $VpnInterfaceAlias -Profile Any -Enabled True | Out-Null
 $physicalNames=@($physical | ForEach-Object {$_.Name})
 $n=0
 foreach($ep in $endpoints){
  $n++
  New-NetFirewallRule -Name ("CIG_KS_ENDPOINT_{0}" -f $n) -DisplayName 'Claude IP Guard - OpenVPN server endpoint' -Direction Outbound -Action Allow -InterfaceAlias $physicalNames -RemoteAddress $ep.Address -RemotePort $ep.Port -Protocol $ep.Protocol -Profile Any -Enabled True | Out-Null
 }
 New-NetFirewallRule -Name 'CIG_KS_DHCP' -DisplayName 'Claude IP Guard - DHCP lease renewal' -Direction Outbound -Action Allow -InterfaceAlias $physicalNames -Protocol UDP -LocalPort 68 -RemotePort 67 -Profile Any -Enabled True | Out-Null
 $residualAllow=@(Get-NetFirewallRule -PolicyStore ActiveStore -Direction Outbound -Action Allow -Enabled True -ErrorAction SilentlyContinue | Where-Object {$_.Name -notlike 'CIG_KS_*'})
 if($residualAllow.Count -gt 0){throw "Could not disable every pre-existing outbound allow rule ($($residualAllow.Count) remain). Kill switch was rolled back."}
 $verify=@(Get-NetFirewallProfile)
 if(@($verify | Where-Object {$_.DefaultOutboundAction -ne 'Block'}).Count -gt 0){throw 'Default outbound block could not be verified on every firewall profile.'}
 if(-not(Get-NetFirewallRule -Name 'CIG_KS_VPN_INTERFACE' -ErrorAction SilentlyContinue)){throw 'VPN interface allow rule could not be verified.'}
 if(@(Get-NetFirewallRule | Where-Object {$_.Name -like 'CIG_KS_ENDPOINT_*'}).Count -eq 0){throw 'No VPN endpoint allow rule could be verified.'}
 Log "Enabled VPN-only kill switch. Interface=$VpnInterfaceAlias; endpoint rules=$($endpoints.Count); existing outbound allow rules backed up and disabled."
 Write-Output 'VPN-only kill switch enabled. All other Windows outbound traffic is blocked.'
}catch{
 try{
  Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object {$_.Name -like 'CIG_KS_*'} | Remove-NetFirewallRule -ErrorAction SilentlyContinue
  foreach($p in $backup.Profiles){Set-NetFirewallProfile -Profile $p.Name -DefaultOutboundAction $p.DefaultOutboundAction -ErrorAction SilentlyContinue}
  foreach($r in $backup.Rules){Set-NetFirewallRule -PolicyStore PersistentStore -Name $r.Name -Enabled $r.Enabled -ErrorAction SilentlyContinue}
  Remove-Item -LiteralPath $backupPath -Force -ErrorAction SilentlyContinue
 }catch{Log ("Rollback encountered an error: "+$_.Exception.Message)}
 Log ("Kill switch activation failed: "+$_.Exception.Message)
 throw
}
