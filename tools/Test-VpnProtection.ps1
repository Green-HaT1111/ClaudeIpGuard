$ErrorActionPreference='Stop'
try {
 $profiles=@(Get-NetFirewallProfile)
 $blocked=$profiles.Count -ge 3 -and @($profiles | Where-Object {$_.DefaultOutboundAction -ne 'Block'}).Count -eq 0
 $tunnel=Get-NetFirewallRule -Name 'CIG_KS_VPN_INTERFACE' -ErrorAction SilentlyContinue
 $endpoints=@(Get-NetFirewallRule | Where-Object {$_.Name -like 'CIG_KS_ENDPOINT_*' -and $_.Enabled -eq 'True'})
 $dhcp=Get-NetFirewallRule -Name 'CIG_KS_DHCP' -ErrorAction SilentlyContinue
 $allAllow=@(Get-NetFirewallRule -PolicyStore ActiveStore -Direction Outbound -Action Allow -Enabled True -ErrorAction SilentlyContinue |
  Where-Object {$_.Name -notlike 'CIG_KS_*'})
 $noBypass=$allAllow.Count -eq 0
 $adapterOk=$false; $routeOk=$false
 if($tunnel -and $tunnel.Enabled -eq 'True'){
  $filters=@(Get-NetFirewallInterfaceFilter -AssociatedNetFirewallRule $tunnel -ErrorAction SilentlyContinue)
  $aliases=@($filters | ForEach-Object {$_.InterfaceAlias} | Where-Object {$_ -and $_ -ne 'Any'})
  foreach($alias in $aliases){
   $adapter=Get-NetAdapter -Name $alias -ErrorAction SilentlyContinue
   if($adapter -and $adapter.Status -eq 'Up'){
    $adapterOk=$true
    $routes=@(Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object {
     $_.InterfaceIndex -eq $adapter.ifIndex -and $_.DestinationPrefix -in @('0.0.0.0/0','0.0.0.0/1','128.0.0.0/1')
    })
    if($routes.Count -gt 0){$routeOk=$true}
   }
  }
 }
 $ok=$blocked -and $tunnel -and $tunnel.Enabled -eq 'True' -and $endpoints.Count -gt 0 -and $dhcp -and $dhcp.Enabled -eq 'True' -and $noBypass -and $adapterOk -and $routeOk
 if($ok){'true'}else{'false'}
 exit 0
}catch{
 'false'
 exit 0
}
