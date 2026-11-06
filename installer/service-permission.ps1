# Lets normal (signed-in) users stop the Claude desktop app's background service, so
# Claude IP Guard can stop it without running as administrator. Run by the installer (as admin).
#   -Action Grant    add the permission, only if users can't stop the service already
#   -Action Revoke   remove only the permission that Grant added (used by uninstall)
#   -DryRun          print what would change, change nothing (no admin needed)
#   -Sddl            test with this security descriptor instead of the real service's
param(
    [ValidateSet('Grant', 'Revoke')][string]$Action = 'Grant',
    [switch]$DryRun,
    [string]$Sddl
)
$ErrorActionPreference = 'Stop'
$service = 'CoworkVMService'

# SERVICE_QUERY_STATUS (LC) + SERVICE_STOP (WP) + READ_CONTROL (RC). Not start, not change config.
$queryStatus = 0x4; $stop = 0x20
$ourMask = $queryStatus -bor $stop -bor 0x20000
# Our entry is for Interactive Users (IU), so uninstall can tell it apart from Claude's own entries.
$ourSid = New-Object System.Security.Principal.SecurityIdentifier 'S-1-5-4'
# Groups that every signed-in user belongs to: Everyone, Interactive, Authenticated Users, Users.
$userSids = 'S-1-1-0', 'S-1-5-4', 'S-1-5-11', 'S-1-5-32-545'

if (-not $Sddl) {
    $out = & sc.exe sdshow $service 2>$null
    if ($LASTEXITCODE -ne 0) { Write-Host "$service is not installed, nothing to do."; exit 0 }
    $Sddl = ($out | Where-Object { $_.Trim() }) -join ''
}

$sd = New-Object System.Security.AccessControl.RawSecurityDescriptor $Sddl
$dacl = $sd.DiscretionaryAcl
if (-not $dacl) { Write-Host 'Service has no access list (anyone can stop it), nothing to do.'; exit 0 }

$ours = -1
for ($i = 0; $i -lt $dacl.Count; $i++) {
    $a = $dacl[$i]
    if ($a.AceType -eq 'AccessAllowed' -and $a.SecurityIdentifier -eq $ourSid -and $a.AccessMask -eq $ourMask) { $ours = $i }
}

if ($Action -eq 'Grant') {
    $canStop = $false
    foreach ($a in $dacl) {
        if ($a.AceType -eq 'AccessAllowed' -and $userSids -contains $a.SecurityIdentifier.Value -and
            ($a.AccessMask -band ($queryStatus -bor $stop)) -eq ($queryStatus -bor $stop)) { $canStop = $true }
    }
    if ($canStop) { Write-Host 'Users can already stop the service, nothing to do.'; exit 0 }
    $ace = New-Object System.Security.AccessControl.CommonAce 'None', 'AccessAllowed', $ourMask, $ourSid, $false, $null
    $dacl.InsertAce($dacl.Count, $ace)
}
else {
    if ($ours -lt 0) { Write-Host 'Our permission is not there, nothing to do.'; exit 0 }
    $dacl.RemoveAce($ours)
}

$new = $sd.GetSddlForm('All')
if ($DryRun) { Write-Host "Would set: $new"; exit 0 }
& sc.exe sdset $service $new | Out-Null
if ($LASTEXITCODE -ne 0) { Write-Host "sc sdset failed ($LASTEXITCODE)"; exit 1 }
Write-Host "Updated $service permissions."
