[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("Enable", "Disable", "Status", "Plan")]
    [string]$Action,
    [string]$ServerAddress,
    [ValidateRange(1, 65535)]
    [int]$ServerPort = 443,
    [ValidateSet("TCP", "UDP")]
    [string]$Protocol = "TCP",
    [string]$TunnelInterfaceAlias,
    [string]$PhysicalInterfaceAlias,
    [string]$BackupDirectory = (Join-Path $env:ProgramData "ClaudeIpGuard")
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
Import-Module NetSecurity -ErrorAction Stop
$RuleGroup = "ClaudeIpGuard Kill Switch"
$BackupFile = Join-Path $BackupDirectory "firewall-backup.json"

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Run this script from an elevated PowerShell window (Run as Administrator)."
    }
}

function Assert-LocalNames {
    if ([string]::IsNullOrWhiteSpace($TunnelInterfaceAlias) -or [string]::IsNullOrWhiteSpace($PhysicalInterfaceAlias)) {
        throw "Specify both TunnelInterfaceAlias and PhysicalInterfaceAlias explicitly."
    }
    $adapter = Get-NetAdapter -Name $TunnelInterfaceAlias -ErrorAction Stop
    if ($adapter.InterfaceDescription -notmatch "TAP|OpenVPN|Wintun") {
        throw "The selected tunnel interface does not look like an OpenVPN/TAP/Wintun adapter: $($adapter.InterfaceDescription)"
    }
    $physical = Get-NetAdapter -Name $PhysicalInterfaceAlias -ErrorAction Stop
    if ($physical.Name -eq $adapter.Name) {
        throw "The physical interface and VPN tunnel interface must be different."
    }
}

function Get-ExistingKillSwitchRules {
    @(Get-NetFirewallRule -PolicyStore PersistentStore -Group $RuleGroup -ErrorAction SilentlyContinue)
}

function Remove-KillSwitchRules {
    $existing = Get-ExistingKillSwitchRules
    if ($existing.Count -gt 0) {
        $existing | Remove-NetFirewallRule -ErrorAction Stop
    }
}

function Restore-Backup {
    if (-not (Test-Path -LiteralPath $BackupFile)) {
        throw "No ClaudeIpGuard firewall backup exists at: $BackupFile"
    }
    $backup = Get-Content -LiteralPath $BackupFile -Raw | ConvertFrom-Json
    if ($backup.SchemaVersion -ne 1) {
        throw "Unsupported firewall backup version. Backup was preserved."
    }

    Remove-KillSwitchRules

    foreach ($profile in $backup.Profiles) {
        Set-NetFirewallProfile -PolicyStore PersistentStore -Profile $profile.Name -Enabled ([bool]$profile.Enabled) -DefaultInboundAction ([string]$profile.DefaultInboundAction) -DefaultOutboundAction ([string]$profile.DefaultOutboundAction) -ErrorAction Stop
    }

    foreach ($name in $backup.DisabledOutboundAllowRuleNames) {
        $rules = @(Get-NetFirewallRule -PolicyStore PersistentStore -Name $name -ErrorAction SilentlyContinue)
        foreach ($rule in $rules) {
            Set-NetFirewallRule -InputObject $rule -Enabled True -ErrorAction Stop
        }
    }

    Remove-Item -LiteralPath $BackupFile -Force
    Write-Host "Claude IP Guard firewall policy has been restored." -ForegroundColor Green
}

function Get-KillSwitchStatus {
    $profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore | Select-Object Name, Enabled, DefaultOutboundAction)
    $rules = @(Get-NetFirewallRule -PolicyStore ActiveStore -Group $RuleGroup -ErrorAction SilentlyContinue | Select-Object Name, DisplayName, Enabled, Direction, Action)
    $backupExists = Test-Path -LiteralPath $BackupFile
    [pscustomobject]@{
        BackupExists = $backupExists
        BackupFile = if ($backupExists) { $BackupFile } else { $null }
        Profiles = $profiles
        ClaudeIpGuardRules = $rules
    } | ConvertTo-Json -Depth 5
}


function Test-KillSwitchPlan {
    Assert-Administrator
    Assert-LocalNames

    $remoteIp = $null
    if ([string]::IsNullOrWhiteSpace($ServerAddress) -or -not [Net.IPAddress]::TryParse($ServerAddress, [ref]$remoteIp)) {
        throw "ServerAddress must be a literal IP address. Hostnames are not accepted by this safety script."
    }
    if ($remoteIp.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork) {
        throw "Only an IPv4 VPN endpoint is supported by this initial configuration."
    }
    if (Test-Path -LiteralPath $BackupFile) {
        throw "An existing firewall backup was found. Disable the current Kill Switch before planning a new one."
    }
    if ((Get-ExistingKillSwitchRules).Count -gt 0) {
        throw "Claude IP Guard rules already exist but no backup was found. Refusing to plan over an unknown state."
    }

    $effectiveProfiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore)
    $gpoProfiles = @($effectiveProfiles | Where-Object {
        $_.PolicyStoreSourceType -and $_.PolicyStoreSourceType.ToString() -eq "GroupPolicy"
    })
    if ($gpoProfiles.Count -gt 0) {
        throw "A Group Policy controls one or more firewall profiles. This configuration cannot safely override managed firewall policy."
    }

    $enabledOutboundAllowRules = @(Get-NetFirewallRule -PolicyStore ActiveStore -Direction Outbound -Action Allow -Enabled True)
    $unsupportedRules = @($enabledOutboundAllowRules | Where-Object {
        $_.PolicyStoreSourceType -and $_.PolicyStoreSourceType.ToString() -ne "Local"
    })
    if ($unsupportedRules.Count -gt 0) {
        $names = ($unsupportedRules | Select-Object -ExpandProperty DisplayName -Unique) -join "; "
        throw "Non-local outbound allow rules are active and cannot safely be neutralized: $names"
    }

    [pscustomobject]@{
        ChangesFirewall = $false
        ServerEndpoint = "$($remoteIp.ToString()):$ServerPort/$Protocol"
        TunnelInterfaceAlias = $TunnelInterfaceAlias
        PhysicalInterfaceAlias = $PhysicalInterfaceAlias
        ActiveProfiles = @($effectiveProfiles | Select-Object Name, Enabled, DefaultOutboundAction)
        ExistingOutboundAllowRules = $enabledOutboundAllowRules.Count
        RulesToDisable = @($enabledOutboundAllowRules | Select-Object -ExpandProperty DisplayName -Unique)
        RulesToAdd = @(
            "Allow only the configured VPN server endpoint on the physical interface",
            "Allow outbound traffic on the selected VPN tunnel interface",
            "Allow DHCP renewal to the local subnet only"
        )
        IPv6 = "Blocked by the default outbound Block policy unless an explicit outbound allow rule remains"
        BackupFile = $BackupFile
    } | ConvertTo-Json -Depth 6
}

function Enable-KillSwitch {
    Assert-Administrator
    Assert-LocalNames

    $remoteIp = $null
    if ([string]::IsNullOrWhiteSpace($ServerAddress) -or -not [Net.IPAddress]::TryParse($ServerAddress, [ref]$remoteIp)) {
        throw "ServerAddress must be a literal IP address. Hostnames are not accepted by this safety script."
    }
    if ($remoteIp.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork) {
        throw "Only the verified IPv4 VPN endpoint is supported by this initial configuration."
    }
    if (Test-Path -LiteralPath $BackupFile) {
        throw "An existing firewall backup was found. Disable the current Kill Switch first; do not overwrite the original backup."
    }
    if ((Get-ExistingKillSwitchRules).Count -gt 0) {
        throw "Claude IP Guard firewall rules already exist but no backup was found. Refusing to modify firewall state."
    }

    $profiles = @(Get-NetFirewallProfile -PolicyStore PersistentStore)
    $effectiveProfiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore)
    $gpoProfiles = @($effectiveProfiles | Where-Object {
        $_.PolicyStoreSourceType -and $_.PolicyStoreSourceType.ToString() -eq "GroupPolicy"
    })
    if ($gpoProfiles.Count -gt 0) {
        throw "A Group Policy controls one or more firewall profiles. This script will not override managed firewall policy."
    }

    $enabledOutboundAllowRules = @(Get-NetFirewallRule -PolicyStore ActiveStore -Direction Outbound -Action Allow -Enabled True)
    $unsupportedRules = @($enabledOutboundAllowRules | Where-Object {
        $_.PolicyStoreSourceType -and $_.PolicyStoreSourceType.ToString() -ne "Local"
    })
    if ($unsupportedRules.Count -gt 0) {
        $names = ($unsupportedRules | Select-Object -ExpandProperty DisplayName -Unique) -join "; "
        throw "Non-local outbound allow rules are active and cannot safely be neutralized by this script: $names"
    }

    $backup = [ordered]@{
        SchemaVersion = 1
        CreatedUtc = [DateTime]::UtcNow.ToString("o")
        Profiles = @($profiles | ForEach-Object {
            [ordered]@{
                Name = $_.Name.ToString()
                Enabled = [bool]$_.Enabled
                DefaultInboundAction = $_.DefaultInboundAction.ToString()
                DefaultOutboundAction = $_.DefaultOutboundAction.ToString()
            }
        })
        DisabledOutboundAllowRuleNames = @(
            $enabledOutboundAllowRules | ForEach-Object { $_.Name.ToString() } | Where-Object { $_ } | Sort-Object -Unique
        )
        ServerAddress = $remoteIp.ToString()
        ServerPort = $ServerPort
        Protocol = $Protocol
        TunnelInterfaceAlias = $TunnelInterfaceAlias
        PhysicalInterfaceAlias = $PhysicalInterfaceAlias
    }

    New-Item -ItemType Directory -Path $BackupDirectory -Force | Out-Null
    $backup | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $BackupFile -Encoding UTF8

    try {
        Set-NetFirewallProfile -PolicyStore PersistentStore -Profile Domain, Private, Public -Enabled True -DefaultOutboundAction Block -ErrorAction Stop

        foreach ($rule in $enabledOutboundAllowRules) {
            Disable-NetFirewallRule -InputObject $rule -ErrorAction Stop
        }

        New-NetFirewallRule -PolicyStore PersistentStore -Name "CIG_KS_VPN_ENDPOINT" -DisplayName "Claude IP Guard - OpenVPN server endpoint" -Group $RuleGroup -Direction Outbound -Action Allow -Enabled True -Profile Any -InterfaceAlias $PhysicalInterfaceAlias -RemoteAddress $remoteIp.ToString() -Protocol $Protocol -RemotePort $ServerPort -Description "Allows only the configured OpenVPN server endpoint outside the VPN tunnel." -ErrorAction Stop | Out-Null

        New-NetFirewallRule -PolicyStore PersistentStore -Name "CIG_KS_VPN_TUNNEL" -DisplayName "Claude IP Guard - VPN tunnel traffic" -Group $RuleGroup -Direction Outbound -Action Allow -Enabled True -Profile Any -InterfaceAlias $TunnelInterfaceAlias -Protocol Any -Description "Allows traffic only when Windows routes it through the configured VPN tunnel adapter." -ErrorAction Stop | Out-Null

        New-NetFirewallRule -PolicyStore PersistentStore -Name "CIG_KS_DHCP" -DisplayName "Claude IP Guard - DHCP renewal on physical adapter" -Group $RuleGroup -Direction Outbound -Action Allow -Enabled True -Profile Any -InterfaceAlias $PhysicalInterfaceAlias -Program (Join-Path $env:SystemRoot "System32\svchost.exe") -Service "Dhcp" -Protocol UDP -LocalPort 68 -RemotePort 67 -RemoteAddress LocalSubnet -Description "Allows DHCP renewal to the local subnet only; it is not a general Internet exception." -ErrorAction Stop | Out-Null

        $effective = @(Get-NetFirewallProfile -PolicyStore ActiveStore)
        $notBlocked = @($effective | Where-Object { -not $_.Enabled -or $_.DefaultOutboundAction.ToString() -ne "Block" })
        if ($notBlocked.Count -gt 0) {
            throw "Effective firewall policy did not become enabled with outbound default Block on every profile."
        }

        $effectiveRules = @(Get-NetFirewallRule -PolicyStore ActiveStore -Group $RuleGroup -ErrorAction SilentlyContinue)
        if ($effectiveRules.Count -ne 3) {
            throw "The three expected Claude IP Guard firewall exceptions were not all found in the effective policy."
        }

        $remainingAllows = @(Get-NetFirewallRule -PolicyStore ActiveStore -Direction Outbound -Action Allow -Enabled True | Where-Object { $_.Group -ne $RuleGroup })
        if ($remainingAllows.Count -gt 0) {
            $names = ($remainingAllows | Select-Object -ExpandProperty DisplayName -Unique) -join "; "
            throw "Other outbound allow rules remain active, so a complete system-wide kill switch cannot be verified: $names"
        }

        Write-Host "Claude IP Guard Kill Switch enabled." -ForegroundColor Green
        Write-Host "VPN endpoint: $($remoteIp.ToString()):$ServerPort/$Protocol"
        Write-Host "Tunnel interface: $TunnelInterfaceAlias"
        Write-Host "Physical interface: $PhysicalInterfaceAlias"
        Write-Host "Backup: $BackupFile"
        Write-Warning "All pre-existing enabled outbound allow rules were disabled and recorded for restoration."
    }
    catch {
        $failure = $_
        Write-Error "Kill Switch setup failed. Attempting to restore the previous firewall policy. $failure"
        try {
            Restore-Backup
        }
        catch {
            Write-Error "Automatic rollback also failed: $_"
            Write-Error "Do not delete the backup. Restore it with: .\tools\KillSwitch.ps1 -Action Disable"
        }
        throw $failure
    }
}

switch ($Action) {
    "Enable" { Enable-KillSwitch }
    "Disable" { Assert-Administrator; Restore-Backup }
    "Status" { Get-KillSwitchStatus }
    "Plan" { Test-KillSwitchPlan }
}
