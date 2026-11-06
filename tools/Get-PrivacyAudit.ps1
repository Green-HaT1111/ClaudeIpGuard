$ErrorActionPreference = 'Stop'
$findings = [System.Collections.Generic.List[object]]::new()
$vpnAdapters = @()
$openVpnConfigs = @()
$osCaption = ''
function Add-Finding {
 param($Id,$Severity,$TitleEn,$TitleFa,$DetailsEn,$DetailsFa,$AdviceEn,$AdviceFa)
 $findings.Add([pscustomobject]@{ Id=$Id; Severity=$Severity; TitleEn=$TitleEn; TitleFa=$TitleFa; DetailsEn=$DetailsEn; DetailsFa=$DetailsFa; AdviceEn=$AdviceEn; AdviceFa=$AdviceFa }) | Out-Null
}
try { $osCaption = (Get-CimInstance Win32_OperatingSystem).Caption } catch { $osCaption = 'Windows (unknown)' }

try {
 $svc = Get-CimInstance Win32_Service -Filter "Name='lfsvc'" -ErrorAction SilentlyContinue
 $locPolicy = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors' -ErrorAction SilentlyContinue
 $appPolicy = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' -ErrorAction SilentlyContinue
 $consent = (Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location' -Name Value -ErrorAction SilentlyContinue).Value
 $locked = ($null -eq $svc -or ($svc.State -ne 'Running' -and $svc.StartMode -eq 'Disabled')) -and $locPolicy.DisableLocation -eq 1 -and $locPolicy.DisableWindowsLocationProvider -eq 1 -and $appPolicy.LetAppsAccessLocation -eq 2 -and $consent -eq 'Deny'
 if ($locked) {
  Add-Finding 'windows-location-disabled' 'Info' 'Windows location access is restricted' 'دسترسی موقعیت مکانی ویندوز محدود شده است' 'The location service, machine policies and current-user consent deny location access.' 'سرویس مکان، سیاست‌های سیستم و مجوز کاربر فعلی دسترسی موقعیت را رد می‌کنند.' 'No action required.' 'نیازی به اقدام نیست.'
 } else {
  Add-Finding 'windows-location-enabled' 'High' 'Windows location access is not fully disabled' 'دسترسی موقعیت مکانی ویندوز کاملاً غیرفعال نیست' "Service state: $($svc.State); startup: $($svc.StartMode); user consent: $consent." "وضعیت سرویس: $($svc.State)؛ نوع راه‌اندازی: $($svc.StartMode)؛ مجوز کاربر: $consent." 'Apply the Windows location lockdown. It affects Windows apps system-wide.' 'قفل موقعیت ویندوز را اعمال کن. این تنظیم روی همه برنامه‌های ویندوز اثر دارد.'
 }
} catch {
 Add-Finding 'windows-location-audit-failed' 'Warning' 'Windows location settings could not be fully inspected' 'بررسی کامل تنظیمات موقعیت ویندوز ممکن نبود' $_.Exception.Message $_.Exception.Message 'Run the audit with administrative permission.' 'بررسی را با دسترسی مدیر اجرا کن.'
}

$claudeRoots = @((Join-Path $env:APPDATA 'Claude'))
$storePackages = Join-Path $env:LOCALAPPDATA 'Packages'
if (Test-Path $storePackages) { foreach ($p in (Get-ChildItem $storePackages -Directory -Filter 'Claude_*' -ErrorAction SilentlyContinue)) { $claudeRoots += (Join-Path $p.FullName 'LocalCache\Roaming\Claude') } }
$prefFiles = @()
foreach ($root in ($claudeRoots | Select-Object -Unique)) { if (Test-Path $root) { $prefFiles += @(Get-ChildItem -LiteralPath $root -File -Filter 'Preferences' -ErrorAction SilentlyContinue) } }
$geoAllow = $false
foreach ($file in $prefFiles) { try { if ((Get-Content -LiteralPath $file.FullName -Raw) -match '"geolocation"\s*:\s*\{[^}]{0,500}"setting"\s*:\s*1') { $geoAllow = $true } } catch {} }
if ($geoAllow) {
 Add-Finding 'claude-geolocation-allow' 'High' 'Claude profile may allow browser geolocation' 'پروفایل Claude ممکن است مکان‌یابی مرورگر را مجاز کرده باشد' 'A Chromium Preferences file contains a known geolocation allow pattern. This is heuristic, not proof of sent data.' 'در فایل Preferences کرومیوم الگویی از مجازبودن مکان‌یابی پیدا شد. این تشخیص احتمالی است و ارسال داده را ثابت نمی‌کند.' 'Keep Windows location denied and review this profile. Session and account data are not rewritten.' 'دسترسی موقعیت ویندوز را مسدود نگه دار و پروفایل را بررسی کن. داده نشست و حساب بازنویسی نمی‌شود.'
} else {
 Add-Finding 'claude-geolocation-no-allow' 'Info' 'No explicit Claude geolocation allow rule was found' 'مجوز صریح مکان‌یابی برای Claude پیدا نشد' 'No known geolocation allow entry was found in inspected Preferences files. IP-based inference remains possible.' 'مجوز صریح شناخته‌شده‌ای در فایل‌های بررسی‌شده پیدا نشد. استنباط موقعیت از IP همچنان ممکن است.' 'Keep Windows location disabled and verify VPN routing.' 'موقعیت ویندوز را غیرفعال و مسیر VPN را بررسی کن.'
}

$profileRoots = @((Join-Path $env:ProgramFiles 'OpenVPN\config'),(Join-Path $env:ProgramFiles 'OpenVPN\config-auto'),(Join-Path $env:ProgramData 'OpenVPN\config'),(Join-Path $env:USERPROFILE 'OpenVPN\config'),(Join-Path $env:APPDATA 'OpenVPN Connect\profiles'),(Join-Path $env:LOCALAPPDATA 'OpenVPN Connect\profiles')) | Where-Object { $_ -and (Test-Path $_) }
$profileFiles = @()
foreach ($root in ($profileRoots | Select-Object -Unique)) { $profileFiles += @(Get-ChildItem -LiteralPath $root -File -Filter '*.ovpn' -ErrorAction SilentlyContinue) }
$openVpnConfigs = @($profileFiles | Select-Object -ExpandProperty FullName -Unique)
$vpnAdaptersRaw = @(Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' -and ("$($_.Name) $($_.InterfaceDescription)" -match 'OpenVPN|TAP-Windows|Wintun|DCO') })
$vpnAdapters = @($vpnAdaptersRaw | ForEach-Object { $_.Name })

if ($profileFiles.Count -eq 0) {
 Add-Finding 'openvpn-profile-not-found' 'Warning' 'OpenVPN profile not found in common locations' 'پروفایل OpenVPN در مسیرهای معمول پیدا نشد' 'Without an accessible .ovpn file the app cannot verify tunnel, DNS and endpoint configuration.' 'بدون دسترسی به فایل .ovpn امکان تأیید تونل، DNS و مقصد VPN نیست.' 'Place the active .ovpn profile in an OpenVPN config folder and scan again. OpenVPN Connect may store profiles elsewhere.' 'پروفایل فعال .ovpn را در پوشه تنظیمات OpenVPN قرار بده و دوباره اسکن کن.'
} else {
 $fullTunnel=0; $dnsBlock=0; $ipv6Tunnel=0; $numericRemote=0
 foreach ($file in $profileFiles) {
  try {
   $lines=Get-Content -LiteralPath $file.FullName
   if ($lines | Where-Object { $_ -match '^\s*redirect-gateway\b' } | Select-Object -First 1) { $fullTunnel++ }
   if ($lines | Where-Object { $_ -match '^\s*block-outside-dns\b' } | Select-Object -First 1) { $dnsBlock++ }
   if ($lines | Where-Object { $_ -match '^\s*redirect-gateway\b.*\bipv6\b|^\s*route-ipv6\s+::/0\b' } | Select-Object -First 1) { $ipv6Tunnel++ }
   $remotes=@($lines | Where-Object { $_ -match '^\s*remote\s+' })
   if ($remotes.Count -gt 0 -and @($remotes | Where-Object { $_ -notmatch '^\s*remote\s+(\d{1,3}\.){3}\d{1,3}\s+' -and $_ -notmatch '^\s*remote\s+\[[0-9a-fA-F:]+\]\s+' }).Count -eq 0) { $numericRemote++ }
  } catch {}
 }
 if ($fullTunnel -eq 0) {
  Add-Finding 'openvpn-no-full-tunnel' 'High' 'OpenVPN profile is not configured for a full tunnel' 'پروفایل OpenVPN برای تونل کامل تنظیم نشده است' 'No inspected profile contains redirect-gateway. Some application traffic may use the normal network.' 'در پروفایل بررسی‌شده redirect-gateway وجود ندارد. ممکن است بخشی از ترافیک از شبکه عادی عبور کند.' 'Use a full-tunnel profile and reconnect before enabling the kill switch.' 'از پروفایل Full-Tunnel استفاده و پیش از فعال‌سازی Kill Switch دوباره متصل شو.'
 }
 if ($dnsBlock -eq 0) {
  Add-Finding 'openvpn-dns-outside-risk' 'High' 'OpenVPN profile has no block-outside-dns directive' 'دستور block-outside-dns در پروفایل OpenVPN وجود ندارد' 'DNS requests may escape the tunnel depending on the driver and Windows configuration.' 'بسته به درایور و تنظیمات ویندوز، احتمال خروج درخواست DNS از تونل وجود دارد.' 'Review adding block-outside-dns for the Windows OpenVPN client; support depends on the driver.' 'افزودن block-outside-dns را برای کلاینت ویندوز بررسی کن؛ پشتیبانی به درایور وابسته است.'
 }
 if ($numericRemote -eq 0) {
  Add-Finding 'openvpn-remote-dns-dependency' 'Warning' 'VPN server endpoint uses a hostname or is not statically known' 'مقصد سرور VPN به نام میزبان وابسته است یا IP ثابت آن مشخص نیست' 'Strict reconnect rules need a known VPN server IP; resolving hostnames while disconnected may require physical DNS.' 'قوانین اتصال مجدد سخت‌گیرانه به IP مشخص سرور نیاز دارند؛ حل نام میزبان هنگام قطع VPN ممکن است به DNS فیزیکی نیاز داشته باشد.' 'For strict mode, use numeric remote IP addresses or a separately verified endpoint rule.' 'برای حالت سخت‌گیرانه از IP عددی remote یا قانون مجازسازی جداگانه و تأییدشده استفاده کن.'
 }
 if ($ipv6Tunnel -eq 0) {
  Add-Finding 'openvpn-ipv6-not-routed' 'Warning' 'No explicit IPv6 tunnel route was found' 'مسیر صریح تونل IPv6 پیدا نشد' 'IPv6 on physical interfaces must be blocked to prevent bypass. IPv6 inside the tunnel requires server support.' 'برای جلوگیری از دورزدن باید IPv6 رابط فیزیکی مسدود شود. IPv6 داخل تونل به پشتیبانی سرور نیاز دارد.' 'The VPN-only firewall blocks physical-interface IPv6; do not add unsupported tunnel routes.' 'فایروال فقط-VPN، IPv6 رابط فیزیکی را می‌بندد؛ مسیر پشتیبانی‌نشده اضافه نکن.'
 }
}

if ($vpnAdapters.Count -eq 0) { Add-Finding 'vpn-adapter-not-active' 'Warning' 'No active OpenVPN tunnel adapter detected' 'آداپتور فعال تونل OpenVPN شناسایی نشد' 'A tunnel interface must be up before strict kill-switch activation.' 'برای فعال‌سازی Kill Switch رابط تونل باید فعال باشد.' 'Connect OpenVPN and scan again.' 'OpenVPN را متصل و دوباره اسکن کن.' }

$killSwitchActive=$false
try {
 $ksRules=@(Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object { $_.Name -like 'CIG_KS_*' })
 $profiles=@(Get-NetFirewallProfile)
 $blocked=$profiles.Count -ge 3 -and @($profiles | Where-Object { $_.DefaultOutboundAction -ne 'Block' }).Count -eq 0
 $hasTunnel=@($ksRules | Where-Object Name -eq 'CIG_KS_VPN_INTERFACE').Count -gt 0
 $hasEndpoint=@($ksRules | Where-Object { $_.Name -like 'CIG_KS_ENDPOINT_*' }).Count -gt 0
 $hasDhcp=@($ksRules | Where-Object Name -eq 'CIG_KS_DHCP').Count -gt 0
 $killSwitchActive=$blocked -and $hasTunnel -and $hasEndpoint -and $hasDhcp
} catch {}

$openVpnBinary=@((Join-Path $env:ProgramFiles 'OpenVPN\bin\openvpn.exe'),(Join-Path ([Environment]::GetEnvironmentVariable('ProgramFiles(x86)')) 'OpenVPN\bin\openvpn.exe')) | Where-Object { $_ -and (Test-Path $_) }
$canEnableKillSwitch=$false
if (-not $killSwitchActive -and $vpnAdapters.Count -eq 1 -and $profileFiles.Count -gt 0 -and $openVpnBinary.Count -gt 0) {
 foreach ($file in $profileFiles) {
  try {
   $lines=Get-Content -LiteralPath $file.FullName
   $hasFull=[bool]($lines | Where-Object { $_ -match '^\s*redirect-gateway\b' } | Select-Object -First 1)
   $remotes=@($lines | Where-Object { $_ -match '^\s*remote\s+' })
   $hasNumeric=$remotes.Count -gt 0 -and @($remotes | Where-Object { $_ -notmatch '^\s*remote\s+(\d{1,3}\.){3}\d{1,3}\s+' -and $_ -notmatch '^\s*remote\s+\[[0-9a-fA-F:]+\]\s+' }).Count -eq 0
   if ($hasFull -and $hasNumeric) { $canEnableKillSwitch=$true; break }
  } catch {}
 }
}
if (-not $killSwitchActive) {
 Add-Finding 'vpn-killswitch-inactive' 'High' 'System-wide VPN kill switch is not active' 'Kill Switch سراسری VPN فعال نیست' 'Without default outbound block rules, Windows may use the normal network after VPN disconnects.' 'بدون مسدودسازی پیش‌فرض خروجی، پس از قطع VPN ویندوز ممکن است از شبکه عادی استفاده کند.' 'Enable only after the active adapter and full-tunnel profile with numeric endpoint IPs are verified. This affects every app.' 'فقط پس از تأیید آداپتور فعال و پروفایل Full-Tunnel با IP عددی سرور فعال کن. این تنظیم روی همه برنامه‌ها اثر دارد.'
}

$cacheFolders=@()
foreach ($root in ($claudeRoots | Select-Object -Unique)) { foreach ($name in @('Cache','Code Cache','GPUCache','DawnCache')) { $candidate=Join-Path $root $name; if (Test-Path $candidate) { $cacheFolders += $candidate } } }
if ($cacheFolders.Count -gt 0) {
 Add-Finding 'claude-cache-present' 'Info' 'Temporary Claude cache folders found' 'پوشه‌های کش موقت Claude پیدا شدند' "$($cacheFolders.Count) cache folder(s) can be backed up and cleared. Cookies, sessions, tokens and account databases are excluded." "$($cacheFolders.Count) پوشه کش را می‌توان پشتیبان‌گیری و پاک‌سازی کرد. کوکی‌ها، نشست‌ها، توکن‌ها و پایگاه داده حساب حذف نمی‌شوند." 'Apply safe fixes while Claude is closed. Cache cleanup cannot delete historical server-side data.' 'هنگام بسته‌بودن Claude اصلاحات امن را اجرا کن. پاک‌سازی کش داده‌های قبلی سمت سرور را حذف نمی‌کند.'
}

[pscustomobject]@{ OsCaption=$osCaption; KillSwitchActive=$killSwitchActive; CanEnableKillSwitch=$canEnableKillSwitch; VpnAdapters=@($vpnAdapters); OpenVpnConfigs=@($openVpnConfigs); Findings=@($findings) } | ConvertTo-Json -Depth 7 -Compress
