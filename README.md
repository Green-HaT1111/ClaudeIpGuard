# Claude IP Guard

Claude IP Guard is a Windows 10 tray application that protects Claude Desktop and Claude Code with an IP-country allow-list, plus an optional Windows-wide VPN-only firewall kill switch and a privacy audit center.

> Important: No local application can guarantee that no person or service can ever infer a user's real-world location. This project reduces specific, testable disclosure paths. Claude and other online services still receive the public VPN exit IP and may infer identity or region from account information, time zone, content, or server-side records.

## Existing Claude protection

- Checks the public IP and country at a configurable interval (10–3600 seconds), and after network changes.
- Closes Claude Desktop and Claude Code when the observed public IP is outside the configured country allow-list.
- Fail-safe mode can close Claude when the location cannot be verified.
- English and Persian (right-to-left) interface, activity log, country picker, tray icon and password-protected settings.

## Privacy Center

Open **Privacy center / مرکز حریم خصوصی** from the dashboard.

The current audit checks:
- Windows Location service, machine policies and current-user location consent.
- Claude Chromium Preferences for a known explicit geolocation-allow pattern (heuristic; not proof that location data was sent).
- OpenVPN profile presence and selected directives: `redirect-gateway`, `block-outside-dns`, IPv6 routing and numeric `remote` endpoints.
- Active OpenVPN/TAP/Wintun/DCO adapter and full-tunnel routes.
- Presence of the Claude IP Guard firewall kill-switch policy and unexpected outbound allow rules.
- Temporary Claude cache folders.

Findings explain the risk and recommended action in English and Persian. Audit results are local; the audit itself does not call online IP/geolocation services.

## Safe remediation

**Apply safe fixes** requests administrator permission and:
- Saves the current Windows location service/policy/consent settings under `%ProgramData%\ClaudeIpGuard\privacy-settings-backup.json`.
- Denies Windows app location access, disables/stops the Windows Location service and flushes the Windows DNS resolver cache.
- When Claude Desktop and Claude Code are closed, backs up and clears only temporary Claude cache folders (`Cache`, `Code Cache`, `GPUCache`, `DawnCache`).

The cleanup deliberately does not touch browser cookies, Local Storage, IndexedDB, login databases, account tokens, credentials or Claude session databases. Cache backup folders are retained under `%ProgramData%\ClaudeIpGuard\Claude-cache-backup-*`.

Use **Restore location settings** to restore the saved Windows location settings. It does not restore deleted cache folders; those backups remain available for manual recovery.

## VPN-only Windows Firewall kill switch

The strict kill switch is intentionally Windows-wide, matching the selected "Option C" behaviour: while active, only traffic through the verified VPN tunnel and the exact OpenVPN server endpoint(s) is allowed. If the tunnel drops, ordinary outbound internet access for every application is blocked, not only Claude. Inbound/default Windows Firewall behaviour is not changed.

Before the UI enables activation, it looks for one active OpenVPN tunnel adapter, a full-tunnel `.ovpn` profile and numeric server IP endpoints. The elevated script validates that the active default/split-default IPv4 route uses the selected tunnel. It refuses to proceed when:
- The profile does not contain `redirect-gateway`.
- A VPN server endpoint is a hostname rather than a numeric IP (strict reconnect must not require physical-interface DNS).
- The tunnel route is not active.
- Group Policy manages an outbound allow rule.
- Windows Firewall profiles are disabled.

Activation stores the previous firewall profile outbound actions and enabled outbound allow rules, then applies default outbound block and adds narrowly scoped VPN-interface, VPN-endpoint and DHCP rules. It also checks that no other enabled outbound allow rules remain. If verification fails, it attempts to roll back.

Use **Restore firewall** or run `Tools\Restore-VpnKillSwitch.ps1` as Administrator to restore the saved firewall settings. Do not delete `%ProgramData%\ClaudeIpGuard\firewall-backup.json` while the kill switch is active.

The kill switch does not modify the OpenVPN profile automatically. Review provider/client guidance for a full-tunnel profile and Windows DNS protection. `block-outside-dns` support depends on the OpenVPN Windows client and driver. A numeric `remote` IP is required for strict reconnect without physical DNS; a provider hostname may change over time, so update the profile and revalidate before enabling the switch again.

## Important limitations

- The VPN exit IP is still visible to Claude and its service providers. IP geolocation is approximate, not GPS.
- Disabling Windows Location prevents apps relying on that Windows location provider; it does not disable location data already held by websites/accounts.
- The audit only inspects known local Claude profile locations and known Chromium preference patterns. It cannot inspect Anthropic's server-side account records.
- The VPN-only kill switch is system-wide by design and can interrupt browsers, email, updates, cloud sync and all other applications whenever VPN is disconnected.
- Windows Firewall rules are not an atomic transaction. There is a short transition period while default outbound blocking is applied and pre-existing allow rules are disabled. Keep the device connected to power and do not interrupt the activation script.
- A local administrator or kernel-level malware can change firewall policies or observe the system. No application can defend against every privileged adversary.
- The original IP-country feature contacts external IP/geolocation providers only after the local preflight confirms the VPN kill switch and a live OpenVPN route. If that preflight fails, it fails closed and does not contact those providers.

## Build

Requirements: Windows 10/11 x64, .NET 8 SDK, Inno Setup 6.

```powershell
.\build.ps1
```

Output:
- `publish\` — self-contained app and required PowerShell tools.
- `dist\ClaudeIpGuard-Setup-1.0.0.exe` — installer.

## Tests

```powershell
dotnet build ClaudeIpGuard.sln -c Release
dotnet run --project tests\ClaudeIpGuard.SelfTest -c Release
```

The GitHub Actions workflow on the privacy-hardening branch parses the PowerShell files, builds on Windows, runs the self-test and produces release artifacts.

## Project layout

```
src/ClaudeIpGuard/
  Core/          GeoIP guard, privacy audit, VPN preflight, process guard, settings
  Localization/  English and Persian strings
  UI/            Dashboard, privacy center, settings, tray
tools/           Privacy audit/remediation/rollback scripts and icon generator
installer/       Inno Setup installer
tests/           Self-test harness
.github/         Windows CI build and test workflow
```
