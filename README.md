# Claude IP Guard

A Windows 10/11 tray app that checks your public IP address and closes **Claude** (desktop app and
Claude Code CLI) when the IP is not in an allowed country. By default the allowed list is every
European country.

## How it works

- Checks your public IP every 30 seconds (configurable, 10–3600 s), and again right after any network
  change (Wi-Fi switch, VPN on/off, cable plugged in).
- Public IP: `api.ipify.org`, falling back to `icanhazip.com`, `checkip.amazonaws.com`, `ifconfig.me`.
- Country: `ipwho.is`, falling back to `country.is`, `freeipapi.com`, `ipapi.co`. The country is cached
  per IP for 6 hours, so the 30-second checks only make one small request.
- **Not allowed** → Claude is closed immediately, and closed again every second if it is reopened.
- **Can't verify** (offline, all services down) → Claude is blocked too (fail-safe, can be turned off).
- Uses the IP the internet sees. With a VPN, that is the VPN's country.

What gets closed:

| Setting | Processes |
|---|---|
| Claude desktop app | `claude.exe` from the Microsoft Store package (`WindowsApps\Claude_*`) or `%LocalAppData%\AnthropicClaude` |
| Claude Code CLI | any other `claude.exe` (native installer), and `node.exe` running `@anthropic-ai/claude-code` (npm install) |

## Dashboard

- **Dashboard**: status (green allowed / red blocked / amber paused), public IP, country, city,
  lookup service, last/next check, counters. Buttons: Check now, Pause/Resume, Hide to tray.
- **Activity**: log of checks, location changes and every time Claude was closed.
- **Settings**: interval, which apps to close, fail-safe, allowed countries, change password.

### Choosing countries

Settings has a picker with all 250 countries and territories, grouped into 10 regions (Europe,
North America, Central America & Caribbean, South America, Middle East & Caucasus, Central & South
Asia, East & Southeast Asia, Africa, Oceania, Antarctica & remote islands).

- Tick single countries, or tick a region to select all of its countries (a partly filled box means
  some of the region is selected; the counter shows e.g. `2/53`).
- Search by name or code (`korea`, `US`). **Select all** / **Clear all** apply to the search results.
- **Europe only** restores the default.

Example: tick United Kingdom, United States, Canada and Germany, save with your password, and
Claude will be closed whenever your IP is in any other country.
- Language: English or Persian (فارسی, right-to-left), switchable in the sidebar.

Closing the window only hides it; the app keeps running in the tray (shield icon, colored by status).
It runs until you choose **Exit program** (sidebar or tray menu).

## Password

On first launch the app asks you to create a password. It is required to **pause protection**,
**save settings**, **change the password** and **exit**. It is stored as a salted PBKDF2-SHA256 hash
in `%AppData%\ClaudeIpGuard\settings.json`, never in plain text.

Forgot it? Uninstall and delete `%AppData%\ClaudeIpGuard\` (an administrator can always end the
process in Task Manager).

## Build

Requirements: .NET 8 SDK, Inno Setup 6.

```powershell
.\build.ps1
```

Output:
- `publish\` – the self-contained app (no .NET install needed on the target PC)
- `dist\ClaudeIpGuard-Setup-1.0.0.exe` – the installer (Windows 10/11 x64)

The installer adds a Start menu shortcut (optional desktop shortcut) and an uninstaller. Setup and
uninstall wait until Claude IP Guard has been exited.

## Testing without closing Claude

```powershell
ClaudeIpGuard.exe --test-mode --simulate-country US    # pretends you are in the US, closes Notepad
ClaudeIpGuard.exe --test-mode --simulate-country DE    # pretends you are in Germany
ClaudeIpGuard.exe --test-mode --simulate-failure       # pretends the lookup fails
ClaudeIpGuard.exe --test-mode                          # real IP lookup, closes Notepad instead of Claude
```

Test mode uses its own settings file (`settings.test.json`) and can run next to the real app.

Automated self-test (kill logic against Notepad, live lookup, UI screenshots):

```powershell
dotnet run --project tests\ClaudeIpGuard.SelfTest -- C:\temp\shots
```

## Other options

- `--minimized` starts hidden in the tray.

## Project layout

```
src/ClaudeIpGuard/
  Core/          GeoIpService, ProcessGuard, GuardEngine, settings, password hashing
  Localization/  English and Persian strings
  UI/            Dashboard window, password dialog, tray icon, theme
installer/       Inno Setup script
tests/           Self-test harness
tools/           Icon generator
```
