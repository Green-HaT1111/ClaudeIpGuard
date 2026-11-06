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
- **Time zone**: after each check the Windows time zone is set to the one of the IP's location
  (IP in England → `(UTC+00:00) London`), using `tzutil` (no admin needed). Can be turned off in
  Settings. Turn off Windows "Set time zone automatically", or Windows may change it back.

What gets closed:

| Setting | Processes |
|---|---|
| Claude desktop app | every process running from the desktop app's folder, whatever its name (Microsoft Store package `WindowsApps\Claude_*`, or `%LocalAppData%\AnthropicClaude`), the Claude Code copy it downloads to `%AppData%\Claude\`, and its background service `CoworkVMService` |
| Claude Code CLI | any other `claude.exe` (native installer), and `node.exe` running `@anthropic-ai/claude-code` (npm install) |

The installer gives normal users permission to stop `CoworkVMService` if they don't have it already,
so the guard doesn't need admin rights for it. Uninstall removes that permission again.

## Dashboard

- **Dashboard**: status (green allowed / red blocked / amber paused), public IP, country, city,
  lookup service, last/next check, counters. Buttons: Check now, Pause/Resume, Hide to tray.
- **Activity**: log of checks, location changes and every time Claude was closed.
- **Leak check**: other ways the real location can be seen besides the IP (see below).
- **Browser data**: data saved by your browsers that can show your real location (see below), with a
  button to clear what you tick.
- **Settings**: interval, which apps to close, fail-safe, time zone sync, allowed countries, change password.

### Browser data

Checks Chrome, Edge, Brave, Vivaldi, Opera, Opera GX, Yandex, Chromium, Firefox, LibreWolf and Waterfox
(all profiles) at start, every 30 minutes and whenever the IP country changes. When it finds data that
shows your location, a banner appears on the dashboard, a Windows notification pops up from the tray icon,
and the Activity log gets a line. Nothing is cleared until you tick items and press **Clear selected**.

| Item | Ticked by default | Signs you out? | What clearing does |
|---|---|---|---|
| Remembered country (Chromium `Local State` `variations_*country`, Firefox `*region*` prefs) | yes | no | browser saves the country of the current IP on next start |
| Sites allowed to see your location | yes | no | sites must ask again |
| Location cookies (only cookies named like `country`, `geo`, `region`, `city`, `timezone`, `currency`...) | yes | no | only those cookies are deleted, one by one |
| Cache | yes | no | pages load slower once |
| Site storage (local storage, IndexedDB, service workers; websites only, not extensions) | no | some sites | the sites are listed |
| All cookies | no | yes | the sites you'd be signed out of are listed |
| History (Chromium only; Firefox keeps it with bookmarks) | no | no | visited pages and suggestions removed |

Only items that can't sign you out are ticked by default. Before anything is deleted, a confirmation
window lists every item and, in red, every site you would be signed out of (sign-in cookies such as
`SID`, `session`, `auth`, `token`) or that would lose its saved data; only **Clear** deletes.

Open browsers lock their cookies, so the app first asks to close them (nothing is deleted at that point),
reads everything, and then shows the confirmation. A remembered country that differs from the current
IP's country is marked red. Passwords, bookmarks and extensions are never touched. In test mode
nothing is cleared.

### Leak check

Runs automatically the first time the page is opened, and again with **Run check**. Read-only:
it never changes any setting. Each item is marked Leak / Warning / OK / Info.

| Check | What it looks at |
|---|---|
| VPN routing and kill switch | Which adapter carries internet traffic, and whether a normal adapter would take over if the VPN drops |
| IPv6 leak | Whether there is a public IPv6 address and whether it is in a different country than the IPv4 address |
| DNS leak | Which DNS server answers your requests (via `o-o.myaddr.l.google.com`) and its country; EDNS client subnet |
| Time zone | Windows time zone vs. the time zone of the IP location |
| Windows region | Windows home location vs. the IP country |
| Languages | Display and installed languages |
| Windows location service | Whether GPS / Wi-Fi positioning is on |
| IP type | Whether the IP belongs to a server or hosting company (easy to detect as VPN) |
| System proxy | Whether a system proxy is on (apps and UDP traffic can bypass it) |
| WebRTC | Not testable from a desktop app; reminder to test in the browser |

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
- `dist\ClaudeIpGuard-Setup-1.1.0.exe` – the installer (Windows 10/11 x64)

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
