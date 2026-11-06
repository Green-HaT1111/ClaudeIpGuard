// Self-test for Claude IP Guard. Never touches Claude: the kill tests target Notepad.
//   dotnet run --project tests\ClaudeIpGuard.SelfTest [-- <folder for UI screenshots>]
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using ClaudeIpGuard.Core;
using ClaudeIpGuard.Localization;
using ClaudeIpGuard.UI;

int failures = 0;
void Check(bool ok, string name)
{
    Console.WriteLine($"{(ok ? "PASS" : "FAIL")}  {name}");
    if (!ok) failures++;
}

var tempData = Path.Combine(Path.GetTempPath(), "ClaudeIpGuardSelfTest");
AppPaths.DataDirectory = tempData;

// 1. Settings + password
{
    var store = new SettingsStore("t.json", tempData);
    var s = new AppSettings();
    PasswordHasher.SetPassword(s, "secret1");
    store.Save(s);
    var loaded = store.Load();
    Check(PasswordHasher.Verify(loaded, "secret1"), "password verifies after save/load");
    Check(!PasswordHasher.Verify(loaded, "wrong"), "wrong password rejected");
    Check(!File.ReadAllText(store.FilePath).Contains("secret1"), "password not stored in plain text");
    Check(loaded.AllowedCountries.Contains("DE") && !loaded.AllowedCountries.Contains("US"), "default list is Europe");
    var all = Countries.Regions.SelectMany(r => r.Countries).ToList();
    Console.WriteLine($"      country list: {all.Count} countries in {Countries.Regions.Count} regions");
    Check(all.Count >= 245 && all.Select(c => c.Code).Distinct().Count() == all.Count, "full world list, no duplicate codes");
    Check(EuropeCountries.Default.Length == 53, "Europe region has 53 entries");

    var picker = new CountryPicker();
    picker.SetSelection(new[] { "GB", "US", "CA", "DE" });
    Check(picker.SelectedCodes.SequenceEqual(new[] { "CA", "DE", "GB", "US" }), "picker: pick UK, USA, Canada, Germany");
    var na = picker.Regions.First(r => r.Countries.Any(c => c.Code == "US"));
    Check(na.IsChecked == null && na.CountText == "2/6", "picker: region shows partial selection");
    na.IsChecked = true;
    Check(na.IsChecked == true && picker.SelectedCodes.Contains("MX"), "picker: ticking a region selects all its countries");
    na.IsChecked = false;
    Check(!picker.SelectedCodes.Contains("US") && picker.SelectedCodes.Contains("GB"), "picker: unticking a region clears only that region");
    picker.SearchText = "japan";
    Check(picker.Regions.Count(r => r.Visibility == Visibility.Visible) == 1, "picker: search filters to matching region");
    picker.SetVisible(true);
    picker.SearchText = "";
    Check(picker.SelectedCodes.SequenceEqual(new[] { "DE", "GB", "JP" }), "picker: select all applies to search results only");
}

// 2. Classification of Claude processes
Check(ProcessGuard.IsDesktopPath(@"C:\Program Files\WindowsApps\Claude_4.4212.0.0_x64__pzs8sxrjxfjjc\app\Claude.exe"), "Store desktop path detected");
Check(ProcessGuard.IsDesktopPath(@"C:\Users\x\AppData\Local\AnthropicClaude\app-1.0\claude.exe"), "classic desktop path detected");
Check(!ProcessGuard.IsDesktopPath(@"C:\Users\x\.local\bin\claude.exe"), "CLI path is not desktop");
Check(ProcessGuard.IsClaudeCliCommandLine(@"node C:\npm\node_modules\@anthropic-ai\claude-code\cli.js"), "npm CLI command line detected");
Check(ProcessGuard.IsDesktopPath(@"C:\Program Files\WindowsApps\Claude_4.23118.0.0_x64__pzs8sxrjxfjjc\app\resources\cowork-svc.exe"), "desktop helper with another name detected");
Check(ProcessGuard.IsDesktopBundledCliPath(@"C:\Users\x\AppData\Roaming\Claude\claude-code\2.1.317\a33aa5518497\claude.exe"), "desktop's bundled Claude Code detected");
Check(!ProcessGuard.IsDesktopBundledCliPath(@"C:\Users\x\.local\bin\claude.exe"), "standalone CLI is not desktop-bundled");
{
    // Read-only: every claude.exe running now (user session) must be found. Nothing is killed here.
    var found = new ProcessGuard().FindTargets(new AppSettings { KillDesktopApp = true, KillCli = true })
        .Select(t => t.Pid).ToHashSet();
    var running = new List<int>();
    foreach (var p in System.Diagnostics.Process.GetProcessesByName("claude"))
        using (p) if (p.SessionId != 0) running.Add(p.Id);
    Check(running.All(found.Contains), $"finds all running claude.exe ({running.Count} running, {found.Count} targets)");
    Check(!found.Contains(Environment.ProcessId), "never targets itself");
}
{
    // Fake desktop install: copies of cmd.exe (as claude.exe) and ping.exe (as a helper with another
    // name) in a folder that looks like the desktop app's. Only these fake processes are killed.
    var fakeDir = Path.Combine(tempData, "Programs", "Claude");
    Directory.CreateDirectory(fakeDir);
    var fakeClaude = Path.Combine(fakeDir, "claude.exe");
    var fakeHelper = Path.Combine(fakeDir, "helper-svc.exe");
    File.Copy(Path.Combine(Environment.SystemDirectory, "cmd.exe"), fakeClaude, true);
    File.Copy(Path.Combine(Environment.SystemDirectory, "PING.EXE"), fakeHelper, true);

    Process StartFake() => Process.Start(new ProcessStartInfo(fakeClaude, $"/c \"\"{fakeHelper}\" -n 60 127.0.0.1\"")
        { CreateNoWindow = true, UseShellExecute = false, RedirectStandardOutput = true })!;
    List<int> FakePids()
    {
        var pids = new List<int>();
        foreach (var p in Process.GetProcesses())
            using (p)
                try { if (p.MainModule?.FileName.StartsWith(fakeDir, StringComparison.OrdinalIgnoreCase) == true) pids.Add(p.Id); }
                catch { }
        return pids;
    }

    var first = StartFake();
    Thread.Sleep(1000);
    first.Kill(entireProcessTree: false); // leaves its helper behind with no parent
    first.WaitForExit();
    using var second = StartFake();
    Thread.Sleep(1000);
    try
    {
        var fake = FakePids();
        var targets = new ProcessGuard().FindTargets(new AppSettings { KillDesktopApp = true, KillCli = false });
        var desktopPids = targets.Where(t => t.Kind == TargetKind.Desktop).Select(t => t.Pid).ToHashSet();
        Check(fake.Count == 3, $"fake desktop started (claude + helper, plus a helper left behind): {fake.Count} processes");
        Check(fake.All(desktopPids.Contains), "finds every fake desktop process, incl. other-named and orphaned helpers");
    }
    finally
    {
        foreach (var pid in FakePids())
            try { using var p = Process.GetProcessById(pid); p.Kill(true); p.WaitForExit(3000); } catch { }
        first.Dispose();
    }
    Check(FakePids().Count == 0, "fake desktop processes cleaned up");
}
{
    // Can this (non-admin) user stop Claude's service? Only asks Windows for the right; does not stop it.
    var scm = OpenSCManager(null, null, 0x1 /* connect */);
    var svc = scm == IntPtr.Zero ? IntPtr.Zero : OpenService(scm, ProcessGuard.DesktopServiceName, 0x24 /* query status + stop */);
    int err = Marshal.GetLastWin32Error();
    if (svc != IntPtr.Zero) Check(true, $"this user may stop {ProcessGuard.DesktopServiceName} (not stopped)");
    else if (err == 1060) Console.WriteLine($"      skip: {ProcessGuard.DesktopServiceName} is not installed");
    else Check(false, $"this user may stop {ProcessGuard.DesktopServiceName}: Windows error {err}");
    if (svc != IntPtr.Zero) CloseServiceHandle(svc);
    if (scm != IntPtr.Zero) CloseServiceHandle(scm);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern IntPtr OpenSCManager(string? machine, string? database, uint access);
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern IntPtr OpenService(IntPtr scm, string name, uint access);
    [DllImport("advapi32.dll")]
    static extern bool CloseServiceHandle(IntPtr handle);
}

// The guard must not run as a child of Claude (it would be closed together with Claude)
Check(SelfLaunch.IsClaude("claude.exe", @"C:\Users\x\.local\bin\claude.exe"), "self-launch: Claude Code CLI is a Claude parent");
Check(SelfLaunch.IsClaude("Claude.exe", @"C:\Program Files\WindowsApps\Claude_4.1_x64__abc\app\Claude.exe"), "self-launch: Claude desktop is a Claude parent");
Check(!SelfLaunch.IsClaude("explorer.exe", @"C:\Windows\explorer.exe") && !SelfLaunch.IsClaude("ClaudeIpGuard.exe", @"C:\Program Files\Claude IP Guard\ClaudeIpGuard.exe"),
    "self-launch: Explorer and the guard itself are not");
Console.WriteLine($"      self-launch: this self-test was started from inside Claude: {SelfLaunch.StartedByClaude()}");

// Kill switch: what the firewall rules would block (nothing is changed here)
{
    // Example VPN servers from the documentation address ranges (RFC 5737), not real servers.
    var vpnA = "198.51.100.10";
    var vpnB = "203.0.113.20";
    var ranges = KillSwitch.PublicRangesExcept(new[] { vpnA, vpnB }).Split(',');
    bool Blocked(string ip)
    {
        var b = System.Net.IPAddress.Parse(ip).GetAddressBytes();
        uint v = (uint)(b[0] << 24 | b[1] << 16 | b[2] << 8 | b[3]);
        return ranges.Any(r =>
        {
            var p = r.Split('-').Select(x => System.Net.IPAddress.Parse(x).GetAddressBytes()).Select(x => (uint)(x[0] << 24 | x[1] << 16 | x[2] << 8 | x[3])).ToArray();
            return v >= p[0] && v <= p[1];
        });
    }
    Check(!Blocked(vpnA) && !Blocked(vpnB), "kill switch: both VPN servers allowed");
    Check(Blocked("198.51.100.9") && Blocked("198.51.100.11") && Blocked("1.1.1.1") && Blocked("8.8.8.8") && Blocked("192.0.2.30"),
        "kill switch: the rest of the internet blocked (1.1.1.1, 8.8.8.8, neighbours of the VPN server)");
    Check(!Blocked("192.168.1.1") && !Blocked("10.0.0.5") && !Blocked("172.16.3.3") && !Blocked("169.254.1.1") && !Blocked("224.0.0.251") && !Blocked("255.255.255.255"),
        "kill switch: local network, router, DHCP and multicast stay open");

    var profiles = Path.Combine(tempData, "ovpn");
    Directory.CreateDirectory(profiles);
    File.WriteAllText(Path.Combine(profiles, "a.ovpn"), $"client\nremote {vpnA} 443 tcp\nremote-cert-tls server\n");
    File.WriteAllText(Path.Combine(profiles, "b.ovpn"), $"client\n  remote {vpnB} 443\n");
    Check(KillSwitch.FindVpnServers(new[] { profiles }).SequenceEqual(new[] { vpnA, vpnB }),
        "kill switch: VPN servers read from .ovpn profiles (remote-cert-tls ignored)");

    // Never block a VPN adapter (that would cut the VPN itself).
    var adapters = KillSwitch.PhysicalAdapters();
    var vpnLike = new System.Text.RegularExpressions.Regex("TAP|TUN|Wintun|WireGuard|OpenVPN|VPN", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
    var blocksVpn = System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces()
        .Any(n => adapters.Contains(n.Name) && vpnLike.IsMatch(n.Description));
    Console.WriteLine($"      kill switch adapters here: {string.Join(", ", adapters)}");
    Check(!blocksVpn, "kill switch: never blocks a VPN adapter");
    Console.WriteLine($"      kill switch now: {(KillSwitch.Read().On ? "on" : "off")}");

    var buildError = KillSwitch.TryBuildRules(new[] { vpnA, vpnB }, adapters.Count > 0 ? adapters : new List<string> { "Wi-Fi" });
    Check(buildError == null, "kill switch: Windows accepts both firewall rules (built, not added)" + (buildError != null ? ": " + buildError : ""));
    Check(!KillSwitch.Description(new[] { vpnA, vpnB }, adapters).Contains('|'),
        "kill switch: rule description has no '|' (Windows refuses it when adding the rule)");
}

// Time zone: IP location -> Windows time zone (dry run, the real time zone is not changed here)
Check(TimeZoneSync.ToWindowsId("Europe/London") == "GMT Standard Time", "England (Europe/London) -> GMT Standard Time");
Check(TimeZoneSync.ToWindowsId("Asia/Tehran") == "Iran Standard Time", "Iran (Asia/Tehran) -> Iran Standard Time");
Check(TimeZoneSync.ToWindowsId("America/New_York") == "Eastern Standard Time", "New York -> Eastern Standard Time");
Check(TimeZoneSync.ToWindowsId("Not/AZone") == null && TimeZoneSync.ToWindowsId(null) == null, "unknown time zone -> nothing");
{
    var tzs = new TimeZoneSync(dryRun: true);
    var target = TimeZoneInfo.Local.Id == "Tokyo Standard Time" ? "Europe/Paris" : "Asia/Tokyo";
    var first = tzs.Apply(target);
    var second = tzs.Apply(target);
    Check(first.Outcome == TzOutcome.Changed && second.Outcome == TzOutcome.AlreadySet, "time zone changed once, then left alone");
    Check(tzs.Apply(null).Outcome == TzOutcome.Unknown, "no time zone from the IP service: nothing changed");
}

// Browser data: fake Chrome + Firefox profiles in a temp folder (real browsers are only read, never cleaned)
{
    var root = Path.Combine(tempData, "browsers");
    if (Directory.Exists(root)) Directory.Delete(root, true);
    var local = Path.Combine(root, "Local");
    var roaming = Path.Combine(root, "Roaming");
    void Put(string path, string text) { Directory.CreateDirectory(Path.GetDirectoryName(path)!); File.WriteAllText(path, text); }

    var chrome = Path.Combine(local, @"Google\Chrome\User Data");
    Put(Path.Combine(chrome, "Local State"),
        """{"variations_country":"gb","variations_permanent_consistency_country":["156.0","ir"],"profile":{"info_cache":{"Default":{"name":"Person 1"}}},"keep_me":1}""");
    var cp = Path.Combine(chrome, "Default");
    Put(Path.Combine(cp, "Preferences"),
        """{"profile":{"content_settings":{"exceptions":{"geolocation":{"https://maps.example,*":{"setting":1}},"cookies":{"a":1}}}},"keep_me":2}""");
    Put(Path.Combine(cp, @"Cache\Cache_Data\f_000001"), new string('x', 5000));
    void CookieDb(string path, bool firefox, params (string Host, string Name)[] cookies)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        using var c = new Microsoft.Data.Sqlite.SqliteConnection($"Data Source={path};Pooling=False");
        c.Open();
        using var cmd = c.CreateCommand();
        cmd.CommandText = firefox
            ? "CREATE TABLE moz_cookies (id INTEGER PRIMARY KEY, host TEXT, name TEXT, value TEXT)"
            : "CREATE TABLE cookies (host_key TEXT, name TEXT, value TEXT, encrypted_value BLOB)";
        cmd.ExecuteNonQuery();
        foreach (var (host, name) in cookies)
        {
            cmd.CommandText = firefox ? "INSERT INTO moz_cookies (host, name, value) VALUES ($h, $n, 'v')" : "INSERT INTO cookies (host_key, name, value) VALUES ($h, $n, 'v')";
            cmd.Parameters.Clear();
            cmd.Parameters.AddWithValue("$h", host);
            cmd.Parameters.AddWithValue("$n", name);
            cmd.ExecuteNonQuery();
        }
    }
    List<string> CookieNames(string path, bool firefox)
    {
        using var c = new Microsoft.Data.Sqlite.SqliteConnection($"Data Source={path};Pooling=False;Mode=ReadOnly");
        c.Open();
        using var cmd = c.CreateCommand();
        cmd.CommandText = firefox ? "SELECT name FROM moz_cookies ORDER BY name" : "SELECT name FROM cookies ORDER BY name";
        var names = new List<string>();
        using var r = cmd.ExecuteReader();
        while (r.Read()) names.Add(r.GetString(0));
        return names;
    }
    CookieDb(Path.Combine(cp, @"Network\Cookies"), false,
        (".booking.com", "country_code"), (".weather.example", "geo_city"), (".shop.example", "currency"),
        (".github.com", "user_session"), (".google.com", "SID"), ("www.google.com", "__Secure-1PSID"), (".news.example", "_ga"));
    Put(Path.Combine(cp, @"Local Storage\leveldb\000004.log"), "xx_https://web.telegram.org\0\u0001token");
    Put(Path.Combine(cp, "History"), "history");
    Put(Path.Combine(cp, @"Local Storage\leveldb\000003.log"), "storage");
    Put(Path.Combine(cp, @"IndexedDB\https_site.example_0.indexeddb.leveldb\000003.log"), "site idb");
    Put(Path.Combine(cp, @"IndexedDB\chrome-extension_abc_0.indexeddb.leveldb\000003.log"), "extension idb");
    Put(Path.Combine(cp, "Login Data"), "passwords");
    Put(Path.Combine(cp, "Bookmarks"), "bookmarks");

    var fp = Path.Combine(roaming, @"Mozilla\Firefox\Profiles\abc.default-release");
    Put(Path.Combine(fp, "prefs.js"), "user_pref(\"browser.search.region\", \"IR\");\r\nuser_pref(\"browser.startup.page\", 3);\r\n");
    CookieDb(Path.Combine(fp, "cookies.sqlite"), true, (".weather.example", "loc"), (".mail.example", "sessionid"));
    Put(Path.Combine(fp, @"storage\default\https+++site.example\ls\data.sqlite"), "site");
    Put(Path.Combine(fp, @"storage\default\moz-extension+++abc\idb\x.sqlite"), "extension");
    Put(Path.Combine(fp, "places.sqlite"), "bookmarks and history");
    Put(Path.Combine(local, @"Mozilla\Firefox\Profiles\abc.default-release\cache2\entries\ABC"), new string('y', 3000));

    var scanner = new BrowserDataScanner(local, roaming);
    var found = scanner.Scan("GB");
    BrowserDataItem? Find(string browser, BrowserDataKind kind) => found.FirstOrDefault(i => i.Browser.Name == browser && i.Kind == kind);
    var chromeCountry = Find("Google Chrome", BrowserDataKind.CountryMemory);
    Check(scanner.FindBrowsers().Select(b => b.Name).SequenceEqual(new[] { "Google Chrome", "Mozilla Firefox" }), "browser data: finds the fake Chrome and Firefox");
    Check(chromeCountry is { Risk: BrowserDataRisk.Problem } && chromeCountry.Countries.SequenceEqual(new[] { "GB", "IR" }),
        "browser data: Chrome remembers Iran while IP is UK -> problem");
    Check(Find("Google Chrome", BrowserDataKind.LocationPermissions) is { Count: 1, Risk: BrowserDataRisk.Warning }, "browser data: 1 site allowed to see location");
    Check(new[] { BrowserDataKind.Cache, BrowserDataKind.SiteStorage, BrowserDataKind.Cookies, BrowserDataKind.History }
        .All(k => Find("Google Chrome", k) != null), "browser data: Chrome cache, site storage, cookies, history found");
    Check(Find("Google Chrome", BrowserDataKind.Cache)!.ProfileName == "Person 1", "browser data: profile shown by its name");
    Check(Find("Mozilla Firefox", BrowserDataKind.CountryMemory) is { Risk: BrowserDataRisk.Problem } &&
          Find("Mozilla Firefox", BrowserDataKind.Cache) != null && Find("Mozilla Firefox", BrowserDataKind.Cookies) != null,
        "browser data: Firefox region, cache, cookies found");
    Check(scanner.Scan("IR").First(i => i.Kind == BrowserDataKind.CountryMemory && i.Browser.Name == "Mozilla Firefox").Risk == BrowserDataRisk.Info,
        "browser data: remembered country = IP country -> not a problem");

    // Location cookies only: every sign-in cookie must survive.
    var chromeLoc = Find("Google Chrome", BrowserDataKind.LocationCookies);
    Check(chromeLoc is { Count: 3, CanSignOut: false } && chromeLoc.Sites.SequenceEqual(new[] { "booking.com", "shop.example", "weather.example" }),
        "browser data: 3 location cookies found (country_code, geo_city, currency)");
    var chromeAll = Find("Google Chrome", BrowserDataKind.Cookies);
    Check(chromeAll is { CanSignOut: true, SiteTotal: 6 } && chromeAll.Sites.SequenceEqual(new[] { "github.com", "google.com" }),
        "browser data: all cookies -> sign-out list is exactly github.com, google.com");
    Check(chromeAll!.OtherSites.SequenceEqual(new[] { "booking.com", "news.example", "shop.example", "weather.example" }),
        "browser data: all cookies -> the other 4 cookie sites are listed too");
    Check(Find("Google Chrome", BrowserDataKind.SiteStorage) is { CanSignOut: true } storageItem &&
          storageItem.Sites.Contains("web.telegram.org") && storageItem.Sites.Contains("site.example"),
        "browser data: site storage lists its sites (web.telegram.org, site.example)");
    var locOnly = scanner.Clean(found.Where(i => i.Kind == BrowserDataKind.LocationCookies));
    Check(locOnly.Cleaned == 2, "browser data: location cookies cleared in Chrome and Firefox");
    Check(CookieNames(Path.Combine(cp, @"Network\Cookies"), false).ToHashSet().SetEquals(new[] { "SID", "_ga", "__Secure-1PSID", "user_session" }),
        "browser data: Chrome sign-in cookies kept (SID, __Secure-1PSID, user_session)");
    Check(CookieNames(Path.Combine(fp, "cookies.sqlite"), true).SequenceEqual(new[] { "sessionid" }), "browser data: Firefox sign-in cookie kept");
    Check(scanner.Scan("GB").All(i => i.Kind != BrowserDataKind.LocationCookies), "browser data: no location cookies left");
    found = scanner.Scan("GB");

    var result = scanner.Clean(found);
    Check(result.Cleaned == found.Count && result.FilesSkipped == 0, $"browser data: cleared {result.Cleaned}/{found.Count} items");
    var state = File.ReadAllText(Path.Combine(chrome, "Local State"));
    Check(!state.Contains("variations_country") && !state.Contains("variations_permanent") && state.Contains("keep_me"), "browser data: Chrome country removed, other settings kept");
    var prefs = File.ReadAllText(Path.Combine(cp, "Preferences"));
    Check(!prefs.Contains("maps.example") && prefs.Contains("\"cookies\":{\"a\":1}") && prefs.Contains("keep_me"), "browser data: location permission removed, other settings kept");
    Check(!Directory.Exists(Path.Combine(cp, "Cache")) && !File.Exists(Path.Combine(cp, @"Network\Cookies")) && !File.Exists(Path.Combine(cp, "History")),
        "browser data: Chrome cache, cookies, history deleted");
    Check(File.Exists(Path.Combine(cp, "Login Data")) && File.Exists(Path.Combine(cp, "Bookmarks")) &&
          Directory.Exists(Path.Combine(cp, @"IndexedDB\chrome-extension_abc_0.indexeddb.leveldb")) &&
          !Directory.Exists(Path.Combine(cp, @"IndexedDB\https_site.example_0.indexeddb.leveldb")),
        "browser data: passwords, bookmarks, extension data kept");
    var ffPrefs = File.ReadAllText(Path.Combine(fp, "prefs.js"));
    Check(!ffPrefs.Contains("region") && ffPrefs.Contains("browser.startup.page"), "browser data: Firefox region removed, other prefs kept");
    Check(File.Exists(Path.Combine(fp, "places.sqlite")) && Directory.Exists(Path.Combine(fp, @"storage\default\moz-extension+++abc")) &&
          !Directory.Exists(Path.Combine(fp, @"storage\default\https+++site.example")) && !File.Exists(Path.Combine(fp, "cookies.sqlite")),
        "browser data: Firefox bookmarks + extension data kept, site data deleted");
    Check(scanner.Scan("GB").Count == 0, "browser data: nothing left after clearing");

    // Read-only look at this PC's real browsers.
    var real = new BrowserDataScanner().Scan("GB");
    foreach (var g in real.GroupBy(i => i.Browser.Name))
        Console.WriteLine($"      real {g.Key}: " + string.Join(", ", g.GroupBy(i => i.Kind).Select(k =>
            k.Key + (k.Key == BrowserDataKind.CountryMemory ? "=" + string.Join("/", k.SelectMany(i => i.Countries)) : $" {k.Sum(i => i.Bytes) / 1048576} MB"))));
}

// 3. Live IP lookup
using (var geo = new GeoIpService())
{
    try
    {
        var r = await geo.LocateAsync(CancellationToken.None);
        Console.WriteLine($"      live result: {r.Ip} -> {r.CountryName} ({r.CountryCode}), {r.City}, via {r.Provider}");
        Check(r.CountryCode.Length == 2, "live IP + country lookup");
        var liveTz = TimeZoneSync.ToWindowsId(r.TimeZone);
        Console.WriteLine($"      live time zone: {r.TimeZone ?? "(none)"} -> {liveTz ?? "(none)"}; Windows now: {TimeZoneInfo.Local.Id}");
        Check(liveTz != null, "live lookup gives a time zone Windows knows");
        var sw = Stopwatch.StartNew();
        await geo.LocateAsync(CancellationToken.None);
        Console.WriteLine($"      second (cached country) lookup took {sw.ElapsedMilliseconds} ms");
    }
    catch (Exception ex)
    {
        Check(false, "live IP + country lookup: " + ex.Message);
    }
}

// 4. Engine against Notepad
async Task<bool> NotepadAliveAfter(GuardEngine engine, int ms)
{
    await Task.Delay(ms);
    return Process.GetProcessesByName("notepad").Length > 0;
}
void KillNotepads()
{
    foreach (var p in Process.GetProcessesByName("notepad")) { try { p.Kill(); } catch { } }
    Thread.Sleep(300);
}

KillNotepads();
// The user's example: only UK, USA, Canada and Germany are allowed.
var settings = new AppSettings { AllowedCountries = new() { "GB", "US", "CA", "DE" } };
var locator = new SimulatedLocator("FR", false);
var engine = new GuardEngine(() => settings, locator, new ProcessGuard(new[] { "notepad" }), new TimeZoneSync(dryRun: true));
var log = new List<string>();
engine.Activity += e => log.Add(Loc.Instance.Format(e.Key, e.Args));

Process.Start("notepad.exe");
await Task.Delay(800);
engine.Start();
Check(!await NotepadAliveAfter(engine, 3000), "France (not picked): target closed");
Process.Start("notepad.exe");
Check(!await NotepadAliveAfter(engine, 2500), "relaunched target closed again while blocked");

locator.Country = "US";
engine.CheckNow();
await Task.Delay(1000);
Process.Start("notepad.exe");
Check(await NotepadAliveAfter(engine, 3000), "United States (picked): target left running");

locator.Country = "CA";
engine.CheckNow();
Check(await NotepadAliveAfter(engine, 2500), "Canada (picked): target left running");

locator.Country = "DE";
engine.CheckNow();
Check(await NotepadAliveAfter(engine, 2500), "Germany (picked): target left running");

locator.Fail = true;
engine.CheckNow();
Check(!await NotepadAliveAfter(engine, 3000), "lookup failure + fail-safe: target closed");

settings.FailSafeBlock = false;
Process.Start("notepad.exe");
Check(await NotepadAliveAfter(engine, 2500), "lookup failure without fail-safe: target left running");
settings.FailSafeBlock = true;

engine.Pause();
Check(await NotepadAliveAfter(engine, 2500), "paused: target left running");
engine.Resume();
Check(!await NotepadAliveAfter(engine, 2500), "resumed: target closed");
Check(engine.KillCount >= 4, $"kill counter = {engine.KillCount}");
Check(log.Any(l => l.StartsWith("Time zone set") && l.Contains("Paris") && l.Contains("France")), "engine: France IP -> Paris time zone");
Check(log.Any(l => l.StartsWith("Time zone set") && l.Contains("Eastern Time")), "engine: USA IP -> US Eastern time zone");
Check(log.Any(l => l.StartsWith("Time zone set") && l.Contains("Berlin")), "engine: Germany IP -> Berlin time zone");
engine.Dispose();
KillNotepads();
Console.WriteLine("      activity log:");
foreach (var line in log) Console.WriteLine("        " + line);

// 5. Render the dashboard (English + Persian) to PNG files
var shotDir = args.Length > 0 ? args[0] : null;
if (shotDir != null)
{
    var thread = new Thread(() =>
    {
        try
        {
            var app = new ClaudeIpGuard.App();
            app.InitializeComponent();
            // Like the real app: code after "await" comes back to the UI thread.
            SynchronizationContext.SetSynchronizationContext(
                new System.Windows.Threading.DispatcherSynchronizationContext(System.Windows.Threading.Dispatcher.CurrentDispatcher));
            var uiSettings = new AppSettings { AllowedCountries = new() { "GB", "US", "CA", "DE" } };
            var host = new FakeHost(uiSettings);
            var uiEngine = new GuardEngine(() => uiSettings, new SimulatedLocator("DE", false), new ProcessGuard(new[] { "no-such-process" }));
            var vm = new MainViewModel(uiEngine, host, testMode: false);
            var win = new MainWindow(vm, host) { Left = -20000, Top = -20000, ShowActivated = false, Width = 1040, Height = 700 };
            win.Show();
            uiEngine.Start();
            Pump(2500);
            Save(win, Path.Combine(shotDir, "dashboard-en.png"));
            win.NavSettings.IsChecked = true;
            Pump(300);
            foreach (var r in vm.Editor.Picker.Regions.Take(2)) r.IsExpanded = true;
            Pump(300);
            win.PageSettings.ScrollToVerticalOffset(330);
            Pump(300);
            Save(win, Path.Combine(shotDir, "settings-en.png"));
            vm.Editor.Picker.SearchText = "korea";
            Pump(300);
            Save(win, Path.Combine(shotDir, "settings-search.png"));
            vm.Editor.Picker.SearchText = "";
            Loc.Instance.Language = "fa";
            Pump(400);
            Save(win, Path.Combine(shotDir, "settings-fa.png"));
            Loc.Instance.Language = "en";
            win.NavActivity.IsChecked = true;
            Pump(300);
            Save(win, Path.Combine(shotDir, "activity-en.png"));
            win.NavPrivacy.IsChecked = true;   // starts the leak check automatically
            var waitUntil = DateTime.Now.AddSeconds(40);
            Pump(500);
            while (!vm.Privacy.CanRun && DateTime.Now < waitUntil) Pump(300);
            Pump(300);
            Console.WriteLine($"      leak check: {vm.Privacy.Summary}");
            foreach (var item in vm.Privacy.Items) Console.WriteLine($"        [{item.StatusText}] {item.Title}: {item.Detail}");
            if (vm.Privacy.Items.Count < 8) throw new Exception($"leak check returned only {vm.Privacy.Items.Count} items");
            Save(win, Path.Combine(shotDir, "privacy-en.png"));
            Loc.Instance.Language = "fa";
            Pump(400);
            Save(win, Path.Combine(shotDir, "privacy-fa.png"));
            Loc.Instance.Language = "en";
            // Browser data page (reads this PC's real browsers; nothing is cleared)
            win.NavBrowser.IsChecked = true;
            Pump(500);
            waitUntil = DateTime.Now.AddSeconds(40);
            while ((!vm.BrowserData.CanAct || !vm.BrowserData.HasRun) && DateTime.Now < waitUntil) Pump(300);
            Pump(500);
            Console.WriteLine($"      browser data: {vm.BrowserData.Summary}");
            Console.WriteLine($"      banner: {vm.BrowserData.BannerText}");
            Save(win, Path.Combine(shotDir, "browser-en.png"));
            Loc.Instance.Language = "fa";
            Pump(400);
            Save(win, Path.Combine(shotDir, "browser-fa.png"));
            Loc.Instance.Language = "en";
            win.NavDashboard.IsChecked = true;
            Pump(400);
            Save(win, Path.Combine(shotDir, "dashboard-banner-en.png"));
            Loc.Instance.Language = "fa";
            win.NavDashboard.IsChecked = true;
            uiEngine.Pause();
            Pump(500);
            Save(win, Path.Combine(shotDir, "dashboard-fa-paused.png"));
            Loc.Instance.Language = "en";
            uiEngine.Dispose();
            win.AllowClose = true;
            win.Close();
            Console.WriteLine("PASS  UI rendered to " + shotDir);
        }
        catch (Exception ex)
        {
            Console.WriteLine("FAIL  UI render: " + ex);
            failures++;
        }
    });
    thread.SetApartmentState(ApartmentState.STA);
    thread.Start();
    thread.Join();
}

Console.WriteLine(failures == 0 ? "ALL TESTS PASSED" : $"{failures} TEST(S) FAILED");
return failures == 0 ? 0 : 1;

static void Pump(int ms)
{
    var end = DateTime.Now.AddMilliseconds(ms);
    while (DateTime.Now < end)
    {
        var frame = new System.Windows.Threading.DispatcherFrame();
        System.Windows.Threading.Dispatcher.CurrentDispatcher.BeginInvoke(
            System.Windows.Threading.DispatcherPriority.Background, new Action(() => frame.Continue = false));
        System.Windows.Threading.Dispatcher.PushFrame(frame);
        Thread.Sleep(30);
    }
}

static void Save(Window win, string path)
{
    var content = (FrameworkElement)win.Content;
    var dpi = VisualTreeHelper.GetDpi(content);
    var rtb = new RenderTargetBitmap((int)(content.ActualWidth * dpi.DpiScaleX), (int)(content.ActualHeight * dpi.DpiScaleY),
        dpi.PixelsPerInchX, dpi.PixelsPerInchY, PixelFormats.Pbgra32);
    content.UpdateLayout();
    rtb.Render(content);
    BitmapSource img = rtb;
    // RenderTargetBitmap draws right-to-left content mirrored; flip it back.
    if (win.FlowDirection == FlowDirection.RightToLeft)
        img = new TransformedBitmap(rtb, new ScaleTransform(-1, 1));
    var enc = new PngBitmapEncoder();
    enc.Frames.Add(BitmapFrame.Create(img));
    Directory.CreateDirectory(Path.GetDirectoryName(path)!);
    using var fs = File.Create(path);
    enc.Save(fs);
}

sealed class FakeHost : IAppHost
{
    public FakeHost(AppSettings s) => Settings = s;
    public AppSettings Settings { get; }
    public bool VerifyPassword(Window? owner, string reasonKey) => true;
    public bool ChangePassword(Window? owner) => true;
    public void SaveSettings(AppSettings settings) { }
    public void SaveLanguage(string language) { }
    public void RequestExit(Window? owner) { }
}
