using System.Diagnostics;
using System.Text.Json.Nodes;
using Microsoft.Data.Sqlite;
using System.Text.RegularExpressions;

namespace ClaudeIpGuard.Core;

public enum BrowserFamily { Chromium, Firefox }

/// <summary>Kinds of browser data that can show where you are (or were).</summary>
/// <remarks>Only <see cref="Cookies"/> and <see cref="SiteStorage"/> can sign you out of websites.</remarks>
public enum BrowserDataKind { CountryMemory, LocationPermissions, LocationCookies, Cache, SiteStorage, Cookies, History }

public enum BrowserDataRisk { Info, Warning, Problem }

/// <param name="DataDir">Profile root (Chromium "User Data", Firefox folder that holds "Profiles").</param>
/// <param name="CacheDir">Where the cache lives when it is not inside the profile (Opera, Firefox).</param>
/// <param name="ProcessName">Process name without .exe.</param>
/// <param name="PathMarker">Part of the browser's exe path, so other programs with the same exe name are left alone.</param>
public sealed record BrowserInfo(string Name, BrowserFamily Family, string DataDir, string? CacheDir, string ProcessName, string PathMarker);

public sealed class BrowserDataItem
{
    public required BrowserInfo Browser { get; init; }
    /// <summary>Profile folder, or "" for data that belongs to the whole browser.</summary>
    public required string ProfileDir { get; init; }
    public required string ProfileName { get; init; }
    public required BrowserDataKind Kind { get; init; }
    public BrowserDataRisk Risk { get; init; }
    public long Bytes { get; init; }
    public int Count { get; init; }
    /// <summary>Countries the browser remembers (CountryMemory), e.g. "IR, GB".</summary>
    public IReadOnlyList<string> Countries { get; init; } = Array.Empty<string>();
    public IReadOnlyList<string> Paths { get; init; } = Array.Empty<string>();
    /// <summary>
    /// Websites concerned. LocationCookies: sites with location cookies. Cookies: sites you'd be signed out of.
    /// SiteStorage: sites that stored data (some may sign you out).
    /// </summary>
    public IReadOnlyList<string> Sites { get; init; } = Array.Empty<string>();
    /// <summary>Cookies: the other sites with cookies (no sign-in cookie recognized, but you may be logged in there too).</summary>
    public IReadOnlyList<string> OtherSites { get; init; } = Array.Empty<string>();
    /// <summary>Number of different websites in the data (Cookies: all sites with cookies).</summary>
    public int SiteTotal { get; init; }
    /// <summary>Row ids of the location cookies to delete (LocationCookies).</summary>
    public IReadOnlyList<long> CookieIds { get; init; } = Array.Empty<long>();
    /// <summary>The browser is open and locks this data, so its details are not known yet.</summary>
    public bool DetailsHidden { get; init; }
    /// <summary>Clearing it can sign you out of websites.</summary>
    public bool CanSignOut => Kind is BrowserDataKind.Cookies or BrowserDataKind.SiteStorage;
    public string Id => $"{Browser.Name}|{ProfileDir}|{Kind}";
}

public sealed record BrowserCleanResult(int Cleaned, long BytesFreed, int FilesSkipped);

/// <summary>
/// Finds installed browsers and the data in them that can reveal the user's location, and clears it
/// on request. Scanning only reads. Passwords, bookmarks, extensions and their settings are never touched.
/// </summary>
public sealed class BrowserDataScanner
{
    // Chromium "Local State": the country the browser got from Google/Microsoft for your IP.
    static readonly string[] ChromiumCountryKeys =
        { "variations_country", "variations_permanent_consistency_country", "variations_permanent_overridden_country" };

    static readonly string[] ChromiumCache = { "Cache", "Code Cache", "GPUCache" };
    static readonly string[] ChromiumStorage = { "Local Storage", "Session Storage", "Service Worker", "databases", "File System" };
    // Cookie names that hold a location: country, region, city, coordinates, time zone, postcode, locale, currency.
    static readonly Regex LocationCookieName = new(
        @"geo|country|region|location|city|latitude|longitude|timezone|time_zone|postal|zip|currency|locale|ip_?info|^(loc|lat|lng|lon|tz|cc)$|(^|[_-])loc([_-]|$)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    // Cookie names that keep you signed in. A cookie that matches this is never treated as a location cookie.
    static readonly Regex SignInCookieName = new(
        @"sess|sid|auth|token|login|logged|jwt|remember|identity|account|user|^(li_at|c_user|xs|ds_user_id)$",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    // Local Storage keys start with "_" + origin + NUL.
    static readonly Regex LocalStorageOrigin = new(@"_(https?://[a-z0-9.\-]+(?::\d+)?)\x00", RegexOptions.Compiled);

    public static bool IsLocationCookie(string name) => LocationCookieName.IsMatch(name) && !IsSignInCookie(name);
    public static bool IsSignInCookie(string name) => SignInCookieName.IsMatch(name);
    static readonly string[] ChromiumHistory =
    {
        "History", "History-journal", "Visited Links", "Top Sites", "Top Sites-journal",
        "Shortcuts", "Shortcuts-journal", "Network Action Predictor", "Network Action Predictor-journal",
    };

    // Firefox prefs.js lines like: user_pref("browser.search.region", "IR");
    static readonly Regex FirefoxRegionPref = new(
        @"^user_pref\(""(?<name>[^""]*region[^""]*)"",\s*""(?<code>[A-Za-z]{2})""\);\s*$",
        RegexOptions.Multiline | RegexOptions.IgnoreCase | RegexOptions.Compiled);

    readonly string _local, _roaming;

    /// <param name="localAppData">Override for tests (default %LocalAppData%).</param>
    /// <param name="roamingAppData">Override for tests (default %AppData%).</param>
    public BrowserDataScanner(string? localAppData = null, string? roamingAppData = null)
    {
        _local = localAppData ?? Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        _roaming = roamingAppData ?? Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
    }

    public List<BrowserInfo> FindBrowsers()
    {
        var list = new List<BrowserInfo>();
        void Chromium(string name, string rel, string exe, string marker)
        {
            var dir = Path.Combine(_local, rel);
            if (Directory.Exists(dir)) list.Add(new BrowserInfo(name, BrowserFamily.Chromium, dir, null, exe, marker));
        }
        void Opera(string name, string rel, string marker)
        {
            var dir = Path.Combine(_roaming, rel);
            if (Directory.Exists(dir)) list.Add(new BrowserInfo(name, BrowserFamily.Chromium, dir, Path.Combine(_local, rel), "opera", marker));
        }
        void Firefox(string name, string rel, string exe, string marker)
        {
            var dir = Path.Combine(_roaming, rel);
            if (Directory.Exists(Path.Combine(dir, "Profiles")))
                list.Add(new BrowserInfo(name, BrowserFamily.Firefox, dir, Path.Combine(_local, rel), exe, marker));
        }

        Chromium("Google Chrome", @"Google\Chrome\User Data", "chrome", @"\Google\Chrome\");
        Chromium("Microsoft Edge", @"Microsoft\Edge\User Data", "msedge", @"\Microsoft\Edge\");
        Chromium("Brave", @"BraveSoftware\Brave-Browser\User Data", "brave", @"\BraveSoftware\");
        Chromium("Vivaldi", @"Vivaldi\User Data", "vivaldi", @"\Vivaldi\");
        Chromium("Yandex Browser", @"Yandex\YandexBrowser\User Data", "browser", @"\Yandex\");
        Chromium("Chromium", @"Chromium\User Data", "chrome", @"\Chromium\");
        Opera("Opera", @"Opera Software\Opera Stable", @"\Opera\");
        Opera("Opera GX", @"Opera Software\Opera GX Stable", @"\Opera GX\");
        Firefox("Mozilla Firefox", @"Mozilla\Firefox", "firefox", @"\Mozilla Firefox\");
        Firefox("LibreWolf", "librewolf", "librewolf", @"\LibreWolf\");
        Firefox("Waterfox", "Waterfox", "waterfox", @"\Waterfox\");
        return list;
    }

    /// <param name="currentCountry">Country of the current public IP; a remembered country that differs is a problem.</param>
    public List<BrowserDataItem> Scan(string? currentCountry)
    {
        var items = new List<BrowserDataItem>();
        foreach (var b in FindBrowsers())
        {
            try
            {
                if (b.Family == BrowserFamily.Chromium) ScanChromium(b, currentCountry, items);
                else ScanFirefox(b, currentCountry, items);
            }
            catch (Exception ex)
            {
                CrashLog.Write($"Browser scan failed for {b.Name}", ex);
            }
        }
        return items;
    }

    static BrowserDataRisk CountryRisk(IEnumerable<string> codes, string? current) =>
        current != null && codes.Any(c => !c.Equals(current, StringComparison.OrdinalIgnoreCase))
            ? BrowserDataRisk.Problem
            : BrowserDataRisk.Info;

    // ---------- Chromium (Chrome, Edge, Brave, Vivaldi, Opera, Yandex) ----------

    void ScanChromium(BrowserInfo b, string? currentCountry, List<BrowserDataItem> items)
    {
        var localStatePath = Path.Combine(b.DataDir, "Local State");
        var localState = ReadJson(localStatePath);
        if (localState != null)
        {
            var codes = ChromiumCountries(localState);
            if (codes.Count > 0)
                items.Add(new BrowserDataItem
                {
                    Browser = b, ProfileDir = "", ProfileName = "", Kind = BrowserDataKind.CountryMemory,
                    Countries = codes, Count = codes.Count, Risk = CountryRisk(codes, currentCountry),
                    Paths = new[] { localStatePath },
                });
        }

        foreach (var (dir, name) in ChromiumProfiles(b, localState))
        {
            var prefs = ReadJson(Path.Combine(dir, "Preferences"));
            var allowed = prefs == null ? 0 : GeolocationSites(prefs).Sum(o => o.Count);
            if (allowed > 0)
                items.Add(new BrowserDataItem
                {
                    Browser = b, ProfileDir = dir, ProfileName = name, Kind = BrowserDataKind.LocationPermissions,
                    Count = allowed, Risk = BrowserDataRisk.Warning, Paths = new[] { Path.Combine(dir, "Preferences") },
                });

            var cacheBase = b.CacheDir == null ? dir
                : string.Equals(dir, b.DataDir, StringComparison.OrdinalIgnoreCase) ? b.CacheDir
                : Path.Combine(b.CacheDir, Path.GetFileName(dir));
            AddFiles(items, b, dir, name, BrowserDataKind.Cache, ChromiumCache.Select(p => Path.Combine(cacheBase, p))
                .Concat(ChromiumCache.Select(p => Path.Combine(dir, p))).Distinct(StringComparer.OrdinalIgnoreCase));

            // IndexedDB: only websites, not extensions (chrome-extension_...). Folder: https_site.com_0.indexeddb.leveldb
            var idb = Path.Combine(dir, "IndexedDB");
            var storage = ChromiumStorage.Select(p => Path.Combine(dir, p)).ToList();
            var storageSites = new List<string>();
            if (Directory.Exists(idb))
                foreach (var d in Directory.EnumerateDirectories(idb).Where(d => Path.GetFileName(d).StartsWith("http", StringComparison.OrdinalIgnoreCase)))
                {
                    storage.Add(d);
                    var folder = Path.GetFileName(d);
                    var start = folder.IndexOf('_') + 1;
                    var end = folder.LastIndexOf('_');
                    if (start > 0 && end > start) storageSites.Add(folder[start..end]);
                }
            storageSites.AddRange(LocalStorageSites(Path.Combine(dir, "Local Storage", "leveldb")));
            AddFiles(items, b, dir, name, BrowserDataKind.SiteStorage, storage, storageSites);

            var cookieDb = Path.Combine(dir, "Network", "Cookies");
            if (!File.Exists(cookieDb)) cookieDb = Path.Combine(dir, "Cookies");
            AddCookies(items, b, dir, name, cookieDb, new[] { cookieDb + "-journal" }, firefox: false);
            AddFiles(items, b, dir, name, BrowserDataKind.History, ChromiumHistory.Select(p => Path.Combine(dir, p)));
        }
    }

    static List<string> ChromiumCountries(JsonNode localState)
    {
        var codes = new List<string>();
        foreach (var key in ChromiumCountryKeys)
        {
            var node = localState[key];
            var value = node switch
            {
                JsonValue v when v.TryGetValue<string>(out var s) => s,
                JsonArray a => a.LastOrDefault() is JsonValue last && last.TryGetValue<string>(out var s2) ? s2 : null,
                _ => null,
            };
            if (value is { Length: 2 }) codes.Add(value.ToUpperInvariant());
        }
        return codes.Distinct().ToList();
    }

    static IEnumerable<JsonObject> GeolocationSites(JsonNode prefs)
    {
        if (prefs["profile"]?["content_settings"]?["exceptions"] is not JsonObject exceptions) yield break;
        foreach (var key in new[] { "geolocation", "geolocation_with_options" })
            if (exceptions[key] is JsonObject sites && sites.Count > 0) yield return sites;
    }

    static IEnumerable<(string Dir, string Name)> ChromiumProfiles(BrowserInfo b, JsonNode? localState)
    {
        // Opera keeps its single profile directly in the data folder.
        var list = new List<(string Dir, string Name, string Folder)>();
        if (File.Exists(Path.Combine(b.DataDir, "Preferences"))) list.Add((b.DataDir, "Default", "Default"));
        foreach (var dir in Directory.EnumerateDirectories(b.DataDir))
        {
            var folder = Path.GetFileName(dir);
            if (folder != "Default" && !folder.StartsWith("Profile ", StringComparison.Ordinal)) continue;
            if (!File.Exists(Path.Combine(dir, "Preferences"))) continue;
            var display = localState?["profile"]?["info_cache"]?[folder]?["name"]?.GetValue<string>();
            list.Add((dir, string.IsNullOrWhiteSpace(display) ? folder : display!, folder));
        }
        // Two profiles with the same name ("Alex", "Alex") get their folder added: "Alex (Profile 1)".
        foreach (var p in list)
            yield return (p.Dir, list.Count(x => x.Name == p.Name) > 1 && p.Name != p.Folder ? $"{p.Name} ({p.Folder})" : p.Name);
    }

    // ---------- Firefox family ----------

    static void ScanFirefox(BrowserInfo b, string? currentCountry, List<BrowserDataItem> items)
    {
        foreach (var dir in Directory.EnumerateDirectories(Path.Combine(b.DataDir, "Profiles")))
        {
            var prefsPath = Path.Combine(dir, "prefs.js");
            if (!File.Exists(prefsPath)) continue;
            var folder = Path.GetFileName(dir);
            var name = folder.Contains('.') ? folder[(folder.IndexOf('.') + 1)..] : folder;

            var codes = FirefoxRegionPref.Matches(ReadText(prefsPath))
                .Select(m => m.Groups["code"].Value.ToUpperInvariant()).Distinct().ToList();
            if (codes.Count > 0)
                items.Add(new BrowserDataItem
                {
                    Browser = b, ProfileDir = dir, ProfileName = name, Kind = BrowserDataKind.CountryMemory,
                    Countries = codes, Count = codes.Count, Risk = CountryRisk(codes, currentCountry), Paths = new[] { prefsPath },
                });

            var cacheDir = Path.Combine(b.CacheDir ?? b.DataDir, "Profiles", folder, "cache2");
            AddFiles(items, b, dir, name, BrowserDataKind.Cache, new[] { cacheDir });

            // storage\default holds one folder per website (https+++site) and per extension (moz-extension+++...).
            var storage = new List<string> { Path.Combine(dir, "webappsstore.sqlite"), Path.Combine(dir, "webappsstore.sqlite-wal") };
            var storageSites = new List<string>();
            var siteStorage = Path.Combine(dir, "storage", "default");
            if (Directory.Exists(siteStorage))
                foreach (var d in Directory.EnumerateDirectories(siteStorage).Where(d => Path.GetFileName(d).StartsWith("http", StringComparison.OrdinalIgnoreCase)))
                {
                    storage.Add(d);
                    var site = Path.GetFileName(d);
                    site = site[(site.IndexOf("+++", StringComparison.Ordinal) + 3)..];
                    var plus = site.IndexOf('+');
                    storageSites.Add(plus > 0 ? site[..plus] : site);
                }
            AddFiles(items, b, dir, name, BrowserDataKind.SiteStorage, storage, storageSites);
            var cookieDb = Path.Combine(dir, "cookies.sqlite");
            AddCookies(items, b, dir, name, cookieDb, new[] { cookieDb + "-wal", cookieDb + "-shm" }, firefox: true);
            // Firefox history lives in places.sqlite together with bookmarks, so it is not offered here.
        }
    }

    // ---------- shared helpers ----------

    static void AddFiles(List<BrowserDataItem> items, BrowserInfo b, string dir, string name, BrowserDataKind kind,
        IEnumerable<string> paths, IEnumerable<string>? sites = null)
    {
        var existing = paths.Where(p => File.Exists(p) || Directory.Exists(p)).ToList();
        var bytes = existing.Sum(SizeOf);
        if (existing.Count == 0 || bytes == 0) return;
        var siteList = SiteList(sites ?? Array.Empty<string>());
        items.Add(new BrowserDataItem
        {
            Browser = b, ProfileDir = dir, ProfileName = name, Kind = kind, Bytes = bytes, Count = existing.Count,
            Risk = BrowserDataRisk.Info, Paths = existing, Sites = siteList, SiteTotal = siteList.Count,
        });
    }

    sealed record CookieRow(long Id, string Host, string Name);

    /// <summary>
    /// Cookies are read one by one, so location cookies can be deleted without signing you out, and the sites
    /// you'd be signed out of can be listed. While the browser is open it locks the file: details are hidden then.
    /// </summary>
    static void AddCookies(List<BrowserDataItem> items, BrowserInfo b, string dir, string name, string db, string[] extra, bool firefox)
    {
        if (!File.Exists(db)) return;
        var files = new[] { db }.Concat(extra).Where(File.Exists).ToList();
        var bytes = files.Sum(SizeOf);
        var rows = ReadCookies(db, firefox);
        if (rows == null)
        {
            items.Add(new BrowserDataItem
            {
                Browser = b, ProfileDir = dir, ProfileName = name, Kind = BrowserDataKind.LocationCookies,
                DetailsHidden = true, Risk = BrowserDataRisk.Info, Paths = new[] { db },
            });
            items.Add(new BrowserDataItem
            {
                Browser = b, ProfileDir = dir, ProfileName = name, Kind = BrowserDataKind.Cookies,
                DetailsHidden = true, Bytes = bytes, Risk = BrowserDataRisk.Info, Paths = files,
            });
            return;
        }
        if (rows.Count == 0) return;

        var location = rows.Where(r => IsLocationCookie(r.Name)).ToList();
        if (location.Count > 0)
        {
            var sites = SiteList(location.Select(r => r.Host));
            items.Add(new BrowserDataItem
            {
                Browser = b, ProfileDir = dir, ProfileName = name, Kind = BrowserDataKind.LocationCookies,
                Count = location.Count, Sites = sites, SiteTotal = sites.Count, CookieIds = location.Select(r => r.Id).ToList(),
                Risk = BrowserDataRisk.Warning, Paths = new[] { db },
            });
        }
        var signIn = SiteList(rows.Where(r => IsSignInCookie(r.Name)).Select(r => r.Host));
        var all = SiteList(rows.Select(r => r.Host));
        items.Add(new BrowserDataItem
        {
            Browser = b, ProfileDir = dir, ProfileName = name, Kind = BrowserDataKind.Cookies,
            Count = rows.Count, Bytes = bytes, Risk = BrowserDataRisk.Info, Paths = files,
            Sites = signIn, OtherSites = all.Except(signIn).ToList(), SiteTotal = all.Count,
        });
    }

    static string Connection(string db, SqliteOpenMode mode) =>
        // No pooling: the file must be released at once, or the browser can't open it later.
        new SqliteConnectionStringBuilder { DataSource = db, Mode = mode, Pooling = false }.ToString();

    static List<CookieRow>? ReadCookies(string db, bool firefox)
    {
        try
        {
            // Fails fast when the browser has the file open (it locks it).
            using (new FileStream(db, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete)) { }
            using var conn = new SqliteConnection(Connection(db, SqliteOpenMode.ReadOnly));
            conn.Open();
            using var cmd = conn.CreateCommand();
            cmd.CommandText = firefox ? "SELECT id, host, name FROM moz_cookies" : "SELECT rowid, host_key, name FROM cookies";
            var list = new List<CookieRow>();
            using var r = cmd.ExecuteReader();
            while (r.Read()) list.Add(new CookieRow(r.GetInt64(0), r.GetString(1), r.GetString(2)));
            return list;
        }
        catch (Exception ex) when (ex is IOException or SqliteException { SqliteErrorCode: 5 or 6 }) // busy / locked
        {
            return null; // locked by the open browser
        }
        catch (Exception ex)
        {
            CrashLog.Write($"Could not read cookies {db}", ex);
            return null;
        }
    }

    static IEnumerable<string> LocalStorageSites(string leveldb)
    {
        if (!Directory.Exists(leveldb)) yield break;
        foreach (var file in Directory.EnumerateFiles(leveldb).Where(f => f.EndsWith(".log") || f.EndsWith(".ldb")))
        {
            string text;
            try { text = System.Text.Encoding.Latin1.GetString(File.ReadAllBytes(file)); }
            catch { continue; }
            foreach (Match m in LocalStorageOrigin.Matches(text))
                if (Uri.TryCreate(m.Groups[1].Value, UriKind.Absolute, out var uri)) yield return uri.Host;
        }
    }

    /// <summary>Clean, sorted, unique site names: ".www.google.com" -> "google.com".</summary>
    static List<string> SiteList(IEnumerable<string> hosts) =>
        hosts.Select(h => h.Trim().TrimStart('.').ToLowerInvariant())
             .Select(h => h.StartsWith("www.") ? h[4..] : h)
             .Where(h => h.Length > 0)
             .Distinct()
             .OrderBy(h => h, StringComparer.Ordinal)
             .ToList();

    static long SizeOf(string path)
    {
        try
        {
            if (File.Exists(path)) return new FileInfo(path).Length;
            if (!Directory.Exists(path)) return 0;
            return new DirectoryInfo(path)
                .EnumerateFiles("*", new EnumerationOptions { RecurseSubdirectories = true, IgnoreInaccessible = true, AttributesToSkip = FileAttributes.ReparsePoint })
                .Sum(f => f.Length);
        }
        catch
        {
            return 0;
        }
    }

    static string ReadText(string path)
    {
        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        using var reader = new StreamReader(fs);
        return reader.ReadToEnd();
    }

    static JsonNode? ReadJson(string path)
    {
        try { return File.Exists(path) ? JsonNode.Parse(ReadText(path)) : null; }
        catch (Exception ex)
        {
            CrashLog.Write($"Could not read {path}", ex);
            return null;
        }
    }

    static void WriteText(string path, string text)
    {
        var tmp = path + ".ipguard.tmp";
        File.WriteAllText(tmp, text);
        File.Move(tmp, path, overwrite: true);
    }

    // ---------- cleaning ----------

    /// <summary>Clears the given items. The browsers must be closed first (see <see cref="CloseBrowser"/>).</summary>
    public BrowserCleanResult Clean(IEnumerable<BrowserDataItem> items)
    {
        int cleaned = 0, skipped = 0;
        long freed = 0;
        var list = items.ToList();
        // When all cookies of a profile go, the location cookies go with them.
        var allCookies = list.Where(i => i.Kind == BrowserDataKind.Cookies).Select(i => i.Browser.Name + "|" + i.ProfileDir).ToHashSet();
        foreach (var item in list)
        {
            try
            {
                switch (item.Kind)
                {
                    case BrowserDataKind.LocationCookies when allCookies.Contains(item.Browser.Name + "|" + item.ProfileDir):
                        break;
                    case BrowserDataKind.LocationCookies:
                        DeleteCookies(item.Paths[0], item.Browser.Family == BrowserFamily.Firefox, item.CookieIds);
                        break;
                    case BrowserDataKind.CountryMemory when item.Browser.Family == BrowserFamily.Chromium:
                    {
                        var path = item.Paths[0];
                        if (ReadJson(path) is JsonObject state)
                        {
                            foreach (var key in ChromiumCountryKeys) state.Remove(key);
                            WriteText(path, state.ToJsonString());
                        }
                        break;
                    }
                    case BrowserDataKind.CountryMemory:
                    {
                        var path = item.Paths[0];
                        WriteText(path, FirefoxRegionPref.Replace(ReadText(path), ""));
                        break;
                    }
                    case BrowserDataKind.LocationPermissions:
                    {
                        var path = item.Paths[0];
                        if (ReadJson(path) is JsonObject prefs)
                        {
                            var exceptions = prefs["profile"]?["content_settings"]?["exceptions"] as JsonObject;
                            foreach (var key in new[] { "geolocation", "geolocation_with_options" })
                                if (exceptions?[key] is JsonObject) exceptions[key] = new JsonObject();
                            WriteText(path, prefs.ToJsonString());
                        }
                        break;
                    }
                    default:
                        foreach (var path in item.Paths) freed += Delete(path, ref skipped);
                        break;
                }
                cleaned++;
            }
            catch (Exception ex)
            {
                skipped++;
                CrashLog.Write($"Could not clear {item.Id}", ex);
            }
        }
        return new BrowserCleanResult(cleaned, freed, skipped);
    }

    /// <summary>Deletes only the given cookies; every other cookie (and so every sign-in) stays.</summary>
    static void DeleteCookies(string db, bool firefox, IReadOnlyList<long> ids)
    {
        if (ids.Count == 0 || !File.Exists(db)) return;
        using var conn = new SqliteConnection(Connection(db, SqliteOpenMode.ReadWrite));
        conn.Open();
        using var tx = conn.BeginTransaction();
        foreach (var chunk in ids.Chunk(500))
        {
            using var cmd = conn.CreateCommand();
            cmd.Transaction = tx;
            cmd.CommandText = (firefox ? "DELETE FROM moz_cookies WHERE id IN (" : "DELETE FROM cookies WHERE rowid IN (") +
                              string.Join(",", chunk) + ")";
            cmd.ExecuteNonQuery();
        }
        tx.Commit();
    }

    static long Delete(string path, ref int skipped)
    {
        long freed = 0;
        if (File.Exists(path))
        {
            var size = new FileInfo(path).Length;
            try { File.Delete(path); freed += size; }
            catch { skipped++; }
            return freed;
        }
        if (!Directory.Exists(path)) return 0;
        foreach (var file in Directory.EnumerateFiles(path, "*", new EnumerationOptions { RecurseSubdirectories = true, IgnoreInaccessible = true, AttributesToSkip = FileAttributes.ReparsePoint }))
        {
            try
            {
                var size = new FileInfo(file).Length;
                File.SetAttributes(file, FileAttributes.Normal);
                File.Delete(file);
                freed += size;
            }
            catch { skipped++; }
        }
        try { Directory.Delete(path, recursive: true); } catch { /* leftovers already counted */ }
        return freed;
    }

    // ---------- browser processes ----------

    static List<Process> Processes(BrowserInfo b)
    {
        var session = Process.GetCurrentProcess().SessionId;
        var list = new List<Process>();
        foreach (var p in Process.GetProcessesByName(b.ProcessName))
        {
            var path = p.SessionId == session ? ProcessGuard.GetImagePath(p.Id) : null;
            if (path != null && path.Contains(b.PathMarker, StringComparison.OrdinalIgnoreCase)) list.Add(p);
            else p.Dispose();
        }
        return list;
    }

    public static bool IsRunning(BrowserInfo b)
    {
        var list = Processes(b);
        foreach (var p in list) p.Dispose();
        return list.Count > 0;
    }

    /// <summary>Asks the browser's windows to close, then ends what is left. True when it is fully closed.</summary>
    public static bool CloseBrowser(BrowserInfo b)
    {
        var deadline = DateTime.UtcNow.AddSeconds(8);
        while (DateTime.UtcNow < deadline)
        {
            var list = Processes(b);
            if (list.Count == 0) return true;
            foreach (var p in list)
                using (p)
                    try { if (p.MainWindowHandle != IntPtr.Zero) p.CloseMainWindow(); } catch { }
            Thread.Sleep(700);
        }
        foreach (var p in Processes(b))
            using (p)
                try { p.Kill(entireProcessTree: true); } catch { }
        for (int i = 0; i < 20; i++)
        {
            if (!IsRunning(b)) return true;
            Thread.Sleep(250);
        }
        return false;
    }
}
