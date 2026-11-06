using System.Collections.ObjectModel;
using System.Windows;
using System.Windows.Media;
using System.Windows.Threading;
using ClaudeIpGuard.Core;
using ClaudeIpGuard.Localization;

namespace ClaudeIpGuard.UI;

/// <summary>
/// The "Browser data" page. Scans the browsers (at start, every 30 minutes and when the IP country
/// changes), notifies when it finds data that shows the location, and clears only what the user ticks.
/// </summary>
public sealed class BrowserDataViewModel : ObservableObject
{
    static readonly TimeSpan RescanEvery = TimeSpan.FromMinutes(30);

    readonly BrowserDataScanner _scanner;
    readonly GuardEngine _engine;
    readonly bool _testMode;
    readonly Dispatcher _dispatcher;
    bool _busy, _dismissed;
    DateTime? _lastScan;
    string? _scannedCountry, _lastAlertKey;
    string _summary = "", _lastScanText = "", _resultText = "", _bannerText = "";
    bool _resultIsError;
    int _browserCount;

    /// <summary>Raised with (title, text) when new location-revealing data is found.</summary>
    public event Action<string, string>? Notify;

    public BrowserDataViewModel(GuardEngine engine, bool testMode, BrowserDataScanner? scanner = null)
    {
        _engine = engine;
        _testMode = testMode;
        _scanner = scanner ?? new BrowserDataScanner();
        _dispatcher = Dispatcher.CurrentDispatcher;
        RefreshTexts();

        // Rescan when the IP country changes: the browsers' remembered country may not match any more.
        engine.StateChanged += () => _dispatcher.BeginInvoke(() =>
        {
            var country = engine.LastResult?.CountryCode;
            if (country != null && country != _scannedCountry) _ = ScanAsync(notify: true);
        });
        new DispatcherTimer(RescanEvery, DispatcherPriority.Background, (_, _) => _ = ScanAsync(notify: true), _dispatcher).Start();
        // If the location lookup keeps failing, still scan once shortly after start.
        var first = new DispatcherTimer(DispatcherPriority.Background, _dispatcher) { Interval = TimeSpan.FromSeconds(15) };
        first.Tick += (_, _) =>
        {
            first.Stop();
            if (_lastScan == null) _ = ScanAsync(notify: true);
        };
        first.Start();
    }

    public ObservableCollection<BrowserGroup> Groups { get; } = new();
    public bool HasRun => _lastScan != null;
    public bool CanAct => !_busy;
    public bool CanClean => !_busy && Rows.Any(r => r.IsSelected);
    public string Summary { get => _summary; private set => Set(ref _summary, value); }
    public string LastScanText { get => _lastScanText; private set => Set(ref _lastScanText, value); }
    public Visibility ProgressVisibility => _busy ? Visibility.Visible : Visibility.Collapsed;
    public Visibility EmptyVisibility => HasRun && Groups.Count == 0 ? Visibility.Visible : Visibility.Collapsed;

    public string ResultText
    {
        get => _resultText;
        private set
        {
            if (Set(ref _resultText, value)) OnPropertyChanged(nameof(ResultVisibility));
        }
    }

    public Brush ResultBrush => _resultIsError ? Brushes.Firebrick : Brushes.SeaGreen;
    public Visibility ResultVisibility => string.IsNullOrEmpty(ResultText) ? Visibility.Collapsed : Visibility.Visible;

    // Dashboard banner
    public string BannerText { get => _bannerText; private set => Set(ref _bannerText, value); }
    public Visibility BannerVisibility => AlertRows.Any() && !_dismissed ? Visibility.Visible : Visibility.Collapsed;

    IEnumerable<BrowserDataRow> Rows => Groups.SelectMany(g => g.Rows);
    IEnumerable<BrowserDataRow> AlertRows => Rows.Where(r => r.Item.Risk != BrowserDataRisk.Info);

    public void DismissBanner()
    {
        _dismissed = true;
        OnPropertyChanged(nameof(BannerVisibility));
    }

    public async Task ScanAsync(bool notify)
    {
        if (_busy) return;
        SetBusy(true);
        var country = _engine.LastResult?.CountryCode;
        try
        {
            var (browsers, items) = await Task.Run(() => (_scanner.FindBrowsers().Count, _scanner.Scan(country)));
            _browserCount = browsers;
            _scannedCountry = country;
            _lastScan = DateTime.Now;

            // Keep the user's ticks across rescans.
            var ticked = Rows.ToDictionary(r => r.Item.Id, r => r.IsSelected);
            Groups.Clear();
            foreach (var g in items.GroupBy(i => i.Browser.Name))
            {
                var multiProfile = g.Select(i => i.ProfileDir).Where(d => d != "").Distinct().Count() > 1;
                var group = new BrowserGroup(g.First().Browser);
                foreach (var item in g.OrderBy(i => i.ProfileDir).ThenBy(i => i.Kind))
                {
                    var row = new BrowserDataRow(item, multiProfile, country, OnSelectionChanged);
                    row.IsSelected = ticked.TryGetValue(item.Id, out var t) ? t : DefaultSelected(item.Kind);
                    group.Rows.Add(row);
                }
                Groups.Add(group);
            }
            await Task.Run(() => { foreach (var g in Groups) g.CheckRunning(); });

            var alertKey = string.Join(";", AlertRows.Select(r => r.Item.Id + ":" + string.Join(",", r.Item.Countries) + ":" + r.Item.Count).OrderBy(s => s));
            if (alertKey != _lastAlertKey)
            {
                _lastAlertKey = alertKey;
                _dismissed = false;
                if (notify && alertKey.Length > 0)
                {
                    var text = AlertSummary();
                    _engine.Log(ActivityLevel.Warning, "Act_BrowserData", text);
                    Notify?.Invoke(Loc.Instance["BD_NotifyTitle"], Loc.Instance.Format("BD_NotifyText", text));
                }
            }
        }
        catch (Exception ex)
        {
            CrashLog.Write("Browser data scan failed", ex);
        }
        finally
        {
            SetBusy(false);
        }
    }

    // Only what can't sign you out is ticked by default.
    static bool DefaultSelected(BrowserDataKind kind) =>
        kind is BrowserDataKind.CountryMemory or BrowserDataKind.LocationPermissions or BrowserDataKind.LocationCookies or BrowserDataKind.Cache;

    string AlertSummary()
    {
        var L = Loc.Instance;
        var parts = new List<string>();
        foreach (var r in AlertRows)
        {
            if (r.Item.Kind == BrowserDataKind.CountryMemory)
            {
                // Name only the countries that differ from the current IP: those are what give you away.
                var other = r.Item.Countries.Where(c => !c.Equals(_scannedCountry, StringComparison.OrdinalIgnoreCase)).ToList();
                parts.Add(L.Format("BD_Alert_Country", r.Item.Browser.Name, BrowserDataRow.CountryList(other.Count > 0 ? other : r.Item.Countries)));
            }
            else if (r.Item.Kind == BrowserDataKind.LocationPermissions)
                parts.Add(L.Format("BD_Alert_Perm", r.Item.Browser.Name, r.Item.Count));
        }
        return string.Join(L.IsPersian ? "؛ " : "; ", parts.Distinct());
    }

    public async Task CleanSelectedAsync(Window owner)
    {
        var L = Loc.Instance;
        var rows = Rows.Where(r => r.IsSelected).ToList();
        if (rows.Count == 0)
        {
            ShowResult(true, L["BD_SelectFirst"]);
            return;
        }
        var browsers = rows.Select(r => r.Item.Browser).DistinctBy(b => b.Name).ToList();
        var running = Groups.Where(g => g.IsRunning && browsers.Any(b => b.Name == g.Browser.Name)).Select(g => g.Browser).ToList();
        var options = L.IsPersian ? MessageBoxOptions.RtlReading | MessageBoxOptions.RightAlign : MessageBoxOptions.None;

        SetBusy(true);
        var closedBrowsers = new List<BrowserInfo>();
        try
        {
            // Step 1: open browsers lock their data. Close them first (nothing is deleted yet) so the
            // exact list of what would be deleted, and which sites would sign you out, can be shown.
            if (running.Count > 0 && !_testMode)
            {
                var names = string.Join(", ", running.Select(b => b.Name));
                if (MessageBox.Show(owner, L.Format("BD_CloseFirst", names), L["BD_CloseFirstTitle"], MessageBoxButton.YesNo,
                        MessageBoxImage.Information, MessageBoxResult.No, options) != MessageBoxResult.Yes) return;
                var stillOpen = await Task.Run(() => running.Where(b => !BrowserDataScanner.CloseBrowser(b)).ToList());
                if (stillOpen.Count > 0)
                {
                    ShowResult(true, L.Format("BD_CloseFailed", string.Join(", ", stillOpen.Select(b => b.Name))));
                    return;
                }
                closedBrowsers = running;
            }

            // Step 2: read the data again, now with every detail, and keep only what was ticked.
            var country = _engine.LastResult?.CountryCode;
            var ticked = rows.Select(r => r.Item.Id).ToHashSet();
            var fresh = _testMode ? rows.Select(r => r.Item).ToList() : await Task.Run(() => _scanner.Scan(country));
            var items = fresh.Where(i => ticked.Contains(i.Id) && !(i.Kind == BrowserDataKind.LocationCookies && i.CookieIds.Count == 0 && !i.DetailsHidden))
                             .ToList();
            if (items.Count == 0)
            {
                ShowResult(false, L["BD_NothingToClear"]);
                return;
            }

            // Step 3: show exactly what goes, and every site you'd be signed out of. Only "Clear" deletes.
            if (!ConfirmClearDialog.Show(owner, L["BD_Dialog_Title"], L["BD_Dialog_Intro"], BuildSections(items),
                    L["BD_Dialog_Clear"], L["BD_Dialog_Cancel"]))
            {
                ShowResult(false, closedBrowsers.Count > 0 ? L["BD_Cancelled"] : L["BD_CancelledNoClose"]);
                return;
            }
            if (_testMode)
            {
                ShowResult(false, L.Format("BD_TestMode", items.Count));
                return;
            }

            var result = await Task.Run(() => _scanner.Clean(items));
            var text = L.Format("BD_Result", result.Cleaned, BrowserDataRow.FormatSize(result.BytesFreed));
            if (result.FilesSkipped > 0) text += " " + L.Format("BD_ResultSkipped", result.FilesSkipped);
            ShowResult(result.FilesSkipped > 0, text);
            _engine.Log(ActivityLevel.Success, "Act_BrowserCleaned", result.Cleaned, BrowserDataRow.FormatSize(result.BytesFreed));
        }
        catch (Exception ex)
        {
            CrashLog.Write("Browser data clean failed", ex);
            ShowResult(true, ex.Message);
        }
        finally
        {
            SetBusy(false);
            await ScanAsync(notify: false);
        }
    }

    static List<ConfirmSection> BuildSections(List<BrowserDataItem> items)
    {
        var L = Loc.Instance;
        var sections = new List<ConfirmSection>
        {
            new(L["BD_Dialog_Items"], items.Select(i => BrowserDataRow.LabelFor(i, items)).ToList(), false),
        };
        var signOut = items.Where(i => i.CanSignOut).ToList();
        foreach (var i in signOut.Where(i => i.Kind == BrowserDataKind.Cookies))
        {
            var where = BrowserDataRow.BrowserAndProfile(i, items);
            if (i.DetailsHidden)
            {
                sections.Add(new ConfirmSection(L.Format("BD_Dialog_SignOutUnknown", where), Array.Empty<string>(), true));
                continue;
            }
            if (i.Sites.Count > 0)
                sections.Add(new ConfirmSection(L.Format("BD_Dialog_SignOut", where, i.Sites.Count), i.Sites, true));
            if (i.OtherSites.Count > 0)
                sections.Add(new ConfirmSection(L.Format("BD_Dialog_OtherCookieSites", where, i.OtherSites.Count), i.OtherSites, true));
        }
        foreach (var i in signOut.Where(i => i.Kind == BrowserDataKind.SiteStorage && i.Sites.Count > 0))
            sections.Add(new ConfirmSection(L.Format("BD_Dialog_Storage", BrowserDataRow.BrowserAndProfile(i, items), i.Sites.Count), i.Sites, true));
        if (signOut.Count == 0)
            sections.Add(new ConfirmSection(L["BD_Dialog_NoSignOut"], Array.Empty<string>(), false));
        return sections;
    }

    void ShowResult(bool isError, string text)
    {
        _resultIsError = isError;
        ResultText = text;
        OnPropertyChanged(nameof(ResultBrush));
    }

    void OnSelectionChanged() => OnPropertyChanged(nameof(CanClean));

    void SetBusy(bool busy)
    {
        _busy = busy;
        OnPropertyChanged(nameof(CanAct));
        OnPropertyChanged(nameof(CanClean));
        OnPropertyChanged(nameof(ProgressVisibility));
        OnPropertyChanged(nameof(HasRun));
        OnPropertyChanged(nameof(EmptyVisibility));
        RefreshTexts();
    }

    public void RefreshTexts()
    {
        var L = Loc.Instance;
        if (_busy) Summary = L["BD_Scanning"];
        else if (_lastScan == null) Summary = L["BD_NotRun"];
        else
            Summary = L.Format("BD_Summary", _browserCount,
                Rows.Count(r => r.Item.Risk == BrowserDataRisk.Problem),
                Rows.Count(r => r.Item.Risk == BrowserDataRisk.Warning),
                Rows.Count());
        LastScanText = _lastScan != null ? L.Format("BD_LastScan", _lastScan.Value.ToString("HH:mm:ss")) : "";
        BannerText = AlertRows.Any() ? L.Format("BD_Banner", AlertSummary()) : "";
        OnPropertyChanged(nameof(BannerVisibility));
        foreach (var g in Groups) g.Refresh();
    }
}

public sealed class BrowserGroup : ObservableObject
{
    public BrowserGroup(BrowserInfo browser) => Browser = browser;

    public BrowserInfo Browser { get; }
    public string Name => Browser.Name;
    public bool IsRunning { get; private set; }
    public ObservableCollection<BrowserDataRow> Rows { get; } = new();
    public string StatusText => Loc.Instance[IsRunning ? "BD_Running" : "BD_NotRunning"];

    public void CheckRunning()
    {
        IsRunning = BrowserDataScanner.IsRunning(Browser);
        Application.Current?.Dispatcher.BeginInvoke(() => OnPropertyChanged(nameof(StatusText)));
    }

    public void Refresh()
    {
        OnPropertyChanged(nameof(StatusText));
        foreach (var r in Rows) r.Refresh();
    }
}

public sealed class BrowserDataRow : ObservableObject
{
    static readonly Brush Red = Frozen("#DC2626"), Amber = Frozen("#D97706"), Grey = Frozen("#64748B");

    readonly bool _showProfile;
    readonly string? _currentCountry;
    readonly Action _selectionChanged;
    bool _isSelected;

    public BrowserDataRow(BrowserDataItem item, bool showProfile, string? currentCountry, Action selectionChanged)
    {
        Item = item;
        _showProfile = showProfile;
        _currentCountry = currentCountry;
        _selectionChanged = selectionChanged;
    }

    public BrowserDataItem Item { get; }

    public bool IsSelected
    {
        get => _isSelected;
        set
        {
            if (Set(ref _isSelected, value)) _selectionChanged();
        }
    }

    string KindTitle => Loc.Instance["BD_Kind_" + Item.Kind];

    public string Title => _showProfile && Item.ProfileName != ""
        ? Loc.Instance.Format("BD_TitleWithProfile", KindTitle, Item.ProfileName)
        : KindTitle;

    public string SizeText => Item.Bytes > 0 ? FormatSize(Item.Bytes) : "";

    /// <summary>"Google Chrome" or "Google Chrome (profile: Alex)" when that browser has several profiles in the list.</summary>
    public static string BrowserAndProfile(BrowserDataItem i, IEnumerable<BrowserDataItem> all) =>
        i.ProfileName != "" && all.Where(x => x.Browser.Name == i.Browser.Name && x.ProfileDir != "").Select(x => x.ProfileDir).Distinct().Count() > 1
            ? Loc.Instance.Format("BD_TitleWithProfile", i.Browser.Name, i.ProfileName)
            : i.Browser.Name;

    /// <summary>One line of the confirmation, e.g. "Google Chrome: Location cookies (12 cookies on 5 sites)".</summary>
    public static string LabelFor(BrowserDataItem i, IEnumerable<BrowserDataItem> all)
    {
        var L = Loc.Instance;
        var detail = i.Kind switch
        {
            BrowserDataKind.LocationCookies when !i.DetailsHidden => L.Format("BD_Label_LocCookies", i.Count, i.Sites.Count),
            BrowserDataKind.Cookies when !i.DetailsHidden => L.Format("BD_Label_Cookies", i.Count, i.SiteTotal),
            BrowserDataKind.CountryMemory => CountryList(i.Countries),
            BrowserDataKind.LocationPermissions => L.Format("BD_Label_Sites", i.Count),
            _ => i.Bytes > 0 ? FormatSize(i.Bytes) : "",
        };
        var text = $"{BrowserAndProfile(i, all)}: {L["BD_Kind_" + i.Kind]}";
        return detail.Length > 0 ? $"{text} ({detail})" : text;
    }

    public string What
    {
        get
        {
            var L = Loc.Instance;
            var browser = Item.Browser.Name;
            return Item.Kind switch
            {
                BrowserDataKind.CountryMemory => L.Format("BD_What_CountryMemory", CountryList(Item.Countries)) +
                    (_currentCountry != null ? " " + L.Format("BD_CountryNow", CountryList(new[] { _currentCountry })) : ""),
                BrowserDataKind.LocationPermissions => L.Format("BD_What_LocationPermissions", Item.Count),
                BrowserDataKind.LocationCookies when Item.DetailsHidden => L.Format("BD_What_LocationCookies_Hidden", browser),
                BrowserDataKind.LocationCookies => L.Format("BD_What_LocationCookies", Item.Count, Item.Sites.Count),
                BrowserDataKind.Cookies when Item.DetailsHidden => L.Format("BD_What_Cookies_Hidden", FormatSize(Item.Bytes), browser),
                BrowserDataKind.Cookies => L.Format("BD_What_Cookies", Item.Count, Item.SiteTotal, FormatSize(Item.Bytes)),
                BrowserDataKind.SiteStorage => L.Format("BD_What_SiteStorage", Item.Sites.Count, FormatSize(Item.Bytes)),
                _ => L.Format("BD_What_" + Item.Kind, FormatSize(Item.Bytes)),
            };
        }
    }

    /// <summary>The websites concerned (shortened); for sign-out items these are the sites you'd be signed out of.</summary>
    public string SitesText
    {
        get
        {
            const int shown = 10;
            static string Short(IReadOnlyList<string> sites) =>
                string.Join(", ", sites.Take(shown)) + (sites.Count > shown ? " " + Loc.Instance.Format("BD_More", sites.Count - shown) : "");

            if (Item.Kind == BrowserDataKind.Cookies && !Item.DetailsHidden)
            {
                var parts = new List<string>();
                if (Item.Sites.Count > 0) parts.Add(Loc.Instance.Format("BD_SignOutSites", Short(Item.Sites)));
                if (Item.OtherSites.Count > 0)
                    parts.Add(Loc.Instance.Format(Item.Sites.Count > 0 ? "BD_OtherCookieSites" : "BD_OtherCookieSitesOnly", Short(Item.OtherSites)));
                return string.Join(Environment.NewLine, parts);
            }
            if (Item.Sites.Count == 0) return "";
            var key = Item.Kind == BrowserDataKind.SiteStorage ? "BD_StorageSites" : "BD_SitesList";
            return Loc.Instance.Format(key, Short(Item.Sites));
        }
    }

    public Visibility SitesVisibility => SitesText.Length > 0 ? Visibility.Visible : Visibility.Collapsed;
    public Brush SitesBrush => Item.CanSignOut ? Red : Grey;

    public string Origin
    {
        get
        {
            var key = Item.Kind == BrowserDataKind.CountryMemory ? "BD_Origin_CountryMemory_" + Item.Browser.Family : "BD_Origin_" + Item.Kind;
            return Loc.Instance["BD_OriginLabel"] + " " + Loc.Instance[key];
        }
    }

    public string After => Loc.Instance["BD_AfterLabel"] + " " + Loc.Instance["BD_After_" + Item.Kind];

    public string RiskText => Loc.Instance[Item.CanSignOut ? "BD_Risk_SignOut" : Item.Risk switch
    {
        BrowserDataRisk.Problem => "BD_Risk_Problem",
        BrowserDataRisk.Warning => "BD_Risk_Warning",
        _ => "BD_Risk_Info",
    }];

    public Brush RiskBrush => Item.CanSignOut ? Red : Item.Risk switch
    {
        BrowserDataRisk.Problem => Red,
        BrowserDataRisk.Warning => Amber,
        _ => Grey,
    };

    public void Refresh()
    {
        OnPropertyChanged(nameof(Title));
        OnPropertyChanged(nameof(What));
        OnPropertyChanged(nameof(Origin));
        OnPropertyChanged(nameof(After));
        OnPropertyChanged(nameof(RiskText));
        OnPropertyChanged(nameof(SitesText));
    }

    // The left-to-right mark keeps "Iran (IR)" in order inside Persian text.
    public static string CountryList(IEnumerable<string> codes) =>
        string.Join(", ", codes.Select(c => $"{CountryNames.Get(c)} ({c})‎"));

    public static string FormatSize(long bytes) => bytes switch
    {
        >= 1L << 30 => $"{bytes / (double)(1L << 30):0.0} GB",
        >= 1L << 20 => $"{bytes / (double)(1L << 20):0.0} MB",
        >= 1L << 10 => $"{bytes / 1024.0:0} KB",
        _ => $"{bytes} B",
    };

    static Brush Frozen(string hex)
    {
        var b = new SolidColorBrush((Color)ColorConverter.ConvertFromString(hex));
        b.Freeze();
        return b;
    }
}
