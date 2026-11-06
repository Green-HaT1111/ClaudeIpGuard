using System.Collections.ObjectModel;
using System.Windows;
using System.Windows.Media;
using ClaudeIpGuard.Core;
using ClaudeIpGuard.Localization;

namespace ClaudeIpGuard.UI;

/// <summary>The "Leak check" page: runs LeakChecker and shows each result.</summary>
public sealed class PrivacyViewModel : ObservableObject
{
    readonly LeakChecker _checker = new();
    bool _running;
    DateTime? _lastRun;
    string _summary = "", _lastRunText = "";

    KillSwitchState _kill = new(false, Array.Empty<string>(), Array.Empty<string>());
    List<string> _profileServers = new();
    bool _killBusy;
    string _killText = "", _killResult = "";
    bool _killResultIsError;

    public PrivacyViewModel()
    {
        RefreshTexts();
        _ = RefreshKillSwitchAsync();
    }

    // ---------- kill switch card ----------

    bool KillUpToDate => _kill.On && _profileServers.All(s => _kill.Servers.Contains(s));
    public string KillSwitchText { get => _killText; private set => Set(ref _killText, value); }
    public string KillResult { get => _killResult; private set { if (Set(ref _killResult, value)) OnPropertyChanged(nameof(KillResultVisibility)); } }
    public Visibility KillResultVisibility => string.IsNullOrEmpty(KillResult) ? Visibility.Collapsed : Visibility.Visible;
    public Brush KillResultBrush => _killResultIsError ? Brushes.Firebrick : Brushes.SeaGreen;
    public Brush KillStatusBrush => _kill.On ? (KillUpToDate ? Brushes.SeaGreen : Brushes.DarkOrange) : Brushes.DarkOrange;
    public string KillStatus => Loc.Instance[_kill.On ? (KillUpToDate ? "Kill_StatusOn" : "Kill_StatusOutdated") : "Kill_StatusOff"];
    public string KillOnButtonText => Loc.Instance[_kill.On ? "Btn_KillUpdate" : "Btn_KillOn"];
    public Visibility KillOnVisibility => KillUpToDate ? Visibility.Collapsed : Visibility.Visible;
    public Visibility KillOffVisibility => _kill.On ? Visibility.Visible : Visibility.Collapsed;
    public bool CanToggleKill => !_killBusy;

    public async Task RefreshKillSwitchAsync()
    {
        var (state, servers) = await Task.Run(() => (KillSwitch.Read(), KillSwitch.FindVpnServers()));
        _kill = state;
        _profileServers = servers;
        RefreshKillTexts();
    }

    void RefreshKillTexts()
    {
        var L = Loc.Instance;
        KillSwitchText = _kill.On
            ? L.Format("Kill_DescOn", string.Join(", ", _kill.Adapters), string.Join(", ", _kill.Servers)) +
              (KillUpToDate ? "" : " " + L.Format("Kill_DescMissing", string.Join(", ", _profileServers.Except(_kill.Servers))))
            : L["Kill_DescOff"];
        foreach (var name in new[] { nameof(KillStatus), nameof(KillStatusBrush), nameof(KillOnButtonText), nameof(KillOnVisibility),
                     nameof(KillOffVisibility), nameof(CanToggleKill), nameof(KillResultBrush) })
            OnPropertyChanged(name);
    }

    /// <summary>Turns the kill switch on (or updates it with the current VPN servers). Windows asks for admin.</summary>
    public async Task TurnKillSwitchOnAsync(Window owner)
    {
        var L = Loc.Instance;
        var servers = await Task.Run(() => KillSwitch.FindVpnServers());
        var adapters = KillSwitch.PhysicalAdapters();
        if (servers.Count == 0) { ShowKillResult(true, L["Kill_NoServers"]); return; }
        if (adapters.Count == 0) { ShowKillResult(true, L["Kill_NoAdapters"]); return; }
        var options = L.IsPersian ? MessageBoxOptions.RtlReading | MessageBoxOptions.RightAlign : MessageBoxOptions.None;
        if (MessageBox.Show(owner, L.Format("Kill_ConfirmOn", string.Join(", ", adapters), string.Join(", ", servers)), L["Kill_Title"],
                MessageBoxButton.YesNo, MessageBoxImage.Question, MessageBoxResult.No, options) != MessageBoxResult.Yes) return;
        await ChangeKillSwitchAsync(true, servers, adapters);
    }

    public async Task TurnKillSwitchOffAsync(Window owner)
    {
        var L = Loc.Instance;
        var options = L.IsPersian ? MessageBoxOptions.RtlReading | MessageBoxOptions.RightAlign : MessageBoxOptions.None;
        if (MessageBox.Show(owner, L["Kill_ConfirmOff"], L["Kill_Title"], MessageBoxButton.YesNo, MessageBoxImage.Warning,
                MessageBoxResult.No, options) != MessageBoxResult.Yes) return;
        await ChangeKillSwitchAsync(false, Array.Empty<string>(), Array.Empty<string>());
    }

    async Task ChangeKillSwitchAsync(bool on, IReadOnlyList<string> servers, IReadOnlyList<string> adapters)
    {
        var L = Loc.Instance;
        _killBusy = true;
        RefreshKillTexts();
        try
        {
            var error = await Task.Run(() => KillSwitch.RunElevated(on, servers, adapters));
            await RefreshKillSwitchAsync();
            if (error == "cancelled") ShowKillResult(true, L["Kill_Cancelled"]);
            else if (error != null || _kill.On != on) ShowKillResult(true, L.Format("Kill_Failed", error ?? "?"));
            else ShowKillResult(false, L[on ? "Kill_DoneOn" : "Kill_DoneOff"]);
        }
        catch (Exception ex)
        {
            CrashLog.Write("Kill switch change failed", ex);
            ShowKillResult(true, L.Format("Kill_Failed", ex.Message));
        }
        finally
        {
            _killBusy = false;
            RefreshKillTexts();
        }
        await RunAsync(); // the routing check result changes
    }

    void ShowKillResult(bool isError, string text)
    {
        _killResultIsError = isError;
        KillResult = text;
        OnPropertyChanged(nameof(KillResultBrush));
    }

    public ObservableCollection<LeakItem> Items { get; } = new();
    public bool HasRun => _lastRun != null;
    public bool CanRun => !_running;
    public string Summary { get => _summary; private set => Set(ref _summary, value); }
    public string LastRunText { get => _lastRunText; private set => Set(ref _lastRunText, value); }
    public Visibility ProgressVisibility => _running ? Visibility.Visible : Visibility.Collapsed;

    public async Task RunAsync()
    {
        if (_running) return;
        _running = true;
        NotifyRunning();
        try
        {
            // Re-read the VPN profiles too: a new VPN server shows "Update kill switch" right away.
            await RefreshKillSwitchAsync();
            var results = await Task.Run(() => _checker.RunAsync(CancellationToken.None));
            Items.Clear();
            foreach (var r in results) Items.Add(new LeakItem(r));
            _lastRun = DateTime.Now;
        }
        catch (Exception ex)
        {
            CrashLog.Write("Leak check failed", ex);
        }
        finally
        {
            _running = false;
            NotifyRunning();
        }
    }

    void NotifyRunning()
    {
        OnPropertyChanged(nameof(CanRun));
        OnPropertyChanged(nameof(ProgressVisibility));
        OnPropertyChanged(nameof(HasRun));
        RefreshTexts();
    }

    public void RefreshTexts()
    {
        var L = Loc.Instance;
        if (_running) Summary = L["Privacy_Running"];
        else if (_lastRun == null) Summary = L["Privacy_NotRun"];
        else
        {
            Summary = L.Format("Privacy_Summary",
                Items.Count(i => i.Result.Status == CheckStatus.Problem),
                Items.Count(i => i.Result.Status == CheckStatus.Warning),
                Items.Count(i => i.Result.Status == CheckStatus.Ok));
        }
        LastRunText = _lastRun != null ? L.Format("Privacy_LastRun", _lastRun.Value.ToString("HH:mm:ss")) : "";
        foreach (var item in Items) item.Refresh();
        if (_killText.Length > 0) RefreshKillTexts();
    }
}

public sealed class LeakItem : ObservableObject
{
    static readonly Brush Green = Frozen("#16A34A"), Amber = Frozen("#D97706"), Red = Frozen("#DC2626"), Grey = Frozen("#64748B");

    public LeakItem(LeakCheckResult result) => Result = result;

    public LeakCheckResult Result { get; }
    public string Title => Loc.Instance[Result.TitleKey];
    public string Detail => Loc.Instance.Format(Result.DetailKey, Result.Args);

    public string StatusText => Loc.Instance[Result.Status switch
    {
        CheckStatus.Ok => "Leak_Status_Ok",
        CheckStatus.Warning => "Leak_Status_Warning",
        CheckStatus.Problem => "Leak_Status_Problem",
        _ => "Leak_Status_Info",
    }];

    public string Glyph => Result.Status switch
    {
        CheckStatus.Ok => "",
        CheckStatus.Warning => "",
        CheckStatus.Problem => "",
        _ => "",
    };

    public Brush StatusBrush => Result.Status switch
    {
        CheckStatus.Ok => Green,
        CheckStatus.Warning => Amber,
        CheckStatus.Problem => Red,
        _ => Grey,
    };

    public void Refresh()
    {
        OnPropertyChanged(nameof(Title));
        OnPropertyChanged(nameof(Detail));
        OnPropertyChanged(nameof(StatusText));
    }

    static Brush Frozen(string hex)
    {
        var b = new SolidColorBrush((Color)ColorConverter.ConvertFromString(hex));
        b.Freeze();
        return b;
    }
}
