using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Windows;
using System.Windows.Media;
using System.Windows.Threading;
using ClaudeIpGuard.Core;
using ClaudeIpGuard.Localization;

namespace ClaudeIpGuard.UI;

public abstract class ObservableObject : INotifyPropertyChanged
{
    public event PropertyChangedEventHandler? PropertyChanged;

    protected void OnPropertyChanged([CallerMemberName] string? name = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));

    protected bool Set<T>(ref T field, T value, [CallerMemberName] string? name = null)
    {
        if (EqualityComparer<T>.Default.Equals(field, value)) return false;
        field = value;
        OnPropertyChanged(name);
        return true;
    }
}

/// <summary>What the host app provides to the window (dialogs, saving, exit).</summary>
public interface IAppHost
{
    AppSettings Settings { get; }
    bool VerifyPassword(Window? owner, string reasonKey);
    bool ChangePassword(Window? owner);
    void SaveSettings(AppSettings settings);
    void SaveLanguage(string language);
    void RequestExit(Window? owner);
}

public sealed class MainViewModel : ObservableObject
{
    const int MaxActivity = 300;

    static readonly Brush GreenBrush = Gradient("#16A34A", "#0F766E");
    static readonly Brush RedBrush = Gradient("#DC2626", "#9F1239");
    static readonly Brush AmberBrush = Gradient("#D97706", "#B45309");
    static readonly Brush GreyBrush = Gradient("#475569", "#334155");

    readonly Dispatcher _dispatcher;
    readonly IAppHost _host;

    string _statusTitle = "", _statusDescription = "", _statusGlyph = "";
    Brush _statusBrush = GreyBrush;
    string _publicIp = "—", _country = "—", _city = "—", _provider = "—", _lastCheck = "—", _nextCheck = "—";
    string _closedCount = "0", _checkCount = "0", _allowedCount = "0", _pauseButtonText = "";
    string _errorText = "";
    bool _canCheck = true;

    public MainViewModel(GuardEngine engine, IAppHost host, bool testMode)
    {
        Engine = engine;
        _host = host;
        _dispatcher = Dispatcher.CurrentDispatcher;
        IsTestMode = testMode;
        Editor = new SettingsEditor();
        Editor.LoadFrom(host.Settings);
        BrowserData = new BrowserDataViewModel(engine, testMode);

        engine.StateChanged += () => Ui(Refresh);
        engine.Activity += e => Ui(() => AddActivity(e));
        Loc.Instance.LanguageChanged += () =>
        {
            Refresh();
            foreach (var item in Activity) item.Refresh();
            Editor.RefreshTexts();
            Privacy.RefreshTexts();
            BrowserData.RefreshTexts();
        };

        var timer = new DispatcherTimer(TimeSpan.FromSeconds(1), DispatcherPriority.Background, (_, _) => UpdateNextCheck(), _dispatcher);
        timer.Start();
        Refresh();
    }

    public GuardEngine Engine { get; }
    public SettingsEditor Editor { get; }
    public PrivacyViewModel Privacy { get; } = new();
    public BrowserDataViewModel BrowserData { get; }
    public ObservableCollection<ActivityItem> Activity { get; } = new();
    public bool IsTestMode { get; }
    public Visibility TestBannerVisibility => IsTestMode ? Visibility.Visible : Visibility.Collapsed;
    public Visibility ActivityEmptyVisibility => Activity.Count == 0 ? Visibility.Visible : Visibility.Collapsed;

    public string StatusTitle { get => _statusTitle; private set => Set(ref _statusTitle, value); }
    public string StatusDescription { get => _statusDescription; private set => Set(ref _statusDescription, value); }
    public string StatusGlyph { get => _statusGlyph; private set => Set(ref _statusGlyph, value); }
    public Brush StatusBrush { get => _statusBrush; private set => Set(ref _statusBrush, value); }
    public string PublicIp { get => _publicIp; private set => Set(ref _publicIp, value); }
    public string Country { get => _country; private set => Set(ref _country, value); }
    public string City { get => _city; private set => Set(ref _city, value); }
    public string Provider { get => _provider; private set => Set(ref _provider, value); }
    public string LastCheck { get => _lastCheck; private set => Set(ref _lastCheck, value); }
    public string NextCheck { get => _nextCheck; private set => Set(ref _nextCheck, value); }
    public string ClosedCount { get => _closedCount; private set => Set(ref _closedCount, value); }
    public string CheckCount { get => _checkCount; private set => Set(ref _checkCount, value); }
    public string AllowedCount { get => _allowedCount; private set => Set(ref _allowedCount, value); }
    public string PauseButtonText { get => _pauseButtonText; private set => Set(ref _pauseButtonText, value); }
    public bool CanCheck { get => _canCheck; private set => Set(ref _canCheck, value); }

    public string ErrorText
    {
        get => _errorText;
        private set
        {
            if (Set(ref _errorText, value)) OnPropertyChanged(nameof(ErrorVisibility));
        }
    }

    public Visibility ErrorVisibility => string.IsNullOrEmpty(ErrorText) ? Visibility.Collapsed : Visibility.Visible;

    void Ui(Action action)
    {
        if (_dispatcher.CheckAccess()) action();
        else _dispatcher.BeginInvoke(action);
    }

    public void Refresh()
    {
        var L = Loc.Instance;
        var e = Engine;
        var r = e.LastResult;
        // The left-to-right mark (U+200E) keeps "Germany (DE)" in the right order inside Persian text.
        var countryLabel = r != null ? $"{r.CountryName} ({r.CountryCode})‎" : "—";

        switch (e.State)
        {
            case GuardState.Paused:
                StatusBrush = AmberBrush;
                StatusGlyph = "";
                StatusTitle = L["Status_Paused_Title"];
                StatusDescription = L["Status_Paused_Desc"];
                break;
            case GuardState.Starting:
                StatusBrush = GreyBrush;
                StatusGlyph = "";
                StatusTitle = L["Status_Checking_Title"];
                StatusDescription = L["Status_Checking_Desc"];
                break;
            case GuardState.Allowed when e.Verdict == Verdict.Unknown:
                StatusBrush = AmberBrush;
                StatusGlyph = "";
                StatusTitle = L["Status_UnknownAllowed_Title"];
                StatusDescription = L["Status_UnknownAllowed_Desc"];
                break;
            case GuardState.Allowed:
                StatusBrush = GreenBrush;
                StatusGlyph = "";
                StatusTitle = L["Status_Allowed_Title"];
                StatusDescription = L.Format("Status_Allowed_Desc", countryLabel);
                break;
            case GuardState.Blocked when e.Verdict == Verdict.Unknown:
                StatusBrush = RedBrush;
                StatusGlyph = "";
                StatusTitle = L["Status_Blocked_Title"];
                StatusDescription = L["Status_Unknown_Desc"];
                break;
            default:
                StatusBrush = RedBrush;
                StatusGlyph = "";
                StatusTitle = L["Status_Blocked_Title"];
                StatusDescription = L.Format("Status_Blocked_Desc", countryLabel);
                break;
        }

        PublicIp = r?.Ip ?? "—";
        Country = countryLabel;
        City = string.IsNullOrEmpty(r?.City) ? "—" : r!.City!;
        Provider = r?.Provider ?? "—";
        LastCheck = e.LastCheck?.ToString("HH:mm:ss") ?? "—";
        ClosedCount = e.KillCount.ToString();
        CheckCount = e.CheckCount.ToString();
        AllowedCount = _host.Settings.AllowedCountries.Count.ToString();
        PauseButtonText = e.IsPaused ? L["Btn_Resume"] : L["Btn_Pause"];
        CanCheck = !e.IsChecking;
        ErrorText = e.LastError != null ? L.Format("Last_Error", e.LastError) : "";
        UpdateNextCheck();
    }

    void UpdateNextCheck()
    {
        if (Engine.IsChecking)
        {
            NextCheck = Loc.Instance["Info_Checking"];
            return;
        }
        var next = Engine.NextCheck;
        if (next == null)
        {
            NextCheck = "—";
            return;
        }
        var seconds = Math.Max(0, (int)Math.Ceiling((next.Value - DateTime.Now).TotalSeconds));
        NextCheck = Loc.Instance.Format("Info_InSeconds", seconds);
    }

    void AddActivity(ActivityEvent e)
    {
        Activity.Insert(0, new ActivityItem(e));
        while (Activity.Count > MaxActivity) Activity.RemoveAt(Activity.Count - 1);
        OnPropertyChanged(nameof(ActivityEmptyVisibility));
    }

    public void ClearActivity()
    {
        Activity.Clear();
        OnPropertyChanged(nameof(ActivityEmptyVisibility));
    }

    static Brush Gradient(string from, string to)
    {
        var b = new LinearGradientBrush(
            (Color)ColorConverter.ConvertFromString(from),
            (Color)ColorConverter.ConvertFromString(to),
            new Point(0, 0), new Point(1, 1));
        b.Freeze();
        return b;
    }
}

public sealed class ActivityItem : ObservableObject
{
    static readonly Brush Info = Frozen("#64748B");
    static readonly Brush Success = Frozen("#16A34A");
    static readonly Brush Warning = Frozen("#D97706");
    static readonly Brush Danger = Frozen("#DC2626");

    public ActivityItem(ActivityEvent e) => Event = e;

    public ActivityEvent Event { get; }
    public string Time => Event.Time.ToString("HH:mm:ss");
    public string Text => Loc.Instance.Format(Event.Key, Event.Args);

    public Brush LevelBrush => Event.Level switch
    {
        ActivityLevel.Success => Success,
        ActivityLevel.Warning => Warning,
        ActivityLevel.Danger => Danger,
        _ => Info,
    };

    public void Refresh() => OnPropertyChanged(nameof(Text));

    static Brush Frozen(string hex)
    {
        var b = new SolidColorBrush((Color)ColorConverter.ConvertFromString(hex));
        b.Freeze();
        return b;
    }
}

