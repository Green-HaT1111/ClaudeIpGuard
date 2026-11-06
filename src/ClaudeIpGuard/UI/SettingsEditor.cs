using System.Windows;
using System.Windows.Media;
using ClaudeIpGuard.Core;
using ClaudeIpGuard.Localization;

namespace ClaudeIpGuard.UI;

/// <summary>Editable copy of the settings shown on the Settings page.</summary>
public sealed class SettingsEditor : ObservableObject
{
    string _intervalText = "30", _message = "";
    bool _killDesktop, _killCli, _failSafe, _syncTimeZone, _messageIsError;
    string? _messageKey;
    object[] _messageArgs = Array.Empty<object>();

    public CountryPicker Picker { get; } = new();

    public string IntervalText { get => _intervalText; set => Set(ref _intervalText, value); }
    public bool KillDesktop { get => _killDesktop; set => Set(ref _killDesktop, value); }
    public bool KillCli { get => _killCli; set => Set(ref _killCli, value); }
    public bool FailSafe { get => _failSafe; set => Set(ref _failSafe, value); }
    public bool SyncTimeZone { get => _syncTimeZone; set => Set(ref _syncTimeZone, value); }

    public string Message { get => _message; private set => Set(ref _message, value); }
    public Brush MessageBrush => _messageIsError ? Brushes.Firebrick : Brushes.SeaGreen;
    public Visibility MessageVisibility => string.IsNullOrEmpty(Message) ? Visibility.Collapsed : Visibility.Visible;

    public void LoadFrom(AppSettings s)
    {
        IntervalText = s.CheckIntervalSeconds.ToString();
        KillDesktop = s.KillDesktopApp;
        KillCli = s.KillCli;
        FailSafe = s.FailSafeBlock;
        SyncTimeZone = s.SyncTimeZone;
        Picker.SearchText = "";
        Picker.SetSelection(s.AllowedCountries);
        ClearMessage();
    }

    public bool TryBuild(AppSettings current, out AppSettings result)
    {
        result = current.Clone();
        if (!int.TryParse(IntervalText.Trim(), out var interval) ||
            interval < AppSettings.MinInterval || interval > AppSettings.MaxInterval)
        {
            ShowMessage(true, "Err_Interval");
            return false;
        }
        var codes = Picker.SelectedCodes;
        if (codes.Count == 0)
        {
            ShowMessage(true, "Err_NoCountries");
            return false;
        }
        if (!KillDesktop && !KillCli)
        {
            ShowMessage(true, "Err_NoTargets");
            return false;
        }

        result.CheckIntervalSeconds = interval;
        result.KillDesktopApp = KillDesktop;
        result.KillCli = KillCli;
        result.FailSafeBlock = FailSafe;
        result.SyncTimeZone = SyncTimeZone;
        result.AllowedCountries = codes.ToList();
        result.Normalize();
        return true;
    }

    public void ShowMessage(bool isError, string key, params object[] args)
    {
        _messageIsError = isError;
        _messageKey = key;
        _messageArgs = args;
        Message = Loc.Instance.Format(key, args);
        OnPropertyChanged(nameof(MessageBrush));
        OnPropertyChanged(nameof(MessageVisibility));
    }

    public void ClearMessage()
    {
        _messageKey = null;
        Message = "";
        OnPropertyChanged(nameof(MessageVisibility));
    }

    public void RefreshTexts()
    {
        Picker.RefreshTexts();
        if (_messageKey != null) Message = Loc.Instance.Format(_messageKey, _messageArgs);
    }
}

/// <summary>All countries grouped by region, with check boxes, region-level select and search.</summary>
public sealed class CountryPicker : ObservableObject
{
    string _searchText = "";
    bool _batch;

    public CountryPicker()
    {
        Regions = Countries.Regions.Select(r => new RegionGroup(this, r)).ToList();
    }

    public IReadOnlyList<RegionGroup> Regions { get; }

    IEnumerable<CountryItem> AllItems => Regions.SelectMany(r => r.Countries);

    public IReadOnlyList<string> SelectedCodes =>
        AllItems.Where(c => c.IsSelected).Select(c => c.Code).OrderBy(c => c).ToList();

    public string SearchText
    {
        get => _searchText;
        set
        {
            if (!Set(ref _searchText, value ?? "")) return;
            ApplyFilter();
            OnPropertyChanged(nameof(PlaceholderVisibility));
        }
    }

    public Visibility PlaceholderVisibility => _searchText.Length == 0 ? Visibility.Visible : Visibility.Collapsed;

    public string SelectedSummary
    {
        get
        {
            var n = AllItems.Count(c => c.IsSelected);
            return n == 0 ? Loc.Instance["Set_SelectedNone"] : Loc.Instance.Format("Set_SelectedCount", n);
        }
    }

    /// <summary>Names of the chosen countries (or just their codes when there are many).</summary>
    public string SelectedList
    {
        get
        {
            var chosen = AllItems.Where(c => c.IsSelected).ToList();
            if (chosen.Count == 0) return "";
            var text = chosen.Count <= 10
                ? string.Join(", ", chosen.Select(c => c.Name))
                : string.Join(", ", chosen.Select(c => c.Code).OrderBy(c => c));
            return Loc.Instance.Format("Set_SelectedList", text);
        }
    }

    public void SetSelection(IEnumerable<string> codes)
    {
        var set = new HashSet<string>(codes, StringComparer.OrdinalIgnoreCase);
        Batch(() =>
        {
            foreach (var c in AllItems) c.IsSelected = set.Contains(c.Code);
        });
    }

    /// <summary>Selects or clears the countries currently shown (all of them when there is no search).</summary>
    public void SetVisible(bool selected) =>
        Batch(() =>
        {
            foreach (var c in AllItems.Where(c => c.Visibility == Visibility.Visible)) c.IsSelected = selected;
        });

    public void SelectEuropeOnly()
    {
        SearchText = "";
        SetSelection(EuropeCountries.Default);
    }

    internal void SetRegion(RegionGroup region, bool selected) =>
        Batch(() =>
        {
            foreach (var c in region.Countries) c.IsSelected = selected;
        });

    void Batch(Action action)
    {
        _batch = true;
        try { action(); }
        finally { _batch = false; }
        foreach (var r in Regions) r.NotifyCounts();
        NotifySelection();
    }

    internal void OnItemChanged(RegionGroup region)
    {
        if (_batch) return;
        region.NotifyCounts();
        NotifySelection();
    }

    void NotifySelection()
    {
        OnPropertyChanged(nameof(SelectedSummary));
        OnPropertyChanged(nameof(SelectedList));
    }

    void ApplyFilter()
    {
        var q = _searchText.Trim();
        foreach (var region in Regions)
        {
            var regionMatches = q.Length > 0 && region.Name.Contains(q, StringComparison.CurrentCultureIgnoreCase);
            var any = false;
            foreach (var c in region.Countries)
            {
                var show = q.Length == 0 || regionMatches ||
                           c.Name.Contains(q, StringComparison.CurrentCultureIgnoreCase) ||
                           c.Code.Equals(q, StringComparison.OrdinalIgnoreCase);
                c.Visibility = show ? Visibility.Visible : Visibility.Collapsed;
                any |= show;
            }
            region.Visibility = any ? Visibility.Visible : Visibility.Collapsed;
            region.IsExpanded = q.Length > 0 && any;
        }
    }

    public void RefreshTexts()
    {
        foreach (var r in Regions) r.NotifyName();
        NotifySelection();
    }
}

public sealed class RegionGroup : ObservableObject
{
    readonly CountryPicker _picker;
    readonly string _key;
    bool _isExpanded;
    Visibility _visibility = Visibility.Visible;

    public RegionGroup(CountryPicker picker, RegionInfoGroup info)
    {
        _picker = picker;
        _key = info.Key;
        Countries = info.Countries.Select(c => new CountryItem(this, c)).ToList();
    }

    public IReadOnlyList<CountryItem> Countries { get; }
    public string Name => Loc.Instance[_key];
    public string CountText => $"{Countries.Count(c => c.IsSelected)}/{Countries.Count}";

    /// <summary>true = all selected, false = none, null = some (shown as a partly filled box).</summary>
    public bool? IsChecked
    {
        get
        {
            var n = Countries.Count(c => c.IsSelected);
            return n == 0 ? false : n == Countries.Count ? true : null;
        }
        set => _picker.SetRegion(this, value ?? false);
    }

    public bool IsExpanded { get => _isExpanded; set => Set(ref _isExpanded, value); }
    public Visibility Visibility { get => _visibility; set => Set(ref _visibility, value); }

    internal void ItemChanged() => _picker.OnItemChanged(this);

    internal void NotifyCounts()
    {
        OnPropertyChanged(nameof(IsChecked));
        OnPropertyChanged(nameof(CountText));
    }

    internal void NotifyName() => OnPropertyChanged(nameof(Name));
}

public sealed class CountryItem : ObservableObject
{
    readonly RegionGroup _region;
    bool _isSelected;
    Visibility _visibility = Visibility.Visible;

    public CountryItem(RegionGroup region, CountryInfo info)
    {
        _region = region;
        Code = info.Code;
        Name = info.Name;
    }

    public string Code { get; }
    public string Name { get; }
    // The left-to-right mark keeps "(GB)" in place when the window is in Persian.
    public string Display => $"{Name} ({Code})‎";

    public bool IsSelected
    {
        get => _isSelected;
        set
        {
            if (Set(ref _isSelected, value)) _region.ItemChanged();
        }
    }

    public Visibility Visibility { get => _visibility; set => Set(ref _visibility, value); }
}
