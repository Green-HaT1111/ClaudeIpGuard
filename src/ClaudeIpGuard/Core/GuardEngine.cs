using System.Net.NetworkInformation;

namespace ClaudeIpGuard.Core;

public enum Verdict { None, Allowed, NotAllowed, Unknown }

public enum GuardState { Starting, Allowed, Blocked, Paused }

public enum ActivityLevel { Info, Success, Warning, Danger }

/// <summary>A log line. Key is a localization key so the text follows the chosen language.</summary>
public sealed record ActivityEvent(DateTime Time, ActivityLevel Level, string Key, object[] Args);

/// <summary>
/// Background worker: checks the location on a timer (and right after network changes) and,
/// while the location is not allowed, closes Claude every second so it can't be reopened.
/// </summary>
public sealed class GuardEngine : IDisposable
{
    readonly Func<AppSettings> _settings;
    readonly IIpLocator _locator;
    readonly ProcessGuard _guard;
    readonly CancellationTokenSource _cts = new();
    readonly SemaphoreSlim _wake = new(0, 1);
    readonly object _enforceLock = new();
    readonly Timer _networkDebounce;
    DateTime _lastNetworkLog = DateTime.MinValue;
    volatile bool _paused;
    volatile bool _checking;
    volatile Verdict _verdict = Verdict.None;
    int _killCount;
    int _checkCount;
    bool _started;

    public event Action? StateChanged;
    public event Action<ActivityEvent>? Activity;

    public GuardEngine(Func<AppSettings> settings, IIpLocator locator, ProcessGuard guard)
    {
        _settings = settings;
        _locator = locator;
        _guard = guard;
        _networkDebounce = new Timer(_ => CheckNow());
    }

    public GeoResult? LastResult { get; private set; }
    public string? LastError { get; private set; }
    public DateTime? LastCheck { get; private set; }
    public DateTime? NextCheck { get; private set; }
    public Verdict Verdict => _verdict;
    public bool IsPaused => _paused;
    public bool IsChecking => _checking;
    public int KillCount => _killCount;
    public int CheckCount => _checkCount;

    public bool ShouldBlock =>
        _verdict == Verdict.NotAllowed || (_verdict == Verdict.Unknown && _settings().FailSafeBlock);

    public GuardState State =>
        _paused ? GuardState.Paused
        : _verdict == Verdict.None ? GuardState.Starting
        : ShouldBlock ? GuardState.Blocked
        : GuardState.Allowed;

    public void Start()
    {
        if (_started) return;
        _started = true;
        Log(ActivityLevel.Info, "Act_Started");
        NetworkChange.NetworkAddressChanged += OnNetworkChanged;
        NetworkChange.NetworkAvailabilityChanged += OnNetworkChanged;
        _ = Task.Run(CheckLoopAsync);
        _ = Task.Run(EnforceLoopAsync);
    }

    public void CheckNow()
    {
        try
        {
            if (_wake.CurrentCount == 0) _wake.Release();
        }
        catch (SemaphoreFullException) { }
        catch (ObjectDisposedException) { }
    }

    public void Pause()
    {
        if (_paused) return;
        _paused = true;
        Log(ActivityLevel.Warning, "Act_Paused");
        RaiseStateChanged();
    }

    public void Resume()
    {
        if (!_paused) return;
        _paused = false;
        Log(ActivityLevel.Success, "Act_Resumed");
        RaiseStateChanged();
        if (ShouldBlock) Enforce();
        CheckNow();
    }

    public void Log(ActivityLevel level, string key, params object[] args)
    {
        try { Activity?.Invoke(new ActivityEvent(DateTime.Now, level, key, args)); }
        catch (Exception ex) { CrashLog.Write("Activity handler failed", ex); }
    }

    void OnNetworkChanged(object? sender, EventArgs e)
    {
        // Windows fires several events while a VPN or Wi-Fi connects; check once things settle.
        if (DateTime.Now - _lastNetworkLog > TimeSpan.FromSeconds(10))
        {
            _lastNetworkLog = DateTime.Now;
            Log(ActivityLevel.Info, "Act_NetworkChanged");
        }
        try { _networkDebounce.Change(2500, Timeout.Infinite); }
        catch (ObjectDisposedException) { }
    }

    async Task CheckLoopAsync()
    {
        var ct = _cts.Token;
        while (!ct.IsCancellationRequested)
        {
            try
            {
                await RunCheckAsync(ct);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                CrashLog.Write("Check failed unexpectedly", ex);
            }

            var interval = TimeSpan.FromSeconds(
                Math.Clamp(_settings().CheckIntervalSeconds, AppSettings.MinInterval, AppSettings.MaxInterval));
            NextCheck = DateTime.Now + interval;
            RaiseStateChanged();
            try
            {
                await _wake.WaitAsync(interval, ct);
            }
            catch (OperationCanceledException)
            {
                break;
            }
        }
    }

    async Task RunCheckAsync(CancellationToken ct)
    {
        _checking = true;
        RaiseStateChanged();
        GeoResult? result = null;
        string? error = null;
        Verdict verdict;
        try
        {
            result = await _locator.LocateAsync(ct);
            var allowed = _settings().AllowedCountries
                .Any(c => string.Equals(c, result.CountryCode, StringComparison.OrdinalIgnoreCase));
            verdict = allowed ? Verdict.Allowed : Verdict.NotAllowed;
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            _checking = false;
            throw;
        }
        catch (Exception ex)
        {
            error = ex.Message;
            verdict = Verdict.Unknown;
        }

        var previousVerdict = _verdict;
        var previousIp = LastResult?.Ip;
        LastResult = result;
        LastError = error;
        LastCheck = DateTime.Now;
        Interlocked.Increment(ref _checkCount);
        _verdict = verdict;
        _checking = false;

        if (verdict != previousVerdict || (result != null && result.Ip != previousIp))
        {
            switch (verdict)
            {
                case Verdict.Allowed:
                    Log(ActivityLevel.Success, "Act_Allowed", result!.CountryName, result.CountryCode, result.Ip);
                    break;
                case Verdict.NotAllowed:
                    Log(ActivityLevel.Danger, "Act_Blocked", result!.CountryName, result.CountryCode, result.Ip);
                    break;
                case Verdict.Unknown:
                    Log(ActivityLevel.Warning, "Act_Failed", error ?? "?");
                    break;
            }
        }

        RaiseStateChanged();
        if (!_paused && ShouldBlock) Enforce();
    }

    async Task EnforceLoopAsync()
    {
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(1));
        try
        {
            while (await timer.WaitForNextTickAsync(_cts.Token))
            {
                if (!_paused && ShouldBlock) Enforce();
            }
        }
        catch (OperationCanceledException) { }
    }

    void Enforce()
    {
        lock (_enforceLock)
        {
            try
            {
                var reports = _guard.KillTargets(_settings());
                if (reports.Count == 0) return;
                Interlocked.Increment(ref _killCount);
                foreach (var r in reports)
                {
                    switch (r.Kind)
                    {
                        case TargetKind.Desktop: Log(ActivityLevel.Danger, "Act_ClosedDesktop", r.Count); break;
                        case TargetKind.Cli: Log(ActivityLevel.Danger, "Act_ClosedCli", r.Count); break;
                        default: Log(ActivityLevel.Danger, "Act_ClosedCustom", r.Name, r.Count); break;
                    }
                }
                RaiseStateChanged();
            }
            catch (Exception ex)
            {
                CrashLog.Write("Enforce failed", ex);
            }
        }
    }

    void RaiseStateChanged()
    {
        try { StateChanged?.Invoke(); }
        catch (Exception ex) { CrashLog.Write("StateChanged handler failed", ex); }
    }

    public void Dispose()
    {
        NetworkChange.NetworkAddressChanged -= OnNetworkChanged;
        NetworkChange.NetworkAvailabilityChanged -= OnNetworkChanged;
        _cts.Cancel();
        _networkDebounce.Dispose();
        (_locator as IDisposable)?.Dispose();
    }
}
