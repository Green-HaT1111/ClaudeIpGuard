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
    readonly TimeZoneSync? _timeZone;
    string? _lastTzLog;
    bool _autoTzWarned;
    readonly CancellationTokenSource _cts = new();
    readonly SemaphoreSlim _wake = new(0, 1);
    readonly object _enforceLock = new();
    readonly Timer _networkDebounce;
    DateTime _lastNetworkLog = DateTime.MinValue;
    volatile bool _paused;
    volatile bool _checking;
    volatile Verdict _verdict = Verdict.None;     // path the desktop app uses
    volatile Verdict _cliVerdict = Verdict.None;  // path Claude Code uses (differs only with a proxy)
    int _killCount;
    int _checkCount;
    bool _started;

    public event Action? StateChanged;
    public event Action<ActivityEvent>? Activity;

    public GuardEngine(Func<AppSettings> settings, IIpLocator locator, ProcessGuard guard, TimeZoneSync? timeZone = null)
    {
        _settings = settings;
        _locator = locator;
        _guard = guard;
        _timeZone = timeZone;
        _guard.ServiceStopDenied += name => Log(ActivityLevel.Warning, "Act_ServiceDenied", name);
        _networkDebounce = new Timer(_ => CheckNow());
    }

    /// <summary>IP and country of the path the desktop app uses.</summary>
    public GeoResult? LastResult { get; private set; }
    /// <summary>Set when Claude Code takes another path than the desktop app (proxy mode): its own IP/country, or null if unknown.</summary>
    public GeoResult? CliResult { get; private set; }
    public bool CliPathDiffers { get; private set; }
    /// <summary>The VPN found at the last check (tunnel and/or proxy, its program), or null before the first check.</summary>
    public VpnInfo? Vpn { get; private set; }
    public string? LastError { get; private set; }
    public DateTime? LastCheck { get; private set; }
    public DateTime? NextCheck { get; private set; }
    public Verdict Verdict => _verdict;
    public bool IsPaused => _paused;
    public bool IsChecking => _checking;
    public int KillCount => _killCount;
    public int CheckCount => _checkCount;

    public bool BlockDesktop => Blocks(_verdict);
    public bool BlockCli => Blocks(CliPathDiffers ? _cliVerdict : _verdict);
    public bool ShouldBlock => BlockDesktop || BlockCli;

    bool Blocks(Verdict v) => v == Verdict.NotAllowed || (v == Verdict.Unknown && _settings().FailSafeBlock);

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
        // With a proxy, the desktop app (Windows' proxy) and Claude Code (HTTPS_PROXY or none) can reach the internet
        // from different IPs. Check each path that is in use; without a proxy that is one check.
        var (windowsProxy, envProxy) = _locator.ProxyInUse();
        var (result, error, verdict) = await CheckPathAsync(direct: !windowsProxy, ct);
        var cliDiffers = windowsProxy != envProxy;
        var (cliResult, cliError, cliVerdict) = cliDiffers ? await CheckPathAsync(direct: !envProxy, ct) : (result, error, verdict);

        try { Vpn = VpnDetector.Detect(); }
        catch (Exception ex) { CrashLog.Write("VPN detection failed", ex); }

        var previousVerdict = _verdict;
        var previousIp = LastResult?.Ip;
        var previousCli = (CliPathDiffers, _cliVerdict, CliResult?.Ip);
        LastResult = result;
        CliResult = cliResult;
        CliPathDiffers = cliDiffers;
        LastError = error ?? cliError;
        LastCheck = DateTime.Now;
        Interlocked.Increment(ref _checkCount);
        _verdict = verdict;
        _cliVerdict = cliVerdict;
        _checking = false;

        if (cliDiffers && previousCli != (true, cliVerdict, cliResult?.Ip))
        {
            if (cliResult == null) Log(ActivityLevel.Warning, "Act_CliPathUnknown", cliError ?? "?");
            else Log(cliVerdict == Verdict.Allowed ? ActivityLevel.Info : ActivityLevel.Danger,
                cliVerdict == Verdict.Allowed ? "Act_CliPathAllowed" : "Act_CliPathBlocked", cliResult.CountryName, cliResult.CountryCode, cliResult.Ip);
        }

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

        if (result != null && _settings().SyncTimeZone) SyncTimeZone(result);

        RaiseStateChanged();
        if (!_paused && ShouldBlock) Enforce();
    }

    async Task<(GeoResult? Result, string? Error, Verdict Verdict)> CheckPathAsync(bool direct, CancellationToken ct)
    {
        try
        {
            var result = await _locator.LocateAsync(direct, ct);
            var allowed = _settings().AllowedCountries
                .Any(c => string.Equals(c, result.CountryCode, StringComparison.OrdinalIgnoreCase));
            return (result, null, allowed ? Verdict.Allowed : Verdict.NotAllowed);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            _checking = false;
            throw;
        }
        catch (Exception ex)
        {
            return (null, ex.Message, Verdict.Unknown);
        }
    }

    /// <summary>Makes the Windows time zone match the IP's location. Repeated outcomes are logged once.</summary>
    void SyncTimeZone(GeoResult r)
    {
        if (_timeZone == null) return;
        try
        {
            var res = _timeZone.Apply(r.TimeZone);
            var logKey = $"{res.Outcome}|{res.WindowsId}|{r.TimeZone}|{r.CountryCode}";
            if (res.Outcome != TzOutcome.Changed && logKey == _lastTzLog) return;
            _lastTzLog = logKey;

            switch (res.Outcome)
            {
                case TzOutcome.Changed:
                    Log(ActivityLevel.Info, "Act_TzChanged", TimeZoneSync.DisplayName(res.WindowsId!), r.CountryName);
                    if (!_autoTzWarned && TimeZoneSync.WindowsAutoTimeZoneOn())
                    {
                        _autoTzWarned = true;
                        Log(ActivityLevel.Warning, "Act_TzAutoOn");
                    }
                    break;
                case TzOutcome.Failed:
                    Log(ActivityLevel.Warning, "Act_TzFailed", res.WindowsId!, res.Error ?? "?");
                    break;
                case TzOutcome.Unknown:
                    Log(ActivityLevel.Warning, "Act_TzUnknown", r.CountryName, r.TimeZone ?? "?");
                    break;
            }
        }
        catch (Exception ex)
        {
            CrashLog.Write("Time zone sync failed", ex);
        }
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
                // Close only what is on a blocked path (with a proxy, the desktop app and Claude Code can differ).
                var settings = _settings().Clone();
                settings.KillDesktopApp &= BlockDesktop;
                settings.KillCli &= BlockCli;
                var reports = _guard.KillTargets(settings);
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
