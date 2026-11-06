using System.Threading;
using System.Windows;
using System.Windows.Threading;
using ClaudeIpGuard.Core;
using ClaudeIpGuard.Localization;
using ClaudeIpGuard.UI;

namespace ClaudeIpGuard;

/// <summary>
/// Startup options:
///   --minimized                start hidden in the tray
///   --test-mode                close Notepad instead of Claude, separate settings file
///   --simulate-country XX      (test mode only) pretend the IP is in country XX
///   --simulate-failure         (test mode only) pretend the location lookup fails
/// </summary>
public sealed record StartupOptions(bool Minimized, bool TestMode, string? SimulateCountry, bool SimulateFailure)
{
    public static StartupOptions Parse(string[] args)
    {
        bool minimized = false, test = false, fail = false;
        string? country = null;
        for (int i = 0; i < args.Length; i++)
        {
            var a = args[i].ToLowerInvariant();
            if (a == "--minimized") minimized = true;
            else if (a == "--test-mode") test = true;
            else if (a == "--simulate-failure") fail = true;
            else if (a == "--simulate-country" && i + 1 < args.Length) country = args[++i].Trim().ToUpperInvariant();
        }
        return test ? new(minimized, true, country, fail) : new(minimized, false, null, false);
    }
}

public partial class App : Application, IAppHost
{
    const string MutexName = "ClaudeIpGuard_SingleInstance";
    const string ShowEventName = "ClaudeIpGuard_ShowDashboard";

    Mutex? _mutex;
    EventWaitHandle? _showEvent;
    RegisteredWaitHandle? _showWait;
    SettingsStore _store = null!;
    volatile AppSettings _settings = new();
    GuardEngine? _engine;
    TrayIcon? _tray;
    MainWindow? _window;
    bool _exiting;

    public AppSettings Settings => _settings;

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        // Elevated helper run (Windows asked for admin): change the kill switch firewall rules and exit.
        if (e.Args.Length > 0 && e.Args[0] == "--kill-switch")
        {
            Shutdown(KillSwitch.RunHelper(e.Args));
            return;
        }
        var options = StartupOptions.Parse(e.Args);
        var suffix = options.TestMode ? "_Test" : "";

        // Started from inside Claude (its terminal, Claude Code...)? Then closing Claude would close the guard too.
        // Restart as an independent copy through Explorer and leave.
        if (!options.TestMode && SelfLaunch.StartedByClaude() && SelfLaunch.RelaunchIndependent(options.Minimized))
        {
            Shutdown();
            return;
        }
        if (SelfLaunch.TakeRelaunchMinimized()) options = options with { Minimized = true };

        // One instance only. A second launch just brings the running dashboard to the front.
        _mutex = new Mutex(true, MutexName + suffix, out var isFirst);
        if (!isFirst)
        {
            try
            {
                using var ev = EventWaitHandle.OpenExisting(ShowEventName + suffix);
                ev.Set();
            }
            catch (Exception) { }
            _mutex.Dispose();
            _mutex = null;
            Shutdown();
            return;
        }
        _showEvent = new EventWaitHandle(false, EventResetMode.AutoReset, ShowEventName + suffix);
        _showWait = ThreadPool.RegisterWaitForSingleObject(_showEvent,
            (_, _) => Dispatcher.BeginInvoke(ShowDashboard), null, Timeout.Infinite, false);

        // Keep running no matter what: log unexpected errors instead of crashing.
        DispatcherUnhandledException += (_, args) =>
        {
            CrashLog.Write("UI error", args.Exception);
            args.Handled = true;
        };
        AppDomain.CurrentDomain.UnhandledException += (_, args) =>
            CrashLog.Write("Fatal error", args.ExceptionObject as Exception);
        TaskScheduler.UnobservedTaskException += (_, args) =>
        {
            CrashLog.Write("Background task error", args.Exception);
            args.SetObserved();
        };

        _store = new SettingsStore(options.TestMode ? "settings.test.json" : "settings.json");
        _settings = _store.Load();
        Loc.Instance.Language = _settings.Language;

        if (!_settings.HasPassword)
        {
            var password = PasswordDialog.ShowCreate(null);
            if (password == null)
            {
                ExitNow();
                return;
            }
            var withPassword = _settings.Clone();
            PasswordHasher.SetPassword(withPassword, password);
            Persist(withPassword);
        }

        IIpLocator locator = options.SimulateCountry != null || options.SimulateFailure
            ? new SimulatedLocator(options.SimulateCountry, options.SimulateFailure)
            : new GeoIpService();
        var guard = new ProcessGuard(options.TestMode ? new[] { "notepad" } : null);
        var timeZone = new TimeZoneSync(dryRun: options.TestMode);

        _engine = new GuardEngine(() => _settings, locator, guard, timeZone);
        var vm = new MainViewModel(_engine, this, options.TestMode);
        _window = new MainWindow(vm, this);
        if (options.TestMode) _window.Title += " [TEST]";
        _tray = new TrayIcon(_engine, ShowDashboard, () => RequestExit(null));
        vm.BrowserData.Notify += (title, text) => _tray?.ShowNotification(title, text);
        _tray.BalloonClicked += () =>
        {
            ShowDashboard();
            _window?.ShowBrowserData();
        };
        _engine.Start();

        if (!options.Minimized) ShowDashboard();
    }

    public void ShowDashboard()
    {
        if (_window == null || _exiting) return;
        _window.Show();
        if (_window.WindowState == WindowState.Minimized) _window.WindowState = WindowState.Normal;
        _window.Activate();
        _window.Topmost = true;
        _window.Topmost = false;
        _window.Focus();
    }

    public bool VerifyPassword(Window? owner, string reasonKey) =>
        PasswordDialog.ShowVerify(owner, reasonKey,
            pwd => PasswordHasher.Verify(_settings, pwd),
            () => _engine?.Log(ActivityLevel.Warning, "Act_WrongPassword"));

    public bool ChangePassword(Window? owner)
    {
        if (!VerifyPassword(owner, "Pwd_Reason_Change")) return false;
        var password = PasswordDialog.ShowCreate(owner, isChange: true);
        if (password == null) return false;
        var updated = _settings.Clone();
        PasswordHasher.SetPassword(updated, password);
        Persist(updated);
        _engine?.Log(ActivityLevel.Info, "Act_PasswordChanged");
        return true;
    }

    public void SaveSettings(AppSettings settings)
    {
        var updated = settings.Clone();
        // The password can only change through ChangePassword.
        updated.PasswordHash = _settings.PasswordHash;
        updated.PasswordSalt = _settings.PasswordSalt;
        updated.PasswordIterations = _settings.PasswordIterations;
        updated.Language = _settings.Language;
        updated.Normalize();
        Persist(updated);
        _engine?.Log(ActivityLevel.Info, "Act_SettingsSaved");
        _engine?.CheckNow();
    }

    public void SaveLanguage(string language)
    {
        var updated = _settings.Clone();
        updated.Language = language;
        updated.Normalize();
        Persist(updated);
    }

    public void RequestExit(Window? owner)
    {
        if (_exiting) return;
        if (owner == null && _window is { IsVisible: true }) owner = _window;
        if (VerifyPassword(owner, "Pwd_Reason_Exit")) ExitNow();
    }

    void Persist(AppSettings settings)
    {
        try
        {
            _store.Save(settings);
        }
        catch (Exception ex)
        {
            CrashLog.Write("Could not save settings", ex);
        }
        _settings = settings;
    }

    void ExitNow()
    {
        if (_exiting) return;
        _exiting = true;
        _engine?.Dispose();
        _tray?.Dispose();
        if (_window != null)
        {
            _window.AllowClose = true;
            _window.Close();
        }
        _showWait?.Unregister(null);
        _showEvent?.Dispose();
        if (_mutex != null)
        {
            try { _mutex.ReleaseMutex(); } catch (Exception) { }
            _mutex.Dispose();
        }
        Shutdown();
    }

    protected override void OnSessionEnding(SessionEndingCancelEventArgs e)
    {
        // Windows is signing out or shutting down: exit without asking for the password.
        base.OnSessionEnding(e);
        ExitNow();
    }
}
