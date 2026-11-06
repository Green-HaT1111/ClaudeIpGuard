using System.Diagnostics;
using Microsoft.Win32;

namespace ClaudeIpGuard.Core;

public enum TzOutcome { AlreadySet, Changed, Unknown, Failed }

public sealed record TzResult(TzOutcome Outcome, string? WindowsId, string? Error);

/// <summary>
/// Sets the Windows time zone to the one of the public IP's location (e.g. IP in England ->
/// "GMT Standard Time"). Uses tzutil.exe, which normal users may run (no admin needed).
/// </summary>
public sealed class TimeZoneSync
{
    readonly bool _dryRun;
    string? _pretendCurrent;

    /// <param name="dryRun">Test mode: only pretend to change the time zone.</param>
    public TimeZoneSync(bool dryRun = false) => _dryRun = dryRun;

    /// <summary>IANA name from the location service ("Europe/London") -> Windows id ("GMT Standard Time").</summary>
    public static string? ToWindowsId(string? iana)
    {
        if (string.IsNullOrWhiteSpace(iana)) return null;
        return TimeZoneInfo.TryConvertIanaIdToWindowsId(iana.Trim(), out var id) ? id : null;
    }

    /// <summary>Friendly name, e.g. "(UTC+00:00) Dublin, Edinburgh, Lisbon, London".</summary>
    public static string DisplayName(string windowsId)
    {
        try { return TimeZoneInfo.FindSystemTimeZoneById(windowsId).DisplayName; }
        catch { return windowsId; }
    }

    public string CurrentId()
    {
        if (_pretendCurrent != null) return _pretendCurrent;
        TimeZoneInfo.ClearCachedData(); // notice changes made outside this app
        return TimeZoneInfo.Local.Id;
    }

    public TzResult Apply(string? iana)
    {
        var id = ToWindowsId(iana);
        if (id == null) return new TzResult(TzOutcome.Unknown, null, iana);
        if (string.Equals(CurrentId(), id, StringComparison.OrdinalIgnoreCase))
            return new TzResult(TzOutcome.AlreadySet, id, null);

        if (_dryRun)
        {
            _pretendCurrent = id;
            return new TzResult(TzOutcome.Changed, id, null);
        }

        var error = SetWithTzutil(id);
        if (error != null) return new TzResult(TzOutcome.Failed, id, error);
        TimeZoneInfo.ClearCachedData();
        return new TzResult(TzOutcome.Changed, id, null);
    }

    static string? SetWithTzutil(string windowsId)
    {
        var psi = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "tzutil.exe"))
        {
            CreateNoWindow = true,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        psi.ArgumentList.Add("/s");
        psi.ArgumentList.Add(windowsId);
        using var p = Process.Start(psi);
        if (p == null) return "tzutil could not start";
        var errTask = p.StandardError.ReadToEndAsync();
        var output = p.StandardOutput.ReadToEnd();
        if (!p.WaitForExit(15000))
        {
            try { p.Kill(); } catch { }
            return "tzutil timed out";
        }
        return p.ExitCode == 0 ? null : $"tzutil exit code {p.ExitCode}: {(output + errTask.Result).Trim()}";
    }

    /// <summary>
    /// Windows "Set time zone automatically" (tzautoupdate service) can change the time zone back
    /// based on Wi-Fi location, so the user should turn it off.
    /// </summary>
    public static bool WindowsAutoTimeZoneOn() =>
        Registry.GetValue(@"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\tzautoupdate", "Start", null) is int start
        && start != 4; // 4 = disabled
}
