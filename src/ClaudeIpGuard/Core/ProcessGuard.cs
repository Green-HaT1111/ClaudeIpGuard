using System.ComponentModel;
using System.Diagnostics;
using System.Management;
using System.ServiceProcess;
using System.Runtime.InteropServices;
using System.Text;

namespace ClaudeIpGuard.Core;

public enum TargetKind { Desktop, Cli, Custom }

public sealed record TargetProcess(int Pid, string Name, TargetKind Kind);

public sealed record KillReport(TargetKind Kind, string Name, int Count);

/// <summary>Finds and closes the Claude desktop app and the Claude Code CLI.</summary>
public sealed class ProcessGuard
{
    public const string DesktopServiceName = "CoworkVMService";

    readonly string[]? _overrideTargets;
    DateTime _nextServiceAttempt = DateTime.MinValue;

    /// <summary>Raised when Windows refuses to stop the desktop app's service (needs admin).</summary>
    public event Action<string>? ServiceStopDenied;

    /// <param name="overrideTargets">Test mode: close these process names instead of Claude (e.g. "notepad").</param>
    public ProcessGuard(IEnumerable<string>? overrideTargets = null)
    {
        _overrideTargets = overrideTargets?
            .Select(n => n.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ? n[..^4] : n)
            .ToArray();
    }

    public IReadOnlyList<KillReport> KillTargets(AppSettings settings)
    {
        var counts = new Dictionary<(TargetKind, string), int>();
        // Desktop first: killing its process tree also closes the Claude Code it started.
        foreach (var target in FindTargets(settings).OrderBy(t => t.Kind))
        {
            try
            {
                using var p = Process.GetProcessById(target.Pid);
                if (p.HasExited) continue;
                p.Kill(entireProcessTree: true);
                var key = (target.Kind, target.Kind == TargetKind.Custom ? target.Name : "claude");
                counts[key] = counts.GetValueOrDefault(key) + 1;
            }
            catch (ArgumentException)
            {
                // Already gone (closed together with its parent).
            }
            catch (Exception ex)
            {
                CrashLog.Write($"Could not close {target.Name} (pid {target.Pid})", ex);
            }
        }

        if (_overrideTargets == null && settings.KillDesktopApp && StopDesktopService() > 0)
        {
            var key = (TargetKind.Desktop, "claude");
            counts[key] = counts.GetValueOrDefault(key) + 1;
        }

        return counts.Select(kv => new KillReport(kv.Key.Item1, kv.Key.Item2, kv.Value)).ToList();
    }

    public List<TargetProcess> FindTargets(AppSettings settings)
    {
        var list = new List<TargetProcess>();

        if (_overrideTargets != null)
        {
            foreach (var name in _overrideTargets)
                foreach (var p in Process.GetProcessesByName(name))
                    using (p) list.Add(new TargetProcess(p.Id, name, TargetKind.Custom));
            return list;
        }

        if (settings.KillDesktopApp || settings.KillCli)
        {
            // Look at every process, not only claude.exe: the desktop app also starts helpers with
            // other names from its install folder, and all of them must go (as in Task Manager).
            int self = Environment.ProcessId;
            foreach (var p in Process.GetProcesses())
            {
                using (p)
                {
                    try
                    {
                        // Session 0 = Windows services (e.g. cowork-svc.exe). Those are stopped through
                        // the service manager in StopDesktopService, not killed.
                        if (p.Id == self || p.Id <= 4 || p.SessionId == 0) continue;
                        bool namedClaude = p.ProcessName.Equals("claude", StringComparison.OrdinalIgnoreCase);
                        var path = GetImagePath(p.Id);
                        if (path == null && !namedClaude) continue;

                        TargetKind kind;
                        if (path == null)
                            kind = settings.KillDesktopApp ? TargetKind.Desktop : TargetKind.Cli;
                        else if (IsDesktopPath(path))
                            kind = TargetKind.Desktop;
                        else if (IsDesktopBundledCliPath(path))
                            kind = settings.KillDesktopApp ? TargetKind.Desktop : TargetKind.Cli;
                        else if (namedClaude)
                            kind = TargetKind.Cli;
                        else
                            continue;

                        if ((kind == TargetKind.Desktop && settings.KillDesktopApp) ||
                            (kind == TargetKind.Cli && settings.KillCli))
                            list.Add(new TargetProcess(p.Id, p.ProcessName, kind));
                    }
                    catch (InvalidOperationException)
                    {
                        // Exited while we were looking at it.
                    }
                }
            }
        }

        // Claude Code installed through npm runs as node.exe ... @anthropic-ai/claude-code/cli.js
        if (settings.KillCli && AnyProcess("node"))
        {
            try
            {
                using var searcher = new ManagementObjectSearcher(
                    "SELECT ProcessId, CommandLine FROM Win32_Process WHERE Name = 'node.exe'");
                foreach (ManagementObject mo in searcher.Get())
                {
                    using (mo)
                    {
                        if (mo["CommandLine"] is string cmd && IsClaudeCliCommandLine(cmd))
                            list.Add(new TargetProcess(Convert.ToInt32(mo["ProcessId"]), "node", TargetKind.Cli));
                    }
                }
            }
            catch (Exception ex)
            {
                CrashLog.Write("WMI query for node.exe failed", ex);
            }
        }

        return list;
    }

    public static bool IsDesktopPath(string path) =>
        path.Contains(@"\WindowsApps\Claude_", StringComparison.OrdinalIgnoreCase) ||   // Microsoft Store / MSIX
        path.Contains(@"\AnthropicClaude\", StringComparison.OrdinalIgnoreCase) ||      // classic installer
        path.Contains(@"\Programs\Claude\", StringComparison.OrdinalIgnoreCase);

    /// <summary>The Claude Code copy that the desktop app downloads and runs (%AppData%\Claude\claude-code\...).</summary>
    public static bool IsDesktopBundledCliPath(string path) =>
        path.Contains(@"\AppData\Roaming\Claude\", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// The desktop app's background Windows service (Cowork VM). Only an admin may stop a service,
    /// so when Windows refuses we report it once and retry later instead of every second.
    /// </summary>
    int StopDesktopService()
    {
        if (DateTime.UtcNow < _nextServiceAttempt) return 0;
        try
        {
            using var sc = new ServiceController(DesktopServiceName);
            var status = sc.Status; // throws if the service is not installed
            if (status is ServiceControllerStatus.Stopped or ServiceControllerStatus.StopPending) return 0;
            sc.Stop();
            return 1;
        }
        catch (InvalidOperationException ex) when (ex.InnerException is Win32Exception { NativeErrorCode: 5 })
        {
            _nextServiceAttempt = DateTime.UtcNow.AddMinutes(10);
            try { ServiceStopDenied?.Invoke(DesktopServiceName); }
            catch (Exception cbEx) { CrashLog.Write("ServiceStopDenied handler failed", cbEx); }
        }
        catch (InvalidOperationException)
        {
            // Not installed (older desktop app or no Cowork): check again in a minute.
            _nextServiceAttempt = DateTime.UtcNow.AddMinutes(1);
        }
        catch (Exception ex)
        {
            _nextServiceAttempt = DateTime.UtcNow.AddMinutes(1);
            CrashLog.Write($"Could not stop service {DesktopServiceName}", ex);
        }
        return 0;
    }

    public static bool IsClaudeCliCommandLine(string cmd) =>
        cmd.Contains("@anthropic-ai/claude-code", StringComparison.OrdinalIgnoreCase) ||
        cmd.Contains(@"@anthropic-ai\claude-code", StringComparison.OrdinalIgnoreCase);

    static bool AnyProcess(string name)
    {
        var procs = Process.GetProcessesByName(name);
        foreach (var p in procs) p.Dispose();
        return procs.Length > 0;
    }

    internal static string? GetImagePath(int pid)
    {
        var handle = OpenProcess(ProcessQueryLimitedInformation, false, pid);
        if (handle == IntPtr.Zero) return null;
        try
        {
            var sb = new StringBuilder(1024);
            int size = sb.Capacity;
            return QueryFullProcessImageName(handle, 0, sb, ref size) ? sb.ToString(0, size) : null;
        }
        finally
        {
            CloseHandle(handle);
        }
    }

    const uint ProcessQueryLimitedInformation = 0x1000;

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr OpenProcess(uint access, bool inheritHandle, int processId);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool QueryFullProcessImageName(IntPtr process, int flags, StringBuilder exeName, ref int size);

    [DllImport("kernel32.dll")]
    static extern bool CloseHandle(IntPtr handle);
}
