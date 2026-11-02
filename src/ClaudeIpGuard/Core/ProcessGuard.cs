using System.Diagnostics;
using System.Management;
using System.Runtime.InteropServices;
using System.Text;

namespace ClaudeIpGuard.Core;

public enum TargetKind { Desktop, Cli, Custom }

public sealed record TargetProcess(int Pid, string Name, TargetKind Kind);

public sealed record KillReport(TargetKind Kind, string Name, int Count);

/// <summary>Finds and closes the Claude desktop app and the Claude Code CLI.</summary>
public sealed class ProcessGuard
{
    readonly string[]? _overrideTargets;

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
                var key = (target.Kind, target.Name);
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
            foreach (var p in Process.GetProcessesByName("claude"))
            {
                using (p)
                {
                    var path = GetImagePath(p.Id);
                    var kind = path == null || IsDesktopPath(path) ? TargetKind.Desktop : TargetKind.Cli;
                    if (path == null && !settings.KillDesktopApp) kind = TargetKind.Cli;
                    if ((kind == TargetKind.Desktop && settings.KillDesktopApp) ||
                        (kind == TargetKind.Cli && settings.KillCli))
                        list.Add(new TargetProcess(p.Id, "claude", kind));
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

    public static bool IsClaudeCliCommandLine(string cmd) =>
        cmd.Contains("@anthropic-ai/claude-code", StringComparison.OrdinalIgnoreCase) ||
        cmd.Contains(@"@anthropic-ai\claude-code", StringComparison.OrdinalIgnoreCase);

    static bool AnyProcess(string name)
    {
        var procs = Process.GetProcessesByName(name);
        foreach (var p in procs) p.Dispose();
        return procs.Length > 0;
    }

    static string? GetImagePath(int pid)
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
