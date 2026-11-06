using System.Diagnostics;
using System.Management;

namespace ClaudeIpGuard.Core;

/// <summary>
/// The guard must never be a child of Claude. If Claude (or a terminal running inside it) starts the guard,
/// Windows ends the guard together with Claude when the guard closes Claude. So when a Claude process is
/// among its parents, the guard restarts itself through Windows Explorer, which makes it independent.
/// </summary>
public static class SelfLaunch
{
    static string MarkerFile => Path.Combine(AppPaths.DataDirectory, "relaunch.txt");

    /// <summary>True when a Claude process (desktop app or Claude Code) is one of this process's parents.</summary>
    public static bool StartedByClaude()
    {
        try
        {
            var parents = new Dictionary<int, (int Parent, string Name, string? Path)>();
            using (var searcher = new ManagementObjectSearcher("SELECT ProcessId, ParentProcessId, Name, ExecutablePath FROM Win32_Process"))
                foreach (ManagementObject mo in searcher.Get())
                    using (mo)
                        parents[Convert.ToInt32(mo["ProcessId"])] =
                            (Convert.ToInt32(mo["ParentProcessId"]), (string)mo["Name"], mo["ExecutablePath"] as string);

            var pid = Environment.ProcessId;
            for (int depth = 0; depth < 16 && parents.TryGetValue(pid, out var p); depth++)
            {
                var parentId = p.Parent;
                if (parentId == 0 || parentId == pid || !parents.TryGetValue(parentId, out var parent)) break;
                if (IsClaude(parent.Name, parent.Path)) return true;
                pid = parentId;
            }
        }
        catch (Exception ex)
        {
            CrashLog.Write("Could not check which process started the guard", ex);
        }
        return false;
    }

    public static bool IsClaude(string name, string? path) =>
        name.Equals("claude.exe", StringComparison.OrdinalIgnoreCase) ||
        (path != null && (ProcessGuard.IsDesktopPath(path) || ProcessGuard.IsDesktopBundledCliPath(path)));

    /// <summary>
    /// Starts a new, independent copy through Explorer. Explorer passes no arguments, so "start minimized" travels
    /// in a small marker file. Returns false when this copy was itself just relaunched (never loop).
    /// </summary>
    public static bool RelaunchIndependent(bool minimized)
    {
        try
        {
            if (File.Exists(MarkerFile) && DateTime.Now - File.GetLastWriteTime(MarkerFile) < TimeSpan.FromSeconds(30))
                return false; // we are the relaunched copy and are still under Claude somehow: just run
            Directory.CreateDirectory(AppPaths.DataDirectory);
            File.WriteAllText(MarkerFile, minimized ? "minimized" : "");
            var exe = Environment.ProcessPath ?? throw new InvalidOperationException("App path unknown");
            Process.Start(new ProcessStartInfo("explorer.exe", $"\"{exe}\"") { UseShellExecute = false })?.Dispose();
            return true;
        }
        catch (Exception ex)
        {
            CrashLog.Write("Could not restart the guard independently", ex);
            return false;
        }
    }

    /// <summary>Called at start: true when the copy that relaunched us asked for "start minimized". Removes the marker.</summary>
    public static bool TakeRelaunchMinimized()
    {
        try
        {
            if (!File.Exists(MarkerFile)) return false;
            var minimized = File.ReadAllText(MarkerFile).Trim() == "minimized";
            File.Delete(MarkerFile);
            return minimized;
        }
        catch
        {
            return false;
        }
    }
}
