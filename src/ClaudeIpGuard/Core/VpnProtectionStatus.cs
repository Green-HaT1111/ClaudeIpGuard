using System.Diagnostics;

namespace ClaudeIpGuard.Core;

/// <summary>
/// Fail-closed preflight for the original public-IP lookup. External IP/geolocation
/// providers are not contacted unless the VPN-only Windows Firewall policy is active
/// and the OpenVPN tunnel has a live default/split-default route.
/// </summary>
public static class VpnProtectionStatus
{
    public static async Task<bool> IsReadyAsync(CancellationToken cancellationToken)
    {
        var script = Path.Combine(AppContext.BaseDirectory, "Tools", "Test-VpnProtection.ps1");
        if (!File.Exists(script)) return false;

        var start = new ProcessStartInfo
        {
            FileName = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System),
                "WindowsPowerShell", "v1.0", "powershell.exe"),
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };
        foreach (var arg in new[] { "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", script })
            start.ArgumentList.Add(arg);

        try
        {
            using var process = Process.Start(start);
            if (process == null) return false;
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(TimeSpan.FromSeconds(8));
            var outputTask = process.StandardOutput.ReadToEndAsync();
            await process.WaitForExitAsync(timeout.Token);
            var output = await outputTask;
            return process.ExitCode == 0 && string.Equals(output.Trim(), "true", StringComparison.OrdinalIgnoreCase);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return false;
        }
        catch (Exception) when (!cancellationToken.IsCancellationRequested)
        {
            return false;
        }
    }
}
