using System.Diagnostics;
using System.Text.Json;

namespace ClaudeIpGuard.Core;

public sealed class PrivacyFinding
{
    public string Id { get; set; } = "";
    public string Severity { get; set; } = "Info";
    public string TitleEn { get; set; } = "";
    public string TitleFa { get; set; } = "";
    public string DetailsEn { get; set; } = "";
    public string DetailsFa { get; set; } = "";
    public string AdviceEn { get; set; } = "";
    public string AdviceFa { get; set; } = "";
}

public sealed class PrivacyAuditReport
{
    public string OsCaption { get; set; } = "";
    public bool KillSwitchActive { get; set; }
    public bool HasFirewallBackup { get; set; }
    public bool CanEnableKillSwitch { get; set; }
    public List<string> VpnAdapters { get; set; } = [];
    public List<string> OpenVpnConfigs { get; set; } = [];
    public List<PrivacyFinding> Findings { get; set; } = [];
}

public static class PrivacyAuditService
{
    public static async Task<PrivacyAuditReport> ScanAsync(CancellationToken cancellationToken = default)
    {
        var script = Path.Combine(AppContext.BaseDirectory, "Tools", "Get-PrivacyAudit.ps1");
        if (!File.Exists(script))
            throw new FileNotFoundException("Privacy audit script was not published with the application.", script);

        var start = new ProcessStartInfo
        {
            FileName = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "WindowsPowerShell", "v1.0", "powershell.exe"),
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };
        foreach (var arg in new[] { "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", script })
            start.ArgumentList.Add(arg);

        using var process = Process.Start(start) ?? throw new InvalidOperationException("Could not start Windows PowerShell.");
        using var registration = cancellationToken.Register(() =>
        {
            try { if (!process.HasExited) process.Kill(entireProcessTree: true); } catch { }
        });
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(40));
        await process.WaitForExitAsync(timeout.Token);
        var output = await stdout;
        var error = await stderr;
        if (process.ExitCode != 0)
            throw new InvalidOperationException(string.IsNullOrWhiteSpace(error) ? $"Privacy audit failed (exit {process.ExitCode})." : error.Trim());

        return JsonSerializer.Deserialize<PrivacyAuditReport>(output, new JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true
        }) ?? throw new InvalidOperationException("Privacy audit returned an empty report.");
    }
}
