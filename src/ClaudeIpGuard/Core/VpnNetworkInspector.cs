using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Management;
using Microsoft.Win32;
using System.Text.RegularExpressions;

namespace ClaudeIpGuard.Core;

public sealed record OpenVpnRemoteEndpoint(string Host, int Port, string Protocol)
{
    public bool IsIpAddress => IPAddress.TryParse(Host, out _);
    public override string ToString() => $"{Host}:{Port}/{Protocol}";
}

public sealed record VpnAdapterInfo(
    string Name,
    string Description,
    OperationalStatus Status,
    IReadOnlyList<string> Gateways,
    IReadOnlyList<string> DnsServers,
    bool IsLikelyVpn);

public sealed record OpenVpnProcessInfo(
    int ProcessId,
    string Name,
    string? ExecutablePath,
    string? CommandLine);

public sealed record WindowsLocationInfo(
    string ServiceState,
    string ServiceStartMode,
    string UserConsent,
    bool DevicePolicyDisablesLocation,
    bool PerDesktopAppControlSupported);

public sealed record VpnNetworkSnapshot(
    DateTime CheckedAt,
    IReadOnlyList<VpnAdapterInfo> Adapters,
    IReadOnlyList<OpenVpnProcessInfo> OpenVpnProcesses,
    WindowsLocationInfo Location,
    string? Error)
{
    public IReadOnlyList<VpnAdapterInfo> ActiveVpnAdapters =>
        Adapters.Where(a => a.IsLikelyVpn && a.Status == OperationalStatus.Up).ToArray();

    public bool HasActiveVpnAdapter => ActiveVpnAdapters.Count > 0;

    public bool HasNonVpnIpv6DefaultGateway =>
        Adapters.Any(a => !a.IsLikelyVpn && a.Status == OperationalStatus.Up &&
                          a.Gateways.Any(g => IPAddress.TryParse(g, out var ip) &&
                                              ip.AddressFamily == AddressFamily.InterNetworkV6));

    public bool HasDnsOnNonVpnAdapter =>
        Adapters.Any(a => !a.IsLikelyVpn && a.Status == OperationalStatus.Up && a.DnsServers.Count > 0);

    public string Fingerprint =>
        string.Join("|",
            string.Join(",", ActiveVpnAdapters.Select(a => a.Name).OrderBy(x => x)),
            string.Join(",", OpenVpnProcesses.Select(p => p.Name).OrderBy(x => x, StringComparer.OrdinalIgnoreCase)),
            HasNonVpnIpv6DefaultGateway,
            HasDnsOnNonVpnAdapter,
            Location.ServiceState,
            Location.ServiceStartMode,
            Location.UserConsent,
            Location.DevicePolicyDisablesLocation,
            Error ?? "");
}

/// <summary>
/// Reads local OpenVPN/network and Windows-location indicators. This is diagnostic only:
/// it does not change firewall, VPN, or Windows privacy settings.
/// </summary>
public sealed class VpnNetworkInspector
{
    static readonly string[] OpenVpnNames =
    {
        "openvpn.exe", "openvpn-gui.exe", "openvpnserv2.exe",
        "openvpnconnect.exe", "agent_ovpnconnect.exe",
        "ovpnhelper_service.exe", "ovpnconnector.exe"
    };

    static readonly string[] VpnAdapterTokens =
    {
        "openvpn", "tap-windows", "wintun", "dco", "tun"
    };

    public static bool IsOpenVpnProcessName(string? name) =>
        !string.IsNullOrWhiteSpace(name) &&
        OpenVpnNames.Contains(Path.GetFileName(name), StringComparer.OrdinalIgnoreCase);

    public static bool IsLikelyOpenVpnAdapter(string? name, string? description)
    {
        var value = $"{name} {description}";
        return VpnAdapterTokens.Any(token => value.Contains(token, StringComparison.OrdinalIgnoreCase));
    }

    public VpnNetworkSnapshot Inspect()
    {
        string? error = null;
        var adapters = ReadAdapters();
        var processes = ReadOpenVpnProcesses(ref error);
        var location = ReadWindowsLocation(ref error);

        return new VpnNetworkSnapshot(
            DateTime.Now,
            adapters,
            processes,
            location,
            error);
    }

    static IReadOnlyList<VpnAdapterInfo> ReadAdapters()
    {
        var list = new List<VpnAdapterInfo>();
        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            try
            {
                var properties = nic.GetIPProperties();
                var gateways = properties.GatewayAddresses
                    .Select(g => g.Address)
                    .Where(a => a != null && !IPAddress.Any.Equals(a) && !IPAddress.IPv6Any.Equals(a))
                    .Select(a => a.ToString())
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .ToArray();

                var dns = properties.DnsAddresses
                    .Select(a => a.ToString())
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .ToArray();

                var isVpn = IsLikelyOpenVpnAdapter(nic.Name, nic.Description);

                list.Add(new VpnAdapterInfo(
                    nic.Name,
                    nic.Description,
                    nic.OperationalStatus,
                    gateways,
                    dns,
                    isVpn));
            }
            catch (NetworkInformationException)
            {
                // An adapter can disappear while Windows is refreshing the network list.
            }
            catch (Exception ex)
            {
                CrashLog.Write($"Could not inspect network adapter {nic.Name}", ex);
            }
        }
        return list;
    }

    static IReadOnlyList<OpenVpnProcessInfo> ReadOpenVpnProcesses(ref string? error)
    {
        var found = new List<OpenVpnProcessInfo>();
        try
        {
            var names = string.Join(" OR ", OpenVpnNames.Select(n => $"Name='{n}'"));
            using var searcher = new ManagementObjectSearcher(
                $"SELECT ProcessId, Name, ExecutablePath, CommandLine FROM Win32_Process WHERE {names}");
            using var results = searcher.Get();

            foreach (ManagementObject item in results)
            {
                using (item)
                {
                    found.Add(new OpenVpnProcessInfo(
                        Convert.ToInt32(item["ProcessId"]),
                        Convert.ToString(item["Name"]) ?? "OpenVPN",
                        Convert.ToString(item["ExecutablePath"]),
                        Convert.ToString(item["CommandLine"])));
                }
            }
        }
        catch (Exception ex)
        {
            error = "WMI process inspection failed: " + ex.Message;
            CrashLog.Write("OpenVPN process inspection failed", ex);
        }
        return found.OrderBy(p => p.Name).ThenBy(p => p.ProcessId).ToArray();
    }

    static WindowsLocationInfo ReadWindowsLocation(ref string? error)
    {
        string state = "Unknown";
        string startMode = "Unknown";
        string consent = "Not configured";
        bool devicePolicyDisables = false;

        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT State, StartMode FROM Win32_Service WHERE Name='lfsvc'");
            using var results = searcher.Get();
            foreach (ManagementObject item in results)
            {
                using (item)
                {
                    state = Convert.ToString(item["State"]) ?? state;
                    startMode = Convert.ToString(item["StartMode"]) ?? startMode;
                }
            }
        }
        catch (Exception ex)
        {
            error ??= "Windows location service inspection failed: " + ex.Message;
            CrashLog.Write("Windows location service inspection failed", ex);
        }

        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(
                @"Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location");
            consent = Convert.ToString(key?.GetValue("Value")) ?? consent;
        }
        catch (Exception ex)
        {
            CrashLog.Write("Could not read current-user location consent", ex);
        }

        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors");
            devicePolicyDisables =
                Convert.ToInt32(key?.GetValue("DisableLocation") ?? 0) == 1;
        }
        catch (Exception ex)
        {
            CrashLog.Write("Could not read Windows location policy", ex);
        }

        // Microsoft documents that classic Win32 desktop apps do not have reliable
        // per-app precise-location switches in Windows 10. Do not claim otherwise.
        return new WindowsLocationInfo(
            state,
            startMode,
            consent,
            devicePolicyDisables,
            PerDesktopAppControlSupported: false);
    }
}

/// <summary>Parses only the non-secret remote/proto/port directives from an OpenVPN profile.</summary>
public static class OpenVpnProfileParser
{
    static readonly Regex TokenRegex = new(@"(?:""([^""]*)""|'([^']*)'|(\S+))",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    public static IReadOnlyList<OpenVpnRemoteEndpoint> ParseRemoteDirectives(string text)
    {
        if (string.IsNullOrWhiteSpace(text)) return Array.Empty<OpenVpnRemoteEndpoint>();

        var lines = text.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None);
        var defaultPort = 1194;
        var defaultProtocol = "UDP";

        foreach (var raw in lines)
        {
            var line = raw.Trim();
            if (line.Length == 0 || line.StartsWith('#') || line.StartsWith(';')) continue;
            var tokens = Tokenize(line);
            if (tokens.Count < 2) continue;

            if (tokens[0].Equals("port", StringComparison.OrdinalIgnoreCase) &&
                int.TryParse(tokens[1], out var configuredPort) &&
                configuredPort is >= 1 and <= 65535)
                defaultPort = configuredPort;

            if (tokens[0].Equals("proto", StringComparison.OrdinalIgnoreCase))
                defaultProtocol = NormalizeProtocol(tokens[1]) ?? defaultProtocol;
        }

        var endpoints = new List<OpenVpnRemoteEndpoint>();
        foreach (var raw in lines)
        {
            var line = raw.Trim();
            if (line.Length == 0 || line.StartsWith('#') || line.StartsWith(';')) continue;
            var tokens = Tokenize(line);
            if (tokens.Count < 2 ||
                !tokens[0].Equals("remote", StringComparison.OrdinalIgnoreCase))
                continue;

            var host = tokens[1].Trim();
            if (host.Length == 0 || host.Any(char.IsWhiteSpace)) continue;

            var port = defaultPort;
            var protocol = defaultProtocol;
            if (tokens.Count >= 3)
            {
                if (int.TryParse(tokens[2], out var remotePort) &&
                    remotePort is >= 1 and <= 65535)
                {
                    port = remotePort;
                    if (tokens.Count >= 4)
                        protocol = NormalizeProtocol(tokens[3]) ?? protocol;
                }
                else
                {
                    protocol = NormalizeProtocol(tokens[2]) ?? protocol;
                }
            }

            endpoints.Add(new OpenVpnRemoteEndpoint(host, port, protocol));
        }

        return endpoints
            .DistinctBy(e => $"{e.Host}|{e.Port}|{e.Protocol}", StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    static IReadOnlyList<string> Tokenize(string line)
    {
        var tokens = new List<string>();
        foreach (Match match in TokenRegex.Matches(line))
        {
            var value = match.Groups[1].Success ? match.Groups[1].Value
                : match.Groups[2].Success ? match.Groups[2].Value
                : match.Groups[3].Value;
            if (value.Length > 0) tokens.Add(value);
        }
        return tokens;
    }

    static string? NormalizeProtocol(string value)
    {
        if (value.StartsWith("udp", StringComparison.OrdinalIgnoreCase)) return "UDP";
        if (value.StartsWith("tcp", StringComparison.OrdinalIgnoreCase)) return "TCP";
        return null;
    }
}

/// <summary>
/// Reads an OpenVPN profile and follows relative 'config' includes without exposing credentials.
/// Only remote endpoint, protocol and port directives are returned.
/// </summary>
public static class OpenVpnProfileReader
{
    public static IReadOnlyList<OpenVpnRemoteEndpoint> ReadRemoteEndpoints(string profilePath)
    {
        var endpoints = new List<OpenVpnRemoteEndpoint>();
        var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        Read(profilePath, visited, endpoints, depth: 0);
        return endpoints
            .DistinctBy(e => $"{e.Host}|{e.Port}|{e.Protocol}", StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    static void Read(
        string path,
        HashSet<string> visited,
        List<OpenVpnRemoteEndpoint> endpoints,
        int depth)
    {
        if (depth > 8) return;

        string fullPath;
        try { fullPath = Path.GetFullPath(path); }
        catch { return; }

        if (!visited.Add(fullPath) || !File.Exists(fullPath)) return;

        string text;
        try { text = File.ReadAllText(fullPath); }
        catch (Exception ex)
        {
            CrashLog.Write($"Could not read OpenVPN profile {fullPath}", ex);
            return;
        }

        endpoints.AddRange(OpenVpnProfileParser.ParseRemoteDirectives(text));

        var directory = Path.GetDirectoryName(fullPath) ?? "";
        foreach (var raw in text.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None))
        {
            var line = raw.Trim();
            if (line.Length == 0 || line.StartsWith('#') || line.StartsWith(';')) continue;
            var tokens = Regex.Matches(line, @"(?:""([^""]*)""|'([^']*)'|(\S+))")
                .Cast<Match>()
                .Select(m => m.Groups[1].Success ? m.Groups[1].Value
                    : m.Groups[2].Success ? m.Groups[2].Value
                    : m.Groups[3].Value)
                .ToArray();

            if (tokens.Length < 2 ||
                !tokens[0].Equals("config", StringComparison.OrdinalIgnoreCase))
                continue;

            var child = Path.IsPathRooted(tokens[1])
                ? tokens[1]
                : Path.Combine(directory, tokens[1]);
            Read(child, visited, endpoints, depth + 1);
        }
    }
}
