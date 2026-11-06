using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;

namespace ClaudeIpGuard.Core;

/// <param name="On">Both firewall rules exist and are enabled.</param>
/// <param name="Servers">VPN server IPs the rules let through.</param>
/// <param name="Adapters">Network adapters the rules block.</param>
public sealed record KillSwitchState(bool On, IReadOnlyList<string> Servers, IReadOnlyList<string> Adapters);

/// <summary>
/// VPN kill switch with Windows Firewall. Two outbound block rules on the physical adapters (Wi-Fi, Ethernet):
/// every public internet address is blocked except the VPN servers. The local network and everything that goes
/// through the VPN adapter keep working. So when the VPN drops, nothing reaches the internet with the real IP.
/// Changing the firewall needs admin rights: the app runs itself elevated with --kill-switch (see App).
/// </summary>
public static class KillSwitch
{
    public const string RuleV4 = "Claude IP Guard kill switch (IPv4)";
    public const string RuleV6 = "Claude IP Guard kill switch (IPv6)";
    const string Group = "Claude IP Guard";
    const string ServersTag = "servers=";
    const string AdaptersTag = "adapters=";

    static readonly Regex VirtualAdapter = new(
        "TAP|TUN|Wintun|WireGuard|OpenVPN|VPN|Tunnel|ZeroTier|Tailscale|NordLynx|WARP|sing-?box|v2ray|Clash|Outline|Psiphon|Hiddify|" +
        "Hyper-V|vEthernet|VirtualBox|VMware|Loopback|Bluetooth|Npcap|Teredo|isatap|Kernel Debug|Wi-Fi Direct",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    static readonly Regex RemoteLine = new(@"^\s*remote\s+(?<host>\S+)", RegexOptions.Multiline | RegexOptions.IgnoreCase | RegexOptions.Compiled);

    // ---------- what to allow / block ----------

    /// <summary>VPN servers from OpenVPN Connect and OpenVPN GUI profiles ("remote host port"). Host names are resolved.</summary>
    public static List<string> FindVpnServers(IEnumerable<string>? profileFolders = null)
    {
        profileFolders ??= new[]
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "OpenVPN Connect", "profiles"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "OpenVPN", "config"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "OpenVPN", "config"),
        };
        var servers = new List<string>();
        foreach (var folder in profileFolders.Where(Directory.Exists))
            foreach (var file in Directory.EnumerateFiles(folder, "*.ovpn", SearchOption.AllDirectories))
            {
                string text;
                try { text = File.ReadAllText(file); }
                catch { continue; }
                foreach (Match m in RemoteLine.Matches(text))
                {
                    var host = m.Groups["host"].Value;
                    if (IPAddress.TryParse(host, out var ip))
                    {
                        if (ip.AddressFamily == AddressFamily.InterNetwork) servers.Add(ip.ToString());
                        continue;
                    }
                    try
                    {
                        servers.AddRange(Dns.GetHostAddresses(host)
                            .Where(a => a.AddressFamily == AddressFamily.InterNetwork).Select(a => a.ToString()));
                    }
                    catch (Exception ex)
                    {
                        CrashLog.Write($"Kill switch: could not resolve VPN server {host}", ex);
                    }
                }
            }
        return servers.Distinct().OrderBy(s => s, StringComparer.Ordinal).ToList();
    }

    /// <summary>Real network adapters (Wi-Fi, Ethernet), connected or not. VPN and virtual adapters are left out.</summary>
    public static List<string> PhysicalAdapters() =>
        NetworkInterface.GetAllNetworkInterfaces()
            .Where(n => n.NetworkInterfaceType is NetworkInterfaceType.Wireless80211 or NetworkInterfaceType.Ethernet
                        or NetworkInterfaceType.GigabitEthernet or NetworkInterfaceType.FastEthernetT or NetworkInterfaceType.FastEthernetFx
                     && !VirtualAdapter.IsMatch(n.Description) && !VirtualAdapter.IsMatch(n.Name))
            .Select(n => n.Name)
            .Distinct()
            .OrderBy(n => n, StringComparer.Ordinal)
            .ToList();

    // Never blocked: this-network, private networks (LAN, router, DNS), CGNAT, loopback, link-local, multicast, reserved.
    static readonly (string Start, string End)[] NotInternet =
    {
        ("0.0.0.0", "0.255.255.255"), ("10.0.0.0", "10.255.255.255"), ("100.64.0.0", "100.127.255.255"),
        ("127.0.0.0", "127.255.255.255"), ("169.254.0.0", "169.254.255.255"), ("172.16.0.0", "172.31.255.255"),
        ("192.168.0.0", "192.168.255.255"), ("224.0.0.0", "255.255.255.255"),
    };

    /// <summary>All public IPv4 ranges minus the VPN servers, in firewall format: "1.0.0.0-9.255.255.255,11.0.0.0-...".</summary>
    public static string PublicRangesExcept(IEnumerable<string> servers)
    {
        var holes = NotInternet.Select(r => (Start: ToUInt(r.Start), End: ToUInt(r.End)))
            .Concat(servers.Select(s => ToUInt(s)).Select(v => (Start: v, End: v)))
            .OrderBy(h => h.Start)
            .ToList();
        var ranges = new List<string>();
        ulong next = 0;
        foreach (var (start, end) in holes)
        {
            if (start > next) ranges.Add($"{ToIp((uint)next)}-{ToIp(start - 1)}");
            next = Math.Max(next, (ulong)end + 1);
        }
        if (next <= uint.MaxValue) ranges.Add($"{ToIp((uint)next)}-{ToIp(uint.MaxValue)}");
        return string.Join(",", ranges);
    }

    static uint ToUInt(string ip)
    {
        var b = IPAddress.Parse(ip).GetAddressBytes();
        return (uint)(b[0] << 24 | b[1] << 16 | b[2] << 8 | b[3]);
    }

    static string ToIp(uint v) => $"{v >> 24}.{(v >> 16) & 255}.{(v >> 8) & 255}.{v & 255}";

    // ---------- firewall (COM: HNetCfg.FwPolicy2, works without PowerShell) ----------

    static dynamic Policy() => Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2", true)!)!;

    static dynamic? FindRule(dynamic policy, string name)
    {
        foreach (dynamic r in policy.Rules)
            if ((string)r.Name == name) return r;
        return null;
    }

    /// <summary>Reads the rules (no admin needed).</summary>
    public static KillSwitchState Read()
    {
        try
        {
            var policy = Policy();
            var v4 = FindRule(policy, RuleV4);
            var v6 = FindRule(policy, RuleV6);
            if (v4 == null) return new KillSwitchState(false, Array.Empty<string>(), Array.Empty<string>());
            var description = (string)(v4.Description ?? "");
            var on = (bool)v4.Enabled && v6 != null && (bool)v6!.Enabled;
            return new KillSwitchState(on, Tagged(description, ServersTag), Tagged(description, AdaptersTag));
        }
        catch (Exception ex)
        {
            CrashLog.Write("Kill switch: could not read firewall rules", ex);
            return new KillSwitchState(false, Array.Empty<string>(), Array.Empty<string>());
        }
    }

    static IReadOnlyList<string> Tagged(string description, string tag)
    {
        var line = description.Split('\n').FirstOrDefault(l => l.StartsWith(tag, StringComparison.Ordinal));
        return line == null ? Array.Empty<string>() : line[tag.Length..].Trim().Split(';', StringSplitOptions.RemoveEmptyEntries);
    }

    /// <summary>Creates (or replaces) the two block rules. Needs admin.</summary>
    public static void Apply(IReadOnlyList<string> servers, IReadOnlyList<string> adapters)
    {
        if (servers.Count == 0) throw new InvalidOperationException("No VPN server to allow.");
        if (adapters.Count == 0) throw new InvalidOperationException("No network adapter to block.");
        if (adapters.Any(a => a.Contains('|') || a.Contains(';')))
            throw new InvalidOperationException("An adapter name contains | or ;");
        var policy = Policy();
        RemoveRules(policy);
        var description = Description(servers, adapters);
        try
        {
            AddRule(policy, RuleV4, description, PublicRangesExcept(servers), adapters);
            AddRule(policy, RuleV6, description, "2000::/3", adapters); // global IPv6 internet
        }
        catch
        {
            RemoveRules(policy); // never leave half a kill switch behind
            throw;
        }
    }

    /// <summary>The rule description; it also stores which servers and adapters the rules were made for.</summary>
    /// <remarks>Windows refuses a rule whose name or description contains "|", so the lists use ";".</remarks>
    public static string Description(IReadOnlyList<string> servers, IReadOnlyList<string> adapters) =>
        "Blocks the internet outside the VPN. Added by Claude IP Guard, turn it off in its Leak check page.\n" +
        ServersTag + string.Join(";", servers) + "\n" + AdaptersTag + string.Join(";", adapters);

    static void AddRule(dynamic policy, string name, string description, string remote, IReadOnlyList<string> adapters)
    {
        var rule = BuildRule(name, description, remote, adapters);
        try { policy.Rules.Add(rule); }
        catch (Exception ex) { throw new InvalidOperationException($"Windows Firewall refused rule \"{name}\": {ex.Message}", ex); }
    }
    /// <summary>Fills in a firewall rule object (does not add it to the firewall). Each failing value is named in the error.</summary>
    public static object BuildRule(string name, string description, string remote, IReadOnlyList<string> adapters)
    {
        dynamic rule = Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FWRule", true)!)!;
        void Set(string property, Action set)
        {
            try { set(); }
            catch (Exception ex) { throw new InvalidOperationException($"Firewall rule {property}: {ex.Message}", ex); }
        }
        Set("Name", () => rule.Name = name);
        Set("Description", () => rule.Description = description);
        Set("Grouping", () => rule.Grouping = Group);
        Set("Protocol", () => rule.Protocol = 256);            // any
        Set("Direction", () => rule.Direction = 2);            // outbound
        Set("Action", () => rule.Action = 0);                  // block
        Set("Profiles", () => rule.Profiles = 0x7FFFFFFF);     // domain, private, public
        Set("RemoteAddresses", () => rule.RemoteAddresses = remote);
        Set("Interfaces", () => rule.Interfaces = adapters.Cast<object>().ToArray());
        Set("Enabled", () => rule.Enabled = true);
        return rule;
    }

    /// <summary>Builds both rules without adding them, to check the values Windows will accept. Returns null or the error.</summary>
    public static string? TryBuildRules(IReadOnlyList<string> servers, IReadOnlyList<string> adapters)
    {
        try
        {
            BuildRule(RuleV4, "test", PublicRangesExcept(servers), adapters);
            BuildRule(RuleV6, "test", "2000::/3", adapters);
            return null;
        }
        catch (Exception ex)
        {
            return ex.Message;
        }
    }

    /// <summary>Removes the rules. Needs admin.</summary>
    public static void Remove() => RemoveRules(Policy());

    static void RemoveRules(dynamic policy)
    {
        foreach (var name in new[] { RuleV4, RuleV6 })
            while (FindRule(policy, name) != null) policy.Rules.Remove(name);
    }

    // ---------- run elevated ----------

    /// <summary>
    /// Starts this app as admin (Windows asks) to turn the kill switch on or off. Returns null on success,
    /// "cancelled" when the user said no to Windows, or an error text.
    /// </summary>
    public static string? RunElevated(bool on, IReadOnlyList<string> servers, IReadOnlyList<string> adapters)
    {
        var exe = Environment.ProcessPath ?? throw new InvalidOperationException("App path unknown");
        static string Pack(IEnumerable<string> values) => Convert.ToBase64String(Encoding.UTF8.GetBytes(string.Join("\n", values)));
        var args = on ? $"--kill-switch on {Pack(servers)} {Pack(adapters)}" : "--kill-switch off";
        try
        {
            File.Delete(HelperErrorFile);
            using var p = Process.Start(new ProcessStartInfo(exe, args) { UseShellExecute = true, Verb = "runas" })!;
            p.WaitForExit();
            if (p.ExitCode == 0) return null;
            // The helper leaves its error message here (same user, same temp folder).
            var message = File.Exists(HelperErrorFile) ? File.ReadAllText(HelperErrorFile).Trim() : "";
            return message.Length > 0 ? message : $"exit code {p.ExitCode}";
        }
        catch (System.ComponentModel.Win32Exception ex) when (ex.NativeErrorCode == 1223)
        {
            return "cancelled";
        }
    }

    /// <summary>The elevated side: "--kill-switch on SERVERS ADAPTERS" or "--kill-switch off". Returns the exit code.</summary>
    public static int RunHelper(string[] args)
    {
        try
        {
            static List<string> Unpack(string s) =>
                Encoding.UTF8.GetString(Convert.FromBase64String(s)).Split('\n', StringSplitOptions.RemoveEmptyEntries).ToList();
            if (args.Length >= 4 && args[1] == "on") Apply(Unpack(args[2]), Unpack(args[3]));
            else if (args.Length >= 2 && args[1] == "off") Remove();
            else return 2;
            return 0;
        }
        catch (Exception ex)
        {
            CrashLog.Write("Kill switch helper failed", ex);
            try { File.WriteAllText(HelperErrorFile, ex.Message); } catch { }
            return 1;
        }
    }

    static string HelperErrorFile => Path.Combine(Path.GetTempPath(), "ClaudeIpGuard-killswitch-error.txt");
}
