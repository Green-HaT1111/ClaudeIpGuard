using System.Management;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using Microsoft.Win32;

namespace ClaudeIpGuard.Core;

/// <summary>A network adapter. Hardware = a real Wi-Fi/Ethernet card (Windows' own flag), not a VPN/virtual adapter.</summary>
public sealed record NetAdapter(string Name, string Description, uint Index, ulong Luid, bool Hardware, IReadOnlyList<IPAddress> IPv4);

/// <param name="TunnelAdapter">The VPN adapter that carries internet traffic (tunnel mode), or null.</param>
/// <param name="Proxy">"host:port" of the proxy Windows or HTTPS_PROXY sends traffic to (proxy mode), or null.</param>
/// <param name="Programs">Full paths of the VPN client programs (the ones that talk to the VPN server).</param>
/// <param name="Servers">VPN server addresses those programs are connected to.</param>
public sealed record VpnInfo(NetAdapter? TunnelAdapter, string? Proxy, IReadOnlyList<string> Programs, IReadOnlyList<string> Servers)
{
    public bool Active => TunnelAdapter != null || Proxy != null;
}

/// <summary>
/// Finds the VPN automatically, whatever its brand (OpenVPN, WireGuard, v2ray/Xray, sing-box/Hiddify, Clash...):
/// tunnel mode = the internet route goes through a non-hardware adapter; proxy mode = Windows' proxy or
/// HTTPS_PROXY points to a program on this PC. The VPN program is the one that, while the VPN is up, talks to the
/// internet directly from the real Wi-Fi/Ethernet address (everything else goes through the VPN).
/// </summary>
public static class VpnDetector
{
    public static VpnInfo Detect()
    {
        var adapters = Adapters();
        var tunnel = InternetAdapter(adapters) is { Hardware: false } a ? a : null;
        var proxy = SystemProxy();
        var programs = new List<string>();
        var servers = new List<string>();
        var rows = TcpRows();

        // Proxy mode: the program listening on the local proxy port is the VPN client.
        int? proxyPid = null;
        if (proxy != null && TryLocalPort(proxy, out var port))
        {
            var listener = rows.FirstOrDefault(r => r.State == TcpListen && r.LocalPort == port);
            if (listener.Pid > 0) proxyPid = listener.Pid;
        }
        if (proxyPid is int pp && ProcessGuard.GetImagePath(pp) is string proxyExe) programs.Add(proxyExe);

        // Who talks to the internet straight from a hardware adapter's address?
        // Tunnel mode: only the VPN client does. Proxy mode: only count the proxy program (others bypass the proxy).
        if (tunnel != null || proxyPid != null)
        {
            var hardwareIps = adapters.Where(x => x.Hardware).SelectMany(x => x.IPv4).ToHashSet();
            foreach (var r in rows.Where(r => r.State == TcpEstablished && hardwareIps.Contains(r.Local) && IsPublic(r.Remote)))
            {
                if (tunnel == null && r.Pid != proxyPid) continue;
                if (r.Pid <= 4 || ProcessGuard.GetImagePath(r.Pid) is not string exe) continue;
                programs.Add(exe);
                servers.Add(r.Remote.ToString());
            }
        }

        return new VpnInfo(tunnel, proxy,
            programs.Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(x => x, StringComparer.OrdinalIgnoreCase).ToList(),
            servers.Distinct().OrderBy(x => x, StringComparer.Ordinal).ToList());
    }

    // ---------- adapters and route ----------

    /// <summary>All adapters, with Windows' "hardware interface" flag (Wi-Fi/Ethernet = true; VPN, TAP, wintun, Wi-Fi Direct = false).</summary>
    public static List<NetAdapter> Adapters()
    {
        var ipv4 = new Dictionary<int, List<IPAddress>>();
        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            try
            {
                if (nic.GetIPProperties().GetIPv4Properties() is { } p)
                    ipv4[p.Index] = nic.GetIPProperties().UnicastAddresses
                        .Where(u => u.Address.AddressFamily == AddressFamily.InterNetwork).Select(u => u.Address).ToList();
            }
            catch (NetworkInformationException) { }
        }

        var list = new List<NetAdapter>();
        using var searcher = new ManagementObjectSearcher(@"root\StandardCimv2",
            "SELECT Name, InterfaceDescription, InterfaceIndex, NetLuid, HardwareInterface FROM MSFT_NetAdapter");
        foreach (ManagementObject mo in searcher.Get())
            using (mo)
            {
                var index = Convert.ToUInt32(mo["InterfaceIndex"]);
                list.Add(new NetAdapter((string)mo["Name"], mo["InterfaceDescription"] as string ?? "", index,
                    Convert.ToUInt64(mo["NetLuid"]), mo["HardwareInterface"] is true,
                    ipv4.TryGetValue((int)index, out var ips) ? ips : new List<IPAddress>()));
            }
        return list;
    }

    /// <summary>The adapter Windows uses to reach the internet now (route to a public address).</summary>
    public static NetAdapter? InternetAdapter(IReadOnlyList<NetAdapter> adapters)
    {
        var dest = BitConverter.ToUInt32(IPAddress.Parse("1.1.1.1").GetAddressBytes(), 0);
        return GetBestInterface(dest, out var index) == 0 ? adapters.FirstOrDefault(a => a.Index == index) : null;
    }

    // ---------- proxy ----------

    /// <summary>The proxy apps are told to use: HTTPS_PROXY etc., else Windows' proxy setting. "host:port" or null.</summary>
    public static string? SystemProxy() => EnvProxy() ?? WindowsProxy();

    /// <summary>Windows' proxy setting (used by the Claude desktop app and browsers), or null when off.</summary>
    public static string? WindowsProxy()
    {
        const string key = @"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings";
        return Registry.GetValue(key, "ProxyEnable", 0) is int on && on == 1
            ? ParseProxy(Registry.GetValue(key, "ProxyServer", null) as string)
            : null;
    }

    /// <summary>HTTPS_PROXY / HTTP_PROXY / ALL_PROXY (used by Claude Code), or null.</summary>
    public static string? EnvProxy()
    {
        foreach (var name in new[] { "HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY" })
            if (ParseProxy(Environment.GetEnvironmentVariable(name) ?? Environment.GetEnvironmentVariable(name.ToLowerInvariant())) is string env)
                return env;
        return null;
    }

    /// <summary>"http://127.0.0.1:12334", "127.0.0.1:12334" or "http=a:1;https=b:2" -> "host:port" (the https one when listed).</summary>
    public static string? ParseProxy(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return null;
        var parts = value.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        var pick = parts.FirstOrDefault(p => p.StartsWith("https=", StringComparison.OrdinalIgnoreCase))
                   ?? parts.FirstOrDefault(p => !p.Contains('=')) ?? parts[0];
        if (pick.Contains('=')) pick = pick[(pick.IndexOf('=') + 1)..];
        if (pick.Contains("://")) pick = pick[(pick.IndexOf("://", StringComparison.Ordinal) + 3)..];
        pick = pick.TrimEnd('/');
        return pick.Length > 0 ? pick : null;
    }

    static bool TryLocalPort(string proxy, out int port)
    {
        port = 0;
        var colon = proxy.LastIndexOf(':');
        if (colon < 0 || !int.TryParse(proxy[(colon + 1)..], out port)) return false;
        var host = proxy[..colon].Trim('[', ']');
        return host.Equals("localhost", StringComparison.OrdinalIgnoreCase) ||
               (IPAddress.TryParse(host, out var ip) && IPAddress.IsLoopback(ip));
    }

    public static bool IsPublic(IPAddress ip)
    {
        var b = ip.GetAddressBytes();
        return !(b[0] == 0 || b[0] == 10 || b[0] == 127 || b[0] >= 224 ||
                 (b[0] == 100 && b[1] >= 64 && b[1] <= 127) || (b[0] == 169 && b[1] == 254) ||
                 (b[0] == 172 && b[1] >= 16 && b[1] <= 31) || (b[0] == 192 && b[1] == 168));
    }

    // ---------- TCP table (owner process of every connection) ----------

    const int TcpListen = 2, TcpEstablished = 5;

    readonly record struct TcpRow(int State, IPAddress Local, int LocalPort, IPAddress Remote, int Pid);

    static List<TcpRow> TcpRows()
    {
        var rows = new List<TcpRow>();
        int size = 0;
        GetExtendedTcpTable(IntPtr.Zero, ref size, false, 2 /* AF_INET */, 5 /* TCP_TABLE_OWNER_PID_ALL */, 0);
        var buffer = Marshal.AllocHGlobal(size);
        try
        {
            if (GetExtendedTcpTable(buffer, ref size, false, 2, 5, 0) != 0) return rows;
            var count = Marshal.ReadInt32(buffer);
            for (int i = 0; i < count; i++)
            {
                var row = Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(buffer + 4 + i * Marshal.SizeOf<MIB_TCPROW_OWNER_PID>());
                rows.Add(new TcpRow((int)row.State, new IPAddress(row.LocalAddr),
                    (ushort)IPAddress.NetworkToHostOrder((short)row.LocalPort), new IPAddress(row.RemoteAddr), (int)row.OwningPid));
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
        return rows;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct MIB_TCPROW_OWNER_PID
    {
        public uint State, LocalAddr, LocalPort, RemoteAddr, RemotePort, OwningPid;
    }

    [DllImport("iphlpapi.dll")]
    static extern uint GetExtendedTcpTable(IntPtr table, ref int size, bool order, int af, int tableClass, uint reserved);

    [DllImport("iphlpapi.dll")]
    static extern int GetBestInterface(uint destAddr, out uint bestIfIndex);
}
