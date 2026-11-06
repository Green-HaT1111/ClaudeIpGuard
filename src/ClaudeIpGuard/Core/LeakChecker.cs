using System.Net;
using System.Net.Http;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Win32;

namespace ClaudeIpGuard.Core;

public enum CheckStatus { Ok, Info, Warning, Problem }

/// <summary>One line of the leak check. Keys are localization keys so the text follows the language.</summary>
public sealed record LeakCheckResult(string TitleKey, CheckStatus Status, string DetailKey, object[] Args);

/// <summary>
/// Looks for ways the real location can be seen besides the IPv4 address:
/// IPv6, DNS, time zone, Windows region, languages, location service, VPN routing,
/// server-type IP, system proxy. Read-only: it never changes anything.
/// </summary>
public sealed class LeakChecker : IDisposable
{
    sealed record IpDetails(string Ip, string CountryCode, string Country, string? Isp, int? UtcOffsetSeconds);

    static readonly Regex VpnAdapter = new(
        "TAP|TUN|Wintun|WireGuard|OpenVPN|VPN|Tunnel|ZeroTier|Tailscale|NordLynx|WARP|sing-?box|v2ray|Clash|Outline|Psiphon|Hiddify",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    static readonly Regex ServerIsp = new(
        "server|hosting|data ?cent|datacamp|cloud|vps|dedicated|colocation|digitalocean|ovh|hetzner|amazon|aws|google|microsoft|azure|" +
        "linode|akamai|vultr|choopa|m247|leaseweb|contabo|scaleway|oracle|alibaba|tencent|ionos|hostinger|g-core|gcore|packet|zenlayer|psychz|quadranet",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    readonly HttpClient _http;

    public LeakChecker()
    {
        var handler = new SocketsHttpHandler { PooledConnectionLifetime = TimeSpan.Zero, ConnectTimeout = TimeSpan.FromSeconds(6) };
        _http = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(8) };
        _http.DefaultRequestHeaders.UserAgent.ParseAdd("ClaudeIpGuard/1.0");
    }

    public async Task<List<LeakCheckResult>> RunAsync(CancellationToken ct)
    {
        var results = new List<LeakCheckResult>();
        IpDetails? v4 = null;
        try
        {
            var ip = (await _http.GetStringAsync("https://api.ipify.org", ct)).Trim();
            v4 = await LookupAsync(ip, ct);
        }
        catch (Exception ex) when (!ct.IsCancellationRequested)
        {
            results.Add(Error("Leak_Isp_Title", ex));
        }

        results.Add(await Safe("Leak_Route_Title", () => Task.FromResult(CheckRouting())));
        results.Add(await Safe("Leak_Ipv6_Title", () => CheckIpv6Async(v4, ct)));
        results.Add(await Safe("Leak_Dns_Title", () => CheckDnsAsync(v4, ct)));
        foreach (var ecs in await SafeMany("Leak_Dns_Title", () => CheckDnsClientSubnetAsync(v4, ct))) results.Add(ecs);
        results.Add(await Safe("Leak_Tz_Title", () => Task.FromResult(CheckTimeZone(v4))));
        results.Add(await Safe("Leak_Region_Title", () => Task.FromResult(CheckRegion(v4))));
        results.Add(await Safe("Leak_Lang_Title", () => Task.FromResult(CheckLanguages())));
        results.Add(await Safe("Leak_Location_Title", () => Task.FromResult(CheckLocationService())));
        if (v4 != null) results.Add(await Safe("Leak_Isp_Title", () => Task.FromResult(CheckIsp(v4))));
        results.Add(await Safe("Leak_Proxy_Title", () => Task.FromResult(CheckProxy())));
        results.Add(new LeakCheckResult("Leak_Webrtc_Title", CheckStatus.Info, "Leak_Webrtc_Info", Array.Empty<object>()));

        // Most serious first.
        return results.OrderByDescending(r => r.Status).ToList();
    }

    // ---- individual checks ----

    LeakCheckResult CheckRouting()
    {
        var nic = GetInternetInterface();
        if (nic == null) return R("Leak_Route_Title", CheckStatus.Info, "Leak_Route_Unknown");
        var label = $"{nic.Name} ({nic.Description})";
        var killSwitch = KillSwitch.Read();
        bool Covered(NetworkInterface n) => killSwitch.On && killSwitch.Adapters.Contains(n.Name, StringComparer.OrdinalIgnoreCase);
        if (!IsVpn(nic))
            return Covered(nic)
                ? R("Leak_Route_Title", CheckStatus.Ok, "Leak_Route_KillBlocking", label)
                : R("Leak_Route_Title", CheckStatus.Warning, "Leak_Route_Direct", label);

        // VPN carries traffic now. If a normal adapter still has a gateway, traffic falls back to it when the VPN drops.
        var fallback = NetworkInterface.GetAllNetworkInterfaces().FirstOrDefault(n =>
            n.OperationalStatus == OperationalStatus.Up && !IsVpn(n) &&
            n.NetworkInterfaceType != NetworkInterfaceType.Loopback &&
            n.GetIPProperties().GatewayAddresses.Any(g =>
                g.Address.AddressFamily == AddressFamily.InterNetwork && !g.Address.Equals(IPAddress.Any)));
        if (fallback == null) return R("Leak_Route_Title", CheckStatus.Ok, "Leak_Route_Vpn", label);
        var fallbackLabel = $"{fallback.Name} ({fallback.Description})";
        if (!Covered(fallback))
            return R("Leak_Route_Title", CheckStatus.Warning, "Leak_Route_VpnNoKill", label, fallbackLabel);
        // Kill switch on. A VPN server in the profiles that it doesn't let through could not connect.
        var missing = KillSwitch.FindVpnServers().Except(killSwitch.Servers).ToList();
        return missing.Count == 0
            ? R("Leak_Route_Title", CheckStatus.Ok, "Leak_Route_KillOn", label, fallbackLabel)
            : R("Leak_Route_Title", CheckStatus.Warning, "Leak_Route_KillMissing", string.Join(", ", missing));
    }

    static bool IsVpn(NetworkInterface n) =>
        n.NetworkInterfaceType is NetworkInterfaceType.Tunnel or NetworkInterfaceType.Ppp ||
        VpnAdapter.IsMatch(n.Description) || VpnAdapter.IsMatch(n.Name);

    async Task<LeakCheckResult> CheckIpv6Async(IpDetails? v4, CancellationToken ct)
    {
        string ip;
        try
        {
            ip = (await _http.GetStringAsync("https://api6.ipify.org", ct)).Trim();
            if (!IPAddress.TryParse(ip, out var a) || a.AddressFamily != AddressFamily.InterNetworkV6)
                return R("Leak_Ipv6_Title", CheckStatus.Ok, "Leak_Ipv6_None");
        }
        catch (Exception) when (!ct.IsCancellationRequested)
        {
            return R("Leak_Ipv6_Title", CheckStatus.Ok, "Leak_Ipv6_None");
        }

        var geo = await LookupAsync(ip, ct);
        if (geo == null || v4 == null)
            return R("Leak_Ipv6_Title", CheckStatus.Warning, "Leak_Ipv6_Unknown", ip);
        return geo.CountryCode == v4.CountryCode
            ? R("Leak_Ipv6_Title", CheckStatus.Ok, "Leak_Ipv6_Same", ip, Label(geo))
            : R("Leak_Ipv6_Title", CheckStatus.Problem, "Leak_Ipv6_Diff", ip, Label(geo), Label(v4));
    }

    async Task<LeakCheckResult> CheckDnsAsync(IpDetails? v4, CancellationToken ct)
    {
        // Google answers this name with the IP of the DNS server that asked, so we see which resolver is used.
        var txt = DnsTxt.Query("o-o.myaddr.l.google.com");
        var resolverIp = txt.FirstOrDefault(s => IPAddress.TryParse(s, out _));
        if (resolverIp == null) return R("Leak_Dns_Title", CheckStatus.Info, "Leak_Dns_Fail", "no answer");

        var geo = await LookupAsync(resolverIp, ct);
        if (geo == null || v4 == null)
            return R("Leak_Dns_Title", CheckStatus.Info, "Leak_Dns_Fail", resolverIp);
        var who = geo.Isp != null ? $"{geo.Isp} ({resolverIp})" : resolverIp;
        return geo.CountryCode == v4.CountryCode
            ? R("Leak_Dns_Title", CheckStatus.Ok, "Leak_Dns_Same", who, Label(geo))
            : R("Leak_Dns_Title", CheckStatus.Warning, "Leak_Dns_Diff", who, Label(geo), Label(v4));
    }

    async Task<List<LeakCheckResult>> CheckDnsClientSubnetAsync(IpDetails? v4, CancellationToken ct)
    {
        var list = new List<LeakCheckResult>();
        foreach (var s in DnsTxt.Query("o-o.myaddr.l.google.com"))
        {
            var m = Regex.Match(s, @"edns0-client-subnet\s+([0-9a-fA-F:.]+)/\d+");
            if (!m.Success) continue;
            var geo = await LookupAsync(m.Groups[1].Value, ct);
            var status = geo != null && v4 != null && geo.CountryCode != v4.CountryCode ? CheckStatus.Problem : CheckStatus.Info;
            list.Add(R("Leak_Dns_Title", status, "Leak_Dns_Ecs", m.Groups[1].Value, geo != null ? Label(geo) : "?"));
        }
        return list;
    }

    static LeakCheckResult CheckTimeZone(IpDetails? v4)
    {
        var tz = TimeZoneInfo.Local;
        var local = tz.GetUtcOffset(DateTime.Now);
        var tzName = tz.Id;
        if (v4?.UtcOffsetSeconds == null)
            return R("Leak_Tz_Title", CheckStatus.Info, "Leak_Tz_Unknown", tzName, Offset(local));
        var expected = TimeSpan.FromSeconds(v4.UtcOffsetSeconds.Value);
        return local == expected
            ? R("Leak_Tz_Title", CheckStatus.Ok, "Leak_Tz_Match", tzName, Label(v4))
            : R("Leak_Tz_Title", CheckStatus.Problem, "Leak_Tz_Diff", tzName, Offset(local), Label(v4), Offset(expected));
    }

    static LeakCheckResult CheckRegion(IpDetails? v4)
    {
        var sb = new StringBuilder(16);
        var code = GetUserDefaultGeoName(sb, sb.Capacity) > 0 ? sb.ToString() : "";
        if (code.Length != 2) return R("Leak_Region_Title", CheckStatus.Info, "Leak_Region_Unknown");
        var name = $"{CountryNames.Get(code)} ({code})‎";
        if (v4 == null) return R("Leak_Region_Title", CheckStatus.Info, "Leak_Region_Only", name);
        return string.Equals(code, v4.CountryCode, StringComparison.OrdinalIgnoreCase)
            ? R("Leak_Region_Title", CheckStatus.Ok, "Leak_Region_Match", name)
            : R("Leak_Region_Title", CheckStatus.Warning, "Leak_Region_Diff", name, Label(v4));
    }

    static LeakCheckResult CheckLanguages()
    {
        var ui = System.Globalization.CultureInfo.CurrentUICulture.Name;
        var langs = Registry.GetValue(@"HKEY_CURRENT_USER\Control Panel\International\User Profile", "Languages", null) as string[];
        var list = langs is { Length: > 0 } ? string.Join(", ", langs) : "?";
        return R("Leak_Lang_Title", CheckStatus.Info, "Leak_Lang_Info", ui, list);
    }

    static LeakCheckResult CheckLocationService()
    {
        var device = Registry.GetValue(
            @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location", "Value", null) as string;
        var user = Registry.GetValue(
            @"HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location", "Value", null) as string;
        var off = string.Equals(device, "Deny", StringComparison.OrdinalIgnoreCase) ||
                  string.Equals(user, "Deny", StringComparison.OrdinalIgnoreCase);
        return off
            ? R("Leak_Location_Title", CheckStatus.Ok, "Leak_Location_Off")
            : R("Leak_Location_Title", CheckStatus.Warning, "Leak_Location_On");
    }

    static LeakCheckResult CheckIsp(IpDetails v4)
    {
        var isp = v4.Isp ?? "?";
        return ServerIsp.IsMatch(isp)
            ? R("Leak_Isp_Title", CheckStatus.Warning, "Leak_Isp_Server", isp)
            : R("Leak_Isp_Title", CheckStatus.Ok, "Leak_Isp_Home", isp);
    }

    static LeakCheckResult CheckProxy()
    {
        const string key = @"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings";
        var enabled = Registry.GetValue(key, "ProxyEnable", 0) is int i && i == 1;
        var server = Registry.GetValue(key, "ProxyServer", null) as string;
        return enabled
            ? R("Leak_Proxy_Title", CheckStatus.Warning, "Leak_Proxy_On", server ?? "?")
            : R("Leak_Proxy_Title", CheckStatus.Ok, "Leak_Proxy_Off");
    }

    // ---- helpers ----

    async Task<IpDetails?> LookupAsync(string ip, CancellationToken ct)
    {
        try
        {
            using var resp = await _http.GetAsync($"https://ipwho.is/{ip}", ct);
            resp.EnsureSuccessStatusCode();
            using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync(ct));
            var j = doc.RootElement;
            if (j.TryGetProperty("success", out var ok) && ok.ValueKind == JsonValueKind.False) return null;
            var code = j.GetProperty("country_code").GetString() ?? "";
            var country = j.TryGetProperty("country", out var c) ? c.GetString() ?? code : code;
            string? isp = null;
            if (j.TryGetProperty("connection", out var conn) && conn.ValueKind == JsonValueKind.Object)
                isp = conn.TryGetProperty("isp", out var x) && x.ValueKind == JsonValueKind.String ? x.GetString()
                    : conn.TryGetProperty("org", out var o) && o.ValueKind == JsonValueKind.String ? o.GetString() : null;
            int? offset = null;
            if (j.TryGetProperty("timezone", out var tz) && tz.ValueKind == JsonValueKind.Object &&
                tz.TryGetProperty("offset", out var off) && off.ValueKind == JsonValueKind.Number)
                offset = off.GetInt32();
            return new IpDetails(ip, code.ToUpperInvariant(), country, isp, offset);
        }
        catch (Exception) when (!ct.IsCancellationRequested)
        {
            return null;
        }
    }

    static NetworkInterface? GetInternetInterface()
    {
        var dest = BitConverter.ToUInt32(IPAddress.Parse("8.8.8.8").GetAddressBytes(), 0);
        if (GetBestInterface(dest, out var index) != 0) return null;
        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            try
            {
                if (nic.GetIPProperties().GetIPv4Properties()?.Index == (int)index) return nic;
            }
            catch (NetworkInformationException) { }
        }
        return null;
    }

    static string Label(IpDetails d) => $"{d.Country} ({d.CountryCode})‎";

    static string Offset(TimeSpan t) => (t < TimeSpan.Zero ? "-" : "+") + t.ToString(@"hh\:mm");

    static LeakCheckResult R(string title, CheckStatus status, string detail, params object[] args) => new(title, status, detail, args);

    static LeakCheckResult Error(string title, Exception ex) => R(title, CheckStatus.Info, "Leak_Error", ex.Message);

    static async Task<LeakCheckResult> Safe(string title, Func<Task<LeakCheckResult>> check)
    {
        try { return await check(); }
        catch (Exception ex) { return Error(title, ex); }
    }

    static async Task<List<LeakCheckResult>> SafeMany(string title, Func<Task<List<LeakCheckResult>>> check)
    {
        try { return await check(); }
        catch (Exception ex) { return new List<LeakCheckResult> { Error(title, ex) }; }
    }

    public void Dispose() => _http.Dispose();

    [DllImport("iphlpapi.dll")]
    static extern int GetBestInterface(uint destAddr, out uint bestIfIndex);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    static extern int GetUserDefaultGeoName(StringBuilder geoName, int geoNameCount);
}

/// <summary>TXT lookups through the Windows DNS client (the same resolver every app uses).</summary>
static class DnsTxt
{
    const ushort TypeTxt = 0x0010;
    const uint BypassCache = 0x00000008;

    public static List<string> Query(string name)
    {
        var list = new List<string>();
        if (DnsQuery_W(name, TypeTxt, BypassCache, IntPtr.Zero, out var records, IntPtr.Zero) != 0) return list;
        try
        {
            int ptr = IntPtr.Size;
            int header = 2 * ptr + 16;                       // pNext, pName, wType, wDataLength, Flags, dwTtl, dwReserved
            int strings = (header + 4 + ptr - 1) / ptr * ptr; // after dwStringCount, aligned for the pointer array
            for (var rec = records; rec != IntPtr.Zero; rec = Marshal.ReadIntPtr(rec))
            {
                if ((ushort)Marshal.ReadInt16(rec, 2 * ptr) != TypeTxt) continue;
                var count = Marshal.ReadInt32(rec, header);
                for (int i = 0; i < count; i++)
                {
                    var s = Marshal.PtrToStringUni(Marshal.ReadIntPtr(rec, strings + i * ptr));
                    if (!string.IsNullOrEmpty(s)) list.Add(s);
                }
            }
        }
        finally
        {
            DnsRecordListFree(records, 1);
        }
        return list;
    }

    [DllImport("dnsapi.dll", CharSet = CharSet.Unicode)]
    static extern int DnsQuery_W(string name, ushort type, uint options, IntPtr extra, out IntPtr results, IntPtr reserved);

    [DllImport("dnsapi.dll")]
    static extern void DnsRecordListFree(IntPtr list, int freeType);
}
