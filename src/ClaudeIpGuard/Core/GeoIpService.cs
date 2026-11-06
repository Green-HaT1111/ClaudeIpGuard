using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text.Json;

namespace ClaudeIpGuard.Core;

public sealed record GeoResult(string Ip, string CountryCode, string CountryName, string? City, string Provider);

public interface IIpLocator
{
    /// <summary>Returns the public IP and its country, or throws if it can't be determined.</summary>
    Task<GeoResult> LocateAsync(CancellationToken ct);
}

public sealed class GeoLookupException : Exception
{
    public GeoLookupException(string message) : base(message) { }
}

/// <summary>
/// Finds the public IP with several "what is my IP" services, then looks up its country with
/// several free geolocation services (first one that answers wins). Country results are cached
/// per IP, so the 30-second checks only hit the cheap IP services.
/// </summary>
public sealed class GeoIpService : IIpLocator, IDisposable
{
    static readonly TimeSpan FreshFor = TimeSpan.FromHours(6);
    static readonly TimeSpan StaleFor = TimeSpan.FromHours(48);

    static readonly string[] IpSources =
    {
        "https://api.ipify.org",
        "https://ipv4.icanhazip.com",
        "https://checkip.amazonaws.com",
        "https://ifconfig.me/ip",
    };

    readonly HttpClient _http;
    readonly object _lock = new();
    readonly Dictionary<string, (GeoResult Result, DateTime At)> _cache = new();
    readonly (string Name, Func<string, CancellationToken, Task<GeoResult?>> Lookup)[] _providers;

    public GeoIpService(bool requireVpnProtection = true)
    {
        _requireVpnProtection = requireVpnProtection;
        var handler = new SocketsHttpHandler
        {
            // No connection reuse: after a VPN or Wi-Fi switch every check must use the new route.
            PooledConnectionLifetime = TimeSpan.Zero,
            ConnectTimeout = TimeSpan.FromSeconds(6),
            AutomaticDecompression = DecompressionMethods.All,
        };
        _http = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(8) };
        _http.DefaultRequestHeaders.UserAgent.ParseAdd("ClaudeIpGuard/1.0");
        _http.DefaultRequestHeaders.CacheControl = new CacheControlHeaderValue { NoCache = true };

        _providers = new (string, Func<string, CancellationToken, Task<GeoResult?>>)[]
        {
            ("ipwho.is", IpWhoIsAsync),
            ("country.is", CountryIsAsync),
            ("freeipapi.com", FreeIpApiAsync),
            ("ipapi.co", IpApiCoAsync),
        };
    }

    public async Task<GeoResult> LocateAsync(CancellationToken ct)
    {
        if (_requireVpnProtection && !await VpnProtectionStatus.IsReadyAsync(ct))
            throw new GeoLookupException("Public IP lookup is disabled until the VPN-only Windows Firewall kill switch is active and an OpenVPN tunnel route is verified. No external IP service was contacted.");

        var errors = new List<string>();
        var ip = await GetPublicIpAsync(errors, ct)
                 ?? throw new GeoLookupException("Could not get public IP (" + string.Join("; ", errors) + ")");

        lock (_lock)
        {
            if (_cache.TryGetValue(ip, out var cached) && DateTime.UtcNow - cached.At < FreshFor)
                return cached.Result;
        }

        foreach (var (name, lookup) in _providers)
        {
            try
            {
                var result = await lookup(ip, ct);
                if (result != null)
                {
                    lock (_lock) _cache[ip] = (result, DateTime.UtcNow);
                    return result;
                }
                errors.Add($"{name}: no country in answer");
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception ex)
            {
                errors.Add($"{name}: {ex.Message}");
            }
        }

        // Same IP as an earlier successful lookup means same location, so an older answer is still valid.
        lock (_lock)
        {
            if (_cache.TryGetValue(ip, out var stale) && DateTime.UtcNow - stale.At < StaleFor)
                return stale.Result;
        }

        throw new GeoLookupException($"Country lookup failed for {ip} (" + string.Join("; ", errors) + ")");
    }

    async Task<string?> GetPublicIpAsync(List<string> errors, CancellationToken ct)
    {
        foreach (var url in IpSources)
        {
            try
            {
                var text = (await _http.GetStringAsync(url, ct)).Trim();
                if (IPAddress.TryParse(text, out var addr)) return addr.ToString();
                errors.Add($"{new Uri(url).Host}: bad answer");
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception ex)
            {
                errors.Add($"{new Uri(url).Host}: {ex.Message}");
            }
        }
        return null;
    }

    async Task<JsonElement> GetJsonAsync(string url, CancellationToken ct)
    {
        using var response = await _http.GetAsync(url, ct);
        response.EnsureSuccessStatusCode();
        var body = await response.Content.ReadAsStringAsync(ct);
        using var doc = JsonDocument.Parse(body);
        return doc.RootElement.Clone();
    }

    async Task<GeoResult?> IpWhoIsAsync(string ip, CancellationToken ct)
    {
        var j = await GetJsonAsync($"https://ipwho.is/{ip}", ct);
        if (j.TryGetProperty("success", out var ok) && ok.ValueKind == JsonValueKind.False) return null;
        return Make(ip, Str(j, "country_code"), Str(j, "country"), Str(j, "city"), "ipwho.is");
    }

    async Task<GeoResult?> CountryIsAsync(string ip, CancellationToken ct)
    {
        var j = await GetJsonAsync($"https://api.country.is/{ip}", ct);
        return Make(ip, Str(j, "country"), null, null, "country.is");
    }

    async Task<GeoResult?> FreeIpApiAsync(string ip, CancellationToken ct)
    {
        var j = await GetJsonAsync($"https://freeipapi.com/api/json/{ip}", ct);
        return Make(ip, Str(j, "countryCode"), Str(j, "countryName"), Str(j, "cityName"), "freeipapi.com");
    }

    async Task<GeoResult?> IpApiCoAsync(string ip, CancellationToken ct)
    {
        var j = await GetJsonAsync($"https://ipapi.co/{ip}/json/", ct);
        if (j.TryGetProperty("error", out var err) && err.ValueKind == JsonValueKind.True) return null;
        return Make(ip, Str(j, "country_code"), Str(j, "country_name"), Str(j, "city"), "ipapi.co");
    }

    static string? Str(JsonElement j, string name) =>
        j.ValueKind == JsonValueKind.Object && j.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String
            ? v.GetString()
            : null;

    static GeoResult? Make(string ip, string? code, string? name, string? city, string provider)
    {
        code = code?.Trim().ToUpperInvariant();
        if (code is not { Length: 2 } || !code.All(char.IsAsciiLetterUpper)) return null;
        if (string.IsNullOrWhiteSpace(name)) name = CountryNames.Get(code);
        return new GeoResult(ip, code, name!, string.IsNullOrWhiteSpace(city) ? null : city, provider);
    }

    public void Dispose() => _http.Dispose();
}

/// <summary>Fake locator for test mode: returns a chosen country or fails on purpose.</summary>
public sealed class SimulatedLocator : IIpLocator
{
    public string? Country { get; set; }
    public bool Fail { get; set; }

    public SimulatedLocator(string? country, bool fail)
    {
        Country = country;
        Fail = fail;
    }

    public Task<GeoResult> LocateAsync(CancellationToken ct)
    {
        if (Fail || string.IsNullOrEmpty(Country))
            throw new GeoLookupException("Simulated lookup failure");
        var code = Country.ToUpperInvariant();
        return Task.FromResult(new GeoResult("203.0.113.10", code, CountryNames.Get(code), "Test City", "simulated"));
    }
}
