using System.Text.Json;
using System.Text.Json.Serialization;

namespace ClaudeIpGuard.Core;

public sealed class AppSettings
{
    public const int MinInterval = 10;
    public const int MaxInterval = 3600;

    public int CheckIntervalSeconds { get; set; } = 30;
    public bool FailSafeBlock { get; set; } = true;
    public bool KillDesktopApp { get; set; } = true;
    public bool KillCli { get; set; } = true;
    public List<string> AllowedCountries { get; set; } = new(EuropeCountries.Default);
    public string Language { get; set; } = "en";

    // PBKDF2 hash of the dashboard password. Never stored in plain text.
    public string? PasswordHash { get; set; }
    public string? PasswordSalt { get; set; }
    public int PasswordIterations { get; set; }

    [JsonIgnore]
    public bool HasPassword => !string.IsNullOrEmpty(PasswordHash) && !string.IsNullOrEmpty(PasswordSalt);

    public AppSettings Clone() =>
        JsonSerializer.Deserialize<AppSettings>(JsonSerializer.Serialize(this))!;

    public void Normalize()
    {
        CheckIntervalSeconds = Math.Clamp(CheckIntervalSeconds, MinInterval, MaxInterval);
        AllowedCountries = (AllowedCountries ?? new List<string>())
            .Select(c => (c ?? "").Trim().ToUpperInvariant())
            .Where(c => c.Length == 2)
            .Distinct()
            .OrderBy(c => c)
            .ToList();
        Language = Language == "fa" ? "fa" : "en";
    }
}

public sealed class SettingsStore
{
    static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    public string FilePath { get; }

    public SettingsStore(string fileName = "settings.json", string? directory = null)
    {
        directory ??= AppPaths.DataDirectory;
        FilePath = Path.Combine(directory, fileName);
    }

    public AppSettings Load()
    {
        try
        {
            if (File.Exists(FilePath))
            {
                var s = JsonSerializer.Deserialize<AppSettings>(File.ReadAllText(FilePath));
                if (s != null)
                {
                    s.Normalize();
                    return s;
                }
            }
        }
        catch (Exception ex)
        {
            CrashLog.Write("Could not read settings, using defaults", ex);
        }
        return new AppSettings();
    }

    public void Save(AppSettings settings)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(FilePath)!);
        var tmp = FilePath + ".tmp";
        File.WriteAllText(tmp, JsonSerializer.Serialize(settings, JsonOptions));
        File.Move(tmp, FilePath, overwrite: true);
    }
}

public static class AppPaths
{
    public static string DataDirectory { get; set; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "ClaudeIpGuard");
}

public static class CrashLog
{
    static readonly object Lock = new();

    public static void Write(string message, Exception? ex = null)
    {
        try
        {
            lock (Lock)
            {
                Directory.CreateDirectory(AppPaths.DataDirectory);
                var path = Path.Combine(AppPaths.DataDirectory, "error.log");
                if (File.Exists(path) && new FileInfo(path).Length > 1_000_000) File.Delete(path);
                File.AppendAllText(path, $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] {message}{Environment.NewLine}{ex}{Environment.NewLine}");
            }
        }
        catch
        {
            // Logging must never crash the guard.
        }
    }
}
