using System.Security.Cryptography;

namespace ClaudeIpGuard.Core;

public static class PasswordHasher
{
    public const int MinLength = 4;
    const int Iterations = 200_000;
    const int HashSize = 32;

    public static void SetPassword(AppSettings settings, string password)
    {
        var salt = RandomNumberGenerator.GetBytes(16);
        var hash = Rfc2898DeriveBytes.Pbkdf2(password, salt, Iterations, HashAlgorithmName.SHA256, HashSize);
        settings.PasswordSalt = Convert.ToBase64String(salt);
        settings.PasswordHash = Convert.ToBase64String(hash);
        settings.PasswordIterations = Iterations;
    }

    public static bool Verify(AppSettings settings, string password)
    {
        if (!settings.HasPassword) return false;
        try
        {
            var salt = Convert.FromBase64String(settings.PasswordSalt!);
            var expected = Convert.FromBase64String(settings.PasswordHash!);
            var iterations = settings.PasswordIterations > 0 ? settings.PasswordIterations : Iterations;
            var actual = Rfc2898DeriveBytes.Pbkdf2(password, salt, iterations, HashAlgorithmName.SHA256, expected.Length);
            return CryptographicOperations.FixedTimeEquals(actual, expected);
        }
        catch (FormatException)
        {
            return false;
        }
    }
}
