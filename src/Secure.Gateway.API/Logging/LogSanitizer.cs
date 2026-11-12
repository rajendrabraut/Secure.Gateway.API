namespace Secure.Gateway.API.Logging;

/// <summary>Neutralises attacker-controlled values before they reach logs (CWE-117 log injection).</summary>
public static class LogSanitizer
{
    public static string Clean(string? value, int maxLength = 256)
    {
        if (string.IsNullOrEmpty(value)) return string.Empty;

        var span = value.AsSpan(0, Math.Min(value.Length, maxLength));
        Span<char> buffer = span.Length <= 512 ? stackalloc char[span.Length] : new char[span.Length];
        for (var i = 0; i < span.Length; i++)
        {
            var c = span[i];
            buffer[i] = char.IsControl(c) ? '_' : c;
        }

        var cleaned = new string(buffer);
        return value.Length > maxLength ? cleaned + "…" : cleaned;
    }
}
