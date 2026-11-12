using System.IO.Compression;
using Microsoft.AspNetCore.ResponseCompression;
using Secure.Gateway.API.Options;

namespace Secure.Gateway.API.Compression;

public static class CompressionExtensions
{
    /// <summary>
    /// Registers zstd, Brotli and Gzip. When the client sends equal q-values the first provider wins,
    /// so the order zstd -> br -> gzip means: fastest modern codec first, universal fallback last.
    /// Clients that send no Accept-Encoding get an uncompressed response.
    /// </summary>
    public static IServiceCollection AddGatewayCompression(this IServiceCollection services, IConfiguration configuration)
    {
        var settings = configuration.GetSection($"{GatewayOptions.SectionName}:Compression").Get<CompressionSettings>() ?? new();

        services.AddResponseCompression(o =>
        {
            o.EnableForHttps = settings.EnableForHttps;
            o.Providers.Add<ZstdCompressionProvider>();
            o.Providers.Add<BrotliCompressionProvider>();
            o.Providers.Add<GzipCompressionProvider>();
            o.MimeTypes = settings.MimeTypes;
        });

        services.Configure<BrotliCompressionProviderOptions>(o => o.Level = ParseLevel(settings.BrotliLevel));
        services.Configure<GzipCompressionProviderOptions>(o => o.Level = ParseLevel(settings.GzipLevel));
        return services;
    }

    private static CompressionLevel ParseLevel(string value) =>
        Enum.TryParse<CompressionLevel>(value, ignoreCase: true, out var level) ? level : CompressionLevel.Fastest;
}
