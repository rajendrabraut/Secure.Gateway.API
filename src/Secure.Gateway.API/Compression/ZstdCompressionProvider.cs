using Microsoft.AspNetCore.ResponseCompression;
using Microsoft.Extensions.Options;
using Secure.Gateway.API.Options;
using ZstdSharp;

namespace Secure.Gateway.API.Compression;

/// <summary>
/// Zstandard (RFC 8878) response compression ("Content-Encoding: zstd").
/// Supported by Chrome/Edge 123+, Firefox 126+ and Safari 26.3+ (HTTPS only).
/// ASP.NET Core 10 has no built-in zstd provider (it arrives in ASP.NET Core 11), so this uses
/// ZstdSharp - a fully managed port of the reference libzstd, no native binaries required.
/// </summary>
public sealed class ZstdCompressionProvider(IOptions<GatewayOptions> options) : ICompressionProvider
{
    private readonly int _level = Math.Clamp(options.Value.Compression.ZstdLevel, 1, 22);

    public string EncodingName => "zstd";

    public bool SupportsFlush => true;

    public Stream CreateStream(Stream outputStream) =>
        new CompressionStream(outputStream, _level, leaveOpen: true);
}
