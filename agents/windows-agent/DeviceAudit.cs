using System.Runtime.Versioning;
using System.Text.Json;
namespace ServerGuard.Agent;

[SupportedOSPlatform("windows")]
internal static class DeviceAudit
{
    private static JsonElement? cached;
    private static DateTimeOffset attempted;
    public static async Task<JsonElement?> Report(AgentOptions options, CancellationToken token)
    {
        if (options.DeviceAuditHelper is null) return null;
        if (DateTimeOffset.UtcNow - attempted < TimeSpan.FromMinutes(2)) return cached;
        attempted = DateTimeOffset.UtcNow;
        try
        {
            var value = await Management.Invoke(options.DeviceAuditHelper, new { operation = "AUDIT" }, token);
            if (System.Text.Encoding.UTF8.GetByteCount(value.GetRawText()) > 100000) throw new InvalidOperationException("Device audit too large");
            if (value.GetProperty("mode").GetString() != "AUDIT_ONLY") throw new InvalidOperationException("Invalid device audit");
            cached = value;
        }
        catch (Exception error) when (error is not OperationCanceledException || !token.IsCancellationRequested)
        {
            // Stop sending old data on collector failure. Control plane retains its
            // receipt timestamp, so unavailable audit becomes visibly stale.
            cached = null;
        }
        return cached;
    }
}
