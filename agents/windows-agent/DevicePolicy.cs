using System.Runtime.Versioning;
using System.Text.Json;
namespace ServerGuard.Agent;
[SupportedOSPlatform("windows")]
internal static class DevicePolicy
{
    private static DateTimeOffset lastAttempt;
    private static int lastRevision;
    public static async Task Execute(AgentOptions options, StateStore store, JsonElement heartbeat, CancellationToken token)
    {
        if (options.DevicePolicyHelper is null || !heartbeat.TryGetProperty("devicePolicy",out var policy) || policy.ValueKind == JsonValueKind.Null) return;
        var revision=policy.GetProperty("revision").GetInt32();
        if(revision==lastRevision && DateTimeOffset.UtcNow-lastAttempt<TimeSpan.FromMinutes(2))return;
        lastRevision=revision;lastAttempt=DateTimeOffset.UtcNow;
        store.State.DevicePolicyResult=JsonSerializer.SerializeToElement(new {revision,status="FAILED",controls=new[]{new{name="execution",status="FAILED",message="Policy execution interrupted; inspect host."}}});
        store.Save();
        try {
            var result=await Management.Invoke(options.DevicePolicyHelper,policy,token);
            if(result.GetProperty("revision").GetInt32()!=revision)throw new InvalidOperationException("Policy revision mismatch");
            store.State.DevicePolicyResult=result;
        } catch(Exception error) when(error is not OperationCanceledException || !token.IsCancellationRequested) { }
        store.Save();
    }
}
