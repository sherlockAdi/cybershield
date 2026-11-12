using System.Runtime.Versioning;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Security.AccessControl;
using Microsoft.Win32.SafeHandles;
using System.Text.Json;
namespace ServerGuard.Agent;

[SupportedOSPlatform("windows")]
internal static class ScreenCapture
{
    [DllImport("kernel32.dll")] private static extern uint WTSGetActiveConsoleSessionId();
    [DllImport("wtsapi32.dll", SetLastError=true)] private static extern bool WTSQueryUserToken(uint sessionId,out SafeAccessTokenHandle token);
    public static void Disable() => config=null;
    private static JsonElement? config;
    private static DateTimeOffset validUntil;
    private static DateTimeOffset nextUpload;
    private static string lastCapture = "";
    private static readonly string Root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "CyberShieldScreenCapture");
    public static void Configure(JsonElement heartbeat)
    {
        if (!heartbeat.TryGetProperty("screen", out var value)) return;
        config=null;validUntil=DateTimeOffset.UtcNow.AddSeconds(65);
        if(!Directory.Exists(Root))return; // Local administrator must provision the consent helper first.
        // The shared root must be admin-controlled; only its frames subdirectory is user-writable.
        var owner=new DirectoryInfo(Root).GetAccessControl().GetOwner(typeof(SecurityIdentifier)).Value;
        if(owner is not ("S-1-5-18" or "S-1-5-32-544"))throw new UnauthorizedAccessException("Screen helper root must be administrator-owned");
        var script=Path.Combine(Root,"Start-ScreenSharing.ps1");
        Management.ValidateHelper(script);
        var path=Path.Combine(Root,"settings.json");
        var temp=Path.Combine(Root,$".settings-{Guid.NewGuid():N}");
        try {
            File.WriteAllText(temp,JsonSerializer.Serialize(new { enabled=value.GetProperty("enabled").GetBoolean(), intervalSeconds=value.GetProperty("intervalSeconds").GetInt32(), revision=value.GetProperty("revision").GetInt32(), validUntil }));
            File.Move(temp,path,true);config=value.Clone();
        } finally { if(File.Exists(temp))File.Delete(temp); }
    }
    public static async Task Tick(AgentOptions options,StateStore store,HttpClient client,CancellationToken token)
    {
        if(config is not JsonElement settings || !settings.GetProperty("enabled").GetBoolean() || DateTimeOffset.UtcNow>validUntil || DateTimeOffset.UtcNow<nextUpload)return;
        var interval=settings.GetProperty("intervalSeconds").GetInt32();
        nextUpload=DateTimeOffset.UtcNow.AddSeconds(interval);
        try {
            var frames=new DirectoryInfo(Path.Combine(Root,"frames"));
            var file=new FileInfo(Path.Combine(frames.FullName,"latest.json"));
            if(!frames.Exists || frames.Attributes.HasFlag(FileAttributes.ReparsePoint) || !file.Exists || file.Attributes.HasFlag(FileAttributes.ReparsePoint) || file.Length>132000)return;
            if(!WTSQueryUserToken(WTSGetActiveConsoleSessionId(),out var userToken))return;
            using var identityToken=userToken;
            // Open under the interactive user's identity: even a replaced junction
            // or symlink cannot make SYSTEM disclose a file that user cannot read.
            using var stream=WindowsIdentity.RunImpersonated(userToken,()=>new FileStream(file.FullName,FileMode.Open,FileAccess.Read,FileShare.Read|FileShare.Delete));
            var bytes=new byte[132001];var count=0;int read;
            while(count<bytes.Length && (read=await stream.ReadAsync(bytes.AsMemory(count),token))>0)count+=read;
            if(count>132000)return;
            using var document=JsonDocument.Parse(bytes.AsMemory(0,count));
            var frame=document.RootElement;
            var stamp=frame.GetProperty("capturedAt").GetString()??"";
            if(stamp==lastCapture || !DateTimeOffset.TryParse(stamp,out var captured) || Math.Abs((DateTimeOffset.UtcNow-captured).TotalSeconds)>25)return;
            if(frame.GetProperty("revision").GetInt32()!=settings.GetProperty("revision").GetInt32())return;
            var jpeg=frame.GetProperty("jpeg").GetString()??"";
            if(jpeg.Length>128000)return;
            if(store.State.Sequence>=9007199254740991)return;
            store.State.Sequence++;store.Save();
            var reply=await AgentWorker.Send(client,store.Key,"/api/agent/v1/screenshot",new {schemaVersion=1,serverId=store.State.ServerId,credentialId=store.State.CredentialId,sequence=store.State.Sequence,revision=settings.GetProperty("revision").GetInt32(),capturedAt=stamp,jpeg},token);
            if(reply.GetProperty("accepted").GetBoolean() && reply.GetProperty("acceptedSequence").GetInt64()==store.State.Sequence)lastCapture=stamp;
        } catch(Exception error) when(error is not OperationCanceledException || !token.IsCancellationRequested) { /* Capture failure must not stop host monitoring. */ }
    }
}
