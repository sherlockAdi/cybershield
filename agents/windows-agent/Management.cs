using System.Diagnostics;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Runtime.Versioning;
using System.Text.Json;
namespace ServerGuard.Agent;

[SupportedOSPlatform("windows")]
internal static class Management
{
    public static void ValidateHelper(string filename)
    {
        if (!Path.IsPathFullyQualified(filename)) throw new InvalidOperationException("Helper path must be absolute");
        var allowed = new HashSet<string> { WindowsIdentity.GetCurrent().User!.Value, "S-1-5-18", "S-1-5-32-544" };
        var depth = 0;
        for (FileSystemInfo? info = new FileInfo(filename); info is not null; info = info is FileInfo file ? file.Directory : ((DirectoryInfo)info).Parent)
        {
            if (!info.Exists || (info.Attributes & FileAttributes.ReparsePoint) != 0) throw new UnauthorizedAccessException("Helper path cannot contain links");
            FileSystemSecurity acl = info is FileInfo f ? f.GetAccessControl() : ((DirectoryInfo)info).GetAccessControl();
            var writes = FileSystemRights.Delete | FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership | (depth++ < 2 ? FileSystemRights.WriteData | FileSystemRights.AppendData | FileSystemRights.WriteExtendedAttributes | FileSystemRights.WriteAttributes : FileSystemRights.DeleteSubdirectoriesAndFiles);
            foreach (FileSystemAccessRule rule in acl.GetAccessRules(true,true,typeof(SecurityIdentifier)))
                if (rule.AccessControlType == AccessControlType.Allow && !allowed.Contains(rule.IdentityReference.Value) && (rule.FileSystemRights & writes) != 0)
                    throw new UnauthorizedAccessException("Helper path is writable by an untrusted identity");
        }
    }
    private static async Task<JsonElement> Invoke(string helper, object input, CancellationToken token)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(token);
        timeout.CancelAfter(TimeSpan.FromSeconds(45));
        var start = new ProcessStartInfo(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), @"WindowsPowerShell\v1.0\powershell.exe")) { UseShellExecute=false, RedirectStandardInput=true, RedirectStandardOutput=true, RedirectStandardError=true, CreateNoWindow=true };
        foreach (var argument in new[] { "-NoProfile", "-NonInteractive", "-File", helper }) start.ArgumentList.Add(argument);
        using var process = Process.Start(start) ?? throw new InvalidOperationException("Cannot start management helper");
        using var cancellation = timeout.Token.Register(() => { try { process.Kill(true); } catch (InvalidOperationException) { } });
        await process.StandardInput.WriteAsync(JsonSerializer.Serialize(input)); process.StandardInput.Close();
        var drainError = process.StandardError.BaseStream.CopyToAsync(Stream.Null, timeout.Token);
        using var output = new MemoryStream(); var chunk = new byte[4096]; int length;
        while ((length = await process.StandardOutput.BaseStream.ReadAsync(chunk,timeout.Token)) > 0) {
            if (output.Length + length > 220000) { process.Kill(true); throw new InvalidOperationException("Helper output too large"); }
            output.Write(chunk,0,length);
        }
        await process.WaitForExitAsync(timeout.Token); await drainError;
        if (process.ExitCode != 0) throw new InvalidOperationException("Management helper failed");
        using var document = JsonDocument.Parse(output.ToArray()); return document.RootElement.Clone();
    }
    public static async Task<object?> Report(AgentOptions options, AgentState state, CancellationToken token)
    {
        if (options.ManagementHelper is null) return null;
        Dictionary<string,object?> report;
        try {
            var value = await Invoke(options.ManagementHelper, new { operation="INVENTORY" }, token);
            report = value.EnumerateObject().ToDictionary(item => item.Name, item => (object?)item.Value.Clone());
        } catch (Exception error) when (error is not OperationCanceledException || !token.IsCancellationRequested) {
            report = new() { ["applications"]=Array.Empty<object>(), ["rules"]=Array.Empty<object>(), ["firewall"]=false, ["errors"]=new[]{"Management helper unavailable; check host installation"}, ["truncated"]=false };
        }
        report["results"] = state.ManagementResult is null ? Array.Empty<object>() : new object[]{state.ManagementResult.Value};
        return report;
    }
    public static async Task Execute(AgentOptions options, StateStore store, JsonElement heartbeat, CancellationToken token)
    {
        if (options.ManagementHelper is null || !heartbeat.TryGetProperty("command",out var command) || command.ValueKind == JsonValueKind.Null) return;
        var id = command.GetProperty("id").GetString();
        if (store.State.ManagementResult?.GetProperty("id").GetString() == id) return;
        store.State.ManagementResult = JsonSerializer.SerializeToElement(new { id, success=false, message="Execution interrupted; inspect host before retrying" });
        store.Save();
        try {
            if (command.GetProperty("expiresAt").GetDateTimeOffset() <= DateTimeOffset.UtcNow) throw new InvalidOperationException("Expired command");
            var result = await Invoke(options.ManagementHelper,command,token);
            if (result.GetProperty("id").GetString() != id) throw new InvalidOperationException("Helper result mismatch");
            store.State.ManagementResult = result;
        } catch (Exception error) when (error is not OperationCanceledException || !token.IsCancellationRequested) {
            store.State.ManagementResult = JsonSerializer.SerializeToElement(new { id, success=false, message="Helper failed; inspect host before retrying" });
        }
        store.Save();
    }
}
