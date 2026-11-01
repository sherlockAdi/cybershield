using System.Net;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace ServerGuard.Agent;

internal static class Program
{
    public static async Task<int> Main(string[] args)
    {
        try
        {
            if (args.SequenceEqual(["--self-test"]))
            {
                Protocol.SelfTest();
                return 0;
            }
            if (!OperatingSystem.IsWindows()) throw new InvalidOperationException("This service runs on Windows; --self-test supports other platforms.");
            var options = AgentOptions.Parse(args);
            var builder = Host.CreateApplicationBuilder();
            builder.Services.AddSingleton(options);
            builder.Services.AddWindowsService(settings => settings.ServiceName = "ServerGuardAgent");
            builder.Services.AddHostedService<AgentWorker>();
            await builder.Build().RunAsync();
            return Environment.ExitCode;
        }
        catch (Exception exception) when (exception is ArgumentException or InvalidOperationException or IOException or CryptographicException or UnauthorizedAccessException)
        {
            Console.Error.WriteLine($"Agent cannot start: {exception.GetType().Name}. Check configuration, state permissions and service identity.");
            return 1;
        }
    }
}

internal sealed record AgentOptions(Uri Api, Guid ServerId, string StateDirectory, string? TokenFile, bool Once, string? EventsFile)
{
    public static AgentOptions Parse(string[] args)
    {
        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        var flags = new HashSet<string>(StringComparer.Ordinal);
        for (var index = 0; index < args.Length; index++)
        {
            if (args[index] is "--once" or "--allow-loopback-http") { if (!flags.Add(args[index])) throw new ArgumentException("Duplicate flag"); continue; }
            if (args[index] is not ("--api" or "--server-id" or "--state-dir" or "--token-file" or "--events-file") || index + 1 >= args.Length) throw new ArgumentException("Unsupported argument");
            if (!values.TryAdd(args[index], args[++index])) throw new ArgumentException("Duplicate argument");
        }
        if (!values.TryGetValue("--api", out var rawOrigin) || !Uri.TryCreate(rawOrigin, UriKind.Absolute, out var origin)) throw new ArgumentException("An API origin is required");
        if (!string.IsNullOrEmpty(origin.UserInfo) || !string.IsNullOrEmpty(origin.Query) || !string.IsNullOrEmpty(origin.Fragment) || origin.AbsolutePath != "/") throw new ArgumentException("API must be an origin without credentials or a path");
        var loopback = IPAddress.TryParse(origin.Host.Trim('[', ']'), out var address) && IPAddress.IsLoopback(address);
        if (origin.Scheme != "https" && !(origin.Scheme == "http" && loopback && flags.Contains("--allow-loopback-http"))) throw new ArgumentException("HTTPS is required outside explicit loopback development");
        if (!values.TryGetValue("--server-id", out var rawServerId) || !Guid.TryParse(rawServerId, out var serverId)) throw new ArgumentException("A server UUID is required");
        var directory = Path.GetFullPath(values.GetValueOrDefault("--state-dir") ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "ServerGuard", "Agent"));
        if (directory.TrimEnd(Path.DirectorySeparatorChar) == Path.GetPathRoot(directory)?.TrimEnd(Path.DirectorySeparatorChar)) throw new ArgumentException("State directory cannot be a drive root");
        return new AgentOptions(origin, serverId, directory, values.GetValueOrDefault("--token-file"), flags.Contains("--once"), values.GetValueOrDefault("--events-file"));
    }
}

internal static class Protocol
{
    public static byte[] Message(string endpoint, string timestamp, string nonce, byte[] body) => Encoding.UTF8.GetBytes($"SG1\nPOST\n{endpoint}\n{timestamp}\n{nonce}\n{Convert.ToHexStringLower(SHA256.HashData(body))}");
    public static string Sign(ECDsa key, byte[] message) => Convert.ToBase64String(key.SignData(message, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence));
    public static void SelfTest()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var message = Message("/api/agent/v1/heartbeat", "1700000000", "abcdefghijklmnopqrstuv", Encoding.UTF8.GetBytes("{\"schemaVersion\":1}"));
        var signature = Sign(key, message);
        if (!key.VerifyData(message, Convert.FromBase64String(signature), HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence)) throw new CryptographicException("Signature self-test failed");
        Console.WriteLine(JsonSerializer.Serialize(new { publicKey = key.ExportSubjectPublicKeyInfoPem(), message = Encoding.UTF8.GetString(message), signature }));
    }
}

internal sealed class AgentState
{
    public string ServerId { get; set; } = "";
    public string ApiOrigin { get; set; } = "";
    public string ProtectedKey { get; set; } = "";
    public string CredentialId { get; set; } = "";
    public long Sequence { get; set; }
    public string ExpiresAt { get; set; } = "";
    public List<AgentEvent> PendingEvents { get; set; } = [];
    public string ImportedEventsHash { get; set; } = "";
}

[SupportedOSPlatform("windows")]
internal sealed class StateStore : IDisposable
{
    private readonly string directory;
    private readonly FileStream stateLock;
    private readonly byte[] entropy;
    public AgentState State { get; }
    public ECDsa Key { get; }

    private static HashSet<string> AllowedIdentities() => [WindowsIdentity.GetCurrent().User!.Value, new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null).Value, new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null).Value];

    private static void ValidateAcl(FileSystemSecurity security)
    {
        var allowed = AllowedIdentities();
        foreach (FileSystemAccessRule rule in security.GetAccessRules(true, true, typeof(SecurityIdentifier)))
            if (rule.AccessControlType == AccessControlType.Allow && !allowed.Contains(rule.IdentityReference.Value)) throw new UnauthorizedAccessException("State or token permissions are too broad");
    }

    public StateStore(AgentOptions options)
    {
        directory = options.StateDirectory;
        var existed = Directory.Exists(directory);
        var info = Directory.CreateDirectory(directory);
        if ((info.Attributes & FileAttributes.ReparsePoint) != 0) throw new UnauthorizedAccessException("State directory must not be a link");
        if (!existed)
        {
            var security = new DirectorySecurity();
            security.SetAccessRuleProtection(true, false);
            foreach (var identity in AllowedIdentities()) security.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(identity), FileSystemRights.FullControl, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
            info.SetAccessControl(security);
        }
        ValidateAcl(info.GetAccessControl());
        var lockInfo = new FileInfo(Path.Combine(directory, "agent.lock"));
        if (lockInfo.Exists && (lockInfo.Attributes & FileAttributes.ReparsePoint) != 0) throw new UnauthorizedAccessException("Lock file must not be a link");
        stateLock = new FileStream(lockInfo.FullName, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
        entropy = Encoding.UTF8.GetBytes($"ServerGuard:{options.ServerId:D}");
        var filename = Path.Combine(directory, "state.json");
        if (File.Exists(filename))
        {
            var stateInfo = new FileInfo(filename);
            if ((stateInfo.Attributes & FileAttributes.ReparsePoint) != 0) throw new UnauthorizedAccessException("State file must not be a link");
            ValidateAcl(stateInfo.GetAccessControl());
            var stateBytes = ReadPrivateBytes(filename,131072);
            using var stateDocument = JsonDocument.Parse(stateBytes);
            foreach (var required in new[] { "ServerId", "ApiOrigin", "ProtectedKey", "Sequence" })
                if (!stateDocument.RootElement.TryGetProperty(required,out var field) || field.ValueKind == JsonValueKind.Null) throw new InvalidOperationException("State is missing identity or replay fields");
            State = JsonSerializer.Deserialize<AgentState>(stateBytes) ?? throw new InvalidOperationException("Invalid state");
            if (State.PendingEvents is null || State.PendingEvents.Count > 100) throw new InvalidOperationException("Invalid persisted event outbox");
            if (State.ServerId != options.ServerId.ToString("D") || State.ApiOrigin != options.Api.GetLeftPart(UriPartial.Authority) || State.Sequence < 0 || State.Sequence > 9007199254740991) throw new InvalidOperationException("State identity mismatch");
            var clearKey = ProtectedData.Unprotect(Convert.FromBase64String(State.ProtectedKey), entropy, DataProtectionScope.CurrentUser);
            try { Key = ECDsa.Create(); Key.ImportPkcs8PrivateKey(clearKey, out _); }
            finally { CryptographicOperations.ZeroMemory(clearKey); }
            if (Key.KeySize != 256 || Key.ExportParameters(false).Curve.Oid.Value != ECCurve.NamedCurves.nistP256.Oid.Value) throw new CryptographicException("Expected a P-256 key");
        }
        else
        {
            Key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var clearKey = Key.ExportPkcs8PrivateKey();
            try { State = new AgentState { ServerId = options.ServerId.ToString("D"), ApiOrigin = options.Api.GetLeftPart(UriPartial.Authority), ProtectedKey = Convert.ToBase64String(ProtectedData.Protect(clearKey, entropy, DataProtectionScope.CurrentUser)) }; }
            finally { CryptographicOperations.ZeroMemory(clearKey); }
            Save();
        }
    }

    public string ReadToken(string? filename)
    {
        if (filename is null) throw new InvalidOperationException("Initial enrollment requires --token-file");
        var info = new FileInfo(filename);
        if (!info.Exists || info.Length > 1024 || (info.Attributes & FileAttributes.ReparsePoint) != 0) throw new InvalidOperationException("Invalid token file");
        ValidateAcl(info.GetAccessControl());
        return new UTF8Encoding(false,true).GetString(ReadPrivateBytes(filename,1024)).Trim();
    }

    public void Save()
    {
        var content = JsonSerializer.SerializeToUtf8Bytes(State);
        if (content.Length > 131072) throw new InvalidOperationException("Agent state exceeds 128 KiB");
        var temporary = Path.Combine(directory, $".state-{Guid.NewGuid():N}");
        try
        {
            using (var file = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
            {
                file.Write(content);
                file.Flush(true);
            }
            File.Move(temporary, Path.Combine(directory, "state.json"), true);
        }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
    }
    public void ImportEvents(string? filename)
    {
        if (filename is null) return;
        var info = new FileInfo(filename);
        if (!info.Exists || info.Length > 32768 || (info.Attributes & FileAttributes.ReparsePoint) != 0) throw new InvalidOperationException("Invalid event file");
        ValidateAcl(info.GetAccessControl());
        var content = ReadPrivateBytes(filename,32768);
        var hash = Convert.ToHexString(SHA256.HashData(content));
        if (hash == State.ImportedEventsHash) return;
        var incoming = new List<AgentEvent>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var line in new UTF8Encoding(false,true).GetString(content).TrimStart('\uFEFF').Split('\n'))
        {
            if (string.IsNullOrWhiteSpace(line)) continue;
            var item = JsonSerializer.Deserialize<AgentEvent>(line, new JsonSerializerOptions { UnmappedMemberHandling = System.Text.Json.Serialization.JsonUnmappedMemberHandling.Disallow }) ?? throw new InvalidOperationException("Invalid event JSONL");
            if (item.kind is not ("AUTH_FAILURE" or "AUTH_SUCCESS" or "PROCESS_START") || string.IsNullOrEmpty(item.sourceEventId) || item.sourceEventId.Length > 128 || item.payload is null || !item.payload.ContainsKey("source") || !DateTimeOffset.TryParse(item.occurredAt, out _)) throw new InvalidOperationException("Unsupported normalized event");
            incoming.Add(item);
            if (!seen.Add(item.sourceEventId)) throw new InvalidOperationException("Duplicate source identity in event file");
            if (incoming.Count > 90) throw new InvalidOperationException("Event file exceeds 90 observations");
        }
        if (State.PendingEvents.Count + incoming.Count > 100) return;
        State.PendingEvents.AddRange(incoming);
        State.ImportedEventsHash = hash;
        Save();
    }
    private static byte[] ReadPrivateBytes(string filename, int limit)
    {
        var info = new FileInfo(filename);
        if (!info.Exists || info.Length > limit || (info.Attributes & (FileAttributes.ReparsePoint | FileAttributes.Directory)) != 0) throw new InvalidOperationException("Expected a bounded private regular file");
        ValidateAcl(info.GetAccessControl());
        using var stream = new FileStream(filename,FileMode.Open,FileAccess.Read,FileShare.Read);
        using var buffer = new MemoryStream();
        var chunk = new byte[4096];
        int length;
        while ((length = stream.Read(chunk,0,Math.Min(chunk.Length,limit+1-(int)buffer.Length))) > 0)
        {
            buffer.Write(chunk,0,length);
            if (buffer.Length > limit) throw new InvalidOperationException("Private file exceeds size limit");
        }
        return buffer.ToArray();
    }
    public void Dispose() { Key.Dispose(); stateLock.Dispose(); }
}

internal sealed class ControlPlaneException(int status) : Exception($"Control plane returned HTTP {status}")
{
    public int Status { get; } = status;
    public bool Fatal => Status is >= 400 and < 500 and not 429;
}

internal sealed class AgentWorker(AgentOptions options, ILogger<AgentWorker> logger, IHostApplicationLifetime lifetime) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!OperatingSystem.IsWindows()) throw new InvalidOperationException("Windows runtime required");
        try { await RunWindows(stoppingToken); }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { }
        catch (Exception exception)
        {
            logger.LogError("Agent stopped ({ErrorType}). Check credentials, state ownership and connection settings.", exception.GetType().Name);
            Environment.ExitCode = 1;
        }
        finally { lifetime.StopApplication(); }
    }

    [SupportedOSPlatform("windows")]
    private async Task RunWindows(CancellationToken cancellationToken)
    {
        using var store = new StateStore(options);
        using var handler = new HttpClientHandler { AllowAutoRedirect = false, SslProtocols = System.Security.Authentication.SslProtocols.Tls12 | System.Security.Authentication.SslProtocols.Tls13 };
        using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(15), BaseAddress = options.Api };
        var state = store.State;
        if (state.PendingEvents.Count >= 100) throw new InvalidOperationException("Event outbox is full; restore ingestion before restarting");
        state.PendingEvents.Add(new AgentEvent(Guid.NewGuid().ToString("D"), "AGENT_STARTED", "INFO", DateTime.UtcNow.ToString("O", System.Globalization.CultureInfo.InvariantCulture), new Dictionary<string, string> { ["source"] = "serverguard-windows-agent", ["message"] = "Agent process started" }));
        store.Save();
        var collector = new TelemetryCollector();
        var backoffSeconds = 5;
        while (!cancellationToken.IsCancellationRequested)
        {
            var delay = TimeSpan.FromSeconds(30);
            try
            {
                store.ImportEvents(options.EventsFile);
                if (string.IsNullOrEmpty(state.CredentialId))
                {
                    var response = await Send(client, store.Key, "/api/agent/v1/enroll", new { schemaVersion = 1, serverId = state.ServerId, token = store.ReadToken(options.TokenFile), publicKey = store.Key.ExportSubjectPublicKeyInfoPem(), hostname = Environment.MachineName, os = "WINDOWS", osVersion = OSVersion(), agentVersion = "0.8.0-prototype" }, cancellationToken);
                    if (response.GetProperty("serverId").GetString() != state.ServerId || !Guid.TryParse(response.GetProperty("credentialId").GetString(), out var credentialId)) throw new InvalidOperationException("Enrollment response identity mismatch");
                    state.CredentialId = credentialId.ToString("D");
                    state.ExpiresAt = response.GetProperty("expiresAt").GetString() ?? "";
                    store.Save();
                    logger.LogInformation("Enrollment accepted; local identity saved");
                }
                if (state.Sequence >= 9007199254740991) throw new InvalidOperationException("Sequence exhausted; new enrollment required");
                state.Sequence++;
                store.Save();
                var heartbeat = await Send(client, store.Key, "/api/agent/v1/heartbeat", new { schemaVersion = 1, serverId = state.ServerId, credentialId = state.CredentialId, sequence = state.Sequence, hostname = Environment.MachineName, os = "WINDOWS", osVersion = OSVersion(), agentVersion = "0.8.0-prototype", uptimeSeconds = Math.Max(0, Environment.TickCount64 / 1000), inventory = new { architecture = RuntimeInformation.OSArchitecture.ToString().ToLowerInvariant(), logicalCpuCount = Environment.ProcessorCount }, metrics = collector.Collect() }, cancellationToken);
                if (!heartbeat.GetProperty("accepted").GetBoolean() || heartbeat.GetProperty("serverId").GetString() != state.ServerId || heartbeat.GetProperty("acceptedSequence").GetInt64() != state.Sequence) throw new InvalidOperationException("Heartbeat response mismatch");
                var interval = heartbeat.GetProperty("heartbeatIntervalSeconds").GetInt32();
                if (interval is >= 10 and <= 300) delay = TimeSpan.FromSeconds(interval);
                logger.LogInformation("Heartbeat accepted (sequence {Sequence})", state.Sequence);
                if (state.PendingEvents.Count > 0)
                {
                    if (state.Sequence >= 9007199254740991) throw new InvalidOperationException("Sequence exhausted; new enrollment required");
                    state.Sequence++;
                    store.Save();
                    var events = await Send(client, store.Key, "/api/agent/v1/events", new { schemaVersion = 1, serverId = state.ServerId, credentialId = state.CredentialId, sequence = state.Sequence, events = state.PendingEvents }, cancellationToken);
                    var accepted = events.GetProperty("acceptedCount").GetInt32();
                    var duplicates = events.GetProperty("duplicateCount").GetInt32();
                    if (accepted < 0 || duplicates < 0 || accepted > state.PendingEvents.Count || duplicates > state.PendingEvents.Count) throw new InvalidOperationException("Invalid event acknowledgement counts");
                    if (!events.GetProperty("accepted").GetBoolean() || events.GetProperty("serverId").GetString() != state.ServerId || events.GetProperty("acceptedSequence").GetInt64() != state.Sequence || events.GetProperty("acceptedCount").GetInt32() + events.GetProperty("duplicateCount").GetInt32() != state.PendingEvents.Count) throw new InvalidOperationException("Event acknowledgement mismatch");
                    state.PendingEvents.Clear();
                    store.Save();
                    logger.LogInformation("Event outbox acknowledged");
                }
                backoffSeconds = 5;
                if (options.Once) return;
            }
            catch (Exception exception) when (exception is HttpRequestException or TaskCanceledException or ControlPlaneException)
            {
                if (cancellationToken.IsCancellationRequested) return;
                if (options.Once || exception is ControlPlaneException { Fatal: true }) throw;
                logger.LogWarning("Control-plane request failed ({ErrorType}); retry scheduled", exception.GetType().Name);
                delay = TimeSpan.FromSeconds(backoffSeconds) + TimeSpan.FromMilliseconds(RandomNumberGenerator.GetInt32(1000));
                backoffSeconds = Math.Min(backoffSeconds * 2, 300);
            }
            await Task.Delay(delay, cancellationToken);
        }
    }

    private static string OSVersion() { var value = RuntimeInformation.OSDescription; return value.Length <= 100 ? value : value[..100]; }

    private static async Task<JsonElement> Send(HttpClient client, ECDsa key, string endpoint, object value, CancellationToken cancellationToken)
    {
        var body = JsonSerializer.SerializeToUtf8Bytes(value);
        var timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(System.Globalization.CultureInfo.InvariantCulture);
        var nonce = Convert.ToBase64String(RandomNumberGenerator.GetBytes(16)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        using var request = new HttpRequestMessage(HttpMethod.Post, endpoint);
        request.Content = new ByteArrayContent(body);
        request.Content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/json");
        request.Headers.Add("X-SG-Timestamp", timestamp);
        request.Headers.Add("X-SG-Nonce", nonce);
        request.Headers.Add("X-SG-Signature", Protocol.Sign(key, Protocol.Message(endpoint, timestamp, nonce, body)));
        using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
        if (!response.IsSuccessStatusCode) throw new ControlPlaneException((int)response.StatusCode);
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
        using var buffer = new MemoryStream();
        var bytes = new byte[4096];
        int length;
        while ((length = await stream.ReadAsync(bytes, cancellationToken)) > 0)
        {
            if (buffer.Length + length > 16384) throw new InvalidOperationException("Control-plane response is too large");
            buffer.Write(bytes, 0, length);
        }
        using var document = JsonDocument.Parse(buffer.ToArray());
        return document.RootElement.Clone();
    }
}
