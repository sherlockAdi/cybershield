# Build and operate the agent prototypes

Version `0.3.0-prototype`. The agents expose no listener, shell, job runner or firewall adapter. They report hostname, OS version, agent version, uptime and signed heartbeats. They are unsigned development artifacts, not production installers.

## Register and obtain a token

Start `node scripts/run.mjs dev`, sign in, and open **Servers & agents**. An Owner/Admin registers a hostname and selects LINUX or WINDOWS. Copy the server UUID and the ten-minute token shown once. Store the token in a private file; do not put it in command arguments, logs or source control.

Remote agents need a reachable HTTPS control-plane origin with a trusted server certificate and proxy forwarding of `/api/agent/v1/*`. The supplied dashboard/API bind to loopback and are not remotely reachable; configure a reviewed TLS ingress before using a different machine. No tunnel/public deployment is created here.

For same-machine tests only, add `--allow-loopback-http` with `http://127.0.0.1:3100` (dashboard proxy) or `http://127.0.0.1:4100` (API). This permits HTTP only to literal loopback IPs, not `localhost` or another machine, and never disables HTTPS certificate validation. Do not use localhost from a different VM and expect it to refer to the control-plane host.

## Linux

Go 1.24+; verified compiler here is Go 1.27.3. Standard library only.

```sh
cd agents/linux-agent
go test ./...
CGO_ENABLED=0 go build -trimpath -o serverguard-agent .

umask 077
mkdir -p "$HOME/.local/state/serverguard-agent"
chmod 700 "$HOME/.local/state/serverguard-agent"
read -r -s -p 'Enrollment token: ' enrollment_token
printf '\n'
printf '%s' "$enrollment_token" > "$HOME/.local/state/serverguard-agent/enrollment.token"
unset enrollment_token
chmod 600 "$HOME/.local/state/serverguard-agent/enrollment.token"

./serverguard-agent --api https://control.example.com --server-id SERVER_UUID \
  --token-file "$HOME/.local/state/serverguard-agent/enrollment.token" \
  --state-dir "$HOME/.local/state/serverguard-agent" --once
```

Replace the origin/UUID. The token input example uses Bash. `--once` enrolls if needed, sends one heartbeat and exits; omit it for continuous operation. After successful enrollment, restarts need only `--api`, `--server-id` and the same `--state-dir`. Remove the used token file after confirming enrollment; preserve the state file and signing key. Add `--ca-file /path/to/trusted-ca.pem` for an explicit private CA while retaining hostname/certificate verification.

Linux state uses 0700 directories, 0600 files, an exclusive flock and flushed atomic writes. Final state/token components cannot be symlinks. The next sequence is saved before transmission, so a crash or lost response does not reuse a number. OS metadata is read from `/etc/os-release` and `/proc/uptime`; no external commands are executed and no root privilege is required for foreground heartbeat operation.

### systemd template

`agents/linux-agent/serverguard-agent.service` is an uninstalled template. Install the binary under `/usr/local/bin`, create a dedicated `serverguard` user/group, place a private token at `/etc/serverguard/enrollment.token` owned by that identity, and replace the HTTPS origin/UUID before enabling it. The template declares a 0700 StateDirectory, no capabilities, no new privileges and a read-only system filesystem. Do not run placeholders unchanged. Actual Linux/systemd execution remains a VM acceptance gate.

## Windows

Build with .NET 10 SDK; the published framework-dependent package requires .NET 10 runtime.

```powershell
dotnet restore agents/windows-agent/ServerGuard.Agent.csproj --configfile agents/windows-agent/NuGet.Config
dotnet build agents/windows-agent/ServerGuard.Agent.csproj --configuration Release --no-restore
dotnet publish agents/windows-agent/ServerGuard.Agent.csproj --configuration Release --no-restore --self-contained false --output artifacts/windows-x64

$agentState = Join-Path $env:LOCALAPPDATA 'ServerGuard\Agent'
$agentTokenPath = Join-Path $env:LOCALAPPDATA 'ServerGuard\enrollment.token'
New-Item -ItemType Directory -Path (Split-Path $agentTokenPath) -Force | Out-Null
$agentTokenFile = [IO.File]::Open($agentTokenPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
$agentTokenFile.Dispose()
$agentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
icacls.exe $agentTokenPath /inheritance:r /grant:r "*$($agentIdentity):(F)"
if ($LASTEXITCODE -ne 0) { throw 'Token ACL setup failed' }
$agentToken = Read-Host 'Enrollment token' -AsSecureString
$tokenPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($agentToken)
try {
  [IO.File]::WriteAllText($agentTokenPath, [Runtime.InteropServices.Marshal]::PtrToStringBSTR($tokenPointer))
} finally {
  [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($tokenPointer)
}
Remove-Variable agentToken

.\artifacts\windows-x64\ServerGuard.Agent.exe --api https://control.example.com --server-id SERVER_UUID --token-file $agentTokenPath --state-dir $agentState --once
```

Use a fresh token path for this example. The state directory is created with inheritance disabled and access for the current identity, SYSTEM and Administrators. Existing state/token ACLs granting other identities access are rejected. Private keys are DPAPI CurrentUser ciphertext: preserve both the state directory and the same service identity on restart. Changing account or machine does not silently regenerate an identity.

The executable integrates with SCM as `ServerGuardAgent`. For a real service, use a dedicated low-privilege identity or LocalService and provision token/state ACLs for that exact identity, SYSTEM and Administrators. Perform initial enrollment under the service identity. A token readable only by an interactive administrator is not readable by LocalService; state enrolled interactively cannot be decrypted by a different service account. Service installation/recovery on Windows Server still needs VM testing. No SCM service was installed in this task.

Private CAs must be trusted in the appropriate Windows certificate store by the operator. There is no TLS-bypass flag. Both clients disable redirects to avoid forwarding enrollment tokens.

## Lifecycle and recovery

The first authenticated heartbeat produces ONLINE. Agents report every 30 seconds and back off with jitter for transient network, 5xx or 429 errors, up to five minutes. Other 4xx/configuration/replay rejection stops the process for operator attention. There is no automatic re-enrollment after revocation.

Health is computed from server receipt time: ONLINE up to 90 seconds; STALE from 90 seconds to five minutes; UNKNOWN after five minutes. Registration/enrollment alone does not establish liveness. Revoked/expired credentials and decommissioning take precedence over an old recent heartbeat.

Credentials expire after 30 days. For this prototype, issue a replacement token and start the agent with a **fresh private state directory/new key**. New token issuance revokes older tokens but retains the active signing key until replacement proof succeeds. Successful replacement enrollment atomically retires the old key and resets observed health. Reusing a previous key for a new enrollment is rejected. Never clone state, reset a sequence, or run two processes against one directory.

Tokens bind one key. Same-key retries can recover the same credential response until token expiry if the first response was lost; a different key cannot consume the token again. Token values are not retained by the agent's persisted state.

Revoke access invalidates all server credentials and outstanding tokens. Decommission also prevents future enrollment. Neither action uninstalls a host service or changes firewall rules. To uninstall, stop/remove the prototype using its host service manager and revoke its authority; preserve needed audit evidence before removing local state.

## Outputs and verification

Built packages are under `artifacts/linux-amd64/serverguard-agent` and `artifacts/windows-x64/ServerGuard.Agent.exe` with supporting files. Keep the Windows publish directory together. The Go SDK installed for this task is project-local under ignored `.runtime/tools/go`; it did not change global PATH.

Both clients support `--self-test` to emit a public, non-secret signing interoperability vector without starting a service. See [protocol](agent-protocol.md) and [Week 3 verification](week-3-checklist.md) for actual checks and unverified VM/service boundaries.
