# Week 3 — agent prototype delivery

Date: 2026-10-29. Scope: Linux/Windows agent prototypes, enrollment and heartbeats. Earlier identity/organization functionality is retained.

## Implemented

- [x] Go Linux agent using only standard-library dependencies.
- [x] .NET 10 Windows Worker with Windows Service integration.
- [x] Administrator registration/token issuance and tenant-isolated inventory API.
- [x] Ten-minute hashed enrollment tokens bound atomically to one P-256 identity.
- [x] Key proof, issuer role/disabled-account checks, expiry/revocation and same-key lost-response recovery.
- [x] Signed versioned heartbeat requests with exact-body/method/path binding and bounded timestamp skew.
- [x] Persisted increasing sequence counters, rejection of replay/out-of-order reports and server receipt timestamps.
- [x] Thirty-second outbound heartbeat loops, network timeout, bounded jittered backoff and fatal identity rejection handling.
- [x] Linux private key/state permissions, flushed atomic writes and exclusive flock.
- [x] Windows DPAPI CurrentUser key protection, private ACLs, flushed writes and exclusive process ownership.
- [x] HTTPS verification, redirect refusal and explicit literal-loopback-only HTTP development flags.
- [x] Credential replacement/revocation, token invalidation and server decommissioning.
- [x] Servers & agents dashboard: registration, token display once, credential lifecycle and ten-second status refresh.
- [x] ONLINE/STALE/UNKNOWN and pending/revoked/decommissioned states derived from actual reports and authority.
- [x] Additive PostgreSQL migration, protocol documentation, systemd template and platform CI job definitions.

## Verification evidence

| Check | Result |
| --- | --- |
| Full Node/API/native acceptance suite | **34 tests passed, 0 failed, 0 skipped**, with RUN_NATIVE_AGENT_TESTS=1. |
| Windows native runtime | Real .NET process enrolled against disposable local API, sent heartbeat sequence 1, restarted from protected state and sent sequence 2; later revocation made the next run fail. |
| Cross-language authentication | Go and .NET emitted the same signing transcript and DER signatures verified by the Node implementation. |
| Go tests on this Windows host | Three cross-platform tests passed: origin restrictions, exact signature binding/key roundtrip and redirect refusal. |
| Linux production executable | Go 1.27.3 cross-compiled Linux/amd64 with CGO disabled and trimpath. |
| Linux-specific tests | Linux flock/persisted-restart tests added and Linux test executable cross-compiled; not run on a Linux kernel here. Ubuntu CI job defined, not remotely executed. |
| Windows build/publication | .NET 10.0.401 Release build: 0 warnings, 0 errors. Framework-dependent Windows package published. |
| Schema | Prisma validation passed; all three SQL migrations applied transactionally in embedded PostgreSQL tests. |
| Web/API | TypeScript checks and optimized Next.js/API build passed. |

Tests cover tenant/RBAC denial, token hashing, OS/server/key binding, stolen/expired token rejection, issuer disable/demotion, competing enrollment, idempotent response recovery, body tampering, stale/future timestamps, replay/order, key replacement, expired/revoked credentials, decommissioning, liveness boundaries, and retained Weeks 1–2 security behavior.

## Outputs and commands

- Linux: `artifacts/linux-amd64/serverguard-agent`.
- Windows: `artifacts/windows-x64/ServerGuard.Agent.exe` and its supporting publication files.
- Setup: [agent guide](agent-guide.md).
- Wire contract: [SG1 protocol](agent-protocol.md).

```powershell
node scripts/run.mjs dev
```

Open `http://127.0.0.1:3100`, sign in and select **Servers & agents**. Registration requires Owner/Admin and MFA. Agents use a separate signed authentication path; browser cookies never authorize heartbeat reports.

Optional native acceptance run after building the Windows project and installing Go:

```powershell
$env:RUN_NATIVE_AGENT_TESTS='1'
$env:GO_BINARY='go'
node scripts/run.mjs test
```

Without the flag, normal tests intentionally skip the two native-dependent checks rather than requiring Go/.NET on every frontend developer machine. This workspace used its ignored project-local Go SDK. Native Windows test data lives under ignored `.runtime/native-agent-tests` with private token files and DPAPI-protected synthetic state; it is not customer data.

## Explicit remaining gates

No firewall mutation, privileged helper, job execution, detection, AI, CA/CSR issuance/mTLS, automatic credential renewal or signed production installer is implemented. Thirty-day identity replacement is administrator-assisted. The systemd template and SCM support have not been installed on real servers. Linux runtime/systemd, Windows Server/SCM deployment, service identity/ACL provisioning, remote TLS ingress, external PostgreSQL concurrency, distributed rate limits, production key lifecycle and signed upgrades require separate validation.

An ONLINE report proves a recent authenticated claim from an enrolled key; it does not independently establish host integrity. Cross-compilation does not prove Linux execution. No host firewall, global PATH, Windows service or public deployment was changed by this task.
