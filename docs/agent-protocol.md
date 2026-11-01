# SG1 agent protocol — v1 prototype

Week 8 adds AUTH_SUCCESS/PROCESS_START and structured authentication/process payloads to signed event batches; see [detections](detections.md). These retain exact-body signatures, one shared durable sequence and source-ID idempotency. Agent-reported severity is not trusted as detector severity, and observations are not OS attestation.

Week 4 additions: [telemetry](telemetry.md) specifies optional heartbeat measurements/inventory and signed `/api/agent/v1/events` batches. Heartbeat/events now share one durable sequence. The events endpoint also rejects Origin headers and requires agent signatures; the original two-path description below is the historical Week 3 baseline.

Per-agent P-256 ECDSA signatures authenticate JSON requests over HTTPS. This is application-level proof of the enrolled key, not mTLS or certificate issuance. Native agents never send browser cookies, Origin or CSRF credentials. No private key enters the control plane.

## Signature envelope

Endpoints: `POST /api/agent/v1/enroll` and `POST /api/agent/v1/heartbeat`. Strict schema version 1, 16KB body limit.

| Header | Format |
| --- | --- |
| X-SG-Timestamp | Ten-digit Unix UTC seconds, within 90 seconds of API time. Synchronize host clocks. |
| X-SG-Nonce | Random 16 bytes encoded as unpadded base64url (current clients: 22 characters). |
| X-SG-Signature | Standard base64 of ECDSA SHA-256 signature in RFC 3279 ASN.1 DER sequence format. |

Sign UTF-8 bytes with LF separators and no trailing LF:

```text
SG1
POST
/api/agent/v1/heartbeat
<timestamp>
<nonce>
<lowercase hex SHA-256 of exact transmitted JSON bytes>
```

Use the enrollment endpoint when enrolling. Do not reserialize/canonicalize JSON after signing or rewrite the path/body in a proxy. Queries are rejected. Body/target/timestamp/nonce changes invalidate the signature. Nonces randomize requests, while the persisted increasing sequence is the authoritative heartbeat replay control; the server does not retain an unbounded nonce cache.

## Enrollment body

Fields: `schemaVersion: 1`, `serverId` UUID, private `token`, `publicKey` P-256 SPKI PEM, `hostname`, `os` (LINUX/WINDOWS), `osVersion`, `agentVersion`. Unknown properties are rejected. The OS must match registration.

Verify signature proof with the submitted public key, then authorize the hashed token, server/tenant binding, expiry/revocation and current issuing user's Owner/Admin role. A transaction consumes the token into one credential; unique SHA-256 SPKI fingerprints prevent key reuse. Same-key retry can recover the same public credential response before token expiry; different-key reuse cannot rotate or create a second identity. Issuer demotion/removal also invalidates unconsumed authority.

Success: `credentialId`, `serverId`, `expiresAt`, `heartbeatIntervalSeconds: 30`. No heartbeat time is set by enrollment. New-key re-enrollment retires previous credentials atomically and clears old observed health. The server stores public keys/fingerprints and token hashes only, never plaintext tokens or private keys.

## Heartbeat body

Fields: `schemaVersion: 1`, `serverId`, `credentialId`, `sequence`, `hostname`, `os`, `osVersion`, `agentVersion`, `uptimeSeconds`. Sequence is a positive safe JSON integer, starts at 1 and must strictly exceed the credential's last accepted value; gaps are allowed. Uptime is a nonnegative safe integer. A changed OS, credential/server mismatch, untrusted signature, revoked/expired key or decommissioned host is rejected.

Agents flush the next sequence to local durable storage before sending. Lost responses and crashes do not justify resetting/replaying it. Server/credential locks serialize accepted reports with replacement/revocation; only the bound server can be updated. Success: `accepted: true`, `serverId`, `acceptedSequence`, database receipt `receivedAt`, `heartbeatIntervalSeconds`, `credentialExpiresAt`. Failed reports never advance sequence or health.

401 rejects identity/signature/timestamp; 409 rejects duplicate/out-of-order sequence; 400 rejects malformed/extra fields. No jobs, arbitrary commands or caller-defined capabilities are accepted. Server capabilities are fixed to heartbeat=true, firewall=false, execution=false. An authenticated report is a host claim, not independent integrity attestation.

## Browser administrator endpoints

These keep session, MFA, Origin and CSRF enforcement:

| Method / path under `/api` | Access/result |
| --- | --- |
| GET /organizations/:id/servers | Any member; latest 500 inventory records and derived status, without keys/tokens. |
| POST /organizations/:id/servers | Owner/Admin; `{hostname, os}`, returns ten-minute enrollment token once. |
| POST /organizations/:id/servers/:serverId/enrollment | Owner/Admin; replace outstanding tokens, retain active key until successful replacement. |
| POST /organizations/:id/servers/:serverId/revoke | Owner/Admin; revoke all server credentials and tokens. |
| POST /organizations/:id/servers/:serverId/decommission | Owner/Admin; revoke authority and prevent future enrollment. |

Only the two exact agent paths bypass browser Origin matching, and they reject any Origin header instead. A browser session cannot substitute for an agent signature. Local initial-enrollment limit: 20 per IP/15 minutes; separate heartbeat limit: 4000 per IP/minute. These process-local limits are not a production distributed quota system.

## References

- [Go ECDSA](https://go.dev/pkg/crypto/ecdsa/)
- [.NET ECDSA SignData](https://learn.microsoft.com/en-gb/dotnet/api/system.security.cryptography.ecdsa.signdata?view=net-10.0)
- [.NET DER signature format](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.dsasignatureformat?view=net-10.0)
