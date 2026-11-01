# Threat model — Weeks 1 and 2

Baseline: 2026-10-29. Owner: project maintainer. Revisit before agent enrollment, firewall execution, provider egress and public deployment. This is a design review and implementation risk register, not a penetration-test certificate.

## Assets and trust boundaries

Protect administrative identities, organization membership, session/refresh tokens, MFA seeds and recovery codes, agent identities and CA keys, approved policies, server availability, event confidentiality and audit history.

Boundaries: browser to Next.js; same-origin proxy to NestJS; API to tenant-scoped storage; worker to Redis and PostgreSQL; outbound agent to mTLS ingress; unprivileged agent transport to privileged native helper; incident projection to optional AI provider. A browser, another tenant, an enrolled endpoint and log contents are all untrusted input sources. Database owners and host administrators are privileged adversaries outside normal application enforcement.

## Threat register

| ID | Threat / impact | Controls and status | Required evidence |
| --- | --- | --- | --- |
| T01 | Password theft, brute force, session theft | Implemented: Argon2id, minimum 12-character passwords, TOTP MFA gate, hashed opaque tokens, HttpOnly cookies, bounded local rate limits. Production requires Secure cookies and HTTPS. | Authentication, MFA gate, invalid credentials and disabled-user tests; deploy ingress rate limits before exposure. |
| T02 | Cross-site request forgery | Implemented: exact configured Origin check for every mutation; session-bound hashed CSRF credential for authenticated writes; SameSite Strict cookies. | Wrong Origin and wrong CSRF rejected through HTTP. |
| T03 | Tenant ID substitution / data disclosure | Implemented: active membership check on every tenant API read/write; roles fetched from DB each request; composite tenant FKs. | Foreign-tenant 404 and mismatched server/group FK tests. RLS not enabled. |
| T04 | Privilege escalation / loss of last owner | Implemented: server-side role matrix, owner-only ownership changes, organization row lock around membership writes, last-owner rejection. | Viewer/admin bypass and last-owner tests. Add multi-process concurrency/load tests before pilot. |
| T05 | Invitation theft, replay or stale privileges | Implemented: random single-use hashed tokens, exact email binding, 48-hour expiry, revocation, issuer privilege recheck at acceptance. | Wrong recipient, replay, expiration, revocation and demoted-issuer tests. No email transport configured. |
| T06 | Refresh-token replay | Implemented: hashed refresh families, transactional rotation, absolute expiration, consumed-token reuse revokes whole family. | Rotate/replay and revoked-session tests. Concurrent legitimate refreshes require client serialization. |
| T07 | MFA seed exposure / code replay | Implemented: AES-256-GCM seed storage, one-use hashed recovery codes, monotonic accepted TOTP steps, row lock during verification. Development key is an ignored local file. | Encryption tamper, TOTP reference vector, recovery reuse tests. Managed KMS and key rotation remain deployment work. |
| T08 | Audit tampering | Implemented: mutation and audit insert share DB transaction; UPDATE/DELETE trigger rejects changes. | DB mutation rejection tests. A DB owner can disable triggers or TRUNCATE: off-host immutable archival and non-owner roles required before production. |
| T09 | Enrollment impersonation / malicious agent | Week 3 implements hashed one-key tokens, P-256 proof, issuer reauthorization, server/tenant/OS binding, expiry/revocation and strict bounded bodies. HTTPS is required remotely. mTLS/CA issuance is not implemented. | Signed enrollment, replay/key theft, issuer demotion/disable and revocation tests; see Week 3 status. |
| T10 | Forged/stale job or arbitrary command execution | Designed only: signed job, expiry/hash/version, persisted idempotency key, allowlisted native helper operations. | Week 3/7 malicious-job and privilege-separation tests. No remote shell endpoint permitted. |
| T11 | Firewall lockout, unsafe default policy, outage | Designed only: native capability checks, management safeguards, canaries, local durable watchdog, previous-state rollback. | Week 5–9 disposable VM enforcement, reconnect, reboot and recovery tests. |
| T12 | Queue loss, duplicate jobs, partial rollout | Designed/schema only: PostgreSQL outbox, leases, retries and explicit per-target states. | Week 7 queue-loss/idempotency tests. Redis is not required by Week 2 runtime. |
| T13 | SQL injection / stored XSS | Implemented: parameterized SQL, strict bounded Zod input, React text escaping, no arbitrary HTML rendering. | Malformed/extra-field tests and UI review. Add production CSP suited to Next.js before external deployment. |
| T14 | AI prompt injection / data exfiltration | Designed only: opt-in redacted incident projection, no execution credentials, output treated as untrusted. | P2 redaction and adversarial log tests before any provider is connected. |
| T15 | Supply-chain compromise / unsigned agents | Dependency versions locked; explicit installation-script allowlist. Agent signing, SBOM, license review and release provenance are later release gates. | Dependency review and signed agent update/uninstall tests before agents reach customers. |
| T16 | Resource exhaustion, noisy tenant | Implemented: 16KB JSON bodies, bounded list responses and process-local write limits. Distributed quotas, pagination, event limits and durable auth failure tracking remain deployment work. | HTTP size/rate checks; load tests before shared deployment. |
| T17 | Backup theft, key loss, data loss | Development persistence exists; no tested backup automation. Backup the local key and DB together using encrypted storage. Production needs separate DB credentials, encrypted off-host backup and restore drill. | Restore test measuring RPO/RTO before pilot. |

## Failure and recovery policy

Week 3 adds persisted heartbeat sequence checks and bounded timestamp skew; raw-body/method/path signatures prevent payload substitution. Health uses API receipt time, not agent-provided time. Keys remain in private Linux state or DPAPI CurrentUser-protected Windows state. Same-key enrollment-response recovery does not grant another key or extend expiry. Local development HTTP is explicit and restricted to literal loopback IPs; it is never a remote deployment option. A compromised endpoint can still sign false metadata, so liveness does not establish host integrity. Linux/systemd and Windows Server/SCM acceptance remain unverified here.

Unauthorized, ambiguous or unsupported operations fail closed before mutation. Control-plane failure must not remove existing native firewall protection. Unknown deployment results remain UNKNOWN, never silently successful. A user losing their authenticator can use an unused recovery code. If both are lost, there is no insecure self-service bypass; an identity-verified administrative recovery process must be designed before commercial rollout.

## Residual risks and deployment gate

This release binds both servers to loopback and is for local development. The default embedded database is single-process. Local MFA key files need host ACL review on Windows; POSIX file-mode arguments alone do not enforce Windows ACLs. Process-local rate limits are shared behind the development proxy and reset on restart. Email verification, password reset/change, MFA reset, distributed lockout protection, managed secrets, audit archival, non-owner DB roles and a hosted TLS deployment remain future hardening tasks. Do not treat completion of Weeks 1–2 as completion of the commercial product.
# Weeks 5–6 firewall boundary

Week 9 adds [bounded-input agent hardening and recovery tests](security-recovery.md), including Linux no-follow/nonblocking private descriptors, state size/counter validation, acknowledgement bounds and real Windows commit-with-lost-response recovery. These reduce malformed-input/data-loss risks, but do not constitute independent review, native firewall recovery or protection against a compromised local administrator.

Week 8 adds [signed-observation detectors and IN_APP notifications](detections.md): tenant/host/source-bound correlation, fixed detector severity, bounded evidence, cooldown/deduplication, atomic incident/outbox creation, restart-safe relay, personal read state and role-audited triage/settings. Native event-file forwarding is opt-in and private; it does not attest log provenance. Missing/stale logs, unsupported RDP/NLA forms and name-only process indicators are explicit coverage limits. No automatic remediation or external destination/credential is accepted.

Week 7: [rollout safeguards](rollouts.md) add distinct requester/author/approver enforcement, authority rechecks, frozen checksums, simulation-only DB constraint, canary/batch gates, idempotency and deadline persistence, explicit UNKNOWN/ROLLBACK_FAILED states and audit. This is not a native watchdog or host attestation: no simulated evidence can authorize actual firewall execution.

Strict network/port/expiry validation, tenant/RBAC checks, optimistic checksums, frozen target snapshots, database-protected seals, append-only audits and compile-only native plans now mitigate authoring risks. Management-port BLOCK and outbound BLOCK submissions fail closed without verified recovery. All plans remain UNVERIFIED/nonexecutable: native ownership/GPO/coexistence, custom management ports/protected networks, cross-language job hashing, approval, watchdog, rollback and native reachability are still execution gates. Packet previews cover one selected version only, never host attestation. See [firewall API](firewall-api.md) for evidence and limits.

