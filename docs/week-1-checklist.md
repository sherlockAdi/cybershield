# Weeks 1–2 delivery status

Historical milestone snapshot. The latest agent work is documented in [Week 3 status](week-3-checklist.md).

Date: 2026-10-29. Project root: `D:\Neural\rkskpeereducator12-03\rkskpeereducator.in\cybersecurity`.

## Week 1

- [x] Product requirements, scope, priorities, roles, acceptance criteria and nonfunctional targets.
- [x] Architecture, trust boundaries, technology decisions and future component ownership.
- [x] Local Git repository initialized; no commits, new named branches, remote or push performed.
- [x] pnpm workspace, pinned dependency lockfile, ignored runtime/secrets and development commands.
- [x] PostgreSQL/Prisma schema covering 23 domain tables, enums, indexes and tenant-aware foreign keys.
- [x] Initial SQL migration plus checks, actor FKs, audit immutability and sealed-policy protection.
- [x] Threat model, residual risk register, recovery principles and deployment gates.
- [x] Development PostgreSQL/Redis Compose configuration and no-Docker embedded PostgreSQL option.
- [x] API specification, policy semantics, future agent/incident guidance and delivery backlog.

## Week 2

- [x] Next.js/React/TypeScript dashboard with responsive navigation and real database-backed counts.
- [x] NestJS API with strict input validation and sanitized failures.
- [x] Account registration/login, Argon2id password hashes and normalized email uniqueness.
- [x] Mandatory TOTP MFA onboarding, encrypted seeds, replay resistance and one-use recovery codes.
- [x] HttpOnly access/refresh cookies, session-bound CSRF and exact Origin checks.
- [x] Short-lived access and rotating refresh families with reuse revocation and absolute lifetime.
- [x] Organization creation, switching, renaming and current membership authorization on every request.
- [x] Owner/Admin/Operator/Viewer roles; owner-only ownership changes and last-owner protection.
- [x] Email-bound, expiring invitations with revocation, one-time acceptance and issuer reauthorization.
- [x] Administrative audit history protected against ordinary UPDATE/DELETE.
- [x] Own-session visibility/revocation, logout and disabled-user enforcement.
- [x] Persistent embedded PostgreSQL runtime and external PostgreSQL adapter.
- [x] CI workflow definition for checks, tests and builds.

## Verification evidence

| Check | Result |
| --- | --- |
| API and dashboard TypeScript checks | Passed. |
| Prisma schema validation | Passed with Prisma 6.19.0. |
| Prisma client generation | Passed. |
| Security/integration suite | 20 tests passed, 0 failed, fresh in-memory embedded PostgreSQL. |
| Migration execution | Both migrations applied transactionally by the acceptance suite and the persistent local API. |
| Production compilation | API and Next.js optimized build passed; rerun after later source changes. |
| Local HTTP | Dashboard returned 200; `/api/health` reported `ok`, `week-2`, `embedded-postgresql`. |
| Browser check | Onboarding rendered in the local in-app browser at its available viewport. Full authenticated browser and device-matrix regression are not claimed. |
| External PostgreSQL / Compose | Configuration supplied; not executed because Docker/PostgreSQL CLI are not installed here. |
| Hosted CI / public deployment | Workflow supplied; not run on a remote provider. No public deployment. |

Tests cover tenant read/write isolation, mandatory MFA, CSRF/Origin enforcement, privilege injection, Viewer/Admin restrictions, ownership races, invitation replay/expiration/revocation/stale issuer, immediate membership removal, audit mutation rejection, cross-tenant foreign keys, sealed policy integrity, refresh-family replay, recovery-code reuse, logout and disabled accounts. TOTP uses a published RFC test vector; encrypted-secret tampering is rejected.

## Remaining boundaries

No agent enrollment, live server monitoring, native firewall mutation, approval worker, threat detection, notification delivery or AI service is implemented; those remain Weeks 3 onward. Password reset/change, verified email, managed key rotation, production ingress/quotas, role-separated external DB provisioning and backup/restore validation remain hardening work. Requirements contain proposed performance/recovery targets, not benchmark results or an SLA.

Local readiness does not constitute commercial-production security certification. Product owner/pilot acceptance is still an external review step. Start the working application using `node scripts/run.mjs dev`; see [development](development.md).
