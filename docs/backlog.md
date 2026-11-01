# Delivery backlog

## Weeks 1–2 delivered scope

Requirements and RBAC matrix; architecture/decision records; 23-table PostgreSQL/Prisma schema and migrations; threat model; local monorepo and Git initialization; Next.js dashboard; NestJS API; Argon2id authentication; mandatory TOTP onboarding and recovery codes; rotating/revocable sessions; tenant-scoped organizations; member roles; invitations; audit trail; embedded local persistence; external PostgreSQL connection option; acceptance checks. See [status](week-1-checklist.md) for execution evidence.

## Next milestones

| Week | Work and exit criterion |
| --- | --- |
| 3 | Prototype implemented: independently buildable Go/.NET agents, signed one-key enrollment, heartbeats, revocation and replay tests. CSR/certificate issuance/mTLS, signed installers and VM/service deployment remain hardening gates; see Week 3 status. |
| 4 | Prototype implemented: searchable inventory, labels/groups, native metrics/history, derived health and bounded signed/idempotent event ingestion. See Week 4 status; isolated Linux/Windows VM service acceptance remains outstanding. |
| 5–6 | Authoring/validation APIs, compile-only native adapters, single-version previews/diffs, sealing and audit history implemented. Effective host inspection, native execution/coexistence and real-traffic VM verification remain outstanding; see firewall-api.md. |
| 7 | Real distinct-administrator approval and durable simulation-only canary/verification/rollback/offline state machine implemented. Native executor queue, independent host watchdog/expiration, signed execution jobs and VM enforcement/recovery remain outstanding; see rollouts.md. |
| 8 | Deterministic signed-event SSH/RDP/process detections, incident triage, normalized export adapters, native opt-in event-file forwarding and durable IN_APP delivery implemented. Continuous OS collectors, audit-policy rollout and external providers remain outstanding; see detections.md. |
| 9 | Security/recovery suite extended with real lost-ack and corrupt Windows state, bounded private-file/state/response hardening, mixed rollback failures, Go fuzzing and CI checks. Linux VM/native recovery, capacity measurements, backup/upgrade drills and independent review remain outstanding; see security-recovery.md. |
| 10 | Unsigned allowlisted pilot bundles, checksum verification, encrypted staged backup/isolated restore tooling and synthetic DB/MFA-key drill, deployment preflight/templates and pilot checklist implemented. Release signing, actual external deployment/restore, native install/uninstall validation and real pilot sign-off remain outstanding. |
| P2 | Opt-in read-only AI summaries after deterministic pipeline is reliable. |
| P3 | SSO, compliance exports, configurable retention and enterprise integrations. |

## Decisions requiring pilot input

Confirm proposed Linux/Windows builds and native firewall coexistence; hosted versus self-hosted packaging; protected management networks and console recovery; target ingestion volume and retention; notification provider; key management and certificate authority; licensing and commercial terms. These do not prevent local Weeks 1–2 implementation but must be resolved before their dependent deployment/features.

## Week 2 hardening follow-ups

Verified email and mail delivery, password change/reset, MFA reset policy, distributed rate limiting, account-specific lockout telemetry, multi-tab refresh coordination, paginated member/audit history, production CSP, accessibility audit, managed KMS, role-separated DB provisioning and external database concurrency/load verification. No automatic production-readiness claim is made.
