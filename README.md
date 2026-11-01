# ServerGuard AI

Security control plane for Linux and Windows Server. The first release focuses on inventory and safe, auditable firewall policy deployment; detection and AI follow later.

## Status

Weeks 1–2 provide the identity/organization dashboard and database foundation. Week 3 adds Go Linux and .NET Windows agent prototypes, signed one-key enrollment, heartbeats, revocation and a Servers & agents dashboard. Local data persists in embedded PostgreSQL; external PostgreSQL and Prisma migrations are also provided. Firewall enforcement, jobs, detection and AI remain later milestones. See [Week 3 status](docs/week-3-checklist.md), [agent setup](docs/agent-installation.md) and the historical [Weeks 1–2 status](docs/week-1-checklist.md).

## Read first

Week 10 adds allowlisted unsigned pilot packaging with SHA-256 verification, authenticated encrypted staged backups/new-destination restore, production environment preflight, private Linux deployment templates and a pilot sign-off checklist. See [release/deployment](docs/release-deployment.md), [backups](docs/backups.md) and [pilot onboarding](docs/pilot-onboarding.md). No public deployment, real-user onboarding or live-data backup was performed.

Week 9 adds bounded private agent reads/state writes, stricter acknowledgement handling, corrupt-state and lost-response recovery tests, mixed rollback failure coverage, Go fuzzing and CI hardening. See [security/recovery evidence and operator runbook](docs/security-recovery.md). Independent review, Linux VM/native-enforcement recovery, load and backup/restore drills remain release gates.

Week 8 adds **Alerts & notifications**: SSH/RDP failure and success-after-failure indicators, configurable process-name alerts, incident triage and real durable in-app notification delivery. Both prototypes accept opt-in private normalized event files. Automatic OS-log tailing and external email/webhook delivery are not enabled. See [detection setup, APIs and coverage limits](docs/detections.md).

Week 7 adds **Approvals & rollouts**: real distinct-administrator approval, plus explicitly simulation-only canary batches, verification evidence, rollback, persistent watchdog deadlines and disconnected/restart scenarios. No host firewall execution is enabled. See [rollout API, safeguards and native-execution gaps](docs/rollouts.md).

Weeks 5–6 now provide firewall policy APIs, strict IPv4/IPv6 validation, optimistic drafts/revisions, native-plan preview adapters (nftables/Windows NetSecurity), packet simulation, semantic diffs, sealed submission and per-policy audit history. Open **Firewall policies** in the dashboard. [API, evidence and enforcement limitations](docs/firewall-api.md): native execution/live application remain disabled pending approval, inspection and rollback safeguards.

Week 4 adds searchable, cursor-paginated inventory with labels/groups, native CPU/memory/system-disk metrics, historical charts, signed idempotent event ingestion and a Security events explorer. See [Week 4 status](docs/week-4-checklist.md) and [telemetry contract](docs/telemetry.md). These remain development prototypes.

1. [Requirements and acceptance criteria](docs/requirements.md)
2. [Architecture and decisions](docs/architecture.md)
3. [Database design](docs/database-design.md)
4. [Threat model](docs/threat-model.md)
5. [Firewall policy semantics](docs/firewall-policy.md)
6. [API and agent contracts](docs/api-specification.md)
7. [Development setup](docs/development.md)
8. [Delivery backlog](docs/backlog.md)

## Repository layout

| Path | Responsibility |
| --- | --- |
| `apps/dashboard` | Next.js UI; never connects directly to managed servers |
| `apps/api` | NestJS authentication, authorization, inventory and control API |
| `agents/linux-agent` | Go enrollment/heartbeat prototype and systemd template; firewall adapter is future work |
| `agents/windows-agent` | .NET enrollment/heartbeat Worker with Windows Service integration; firewall adapter is future work |
| `packages/api-contracts` | Versioned API and agent message schemas |
| `packages/policy-models` | Shared policy vocabulary and validation contract |
| `services/event-processor` | Event normalization and deterministic detection |
| `services/ai-analysis` | Read-only explanations with redacted event input |
| `infrastructure/database` | Prisma schema, migrations and DB documentation |
| `infrastructure/containers` | Local PostgreSQL and Redis Compose services |
| `infrastructure/reverse-proxy` | Future TLS/mTLS ingress configuration |
| `infrastructure/monitoring` | Future OpenTelemetry and metrics configuration |
| `tests/integration`, `tests/security`, `tests/end-to-end` | Future behavior and release acceptance tests |

## Quick start

Prerequisites: Node.js 22 or 24 and pnpm 11.25.0. Docker is optional for external PostgreSQL/Redis. These are development targets, not a compatibility claim for agent operating systems.

```powershell
pnpm install --frozen-lockfile
node scripts/run.mjs check
node scripts/run.mjs test
node scripts/run.mjs dev
```

Open `http://127.0.0.1:3100`. Create an account, enable MFA and save recovery codes; no default credentials are provided. Leave `DATABASE_URL` unset for embedded mode. `.env` and `.runtime` are ignored. The dashboard/API bind only to loopback. Follow [development.md](docs/development.md) for external database setup and production prerequisites.

## Contribution rules

Changes require organization authorization, explicit input validation, safe failure behavior, and an audit trail where relevant. Do not introduce arbitrary remote shell execution. Run `pnpm check` and relevant behavior tests before review. Do not commit secrets, real event payloads, or private keys. No product license is selected yet; see [licensing](docs/licensing.md).
