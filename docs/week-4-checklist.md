# Week 4 prototype acceptance

## Implemented

- Search/filter/paginated inventory, architecture/logical CPUs, tenant labels/groups, audited administrator metadata changes.
- Native CPU, memory and root/system disk collectors; nullable measurements, receipt-time health and historical charts (1h/24h/7d).
- Resource-state transitions/recovery, signed event batches, shared durable replay sequence, stable-ID deduplication and conflict rollback.
- Persistent bounded agent startup outboxes; tenant event explorer with severity/kind/time filters and pagination.
- Additive fourth migration, validated 24-table Prisma schema and [telemetry contract/limitations](telemetry.md).

## Executed validation

- `node scripts/run.mjs check`: API/dashboard TypeScript and Prisma pass.
- `node scripts/run.mjs build`: API and Next.js production build pass.
- `RUN_NATIVE_AGENT_TESTS=1 node scripts/run.mjs test`: 46 pass, zero skips. Includes validation/history, health transitions, batch limits, tampering/replay, duplicate/conflict atomicity, pagination, RBAC/tenant isolation, real Windows metrics/startup/restart and Go/.NET signature interoperability.
- Go unit tests pass on Windows; Linux amd64 binary and test binary cross-compile. Updated framework-dependent Windows artifact publishes successfully.

## Not claimed

No Linux runtime/isolated VM execution, Windows Service installation, browser interaction/accessibility test, external PostgreSQL load test or automatic retention deletion. No per-volume monitoring, OS authentication/file collectors, detections, notifications, event-worker queue, production TLS/mTLS or signed installers. Artifacts remain unsigned development prototypes; both native services need isolated VM acceptance.
