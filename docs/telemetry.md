# Inventory, health and event ingestion

## Browser API

Paths below are under `/api/organizations/:id`; session, MFA, current tenant membership, Origin/CSRF rules apply. Reads allow all members; mutations require Owner/Admin and are audited.

| Method / path | Contract |
| --- | --- |
| GET /inventory | Optional `q` searches hostname/OS version/labels; `os`, `status`, `groupId`, UUID `cursor`, `limit` 1–100 (default 50). Returns `{items,nextCursor}`, newest creation first, including labels/groups, architecture/logical CPUs, latest active-credential measurements and derived health. |
| GET /groups | Up to 500 groups sorted by name. |
| POST /groups | `{name}`, unique per tenant. |
| PATCH /servers/:serverId/metadata | Full replacement `{labels,groupIds}`. Up to 16 labels (keys 1–32 alphanumeric/underscore/hyphen, string values up to 120 characters), 20 distinct same-tenant group IDs. |
| GET /servers/:serverId/metrics | `hours` 1, 24 (default), or 168. Returns `{windowHours,bucketSeconds,points}`. Receipt-time averages in 30-second, 10-minute or hourly buckets; includes historical credentials. |
| GET /events | Optional `serverId`, `kind`, `severity`, `hours` 1–720 (default 24), UUID `cursor`, `limit` 1–100 (default 50). Returns `{items,nextCursor}`, newest receipt first, with occurrence and receipt timestamps. |

Statuses: ONLINE, STALE, UNKNOWN, PENDING_ENROLLMENT, AWAITING_HEARTBEAT, REVOKED_OR_EXPIRED, DECOMMISSIONED. Receipt time and active credential state are authoritative.

## Heartbeat extension

Existing v1 agents remain compatible. Optional strict `inventory`: `{architecture,logicalCpuCount}`. Optional strict `metrics`:

```json
{"sampledAt":"2026-10-29T12:00:00.000Z","cpuPercent":23.5,"memoryTotalBytes":8589934592,"memoryUsedBytes":4294967296,"diskTotalBytes":107374182400,"diskUsedBytes":21474836480}
```

Each measurement may be null. Memory/disk total and used must be null together or safe integers, total > 0, 0 <= used <= total. CPU is 0–100. Sample time must be within ten minutes past/90 seconds future. Invalid data rolls back the heartbeat and sequence. Composite foreign keys bind samples to tenant/server/credential.

CPU is aggregate busy-time delta; first measurement may be unavailable. Linux reads `/proc/stat`, `/proc/meminfo` MemAvailable and root statfs available space. Windows uses GetSystemTimes (kernel includes idle), GlobalMemoryStatusEx and system-drive available space. Only root/system disk is measured, not every volume/container quota. OS/inventory are agent assertions, not independent attestation.

Health gives liveness/revocation precedence. Metrics older than 90 seconds are stale; missing values are never zero. CPU warning >=80%, memory/disk warning >=85%, critical >=95%. Server-derived HEALTH_THRESHOLD events occur on transitions including recovery, not repeated states. Missing data does not produce false recovery.

## Signed event batches

`POST /api/agent/v1/events` uses the SG1 P-256 transcript/headers in [agent-protocol](agent-protocol.md), signing this exact path. Maximum raw body: 64 KiB; other endpoints: 16 KiB. Enrollment, heartbeat and events bypass browser Origin matching but reject any Origin header and require agent authorization.

```json
{"schemaVersion":1,"serverId":"<UUID>","credentialId":"<UUID>","sequence":2,"events":[{"sourceEventId":"startup-unique-id","kind":"AGENT_STARTED","severity":"INFO","occurredAt":"2026-10-29T12:00:00.000Z","payload":{"source":"serverguard-agent","message":"Agent started"}}]}
```

Heartbeat/events share one durable strictly increasing safe-integer sequence; gaps are allowed. Batches contain 1–100 events, at most 30 days old/five minutes future. Source IDs are 1–128 alphanumeric/dot/underscore/colon/hyphen characters; `sg:` is server-reserved. Kinds: AGENT_STARTED, HEALTH_THRESHOLD, AUTH_FAILURE, FILE_CHANGE, SYSTEM_EVENT. Severities: INFO, LOW, MEDIUM, HIGH, CRITICAL.

Strict payload: required `source` (1–80), optional `message` (1–500), `code` (1–80), `metric` CPU/MEMORY/DISK, `level` NORMAL/WARNING/CRITICAL, `valuePercent` 0–100. HEALTH_THRESHOLD requires the three resource fields. Extra properties are rejected. Do not send credentials, raw logs or personal data; free-text fields are not automatically redacted.

Success: `{accepted:true,serverId,acceptedSequence,acceptedCount,duplicateCount}`. Same server/source ID and normalized content deduplicates; changed content returns 409 and rolls back the whole batch. Lost acknowledgements retry stable IDs with a NEW durable sequence/signature. Malformed, tampered, replayed or revoked requests cannot advance events/sequence. Event receipt never refreshes heartbeat liveness.

Native prototypes persist a bounded 100-event startup outbox before sending; clear only after accepted+duplicate count matches. They emit startup events, not OS authentication/file collectors. Full outbox/permanently rejected batches stop for operator attention rather than silently dropping data. Pending events older than 30 days need operator resolution. Resource transitions are calculated by the API; severity is not a detection verdict.

## Operations and limits

Migration `202610290004_telemetry` adds `metric_samples`, inventory columns, event hashes and tenant/time indexes: 24 domain tables. Embedded mode migrates at startup; external PostgreSQL needs `node scripts/run.mjs db:deploy` with intended DATABASE_URL and normal backup/change controls.

Read windows/admission age are bounded; automatic retention deletion is NOT implemented. Provision storage and archive/prune under an explicit policy. Group listing caps at 500; group pagination/rename/delete remain future work. Ingestion is transactional in the API, not a scalable asynchronous queue. Process-local rate limiting is not a distributed tenant quota. No detections, notifications, arbitrary commands or firewall mutations. Signed HTTPS messages are not mTLS or signed installers. Validate load/concurrency and isolated VM/service deployments before production.

Collector references: [Linux proc](https://www.kernel.org/doc/html/latest/filesystems/proc.html), [Microsoft GetSystemTimes](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getsystemtimes).
