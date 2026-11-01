# SSH/RDP detection, process alerts and notifications

## Delivered scope and coverage

**Alerts & notifications** provides real deterministic incident creation, bounded evidence, investigation/resolution, a delivered in-app inbox with personal read state, administrator detector settings and an observable durable notification outbox. These are not rollout simulations. No automatic firewall response, process termination, malware attestation or external notification is performed.

Detectors consume **new signed observations** accepted by `/api/agent/v1/events`. Both updated native prototypes support an opt-in private `--events-file` containing normalized JSONL; imported records join their existing durable signed outbox. Default agents still do not automatically tail security logs. Manual export/normalization/forwarding is implemented; persistent journal bookmarks/Windows subscriptions, audit-policy provisioning, full log rotation/reboot handling and collector health attestation remain future work. A healthy heartbeat or empty alert list does not establish detection coverage.

## Detection rules

Linux process audit/eBPF collection is not supplied. Linux process alerts require an upstream normalized PROCESS_START feed; the supplied native-log process normalizer targets Windows 4688 only.

| Rule | Conditions and meaning |
| --- | --- |
| SSH_FAILURE_BURST / RDP_FAILURE_BURST | Default five AUTH_FAILURE observations for the same tenant/host/service/source IP within five minutes. MEDIUM regardless of agent-supplied severity. Configurable threshold 3–50. |
| SSH_SUCCESS_AFTER_FAILURES / RDP_SUCCESS_AFTER_FAILURES | AUTH_SUCCESS from the same tenant/host/service/source IP after the failure threshold. HIGH. This is source-IP correlation, **not** proof the same account was compromised. |
| PROCESS_WATCHLIST | PROCESS_START basename matches the organization's case-normalized exact watchlist. MEDIUM, name-based indicator only. Defaults: `mimikatz`, `mimikatz.exe`; names can be spoofed or used legitimately. No file hash, signature, argument-based or behavioral malware verdict. |

Events must be recent: occurrence within five minutes past/60 seconds future and receipt within the five-minute correlation window. Older observations (up to the ingestion contract's 30 days) are stored but do not create fresh detections. Clock skew beyond the detector window can prevent alerts. Success records must be submitted chronologically after relevant failures; there is no historical/out-of-order success backfill. A disconnected host forwarding old logs may therefore have no real-time alert.

One incident per host/rule/correlation key has a five-minute cooldown, including after resolution. Same source-event ID retries never rerun detection; reused IDs with conflicting content roll back the entire batch. Source-IP IPv6 spelling normalizes. Cross-host, cross-service and cross-tenant events never combine. Evidence includes at most ten event IDs, source/host/process identifiers, threshold, count at detection (capped at 50), provenance `ENROLLED_AGENT_CLAIM` and an investigation caveat. A compromised enrolled agent can still fabricate observations; signatures prove enrollment identity, not OS integrity.

## Observation wire format

The existing SG1 signature, shared durable sequence, revocation, raw-body and 64 KiB batch limits still apply. Maximum 100 events per signed request. Additive kinds: AUTH_SUCCESS and PROCESS_START; AUTH_FAILURE with structured fields is now correlated. Historical AUTH_FAILURE records without service/source IP remain compatible and are not detected.

```json
{"sourceEventId":"journal:stable-unique-id","kind":"AUTH_FAILURE","severity":"INFO","occurredAt":"2026-10-29T12:00:00.000Z","payload":{"source":"linux-journal-sshd","service":"SSH","sourceIp":"192.0.2.5","account":"example-user"}}
```

AUTH_SUCCESS uses the same structured fields. Authentication requires service SSH/RDP and plain IPv4/IPv6 sourceIp. Account is optional, max 128. PROCESS_START requires `processName` (basename, max 120, ASCII letters/digits/underscore/dot/space/hyphen) and `processId` (**decimal string**, 1–4294967295); optional imagePath max 512 and parentProcessName max 120. Do not send command lines, passwords, tokens or raw security logs. Extra properties are rejected; free text is not automatically redacted.

```json
{"sourceEventId":"winsec:stable-unique-id","kind":"PROCESS_START","severity":"INFO","occurredAt":"2026-10-29T12:00:00.000Z","payload":{"source":"windows-security-4688","processName":"example.exe","processId":"291","imagePath":"C:\\Tools\\example.exe"}}
```

## Manual normalization and native forwarding

`scripts/normalize-observations.ts` reads UTF-8 JSONL from stdin and emits only normalized observations. It rejects malformed JSON or oversized input/output without partial stdout. Limits: 1 MiB input, 1000 input records, 90 normalized records, 32 KiB output. Unsupported records are ignored with counts on stderr; this is not evidence that every OS log variant was understood. Inspect the exit code before publishing a file. Keep export and normalized files private and remove raw exports under your data-retention policy.

### Linux SSH journal

Input: journal JSON containing `__CURSOR`, `__REALTIME_TIMESTAMP` (microseconds), `_COMM` of `sshd`/`sshd-session`, and MESSAGE. English OpenSSH failed/accepted password/publickey forms are recognized; other PAM/localized/authentication variants are not. Stable IDs hash the journal cursor; no command line/raw MESSAGE is forwarded. Access to the system journal must already be provisioned.

From the project root on an isolated Linux test host with Node/tsx available:

```sh
umask 077
journalctl -u ssh -u sshd --since '5 minutes ago' --no-pager -o json -n 90 > journal-export.jsonl
node node_modules/tsx/dist/cli.mjs scripts/normalize-observations.ts journal < journal-export.jsonl > events.next.jsonl
# Only after both commands succeed, inspect size/count, then publish atomically:
chmod 600 events.next.jsonl
mv events.next.jsonl events.jsonl
```

Add `--events-file /private/path/events.jsonl` to the enrolled agent's documented command/service configuration. File must be regular, mode 0600 and at most 32 KiB; use a private directory and same-filesystem atomic replacement. Do not put tokens in arguments. No journal unit name/format compatibility is claimed beyond parser fixtures; verify against the target distribution.

### Windows Security projection

Input is a JSON projection, **not raw EVTX/XML**:

```json
{"provider":"Microsoft-Windows-Security-Auditing","channel":"Security","computer":"test-win","recordId":"123","eventId":4625,"timeCreated":"2026-10-29T12:00:00.000Z","data":{"LogonType":"10","IpAddress":"192.0.2.5","TargetUserName":"example-user"}}
```

Only 4624/4625 with LogonType **10 (RemoteInteractive)** normalize as RDP success/failure. Type 3/NLA-only failures are deliberately not assumed to be RDP; this leaves an explicit coverage gap. Missing/unavailable source IP is ignored. For 4688, project `NewProcessName`, `NewProcessId` (hex or decimal) and optionally `ParentProcessName`. Stable IDs hash computer/channel/record ID/time/event ID, distinguishing log reset/reuse. Raw command lines and passwords are dropped by the normalizer.

An administrator-approved exporter may use Get-WinEvent on the Security log, read `.ToXml()` named EventData values, and project provider/channel/computer/record ID/event ID/UTC time/data in chronological order. Normalize with:

```powershell
Get-Content -LiteralPath .\security-projection.jsonl -Encoding utf8 |
  node node_modules/tsx/dist/cli.mjs scripts/normalize-observations.ts windows-security |
  Set-Content -LiteralPath .\events.next.jsonl -Encoding utf8
```

Check native exit status before atomic publication; protect the existing private parent directory/file ACLs to the service identity, SYSTEM and Administrators, then replace `events.jsonl` atomically. The normalizer and forwarders accept a UTF-8 BOM, but exports must not be UTF-16. Add `--events-file C:\private\events.jsonl` to the Windows prototype's documented arguments. The agent validates restrictive ACLs and rejects reparse points. Do not enable command-line auditing for this feature: it does not consume arguments. Security log access/audit policies must be separately reviewed; 4688 requires Process Creation auditing to already be enabled.

### Durable import behavior

Hardening update: imported batches must also be valid UTF-8 with distinct source IDs within the file. State and input reads are bounded; see [security/recovery](security-recovery.md) for limits and safe handling of corrupt or permanently rejected data.

At most 90 auth/process records per file, one JSON object per line. Both agents queue the complete bounded file and persist its SHA-256 receipt together with pending observations before sending. An unchanged file is not imported twice across restarts, and server source IDs deduplicate repeated exports. When old pending events occupy the 100-item outbox, a new file is deferred without recording its receipt until capacity is available; old events can drain first. In `--once` mode this can require another run.

This is a single manually managed batch file, **not a spool directory or automatic tailer**. Do not overwrite/remove a batch before import/delivery has been verified in the event stream; otherwise an unobserved file replacement can lose records. Delivery failures retain pending events and stable IDs. Malformed/permanently rejected observations require operator correction; no silent drop or command execution occurs. New file receipt is not a server acknowledgement. Native state remains private and must never be copied to expose its receipt/hash.

## Incidents, configuration and inbox APIs

All paths below are under `/api/organizations/:id`, with current membership, authenticated MFA, Origin/CSRF checks. All members can read and mark their own notifications read. Owner/Admin/Operator can change incident state; only Owner/Admin can change settings or inspect/retry relay failures.

| Method / path | Contract |
| --- | --- |
| GET /incidents | Optional state OPEN/INVESTIGATING/RESOLVED, severity, UUID cursor, limit 1–100 (default 30). `{items,nextCursor}`. |
| GET /incidents/:incidentId | Incident and bounded same-tenant/host referenced events. |
| PATCH /incidents/:incidentId | `{state,reason}`; reason 3–1000; appends audit and sets/clears resolved_at. |
| GET /security/settings | Effective configuration, 300-second window/cooldown, IN_APP channel and explicit collection-coverage limitation. |
| PATCH /security/settings | Full `{enabled,authFailureThreshold,processWatchlist,inAppNotifications}`. Watchlist <=32 distinct normalized basenames. Disabling detections leaves stored observations intact; re-enabling can correlate still-fresh stored failures. |
| GET /notifications | Optional unread true/false, UUID cursor, limit 1–100 (default 30). Only actually delivered IN_APP messages; personal unreadCount/read flag, no other users' read-by IDs. |
| PATCH /notifications/:notificationId/read | Strict empty object `{}`; idempotently marks only the authenticated member's receipt. |
| GET /security/deliveries | Latest 100 durable outbox statuses, retries/backoff/errors, no external-delivery claim. |
| POST /security/deliveries/:deliveryId/retry | Strict `{}`; only exhausted unpublished deliveries, audited administrative retry. |

## Notification delivery guarantees

Incident, evidence and `security.incident_created` outbox row commit in the same ingestion transaction. The five-second API relay creates a SENT IN_APP notification and publishes the outbox marker atomically. A crash/retry cannot duplicate the per-incident inbox message. SENT means the message exists in the organization inbox, **not** that a human read it or an email/webhook was delivered. Read state is per authenticated member.

Relay errors remain unpublished and unsent, use bounded exponential retry backoff, and stop after five attempts for operator attention. Errors contain generic codes, not raw logs/secrets. An exhausted delivery can be retried explicitly after correcting its cause. Current notification preferences are serialized with delivery; disabling in-app notifications suppresses still-pending deliveries and records DISABLED_BY_SETTINGS. Suppressed messages are not automatically replayed when re-enabled.

No email, SMS, browser push, webhook provider or external account is configured. No credentials are accepted in these APIs. User-requested external delivery needs a separate provider/integration, secure credential storage, egress/SSRF controls and delivery tests.

## Storage, acceptance and remaining work

Additive migration `202610290006_detections` adds incident identity/deduplication, correlation indexes, config, inbox payload/read state and relay retry metadata. Table count remains 24. Embedded mode migrates at startup; external PostgreSQL needs backed-up `node scripts/run.mjs db:deploy`. Existing retention cleanup is still not automatic; source IPs, usernames and executable paths are sensitive and need a reviewed retention/access policy.

API/dashboard TypeScript, Prisma and production build pass. Full security suite: **90 passing, no skips**, including parser fixtures, SSH/RDP/process rules, cooldown, batch rollback atomicity, tenant/RBAC/CSRF, per-user inbox state, relay failure/backoff/exhaustion/retry, and real Windows private-file forwarding through signed ingestion into an RDP incident. Go unit tests pass; Linux amd64 artifact/test binary cross-compile; updated framework-dependent Windows prototype publishes. Linux runtime/log collection, actual Security-log export/audit setup, continuous collector/bookmark correctness, UI interaction/accessibility, external delivery, capacity and independent review remain unverified.

References: [systemd journal fields](https://www.freedesktop.org/software/systemd/man/258/systemd.journal-fields.html), [Microsoft 4625 and LogonType 10](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625), [Microsoft Process Creation audit requirements](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-process-creation), [command-line audit privacy](https://github.com/MicrosoftDocs/windowsserverdocs/blob/main/WindowsServerDocs/identity/ad-ds/manage/component-updates/Command-line-process-auditing.md).
