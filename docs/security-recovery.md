# Security tests, failure simulation, recovery and agent hardening

## Implemented hardening

- Both agents bound serialized state to 128 KiB, preserve the last durable file when serialization exceeds that limit, reject corrupt/missing identity/replay fields and refuse oversized/null event outboxes. They never repair corruption by silently generating a new identity or resetting the counter.
- Linux token/state/event inputs share a bounded private-regular-file reader. It checks mode, size and inode identity; native Linux opens use O_NOFOLLOW, O_NONBLOCK and O_CLOEXEC, rejecting symlinks/FIFOs rather than blocking or following a replacement. Read limits remain enforced on the descriptor, not just a pre-open length check. Limits: token 1 KiB, event file 32 KiB, state 128 KiB.
- Windows private readers retain restrictive ACL/reparse checks and bound reads as data arrives. State is atomically replaced only after bounded serialization and flush. This does not claim to defeat a malicious local Administrator/SYSTEM or every Windows reparse-point race; keep the service-owned parent directory private.
- Event-file imports reject invalid UTF-8 and duplicate source IDs within the incoming batch before modifying pending events or its receipt hash. Capacity deferral preserves old pending data and does not acknowledge an unimported file. Malformed replacement input cannot partially mutate the in-memory durable outbox.
- Go control-plane responses are now fully bounded at 16 KiB and reject trailing JSON, including a valid JSON prefix followed by oversized padding. Windows already bounded streamed responses. Both reject negative/out-of-range event acknowledgement counts before clearing pending observations.
- Existing HTTPS/TLS verification, no redirects, P-256 exact-body/path signatures, private Linux state, Windows CurrentUser DPAPI, exclusive state lock, pre-send durable sequence and post-ack outbox clearing remain in force. No remote shell, native firewall execution or agent download/update channel was added.

## Failure and recovery matrix

| Fault | Expected behavior / tested evidence |
| --- | --- |
| Malformed/oversized control-plane JSON | Go rejects the whole response, not just an acceptable prefix; no successful acknowledgement is inferred. |
| Full pending outbox / changed event file | New input defers; old events/receipt remain intact until capacity is available. |
| Malformed event replacement / invalid UTF-8 | Import fails atomically; prior pending IDs and input receipt remain unchanged. |
| Corrupt, oversized, missing-counter, negative-counter, null-outbox or bad-key Windows state | Native process exits unsuccessfully, leaves the corrupt file unchanged and does not issue a replacement credential. Restore the known-good current file in the isolated fixture: original credential/counter resumes. |
| Server commits events but event acknowledgement connection is destroyed | Real Windows agent exits with pending events retained. Restart advances the persisted sequence and retries stable source IDs; already committed events/incidents do not duplicate. Pending data clears only after a valid count-bound acknowledgement. |
| Mixed rollback: one simulated restore fails, another target is offline | Rollout remains ROLLING_BACK while recovery is unsettled; reconnecting target restores. Final deployment remains FAILED because the other target failed. No false all-success or abandoned unsettled target. |
| Approval demotion/expiry, tampering/replay, conflicting event ID, cross-tenant access | Existing acceptance checks continue to deny authority, pause dispatch or roll back the transaction as appropriate. |
| Reconciler recreation / confirmation timeout | Existing simulation-only watchdog deadlines remain persisted and are not reset; expired unconfirmed sandbox state restores or records explicit failure. This is not an independent native watchdog. |
| Notification relay fault | Existing durable outbox backs off, exhausts and remains unsent until explicit administrative retry; personal inbox reads cannot impersonate another user. |

## Safe operational recovery

1. Stop the affected agent/service using normal service management. Do not repeatedly restart against corrupt input or relax file permissions to force startup. Preserve the failed state and relevant normalized batch in a private, access-controlled quarantine; they may contain a private key or personal data. Never upload them into a ticket/chat/log.
2. Record the server ID, software version, last known public credential ID, generic error category and whether events were committed/acknowledged. Do not record tokens/private key material. Check time synchronization, network/TLS, free space and service-account file/DPAPI access. DPAPI recovery requires the intended Windows identity/profile, not simply copying files to another account.
3. For a transient network/lost-ack fault, retain the **current** state file and pending events, correct connectivity and restart. Stable IDs and monotonic sequences allow idempotent delivery. Verify receipt in the event stream, not just a successful heartbeat. Observations older than the detector's freshness window may be stored without a fresh alert.
4. For malformed optional event input, stop the producer, validate a corrected bounded normalized batch and publish it atomically with the documented private permissions. Do not discard already pending observations or invent new IDs for the same log records. A permanently rejected pending batch requires deliberate operator diagnosis; no automated poison-record deletion is supplied.
5. Never restore an arbitrarily old state snapshot under an active credential: its counter may be behind the server. Never edit Sequence to zero, delete only the key/counter or copy a token into arguments. If authoritative current state/key cannot be recovered, an Owner/Admin should revoke the old credential and issue a new short-lived enrollment token, then enroll a fresh private state directory. Verify the replacement identity and revoke/delete the token securely under the installation guide.
6. For simulation rollback failure, preserve the retained previous state and audit, diagnose the sandbox mismatch/offline target, and resolve competing rollouts before proceeding. The API intentionally refuses silent rollback retries after failure. No production-native rules were changed, and the simulator's recovery cannot prove real host reachability.

This is an operator runbook, not an executed encrypted backup/restore or disaster-recovery drill. Production recovery needs reviewed backups, independent console access, tested native snapshots/watchdogs, external PostgreSQL restore/concurrency tests and measured RPO/RTO.

## Validation commands and CI

```powershell
node scripts/run.mjs check
$env:RUN_NATIVE_AGENT_TESTS='1'
node scripts/run.mjs test
node scripts/run.mjs build
```

Native prerequisites and private runtime/cache setup are in development/agent guides. Go checks from the agent directory:

```sh
go vet ./...
go test ./...
go test -run '^$' -fuzz FuzzEventFileImportIsAtomic -fuzztime=5s -parallel=2
```

GitHub CI now includes Linux vet and a bounded 10-second event-import fuzz step in addition to Linux runtime tests and Windows native acceptance. These workflow changes are configured, not evidence that a remote CI run has executed.

## Local evidence and remaining gates

- API/dashboard TypeScript and Prisma checks pass; production build passes.
- Full acceptance suite: 91 checks, including native regressions; corrupt-state and mixed rollback cases included. The final native lost-ack test also verifies no duplicate event/incident after actual process restart.
- Go unit tests/vet pass on Windows; a configured five-second fuzz campaign completed 29,020 executions without failure. Linux-only private-file/corrupt-state checks are supplied and cross-compiled, not executed on this Windows host.
- .NET Release compilation succeeds with no warnings/errors; updated framework-dependent Windows and Linux amd64 development artifacts are built. They remain unsigned prototypes.

No independent penetration test, Linux VM runtime test, native firewall mutation/recovery, power-loss/disk-full drill, Windows Service deployment, race-detector campaign, capacity benchmark, external notification test, continuous collector validation, encrypted backup restore or release signing is claimed. Do not equate this milestone with production readiness.
