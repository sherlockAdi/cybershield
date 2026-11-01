# Approvals, canaries, verification, rollback and offline handling

## Delivered boundary

Approval decisions are real, tenant-scoped, audited authorization. Rollout execution is **SIMULATION ONLY**: a transactional database sandbox represents each host's managed state. No native firewall commands run, no execution jobs are delivered to agents, no real desired/observed checksum is updated, and simulated reachability is never host attestation. LIVE mode is rejected by the API and a database constraint.

The dashboard exposes **Approvals & rollouts**. Start in Firewall policies: seal a version, select 1–3 canaries from its frozen target snapshot and request a simulation rollout. Another current Owner/Admin, distinct from both requester and policy author, must approve. A single-administrator organization needs a second administrator; there is no self-approval bypass.

## API

Prefix: `/api/organizations/:id/rollouts`. All endpoints retain authenticated MFA, tenant membership, browser Origin and CSRF rules. Any member may read; Owner/Admin is required for mutations.

| Method / path | Contract |
| --- | --- |
| GET / | Cursor/limit (1–100, default 30), newest first; `{items,nextCursor,liveExecutionEnabled:false}`. |
| POST / | `{mode:"SIMULATION",versionId,expectedChecksum,canaryServerIds,batchSize,canaryTimeoutSeconds,reason}`. Batch 1–10 (default 2), stage timeout 30–600 seconds (default 300), 1–3 distinct snapshot canaries, reason 3–1000 characters. Returns deployment ID and PENDING_APPROVAL. |
| GET /:deploymentId | Deployment, approval, up to 100 snapshot targets, up to 400 sandbox jobs, latest 100 audit entries; `verificationScope:SIMULATION_ONLY_NOT_HOST_ATTESTATION`. |
| POST /:deploymentId/decision | `{decision:"APPROVE"|"REJECT",expectedChecksum,reason}`. Single-use, distinct actor, expires after 24h. |
| POST /:deploymentId/actions | `{action:"PAUSE"|"RESUME"|"PROMOTE"|"ROLLBACK"|"CANCEL",reason}` with state-machine enforcement. |
| PATCH /:deploymentId/targets/:targetId/scenario | `{online:boolean,failureMode:"NONE"|"APPLY"|"VERIFY"|"ROLLBACK",reason}`. Explicit, audited sandbox fault injection; does not change actual agent liveness. |

There is no browser `verified:true` endpoint, LIVE switch, remote shell or agent job-claim endpoint. 400 rejects invalid requests, 403 denies role/self-approval/CSRF, 404 hides foreign resources, 409 rejects stale hashes/invalid transitions/uncertain targets. Existing 16 KiB body and process-local write limits remain unchanged.

## Approval and rollout lifecycle

1. Request references a sealed PENDING_APPROVAL/APPROVED version and checksum. Group membership is not expanded again: targets come from the sealed snapshot, must exist in the tenant and not be decommissioned. Temporary rules require ten minutes remaining at request time.
2. An independent administrator approves or rejects the exact checksum. Requester and policy author must still be active MFA-enabled administrators. Approval changes version state to APPROVED and deployment to QUEUED; rejection cancels targets. Expired pending approvals are reconciled to EXPIRED/CANCELLED, never executed.
3. The five-second API-process reconciler moves QUEUED -> CANARY only when no other active/uncertain rollout owns a target. Competing queued rollouts do not deadlock one another. Targets are server-ID ordered; only configured canaries dispatch first, within the batch bound.
4. Dispatch persists a previous sandbox-state snapshot, immutable idempotency key, 60-second dispatch deadline and 120-second confirmation/watchdog deadline **before** the next transaction performs simulated application. Separate APPLY_POLICY and INSPECT_POLICY records distinguish APPLIED from VERIFIED.
5. Simulated verification requires connected scenario state, expected sandbox checksum and simulated management/control-plane reachability. It stores mode, observed checksum, receipt time and `hostAttestation:false`. Success confirms the exact target/checksum and clears its watchdog. Failure pauses rollout; unapplied targets do not fan out.
6. All canaries VERIFIED does not auto-promote. A current administrator explicitly PROMOTEs to ROLLING_OUT. Further batches preserve the in-flight limit. Only all targets VERIFIED produces simulation SUCCEEDED.
7. Every active reconciliation rechecks requester/approver/author authority, approved checksum/state, target decommissioning and rule-expiry proximity. Invalid authority, unavailable targets or rules within two minutes of expiration pause dispatch. Pause does not cancel already persisted watchdogs.

Approval is authorization for this sandbox deployment, not native execution or blanket authority for later versions. Other members cannot spoof an actor, checksum or evidence state. Policy content stays protected by existing database sealing triggers.

## Offline, restart and recovery semantics

- Disconnected before dispatch: target stays PENDING with no fabricated result. Stage timeout pauses; reconnect alone does not resume a paused deployment. RESUME is explicit and may require PROMOTE again.
- Disconnected after dispatch: dispatch expiry produces UNKNOWN and pauses fan-out. It never becomes VERIFIED on stale connectivity. There is no automatic replay/reset of an expired apply key.
- Disconnected after simulated application, before confirmation: persisted watchdog remains. Reconciliation restores previous sandbox state after its deadline, even while the scenario is disconnected or deployment paused. Recreating the reconciler does not reset the deadline. A failed target cannot resume in place; rollback is required.
- The simulator's watchdog is **not an independent native host watchdog**. If the API is down, no sandbox work executes; catch-up occurs after service recovery using persisted timestamps. Native offline expiration and autonomous reboot-safe host rollback remain unimplemented.
- API startup resumes reconciliation from PostgreSQL/PGlite. Every job key is stable per target/operation, and target-state advancement, sandbox mutation, job result and audit are transactional. There is no network lease/Redis delivery claim; these are local transactional sandbox jobs, not a production multi-host executor queue.
- Worker shutdown waits for in-progress work before DB close. Per-deployment failures retain state and do not stop reconciliation of other deployments. Multiple API instances serialize using organization/deployment row locks; external PostgreSQL concurrency/load tests remain a deployment gate.

## Rollback and cancellation

ROLLBACK enters ROLLING_BACK and creates stable rollback jobs for applied targets; unapplied targets cancel. The simulator restores only when current sandbox state equals this deployment's hash or the retained prior hash. A different/newer state is never overwritten: it records ROLLBACK_FAILED. Active overlapping rollouts block an older rollback request.

Confirmed rollback requires the connected scenario; offline work stays ROLLING_BACK until its five-minute job expiry, then ROLLBACK_FAILED. An unconfirmed watchdog may still restore the sandbox before that expiry. Rollout does not become terminal while other rollback targets remain unsettled. Once all settle, all restored/cancelled -> ROLLED_BACK; any failed restore -> FAILED with explicit target evidence. Snapshots and audit are retained. Failed rollback requires manual sandbox diagnosis; the API does not silently reset deadlines or pretend retry succeeded.

CANCEL stops work only before any target applied. It expires pending sandbox jobs and cancels targets. Cancellation cannot undo application, replace rollback, or imply live rules were reverted. Pause/resume, promotion, decisions, scenario injection, watchdogs, verification and rollback transitions are append-only audited.

## Database and limitations

Migration `202610290005_rollouts` adds simulation-only mode/config/deadlines, target confirmation/evidence/scenarios, dedicated `servers.simulation_firewall_state` and worker/job indexes. Domain table count remains 24. Embedded startup applies migrations; external PostgreSQL needs the normal backed-up `node scripts/run.mjs db:deploy` process. Real `observed_checksum`/agent health remain untouched.

Live native executor adapters, trusted host inspection/GPO/firewalld coexistence, signed cross-language execution jobs, agent leases, native verification/reachability, canary observation windows, durable host-local watchdog/expiration, encrypted real-native snapshots, backup/restore, recovery-console evidence and isolated VM traffic/rollback drills are **not complete**. Simulation also does not model per-rule expiration after a completed rollout or arbitrary real external firewall state. No native-service, real firewall mutation or browser-interaction acceptance is claimed.

See `tests/security/rollouts.test.ts`: distinct approval/author rules, tenant/RBAC/CSRF, expiry, canary gate and batches, verification failure, pre/post-dispatch disconnection, recreated reconciler/watchdog, offline rollback failure, superseded-state protection, changed authority, competing deployments, stable jobs and append-only audits.
