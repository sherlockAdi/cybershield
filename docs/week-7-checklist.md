# Week 7 status — approval and simulation rollout prototype

## Implemented

- Real, single-use, checksum-bound approval/rejection by a current MFA-enabled Owner/Admin distinct from requester and policy author; expiry and authority rechecks.
- Frozen targets, explicitly selected canaries, bounded batches, explicit promotion, pause/resume and safe cancellation.
- Persisted simulation apply/inspect/rollback jobs, stable keys, pre-mutation previous-state snapshot and immutable confirmation deadline.
- Separate APPLIED/VERIFIED evidence; explicit SIMULATION scope, no native attestation or real observed-health mutation.
- Offline pending/UNKNOWN states, stage timeout, reconnect without automatic resume, retained watchdog on pause and recovery after reconciler recreation.
- Rollback with snapshot/hash checks, offline timeout and explicit ROLLBACK_FAILED; no overwrite of a superseding sandbox version.
- Transactional append-only audit, rollout UI with scenario injection, additive fifth migration (24 domain tables remain).

## Validation

- TypeScript/API/dashboard checks and Prisma schema validation pass.
- API/Next.js production build passes.
- Full security suite with native agent tests enabled: 75 passing, zero skipped. Existing native Windows enrollment/telemetry/restart and Go/.NET signing checks remain passing.
- Focused rollout acceptance: 13 passing, including late canary-stage deadline rejection after final safety tightening. One Windows V8 test-process crash was transient; rerun passed without a code workaround.

## Not complete

This is not native firewall rollout execution. No Linux/Windows firewall is modified, no native job transport/leases or signed cross-language execution payloads exist, and no independent host-local watchdog/expiration/recovery is claimed. Native-state inspection, verification, real traffic/coexistence, canary observation windows, production rollback/console drills, external PostgreSQL load tests and browser interaction QA remain release gates. Read [rollout semantics and limitations](rollouts.md) before using the simulator.
