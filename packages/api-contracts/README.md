# API contracts

The user HTTP surface is described in [API specification](../../docs/api-specification.md). The independent Go/.NET clients implement [SG1 v1](../../docs/agent-protocol.md); strict enrollment/heartbeat schemas are enforced in `apps/api/src/agents.ts`. Public interoperability vectors from both native clients are verified against the Node implementation in the security suite. No published package or future job-execution compatibility is claimed.
# Week 4 contract supplement

The executable telemetry validators are `apps/api/src/telemetry-model.ts` and `apps/api/src/telemetry.ts`; [telemetry documentation](../../docs/telemetry.md) specifies request/response fields, limits, replay and compatibility. Both native agents implement these contracts; security acceptance lives in `tests/security/telemetry.test.ts`.

