# Observability backlog

The local API exposes `/api/health`. Add OpenTelemetry and redacted structured request logs, auth-denial counters, DB/queue latency, heartbeat lag, job age, canary failure and rollback metrics before shared pilot deployment. Do not log bearer tokens, MFA seeds, recovery codes, raw passwords or full security-event payloads.
