# Firewall policy contract v1

Implementation status: [Weeks 5–6 firewall APIs and preview adapters](firewall-api.md). Authoring, validation, single-version simulation, native-plan compilation, target snapshots, sealing and audit history are implemented. Native executor adapters, effective host inspection, approval decisions, deployment and watchdog/rollback remain future work. The execution/state-machine requirements below are safety gates, not claims of completed live enforcement.

## Input

Each rule has a UUID, organization, ALLOW/BLOCK action, INBOUND/OUTBOUND direction, canonical IPv4/IPv6 CIDR, TCP/UDP/ICMP protocol, optional inclusive port range, optional UTC expiration and required human reason. TCP/UDP require ports 1..65535; ICMP prohibits ports. IPv4 without a prefix becomes /32 and IPv6 /128. Reject hostnames, zone identifiers, mapped IPv6 ambiguities and noncanonical network addresses until explicit canonicalization tests exist.

One policy version contains one explicit server or one server group target. Submission snapshots group membership into deployment targets; later membership changes do not modify an approved rollout. First-release scope excludes automatic organization-wide targeting, custom protocol numbers and default host firewall changes.

## Effective policy and precedence

Within ServerGuard-managed rules, BLOCK wins when two active rules match the same packet. No broad ALLOW overrides a more specific BLOCK. Expired rules do not participate. Preserve existing OS policies and expose external conflicts; an ALLOW means allowance within the managed rules, not a promise to override a host/GPO deny. Preview must reject a requested effect the adapter cannot guarantee. Protect SSH/RDP ingress and agent control-plane egress using adapter-specific safeguards validated before applying a plan; do not assume a generic allow rule overrides an external deny.

First-release Linux adapter operates only in dedicated nftables objects after inspecting base-chain priorities and coexistence. A firewalld owner requires a firewalld adapter, not direct nftables modification. Windows uses a dedicated rule group and inspects effective policy, including domain policy. If precedence or local-rule application cannot be established, return UNSUPPORTED with no mutation.

## High-impact classification

All MVP deployments need a distinct approver. Additionally label as high-impact: IPv4 prefix shorter than /24, IPv6 shorter than /64, any outbound rule, all-port equivalents, a rule touching protected source networks or management ports, and target groups exceeding five servers. High-impact management-access changes are rejected in MVP unless they preserve an independently verified recovery path. A reason alone is not a recovery path.

## State machines

Policy versions: DRAFT -> PENDING_APPROVAL -> APPROVED -> SUPERSEDED. Submission seals rules, target definition and canonical checksum; rejected requests return a new draft version rather than mutating the sealed record. Approved content remains immutable.

Deployment: PENDING_APPROVAL -> QUEUED -> CANARY -> ROLLING_OUT -> SUCCEEDED. CANARY/ROLLING_OUT can transition to PAUSED or FAILED. A rollback request enters ROLLING_BACK and ends ROLLED_BACK or FAILED. Cancellation stops undispatched targets; it never implies already applied changes have been reverted.

Target: PENDING -> DISPATCHED -> APPLIED -> VERIFIED. Errors lead to FAILED, UNKNOWN or ROLLING_BACK. APPLIED means the adapter mutation completed; only native-state verification plus reachability evidence allows VERIFIED. Record desired version separately from observed version. Stale/offline targets cannot be VERIFIED. An expired watchdog produces ROLLED_BACK or ROLLBACK_FAILED, both audited.

## Agent execution and watchdog

1. Validate certificate identity, signed job payload, organization/server binding, job expiration, version/hash, operation allowlist and persisted deduplication key.
2. Capture the last known good managed native state and persist a rollback deadline before mutation. Defaults: 120 seconds pending confirmation; timer must survive agent restart.
3. Apply atomically where supported. Never flush unrelated rules or invoke user-provided shell content.
4. Inspect native state and perform bounded connectivity checks. Send the signed/hash-bound result with native policy checksum.
5. Receive an explicit authenticated confirmation for the exact job/version only after verification. Cancel the watchdog only then. No confirmation means local rollback at the deadline, even if control plane reports success elsewhere.
6. Persist expiration timers locally; expire temporary rules while offline. Reconcile elapsed expiration and interrupted jobs on startup before polling new work.

Job retries reuse the same idempotency key and cannot reset a rollback deadline indefinitely. An older desired version cannot overwrite a newer version except an explicit authorized rollback job referencing a retained snapshot. Hash canonicalization is UTF-8 RFC 8785 JSON followed by SHA-256; all SDKs must pass shared vectors before agent delivery.

## Acceptance scenarios

Test IPv4/IPv6 malformed and boundary prefixes; TCP/UDP/ICMP combinations; overlapping allow/block; expired rules; tenant mismatch; unsupported GPO/firewalld state; protected SSH/RDP; duplicate/stale jobs; certificate revocation; canary timeout; partial batches; disconnect before/after mutation; agent restart before watchdog; expiration during outage; rollback failure and emergency console recovery. Real enforcement tests require disposable Linux and Windows VMs.
