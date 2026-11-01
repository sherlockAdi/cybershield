# Product requirements — baseline 2026-10-29

## Outcome and scope

An administrator enrolls a Linux server and a Windows Server, previews a bounded IP rule, obtains required approval, deploys it through a canary, verifies native enforcement, and can recover safely. Server inventory and all resulting decisions are visible in one tenant-scoped dashboard.

Pilot assumption: one region, 100 enrolled servers per organization, 10 organizations, up to 10 normalized events/second/server sustained. These are design targets requiring load tests, not measured capabilities. Product owner approval of this baseline and pilot customer feedback remain external acceptance steps.

## Actors and permissions

| Capability | Owner | Administrator | Operator | Viewer |
| --- | --- | --- | --- | --- |
| Read inventory, policies, events, audit | Yes | Yes | Yes | Yes |
| Draft rules and preview | Yes | Yes | Yes | No |
| Submit deployment request | Yes | Yes | Yes | No |
| Approve another person's deployment | Yes | Yes | No | No |
| Enroll, revoke or decommission servers | Yes | Yes | No | No |
| Manage memberships except owners | Yes | Yes | No | No |
| Change ownership or delete organization | Yes | No | No | No |

All permissions are organization-specific; membership in one tenant grants nothing in another. The requester cannot approve their own deployment. Last-owner removal is rejected transactionally. All MVP firewall changes require a second Owner/Administrator; pilots therefore require two distinct accounts. Later low-risk auto-approval needs a separate reviewed design.

## Functional acceptance criteria

| ID | Priority | Requirement and observable acceptance |
| --- | --- | --- |
| AUTH-01 | P0 | Login uses hashed passwords, MFA for privileged accounts, short sessions and revocable rotating refresh credentials; disabled users cannot authenticate. |
| AUTH-02 | P0 | Every tenant resource read/write validates active membership and role; cross-tenant IDs return a non-disclosing 404. |
| INV-01 | P0 | Inventory displays hostname, OS/version, agent version, last heartbeat, labels and applied policy version. |
| AGT-01 | P0 | A single-use enrollment token expires after 10 minutes, is hashed at rest, binds one server and is consumed atomically. |
| AGT-02 | P0 | Agents use outbound HTTPS/mTLS, heartbeat every 30 seconds, become stale after 90 seconds, and unknown after 5 minutes. |
| FW-01 | P0 | Reject malformed IPv4/IPv6/CIDR, unsupported protocols, incompatible ports and ambiguous targets before persistence. |
| FW-02 | P0 | Preview returns effective managed policy, conflicts, management-access impact, capabilities, target snapshot and checksum. |
| FW-03 | P0 | Approval binds an immutable policy version and target checksum; any edit requires a new preview and approval. |
| FW-04 | P0 | Canary verification precedes batches of at most five servers; failures pause the rollout and remain visible. |
| FW-05 | P0 | A server is VERIFIED only after its authenticated native-state report matches the desired checksum and connectivity checks pass. |
| FW-06 | P0 | Agent-local rollback timer restores the last known good managed policy without needing control-plane connectivity. |
| FW-07 | P0 | Temporary rules expire on the agent even while disconnected; reconnect reconciles desired and observed state. |
| AUD-01 | P0 | Actor, tenant, request ID, target, action, policy version, decision, timestamp and result are recorded without secrets. |
| EVT-01 | P1 | Normalize SSH/RDP login failures, deduplicate source events, and trigger deterministic testable thresholds. |
| FIM-01 | P1 | Baseline explicitly selected files and report changes; exclude contents and private keys from payloads. |
| NOT-01 | P1 | Email/webhook delivery retries are bounded, observable and idempotent. |
| AI-01 | P2 | Explain redacted structured incidents; no execution permissions, auto-approval or unsupervised firewall action. |
| ENT-01 | P3 | SSO, compliance exports, custom retention and advanced integrations follow the pilot. |

## Nonfunctional requirements

| Area | Initial target and verification |
| --- | --- |
| API latency | p95 below 500 ms for inventory and policy reads at pilot scale; exclude asynchronous deployments. Measure under load. |
| Availability | Pilot objective 99.5% control-plane monthly availability; no SLA until production design and measurement. |
| Safe outage | Existing native rules remain enforced during control-plane loss; no automatic blanket allow or deny. |
| Transport | TLS 1.2+; public ingress terminated separately from authenticated agent ingress. |
| Storage | UTC timestamptz, UUID identifiers, composite tenant FKs, no plaintext reusable credentials. |
| Retention | Events 30 days; audit 365 days; job/result metadata 90 days after terminal state; pilot defaults subject to customer policy. |
| Recovery | Proposed RPO 24 hours, RTO 4 hours; daily encrypted backups and a restore drill before pilot. |
| Accessibility | Keyboard navigation, labeled controls, textual state indicators and responsive dashboard. |
| Observability | Structured redacted logs, request/job correlation, heartbeat lag, queue delay, rollout failure and rollback metrics. |

## Supported first adapter targets

Ubuntu Server 24.04 LTS with nftables and Windows Server 2022 with Windows Defender Firewall are proposed pilot targets. Validate exact builds, privileges, coexistence and recovery in isolated VMs before claiming support. firewalld-managed hosts require a distinct adapter; never bypass firewalld using direct nftables writes. Existing domain/GPO-managed Windows rules must be detected and respected. Other distributions and Windows versions are not automatically supported.

## Exclusions

No arbitrary remote terminal, antivirus replacement, autonomous AI remediation, kernel driver, vulnerability exploit testing, guaranteed compliance certification, Kubernetes orchestration, high availability deployment, or commercial billing implementation in the MVP. Vulnerability scanning and network anomaly analysis require additional specifications.

## Release gate

Week 3 prototype qualification: per-agent identity is currently implemented as signed P-256 requests over server-verified HTTPS, not CA-issued mTLS. The original production certificate lifecycle remains a separate gate (ADR-007). Enrollment/heartbeat/authority controls are implemented; privileged firewall/job behavior is not implied. See [agent status](week-3-checklist.md).

AUTH-01 through AUD-01 must pass integration and isolated-VM security acceptance tests on both pilot operating systems. No lockout recovery, signed upgrade, or rollback test may be waived merely to meet the 10-week schedule. See [backlog](backlog.md) for sequencing and [threat model](threat-model.md) for residual risks.
