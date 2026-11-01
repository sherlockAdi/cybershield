# Private pilot onboarding and sign-off

## Pilot record (complete before inviting users)

| Field | Operator entry |
| --- | --- |
| Pilot name / owner / security reviewer | Required |
| Approved purpose, scope and end date | Required |
| Release version and trusted manifest hash | Required |
| HTTPS origin, VPN CIDR, DB/software versions | Required; no secrets here |
| Backup owner, key escrow location and restore evidence | Required; no key material here |
| Named primary and independent approving administrator | Required; no shared account |
| Linux/Windows isolated hosts and console-recovery owner | Required |
| Accepted gaps / go-no-go decision / signatures | Required |

## Prerequisites and stop conditions

- Verify the unsigned release through an independently trusted manifest hash. Accept unsigned development code explicitly or wait for release signing. Review license/dependency provenance; no commercial-product license is selected by the project.
- Restrict ingress to approved private pilot clients, verify TLS and keep API/dashboard loopback-only. Close registration after controlled first-owner bootstrap. No default accounts/passwords are shipped.
- Complete a backup and isolated restore with matching MFA key. Verify runtime DB role isolation, schema version, private file ownership, time synchronization and generic operational logging.
- Scope this as inventory, signed observations/detections, in-app delivery and **simulation-only** firewall rollout. Real native enforcement, autonomous watchdog, continuous OS-log collection, external notifications and production SLA are not available.
- Stop onboarding on cross-tenant exposure, MFA/key failure, unexpected public registration, invalid signature acceptance, duplicate/lost evidence, unexplained state corruption or failed restore. Preserve private diagnostics and revoke affected credentials; do not weaken checks to continue.

## Administrator onboarding

1. The nominated first owner registers only during the reviewed private bootstrap window, enables TOTP and stores recovery codes in an approved vault. Disable registration and verify an unauthenticated new registration is rejected before handover.
2. Invite the second administrator by the intended email/role. They join, enable MFA and use a separate account/device. Verify a Viewer cannot invite, change detection settings or approve; an Operator may triage incidents but not administer settings.
3. Create a second test organization/account and verify foreign inventory, events, incidents, notifications, policies and rollout IDs are inaccessible. Capture sanitized pass/fail evidence, not cookies or tokens.
4. Confirm invitations expire/revoke as expected and removed users lose access with existing sessions. Test recovery codes on a disposable test account and revoke unused sessions.

## Host onboarding

1. Use an isolated VM with console access and approved OS/runtime. Check the native artifact hash, permissions and required .NET runtime for Windows. Service installation and runtime compatibility still need this pilot's actual host evidence.
2. Register the host in the intended organization and securely supply the ten-minute enrollment token in a protected file. Follow agent-installation.md; never place the token/private key in arguments, release folders, tickets or logs.
3. Verify signed enrollment/heartbeat, correct OS/hostname/architecture, resource availability and stale/revoked states. Revoke a test credential and verify subsequent reports fail. Test fresh-key re-enrollment without resetting a counter under the old credential.
4. For detection coverage, explicitly configure and review the manual bounded normalized auth/process event feed. Verify one benign synthetic SSH/RDP failure burst and process-watchlist observation create exactly the intended incident. No real brute-force attempt, malware execution, audit-policy alteration or process kill is required.
5. Confirm unsupported NLA/type-3 RDP and nonrecognized log variants are understood as gaps. Empty alerts are not proof of host safety. Review username/source-IP/path privacy and retention before forwarding actual logs.

## Workflow acceptance

- In-app notifications appear once, personal reads do not mark other members' messages read, and failed relay work is visible/retryable. Record that email/SMS/webhook delivery is not configured.
- Create a harmless policy preview; inspect BLOCK precedence, expiry, protected management-port rejection, target snapshots and sealed audit history. No native firewall mutation should occur.
- Request a simulation rollout, deny self-approval, approve from the independent administrator, verify only canaries progress and explicitly promote. Exercise sandbox disconnect, verification failure, rollback failure and recovery using the documented scenario controls. Never call this native reachability or real firewall rollback.
- Review service restart behavior, DB/storage capacity and backup retention with operators. Do not extrapolate local test throughput into a production capacity claim.

## Handover / offboarding

Record every acceptance result, accepted limitation, owner and evidence location. Agree incident response, maintenance access, backup/restore drill cadence, retention and go/no-go criteria. No accounts or services were actually onboarded by generating this checklist.

At pilot end, revoke pilot memberships/invitations/sessions and agent credentials, stop/uninstall test services through the approved procedure, remove plaintext log exports/staging under retention policy and retain encrypted backups/audit evidence only as authorized. Do not delete shared host firewall objects or assume simulation cancellation uninstalled agents. Expand scope only after closing native deployment, signing, continuous collection, external delivery, backup and independent-review gates.
