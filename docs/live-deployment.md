# CyberShield360 live deployment — 30 October 2026

## Scope and endpoints

Deployed to the user-supplied Ubuntu server at `200.234.45.166`, using a dedicated `cybershield360` Docker Compose project, PostgreSQL 17 volume/network, non-root application container and dedicated Nginx virtual hosts. Existing unrelated projects/configurations were not replaced. No host firewall rules were changed.

- Dashboard: `https://cybershield360.vvvitsolutions.online`
- API health: `https://api.cybershield360.vvvitsolutions.online/api/health`
- Signed-agent API aliases: `https://agent1.cybershield360.vvvitsolutions.online` and `https://agent2.cybershield360.vvvitsolutions.online` (health at `/api/health`). Non-agent paths on these aliases return 404.

All four DNS names resolve to the same supplied host. They do not represent two separately managed machines. One real Linux host, `srv1955495`, is registered and enrolled; no duplicate/fictitious second host was created.

## Security and state

Owner handover update: the initial default sign-in identifier described below was replaced with the operator-supplied owner email. The password, organization, ownership and MFA configuration were preserved, old sessions revoked and the change audited. Read the current private admin-access JSON for the current login identifier; do not use the historical default after this update.

Certificates cover all four names; HTTP redirects to HTTPS. A certificate-specific renewal hook validates/reloads Nginx. Public registration stays disabled. Initial owner sign-in ID defaults to `admin@cybershield360.vvvitsolutions.online`; this is an application identifier, not a provisioned email mailbox. Its random password is stored only in `/opt/cybershield360/private/bootstrap/admin-access.json` on the server, mode 0600. First login must complete TOTP onboarding before protected inventory/workspace access. No MFA secret/recovery code was generated or exposed on the user's behalf.

The SSH password supplied in chat is not stored in source/configuration. Rotate it through an approved procedure after confirming access; SSH hardening/account-password rotation was not performed automatically on this shared host.

Runtime DB credentials and the MFA encryption key were generated on-host into `/opt/cybershield360/private/production.env`, mode 0600, never printed. Runtime/migration/bootstrap database roles are separate; PostgreSQL has no published host port. App ports 13100/14100 are published only on host loopback; inside Docker the explicit bind-host settings allow container networking. Default local development binds remain loopback. Docker image includes OpenSSL/CA runtime dependencies and was built on-host.

Deployment root: `/opt/cybershield360`. Baseline pilot bundle was verified before extraction. Two source files (`apps/api/src/main.ts`, `scripts/run.mjs`) were updated with the container bind option; the original baseline manifest therefore describes the original bundle, not those deployed patches. Current infrastructure/production files and this deployment record document the changes; do not present the patched deployment as an untouched or signed original release.

## Registered host agent

`cybershield360-agent.service` runs as a dedicated non-login, unprivileged system user with private state at `/var/lib/cybershield360-agent`. It uses `agent1` as its pinned HTTPS API origin. Enrollment, signed heartbeats and event acknowledgements were observed, with actual host architecture/resource samples. State/private key are not copied into the deployment source bundle. Do not expose state, enrollment tokens or database environment files in diagnostics.

Native firewall execution remains disabled; rollout verification/rollback is simulation-only. The operator approved SSH login and network/ICMP metadata collection on this host; see [server activity](server-activity.md) for coverage and limitations. Process feeds remain opt-in/manual and external email/webhook delivery remains unconfigured. Making the service reachable does not close these product limitations or constitute an independent security review.

## Backup and operator commands

An initial PostgreSQL custom-format dump and the matching private deployment environment were staged and encrypted on-host into `/opt/cybershield360/private/backups/initial.sgbak`. The separate decryption key is `/opt/cybershield360/private/backup.key`. These were not printed or downloaded. Arrange separate off-host backup storage/key escrow; same-host encrypted backup is not disaster recovery. No live DB restore was performed.

Validation also decrypted that backup into a separate private directory, compared the restored environment without printing values, and successfully parsed the dump with PostgreSQL's `pg_restore --list`. This validates envelope/config/archive readability, not a complete external DB restore or RPO/RTO. Temporary plaintext backup copies and consumed enrollment-token files were removed after checks; the encrypted artifact, private key and restore receipt remain. Admin access JSON remains private for handover.

Live login verification succeeded with its generated credential, required initial MFA, rejected protected inventory access before MFA, and revoked the test session. Public registration returned 403. Independent checks from the operator computer verified dashboard HTTP 200 and successful API health JSON on all three API/agent domains. The local operations/security regression suites passed (4 operations + 91 security/native checks).

Use narrowly scoped administration, not a persistent root shell:

```sh
sudo docker compose --env-file /opt/cybershield360/private/production.env -f /opt/cybershield360/deployment/compose.yaml ps
sudo docker compose --env-file /opt/cybershield360/private/production.env -f /opt/cybershield360/deployment/compose.yaml logs --tail=50 app
sudo systemctl status cybershield360-agent
sudo journalctl -u cybershield360-agent -n 20 --no-pager
```

Retrieve initial credentials only in a private SSH terminal. Keep them out of tickets, screenshots and chat. Complete MFA and retain recovery codes in the approved vault before inviting members. There are no shared/default MFA codes and no second administrator provisioned automatically.

Existing Nginx configuration had duplicate-name warnings for an unrelated domain; they were not altered. The shared host also reported pending OS security updates; coordinate its maintenance with its administrator rather than upgrading/restarting other hosted services as part of this deployment.

## Server activity drawer update

The deployed dashboard now opens a right-hand server details drawer, half-width on desktop and full-width on small screens. The approved metadata helper and updated signed agent are active on the registered host. Live ingestion was verified for SSH success records, TCP observations, source coverage and received ICMP echo metadata. SSH backfill and bounded TCP sampling can initially report BACKFILLING. This is recorded metadata coverage, not complete historical traffic accounting. The activity API and daily India-time aggregation passed regression tests; the production build and public HTTPS health checks passed. Visual browser interaction was not independently verified in this update.
