# Packaging and private pilot deployment

## Release boundary

This is an **unsigned development/pilot bundle**, not a signed installer or a production-readiness certificate. Control-plane source and locked dependency manifests are packaged for installation/build on the target host; prebuilt Linux amd64 and framework-dependent Windows x64 agent artifacts are included. They retain existing limitations: no live native firewall executor, no autonomous host-local rollback, no automatic OS-log tailing and no external notification provider.

The task does not publish to a registry, install services, change DNS/firewalls, provision TLS, expose a public endpoint, migrate an external database or onboard real users/hosts. Deployment files are operator-reviewed templates only.

## Create and verify a release

Build/test native artifacts and the application first, following the development and security guides. Then, from the repository root:

```powershell
New-Item -ItemType Directory -Force -Path .\artifacts\releases | Out-Null
node scripts/package-release.mjs create artifacts/releases/serverguard-0.1.0-pilot.1 0.1.0-pilot.1
node scripts/package-release.mjs verify artifacts/releases/serverguard-0.1.0-pilot.1
```

Creation refuses an existing destination and missing native artifacts. The allowlist includes source/docs/schema/migrations/scripts/tests/CI and selected native runtime files. Dependency trees, caches, runtime databases, real `.env`, backup folders, private key/certificate extensions, PDBs and logs are excluded. Symbolic links are rejected. `manifest.json` records version, capabilities, prerequisites and every file's SHA-256/length. Verification rejects modified, missing, extra or unsafe content. A partial output after an error is not a release; inspect it before removal/retry under a new directory.

Checksum verification detects accidental tampering **only when the manifest is trusted**. It does not authenticate the publisher: `signed:false`, `authenticityVerified:false`. Distribute the manifest hash through a separate trusted channel. Code signing, provenance/attestation, SBOM/license review and installer/uninstaller validation remain release gates; no self-signed certificate is substituted as a trusted release signature.

The folder can be archived by your approved ZIP/TAR tooling after verification, preserving its structure. Verify the extracted folder again. No archive is auto-extracted by the application. On Linux, explicitly apply executable permission to the supplied agent after verifying its hash. Do not treat Windows `.exe` as self-contained: install the required .NET 10 runtime and retain adjacent DLL/JSON files.

## Private pilot topology

Use one controlled Linux host for API/dashboard, an external PostgreSQL instance, a trusted TLS reverse proxy and a narrow VPN/network allowlist. API/dashboard remain loopback-bound at 4100/3100; only the proxy accepts authorized pilot traffic. Browser/agent connections must use the intended HTTPS origin. The initial pilot should be small (for example 2–3 administrators and one isolated test host per OS), not an unmeasured shared production service.

Templates:

- `infrastructure/deployment/control-plane.env.example`: exact HTTPS origin, runtime DB URI, explicit MFA key and closed registration. Replace every placeholder in a **private** `/etc/serverguard/control-plane.env`; never include it in a release or ticket. Keep it readable only by the operator/service policy.
- `serverguard-api.service` / `serverguard-dashboard.service`: non-root `serverguard` service account, `/opt/serverguard/current` checkout, production environment, restart and basic systemd restrictions. Adjust Node path/user/paths for the actual host. Create the dashboard `.next/cache` before using ReadWritePaths and grant only the required cache write access. Do not make application source/world data writable to solve startup failures.
- `Caddyfile`: `PILOT_HOST` and `PILOT_CIDR` are mandatory operator-provided environment values for a real hostname and intended VPN client CIDR. It rejects peers outside that CIDR. Do not use `0.0.0.0/0` or `::/0`; do not add a CDN/proxy or trust arbitrary forwarded headers without redesigning the network boundary. Real certificate issuance/domain validation is not tested here.

Provision compatible Node.js 22/24 and pnpm 11.25.0. Install locked dependencies and build on the target OS; do not copy the development `node_modules` across platforms. Review dependency installation hooks and package licenses before distribution. The supplied development Compose file is not a hardened production DB/Redis deployment.

## Ordered deployment procedure

1. Verify the extracted manifest and trusted-channel hash; review open release gates and freeze a pilot version. Keep the previous release and migration history. Use a separate staging/pilot environment, not existing production services.
2. Provision a dedicated non-superuser application DB role and separate migration/backup roles. Enforce encrypted DB connectivity and network ACLs using the actual PostgreSQL service's procedures. Do not use the Compose bootstrap owner as the production runtime role. Provision/escrow a random 32-byte MFA key through your secret manager.
3. Perform and verify an encrypted backup using the [backup runbook](backups.md). Confirm a restore on an isolated destination before migration. Data/key mismatch can make MFA secrets unrecoverable.
4. With maintenance access restricted, install frozen dependencies and run checks/build. Apply additive external migrations with `node scripts/run.mjs db:deploy` using the migration role and intended DATABASE_URL. Do not run the embedded migration adapter and Prisma migration runner against the same DB.
5. Load production environment **without printing secrets**, then run `node scripts/deployment-check.mjs`. It checks environment shape, non-placeholder credentials/MFA key, closed registration and build files. It does not connect to the database or validate TLS, privileges, backups, network policy, capacity or security posture.
6. Review/install service and proxy templates with the host administrator. Validate Caddy configuration with the installed Caddy binary and verify the allowlist/certificate from inside and outside the VPN. Start the API before dashboard/proxy; inspect generic service logs for startup/migration errors without copying secrets. No install command is executed by these scripts.
7. Use a tightly controlled first-owner bootstrap window: keep VPN/maintenance access restricted, explicitly allow registration only long enough for the nominated first administrator to register and enable MFA, then disable it and restart/recheck before handover. Subsequent organization members join by invitations. No default credentials or hidden bootstrap backdoor is provided.
8. Follow the [pilot checklist](pilot-onboarding.md), record evidence/sign-off and keep traffic blocked if any critical check fails. Monitor notification outbox failures, unexpected restarts, DB/storage growth and authentication denials. Retention cleanup, external alerts and a full observability stack are not supplied.

The current API rate limits key on the immediate socket address. Behind one loopback proxy, clients share process-local quotas; this is conservative but can cause pilot onboarding throttling. It is not a distributed per-user/IP defense. Do not disable limits or blindly trust X-Forwarded-For to bypass this deployment gate.

## Upgrade / rollback policy

Stop or quiesce writers before a coordinated upgrade, take a tested backup and preserve the matching MFA key. Additive migration checksums must never be edited after application. Keep migrations forward-only; reverting binaries does not revert schema/data. If older code compatibility is uncertain, remain in maintenance and restore to a **new isolated database/directory** for review rather than overwriting live state.

Database restoration can revive old sessions, tokens or revoked agent credentials. Before exposing a recovered database, review/revoke stale authority and re-enroll where necessary using the security recovery procedure. Restore/rotation decisions require the security owner; the tool never restarts a restored DB or silently resets an agent counter.

## Evidence / not executed

Local tests cover allowlist packaging, hash/extra-file rejection, deployment preflight failures, encrypted round-trip/tamper/wrong-key refusal and a stopped synthetic PGlite database plus matching MFA-key restore. No real user data is packaged or backed up by these tests. Actual Linux service installation, public/private DNS, Caddy validation/TLS, external PostgreSQL deployment/restore, signed packages, disaster recovery and real pilot acceptance still require the named operators' evidence.

References: [Caddy reverse proxy](https://caddyserver.com/docs/caddyfile/directives/reverse_proxy), [Caddy peer-IP matchers](https://caddyserver.com/docs/caddyfile/matchers), [PostgreSQL 17 pg_dump](https://www.postgresql.org/docs/17/app-pgdump.html).
