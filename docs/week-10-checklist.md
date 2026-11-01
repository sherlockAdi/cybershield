# Week 10 pilot preparation status

## Delivered

- Source/native-artifact bundle generator with explicit exclusions, per-file SHA-256 manifest, missing/extra/tampered-file rejection and explicit unsigned/capability flags.
- Authenticated encrypted, bounded staged-directory backups with private keys and no-overwrite isolated restore; empty-directory and portable-path preservation, wrong-key/tamper rejection and restore receipt.
- Automated stopped synthetic PGlite database restore with matching MFA key and successful decryption of its synthetic secret. No live application data was read or replaced.
- Redacted production-environment/build preflight, same-host loopback API/dashboard service templates and VPN-peer-restricted TLS proxy template.
- Release/deployment, backup/recovery and pilot user/host/workflow/sign-off/offboarding documentation.
- Operations tests integrated ahead of the existing native/security acceptance suite.

## Evidence and release gates

Packaging/backup/preflight checks run against isolated test directories and synthetic values. App/agent security coverage remains separate from operations acceptance. Build, full test and generated release verification results should be recorded with the pilot manifest hash.

This does not complete production release signing, registry publication, TLS/domain provisioning, systemd/Caddy installation/validation, external PostgreSQL migrations/dump restore, real backup RPO/RTO, service uninstall, independent review or real customer/host onboarding. Native firewall execution remains disabled, OS event collection is opt-in/manual and external notifications are unconfigured. See [deployment](release-deployment.md), [backups](backups.md), and [pilot checklist](pilot-onboarding.md) for the required operator decisions.
