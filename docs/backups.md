# Encrypted backups and isolated restore

## Safety and scope

`scripts/backup.mjs` encrypts a **consistent, privately staged directory** using a separate random 32-byte key, AES-256-GCM, random nonce and authenticated header. Paths, file contents, sizes and checksums are encrypted; the header exposes format/version/time/key fingerprint, not secrets. Restore authenticates/decompresses/validates the whole manifest before creating a new destination. It rejects unsafe/case-colliding paths, links, malformed limits, wrong keys, tampering and existing destinations. Empty directories are retained.

This is bounded pilot tooling, not online database replication, a general archive extractor or a large production backup system. Maximum source: 64 MiB total, 16 MiB per file, 10,000 entries, depth 32; encrypted input/decompressed manifest limits apply. Files must have portable names. Larger external databases need reviewed streaming PostgreSQL backup infrastructure, not raised constants without capacity/security tests.

**The consistency flag is an operator assertion, not a lock or hot-backup mechanism. Never point it at a running embedded database or an uncontrolled changing tree.** No live application data was read by this task's tests. A failed output may remain partial; a failed restore after writes may leave an isolated partial directory, never a usable database. Keep such outputs quarantined for inspection; the tool does not recursively delete data to clean up.

## Keys and storage

Generate a separate backup-encryption key in a private directory outside the source tree and backup artifact:

```powershell
node scripts/backup.mjs keygen --key-file D:\private-backup-keys\pilot-backup.key
```

Parent directories must already exist and be controlled by the operator. Existing keys are never overwritten; key bytes are never printed or accepted as command-line arguments. POSIX key files require 0600. Windows ACLs allow only the intended identity, SYSTEM and Administrators; generated files are restricted to the current identity. Keep the backup key off-host/escrowed separately from encrypted backups. Losing it means losing restore access; storing it beside an exposed backup defeats encryption.

The **MFA encryption key** is different and must match the DB snapshot. In local embedded mode, preserve `.runtime/local-mfa-key` with the stopped DB. In external production mode, securely escrow/export the exact MFA key version from the secret manager into the protected staging set or record a tested retrievable key reference. Do not assume DATABASE_URL, `.env`, Node's environment or a release bundle automatically includes it. Protect staging plaintext and remove it under reviewed retention procedures.

## Embedded development/pilot backup

1. Stop the API/dashboard and all writers using normal service/process management. Verify they stopped; do not kill arbitrary Node/PostgreSQL processes by name. Do not delete `.runtime`.
2. In a new private staging directory, copy the entire stopped `.runtime/postgres` directory (including empty directories) and the matching local MFA key. Do not include agent private state/tokens or the backup-decryption key. Record app/PGlite version and migration state in a small metadata file. Source staging must remain immutable while encrypted.
3. Create an encrypted artifact outside staging:

```powershell
node scripts/backup.mjs create --source D:\private-staging\pilot-snapshot --output D:\encrypted-backups\pilot-001.sgbak --key-file D:\private-backup-keys\pilot-backup.key --confirm-consistent-source
```

4. Record the returned artifact hash/file count/size, copy to reviewed off-host storage and perform an isolated restore. Do not log file contents, MFA keys or live DB credentials. Restart original services only after snapshot consistency has been established.

## External PostgreSQL

Use a compatible `pg_dump` backup role and a custom-format dump, following PostgreSQL's documented consistency/privilege procedures. Supply credentials via an approved private password file/secret mechanism, **not** a password in process arguments. Stage the dump and matching MFA key metadata privately, then encrypt the staged directory with this tool if it fits the pilot limits. Large dumps require separate streaming encryption/storage tooling.

Restore a custom dump into a newly provisioned, isolated PostgreSQL database using `pg_restore` and the reviewed role/extension/ownership process. The backup tool only restores encrypted **files**; it does not execute SQL, choose a server, create roles or invoke pg_restore. Do not use `--clean` or target a live DB without an explicit reviewed migration/recovery plan. No external PostgreSQL dump/restore was executed here.

## Isolated restore and acceptance

```powershell
node scripts/backup.mjs restore --input D:\encrypted-backups\pilot-001.sgbak --destination D:\restore-drills\pilot-001 --key-file D:\private-backup-keys\pilot-backup.key
```

The destination must not exist. The tool creates private files/directories and `RESTORE_RECEIPT.json` with the artifact hash, time and counts; `databaseStarted:false` is deliberate. It does not move restored data into `.runtime`, overwrite production or start services.

Acceptance requires an isolated application/DB with the correct software/key version; verify migration history, tenant memberships, sample data, MFA decryption/login, append-only audit, pending outbox/rollout state and revoked authority. Do not reuse live sessions or enable outgoing notifications while testing. A restored older snapshot can resurrect previously revoked credentials: review session/token/agent revocation and key rotation before any cutover. Real agent state/counter restoration uses the [security recovery runbook](security-recovery.md), not arbitrary old snapshots.

The local automated drill used a **stopped synthetic PGlite DB**, encrypted table content and its matching MFA key. After restore to a separate directory, the DB reopened and the restored key decrypted the synthetic secret. This is not evidence of production RPO/RTO, external PG restore, power-loss durability or off-host retention. Assign backup/restore owners, record recovery timing in the real pilot, and schedule approved drills/retention separately; no recurring automation was created.

Reference: [PostgreSQL pg_dump](https://www.postgresql.org/docs/17/app-pgdump.html), [pg_restore](https://www.postgresql.org/docs/current/app-pgrestore.html).
