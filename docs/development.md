# Development and verification

## Tools

Node.js 22 or 24 and pnpm 11.25.0. The lockfile pins installed dependency versions. On a machine with pnpm available, use the commands below. If using the bundled Codex runtime without a pnpm shim, invoke its `pnpm.cjs` using Node; the application itself can run entirely through `node scripts/run.mjs ...` after installation.

## Fast local start — no Docker needed

```powershell
pnpm install --frozen-lockfile
node scripts/run.mjs check
node scripts/run.mjs test
node scripts/run.mjs dev
```

Open `http://127.0.0.1:3100` exactly (not `localhost`, unless `APP_ORIGIN` is changed to match). API health is `http://127.0.0.1:4100/api/health`. Ports are fixed for the local Next.js proxy. Both processes bind to loopback only. Ctrl+C ends the retained foreground processes.

Leave `DATABASE_URL` unset for embedded PostgreSQL. First API startup applies checked-in migrations into `.runtime/postgres` and generates a 32-byte MFA encryption key at `.runtime/local-mfa-key`. Both paths are ignored by Git. They contain sensitive state: protect their Windows ACLs and keep encrypted backups together. Do not delete the key while retaining MFA-enabled users. There are no seeded users or default passwords.

Create an account and organization, scan the TOTP QR code, confirm a code and save the ten one-use recovery codes. Invite another account from Team & access. Invitations are returned once for manual private sharing; no email is sent. The invited account must use the exact recipient email and finish MFA before accepting its token from Organizations.

## External PostgreSQL with optional Redis

```powershell
Copy-Item .env.example .env
# Set passwords and a matching DATABASE_URL in .env.
pnpm infra:up
pnpm db:deploy
node scripts/run.mjs dev
```

Compose needs Docker with Compose v2. PostgreSQL binds `127.0.0.1:54329`, Redis `127.0.0.1:63799`. Redis is prepared for later job processing and is not required by Week 2. Images pin major versions for development; select and record immutable digests before production. Passwords in the connection URI must be URL-encoded independently of the literal `POSTGRES_PASSWORD` value. `infra:down` keeps named volumes; never delete volumes to solve migration errors without reviewing data loss.

The API loads the root `.env` using dotenv. Prisma CLI also reads root `.env`. Schema validation/build checks use a nonconnecting dummy URL when none is set; this does not start or test an external PostgreSQL server. `prisma migrate deploy` is the external bootstrap command; the embedded adapter uses its own checksum table, so do not mix both migration runners on the same database.

## Build and run

```powershell
node scripts/run.mjs check
node scripts/run.mjs test
node scripts/run.mjs build
node scripts/run.mjs start
```

`start` serves the compiled local application; it does not implicitly set NODE_ENV=production for the API. To configure an externally hosted deployment, review the production prerequisites below and use a TLS reverse proxy. There is no public deployment in this task.

## Environment

| Variable | Meaning |
| --- | --- |
| APP_ORIGIN | Exact browser origin; default `http://127.0.0.1:3100`. Writes reject other origins. |
| DATABASE_URL | Optional external PostgreSQL connection URI; unset selects embedded local persistence. |
| MFA_ENCRYPTION_KEY | Base64-encoded 32-byte encryption key; required for production, local ignored-file fallback otherwise. |
| NODE_ENV | `production` requires HTTPS origin, external database and explicit MFA key. |
| ALLOW_REGISTRATION | Public account creation is disabled in production unless explicitly set to `true`; local development permits registration. |
| POSTGRES_USER / POSTGRES_DB / POSTGRES_PASSWORD | Compose bootstrap credentials; not application authorization roles. |
| REDIS_PASSWORD | Local Redis password for future workers. |

## Before public deployment

Week 3 agent prototypes and native test prerequisites are documented in [agent setup](agent-installation.md) and [Week 3 evidence](week-3-checklist.md). Embedded startup automatically applies the additive agent migration; external PostgreSQL still requires `pnpm db:deploy` before running the updated API. Existing data and prior migration checksums are preserved.

Provision TLS ingress, managed keys and rotation, non-owner DB credentials, distributed per-account/IP login limits and durable lockout telemetry, verified email delivery/account recovery, off-host audit archival, tested backups/restore, production CSP and monitored operations. Default processes remain loopback-bound; changing exposure requires a reviewed ingress/deployment design. No Windows/Linux firewall adapter exists in Weeks 1–2.

## Sources

- [Next.js rewrites](https://nextjs.org/docs/app/api-reference/config/next-config-js/rewrites)
- [NestJS validation](https://docs.nestjs.com/application/validation)
- [PGlite query and transaction API](https://pglite.dev/docs/api)
