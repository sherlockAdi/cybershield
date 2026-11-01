# HTTP API v1 — implemented Week 2 surface

Base path `/api`. JSON bodies only, maximum 16KB. All responses use `Cache-Control: no-store`. All mutations require exact `Origin: APP_ORIGIN`. Authenticated mutations additionally require `X-CSRF-Token` matching the current readable `sg_csrf` cookie. The access/refresh cookies are HttpOnly, SameSite Strict and Secure in production; do not copy them into browser storage.

Access sessions expire after 15 minutes, bounded by the refresh family's seven-day absolute expiration. Refresh consumes the old credentials and rotates access/refresh/CSRF values. Reuse revokes the whole family. The dashboard serializes refresh attempts in one tab. Independently racing tabs may require reauthentication after detected reuse; no replay grace window is implemented.

## Endpoints

| Method / path | Input | Authorization / result |
| --- | --- | --- |
| GET /health | — | Public liveness and database mode; not a detailed operational readiness probe. |
| POST /auth/register | name, email, password, organization | Creates account, owner membership, unverified session; production registration disabled by default. |
| POST /auth/login | email, password, optional code | Existing MFA requires TOTP or unused recovery code. Returns `challenge: true` without credentials if code is required. |
| POST /auth/refresh | empty JSON | Refresh cookie + matching CSRF header; rotates credentials. |
| POST /auth/logout | empty JSON | Refresh-bound CSRF; revokes family and clears cookies. |
| GET /auth/me | — | Valid access session; returns safe user fields and current organization memberships. Allowed before MFA setup. |
| POST /auth/mfa/setup | empty JSON | Authenticated not-yet-enabled account; returns QR, URI and manual secret. |
| POST /auth/mfa/confirm | code | Enables MFA, returns ten recovery codes once, verifies current session, revokes other sessions. |
| GET /auth/sessions | — | MFA-verified user; latest 100 active own sessions, no bearer secrets. |
| DELETE /auth/sessions/:id | — | MFA-verified owner of session; revokes its family. |
| POST /organizations | name | MFA-verified account becomes owner of new organization. |
| GET /organizations/:id/overview | — | Any member; real counts and latest 12 audit entries. |
| PATCH /organizations/:id | name | Owner/Admin; rename organization. |
| GET /organizations/:id/members | — | Any member; member identities, role and MFA-enabled flag. |
| PATCH /organizations/:id/members/:userId | role | Owner/Admin; ownership changes owner-only; cannot demote last owner. |
| DELETE /organizations/:id/members/:userId | — | Same checks; immediately removes organization access. |
| GET /organizations/:id/invitations | — | Owner/Admin; latest 100, never token hashes or bearer values. |
| POST /organizations/:id/invitations | email, role | Owner/Admin; OWNER invitation requires Owner. Returns bearer token once, no mail delivery. |
| DELETE /organizations/:id/invitations/:invitationId | — | Owner/Admin; owner invitation revocation requires Owner. |
| POST /invitations/accept | token | MFA-verified matching-email recipient; atomically consumes unexpired token after issuer privilege recheck. |

POST success defaults to 201; GET/PATCH/DELETE success is 200. Errors return `{statusCode, message}` from handlers (middleware may return only `message`). 400 malformed/extra input; 401 missing/expired credentials; 403 CSRF/origin/MFA/role denial; 404 absent or foreign-tenant resource; 409 duplicate/conflicting invariant; 415 non-JSON write; 429 local rate limit; 500 sanitized internal error. The API accepts no actor ID or role from client-supplied session claims.

## Implemented agent surface — Week 3

See [SG1 protocol](agent-protocol.md) for the separate signed `/api/agent/v1/enroll` and `/api/agent/v1/heartbeat` endpoints, administrator enrollment/revocation routes and strict wire format. These native endpoints require signature proof rather than browser cookies/CSRF and reject browser Origin headers. Job polling, executable operations, certificate issuance/mTLS and security-event ingestion remain future work; no shell field is accepted.
# Current firewall supplement

[Detection and notification APIs](detections.md) add structured signed authentication/process observations, incidents, triage, settings, personal inbox reads and observable IN_APP outbox delivery. No external provider or automatic OS collector is configured.

[Rollout APIs](rollouts.md) now add real distinct-person approval and simulation-only canary, verification, rollback and offline scenarios. They cannot execute native firewall rules. Execution gaps and acceptance evidence are in [Week 7 status](week-7-checklist.md).

[Firewall API](firewall-api.md) documents implemented authoring, preview, sealing and audit-history routes. These browser endpoints do not authorize execution or queue jobs. [Telemetry](telemetry.md) documents the implemented Week 4 event ingestion extension; earlier agent-future descriptions below are historical.

