# Integration coverage

The current HTTP/database integration and security acceptance suite is `tests/security/foundation.test.ts` and runs against fresh embedded PostgreSQL. External PostgreSQL pooling, multi-process concurrency, Redis/outbox and native agent adapters require additional integration environments as those components are introduced.
