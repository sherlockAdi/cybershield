# Policy models

Policy semantics are defined in [firewall-policy.md](../../docs/firewall-policy.md). Executable API validation, canonical checksums, packet simulation and compile-only nftables/Windows NetSecurity adapters live in `apps/api/src/firewall-model.ts`; acceptance vectors are in `tests/security/firewall.test.ts`. See [API and native adapter limits](../../docs/firewall-api.md). Native executor integration and cross-language signed-job canonicalization remain future work; no live firewall enforcement is enabled.
