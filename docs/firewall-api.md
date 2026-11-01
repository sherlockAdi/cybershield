# Firewall APIs and native-plan adapters (Weeks 5–6 prototype)

Week 7 extension: [real approvals and simulation-only rollouts](rollouts.md) now implement approval decisions, canary gates, sandbox verification, rollback and offline/restart scenarios. Native execution and host-local safeguards remain disabled/unimplemented; historical scope descriptions below refer to the earlier authoring milestone.

## Scope and safety boundary

This milestone implements policy authoring, validation, deterministic native-plan compilation, single-version packet simulation, version comparisons, submission sealing and append-only policy audit history. It does **not** execute firewall commands or claim an inspected/effective host policy. Existing agents continue to advertise firewall=false. There is no apply endpoint, approval decision API, deployment, agent job or shell-execution path.

Native-plan adapters compile dedicated nftables tables or structured Windows NetSecurity command/parameter objects. They are not native executor adapters. Both always return `executable:false`, `status:UNVERIFIED` and inspection gates. Until distinct-person approval, trusted native-state inspection, coexistence checks, management/control-plane safeguards, persistent expiration, durable watchdog, rollback and reachability verification exist, live enforcement remains disabled. No firewall configuration was changed during acceptance.

## Browser APIs

Prefix: `/api/organizations/:id/firewall/policies`. All require current tenant membership, authenticated MFA session and normal browser Origin/CSRF checks. Any member may list/read/preview/history; only Owner/Admin may create/edit/revise/submit. No caller-supplied actor, role, state or native command is accepted.

| Method / suffix | Contract |
| --- | --- |
| GET / | Optional UUID cursor, limit 1–100 (default 30); `{items,nextCursor}`, newest policy first. |
| POST / | `{name,target,rules}` creates policy and v1 draft; returns `{policyId,versionId,checksum}`. |
| GET /:policyId | Optional `versionId`; policy, latest 100 version summaries and selected version with rules. |
| PATCH /:policyId/versions/:versionId | `{target,rules,expectedChecksum}` replaces an unsealed draft atomically. Stale checksum/sealed version returns 409. |
| POST /:policyId/versions/:versionId/revise | Clones content into a new numbered DRAFT with fresh rule UUIDs, leaving prior versions unchanged. Expired source rules must be removed/updated before saving/submitting. |
| POST /:policyId/versions/:versionId/preview | `{expectedChecksum,packet?,compareVersionId?}` returns checksum, generation time, current targets, frozen target IDs, drift, risk/blockers, expired IDs, native plans, optional packet verdict and semantic diff. Audits the preview. |
| POST /:policyId/versions/:versionId/submit | `{expectedChecksum}` validates expiry, target snapshot and safeguards, then seals DRAFT -> PENDING_APPROVAL. Returns `applyEnabled:false`; it does not create an approval request or deploy. |
| GET /:policyId/history | Optional UUID cursor, limit 1–100 (default 30); newest append-only policy audit entries with actor/time/version/checksum. |

404 hides inaccessible tenant/policy/version/group resources. Invalid input returns 400; permissions/CSRF 403; stale version, snapshot drift, duplicate rule identity or repeated submission 409. Existing 16 KiB JSON body limit and process-local write limits apply. No database migration is needed; existing policy/rule/audit tables and sealing triggers are used.

## Authoring contract

Target: `{type:"SERVER"|"GROUP",id:"UUID"}`. A target must resolve to 1–100 registered, non-decommissioned same-tenant hosts. This does not mean online/enrolled or deployment-ready. Draft saves snapshot current membership; submission refuses membership drift. Sealed snapshot IDs never change when group membership changes later. Removing/decommissioning all targets prevents preview/revision until an appropriate new target is chosen through a new draft workflow.

Rules: 1–50, each `{id,action,direction,cidr,protocol,portStart,portEnd,expiresAt,reason}`. Rule UUIDs are unique per version and globally unique database rows; revision creates fresh IDs. Action ALLOW/BLOCK, direction INBOUND/OUTBOUND, protocol TCP/UDP/ICMP. TCP/UDP require ordered integer destination ports 1–65535. ICMP requires null ports and represents all ICMP types in the address family. Reason is 3–1000 trimmed characters. Expiration is null or UTC ISO timestamp; new saves/submission require at least one minute remaining. Bodies must also fit 16 KiB.

Remote CIDR is source inbound and destination outbound. Bare IPv4/IPv6 addresses become /32 or /128; equivalent IPv6 spelling canonicalizes. Non-network host bits, hostnames, zones, malformed prefixes, IPv4-in-IPv6/mapped ambiguity, custom protocol values and extra fields are rejected. UUIDs and timestamps normalize before hashing/storing. Checksum is SHA-256 over recursively sorted JSON with schemaVersion, target, sorted frozen target IDs and ID-sorted normalized rules. Values are restricted to strings, integers and null; this is not yet a cross-language signed-job delivery contract. Shared Go/.NET canonicalization vectors remain an execution gate.

High-impact classification: IPv4 prefix shorter than /24, IPv6 shorter than /64, outbound rules, all-port ranges, SSH/RDP ports, or more than five targets. Inbound BLOCK touching ports 22/3389 and **all outbound BLOCK** submissions are conservatively rejected because no independently verified management/recovery/control-plane path exists. Custom management ports and protected source networks are not yet inventoried; classification does not prove safety. Live execution is disabled regardless of impact.

## Preview semantics

Only nonexpired selected-version rules participate. Native plans use saved snapshot targets, not changed group membership; current membership and drift are reported separately, even when a group becomes empty. Snapshot host records expose decommissioning, but do not imply deployment eligibility. Matching BLOCK beats ALLOW regardless of author order. Packet `{address,direction,protocol,port}` uses a plain remote IP and destination port (null for ICMP). Result is BLOCK/ALLOW/NO_MATCH **for the selected version only**, not all ServerGuard policies or the host's effective firewall. External rules/default policies and other ServerGuard versions can still deny traffic. The diff compares target snapshots and rule content ignoring regenerated row IDs; it is not a comparison with observed native state.

Linux plans create a version-specific `inet sg_<version UUID>` table with input/output base chains, policy accept, priority 10; BLOCK rules precede ALLOW. Address family and ICMPv4/v6 are explicit. No flush, table replacement, arbitrary text interpolation from reasons or unrelated object removal is generated. Plans are create-only, not idempotent replacement/reconciliation scripts. A firewalld-owned host is unsupported until a firewalld adapter exists; inspecting nft base chains/priorities is mandatory before execution.

Windows plans are structured `New-NetFirewallRule` objects in a version-specific group, PersistentStore, Profile Any, no authenticated bypass. Inbound uses LocalPort; outbound uses RemotePort; RemoteAddress selects source/destination consistently. Names derive only from validated UUIDs. User reasons are not executable content. ActiveStore/GPO merging, enabled profiles and bypass conflicts remain unverified; inspect these before any future executor. Plans never alter defaults or remove unrelated rules.

Temporary-rule plans explicitly require durable offline expiration scheduling. Generated plans become stale as time, group membership, native policies or host state change; no artifact should be manually applied on production infrastructure. Test eventual syntax/application/rollback only in disposable Linux and Windows VMs with independent console access.

## Acceptance evidence

`node scripts/run.mjs check` and API/dashboard production build pass. Full suite with `RUN_NATIVE_AGENT_TESTS=1`: **62 passing, zero skipped**, including 16 firewall checks covering network boundaries, strict combinations, canonical hashing, BLOCK/expiry simulation, adapter artifacts, tenant/role/CSRF, optimistic conflicts, sealing triggers, revisions/diffs, target drift, management safeguards and audit pagination. Existing native Windows telemetry/restart and Go/.NET signing tests still pass. Native firewall syntax/enforcement, VM coexistence, rollback and browser interaction are not verified.

References: [nftables manual](https://netfilter.org/projects/nftables/manpage.html), [Windows New-NetFirewallRule](https://learn.microsoft.com/en-us/powershell/module/netsecurity/new-netfirewallrule?view=windowsserver2025-ps). These explain why host coexistence/GPO state and external deny behavior must not be inferred from a generated allow rule.
