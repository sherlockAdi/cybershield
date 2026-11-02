# Server inventory, login pages and host management

The server table and server login history show **10 rows per page**, with Previous and Next controls. Refresh retains the inventory page. Login pagination uses an exclusive `(occurred_at, id)` cursor and a fixed cutoff while browsing older pages; Latest returns to current activity. Login history can page through the full retained day, beyond the old 100-record cap.

Open a server to see Applications & IP access. Applications, managed IP blocks and the latest 100 actions have ten-row pages. Counts are reported managed resources, not unique products: a service and its container, or an IIS site and its pool, may represent related components. Inventory is capped at 200 resources and explicitly marked if truncated. Missing collectors appear as errors instead of implying an empty server.

## Deployment order

1. Back up the database and deploy migration `202611020001_host_management` using `pnpm db:deploy` with the migration role. The existing production default privileges give the runtime role access to new tables.
2. Build and deploy the API/dashboard with `pnpm build`. Existing agents continue reporting telemetry and show management unavailable until upgraded. The heartbeat request limit is now 256 KiB; allow at least that at the reverse proxy.
3. Build/install agent version `0.9.0-management` and its optional helper on each managed host. Management is **opt-in**; merely upgrading an agent does not give it privileged access.
4. Verify a fresh management report, inspect application details, and exercise a disposable application's Stop action and a test IP's block/unblock from a separate management connection. Windows/IIS requires this runtime acceptance test on a Windows Server host; cross-platform compilation cannot validate Windows Firewall or IIS.

No existing application is stopped and no IP is blocked by deployment itself. The public registration setting is independent and is not modified by this change.

## Linux

The helper `agents/management/linux.py` requires Python 3, systemd, root privileges, and nftables for IP blocking. Docker inventory is optional and uses the local Docker CLI. Install the helper at `/usr/local/lib/cybershield360/linux.py`, owned by root with mode 0755; its directory and all ancestors must be root-owned and not writable by group/others. The helper has no arbitrary shell endpoint.

Install `/etc/cybershield360/management.json`, root-owned mode 0600 in a root-owned directory:

```json
{
  "firewallEnabled": true,
  "protectedAddresses": ["192.0.2.10/32", "2001:db8::10/128"],
  "stopAllowlist": ["systemd:example-app.service", "docker:example-app"]
}
```

Replace the example protected addresses with administrator/bastion/control-plane addresses and replace the stop allowlist with actual applications. An empty allowlist permits inventory but no stops. Docker entries use the container **name** locally; dispatched targets use full container ID and start time. Do not add the control plane, database, SSH, agent, Docker daemon, or other essential infrastructure to the allowlist.

Use a dedicated management-enabled agent service under root, using the same server identity/state as the existing agent (never run two agents against the same state). Stop the existing service first, preserve the state and its sequence, change the private state directory and contents to root ownership, and add:

```text
--management-helper /usr/local/lib/cybershield360/linux.py
```

The telemetry-only service's empty capability bounding set is insufficient for this mode. Supply a reviewed root service with CAP_NET_ADMIN available, local systemd/Docker socket access, and write access to `/var/lib/cybershield360-management` (StateDirectory mode 0700) and the private agent state. Keep helper/config directories read-only to the service where possible. Root management mode expands the agent's trust boundary; keep the signing state and local configuration private.

Blocks use isolated `inet sg_<rule UUID>` nftables tables on prerouting before NAT, covering inbound TCP to the host and forwarded Docker traffic. They do not flush the host ruleset. Login means the **specified TCP ports** (normally SSH 22), not a PAM/account policy. Custom SSH ports must be entered explicitly. The helper persists desired rules in `/var/lib/cybershield360-management/rules.json` and restores/verifies them on inventory collection. There is a reboot gap until the management service runs. Unblock removes only its own table; another firewall rule may still deny traffic. IPs must be individual IPv4/IPv6 addresses; protected networks, loopback, multicast and unspecified addresses are refused.

Stop supports allowlisted systemd services and Docker containers, without forwarding shell commands or environment variables. Resource details include service description, PID, unit path and available memory, or container image, state, age and port mappings. Process/resource metrics not provided by a manager remain unavailable. Snapshot/stop operations can fail on inaccessible or changing resources; the dashboard shows failure rather than assuming success.

## Windows / IIS

Build `agents/windows-agent` with the .NET 10 SDK. Install `agents/management/windows.ps1` in an administrator-controlled absolute path. Add `--management-helper <absolute script path>` to the Windows service arguments. The service identity needs administrative permissions for Windows Firewall, service control and IIS. Keep the existing DPAPI identity; changing identities without re-enrollment makes the protected key unreadable.

Create `%ProgramData%\ServerGuard\management.json` with ACLs writable only by the service identity, SYSTEM and Administrators:

```json
{
  "firewallEnabled": true,
  "protectedAddresses": ["192.0.2.10", "2001:db8::10"],
  "stopAllowlist": ["service:ExampleApp", "iis-site:Example Website", "iis-pool:ExamplePool"]
}
```

Windows protected addresses are exact addresses (Linux also supports CIDRs). PowerShell execution policy must allow the locally installed script; the agent does not bypass it. The agent checks helper/config ACLs and rejects writable or linked paths. Windows service inventory comes from CIM; IIS sites and application pools are reported when the WebAdministration module is installed. Details include service PID/start mode/account/executable (without arguments), IIS bindings/path/pool, and pool runtime/pipeline. For IIS, a site and an application pool are independently stoppable resources. Stop does not disable automatic start/recovery policies.

Windows IP blocks are persistent inbound Windows Firewall TCP rules, applied to all profiles. All profiles must be enabled. Login defaults to RDP 3389; use the actual port, or add 22 for OpenSSH. This does not block RDP UDP or establish application-specific IIS login restrictions. Rules are named `CyberShield-<UUID>` and unblock only removes the selected managed rule. Group Policy or other firewall products may still deny traffic.

## Command and trust model

Only authenticated, MFA-verified organization Owners/Administrators can request actions. The API validates tenant ownership, current inventory and a live credential. One command per server can be pending; it expires after two minutes. Agents receive commands over their configured HTTPS origin following a signed heartbeat and return results in the next signed heartbeat, using the same anti-replay sequence as telemetry. The server checks the requester's current role again before dispatch. Re-enrollment clears the old management snapshot. Agent credentials are scoped to a server; commands are bound to that credential.

Agents persist an indeterminate failure before invoking a helper. Retrying the same command ID never reruns a stop after a response loss or restart. A crash between execution and result persistence reports failure requiring inspection, not fabricated success. UI status is Pending/Dispatched until an authenticated result arrives. Expired actions may have executed without a received acknowledgement; inspect the host before retrying. Request and result are recorded in append-only audit history.

The helper allowlist is an additional local boundary. It does not replace API permissions. Reported status reflects the latest observation; it is not independent security attestation. Changes made outside this console and restarts by supervisors can change state after acknowledgement.

## Validation

- `pnpm check`, `pnpm build`, `pnpm test`
- `python3 -m unittest discover -s agents/management -p 'test_*.py'`
- Linux agent: `go test ./...` on Linux; `GOOS=linux GOARCH=amd64 go test -c` for cross-compilation.
- Windows agent: `dotnet build -c Release`; run native Windows service/IIS/firewall tests on a disposable Windows Server before enabling that host.
