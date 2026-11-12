# Windows laptop pilot

## Current deliverable

`Audit-Device.ps1` is an administrator-run, read-only assessment for Windows
PowerShell 5.1. It reports OS, firewall, Defender/antivirus, disk encryption,
recent hotfixes, machine lock policy, local users/admins, present peripherals,
services and existing device/storage policies. Unavailable collectors are
explicitly `UNKNOWN`. It does not change Windows accounts or policies, install
the agent, upload reports, or claim that the laptop is secured.

From a local administrator PowerShell console in this directory:

```powershell
.\Audit-Device.ps1 | Out-File -Encoding utf8 .\device-audit.json
```

Use an administrator-controlled directory for this report. It contains account
and device identifiers. Review the script and use the organization's approved
PowerShell signing/execution policy; do not bypass execution policy globally.
BitLocker recovery passwords, file contents, Wi-Fi passwords and browser
history are not collected.

## Deployment gates

1. Confirm owner consent, Windows edition/build and employee organization/account.
2. Run the audit. Check domain/MDM ownership and conflicting policy before edits.
3. Verify a separate administrator account by logging in locally. Escrow any
   BitLocker recovery key in the owner's approved secure location before
   encryption changes. Never send it with the audit report.
4. Enroll the existing signed Windows agent using `docs/agent-guide.md`. Retain
   its service identity: DPAPI-protected credentials are identity-bound. Test
   restart, heartbeat and revoked-credential rejection.
5. Use Device Management configuration to assign an existing organization member
   or leave the device unassigned. Local usernames are not employee mappings.
6. Review peripheral instance IDs. Begin with storage only; keep input devices,
   recovery networking and required printers available. Installation restrictions
   and read/write access policies have different semantics. Do not apply a
   blanket deny-all policy and assume it has per-device exceptions.
7. Apply the reviewed policy on the actual pilot with before-state backup and
   rollback. Test existing and newly attached storage, phone/MTP, Bluetooth and
   USB networking separately. Do not label these protected until each test passes.
8. Convert only the employee account to standard user after the separate admin
   and required applications have been tested. Preserve recovery access.

## Acceptance checklist

- Employee assignment rejects another organization's user; changes are audited.
- Unique agent key survives service restart; copied IP/MAC is not identity.
- Employee is standard user; recovery administrator can sign in offline.
- Firewall/AV/updates/encryption/lock have observed states, with unavailable data
  displayed as unknown rather than healthy.
- Unapproved storage read/write is denied, including previously installed devices.
- Approved storage follows its selected allow/read-only policy.
- Keyboard/mouse and approved peripherals still function.
- Peripheral connection and violation events reach the authenticated dashboard.
- Unplugging the network and rebooting retain the supported local restrictions.
- Reconnection sends buffered events without duplication; missing agent is stale.
- Rollback restores only pilot-owned settings without overwriting GPO/MDM policy.

The audit has not been executed on Windows in this development environment.
The Device Management dashboard now supports registration, member assignment,
configuration drafts and signed audit display. Continuous peripheral events and
policy enforcement/rollback remain future work. The standalone service package
is in https://github.com/sherlockAdi/cybershield-device-agent.

## References

- [Microsoft device installation policies](https://learn.microsoft.com/en-us/windows/client-management/client-tools/manage-device-installation-with-group-policy)
- [Microsoft device control capability comparison](https://learn.microsoft.com/en-us/defender-endpoint/device-control-removable-storage-access-control)
