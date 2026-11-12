# Device registration and Windows service pilot

Device Management is organization-scoped and separate from server inventory.
Windows devices reuse the existing signed server credential protocol and also
appear under Servers & agents. Employee assignment is optional and restricted to
active members in the same organization. Registration, enrollment, revocation and
configuration writes require Owner/Admin and MFA.

Inventory paginates ten records. Selecting a device opens Overview, Configuration,
Security audit, Applications, IP access, Action history and Enrollment tabs.
Configuration writes use optimistic revisions and organization audit history.
Endpoint policies remain **draft / NOT_APPLIED**; saving never claims enforcement.

Companion repository: https://github.com/sherlockAdi/cybershield-device-agent
Windows Actions builds a self-contained win-x64 package with install/uninstall
and audit scripts. Install with owner permission using administrator PowerShell.
Enrollment runs as LocalSystem so DPAPI identity survives service restart. The
installer does not enable remote shell or the optional host-management helper.

The ACL-protected audit script runs every two minutes. Bounded JSON travels in
signed heartbeats; the API checks signature, credential, sequence, Windows OS,
timestamp, structure and size. Collector failures stay UNKNOWN; receipt timestamps
show stale data. Re-enrollment clears audit snapshots. No recovery keys are sent.
Reports contain local account/device identifiers and are readable by tenant members.

Apply migration `202611120001_devices` before deploying API/dashboard. Existing
agents remain compatible; install the new audit agent only after the API upgrade.
Employee registration is not needed for device enrollment.

Native policy enforcement, continuous peripheral-event monitoring, automatic
credential renewal, update/rollback installation and Windows account management
remain future work. Application/IP controls remain separately opt-in; see
host-management.md. This registration pilot is not full DLP.

Security tests cover tenant/role isolation, optional mapping, foreign-member
rejection, revision conflicts, pagination, signatures, replay, stale audit and
revocation. Windows CI compiles/parses/runs an audit. Actual SCM installation,
reboot/DPAPI continuity and uninstall still require the owner's pilot laptop.
