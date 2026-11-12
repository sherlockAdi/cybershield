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

## Online policies and automatic updates (1.1)

The updated agent enables the host-management helper (service inventory and IP
rules; service stops still require the local allowlist), plus IP address/TCP/UDP
and process snapshots. Missing collectors report UNKNOWN. Network snapshots are
capped at 100 rows per section and displayed ten at a time, not full traffic logs.

**Save and apply** queues the next revision for a policy-capable Windows agent.
Delivery is on the next 30-second heartbeat and acknowledgement normally on the
following heartbeat. The agent rechecks the policy about every two minutes.
Previously saved drafts remain drafts until explicitly applied. Each control
returns a verified result, failure, unsupported or pending-restart status. Server
save alone never changes the device status to applied. Stale/offline agents show
stale results; new revisions remain pending until reconnection.

Implemented controls: enable/verify Windows Firewall and Defender real-time AV;
write/read back native removable-disk block/read-only policy and inactivity lock.
Storage/lock retain PENDING_RESTART until native acceptance is performed; existing
handles/fixed USB disks/session behavior must be tested. Storage AUDIT removes
only CyberShield-owned values; externally changed/GPO values are not overwritten.
Domain/Home policy deployments are rejected by this pilot. No keyboard/mouse is
disabled. Per-device storage exceptions, Bluetooth/MTP/printer/network-adapter
blocking remain unsupported. BitLocker is checked but never enabled without
recovery-key escrow. Unchecking antivirus/firewall does not disable protections.

Existing installs must run Update-Service.ps1 once as administrator, preserving
DPAPI keys, server UUID and sequences. This enables a SYSTEM scheduled updater
checking the same HTTPS origin every 15 minutes. Main production CI builds the
Windows package after tests, signs the manifest with the repository signing secret,
and deploys the manifest/ZIP with the app. Companion repository builds provide
manual bootstrap packages; the production feed is published by the main control
plane pipeline, not every unreviewed standalone build.

The updater pins the RSA public key, verifies the manifest signature and SHA-256,
rejects redirects/foreign paths, stale generations and unsafe archive entries,
backs up binaries, restarts the same service and waits for a successful signed
heartbeat marker. Failure restores the prior binaries and suppresses that failed
version. No GitHub token is stored on a laptop. Old state remains untouched. The
updater reports task/status in the security audit. Signing-key rotation needs a
separate planned trust transition. SCM update/rollback remains a pilot acceptance
gate even after CI passes; do not claim it has run on a customer device.

## Consented screenshots (1.2)

The Screenshots tab is Owner/Admin-only and supports 1, 5, 10 or 15 seconds.
Capture defaults off. Enabling it requests capture; it cannot bypass local consent.
A local administrator provisions Enable-ScreenCapture.ps1 for the intended Windows
account (use -User when elevation uses another account). That user runs the visible
Start-ScreenSharing.ps1 helper and clicks Allow. The window/taskbar/tray show capture
status and Stop. Closing the helper stops capture. Only the active local console's
primary display is supported; locked/secure desktops and other sessions are skipped.
After a network/agent outage the 65-second settings lease expires and fresh local
consent is required. This is best-effort periodic capture, not real-time video.

The service receives bounded JPEG frames from a user-writable spool but opens them
under the interactive user's token, so privileged file reads cannot be obtained by
replacing a link. The shared settings/script directory is administrator-owned and
read-only to the user. Frames are resized to at most 960px width/96KB. Current
frames use the agent's signed envelope and shared durable monotonic sequence;
server checks credential, tenant, OS, revision, interval and capture timestamp.

Only the latest encrypted image is stored in the database, using AES-GCM with a
purpose/device-derived server key. This is server-side encryption, not zero-knowledge
storage. Authorized Owner/Admin reads are audited and no-store; viewers cannot read
or configure capture. Images older than 60 seconds are hidden; live-database cleanup
runs every minute for images older than five minutes. Disabling, revoking or
re-enrolling clears the latest image. Normal encrypted database backups follow the
existing backup retention policy. The local restricted spool holds only the latest
frame and is cleared on normal stop; a forcibly killed helper can leave that file
until the next session/admin cleanup. No screenshot history or public links exist.

The automatic updater includes 1.2 binaries/scripts, but does not silently provision
or launch the interactive capture helper. Local owner setup/consent remains required.
Windows UI consent, lock/unlock and actual screen capture need pilot verification;
CI checks compilation/scripts and API permission/crypto/replay/retention behavior.
