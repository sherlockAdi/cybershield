# Incident response foundation

Detection and automated incident response are not implemented in Weeks 1–2. For identity incidents, an organization Owner/Admin can remove a compromised member or revoke invitations. A user can revoke their own sessions. Removal is immediately effective because authorization reads current memberships on each request.

If credentials are suspected compromised, retain audit evidence, revoke affected sessions, remove unnecessary memberships, and investigate the host and database using an approved internal process. Account disabling is currently an administrative database operation, not a dashboard feature. Password reset and MFA recovery escalation require a reviewed identity-verification workflow before public deployment.

For future firewall incidents: pause rollout, preserve desired/observed states, use the agent-local watchdog and retained known-good snapshot, confirm native enforcement, and use independent console recovery when connectivity is unavailable. Never interpret a missing heartbeat as proof of successful rollback. Record responder, approvals, timeline, affected servers and verified recovery evidence.
