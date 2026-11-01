CREATE TYPE "Role" AS ENUM ('OWNER', 'ADMIN', 'OPERATOR', 'VIEWER');

CREATE TYPE "OperatingSystem" AS ENUM ('LINUX', 'WINDOWS');

CREATE TYPE "RuleAction" AS ENUM ('ALLOW', 'BLOCK');

CREATE TYPE "Direction" AS ENUM ('INBOUND', 'OUTBOUND');

CREATE TYPE "Protocol" AS ENUM ('TCP', 'UDP', 'ICMP');

CREATE TYPE "PolicyState" AS ENUM ('DRAFT', 'PENDING_APPROVAL', 'APPROVED', 'SUPERSEDED');

CREATE TYPE "DeploymentState" AS ENUM ('PENDING_APPROVAL', 'QUEUED', 'CANARY', 'ROLLING_OUT', 'PAUSED', 'SUCCEEDED', 'FAILED', 'ROLLING_BACK', 'ROLLED_BACK', 'CANCELLED');

CREATE TYPE "TargetState" AS ENUM ('PENDING', 'DISPATCHED', 'APPLIED', 'VERIFIED', 'FAILED', 'UNKNOWN', 'ROLLING_BACK', 'ROLLED_BACK', 'ROLLBACK_FAILED', 'CANCELLED');

CREATE TYPE "ApprovalState" AS ENUM ('PENDING', 'APPROVED', 'REJECTED', 'EXPIRED');

CREATE TYPE "Severity" AS ENUM ('INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL');

CREATE TYPE "IncidentState" AS ENUM ('OPEN', 'INVESTIGATING', 'RESOLVED');

CREATE TYPE "JobState" AS ENUM ('PENDING', 'LEASED', 'SUCCEEDED', 'FAILED', 'EXPIRED');

CREATE TYPE "DeliveryState" AS ENUM ('PENDING', 'SENT', 'FAILED');

CREATE TABLE "organizations" (
    "id" UUID NOT NULL,
    "name" VARCHAR(120) NOT NULL,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "organizations_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "users" (
    "id" UUID NOT NULL,
    "email" VARCHAR(254) NOT NULL,
    "name" VARCHAR(100) NOT NULL,
    "password_hash" TEXT NOT NULL,
    "disabled_at" TIMESTAMPTZ(3),
    "mfa_secret_encrypted" TEXT,
    "mfa_pending_encrypted" TEXT,
    "mfa_enabled" BOOLEAN NOT NULL DEFAULT false,
    "mfa_last_step" BIGINT NOT NULL DEFAULT -1,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "users_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "memberships" (
    "organization_id" UUID NOT NULL,
    "user_id" UUID NOT NULL,
    "role" "Role" NOT NULL,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "memberships_pkey" PRIMARY KEY ("organization_id","user_id")
);

CREATE TABLE "sessions" (
    "id" UUID NOT NULL,
    "user_id" UUID NOT NULL,
    "family_id" UUID NOT NULL,
    "access_hash" CHAR(64) NOT NULL,
    "refresh_hash" CHAR(64) NOT NULL,
    "csrf_hash" CHAR(64) NOT NULL,
    "mfa_verified" BOOLEAN NOT NULL DEFAULT false,
    "access_expires_at" TIMESTAMPTZ(3) NOT NULL,
    "expires_at" TIMESTAMPTZ(3) NOT NULL,
    "consumed_at" TIMESTAMPTZ(3),
    "revoked_at" TIMESTAMPTZ(3),
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "sessions_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "mfa_recovery_codes" (
    "id" UUID NOT NULL,
    "user_id" UUID NOT NULL,
    "code_hash" CHAR(64) NOT NULL,
    "used_at" TIMESTAMPTZ(3),

    CONSTRAINT "mfa_recovery_codes_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "invitations" (
    "id" UUID NOT NULL,
    "organization_id" UUID NOT NULL,
    "email" VARCHAR(254) NOT NULL,
    "role" "Role" NOT NULL,
    "token_hash" CHAR(64) NOT NULL,
    "invited_by" UUID NOT NULL,
    "expires_at" TIMESTAMPTZ(3) NOT NULL,
    "accepted_at" TIMESTAMPTZ(3),
    "revoked_at" TIMESTAMPTZ(3),
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "invitations_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "servers" (
    "id" UUID NOT NULL,
    "organization_id" UUID NOT NULL,
    "hostname" VARCHAR(253) NOT NULL,
    "os" "OperatingSystem" NOT NULL,
    "os_version" TEXT,
    "agent_version" TEXT,
    "last_heartbeat_at" TIMESTAMPTZ(3),
    "decommissioned_at" TIMESTAMPTZ(3),
    "labels" JSONB NOT NULL DEFAULT '{}',
    "capabilities" JSONB NOT NULL DEFAULT '{}',
    "observed_checksum" CHAR(64),
    "observed_version" INTEGER,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "servers_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "server_groups" (
    "id" UUID NOT NULL,
    "organization_id" UUID NOT NULL,
    "name" VARCHAR(120) NOT NULL,

    CONSTRAINT "server_groups_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "server_group_members" (
    "organization_id" UUID NOT NULL,
    "group_id" UUID NOT NULL,
    "server_id" UUID NOT NULL,

    CONSTRAINT "server_group_members_pkey" PRIMARY KEY ("organization_id","group_id","server_id")
);

CREATE TABLE "agent_credentials" (
    "id" UUID NOT NULL,
    "organization_id" UUID NOT NULL,
    "server_id" UUID NOT NULL,
    "certificate_fingerprint" CHAR(64) NOT NULL,
    "certificate_serial" TEXT NOT NULL,
    "expires_at" TIMESTAMPTZ(3) NOT NULL,
    "revoked_at" TIMESTAMPTZ(3),
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "agent_credentials_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "enrollment_tokens" (
    "id" UUID NOT NULL,
    "organization_id" UUID NOT NULL,
    "server_id" UUID NOT NULL,
    "token_hash" CHAR(64) NOT NULL,
    "created_by" UUID NOT NULL,
    "expires_at" TIMESTAMPTZ(3) NOT NULL,
    "consumed_at" TIMESTAMPTZ(3),

    CONSTRAINT "enrollment_tokens_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "firewall_policies" (
    "id" UUID NOT NULL,
    "organization_id" UUID NOT NULL,
    "name" VARCHAR(120) NOT NULL,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "firewall_policies_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "policy_versions" (
    "id" UUID NOT NULL,
    "organization_id" UUID NOT NULL,
    "policy_id" UUID NOT NULL,
    "version" INTEGER NOT NULL,
    "state" "PolicyState" NOT NULL DEFAULT 'DRAFT',
    "checksum" CHAR(64),
    "target" JSONB NOT NULL,
    "created_by" UUID NOT NULL,
    "sealed_at" TIMESTAMPTZ(3),
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "policy_versions_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "firewall_rules" (
    "id" UUID NOT NULL,
    "organization_id" UUID NOT NULL,
    "policy_version_id" UUID NOT NULL,
    "cidr" INET NOT NULL,
    "action" "RuleAction" NOT NULL,
    "direction" "Direction" NOT NULL,
    "protocol" "Protocol" NOT NULL,
    "port_start" INTEGER,
    "port_end" INTEGER,
    "expires_at" TIMESTAMPTZ(3),
    "reason" VARCHAR(1000) NOT NULL,

    CONSTRAINT "firewall_rules_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "policy_deployments" (
    "id" UUID NOT NULL,
    "organization_id" UUID NOT NULL,
    "policy_version_id" UUID NOT NULL,
    "state" "DeploymentState" NOT NULL DEFAULT 'PENDING_APPROVAL',
    "target_checksum" CHAR(64) NOT NULL,
    "requested_by" UUID NOT NULL,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "completed_at" TIMESTAMPTZ(3),

    CONSTRAINT "policy_deployments_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "approval_requests" (
    "id" UUID NOT NULL,
    "organization_id" UUID NOT NULL,
    "deployment_id" UUID NOT NULL,
    "requester_id" UUID NOT NULL,
    "approver_id" UUID,
    "state" "ApprovalState" NOT NULL DEFAULT 'PENDING',
    "reason" VARCHAR(1000),
    "expires_at" TIMESTAMPTZ(3) NOT NULL,
    "decided_at" TIMESTAMPTZ(3),

    CONSTRAINT "approval_requests_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "deployment_targets" (
    "id" UUID NOT NULL,
    "organization_id" UUID NOT NULL,
    "deployment_id" UUID NOT NULL,
    "server_id" UUID NOT NULL,
    "state" "TargetState" NOT NULL DEFAULT 'PENDING',
    "is_canary" BOOLEAN NOT NULL DEFAULT false,
    "error_code" TEXT,
    "observed_hash" CHAR(64),
    "verified_at" TIMESTAMPTZ(3),
    "rollback_state" JSONB,

    CONSTRAINT "deployment_targets_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "agent_jobs" (
    "id" UUID NOT NULL,
    "organization_id" UUID NOT NULL,
    "target_id" UUID NOT NULL,
    "idempotency_key" TEXT NOT NULL,
    "operation" VARCHAR(40) NOT NULL,
    "payload" JSONB NOT NULL,
    "state" "JobState" NOT NULL DEFAULT 'PENDING',
    "attempts" INTEGER NOT NULL DEFAULT 0,
    "lease_until" TIMESTAMPTZ(3),
    "expires_at" TIMESTAMPTZ(3) NOT NULL,
    "result" JSONB,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "agent_jobs_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "security_events" (
    "id" UUID NOT NULL,
    "organization_id" UUID NOT NULL,
    "server_id" UUID NOT NULL,
    "source_event_id" TEXT NOT NULL,
    "schema_version" INTEGER NOT NULL DEFAULT 1,
    "kind" VARCHAR(80) NOT NULL,
    "severity" "Severity" NOT NULL,
    "occurred_at" TIMESTAMPTZ(3) NOT NULL,
    "received_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "payload" JSONB NOT NULL,

    CONSTRAINT "security_events_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "incidents" (
    "id" UUID NOT NULL,
    "organization_id" UUID NOT NULL,
    "title" VARCHAR(250) NOT NULL,
    "severity" "Severity" NOT NULL,
    "state" "IncidentState" NOT NULL DEFAULT 'OPEN',
    "evidence" JSONB NOT NULL,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "resolved_at" TIMESTAMPTZ(3),

    CONSTRAINT "incidents_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "audit_logs" (
    "id" UUID NOT NULL,
    "organization_id" UUID NOT NULL,
    "actor_id" UUID,
    "action" VARCHAR(100) NOT NULL,
    "resource_id" TEXT,
    "request_id" UUID NOT NULL,
    "metadata" JSONB NOT NULL DEFAULT '{}',
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "audit_logs_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "notifications" (
    "id" UUID NOT NULL,
    "organization_id" UUID NOT NULL,
    "deduplication_key" TEXT NOT NULL,
    "channel" VARCHAR(20) NOT NULL,
    "destination_ref" TEXT NOT NULL,
    "state" "DeliveryState" NOT NULL DEFAULT 'PENDING',
    "attempts" INTEGER NOT NULL DEFAULT 0,
    "next_attempt_at" TIMESTAMPTZ(3),
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "notifications_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "outbox_events" (
    "id" UUID NOT NULL,
    "organization_id" UUID NOT NULL,
    "topic" VARCHAR(80) NOT NULL,
    "payload" JSONB NOT NULL,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "published_at" TIMESTAMPTZ(3),
    "attempts" INTEGER NOT NULL DEFAULT 0,

    CONSTRAINT "outbox_events_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "users_email_key" ON "users"("email");

CREATE INDEX "memberships_user_id_idx" ON "memberships"("user_id");

CREATE UNIQUE INDEX "sessions_access_hash_key" ON "sessions"("access_hash");

CREATE UNIQUE INDEX "sessions_refresh_hash_key" ON "sessions"("refresh_hash");

CREATE INDEX "sessions_family_id_idx" ON "sessions"("family_id");

CREATE INDEX "sessions_user_id_expires_at_idx" ON "sessions"("user_id", "expires_at");

CREATE UNIQUE INDEX "mfa_recovery_codes_code_hash_key" ON "mfa_recovery_codes"("code_hash");

CREATE INDEX "mfa_recovery_codes_user_id_idx" ON "mfa_recovery_codes"("user_id");

CREATE UNIQUE INDEX "invitations_token_hash_key" ON "invitations"("token_hash");

CREATE INDEX "invitations_organization_id_email_idx" ON "invitations"("organization_id", "email");

CREATE INDEX "servers_organization_id_last_heartbeat_at_idx" ON "servers"("organization_id", "last_heartbeat_at");

CREATE UNIQUE INDEX "servers_organization_id_id_key" ON "servers"("organization_id", "id");

CREATE UNIQUE INDEX "server_groups_organization_id_id_key" ON "server_groups"("organization_id", "id");

CREATE UNIQUE INDEX "server_groups_organization_id_name_key" ON "server_groups"("organization_id", "name");

CREATE UNIQUE INDEX "agent_credentials_certificate_fingerprint_key" ON "agent_credentials"("certificate_fingerprint");

CREATE UNIQUE INDEX "agent_credentials_certificate_serial_key" ON "agent_credentials"("certificate_serial");

CREATE INDEX "agent_credentials_organization_id_server_id_idx" ON "agent_credentials"("organization_id", "server_id");

CREATE UNIQUE INDEX "enrollment_tokens_token_hash_key" ON "enrollment_tokens"("token_hash");

CREATE UNIQUE INDEX "firewall_policies_organization_id_id_key" ON "firewall_policies"("organization_id", "id");

CREATE UNIQUE INDEX "policy_versions_organization_id_id_key" ON "policy_versions"("organization_id", "id");

CREATE UNIQUE INDEX "policy_versions_organization_id_policy_id_version_key" ON "policy_versions"("organization_id", "policy_id", "version");

CREATE INDEX "firewall_rules_organization_id_policy_version_id_idx" ON "firewall_rules"("organization_id", "policy_version_id");

CREATE INDEX "policy_deployments_organization_id_created_at_idx" ON "policy_deployments"("organization_id", "created_at");

CREATE UNIQUE INDEX "policy_deployments_organization_id_id_key" ON "policy_deployments"("organization_id", "id");

CREATE UNIQUE INDEX "approval_requests_deployment_id_key" ON "approval_requests"("deployment_id");

CREATE INDEX "approval_requests_organization_id_state_idx" ON "approval_requests"("organization_id", "state");

CREATE UNIQUE INDEX "approval_requests_organization_id_deployment_id_key" ON "approval_requests"("organization_id", "deployment_id");

CREATE UNIQUE INDEX "deployment_targets_organization_id_id_key" ON "deployment_targets"("organization_id", "id");

CREATE UNIQUE INDEX "deployment_targets_deployment_id_server_id_key" ON "deployment_targets"("deployment_id", "server_id");

CREATE UNIQUE INDEX "agent_jobs_idempotency_key_key" ON "agent_jobs"("idempotency_key");

CREATE INDEX "agent_jobs_state_lease_until_idx" ON "agent_jobs"("state", "lease_until");

CREATE INDEX "security_events_organization_id_occurred_at_idx" ON "security_events"("organization_id", "occurred_at");

CREATE UNIQUE INDEX "security_events_organization_id_server_id_source_event_id_key" ON "security_events"("organization_id", "server_id", "source_event_id");

CREATE INDEX "incidents_organization_id_state_created_at_idx" ON "incidents"("organization_id", "state", "created_at");

CREATE INDEX "audit_logs_organization_id_created_at_id_idx" ON "audit_logs"("organization_id", "created_at", "id");

CREATE UNIQUE INDEX "notifications_deduplication_key_key" ON "notifications"("deduplication_key");

CREATE INDEX "notifications_state_next_attempt_at_idx" ON "notifications"("state", "next_attempt_at");

CREATE INDEX "outbox_events_published_at_created_at_idx" ON "outbox_events"("published_at", "created_at");

ALTER TABLE "memberships" ADD CONSTRAINT "memberships_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "organizations"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "memberships" ADD CONSTRAINT "memberships_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "sessions" ADD CONSTRAINT "sessions_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "mfa_recovery_codes" ADD CONSTRAINT "mfa_recovery_codes_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "invitations" ADD CONSTRAINT "invitations_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "organizations"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "servers" ADD CONSTRAINT "servers_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "organizations"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "server_groups" ADD CONSTRAINT "server_groups_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "organizations"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "server_group_members" ADD CONSTRAINT "server_group_members_organization_id_group_id_fkey" FOREIGN KEY ("organization_id", "group_id") REFERENCES "server_groups"("organization_id", "id") ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "server_group_members" ADD CONSTRAINT "server_group_members_organization_id_server_id_fkey" FOREIGN KEY ("organization_id", "server_id") REFERENCES "servers"("organization_id", "id") ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "agent_credentials" ADD CONSTRAINT "agent_credentials_organization_id_server_id_fkey" FOREIGN KEY ("organization_id", "server_id") REFERENCES "servers"("organization_id", "id") ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "enrollment_tokens" ADD CONSTRAINT "enrollment_tokens_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "organizations"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "enrollment_tokens" ADD CONSTRAINT "enrollment_tokens_organization_id_server_id_fkey" FOREIGN KEY ("organization_id", "server_id") REFERENCES "servers"("organization_id", "id") ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "firewall_policies" ADD CONSTRAINT "firewall_policies_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "organizations"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "policy_versions" ADD CONSTRAINT "policy_versions_organization_id_policy_id_fkey" FOREIGN KEY ("organization_id", "policy_id") REFERENCES "firewall_policies"("organization_id", "id") ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "firewall_rules" ADD CONSTRAINT "firewall_rules_organization_id_policy_version_id_fkey" FOREIGN KEY ("organization_id", "policy_version_id") REFERENCES "policy_versions"("organization_id", "id") ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "policy_deployments" ADD CONSTRAINT "policy_deployments_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "organizations"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "policy_deployments" ADD CONSTRAINT "policy_deployments_organization_id_policy_version_id_fkey" FOREIGN KEY ("organization_id", "policy_version_id") REFERENCES "policy_versions"("organization_id", "id") ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "approval_requests" ADD CONSTRAINT "approval_requests_organization_id_deployment_id_fkey" FOREIGN KEY ("organization_id", "deployment_id") REFERENCES "policy_deployments"("organization_id", "id") ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "deployment_targets" ADD CONSTRAINT "deployment_targets_organization_id_deployment_id_fkey" FOREIGN KEY ("organization_id", "deployment_id") REFERENCES "policy_deployments"("organization_id", "id") ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "deployment_targets" ADD CONSTRAINT "deployment_targets_organization_id_server_id_fkey" FOREIGN KEY ("organization_id", "server_id") REFERENCES "servers"("organization_id", "id") ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "agent_jobs" ADD CONSTRAINT "agent_jobs_organization_id_target_id_fkey" FOREIGN KEY ("organization_id", "target_id") REFERENCES "deployment_targets"("organization_id", "id") ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "security_events" ADD CONSTRAINT "security_events_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "organizations"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "security_events" ADD CONSTRAINT "security_events_organization_id_server_id_fkey" FOREIGN KEY ("organization_id", "server_id") REFERENCES "servers"("organization_id", "id") ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "incidents" ADD CONSTRAINT "incidents_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "organizations"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "audit_logs" ADD CONSTRAINT "audit_logs_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "organizations"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "audit_logs" ADD CONSTRAINT "audit_logs_actor_id_fkey" FOREIGN KEY ("actor_id") REFERENCES "users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "notifications" ADD CONSTRAINT "notifications_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "organizations"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "outbox_events" ADD CONSTRAINT "outbox_events_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "organizations"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

