ALTER TABLE servers ADD COLUMN management_snapshot jsonb;
ALTER TABLE servers ADD COLUMN management_received_at timestamptz(3);
CREATE TABLE host_commands (
 id uuid PRIMARY KEY, organization_id uuid NOT NULL, server_id uuid NOT NULL,
 credential_id uuid NOT NULL, requested_by uuid NOT NULL REFERENCES users(id),
 operation varchar(24) NOT NULL CHECK(operation IN ('BLOCK_IP','UNBLOCK_IP','STOP_APPLICATION')),
 payload jsonb NOT NULL, state varchar(16) NOT NULL DEFAULT 'PENDING' CHECK(state IN ('PENDING','DISPATCHED','SUCCEEDED','FAILED','EXPIRED')),
 created_at timestamptz(3) NOT NULL DEFAULT now(), expires_at timestamptz(3) NOT NULL,
 completed_at timestamptz(3), message varchar(500),
 FOREIGN KEY(organization_id,server_id) REFERENCES servers(organization_id,id),
 FOREIGN KEY(organization_id,credential_id) REFERENCES agent_credentials(organization_id,id)
);
CREATE INDEX host_commands_server_idx ON host_commands(organization_id,server_id,created_at DESC,id DESC);
CREATE UNIQUE INDEX host_commands_one_active_idx ON host_commands(server_id) WHERE state IN ('PENDING','DISPATCHED');
CREATE INDEX activity_login_page_idx ON security_events(organization_id,server_id,occurred_at DESC,id DESC) WHERE kind IN ('AUTH_SUCCESS','AUTH_FAILURE');
