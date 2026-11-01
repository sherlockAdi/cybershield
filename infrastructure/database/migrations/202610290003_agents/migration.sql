ALTER TABLE servers ADD COLUMN uptime_seconds BIGINT;
ALTER TABLE servers ADD CONSTRAINT servers_uptime_nonnegative CHECK (uptime_seconds IS NULL OR uptime_seconds >= 0);
ALTER TABLE agent_credentials ALTER COLUMN certificate_fingerprint DROP NOT NULL;
ALTER TABLE agent_credentials ALTER COLUMN certificate_serial DROP NOT NULL;
ALTER TABLE agent_credentials ADD COLUMN public_key_pem TEXT;
ALTER TABLE agent_credentials ADD COLUMN key_fingerprint CHAR(64);
ALTER TABLE agent_credentials ADD COLUMN last_sequence BIGINT NOT NULL DEFAULT 0;
ALTER TABLE agent_credentials ADD CONSTRAINT agent_sequence_nonnegative CHECK (last_sequence >= 0);
ALTER TABLE agent_credentials ADD CONSTRAINT agent_identity_required CHECK (
  (public_key_pem IS NOT NULL AND key_fingerprint IS NOT NULL) OR
  (certificate_fingerprint IS NOT NULL AND certificate_serial IS NOT NULL)
);
CREATE UNIQUE INDEX agent_credentials_key_fingerprint_key ON agent_credentials(key_fingerprint);
CREATE UNIQUE INDEX agent_credentials_organization_id_id_key ON agent_credentials(organization_id,id);
ALTER TABLE enrollment_tokens ADD COLUMN revoked_at TIMESTAMPTZ(3);
ALTER TABLE enrollment_tokens ADD COLUMN credential_id UUID;
ALTER TABLE enrollment_tokens ADD CONSTRAINT enrollment_tokens_organization_id_credential_id_fkey
  FOREIGN KEY (organization_id,credential_id) REFERENCES agent_credentials(organization_id,id) ON DELETE RESTRICT ON UPDATE CASCADE;
