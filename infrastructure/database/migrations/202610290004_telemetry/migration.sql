ALTER TABLE servers ADD COLUMN architecture VARCHAR(32);
ALTER TABLE servers ADD COLUMN logical_cpu_count INTEGER;
ALTER TABLE servers ADD CONSTRAINT servers_cpu_count CHECK (logical_cpu_count IS NULL OR logical_cpu_count BETWEEN 1 AND 65536);
ALTER TABLE security_events ADD COLUMN event_hash CHAR(64);
CREATE INDEX security_events_organization_id_received_at_id_idx ON security_events(organization_id,received_at,id);
CREATE INDEX security_events_organization_id_server_id_received_at_idx ON security_events(organization_id,server_id,received_at);
CREATE UNIQUE INDEX agent_credentials_server_identity_key ON agent_credentials(organization_id,server_id,id);
CREATE TABLE metric_samples (
  id UUID PRIMARY KEY,
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT ON UPDATE CASCADE,
  server_id UUID NOT NULL,
  credential_id UUID NOT NULL,
  sequence BIGINT NOT NULL CHECK (sequence > 0 AND sequence <= 9007199254740991),
  cpu_percent DOUBLE PRECISION CHECK (cpu_percent IS NULL OR cpu_percent BETWEEN 0 AND 100),
  memory_total_bytes BIGINT,
  memory_used_bytes BIGINT,
  disk_total_bytes BIGINT,
  disk_used_bytes BIGINT,
  sampled_at TIMESTAMPTZ(3) NOT NULL,
  received_at TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT metric_memory_range CHECK (
    (memory_total_bytes IS NULL AND memory_used_bytes IS NULL) OR
    (memory_total_bytes IS NOT NULL AND memory_used_bytes IS NOT NULL AND memory_total_bytes BETWEEN 1 AND 9007199254740991 AND memory_used_bytes BETWEEN 0 AND memory_total_bytes)
  ),
  CONSTRAINT metric_disk_range CHECK (
    (disk_total_bytes IS NULL AND disk_used_bytes IS NULL) OR
    (disk_total_bytes IS NOT NULL AND disk_used_bytes IS NOT NULL AND disk_total_bytes BETWEEN 1 AND 9007199254740991 AND disk_used_bytes BETWEEN 0 AND disk_total_bytes)
  ),
  CONSTRAINT metric_samples_organization_id_server_id_fkey FOREIGN KEY (organization_id,server_id) REFERENCES servers(organization_id,id) ON DELETE RESTRICT ON UPDATE CASCADE,
  CONSTRAINT metric_samples_identity_fkey FOREIGN KEY (organization_id,server_id,credential_id) REFERENCES agent_credentials(organization_id,server_id,id) ON DELETE RESTRICT ON UPDATE CASCADE
);
CREATE UNIQUE INDEX metric_samples_credential_id_sequence_key ON metric_samples(credential_id,sequence);
CREATE INDEX metric_samples_organization_id_server_id_received_at_idx ON metric_samples(organization_id,server_id,received_at);
CREATE INDEX metric_samples_organization_id_received_at_idx ON metric_samples(organization_id,received_at);
