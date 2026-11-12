ALTER TABLE servers ADD COLUMN device_config JSONB;
ALTER TABLE servers ADD COLUMN device_revision INTEGER NOT NULL DEFAULT 0 CHECK (device_revision >= 0);
ALTER TABLE servers ADD COLUMN device_snapshot JSONB;
ALTER TABLE servers ADD COLUMN device_received_at TIMESTAMPTZ(3);
CREATE INDEX servers_devices_idx ON servers(organization_id,created_at,id) WHERE device_config IS NOT NULL;
