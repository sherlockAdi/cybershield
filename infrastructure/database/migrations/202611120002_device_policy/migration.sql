ALTER TABLE servers ADD COLUMN device_policy_requested BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE servers ADD COLUMN device_policy_actor UUID;
ALTER TABLE servers ADD COLUMN device_policy_report JSONB;
ALTER TABLE servers ADD COLUMN device_policy_received_at TIMESTAMPTZ(3);
ALTER TABLE servers ADD COLUMN device_policy_supported BOOLEAN NOT NULL DEFAULT false;
