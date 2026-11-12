ALTER TABLE servers ADD COLUMN screen_config JSONB NOT NULL DEFAULT '{"enabled":false,"intervalSeconds":5,"revision":0}';
ALTER TABLE servers ADD COLUMN screen_ciphertext TEXT;
ALTER TABLE servers ADD COLUMN screen_captured_at TIMESTAMPTZ(3);
ALTER TABLE servers ADD COLUMN screen_received_at TIMESTAMPTZ(3);
