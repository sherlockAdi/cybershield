CREATE TABLE device_screenshots (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL,
  server_id uuid NOT NULL,
  captured_at timestamptz NOT NULL,
  ciphertext text NOT NULL,
  FOREIGN KEY (organization_id, server_id) REFERENCES servers (organization_id, id) ON DELETE CASCADE
);

CREATE INDEX device_screenshots_device_date ON device_screenshots (organization_id, server_id, captured_at DESC, id DESC);
CREATE INDEX device_screenshots_expiry ON device_screenshots (captured_at);

INSERT INTO device_screenshots (organization_id, server_id, captured_at, ciphertext)
SELECT organization_id, id, screen_captured_at, screen_ciphertext FROM servers
WHERE screen_ciphertext IS NOT NULL AND screen_captured_at >= now() - interval '72 hours';
