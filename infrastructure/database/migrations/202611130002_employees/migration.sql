CREATE TABLE employees (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES organizations(id),
  name text NOT NULL,
  email text NOT NULL,
  aadhaar_reviewed_at timestamptz,
  pan_reviewed_at timestamptz,
  UNIQUE (organization_id, email)
);
