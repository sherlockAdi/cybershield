CREATE TABLE document_vaults (
 organization_id uuid NOT NULL REFERENCES organizations(id), user_id uuid NOT NULL REFERENCES users(id),
 salt text NOT NULL, wrapped_key jsonb NOT NULL, created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(organization_id,user_id)
);
CREATE TABLE encrypted_documents (
 id uuid PRIMARY KEY, organization_id uuid NOT NULL, user_id uuid NOT NULL,
 wrapped_key jsonb NOT NULL, metadata jsonb NOT NULL, ciphertext_size integer NOT NULL CHECK(ciphertext_size BETWEEN 17 AND 5242896),
 chunk_count integer NOT NULL CHECK(chunk_count BETWEEN 1 AND 107),
 ready boolean NOT NULL DEFAULT false, created_at timestamptz NOT NULL DEFAULT now(),
 FOREIGN KEY(organization_id,user_id) REFERENCES document_vaults(organization_id,user_id)
);
CREATE INDEX encrypted_documents_owner_idx ON encrypted_documents(organization_id,user_id,created_at DESC);
CREATE TABLE document_chunks (
 document_id uuid NOT NULL REFERENCES encrypted_documents(id) ON DELETE CASCADE,
 chunk_index integer NOT NULL CHECK(chunk_index BETWEEN 0 AND 106),
 ciphertext text NOT NULL CHECK(length(ciphertext) BETWEEN 4 AND 65536),
 PRIMARY KEY(document_id,chunk_index)
);
CREATE TABLE document_links (
 id uuid PRIMARY KEY, document_id uuid NOT NULL REFERENCES encrypted_documents(id) ON DELETE CASCADE,
 token_hash text NOT NULL UNIQUE, created_at timestamptz NOT NULL DEFAULT now(),
 expires_at timestamptz NOT NULL, revoked_at timestamptz
);
CREATE INDEX document_links_document_idx ON document_links(document_id);
