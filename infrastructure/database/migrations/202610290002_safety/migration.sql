ALTER TABLE users ADD CONSTRAINT users_email_normalized CHECK (email = lower(trim(email)));
ALTER TABLE users ADD CONSTRAINT users_mfa_secret_required CHECK (NOT mfa_enabled OR mfa_secret_encrypted IS NOT NULL);
ALTER TABLE sessions ADD CONSTRAINT sessions_expiration_order CHECK (access_expires_at <= expires_at);
ALTER TABLE policy_versions ADD CONSTRAINT policy_versions_positive_version CHECK (version > 0);
ALTER TABLE policy_versions ADD CONSTRAINT policy_versions_sealed CHECK (state = 'DRAFT' OR (sealed_at IS NOT NULL AND checksum IS NOT NULL));
ALTER TABLE firewall_rules ADD CONSTRAINT firewall_rules_ports CHECK (
  (protocol = 'ICMP' AND port_start IS NULL AND port_end IS NULL) OR
  (protocol IN ('TCP','UDP') AND port_start IS NOT NULL AND port_end IS NOT NULL AND port_start BETWEEN 1 AND 65535 AND port_end BETWEEN port_start AND 65535)
);
ALTER TABLE firewall_rules ADD CONSTRAINT firewall_rules_reason CHECK (length(trim(reason)) > 0);
ALTER TABLE firewall_rules ADD CONSTRAINT firewall_rules_canonical_network CHECK (cidr = network(cidr)::inet);
ALTER TABLE approval_requests ADD CONSTRAINT approval_requests_distinct_approver CHECK (approver_id IS NULL OR approver_id <> requester_id);
ALTER TABLE approval_requests ADD CONSTRAINT approval_requests_decision CHECK (
  (state IN ('PENDING','EXPIRED') AND approver_id IS NULL AND decided_at IS NULL) OR
  (state IN ('APPROVED','REJECTED') AND approver_id IS NOT NULL AND decided_at IS NOT NULL)
);
ALTER TABLE agent_jobs ADD CONSTRAINT agent_jobs_operation CHECK (operation IN ('APPLY_POLICY','INSPECT_POLICY','ROLLBACK_POLICY'));
ALTER TABLE agent_jobs ADD CONSTRAINT agent_jobs_attempts CHECK (attempts >= 0);
ALTER TABLE notifications ADD CONSTRAINT notifications_attempts CHECK (attempts >= 0);
ALTER TABLE invitations ADD CONSTRAINT invitations_email_normalized CHECK (email = lower(trim(email)));
ALTER TABLE invitations ADD CONSTRAINT invitations_issuer_fk FOREIGN KEY (invited_by) REFERENCES users(id) ON DELETE RESTRICT;
ALTER TABLE enrollment_tokens ADD CONSTRAINT enrollment_tokens_creator_fk FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE RESTRICT;
ALTER TABLE policy_versions ADD CONSTRAINT policy_versions_creator_fk FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE RESTRICT;
ALTER TABLE policy_deployments ADD CONSTRAINT policy_deployments_requester_fk FOREIGN KEY (requested_by) REFERENCES users(id) ON DELETE RESTRICT;
ALTER TABLE approval_requests ADD CONSTRAINT approval_requests_requester_fk FOREIGN KEY (requester_id) REFERENCES users(id) ON DELETE RESTRICT;
ALTER TABLE approval_requests ADD CONSTRAINT approval_requests_approver_fk FOREIGN KEY (approver_id) REFERENCES users(id) ON DELETE RESTRICT;

CREATE FUNCTION reject_audit_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'audit_logs are append-only' USING ERRCODE = '42501';
END;
$$;
CREATE TRIGGER audit_logs_append_only BEFORE UPDATE OR DELETE ON audit_logs FOR EACH ROW EXECUTE FUNCTION reject_audit_mutation();

CREATE FUNCTION protect_sealed_policy() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF OLD.sealed_at IS NOT NULL THEN
    IF TG_OP = 'DELETE' THEN
      RAISE EXCEPTION 'sealed policy versions cannot be deleted' USING ERRCODE = '42501';
    END IF;
    IF (to_jsonb(NEW) - 'state') IS DISTINCT FROM (to_jsonb(OLD) - 'state') THEN
      RAISE EXCEPTION 'sealed policy content is immutable' USING ERRCODE = '42501';
    END IF;
  END IF;
  IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER sealed_policy_content BEFORE UPDATE OR DELETE ON policy_versions FOR EACH ROW EXECUTE FUNCTION protect_sealed_policy();

CREATE FUNCTION protect_sealed_rules() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
  version_key UUID;
  tenant_key UUID;
  version_sealed_at TIMESTAMPTZ;
BEGIN
  IF TG_OP <> 'INSERT' THEN
    version_key := OLD.policy_version_id;
    tenant_key := OLD.organization_id;
    SELECT sealed_at INTO version_sealed_at FROM policy_versions WHERE id=version_key AND organization_id=tenant_key FOR UPDATE;
    IF version_sealed_at IS NOT NULL THEN RAISE EXCEPTION 'sealed policy rules are immutable' USING ERRCODE = '42501'; END IF;
  END IF;
  IF TG_OP <> 'DELETE' THEN
    version_key := NEW.policy_version_id;
    tenant_key := NEW.organization_id;
    SELECT sealed_at INTO version_sealed_at FROM policy_versions WHERE id=version_key AND organization_id=tenant_key FOR UPDATE;
    IF version_sealed_at IS NOT NULL THEN RAISE EXCEPTION 'sealed policy rules are immutable' USING ERRCODE = '42501'; END IF;
  END IF;
  IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER sealed_policy_rules BEFORE INSERT OR UPDATE OR DELETE ON firewall_rules FOR EACH ROW EXECUTE FUNCTION protect_sealed_rules();
