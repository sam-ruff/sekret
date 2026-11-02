-- Per-secret access: a project setting, off by default, a restricted flag on each secret, also
-- off by default, and the list of who may reach a restricted secret.
ALTER TABLE projects ADD COLUMN secret_access BIGINT NOT NULL DEFAULT 0;
ALTER TABLE secrets ADD COLUMN restricted BIGINT NOT NULL DEFAULT 0;
-- Goes up with every change to a secret's access, so a write planned before one is refused.
ALTER TABLE secrets ADD COLUMN access_epoch BIGINT NOT NULL DEFAULT 0;
-- Entries about restricted secrets, kept from readers off their lists.
ALTER TABLE audit_log ADD COLUMN restricted BIGINT NOT NULL DEFAULT 0;

CREATE TABLE secret_grants (
    secret_id TEXT NOT NULL REFERENCES secrets(id) ON DELETE CASCADE,
    principal_kind TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    actions TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    PRIMARY KEY (secret_id, principal_kind, principal_id)
);
CREATE INDEX secret_grants_principal ON secret_grants(principal_kind, principal_id);
CREATE INDEX secrets_restricted ON secrets(project_id, restricted);
