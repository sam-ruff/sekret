-- The seal configuration is authenticated under the root key; epoch counts changes to it.
ALTER TABLE seal_config ADD COLUMN epoch BIGINT NOT NULL DEFAULT 0;
ALTER TABLE seal_config ADD COLUMN config_mac BYTEA;

-- When the person behind a browser session last authenticated with the identity provider.
ALTER TABLE access_tokens ADD COLUMN auth_time BIGINT;
ALTER TABLE login_states ADD COLUMN max_age BIGINT;

-- backup-reader is now a built-in organisation role; a custom role of that name keeps its rules
-- under a new slug, and so do its bindings.
UPDATE org_bindings SET role_slug = 'backup-reader-custom'
WHERE role_slug = 'backup-reader'
  AND EXISTS (SELECT 1 FROM roles WHERE project_id = '' AND slug = 'backup-reader')
  AND NOT EXISTS (SELECT 1 FROM roles WHERE project_id = '' AND slug = 'backup-reader-custom');
UPDATE roles SET slug = 'backup-reader-custom'
WHERE project_id = '' AND slug = 'backup-reader'
  AND NOT EXISTS (SELECT 1 FROM roles WHERE project_id = '' AND slug = 'backup-reader-custom');
