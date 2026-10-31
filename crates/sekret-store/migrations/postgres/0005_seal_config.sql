-- How the root key is kept: wrapped under a passphrase here, or in a key file. At most one row.
-- The root key fingerprint stays in meta.root_key_fingerprint.
CREATE TABLE seal_config (
    id BIGINT PRIMARY KEY CHECK (id = 1),
    mode TEXT NOT NULL,
    wrapped_root_key BYTEA,
    kdf_salt BYTEA,
    kdf_params TEXT,
    unlock_policy TEXT NOT NULL DEFAULT 'manual',
    remembered_root_key BYTEA,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL
);
