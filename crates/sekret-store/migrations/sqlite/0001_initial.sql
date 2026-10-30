CREATE TABLE meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE users (
    id TEXT PRIMARY KEY,
    subject TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL DEFAULT '',
    name TEXT NOT NULL DEFAULT '',
    groups TEXT NOT NULL DEFAULT '[]',
    disabled INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    last_login_at INTEGER NOT NULL
);

CREATE TABLE identities (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    token_ttl INTEGER NOT NULL,
    token_max_ttl INTEGER NOT NULL,
    trusted_cidrs TEXT NOT NULL DEFAULT '[]',
    disabled INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL
);

CREATE TABLE identity_auth_methods (
    identity_id TEXT NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    config TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (identity_id, kind)
);

CREATE TABLE client_secrets (
    id TEXT PRIMARY KEY,
    identity_id TEXT NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
    description TEXT NOT NULL DEFAULT '',
    secret_hash TEXT NOT NULL UNIQUE,
    prefix TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER,
    uses_remaining INTEGER,
    revoked INTEGER NOT NULL DEFAULT 0,
    last_used_at INTEGER
);

CREATE TABLE access_tokens (
    id TEXT PRIMARY KEY,
    token_hash TEXT NOT NULL UNIQUE,
    kind TEXT NOT NULL,
    principal_kind TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    max_expires_at INTEGER NOT NULL,
    revoked INTEGER NOT NULL DEFAULT 0,
    last_used_at INTEGER
);
CREATE INDEX access_tokens_principal ON access_tokens(principal_kind, principal_id);

CREATE TABLE org_bindings (
    principal_kind TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    role_slug TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (principal_kind, principal_id, role_slug)
);

CREATE TABLE projects (
    id TEXT PRIMARY KEY,
    slug TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    wrapped_key BLOB NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE TABLE roles (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    slug TEXT NOT NULL,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    rules TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    UNIQUE (project_id, slug)
);

CREATE TABLE project_memberships (
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    principal_kind TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    role_slug TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (project_id, principal_kind, principal_id, role_slug)
);

CREATE TABLE environments (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    slug TEXT NOT NULL,
    name TEXT NOT NULL,
    position INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    UNIQUE (project_id, slug)
);

CREATE TABLE folders (
    environment_id TEXT NOT NULL REFERENCES environments(id) ON DELETE CASCADE,
    path TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (environment_id, path)
);

CREATE TABLE secrets (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    environment_id TEXT NOT NULL REFERENCES environments(id) ON DELETE CASCADE,
    path TEXT NOT NULL,
    key TEXT NOT NULL,
    current_version INTEGER NOT NULL,
    deleted INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    UNIQUE (environment_id, path, key)
);

CREATE TABLE secret_versions (
    secret_id TEXT NOT NULL REFERENCES secrets(id) ON DELETE CASCADE,
    version INTEGER NOT NULL,
    value BLOB,
    comment TEXT NOT NULL DEFAULT '',
    tags TEXT NOT NULL DEFAULT '[]',
    deleted INTEGER NOT NULL DEFAULT 0,
    actor TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (secret_id, version)
);

CREATE TABLE snapshots (
    id TEXT PRIMARY KEY,
    environment_id TEXT NOT NULL REFERENCES environments(id) ON DELETE CASCADE,
    entries TEXT NOT NULL,
    reason TEXT NOT NULL,
    actor TEXT NOT NULL,
    created_at INTEGER NOT NULL
);
CREATE INDEX snapshots_environment ON snapshots(environment_id, created_at);

CREATE TABLE audit_log (
    id TEXT PRIMARY KEY,
    created_at INTEGER NOT NULL,
    actor_kind TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_name TEXT NOT NULL,
    action TEXT NOT NULL,
    project_id TEXT,
    environment TEXT,
    path TEXT,
    secret_key TEXT,
    detail TEXT NOT NULL DEFAULT '{}',
    ip TEXT NOT NULL DEFAULT ''
);
CREATE INDEX audit_log_project ON audit_log(project_id, created_at);

CREATE TABLE login_states (
    state TEXT PRIMARY KEY,
    nonce TEXT NOT NULL,
    pkce_verifier TEXT NOT NULL,
    return_to TEXT NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE TABLE cli_logins (
    device_code_hash TEXT PRIMARY KEY,
    user_code TEXT NOT NULL UNIQUE,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    approved_user_id TEXT,
    consumed INTEGER NOT NULL DEFAULT 0
);
