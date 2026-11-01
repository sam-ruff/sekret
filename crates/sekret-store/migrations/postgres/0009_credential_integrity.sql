-- Credentials are authenticated under the integrity key, which is kept wrapped under the root key.
-- Rows from before have no MAC until the first unlock vouches for them.
ALTER TABLE access_tokens ADD COLUMN mac TEXT;
ALTER TABLE client_secrets ADD COLUMN mac TEXT;
ALTER TABLE identity_auth_methods ADD COLUMN mac TEXT;
ALTER TABLE cli_logins ADD COLUMN approval_mac TEXT;

-- A plain hash for the few routes open while sealed, when the integrity key is out of reach.
-- Tokens were stored under exactly this hash until now.
ALTER TABLE access_tokens ADD COLUMN sealed_hash TEXT;
UPDATE access_tokens SET sealed_hash = token_hash;
CREATE INDEX access_tokens_sealed_hash ON access_tokens(sealed_hash);

-- Machine tokens minted before 0002 name no credential, so revoking theirs would miss them.
UPDATE access_tokens SET revoked = 1 WHERE kind = 'machine' AND source = '';
