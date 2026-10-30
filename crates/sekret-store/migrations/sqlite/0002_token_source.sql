-- The credential a token was minted from, such as `client-secret:<id>`, so revoking it can revoke its tokens.
ALTER TABLE access_tokens ADD COLUMN source TEXT NOT NULL DEFAULT '';
CREATE INDEX access_tokens_source ON access_tokens(source);
