# Configuration

`sekret server` takes every setting as a flag or as the `SEKRET_*` environment variable in the table below. Only two are required: the public URL and the root key file. Without an OIDC issuer the server still runs, but people can only get in with a token from `sekret admin bootstrap`.

## Server settings

| Flag | Environment variable | Default | What it does |
|---|---|---|---|
| `--public-url` | `SEKRET_PUBLIC_URL` | required | The URL people and machines use. Redirects and cookies are built from it, and cookies are marked `Secure` when it starts with `https://`. |
| `--root-key-file` | `SEKRET_ROOT_KEY_FILE` | required | File holding the 32-byte root key, raw, base64 or hex. |
| `--database-url` | `SEKRET_DATABASE_URL` | `sqlite://sekret.db?mode=rwc` | `sqlite://path?mode=rwc` or `postgres://user:pass@host/db`. |
| `--listen` | `SEKRET_LISTEN` | `0.0.0.0:8080` | Address and port for HTTP. |
| `--oidc-issuer` | `SEKRET_OIDC_ISSUER` | none | Issuer URL of your OIDC provider. Turns on browser sign-in. |
| `--oidc-client-id` | `SEKRET_OIDC_CLIENT_ID` | `sekret` | Client id registered with the provider. |
| `--oidc-client-secret-file` | `SEKRET_OIDC_CLIENT_SECRET_FILE` | none | File holding the client secret. |
| `--oidc-scopes` | `SEKRET_OIDC_SCOPES` | `openid profile email` | Scopes to request. |
| `--oidc-group-claims` | `SEKRET_OIDC_GROUP_CLAIMS` | `roles,groups` | Claims whose values become the user's groups. A name starting with `/` is a JSON pointer, such as `/realm_access/roles`. |
| `--oidc-admin-groups` | `SEKRET_OIDC_ADMIN_GROUPS` | `sekret-admin` | Groups that make someone an organisation admin. |
| `--oidc-required-groups` | `SEKRET_OIDC_REQUIRED_GROUPS` | none | When set, only members of one of these groups may sign in. |
| `--default-org-role` | `SEKRET_DEFAULT_ORG_ROLE` | `org-member` | Organisation role everyone who signs in receives. Empty for none. |
| `--session-ttl` | `SEKRET_SESSION_TTL` | `43200` | Browser session length in seconds. |
| `--cli-token-ttl` | `SEKRET_CLI_TOKEN_TTL` | `86400` | Lifetime of a `sekret login` token in seconds. It can be renewed up to seven times its lifetime. |
| `--trusted-proxies` | `SEKRET_TRUSTED_PROXIES` | none | CIDRs of reverse proxies whose `X-Forwarded-For` header is believed. |
| `--snapshots-to-keep` | `SEKRET_SNAPSHOTS_TO_KEEP` | `200` | Snapshots kept per environment. |
| `--login-rate-per-minute` | `SEKRET_LOGIN_RATE_PER_MINUTE` | `30` | Login attempts allowed per client address per minute. |
| `--allow-insecure-http` | `SEKRET_ALLOW_INSECURE_HTTP` | off | Allows `http://` OIDC issuers and Kubernetes API servers. For local testing only. |
| `--tls-cert-file` | `SEKRET_TLS_CERT_FILE` | none | PEM certificate chain. With `--tls-key-file`, the server speaks HTTPS itself. |
| `--tls-key-file` | `SEKRET_TLS_KEY_FILE` | none | PEM private key for the certificate. |
| `--tls-client-ca-file` | `SEKRET_TLS_CLIENT_CA_FILE` | none | PEM CA certificates that client certificates must chain to. Turns on mutual TLS. |
| `--tls-client-auth` | `SEKRET_TLS_CLIENT_AUTH` | `required` | With a client CA, `required` refuses connections without a certificate and `optional` only checks the ones offered. |

Lists such as `--oidc-admin-groups` take comma-separated values. Set `SEKRET_LOG` to a [tracing filter](https://docs.rs/tracing-subscriber/latest/tracing_subscriber/filter/struct.EnvFilter.html) such as `info` or `sekret_server=debug` to change logging; logs go to standard error.

## The root key

```sh
sekret admin generate-root-key > /etc/sekret/root.key
chmod 600 /etc/sekret/root.key
```

The root key wraps a separate data key for each project, and the data keys encrypt the values. The server records the key's fingerprint on first start and refuses to start with a different key, so pointing it at the wrong file fails loudly rather than producing unreadable data. Back the key up somewhere other than the database backups: the database without the key is useless, and the key without the database is harmless.

To replace the key, stop the server and run:

```sh
sekret admin generate-root-key > /etc/sekret/root.key.new
sekret admin rotate-root-key --root-key-file /etc/sekret/root.key --new-root-key-file /etc/sekret/root.key.new
mv /etc/sekret/root.key.new /etc/sekret/root.key
```

Rotation re-wraps every project key and every stored credential (such as Kubernetes reviewer tokens) in one transaction. Secret values themselves are not re-encrypted, because they are encrypted with the project keys, which do not change.

## Signing in with OIDC

Any provider that publishes `/.well-known/openid-configuration` works. sekret uses the authorisation code flow with PKCE and checks the ID token's issuer, audience, nonce, expiry and signature.

Register a confidential client with:

- redirect URI `https://sekret.example.com/auth/callback`;
- post-logout redirect URI `https://sekret.example.com`, exactly the public URL;
- PKCE method `S256`;
- a mapper that puts the user's groups or roles into the ID token.

Then start the server with:

```sh
sekret server \
  --public-url https://sekret.example.com \
  --root-key-file /etc/sekret/root.key \
  --oidc-issuer https://auth.example.com/realms/main \
  --oidc-client-secret-file /etc/sekret/oidc-client-secret \
  --oidc-admin-groups platform-admins
```

### Keycloak

In Keycloak, create a client called `sekret` with client authentication on, the standard flow enabled and the redirect URIs above. Add two mappers to the client's dedicated scope: an *Audience* mapper that adds `sekret` to the ID token, and a *User Realm Role* mapper with claim name `roles`, multivalued, added to the ID token. Realm roles then arrive in the `roles` claim, which is one of the defaults for `--oidc-group-claims`.

Group membership is copied from the token at each sign-in. Removing someone from a group in your provider takes effect at their next sign-in, or when their session expires, whichever comes first.

## Reverse proxies

sekret speaks plain HTTP and expects TLS to end at a reverse proxy in front of it. Set `--trusted-proxies` to the proxy's address so that rate limiting and machine identities' trusted CIDRs see the real client address; without it, every request appears to come from the proxy. Only the rightmost address in `X-Forwarded-For` that is not a trusted proxy is used.

## TLS and mutual TLS

The server can serve HTTPS itself, which suits a single host without a reverse proxy, or a setup that wants certificates checked all the way to sekret:

```sh
sekret server \
  --public-url https://sekret.example.com:8443 \
  --listen 0.0.0.0:8443 \
  --root-key-file /etc/sekret/root.key \
  --tls-cert-file /etc/sekret/tls/server.pem \
  --tls-key-file /etc/sekret/tls/server-key.pem \
  --tls-client-ca-file /etc/sekret/tls/clients-ca.pem
```

With `--tls-client-ca-file`, every connection must present a certificate issued by that CA, or the TLS handshake fails before any HTTP is exchanged. This is in addition to sekret's own sign-in, not instead of it: a client with a valid certificate still needs a token. Browsers prompt for a certificate from the user's store, so people using the web interface need one installed too. Use `--tls-client-auth optional` while rolling certificates out; certificates that are offered are still checked.

TLS 1.2 and 1.3 are supported, using rustls. The certificate files are read at start-up, so restart the server after renewing them.

Every client can present a certificate, whether sekret checks it or a reverse proxy in front of it does:

| Client | Settings |
|---|---|
| CLI | `--client-cert` and `--client-key`, or `SEKRET_CLIENT_CERT` and `SEKRET_CLIENT_KEY` |
| Kubernetes operator | The same flags and variables, or `sekret.clientCertificate.secretName` in the Helm chart, naming a `kubernetes.io/tls` Secret |
| Ansible | `client_cert` and `client_key`, or the same variables |

```sh
sekret whoami \
  --ca-file /etc/sekret/tls/server-ca.pem \
  --client-cert ~/.config/sekret/client.pem \
  --client-key ~/.config/sekret/client-key.pem
```

## CLI configuration

The CLI reads its server, project, environment and folder from, in order of priority: command-line flags, `SEKRET_URL`, `SEKRET_PROJECT`, `SEKRET_ENVIRONMENT` and `SEKRET_PATH`, then the nearest `.sekret.toml` in the current directory or a parent, then the server saved by `sekret login`.

```toml
# .sekret.toml
server = "https://sekret.example.com"
project = "web"
environment = "dev"
path = "/"
```

`sekret login` saves its token in `$XDG_CONFIG_HOME/sekret/credentials.toml` (usually `~/.config/sekret/`) with mode 0600, keyed by server. `SEKRET_TOKEN` overrides it. For a server with a certificate from a private CA, pass `--ca-file` or set `SEKRET_CA_FILE`.
