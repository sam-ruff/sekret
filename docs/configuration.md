# Configuration

`sekret server` reads its settings from a YAML file, from `SEKRET_*` environment variables and from flags. When the same setting appears in more than one place, a flag wins over an environment variable, which wins over the file, which wins over the built-in default. Only the public URL is required. Without an OIDC issuer the server still runs, but people can only get in with an admin token.

## The configuration file

Pass the file with `--config` or `SEKRET_CONFIG`. `sekret server --print-config` prints a commented example holding every setting and its default; the same file is in the repository as [`docs/sekret.example.yaml`](https://github.com/sam-ruff/sekret/blob/main/docs/sekret.example.yaml).

```yaml
server:
  public_url: https://sekret.example.com
  listen: 127.0.0.1:8080
  trusted_proxies: [127.0.0.1/32]
database:
  url: sqlite:///var/lib/sekret/sekret.db?mode=rwc
oidc:
  issuer: https://auth.example.com/realms/main
  client_secret_file: /etc/sekret/oidc-client-secret
  admin_groups: [platform-admins]
seal:
  mode: passphrase
  unlock: manual
setup:
  web: true
```

Unknown keys are an error, so a misspelt setting stops the server instead of being ignored. The file holds paths to secrets, never the secrets themselves.

## Every setting

| File key | Flag | Environment variable | Default | What it does |
|---|---|---|---|---|
| `server.public_url` | `--public-url` | `SEKRET_PUBLIC_URL` | required | The URL people and machines use. Redirects and cookies are built from it, and cookies are marked `Secure` when it starts with `https://`. |
| `server.listen` | `--listen` | `SEKRET_LISTEN` | `0.0.0.0:8080` | Address and port to listen on. |
| `server.trusted_proxies` | `--trusted-proxies` | `SEKRET_TRUSTED_PROXIES` | none | CIDRs of reverse proxies whose `X-Forwarded-For` header is believed. |
| `server.allow_insecure_http` | `--allow-insecure-http` | `SEKRET_ALLOW_INSECURE_HTTP` | `false` | Allows `http://` OIDC issuers and Kubernetes API servers. For local testing only. |
| `database.url` | `--database-url` | `SEKRET_DATABASE_URL` | `sqlite://sekret.db?mode=rwc` | `sqlite://path?mode=rwc` or `postgres://user:pass@host/db`. |
| `database.snapshots_to_keep` | `--snapshots-to-keep` | `SEKRET_SNAPSHOTS_TO_KEEP` | `200` | Snapshots kept per environment. |
| `auth.default_org_role` | `--default-org-role` | `SEKRET_DEFAULT_ORG_ROLE` | `org-member` | Organisation role everyone who signs in receives. Empty for none. |
| `auth.session_ttl` | `--session-ttl` | `SEKRET_SESSION_TTL` | `43200` | Browser session length in seconds. |
| `auth.cli_token_ttl` | `--cli-token-ttl` | `SEKRET_CLI_TOKEN_TTL` | `86400` | Lifetime of a `sekret login` token in seconds. It can be renewed up to seven times its lifetime, or not past it at all when `cli_login_max_auth_age` is set. |
| `auth.cli_login_max_auth_age` | `--cli-login-max-auth-age` | `SEKRET_CLI_LOGIN_MAX_AUTH_AGE` | unset | Seconds. Approving a `sekret login` needs a browser sign-in with the identity provider at most this old. See [CLI login re-authentication](#cli-login-re-authentication). |
| `auth.login_rate_per_minute` | `--login-rate-per-minute` | `SEKRET_LOGIN_RATE_PER_MINUTE` | `30` | Attempts allowed per client address (per /64 for IPv6) per minute. Sign-in has one allowance and setup, unlocking and passphrase changes have another, so using up one never blocks the other. |
| `oidc.issuer` | `--oidc-issuer` | `SEKRET_OIDC_ISSUER` | none | Issuer URL of your OIDC provider. Turns on browser sign-in. |
| `oidc.client_id` | `--oidc-client-id` | `SEKRET_OIDC_CLIENT_ID` | `sekret` | Client id registered with the provider. |
| `oidc.client_secret_file` | `--oidc-client-secret-file` | `SEKRET_OIDC_CLIENT_SECRET_FILE` | none | File holding the client secret. |
| `oidc.scopes` | `--oidc-scopes` | `SEKRET_OIDC_SCOPES` | `openid profile email` | Scopes to request. |
| `oidc.group_claims` | `--oidc-group-claims` | `SEKRET_OIDC_GROUP_CLAIMS` | `roles,groups` | Claims whose values become the user's groups. A name starting with `/` is a JSON pointer, such as `/realm_access/roles`. |
| `oidc.admin_groups` | `--oidc-admin-groups` | `SEKRET_OIDC_ADMIN_GROUPS` | `sekret-admin` | Groups that make someone an organisation admin. |
| `oidc.required_groups` | `--oidc-required-groups` | `SEKRET_OIDC_REQUIRED_GROUPS` | none | When set, only members of one of these groups may sign in. |
| `tls.cert_file` | `--tls-cert-file` | `SEKRET_TLS_CERT_FILE` | none | PEM certificate chain. With a key file, the server speaks HTTPS itself. |
| `tls.key_file` | `--tls-key-file` | `SEKRET_TLS_KEY_FILE` | none | PEM private key for the certificate. |
| `tls.client_ca_file` | `--tls-client-ca-file` | `SEKRET_TLS_CLIENT_CA_FILE` | none | PEM CA certificates that client certificates must chain to. Turns on mutual TLS. |
| `tls.client_auth` | `--tls-client-auth` | `SEKRET_TLS_CLIENT_AUTH` | `required` | With a client CA, `required` refuses connections without a certificate and `optional` only checks the ones offered. |
| `seal.mode` | `--seal-mode` | `SEKRET_SEAL_MODE` | unset | `passphrase` or `key-file`. Unset, setup offers passphrase mode and either kind of database starts. Set, a database in the other mode is refused. |
| `seal.root_key_file` | `--root-key-file` | `SEKRET_ROOT_KEY_FILE` | none | The root key file in key-file mode, raw, base64 or hex. |
| `seal.unlock` | `--unlock` | `SEKRET_UNLOCK` | unset | `manual`, `remember` or `passphrase-file`. Unset, the choice made at setup applies. See [Unlocking](unlocking.md). |
| `seal.remember_file` | `--remember-file` | `SEKRET_REMEMBER_FILE` | none | Device key file for the `remember` policy, which needs it set. It may not be the database, root key or a passphrase file. |
| `seal.remember_secret_file` | `--remember-secret-file` | `SEKRET_REMEMBER_SECRET_FILE` | none | File holding a secret of at least 32 characters mixed into the remember key, so the disk alone cannot unlock. `SEKRET_REMEMBER_SECRET` holding the value itself also works. See [Unlocking](unlocking.md#remember-secret). |
| `seal.passphrase_file` | `--unlock-passphrase-file` | `SEKRET_UNLOCK_PASSPHRASE_FILE` | none | Passphrase for the `passphrase-file` policy, read only under that policy. `SEKRET_UNLOCK_PASSPHRASE` holding the passphrase itself also works, but leaves a copy in `/proc/<pid>/environ`. |
| `setup.web` | `--web-setup` | `SEKRET_WEB_SETUP` | `true` | Offer first-boot setup through the API and web interface. When false, no setup code is made; set up with `auto_init` or `sekret admin init`. |
| `setup.auto_init` | `--auto-init` | `SEKRET_AUTO_INIT` | `false` | Set up an empty database at start, without a person. Skipped when the database already has a root key; refused when it holds projects or identities. |
| `setup.passphrase_file` | `--setup-passphrase-file` | `SEKRET_SETUP_PASSPHRASE_FILE` | none | First passphrase for `auto_init`, read only when the database is not set up yet. The server warns while the file still exists afterwards. |
| `setup.admin_token_file` | `--setup-admin-token-file` | `SEKRET_SETUP_ADMIN_TOKEN_FILE` | none | Where `auto_init` writes a one-hour admin token, mode 0600. It must not exist yet and its directory must be writable, checked before anything is set up. |
| `setup.code_file` | `--setup-code-file` | `SEKRET_SETUP_CODE_FILE` | none | Where to write the one-time setup code, mode 0600, as well as the log and standard error. Deleted once setup succeeds. |
| `backup.temp_dir` | `--backup-temp-dir` | `SEKRET_BACKUP_TEMP_DIR` | beside the SQLite database | Where API backups are staged, in a private 0700 directory. |
| | `--config` | `SEKRET_CONFIG` | none | The YAML file itself. |

Lists such as `--oidc-admin-groups` take comma-separated values on the command line and YAML lists in the file. Switches such as `--auto-init` can be given bare or as `--auto-init=false`; in the file they must be `true` or `false`, and `yes`, `no`, `on` and `off` are refused. Configuration errors give the line and column but never echo the value, so a password in a database URL does not end up in a log.

Every file the server reads (configuration, keys, passphrases, secrets) must be a regular file and is read with a size limit, 4 KiB for keys, passphrases and secrets, so pointing a setting at `/dev/zero` or a FIFO fails straight away. Key files may be symlinks, because Kubernetes mounts secrets that way; the remember file may not.

At start the server logs, at `info`, each seal, unlock and setup setting with its value (never a secret) and where it came from: flag, environment, file or default. It warns about settings that weaken it: `allow_insecure_http`, an `http://` public URL with a non-loopback listen address, trusted proxy ranges shorter than /8, the `passphrase-file` policy coming from the environment, and environment variables overriding unlock or setup settings in the file. Set `SEKRET_LOG` to a [tracing filter](https://docs.rs/tracing-subscriber/latest/tracing_subscriber/filter/struct.EnvFilter.html) such as `info` or `sekret_server=debug` to change logging; logs go to standard error.

The `admin` commands also accept `--config`, and take the database URL and root key file from it.

## First-boot setup

The root key wraps a separate data key for each project, and the data keys encrypt the values. On first start, with an empty database and no root key file, the server creates nothing yet. It starts *uninitialised*, prints a one-time setup code to its log and to standard error (so `SEKRET_LOG=warn` cannot hide it) and waits:

```text
INFO setup code: K7QM-3XRA-WH9P
INFO finish setting up at https://sekret.example.com/setup or with `sekret sys init`; a restart makes a new code
```

Open the setup page, or run `sekret sys init` from any machine that can reach the server, and give it the code. Setup asks for a passphrase and how the server should unlock after a restart, creates the root key, and prints a break-glass admin token that is valid for an hour and shown only once. The code lives only in memory and a restart replaces it, so set `setup.code_file` if whoever runs setup cannot read the log.

The root key is kept in one of two ways.

**Passphrase mode**, the default, wraps the root key under a key derived from your passphrase with Argon2id (256 MiB, three passes) and stores the result in the database. The root key exists unwrapped only in the server's memory. After a restart the server is *sealed*: it answers health checks and its status endpoint, and refuses everything else with 503 until it is unlocked. How it gets unlocked is the [unlock policy](unlocking.md). The passphrase must be at least 12 characters, contain no control characters and score 4 out of 4 with zxcvbn; five or six unrelated words is the easiest way there.

There is no recovery key. If the passphrase is forgotten, everything in sekret is gone, backups included. Write the passphrase down somewhere safe, such as a password manager that does not depend on sekret.

**Key-file mode** keeps the root key in a file read on every start, so the server is never sealed. It suits tests and setups that protect the host by other means. The setup page does not offer it. To use it, start the server with `--root-key-file` pointing at a file that does not exist yet and choose it with `sekret sys init --key-file-mode`, or let the server create it with `setup.auto_init`, or generate the key yourself:

```sh
sekret admin generate-root-key > /etc/sekret/root.key
chmod 600 /etc/sekret/root.key
sekret server --public-url https://sekret.example.com --root-key-file /etc/sekret/root.key
```

A server started with a key file and an empty database records key-file mode and starts unlocked, which is also how installs from before sealing existed keep working unchanged. The server records the key's fingerprint and refuses to start with a different key, so pointing it at the wrong file fails loudly rather than producing unreadable data. Keep a copy of the key file somewhere other than the database backups: the database without the key is useless, and the key without the database is harmless.

In passphrase mode, `--root-key-file` is an emergency way in. If the file holds the right root key, the server starts unlocked without the passphrase; any other key is refused.

### Setting up without a person

`setup.auto_init` sets up an empty database at start, in `seal.mode`:

- In key-file mode it generates the root key into `seal.root_key_file`, or uses the file if it already exists.
- In passphrase mode it needs a passphrase, from `setup.passphrase_file`, or from `seal.passphrase_file` or `SEKRET_UNLOCK_PASSPHRASE` when the unlock policy is `passphrase-file`. The setup file is read once, at setup. Keeping a passphrase on disk defeats sealing, so this is for a one-off bootstrap from a vault: delete the file afterwards. Later starts are still sealed unless the unlock policy says otherwise, because the setup passphrase is never used to unlock.

With `setup.admin_token_file`, auto-setup also writes a one-hour admin token there with mode 0600. Without it, no token is issued and admins sign in through the OIDC admin groups.

`setup.web: false` turns the setup page and `POST /api/v1/sys/init` off, so a server configured in code cannot be claimed by whoever reaches it first. Set it up with `auto_init`, or stop the server, run `sekret admin init` on the host and start it again.

### Changing mode

If `seal.mode` is set and the database is in the other mode, the server refuses to start. Changing mode is deliberate: stop the server and run `sekret admin set-seal-mode`.

```sh
# Passphrase mode to key-file mode: unwraps the key with the passphrase and writes it out.
sekret admin set-seal-mode key-file --root-key-file /etc/sekret/root.key
# Key-file mode to passphrase mode: wraps the key in the file under a new passphrase.
sekret admin set-seal-mode passphrase --root-key-file /etc/sekret/root.key
```

After moving to passphrase mode, start the server without the key file, unlock it, and then delete the file.

### Rotating the root key

Stop the server and run `sekret admin rotate-root-key`. In passphrase mode it asks for the passphrase and always checks it against the stored wrap, even when a key file is present, then generates a new root key and wraps it under that passphrase. In key-file mode it needs the new key:

```sh
sekret admin generate-root-key > /etc/sekret/root.key.new
sekret admin rotate-root-key --root-key-file /etc/sekret/root.key --new-root-key-file /etc/sekret/root.key.new
mv /etc/sekret/root.key.new /etc/sekret/root.key
```

Rotation gives every project a new data key, re-encrypts every secret value under it (history included), reseals every stored credential, such as Kubernetes reviewer tokens, and records the new key, all in one transaction. Changing the passphrase through the API or `sekret sys change-passphrase` does the same while the server runs. A remembered unlock is dropped, so the next start needs the passphrase once. Backups and database copies taken before still open with the old key and passphrase; see [Security model](security.md#changing-the-passphrase).

## CLI login re-authentication

By default any signed-in browser session can approve a `sekret login`. Set `auth.cli_login_max_auth_age` to make approval need a recent sign-in with the identity provider:

- The server stores `auth_time` from the ID token on each browser session.
- When someone approves a CLI login with a session that authenticated longer ago than the limit, the API answers 403 `reauthentication_required`, and the approval page sends the browser to `/auth/login?reauth=1&return_to=...`.
- That sign-in asks the provider for `max_age` set to the limit, and `prompt=login` when the session is older, so the provider asks for the password and any second factor again. The callback refuses an ID token whose `auth_time` is still too old.
- CLI tokens issued this way cannot be renewed past `auth.cli_token_ttl`. Once one expires, `sekret login` goes through the browser again.

For example, with Keycloak and a client whose browser flow requires a passkey as a second factor:

```yaml
auth:
  cli_token_ttl: 3600
  cli_login_max_auth_age: 900
```

`sekret login` opens the browser. If you signed in to sekret more than 15 minutes ago, Keycloak asks for your password and passkey again before the approval goes through. An hour later the token expires and the next `sekret login` asks again.

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
  --oidc-issuer https://auth.example.com/realms/main \
  --oidc-client-secret-file /etc/sekret/oidc-client-secret \
  --oidc-admin-groups platform-admins
```

### Keycloak

In Keycloak, create a client called `sekret` with client authentication on, the standard flow enabled and the redirect URIs above. Add two mappers to the client's dedicated scope: an *Audience* mapper that adds `sekret` to the ID token, and a *User Realm Role* mapper with claim name `roles`, multivalued, added to the ID token. Realm roles then arrive in the `roles` claim, which is one of the defaults for `--oidc-group-claims`.

Group membership is copied from the token at each sign-in. Removing someone from a group in your provider takes effect at their next sign-in, or when their session expires, whichever comes first.

## Reverse proxies

sekret speaks plain HTTP and expects TLS to end at a reverse proxy in front of it. Set `--trusted-proxies` to the proxy's address so that rate limiting and machine identities' trusted CIDRs see the real client address; without it, every request appears to come from the proxy. Only the rightmost address in `X-Forwarded-For` that is not a trusted proxy is used, across all of the header's lines; an entry that is not an address stops the search at the proxy's own address. Keep the trusted ranges narrow: the server warns about anything shorter than /8.

## TLS and mutual TLS

The server can serve HTTPS itself, which suits a single host without a reverse proxy, or a setup that wants certificates checked all the way to sekret:

```sh
sekret server \
  --public-url https://sekret.example.com:8443 \
  --listen 0.0.0.0:8443 \
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

`sekret login` saves its token in `$XDG_CONFIG_HOME/sekret/credentials.toml` (usually `~/.config/sekret/`) with mode 0600, in a 0700 directory, keyed by server. It writes a new file under a random name and renames it into place. `SEKRET_TOKEN` overrides it. For a server with a certificate from a private CA, pass `--ca-file` or set `SEKRET_CA_FILE`.
