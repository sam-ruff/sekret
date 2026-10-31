# Security model

sekret protects secrets at rest with envelope encryption and protects access with short-lived tokens and fine-grained roles. It does not protect secrets from the server itself. Whoever controls the running server process, or holds both the database and the root key, can read every value. That is the price of having no keys on clients, and it makes sekret a poor fit if you need to hide secrets from the people who run it.

## The root key and sealing

Everything hangs off one 256-bit root key. How it is kept decides what a stolen disk or a leaked backup is worth.

In **passphrase mode** the root key is stored in the database encrypted with XChaCha20-Poly1305 under a key derived from the passphrase with Argon2id (256 MiB of memory, three passes, one lane, a random 16-byte salt). Stored parameters below 64 MiB or three passes are refused, so a tampered database cannot make guessing cheap, and wraps made at the older 64 MiB default are redone at the current cost on the next successful unlock. The root key exists unwrapped only in the server's memory, from the moment someone unlocks the server until it is sealed or stops. A copy of the database, a backup, or the powered-down disk is not enough to read any value; an attacker also needs the passphrase, and each guess costs them the Argon2 work.

The passphrase must be at least 12 characters, at most 1 KiB, free of control characters (tabs, line breaks and the like), and score 4 out of 4 with [zxcvbn](https://github.com/dropbox/zxcvbn). The server checks this at setup, when the passphrase changes, and when the root key is rotated. Every way of supplying a passphrase (prompt, file, standard input, environment variable or the API) drops exactly one trailing `\n` or `\r\n` and nothing else, so the same passphrase works however it is typed.

The strength check runs zxcvbn on the passphrase, which makes copies inside that library sekret cannot wipe. sekret wipes its own buffers, but a passphrase may linger in freed memory until it is reused. That risk is accepted: anyone able to read the server's memory can read the root key anyway.

The seal configuration (mode, unlock policy, fingerprint, the wraps and a change counter) is signed under a key derived from the root key, so a database writer cannot switch the unlock policy without being caught; see [Unlocking](unlocking.md#the-policy-cannot-be-changed-behind-your-back).

### Changing the passphrase

Changing the passphrase does more than re-wrap the root key. It generates a new root key and a new data key for every project, re-encrypts every secret value (history included) and every stored machine credential, and stores the new wrap, all in one database transaction. `sekret admin rotate-root-key` does the same offline, and in passphrase mode it always checks the passphrase against the stored wrap first, so a typo cannot become the new passphrase.

After a change, the old passphrase opens nothing in the live database. It still opens every backup and database copy taken before the change, and those hold the secrets as they were then. If a passphrase leaks, change it, then rotate the secrets themselves and delete the old backups; changing the passphrase alone does not protect what was already copied.

The [unlock policy](unlocking.md) can weaken this on purpose. `remember` keeps a device key in a file on the server, so the server's own disk is enough to unlock it; `passphrase-file` keeps the passphrase itself on the host. `manual` keeps the full protection.

In **key-file mode** the root key sits in a file on the host, read on every start. Whoever can read that file and the database can read every value, so protect the file as you would the secrets.

There is no recovery key in either mode. A forgotten passphrase or a lost key file means the data is gone.

While sealed, the server answers only its status endpoint, setup and unlock, the health checks, signing out and revoking a token, the OpenAPI document and the web interface's static files. Every other API route and the sign-in flow return 503.

The setup code is compared in constant time and never stored. It is printed to the log and to standard error once at start, written to `setup.code_file` if one is set, and that file is deleted once setup succeeds. With `setup.web` off, no code is made at all. Passphrases are never logged or written to the audit log.

Abuse of the unlock endpoints is limited in three ways:

- **Per client:** setup, unlock and passphrase changes have a rate limit of their own, separate from sign-in, so exhausting one never locks anyone out of the other. IPv6 clients are counted per /64.
- **Server-wide:** after five wrong passphrases in a row, from anywhere, every further attempt waits 1 second, then 2, 4 and so on up to a minute, until one succeeds. Argon2 already holds guessing to about one attempt a second, so the delay adds friction without locking the owner out for long while an attack is under way.
- **Memory:** only one Argon2 derivation runs at a time, and a request that arrives while one is running gets 429 `kdf_busy` straight away rather than queueing. The derivation keeps its slot until it finishes, even if the client gives up. Passphrases over 1 KiB, setup codes over 64 bytes and system request bodies over 16 KiB are refused before any work is done.

Setup, unlocks, passphrase changes and their failures (`sys.init.failed`, `sys.unseal.failed`, `sys.passphrase.failed`) are audited with the client address.

## What the database and backups contain

Secret values, project keys and stored credentials are encrypted in the database. Key names, folder paths, comments, tags, users, groups, machine identities, role bindings and the audit log are stored in plain text. So a raw copy of the database, a Postgres dump, or a copy of the SQLite file reveals the shape of your secrets and who can reach them, though not the values.

An `.skb` backup from `sekret sys backup` encrypts the whole database, metadata included, with a key derived from the root key (HKDF-SHA256). Its header is plain text and shows:

- the root key fingerprint, the seal mode and the sekret version that wrote it;
- when it was made, and the file's size;
- in passphrase mode, the Argon2 salt and parameters and the passphrase-wrapped root key.

That wrap is an offline guessing target: anyone holding the file can try passphrases against it at the cost of one Argon2 run per guess, with no rate limit. A strong passphrase is what keeps it safe, which is why sekret insists on one. With that, a backup is reasonable to keep in S3 or a private repository, but treat old copies as live for as long as their passphrase might leak. Backups never contain the remembered unlock.

Downloading a backup is a `POST`, needs the `backups` read permission, and is audited with the size. Only one runs at a time. The snapshot is staged in a private (0700) directory beside the database, or in `backup.temp_dir`, never in `/tmp`, and is written with no journal so the remembered unlock is not copied out on the way. The live SQLite database has `secure_delete` on, so overwritten seal configuration rows do not linger in free pages, and it and its `-wal` and `-shm` files are created readable by their owner only.

## Encryption

Each project has a random 256-bit data key, stored wrapped (encrypted) under the root key. Each value is encrypted with its project's data key using XChaCha20-Poly1305, with a random 192-bit nonce per version. The additional authenticated data ties the ciphertext to its project, secret and version, so copying a ciphertext from one row or project to another makes it fail to decrypt rather than show up under the wrong name. Stored credentials, such as Kubernetes reviewer tokens, are encrypted under the root key and tied to their identity the same way.

Key material is wiped from memory when it is dropped.

## Tokens

Every token, whether a browser session, a CLI login or a machine login, is 256 random bits, stored only as a SHA-256 hash, and has an expiry and a maximum lifetime. Tokens can be revoked one at a time, all at once for an identity, or by revoking the credential that issued them. Browser sessions travel in an `HttpOnly`, `SameSite=Lax` cookie (`Secure` over HTTPS), and every request that changes something and carries a session cookie must also carry an `x-sekret-csrf` header, which another site's form cannot add.

## Sign-in

Browser sign-in uses the OIDC authorisation code flow with PKCE, a one-time state value tied to the browser by a cookie, and a nonce checked in the ID token. Machine logins accept only asymmetric signatures (RS, PS, ES and EdDSA families), check expiry, not-before and issued-at against the server's clock with 30 seconds of leeway, and require bindings that pin the audience and the subject or other claims.

Login endpoints are rate limited per client address. `X-Forwarded-For` is honoured only from `server.trusted_proxies`: every header line is read, right to left, trusted proxies are skipped, IPv4-mapped IPv6 addresses are treated as IPv4, and an entry that does not parse stops the walk at the connecting address. The server warns at start about any trusted range shorter than /8, and loudly about `0.0.0.0/0` or `::/0`.

Approving a `sekret login` in the browser can be made to need a recent sign-in with the identity provider; see [`auth.cli_login_max_auth_age`](configuration.md#cli-login-re-authentication).

## Transport

By default sekret speaks plain HTTP and expects a reverse proxy to provide TLS. It can also serve HTTPS itself and require client certificates (mutual TLS); see [Configuration](configuration.md#tls-and-mutual-tls).

Outgoing requests, to OIDC issuers and Kubernetes API servers, must use HTTPS unless `--allow-insecure-http` is set, never carry credentials in the URL, and do not follow redirects.

## The web interface

The interface is served with a Content Security Policy that allows scripts only from the server itself, forbids framing, and sets `nosniff`. Uploaded logos are decoded and re-encoded as PNG before they are stored, so no uploaded file is ever served back as sent.

## Reporting a problem

Please report security issues privately through GitHub's security advisories on the repository rather than in a public issue.
