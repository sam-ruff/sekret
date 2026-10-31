# Security model

sekret protects secrets at rest with envelope encryption and protects access with short-lived tokens and fine-grained roles. It does not protect secrets from the server itself. Whoever controls the running server process, or holds both the database and the root key, can read every value. That is the price of having no keys on clients, and it makes sekret a poor fit if you need to hide secrets from the people who run it.

## The root key and sealing

Everything hangs off one 256-bit root key. How it is kept decides what a stolen disk or a leaked backup is worth.

In **passphrase mode** the root key is stored in the database encrypted with XChaCha20-Poly1305 under a key derived from the passphrase with Argon2id (256 MiB of memory, three passes, one lane, a random 16-byte salt). Stored or backed-up parameters below 64 MiB or three passes are refused, so a tampered database cannot make guessing cheap, and so are parameters above 512 MiB, ten passes or 16 lanes, so a crafted file cannot tie the server up. Wraps made at the older 64 MiB default are redone at the current cost on the next successful unlock. The root key exists unwrapped only in the server's memory, from the moment someone unlocks the server until it is sealed or stops. A copy of the database, a backup, or the powered-down disk is not enough to read any value; an attacker also needs the passphrase, and each guess costs them the Argon2 work.

The passphrase must be at least 12 characters, at most 1 KiB, and score 4 out of 4 with [zxcvbn](https://github.com/dropbox/zxcvbn). It may not contain characters nobody can reliably type again: control characters (tabs, line breaks, C1 controls), invisible format characters such as zero-width spaces and direction marks, line and paragraph separators, or non-breaking spaces. The server checks this at setup, when the passphrase changes, and when the root key is rotated.

Every way of supplying a passphrase (prompt, file, standard input, environment variable or the API) drops a leading byte order mark and exactly one trailing `\n` or `\r\n`, and nothing else. The passphrase is then put in Unicode NFC form before the key is derived, so an accented letter typed as one character on one system and as a letter plus a combining accent on another opens the same wrap. Wraps made before this normalisation still open with the passphrase as it was typed then, and are redone in NFC form on that unlock.

The strength check runs zxcvbn on the passphrase, which makes copies inside that library sekret cannot wipe. sekret wipes its own buffers, but a passphrase may linger in freed memory until it is reused. That risk is accepted: anyone able to read the server's memory can read the root key anyway.

The seal configuration (mode, unlock policy, fingerprint, the wraps and a change counter) is signed under a key derived from the root key, so a database writer cannot switch the unlock policy without being caught, and the highest counter seen is kept outside the database so an older signed configuration cannot be put back unnoticed; see [Unlocking](unlocking.md#the-policy-cannot-be-changed-behind-your-back).

### Changing the passphrase

Changing the passphrase does more than re-wrap the root key. It generates a new root key and a new data key for every project, re-encrypts every secret value (history included) and every stored machine credential, and stores the new wrap, all in one database transaction. `sekret admin rotate-root-key` does the same offline, and in passphrase mode it always checks the passphrase against the stored wrap first, so a typo cannot become the new passphrase.

After a change, the old passphrase opens nothing in the live database. It still opens every backup and database copy taken before the change, and those hold the secrets as they were then. If a passphrase leaks, change it, then rotate the secrets themselves and delete the old backups; changing the passphrase alone does not protect what was already copied.

The [unlock policy](unlocking.md) can weaken this on purpose. `remember` keeps a device key in a file on the server, so the server's own disk is enough to unlock it; `passphrase-file` keeps the passphrase itself on the host. `manual` keeps the full protection.

In **key-file mode** the root key sits in a file on the host, read on every start. Whoever can read that file and the database can read every value, so protect the file as you would the secrets.

There is no recovery key in either mode. A forgotten passphrase or a lost key file means the data is gone.

While sealed, the server answers only its status endpoint, setup and unlock, the health checks, signing out and revoking a token, an admin's full status, the OpenAPI document and the web interface's static files. Every other API route and the sign-in flow return 503.

The public status endpoint says only whether the server is set up and unlocked, whether web setup is on, and the version; before setup it also shows what configuration has already decided, so the setup page can skip those questions. How the server was unlocked, the unlock policy and whether an unlock is remembered are for organisation admins, at `GET /api/v1/sys/status/detail`.

The setup code is compared in constant time and never stored. It is printed to the log and to standard error once at start, and written to `setup.code_file` if one is set. That file is created new with mode 0600: a file of sekret's own left from an earlier start is replaced, but anything else at the path, such as a symlink, a hard link to another file or another user's file, makes the server refuse to start rather than overwrite it. Once setup succeeds the file is deleted, but only if it is still the same file with the same size. The code file, the admin token file and the remember file may not be the database, its `-wal`, `-shm`, lock or epoch files, a key or passphrase file, the configuration file or each other. With `setup.web` off, no code is made at all. Passphrases are never logged or written to the audit log.

Abuse of the unlock endpoints is limited in four ways:

- **Per client:** setup, unlock and passphrase changes have a rate limit of their own, separate from sign-in, so exhausting one never locks anyone out of the other. IPv6 clients are counted per /64.
- **Back-off per source:** after five wrong passphrases from one address (or IPv6 /64), that source waits 1 second, then 2, 4 and so on up to five minutes, until it gets one right. Other sources are not held back, so someone guessing slowly from elsewhere cannot lock the owner out. Only when wrong passphrases arrive from many sources at once, more than 20 in ten seconds, does everyone pause, and then for five seconds at most. A refused attempt is told to try again shortly, with a `Retry-After` rounded up, never the exact wait.
- **Memory:** only one Argon2 derivation runs at a time, and a request that arrives while one is running gets 429 `kdf_busy` straight away rather than queueing. Setup checks the setup code before it takes that slot. The derivation keeps its slot until it finishes, even if the client gives up, and a wrong passphrase is still counted and audited then. Passphrases over 1 KiB, setup codes over 64 bytes and system request bodies over 16 KiB are refused before any work is done.
- **On the host:** with `server.unix_socket` set, `sekret sys unseal --socket PATH` unseals through a Unix socket that serves only status and unseal. The network's rate limits and back-off do not apply there; the socket file's mode (0600, or 0660 for its group) decides who may use it.

Setup, unlocks (including automatic ones at start, recorded under the actor `remember`, `passphrase-file` or `key-file`), passphrase changes and their failures (`sys.init.failed`, `sys.unseal.failed`, `sys.passphrase.failed`) are audited with the client address. So are refused machine logins (`auth.machine-login.failed`, with the reason, though the caller only ever sees `login_failed`), sign-outs (`auth.logout`), refusals on the system routes (`sys.forbidden`), and the admin commands run on the host (`admin.init`, `admin.bootstrap`, `admin.rotate_root_key`, `admin.set_seal_mode` and `admin.restore`, from the address `local`).

Setup, unlocking and changing the passphrase run to the end once started, even if the client hangs up, so a key change is never left half done.

## One server per database

A running server holds an exclusive lock on its database: a `flock` on `<db>.lock` beside a SQLite file, or a Postgres advisory lock. A second server on the same database refuses to start, and so do `sekret admin init`, `rotate-root-key`, `set-seal-mode` and `restore` while a server holds it, because rewriting the root key underneath a running server would lose whatever the server wrote next. `sekret admin bootstrap` writes nothing under the root key, so it still works with the server running; it is how admin access is recovered. As a second guard, before every change the server checks that the database still holds its own root key's fingerprint, and refuses writes with `root_key_changed` until it is restarted if not.

## The process environment

`SEKRET_UNLOCK_PASSPHRASE` and `SEKRET_REMEMBER_SECRET` are read once as the server starts, before it starts any threads. Their values are then overwritten with zeros in the process's own environment block and the variables removed, so they are gone from `/proc/<pid>/environ` and nothing the server runs inherits them. Whoever started the server, a systemd unit file or a container definition, still has them, so a file is still the better choice.

## What the database and backups contain

Secret values, project keys and stored credentials are encrypted in the database. Key names, folder paths, comments, tags, users, groups, machine identities, role bindings and the audit log are stored in plain text. So a raw copy of the database, a Postgres dump, or a copy of the SQLite file reveals the shape of your secrets and who can reach them, though not the values.

An `.skb` backup from `sekret sys backup` encrypts the whole database, metadata included, with a key derived from the root key (HKDF-SHA256). Its header is plain text and shows:

- the root key fingerprint, the seal mode and the sekret version that wrote it;
- when it was made, and the file's size;
- in passphrase mode, the Argon2 salt and parameters and the passphrase-wrapped root key.

That wrap is an offline guessing target: anyone holding the file can try passphrases against it at the cost of one Argon2 run per guess, with no rate limit. A strong passphrase is what keeps it safe, which is why sekret insists on one. With that, a backup is reasonable to keep in S3 or a private repository, but treat old copies as live for as long as their passphrase might leak. Backups never contain the remembered unlock.

Downloading a backup is a `POST`, needs the `backups` read permission, and is audited with the size. Only one runs at a time, and a root key change waits for it, so a backup never mixes data from two keys. The snapshot is staged in a private (0700) directory beside the database, or in `backup.temp_dir`, never in `/tmp`, and the remembered unlock is wiped from the copy before anything else touches it. Staging directories left by a crash are removed when the server next starts.

The live SQLite database has `secure_delete` on, so overwritten rows do not linger in free pages, and it and its `-wal` and `-shm` files are created readable by their owner only. After the root key, the passphrase, the unlock policy or the remembered unlock changes, the write-ahead log is folded back into the database and truncated, so the old wraps and values do not survive in `-wal`.

Postgres keeps old row versions until it vacuums them, and its write-ahead log and any archives taken for point-in-time recovery keep them for as long as they are kept. After changing the passphrase on Postgres, run `VACUUM FULL` on the sekret database, and treat older WAL archives and base backups like old backups: they open with the old passphrase.

## Encryption

Each project has a random 256-bit data key, stored wrapped (encrypted) under the root key. Each value is encrypted with its project's data key using XChaCha20-Poly1305, with a random 192-bit nonce per version. The additional authenticated data ties the ciphertext to its project, secret and version, so copying a ciphertext from one row or project to another makes it fail to decrypt rather than show up under the wrong name. Stored credentials, such as Kubernetes reviewer tokens, are encrypted under the root key and tied to their identity the same way. A reviewer token is also tied to the Kubernetes host, CA certificate and mode it was entered for, so someone who can write the database cannot send it to another cluster. Reviewer tokens stored by an earlier version are re-sealed this way on the first unlock after upgrading.

Key material, the reviewer token while it is in use, and the base64 text of keys written to files are wiped from memory when they are dropped.

## Tokens

Every token, whether a browser session, a CLI login or a machine login, is 256 random bits, stored only as a SHA-256 hash, and has an expiry and a maximum lifetime. Tokens can be revoked one at a time, all at once for an identity, or by revoking the credential that issued them. Browser sessions travel in an `HttpOnly`, `SameSite=Lax` cookie (`Secure` over HTTPS), and every request that changes something and carries a session cookie must also carry an `x-sekret-csrf` header, which another site's form cannot add.

## Sign-in

Browser sign-in uses the OIDC authorisation code flow with PKCE, a one-time state value tied to the browser by a cookie, and a nonce checked in the ID token. Machine logins accept only asymmetric signatures (RS, PS, ES and EdDSA families), check expiry, not-before and issued-at against the server's clock with 30 seconds of leeway, and require bindings that pin the audience and the subject or other claims.

Login endpoints are rate limited per client address. `X-Forwarded-For` is honoured only from `server.trusted_proxies`: every header line is read, right to left, trusted proxies are skipped and IPv4-mapped IPv6 addresses are treated as IPv4. If any entry on any line is not a plain ASCII address, the client counts as unknown (`::`): no identity's trusted CIDRs match it, all such clients share one rate limit, and the proxy's own address is never used in its place. The server warns at start about IPv4 ranges wider than /16, IPv6 ranges wider than /32, ranges outside private address space, and ranges that together cover more than a /8.

`oidc.allowed_subjects` and `oidc.required_groups` are checked on every request, against the subject and groups stored at the person's last browser sign-in, not only when they sign in. Narrowing either list therefore cuts off existing sessions and CLI tokens at once, and the server also revokes them when it next starts. Roles that come from groups (`oidc.admin_groups`, or bindings to a group) follow the groups as they were at the last browser sign-in, so a change in the identity provider takes effect at the next sign-in; for that reason a CLI token for someone with groups cannot be renewed past its first lifetime.

Approving a `sekret login` in the browser can be made to need a recent sign-in with the identity provider; see [`auth.cli_login_max_auth_age`](configuration.md#cli-login-re-authentication). The code a `sekret login` shows expires after five minutes.

Requests have time limits: 30 seconds to send the body, and 60 seconds in all, or ten minutes for a backup. A change only waits for a root key change in progress once its body has arrived and its caller is signed in, so a slow or anonymous request cannot hold up a passphrase change or the writers behind it, and a key change that waits more than 30 seconds for writes to finish gives up cleanly.

## Transport

By default sekret speaks plain HTTP and expects a reverse proxy to provide TLS. It can also serve HTTPS itself and require client certificates (mutual TLS); see [Configuration](configuration.md#tls-and-mutual-tls).

Outgoing requests, to OIDC issuers and Kubernetes API servers, must use HTTPS unless `--allow-insecure-http` is set, never carry credentials in the URL, and do not follow redirects.

## The CLI

A `.sekret.toml` can come with any repository you clone, so the CLI does not trust its `server` with credentials. A token from `--token` or `SEKRET_TOKEN`, and a machine login's client secret or OIDC token, only go to a server named by `--server`, `SEKRET_URL` or an earlier `sekret login`; a server that only a project file names gets an error instead. A saved login token only ever goes to the server it was saved for. Project files owned by another user, or sitting in a directory every user can write to, are skipped with a warning.

The CLI refuses plain `http://` to anything but this machine unless `--allow-insecure-http` is given, and refuses a login approval link that points to a different site from the server.

`sekret run` never passes `SEKRET_TOKEN`, `SEKRET_CLIENT_SECRET`, `SEKRET_UNLOCK_PASSPHRASE` or `SEKRET_REMEMBER_SECRET` to the command it starts. Secrets named like sekret's own settings (`SEKRET_*`) or like variables that change how programs load and run, such as `LD_PRELOAD`, `GIT_ASKPASS` or `HTTPS_PROXY`, are left out of `sekret run`, `sekret env use` and `sekret export --format dotenv` or `shell`.

## The web interface

The interface is served with a Content Security Policy that allows scripts only from the server itself, forbids framing, and sets `nosniff`. Its pages also send `Cross-Origin-Opener-Policy: same-origin`, so a site that opens sekret, or that sekret links to, gets no handle on its window. Uploaded logos are decoded and re-encoded as PNG before they are stored, so no uploaded file is ever served back as sent.

The browser holds as few secrets, for as short a time, as it can:

- A revealed value belongs to the environment and folder it was revealed in. Moving to another one starts with everything masked, and nothing is fetched until you ask.
- Revealing, copying or editing one secret fetches that secret alone; only "reveal all" fetches the whole folder.
- Passphrases, typed values, pasted `.env` files and newly created client secrets are dropped from memory once the form that used them closes. Fields that hold them turn off spellcheck, autocorrect and writing assistants such as Grammarly, which can send text to a cloud service.
- Signing out or locking the server in one tab makes every other open tab drop what it has loaded. A page restored from the browser's back-forward cache reloads instead of showing what it held before.
- The sign-in page shows only fixed messages for failed sign-ins, never text taken from the link, so a crafted link cannot put words on it.

The page for approving a `sekret login` shows the address and program that started the request and how long ago, and approving needs the code typed from the terminal. A link someone sends you is not enough on its own: if you did not run `sekret login` yourself, you have no code to type.

## Reporting a problem

Please report security issues privately through GitHub's security advisories on the repository rather than in a public issue.
