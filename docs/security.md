# Security model

sekret protects secrets at rest with envelope encryption and protects access with short-lived tokens and fine-grained roles. It does not protect secrets from the server itself. Whoever controls the running server process, or holds both the database and the root key, can read every value. That is the price of having no keys on clients, and it makes sekret a poor fit if you need to hide secrets from the people who run it.

## The root key and sealing

Everything hangs off one 256-bit root key. How it is kept decides what a stolen disk or a leaked backup is worth.

In **passphrase mode** the root key is stored in the database encrypted with XChaCha20-Poly1305 under a key derived from the passphrase with Argon2id (256 MiB of memory, three passes, one lane, a random 16-byte salt). Stored or backed-up parameters below 64 MiB or three passes are refused, so a tampered database cannot make guessing cheap, and so are parameters above 512 MiB, ten passes or 16 lanes, so a crafted file cannot tie the server up. Wraps made at the older 64 MiB default are redone at the current cost on the next successful unlock. The root key exists unwrapped only in the server's memory, from the moment someone unlocks the server until it is sealed or stops. A copy of the database, a backup, or the powered-down disk is not enough to read any value; an attacker also needs the passphrase, and each guess costs them the Argon2 work.

The passphrase must be at least 12 characters, at most 1 KiB, and score 4 out of 4 with [zxcvbn](https://github.com/dropbox/zxcvbn). It may not contain characters nobody can reliably type again: control characters (tabs, line breaks, C1 controls), invisible format characters such as zero-width spaces and direction marks, any space other than the ordinary one (non-breaking, ideographic, en and em spaces and the rest), line and paragraph separators, default-ignorable characters such as variation selectors and the Hangul filler, the Braille blank, and private-use or unassigned code points. The server checks this at setup, when the passphrase changes, and when the root key is rotated.

Every way of supplying a passphrase (prompt, file, standard input, environment variable or the API) drops a leading byte order mark and exactly one trailing `\n` or `\r\n`, and nothing else, exactly once: the CLI sends what it read to the API, which trims it, and trims it itself only for the offline admin commands, so the same file opens the same wrap either way. The passphrase is then put in Unicode NFKC form before the key is derived, so an accented letter typed as one character or as a letter plus a combining accent, a full-width letter or a ligature all open the same wrap. Wraps made with the earlier NFC form, or before any normalisation, still open, and are redone in NFKC form on that unlock.

The strength check runs zxcvbn on the passphrase, which makes copies inside that library sekret cannot wipe. sekret wipes its own buffers, but a passphrase may linger in freed memory until it is reused. That risk is accepted: anyone able to read the server's memory can read the root key anyway.

The seal configuration (mode, unlock policy, fingerprint, the wraps and a change counter) is signed under a key derived from the root key, so a database writer cannot switch the unlock policy without being caught, and the highest counter seen is kept outside the database so an older signed configuration cannot be put back unnoticed; see [Unlocking](unlocking.md#the-policy-cannot-be-changed-behind-your-back).

### Changing the passphrase

Changing the passphrase does more than re-wrap the root key. It generates a new root key and a new data key for every project, re-encrypts every secret value (history included) and every stored machine credential, and stores the new wrap, all in one database transaction. `sekret admin rotate-root-key` does the same offline, and in passphrase mode it always checks the passphrase against the stored wrap first, so a typo cannot become the new passphrase.

If a value, a project key or a stored credential no longer decrypts, the change is refused with `unreadable_data` and the error names each one by id, never by content. With `skip_unreadable` in the request (`--skip-unreadable` on `sekret sys change-passphrase` and `sekret admin rotate-root-key`), those rows are left as they were, still unreadable, and listed in the audit log (`sys.passphrase.skipped`, or the `skipped` detail of `admin.rotate_root_key`); everything else moves to the new key.

After a change, the old passphrase opens nothing in the live database. It still opens every backup and database copy taken before the change, and those hold the secrets as they were then. If a passphrase leaks, change it, then rotate the secrets themselves and delete the old backups; changing the passphrase alone does not protect what was already copied.

The [unlock policy](unlocking.md) can weaken this on purpose. `remember` keeps a device key in a file on the server, so the server's own disk is enough to unlock it; `passphrase-file` keeps the passphrase itself on the host. `manual` keeps the full protection.

In **key-file mode** the root key sits in a file on the host, read on every start. Whoever can read that file and the database can read every value, so protect the file as you would the secrets.

There is no recovery key in either mode. A forgotten passphrase or a lost key file means the data is gone.

While sealed, the server answers only its status endpoint, setup and unlock, the health checks, signing out and revoking a token, an admin's full status, the OpenAPI document and the web interface's static files. Every other API route and the sign-in flow return 503.

The public status endpoint says only whether the server is set up and unlocked, whether web setup is on, and the version; before setup it also shows what configuration has already decided, so the setup page can skip those questions. How the server was unlocked, the unlock policy and whether an unlock is remembered are for organisation admins, at `GET /api/v1/sys/status/detail`.

The setup code is compared in constant time and never stored. It is printed to the log and to standard error once at start, and written to `setup.code_file` if one is set. That file is created new with mode 0600: a file of sekret's own left from an earlier start is replaced, but anything else at the path, such as a symlink, a hard link to another file or another user's file, makes the server refuse to start rather than overwrite it. Once setup succeeds the file is deleted, but only if it is still the same file with the same size. The code file, the admin token file and the remember file may not be the database, its `-wal`, `-shm`, lock or epoch files, a key or passphrase file, the configuration file or each other. With `setup.web` off, no code is made at all. Passphrases are never logged or written to the audit log.

Abuse of the unlock endpoints is limited in four ways:

- **Per client and per network:** setup, unlock and passphrase changes have a rate limit of their own, separate from sign-in, so exhausting one never locks anyone out of the other. IPv6 clients are counted per /64. Passphrase attempts, right or wrong, are also counted per IPv4 /24 and IPv6 /48 at the same rate, so one party holding many addresses in a network shares one allowance.
- **Back-off per source:** after five wrong passphrases from one address (or IPv6 /64), that source waits 1 second, then 2, 4 and so on up to five minutes, until it gets one right. Other sources are not held back, so someone guessing slowly from elsewhere cannot lock the owner out. When wrong passphrases arrive from many sources at once, more than 20 in ten seconds, every source that has already failed pauses for up to five seconds; sources that have never failed do not. While the server is forgetting old sources to make room, a new source gets one free failure rather than five, so a source pushed out cannot come back with a fresh allowance. A refused attempt is told to try again shortly, with a `Retry-After` rounded up, never the exact wait.
- **Memory:** only one Argon2 derivation runs at a time. An attempt from a source with no recent failures waits its turn in a short line, at most eight deep and for at most ten seconds, so a flood cannot simply crowd the owner out; a source that has failed recently gets 429 `kdf_busy` straight away while one is running, and so does anyone when the line is full. Setup checks the setup code before it takes that slot. The derivation keeps its slot until it finishes, even if the client gives up, and a wrong passphrase is still counted and audited then. Passphrases over 1 KiB, setup codes over 64 bytes and system request bodies over 16 KiB are refused before any work is done.
- **On the host:** with `server.unix_socket` set, `sekret sys unseal --socket PATH` unseals through a Unix socket that serves only status and unseal. The network's rate limits and back-off do not apply there; the socket file's mode (0600, or 0660 for its group) decides who may use it. The server binds it inside a fresh owner-only directory and moves it into place once its mode is set, and refuses a directory that belongs to another user or that other users can write to. The CLI checks the same before sending a passphrase, and on Linux also checks that the process listening is the socket's owner.

Setup, unlocks (including automatic ones at start, recorded under the actor `remember`, `passphrase-file` or `key-file`), passphrase changes and their failures (`sys.init.failed`, `sys.unseal.failed`, `sys.passphrase.failed`) are audited with the client address, and with the TCP peer as `peer` when a proxy forwarded the request. So are refused machine logins (`auth.machine-login.failed`, with the reason, though the caller only ever sees `login_failed`; an identity id that is not shaped like one, such as a client secret pasted into the wrong field, is recorded only as a short hash), sign-outs (`auth.logout`), refusals on the system routes (`sys.forbidden`), and the admin commands run on the host (`admin.init`, `admin.bootstrap`, `admin.rotate_root_key`, `admin.set_seal_mode` and `admin.restore`, from the address `local`).

Refused machine logins and `sys.forbidden` refusals from the same caller and source are folded together, so a flood of them cannot flood the audit log: the first in a minute is written at once, and any more in that minute become one later entry with `repeats` (how many) and `window_seconds`.

Setup, unlocking and changing the passphrase run to the end once started, even if the client hangs up, so a key change is never left half done. They have no overall time limit either, so the answer always says how the change went rather than that it timed out.

## One server per database

A running server holds an exclusive lock on its database: a `flock` on the SQLite file itself and on `<db>.lock` beside its real path, or a Postgres advisory lock. Because the file itself is locked and the `.lock` name comes from the resolved path, reaching the database through a symlink or a hard link meets the same lock. A second server on the same database waits up to 30 seconds and then refuses to start, and `sekret admin init`, `rotate-root-key`, `set-seal-mode` and `restore` refuse at once while a server holds it, because rewriting the root key underneath a running server would lose whatever the server wrote next. The server checks every 10 seconds that it still holds the lock and exits if it does not.

`sekret admin bootstrap` writes nothing under the root key, so it still works with the server running; it is how admin access is recovered. It never migrates the database, and refuses one whose applied migrations differ from its own, so a newer binary cannot change the tables under an older running server. The other admin commands need the database to exist and never create one.

As a second guard, before every change, including passphrase changes, unlock policy changes and backups, the server checks that the database still holds its own root key's fingerprint, and refuses with `root_key_changed` until it is restarted if not. Sealing is always allowed.

## The process environment

`SEKRET_UNLOCK_PASSPHRASE` and `SEKRET_REMEMBER_SECRET` are read once as the server starts, before it starts any threads. Their values are then overwritten with zeros in the process's own environment block and the variables removed, so they are gone from `/proc/<pid>/environ` and nothing the server runs inherits them. Whoever started the server, a systemd unit file or a container definition, still has them, so a file is still the better choice. `SEKRET_DATABASE_URL`, which can hold a Postgres password, is removed the same way by the server and the `admin` commands; `database.url_file` keeps it out of the environment altogether.

## What the database and backups contain

Secret values, project keys and stored credentials are encrypted in the database. Key names, folder paths, comments, tags, users, groups, machine identities, role bindings and the audit log are stored in plain text. So a raw copy of the database, a Postgres dump, or a copy of the SQLite file reveals the shape of your secrets and who can reach them, though not the values.

An `.skb` backup from `sekret sys backup` encrypts the whole database, metadata included, with a key derived from the root key (HKDF-SHA256). Its header is plain text and shows:

- the root key fingerprint, the seal mode and the sekret version that wrote it;
- when it was made, and the file's size;
- in passphrase mode, the Argon2 salt and parameters and the passphrase-wrapped root key.

That wrap is an offline guessing target: anyone holding the file can try passphrases against it at the cost of one Argon2 run per guess, with no rate limit. A strong passphrase is what keeps it safe, which is why sekret insists on one. With that, a backup is reasonable to keep in S3 or a private repository, but treat old copies as live for as long as their passphrase might leak. Backups never contain the remembered unlock.

Downloading a backup is a `POST`, needs the `backups` read permission, and is audited with the size. The seal configuration is checked (signature and epoch marks) before the backup's copy of it is signed, and a configuration that fails is never backed up; see [Unlocking](unlocking.md#the-policy-cannot-be-changed-behind-your-back). Only one runs at a time, and one whose client hangs up still runs to the end before another can start. A root key change waits for it, so a backup never mixes data from two keys. The snapshot is staged in a private (0700) directory beside the database, or in `backup.temp_dir`, never in `/tmp`, and the remembered unlock is wiped from the copy before anything else touches it. Staging directories left by a crash are removed when the server next starts.

The live SQLite database has `secure_delete` on, so overwritten rows do not linger in free pages, and it and its `-wal` and `-shm` files are created readable by their owner only. After the root key, the passphrase, the unlock policy or the remembered unlock changes, the write-ahead log is folded back into the database and truncated, so the old wraps and values do not survive in `-wal`.

Postgres keeps old row versions until it vacuums them, and its write-ahead log and any archives taken for point-in-time recovery keep them for as long as they are kept. After changing the passphrase on Postgres, run `VACUUM FULL` on the sekret database, and treat older WAL archives and base backups like old backups: they open with the old passphrase.

## Encryption

Each project has a random 256-bit data key, stored wrapped (encrypted) under the root key. Each value is encrypted with its project's data key using XChaCha20-Poly1305, with a random 192-bit nonce per version. The additional authenticated data ties the ciphertext to its project, secret and version, so copying a ciphertext from one row or project to another makes it fail to decrypt rather than show up under the wrong name. Stored credentials, such as Kubernetes reviewer tokens, are encrypted under the root key and tied to their identity the same way. A reviewer token is also tied to the Kubernetes host, CA certificate and mode it was entered for, so someone who can write the database cannot send it to another cluster. Reviewer tokens stored by an earlier version are re-sealed this way on the first unlock after upgrading, once: the signed seal configuration then records that the move is done, and a token in the old format found later, such as one a database writer put back and pointed at another cluster, is never moved or used. Enter it again instead.

Key material, the reviewer token while it is in use, and the base64 text of keys written to files are wiped from memory when they are dropped.

## Tokens

Every token, whether a browser session, a CLI login or a machine login, is 256 random bits, stored only as a SHA-256 hash, and has an expiry and a maximum lifetime. Tokens can be revoked one at a time, all at once for an identity, or by revoking the credential that issued them. Browser sessions travel in an `HttpOnly`, `SameSite=Lax` cookie (`Secure` over HTTPS), and every request that changes something and carries a session cookie must also carry an `x-sekret-csrf` header, which another site's form cannot add.

## Sign-in

Browser sign-in uses the OIDC authorisation code flow with PKCE, a one-time state value tied to the browser by a cookie, and a nonce checked in the ID token. Machine logins accept only asymmetric signatures (RS, PS, ES and EdDSA families), check expiry, not-before and issued-at against the server's clock with 30 seconds of leeway, and require bindings that pin the audience and the subject or other claims.

Login endpoints are rate limited per client address. `X-Forwarded-For` is honoured only from `server.trusted_proxies`: every header line is read, right to left, trusted proxies are skipped and IPv4-mapped IPv6 addresses are treated as IPv4. Entries may carry a port (`203.0.113.9:443`, `[2001:db8::7]:443`). The first address that is not a trusted proxy is the client, so whatever a client writes further left, garbage included, cannot hide the address its proxy appended. Only when an entry that is not an address comes before any untrusted one does the client count as unknown (`::`): no identity's trusted CIDRs match it, all such clients share one rate limit, and the proxy's own address is never used in its place. The server warns at start about IPv4 ranges wider than /16, IPv6 ranges wider than /32, ranges outside private address space, and ranges that together cover more than a /8.

`oidc.allowed_subjects` and `oidc.required_groups` are checked on every request, against the subject and groups stored at the person's last browser sign-in, not only when they sign in. Narrowing either list therefore cuts off existing sessions and CLI tokens at once, and the server also revokes them when it next starts. Roles that come from groups (`oidc.admin_groups`, or bindings to a group) follow the groups as they were at the last browser sign-in, so a change in the identity provider takes effect at the next sign-in; for that reason a CLI token for someone with groups cannot be renewed past its first lifetime. That limit is worked out again at each renewal, from the person's groups and `auth.cli_login_max_auth_age` as they are then, so a token minted before either changed follows the new rule.

Approving a `sekret login` in the browser can be made to need a recent sign-in with the identity provider; see [`auth.cli_login_max_auth_age`](configuration.md#cli-login-re-authentication). The code a `sekret login` shows expires after five minutes. The approval page shows where the request came from, its address and program as the requester reported them, and whether that address matches the browser's own, but none of this proves who started it: a program name can be faked, and people behind the same NAT share an address. Only approve a code you started yourself. A request you did not start can be refused, which ends it at once (`auth.cli-deny`). Approvals and refusals are audited with the requester's address, program and when it asked.

Requests have time limits: 30 seconds to send the body, and 60 seconds in all, or ten minutes for a backup. A connection has 10 seconds to send each request's headers (and to finish its TLS handshake), is closed after 60 seconds with nothing running and no traffic, and at most `server.max_connections` (512 unless set) are served at once. A change is authenticated from its headers before its body is read, so an anonymous client cannot make the server buffer a body, and only waits for a root key change in progress once its body has arrived, so a slow request cannot hold up a passphrase change or the writers behind it; a key change that waits more than 30 seconds for writes to finish gives up cleanly. Sign-in requests (`/api/v1/auth/`) take bodies of at most 64 KiB.

## Transport

By default sekret speaks plain HTTP and expects a reverse proxy to provide TLS. It can also serve HTTPS itself and require client certificates (mutual TLS); see [Configuration](configuration.md#tls-and-mutual-tls).

Outgoing requests, to OIDC issuers and Kubernetes API servers, must use HTTPS unless `--allow-insecure-http` is set, never carry credentials in the URL, and do not follow redirects.

## The CLI

A `.sekret.toml` can come with any repository you clone, so the CLI does not trust its `server` with anything secret. A token from `--token` or `SEKRET_TOKEN`, and a machine login's client secret or OIDC token, only go to a server named by `--server` or `SEKRET_URL`; an earlier login to the server is not enough, since a planted server could otherwise collect them after one login. `sekret sys` commands, which send passphrases and setup codes, also accept a server you have logged in to. A browser login to a server only a project file names must be confirmed at a terminal, which shows the server's address and its host in ASCII form, so a look-alike name stands out. A saved login token only ever goes to the server it was saved for. Project files are skipped with a warning when they or their directory belong to another user, or their directory can be written by every user or by a group other than your own private group; each is checked on the handle it is read from. The credentials file is refused if another user owns it or can change it or its directory, and a relative `XDG_CONFIG_HOME` is ignored.

Text from the server is printed with control characters, terminal escape sequences and bidirectional overrides removed, so a hostile server cannot clear the screen, set the clipboard, hide a link or disguise what it shows.

The CLI refuses plain `http://` to anything but this machine unless `--allow-insecure-http` is given, and refuses a login approval link that points to a different site from the server.

`sekret run` never passes `SEKRET_TOKEN`, `SEKRET_CLIENT_SECRET`, `SEKRET_UNLOCK_PASSPHRASE` or `SEKRET_REMEMBER_SECRET` to the command it starts, and overwrites them in its own environment first, so the command cannot read them from `/proc` either. `sekret run`, `sekret env use` and `sekret export --format dotenv` or `shell` only load valid variable names, never `SEKRET_*`, and block a broad set of names that change what programs run or where they connect, such as `LD_PRELOAD`, `GIT_EXTERNAL_DIFF`, `PAGER` or `HTTPS_PROXY`, unless the person allows a name with `--allow` or the project file's `allow`. The list is in [Shells and AI agents](integrations/shells-and-agents.md).

## The web interface

The interface is served with a Content Security Policy that allows scripts only from the server itself, forbids framing, and sets `nosniff`. Its pages also send `Cross-Origin-Opener-Policy: same-origin`, so a site that opens sekret, or that sekret links to, gets no handle on its window. Uploaded logos are decoded and re-encoded as PNG before they are stored, so no uploaded file is ever served back as sent.

The browser holds as few secrets, for as short a time, as it can:

- A revealed value belongs to the environment and folder it was revealed in. Moving to another one starts with everything masked, and nothing is fetched until you ask.
- Revealing, copying or editing one secret fetches that secret alone; only "reveal all" fetches the whole folder.
- Passphrases, typed values, pasted `.env` files and newly created client secrets are dropped from memory once the form that used them closes. Fields that hold them turn off spellcheck, autocorrect and writing assistants such as Grammarly, which can send text to a cloud service.
- Signing out or locking the server in one tab makes every other open tab drop what it has loaded. A page restored from the browser's back-forward cache reloads instead of showing what it held before.
- The sign-in page shows only fixed messages for failed sign-ins, never text taken from the link, so a crafted link cannot put words on it.

The page for approving a `sekret login` shows the address that started the request, the program it says it is (which the requester can fake), how long ago it started and when it expires, and approving needs the code typed from the terminal. A link someone sends you is not enough on its own: if you did not run `sekret login` yourself, you have no code to type. When the request came from a different address than your browser, the page warns you and asks you to tick that you started it yourself on that machine. That check is a hint rather than proof: people behind the same office network share an address, and a VPN can make your own request look foreign. Cancelling refuses the request, so the terminal that asked stops waiting.

## Reporting a problem

Please report security issues privately through GitHub's security advisories on the repository rather than in a public issue.
