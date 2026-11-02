# CLI reference

Every command is part of the single `sekret` binary. `sekret <command> --help` prints the full flag list for any of them.

## Options shared by every command

| Flag | Environment | Meaning |
|---|---|---|
| `--server` | `SEKRET_URL` | Server URL. Falls back to the nearest `.sekret.toml`; there is no other default. |
| `--token` | `SEKRET_TOKEN` | Access token. Defaults to the one `sekret login` saved for the server. Any local user can read a flag in the process list, so `--token` prints a warning; prefer the variable. |
| `--allow-insecure-http` | `SEKRET_CLIENT_ALLOW_INSECURE_HTTP` | Allow a plain `http://` server that is not on this machine. Without it, only `localhost` and loopback addresses may use `http://`. |
| `-p`, `--project` | `SEKRET_PROJECT` | Project slug. |
| `-e`, `--env` | `SEKRET_ENVIRONMENT` | Environment slug. |
| `--path` | `SEKRET_PATH` | Folder, default `/`. |
| `--ca-file` | `SEKRET_CA_FILE` | Extra PEM CA certificates to trust. |
| `--client-cert`, `--client-key` | `SEKRET_CLIENT_CERT`, `SEKRET_CLIENT_KEY` | PEM client certificate and key, for servers or proxies that require mTLS. |

The CLI and the operator honour `HTTPS_PROXY`, `ALL_PROXY` and `NO_PROXY` only for an `https://` server on another machine, where TLS still protects the traffic inside the proxy's tunnel. A plain `http://` server, and any server on `localhost` or a loopback address, is always reached directly: a proxy would see tokens, passphrases and secret values in the clear, and would connect to its own loopback rather than yours. If a plain `http://` server is only reachable through a proxy, switch it to `https://`.

A `.sekret.toml` in the current directory or one above it can set `server`, `project`, `environment`, `path` and `allow` (see [Using secrets](#using-secrets)). Because such a file can arrive with any repository you clone, a server it names is not trusted with anything secret on its own:

- A token from `--token` or `SEKRET_TOKEN`, and a machine login's client secret or OIDC token, only go to a server named by `--server` or `SEKRET_URL`. Having logged in to the server before is not enough.
- `sekret sys` commands, which send passphrases and setup codes, need the server named by `--server` or `SEKRET_URL`, or one you have logged in to.
- `sekret login` in the browser to a server only a project file names shows its address and host and asks you to confirm at a terminal. Without a terminal it stops.
- A saved login token only ever goes to the server it was saved for.

Otherwise the command stops with an error. Project files are skipped with a warning when they, or a symlink to them, belong to another user, when their directory belongs to another user (root is fine), or when they or their directory can be written by every user or by a shared group. A group-writable file or directory is fine when the group is your own private group, the usual setup with `umask 002`. The file is checked on the same open handle it is read from.

Saved logins live in `$XDG_CONFIG_HOME/sekret/credentials.toml`, or `~/.config/sekret/credentials.toml` when that variable is unset or not an absolute path. The CLI writes the file with mode 0600 in a 0700 directory, refuses it if it belongs to someone else or others can change it or its directory, and warns if others can read it. Project files, credentials, CA and client certificate files are limited to 1 MiB.

Passphrase, setup code, client secret and client key files are checked before use, and the CLI warns when other users can read them, another user owns them, or their directory lets others replace them. Responses from the server are capped at 32 MiB, and backups at 1 GiB, so a broken or hostile server cannot exhaust memory.

Text from the server, such as error messages, table cells, the login code and its link, is printed with control characters and terminal escape sequences removed, so a server cannot rewrite or hide what your terminal shows.

## Signing in

| Command | What it does |
|---|---|
| `sekret login` | Opens the browser to approve this CLI, then saves a token. The approval page shows the address the request came from, whether it matches your browser's, and the program it reported, which can be faked; none of that proves the request is yours, so only approve a code you started. You type the code the CLI prints to approve it, or refuse a request you did not start, which ends it at once. `--no-browser` prints the link instead, and a link to a different site from the server is refused. When the server sets `auth.cli_login_max_auth_age`, approving may ask you to sign in to your identity provider again. |
| `sekret login --github-actions --identity-id ID` | Logs in as a machine identity with the job's GitHub OIDC token. |
| `sekret login --oidc-token-file F --identity-id ID` | The same with any OIDC token in a file; `--oidc-token-env VAR` reads a variable. |
| `sekret login --kubernetes --identity-id ID` | Logs in with the pod's service account token. |
| `sekret login --client-id ID --client-secret-file F` | Universal auth; `SEKRET_CLIENT_SECRET` also works. |
| `sekret logout` | Revokes and forgets the saved token. |
| `sekret whoami` | Shows who the token belongs to. |

Add `--print-token` to any machine login to print the token rather than save it.

## Projects and secrets

| Command | What it does |
|---|---|
| `sekret projects` | Lists the projects you can see. |
| `sekret projects create SLUG [--name N] [--environment E]...` | Creates a project, with `dev`, `staging` and `prod` unless you list others. |
| `sekret secrets list [--values] [--recursive]` | Lists keys, and values if asked. |
| `sekret secrets get KEY [--json] [--raw]` | Prints one value, or the whole record as JSON. A value with control characters or escape sequences, or a JSON record with characters JSON does not escape such as bidirectional overrides, is refused when printing to a terminal, since it could rewrite the screen or set the clipboard; pipe it, or pass `--raw` to print it anyway. |
| `sekret secrets set KEY=value ... [--from-dotenv F] [--comment C]` | Creates or updates secrets in one write. `KEY=-` reads the value from standard input. Typed at a terminal, `KEY=value` warns that the value is now in your shell history. |
| `sekret secrets delete KEY ...` | Deletes secrets; their history stays. |
| `sekret secrets history KEY [--values] [--diff A B]` | Lists versions, or diffs two of them. |
| `sekret secrets rollback KEY VERSION` | Writes a new version with the old value. |
| `sekret secrets generate KEY [--length N] [--charset C]` | Stores a random value without printing it. |
| `sekret secrets policy KEY [--rotate-days N] [--length N] [--charset C] [--off] [--inherit]` | Shows or sets a secret's generation and rotation policy. |
| `sekret policy [--rotate-days N] [--length N] [--charset C] [--off]` | Shows or sets the project default. |
| `sekret snapshots list` | Lists the environment's snapshots. |
| `sekret snapshots restore ID [--path P]` | Restores a snapshot, limited to a folder if given. |

## Using secrets

| Command | What it does |
|---|---|
| `sekret run [--recursive] [--allow NAME]... -- CMD ARGS...` | Runs a command with the secrets as environment variables. Exits with the command's status. The command never sees `SEKRET_TOKEN`, `SEKRET_CLIENT_SECRET`, `SEKRET_UNLOCK_PASSPHRASE` or `SEKRET_REMEMBER_SECRET`, and sekret removes them from its own environment before starting it, so the command cannot read them from its parent either. |
| `sekret export [--format dotenv\|json\|yaml\|shell] [--recursive] [--allow NAME]... [--raw]` | Prints secrets in a format. YAML keys and values are quoted. Like `secrets get`, it refuses to print control characters or escape sequences to a terminal; redirect it to a file, or pass `--raw` to print them anyway. |
| `sekret env use [ENV] [--shell bash\|zsh\|sh\|fish] [--allow NAME]...` | Prints shell code that swaps this shell's secrets for an environment's. Use inside `eval`. |
| `sekret env unload` | Prints shell code that removes them again, along with the `SEKRET_PROJECT`, `SEKRET_ENVIRONMENT`, `SEKRET_PATH` and `SEKRET_LOADED_FILE` that `env use` set. |
| `sekret env status` | Shows what this shell has loaded, names only. |
| `sekret shell-init [bash\|zsh\|sh\|fish]` | Prints the `sekret-env` function. See [Shells and AI agents](integrations/shells-and-agents.md). |

`sekret run`, `sekret env use` and the `dotenv` and `shell` export formats only load names made of letters, digits and underscores that do not start with a digit. Of those, they leave out names starting with `SEKRET_`, a broad set of names that change what programs run or where they connect, such as `LD_PRELOAD`, `GIT_EXTERNAL_DIFF`, `CONFIG_SHELL` or `HTTPS_PROXY`, and names without an underscore other than a few common app settings such as `PORT` or `DEBUG`, since tools read single-word names such as `CC` or `TMPDIR`. Each skipped key is named on standard error with the reason, never its value. A blocked name loads when you name it exactly with `--allow NAME`, which can be repeated, or list it in the project file:

```toml
allow = ["KUBECONFIG", "GIT_PAGER"]
```

Because a project file can come with a repository you cloned, its `allow` list only counts once you have confirmed it. The first `run`, `env use` or `export` that meets it shows the file, the names and the server, project, environment and folder they would load from, and asks at the terminal. A yes is saved in the credentials file for that file, that exact list and that place. A changed list asks again, and so does loading from another server, project, environment or folder, whether the file or a flag picked it. Without a terminal, the names stay blocked and a note says so.

The same goes for where secrets load from. When the project file, not `--project`, `--env`, `SEKRET_PROJECT` or `SEKRET_ENVIRONMENT`, picks the project or environment, the first `run`, `env use` or `export` shows the file, the project, the environment and the server, and asks before loading anything. A yes is saved for that file and that place, so pointing the file at another project, environment or server asks again. Without a terminal the command stops; pass `--project` and `--env`, or answer once at a terminal. This keeps a cloned repository from quietly loading, say, prod secrets into its own build scripts.

`SEKRET_*` names can never be allowed. The full blocked set is in [Shells and AI agents](integrations/shells-and-agents.md). JSON and YAML keep every key.

## Setting up, unlocking and backing up

These talk to a running server, so they work from any machine that can reach it. Status, setup and unsealing need no token, but the server must be named by `--server` or `SEKRET_URL`, or be one you have logged in to, since these commands send passphrases and setup codes.

| Command | What it does |
|---|---|
| `sekret sys status [--json] [--socket PATH [--socket-owner USER]]` | Shows whether the server is set up and unlocked. Exits 0 when unsealed, 2 when sealed and 3 when not set up. Signed in as an org admin, it also shows the unlock policy and how the server was unlocked. |
| `sekret sys init [--setup-code-file F] [--passphrase-file F] [--unlock P] [--key-file-mode]` | First-boot setup through the API, with the code from the server log. Asks for the passphrase twice and whether to require it after every restart, then prints a one-hour admin token once. With web setup turned off, use `sekret admin init` on the host instead. |
| `sekret sys unseal [--passphrase-file F] [--socket PATH [--socket-owner USER]]` | Unlocks a sealed server. With `--socket`, it goes through the server's Unix socket on this host (`server.unix_socket`), which needs no server URL and is not held back by the network's rate limits. The CLI refuses the socket if its directory can be written by its group or by everyone, if the socket and its directory have different owners, if the process listening is not the socket's owner, if any directory above it lets another user swap what is below, or if the socket belongs to anyone but root, you or the user named by `--socket-owner` (or `SEKRET_SOCKET_OWNER`), and sends the passphrase over the same connection it checked. Name the user sekret runs as, such as `--socket-owner sekret`, unless you run the command as that user or the server runs as root. |
| `sekret sys seal` | Drops the root key from the server's memory. A remembered unlock is kept, so the next restart still unlocks itself. Org admins only. |
| `sekret sys change-passphrase [--passphrase-file F] [--new-passphrase-file F] [--skip-unreadable]` | Changes the passphrase, replacing the root key and re-encrypting every secret. Older backups still open with the old passphrase. Refuses, naming them, if any values or stored credentials no longer decrypt; `--skip-unreadable` leaves those as they are and audits them. Refused on a server that reads a root key file. Org admins only. |
| `sekret sys unlock-policy manual\|remember\|passphrase-file [--passphrase-file F]` | Changes how the server unlocks after a restart. `remember` and `passphrase-file` ask for the current passphrase. See [Unlocking](unlocking.md). |
| `sekret sys forget-unlock` | Deletes the remembered unlock. Org admins only. |
| `sekret sys backup -o FILE` | Downloads an encrypted backup, written with mode 0600 under a temporary name and then renamed, or to standard output with `-o -` when that is a pipe or a file, never a terminal. Needs the `backups` read permission. |

Every `--passphrase-file` and `--setup-code-file` also accepts `-`, which reads the first line of standard input. Without one, the CLI asks without echoing. Files and standard input are limited to 4 KiB, and a leading byte order mark and one trailing line ending are dropped, once: commands that talk to the server send the text as read and the server drops them, while the offline `sekret admin` commands drop them themselves. `--setup-code C` still works but puts the code where other users can see it in the process list.

For an org admin, `sekret sys status` also says how the server was unlocked (`passphrase`, `remember`, `passphrase-file` or `key-file`) and flags a root key file that overrode passphrase mode. Anyone else sees only the state.

## Running the server

| Command | What it does |
|---|---|
| `sekret server [--config FILE]` | Runs the API and web interface. See [Configuration](configuration.md). |
| `sekret server --print-config` | Prints a commented example configuration file with every default. |
| `sekret admin generate-root-key` | Prints a new random root key. |
| `sekret admin bootstrap [--ttl SECONDS]` | Prints an organisation admin token, valid for an hour unless `--ttl` says otherwise, at most a day. Run it on the server host; in passphrase mode it asks for the passphrase. It works while the server runs, which makes it the way back in when nobody can sign in. It never changes the database's tables, and refuses a database whose schema is from another sekret version: run the bootstrap of the version the server runs. |
| `sekret admin init [--key-file-mode] [--passphrase-file F] [--unlock P] [--ttl SECONDS]` | Sets up the database on the host, for servers with web setup turned off, and prints an admin token (an hour by default, at most a day). Stop the server first, then start it afterwards. |
| `sekret admin rotate-root-key [--new-root-key-file F] [--passphrase-file F] [--skip-unreadable] [--new-integrity-key]` | Replaces the root key and re-encrypts every secret under new project keys. In passphrase mode it checks the passphrase against the stored wrap first, even when a key file is present, wraps the new key under it, and writes the new key over that key file. Refuses, naming them, if any values, project keys or stored credentials no longer decrypt; `--skip-unreadable` leaves those as they are and audits them. `--new-integrity-key` also replaces the key that authenticates tokens and client secrets and revokes every one of them, which recovering from a leaked root key or passphrase needs; see [After a root key or passphrase leak](security.md#after-a-root-key-or-passphrase-leak). Refuses while a server is using the database. |
| `sekret admin reset-epoch [--passphrase-file F] [--adopt-root-key] [--drop-passphrase-wrap] [--lower-marks]` | Re-signs the seal configuration above every seal epoch mark and raises the marks to it: after restoring an older database in place, or when a mark is damaged. It never lowers a mark. A configuration that fails its signature or is older than the marks falls back to the manual unlock policy. `--lower-marks` is only for marks at the epoch limit, which takes a planted mark: it lowers every mark, after which older signed configurations can be put back unnoticed, and is refused while the configuration fails its signature. `--adopt-root-key` also accepts a root key the marks do not name, such as that of a database restored from before a passphrase change, and moves the marks to it; it checks only that the key opens every project key, not every value. With a root key file in passphrase mode, a wrap that failed its signature is only kept if the passphrase opens it to the same key; `--drop-passphrase-wrap` drops one that does not and falls back to key-file mode. Refuses while a server is using the database. See [Unlocking](unlocking.md#the-root-key-cannot-be-swapped). |
| `sekret admin set-seal-mode passphrase\|key-file --root-key-file F [--skip-unreadable]` | Moves between passphrase and key-file mode under a new root key, re-encrypting every secret, so the old key file or passphrase opens nothing in the live database. Refuses while a server is using the database. |
| `sekret admin restore --backup FILE --database-url sqlite://NEW.db` | Writes the database from a backup into a new SQLite file. Prints when the backup was taken and its root key fingerprint once the backup has been decrypted and checked, never before, refuses if the file or a `-wal`, `-shm` or `-journal` beside it exists, and checks the restored copy before linking it into place. Never overwrites. |

`init`, `rotate-root-key`, `set-seal-mode`, `reset-epoch` and `restore` take the database's lock (a `flock` on the SQLite file and on `<db>.lock` beside its real path, or an advisory lock on Postgres) and stop with an error while a server holds it, whatever path or link they reach the database by. Every admin command except `init` and `restore` needs the database to exist already, so a mistyped `--database-url` stops with an error instead of creating an empty database. Admin commands take `--database-url-file` (or `SEKRET_DATABASE_URL_FILE`) as well as `--database-url`, and `--remember-file` (or `SEKRET_REMEMBER_FILE`, or `seal.remember_file` from `--config`), so they read and raise the seal epoch mark beside the remember file the way the server does. They take `--epoch-file` (or `SEKRET_EPOCH_FILE`, or `seal.epoch_file`) for the same reason, and on Postgres without a remember file or root key file they refuse to run without it, as they do anywhere no mark exists and none can be written. Each admin command that changes the database records itself in the audit log, from the address `local`.
| `sekret admin web-check` | Exits non-zero unless the binary contains the web interface. |
| `sekret operator --server-url URL --namespace NS[,NS...]` | Runs the Kubernetes operator in the given namespaces. `--all-namespaces` watches the whole cluster instead; one of the two is required. A plain `http://` server that is not on loopback needs `--allow-insecure-http`. See [Kubernetes](integrations/kubernetes.md). |
| `sekret operator crd` | Prints the CustomResourceDefinition. |
| `sekret openapi` | Prints the server's OpenAPI document. |

The admin commands work on the database directly, so run them on the server host. They take `--database-url`, `--root-key-file` and `--config` like the server does, and warn on standard error, as the server does at start, about a configuration file other users can change or replace, and about a root key, remember, database URL or new root key file other users can read or replace.

The server also serves the OpenAPI document at `/api/openapi.json`.
