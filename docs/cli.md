# CLI reference

Every command is part of the single `sekret` binary. `sekret <command> --help` prints the full flag list for any of them.

## Options shared by every command

| Flag | Environment | Meaning |
|---|---|---|
| `--server` | `SEKRET_URL` | Server URL. Falls back to the nearest `.sekret.toml`; there is no other default. |
| `--token` | `SEKRET_TOKEN` | Access token. Defaults to the one `sekret login` saved for the server. |
| `--allow-insecure-http` | `SEKRET_CLIENT_ALLOW_INSECURE_HTTP` | Allow a plain `http://` server that is not on this machine. Without it, only `localhost` and loopback addresses may use `http://`. |
| `-p`, `--project` | `SEKRET_PROJECT` | Project slug. |
| `-e`, `--env` | `SEKRET_ENVIRONMENT` | Environment slug. |
| `--path` | `SEKRET_PATH` | Folder, default `/`. |
| `--ca-file` | `SEKRET_CA_FILE` | Extra PEM CA certificates to trust. |
| `--client-cert`, `--client-key` | `SEKRET_CLIENT_CERT`, `SEKRET_CLIENT_KEY` | PEM client certificate and key, for servers or proxies that require mTLS. |

A `.sekret.toml` in the current directory or one above it can set `server`, `project`, `environment` and `path`. Because such a file can arrive with any repository you clone, a server it names is not trusted with credentials on its own: a token from `--token` or `SEKRET_TOKEN`, or a machine login's secret, is only sent when `--server`, `SEKRET_URL` or an earlier `sekret login` names the same server. Otherwise the command stops with an error. Project files owned by another user, or in a directory everyone can write to, are skipped with a warning. Project files, credentials, CA and client certificate files are limited to 1 MiB.

## Signing in

| Command | What it does |
|---|---|
| `sekret login` | Opens the browser to approve this CLI, then saves a token. The approval page shows the address and program the request came from, and you type the code the CLI prints to approve it. `--no-browser` prints the link instead, and a link to a different site from the server is refused. When the server sets `auth.cli_login_max_auth_age`, approving may ask you to sign in to your identity provider again. |
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
| `sekret secrets get KEY [--json]` | Prints one value, or the whole record as JSON. |
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
| `sekret run [--recursive] -- CMD ARGS...` | Runs a command with the secrets as environment variables. Exits with the command's status. The command never sees `SEKRET_TOKEN`, `SEKRET_CLIENT_SECRET`, `SEKRET_UNLOCK_PASSPHRASE` or `SEKRET_REMEMBER_SECRET`. |
| `sekret export [--format dotenv\|json\|yaml\|shell] [--recursive]` | Prints secrets in a format. |
| `sekret env use [ENV] [--shell bash\|zsh\|sh\|fish]` | Prints shell code that swaps this shell's secrets for an environment's. Use inside `eval`. |
| `sekret env unload` | Prints shell code that removes them again. |
| `sekret env status` | Shows what this shell has loaded, names only. |
| `sekret shell-init [bash\|zsh\|sh\|fish]` | Prints the `sekret-env` function. See [Shells and AI agents](integrations/shells-and-agents.md). |

`sekret run`, `sekret env use` and the `dotenv` and `shell` export formats leave out secrets whose names start with `SEKRET_`, are not valid variable names, or change how programs load and run, such as `LD_PRELOAD`, `GIT_ASKPASS` or `HTTPS_PROXY`, and name them on standard error. See [Shells and AI agents](integrations/shells-and-agents.md). JSON and YAML keep every key.

## Setting up, unlocking and backing up

These talk to a running server, so they work from any machine that can reach it. Status, setup and unsealing need no token.

| Command | What it does |
|---|---|
| `sekret sys status [--json] [--socket PATH]` | Shows whether the server is set up and unlocked. Exits 0 when unsealed, 2 when sealed and 3 when not set up. Signed in as an org admin, it also shows the unlock policy and how the server was unlocked. |
| `sekret sys init [--setup-code-file F] [--passphrase-file F] [--unlock P] [--key-file-mode]` | First-boot setup through the API, with the code from the server log. Asks for the passphrase twice and whether to require it after every restart, then prints a one-hour admin token once. With web setup turned off, use `sekret admin init` on the host instead. |
| `sekret sys unseal [--passphrase-file F] [--socket PATH]` | Unlocks a sealed server. With `--socket`, it goes through the server's Unix socket on this host (`server.unix_socket`), which needs no server URL and is not held back by the network's rate limits. |
| `sekret sys seal` | Drops the root key from the server's memory. A remembered unlock is kept, so the next restart still unlocks itself. Org admins only. |
| `sekret sys change-passphrase [--passphrase-file F] [--new-passphrase-file F]` | Changes the passphrase, replacing the root key and re-encrypting every secret. Older backups still open with the old passphrase. Org admins only. |
| `sekret sys unlock-policy manual\|remember\|passphrase-file [--passphrase-file F]` | Changes how the server unlocks after a restart. `remember` and `passphrase-file` ask for the current passphrase. See [Unlocking](unlocking.md). |
| `sekret sys forget-unlock` | Deletes the remembered unlock. Org admins only. |
| `sekret sys backup -o FILE` | Downloads an encrypted backup, written with mode 0600 under a temporary name and then renamed, or to standard output with `-o -`. Needs the `backups` read permission. |

Every `--passphrase-file` and `--setup-code-file` also accepts `-`, which reads the first line of standard input. Without one, the CLI asks without echoing. Files and standard input are limited to 4 KiB, and a leading byte order mark and one trailing line ending are dropped. `--setup-code C` still works but puts the code where other users can see it in the process list.

For an org admin, `sekret sys status` also says how the server was unlocked (`passphrase`, `remember`, `passphrase-file` or `key-file`) and flags a root key file that overrode passphrase mode. Anyone else sees only the state.

## Running the server

| Command | What it does |
|---|---|
| `sekret server [--config FILE]` | Runs the API and web interface. See [Configuration](configuration.md). |
| `sekret server --print-config` | Prints a commented example configuration file with every default. |
| `sekret admin generate-root-key` | Prints a new random root key. |
| `sekret admin bootstrap` | Prints a one-hour organisation admin token. Run it on the server host; in passphrase mode it asks for the passphrase. It works while the server runs, which makes it the way back in when nobody can sign in. |
| `sekret admin init [--key-file-mode] [--passphrase-file F] [--unlock P]` | Sets up the database on the host, for servers with web setup turned off. Stop the server first, then start it afterwards. |
| `sekret admin rotate-root-key [--new-root-key-file F] [--passphrase-file F]` | Replaces the root key and re-encrypts every secret under new project keys. In passphrase mode it checks the passphrase against the stored wrap first, even when a key file is present, and wraps the new key under it. Refuses while a server is using the database. |
| `sekret admin set-seal-mode passphrase\|key-file --root-key-file F` | Moves between passphrase and key-file mode. Refuses while a server is using the database. |
| `sekret admin restore --backup FILE --database-url sqlite://NEW.db` | Writes the database from a backup into a new SQLite file. Prints when the backup was taken and its root key fingerprint first, refuses if the file or a `-wal`, `-shm` or `-journal` beside it exists, and checks the restored copy before linking it into place. Never overwrites. |

`init`, `rotate-root-key`, `set-seal-mode` and `restore` take the database's lock (`<db>.lock`, or an advisory lock on Postgres) and stop with an error while a server holds it. Each admin command that changes the database records itself in the audit log, from the address `local`.
| `sekret admin web-check` | Exits non-zero unless the binary contains the web interface. |
| `sekret operator --server-url URL` | Runs the Kubernetes operator. See [Kubernetes](integrations/kubernetes.md). |
| `sekret operator crd` | Prints the CustomResourceDefinition. |
| `sekret openapi` | Prints the server's OpenAPI document. |

The admin commands work on the database directly, so run them on the server host. They take `--database-url`, `--root-key-file` and `--config` like the server does.

The server also serves the OpenAPI document at `/api/openapi.json`.
