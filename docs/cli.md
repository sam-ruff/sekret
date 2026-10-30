# CLI reference

Every command is part of the single `sekret` binary. `sekret <command> --help` prints the full flag list for any of them.

## Options shared by every command

| Flag | Environment | Meaning |
|---|---|---|
| `--server` | `SEKRET_URL` | Server URL. Falls back to `.sekret.toml`, then the last server you logged in to. |
| `--token` | `SEKRET_TOKEN` | Access token. Defaults to the one `sekret login` saved for the server. |
| `-p`, `--project` | `SEKRET_PROJECT` | Project slug. |
| `-e`, `--env` | `SEKRET_ENVIRONMENT` | Environment slug. |
| `--path` | `SEKRET_PATH` | Folder, default `/`. |
| `--ca-file` | `SEKRET_CA_FILE` | Extra PEM CA certificates to trust. |
| `--client-cert`, `--client-key` | `SEKRET_CLIENT_CERT`, `SEKRET_CLIENT_KEY` | PEM client certificate and key, for servers or proxies that require mTLS. |

## Signing in

| Command | What it does |
|---|---|
| `sekret login` | Opens the browser to approve this CLI, then saves a token. `--no-browser` prints the link instead. |
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
| `sekret secrets set KEY=value ... [--from-dotenv F] [--comment C]` | Creates or updates secrets in one write. `KEY=-` reads the value from standard input. |
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
| `sekret run [--recursive] -- CMD ARGS...` | Runs a command with the secrets as environment variables. Exits with the command's status. |
| `sekret export [--format dotenv\|json\|yaml\|shell] [--recursive]` | Prints secrets in a format. |
| `sekret env use [ENV] [--shell bash\|zsh\|sh\|fish]` | Prints shell code that swaps this shell's secrets for an environment's. Use inside `eval`. |
| `sekret env unload` | Prints shell code that removes them again. |
| `sekret env status` | Shows what this shell has loaded, names only. |
| `sekret shell-init [bash\|zsh\|sh\|fish]` | Prints the `sekret-env` function. See [Shells and AI agents](integrations/shells-and-agents.md). |

## Running the server

| Command | What it does |
|---|---|
| `sekret server` | Runs the API and web interface. See [Configuration](configuration.md). |
| `sekret admin generate-root-key` | Prints a new random root key. |
| `sekret admin bootstrap` | Prints a one-hour organisation admin token. Run it on the server host. |
| `sekret admin rotate-root-key --new-root-key-file F` | Re-wraps every key under a new root key. Stop the server first. |
| `sekret admin web-check` | Exits non-zero unless the binary contains the web interface. |
| `sekret operator --server-url URL` | Runs the Kubernetes operator. See [Kubernetes](integrations/kubernetes.md). |
| `sekret operator crd` | Prints the CustomResourceDefinition. |
| `sekret openapi` | Prints the server's OpenAPI document. |

The server also serves the OpenAPI document at `/api/openapi.json`.
