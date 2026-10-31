# Getting started

This page runs a throwaway server on your own machine with SQLite, stores a secret and reads it back with the CLI. It takes about five minutes and needs nothing but Linux on x86-64.

## Install the binary

```sh
curl -fsSL https://raw.githubusercontent.com/sam-ruff/sekret/main/install.sh | sh
```

The script downloads the latest release from GitHub, checks it against the published SHA-256, and puts `sekret` in `/usr/local/bin`, or in `~/.local/bin` if it cannot write there. Set `SEKRET_VERSION=v1.2.3` to pin a release and `SEKRET_INSTALL_DIR` to choose the directory. Read the script first if you prefer: it is about sixty lines of POSIX shell.

The binary is statically linked, so it runs on any x86-64 Linux distribution. There are no macOS or Windows builds yet.

## Start a server

```sh
mkdir -p ~/sekret-demo && cd ~/sekret-demo
sekret server --public-url http://localhost:8080 --database-url 'sqlite://sekret.db?mode=rwc'
```

The first start prints a one-time setup code in the log, such as `setup code: K7QM-3XRA-WH9P`. Open <http://localhost:8080> and enter it, or finish from a second terminal:

```sh
export SEKRET_URL=http://localhost:8080
export SEKRET_TOKEN=$(sekret sys init)
sekret whoami
```

Setup asks for the code, then for a passphrase twice. The passphrase protects the root key, which wraps the per-project keys that encrypt your secrets. It needs to be at least 12 characters and hard to guess; a few unrelated words works well. There is no recovery key, so if you lose the passphrase you lose the data.

Setup prints an admin token valid for an hour. It belongs to a built-in break-glass admin; use it to set things up, then sign in properly through your OIDC provider (see [Configuration](configuration.md#signing-in-with-oidc)).

Stop the server and start it again, and it comes back sealed. Unlock it with `sekret sys unseal` or on the web page; [Unlocking](unlocking.md) covers the other ways to do this.

If you would rather keep the root key in a file and never unlock anything, generate one and pass it in; the server then starts unlocked every time, and `sekret admin bootstrap` prints an admin token:

```sh
sekret admin generate-root-key > root.key && chmod 600 root.key
sekret server --public-url http://localhost:8080 --root-key-file root.key &
export SEKRET_TOKEN=$(sekret admin bootstrap --root-key-file root.key)
```

## Store and use a secret

```sh
sekret projects create demo --name Demo
sekret secrets set -p demo -e dev DATABASE_URL=postgres://localhost/demo
sekret secrets generate -p demo -e dev SESSION_KEY
sekret secrets list -p demo -e dev
sekret run -p demo -e dev -- sh -c 'echo "connecting to $DATABASE_URL"'
```

New projects get `dev`, `staging` and `prod` environments. `secrets generate` stores a random 32-character value without printing it, and `run` starts the command with every secret in the environment as a variable.

To skip `-p` and `-e`, put a `.sekret.toml` in your repository:

```toml
server = "http://localhost:8080"
project = "demo"
environment = "dev"
```

## Next steps

- Connect your OIDC provider so people can sign in: [Configuration](configuration.md).
- Run it properly, with TLS, backups and Postgres if you want it: [Deployment](deployment.md).
- Give CI jobs and pods their own identities: [Machine identities](user-guide/machine-identities.md).
