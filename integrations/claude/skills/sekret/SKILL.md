---
name: sekret
description: Load secrets from a sekret server into a shell, switch between environments (dev, staging, prod) and run commands with secrets, without printing values. Use whenever a task needs credentials, API keys, database URLs or other configuration held in sekret, mentions sekret, SEKRET_* variables or a .sekret.toml, or asks to run something "against prod/staging/dev".
---

# sekret

sekret is a self-hosted secrets manager. Its `sekret` CLI fetches a project environment's secrets and either runs a command with them or prints shell code that loads them.

## Before anything else

1. Check the CLI and the login: `sekret whoami`. It prints the account and server, never secrets.
2. If it says "not logged in", the browser-approved login needs a human. Ask the user to run `! sekret login --server <url>` themselves. Do not try to complete it yourself, and never ask them to paste a token into the conversation. A `SEKRET_TOKEN` that is already in the environment also works, together with `SEKRET_URL` or `--server`: a token is never sent to a server that only `.sekret.toml` names.
3. Find the project and environment. A `.sekret.toml` in the repository sets defaults (`server`, `project`, `environment`). Otherwise `sekret projects` lists projects, and `-p <project>` and `-e <environment>` pick one. `sekret env status` shows what the current shell has loaded, by name only.

## Using secrets

Each Bash tool call is a fresh shell, so variables loaded in one call are gone in the next. Load and use them in the same call.

- **One command:** `sekret run -e dev -- npm test`. The secrets go to that process only. This is the default choice.
- **Several commands that share secrets:** `eval "$(sekret env use dev)" && ./migrate && ./seed`.
- **Switching environment:** run `env use` again with the other environment. It removes the keys the previous one loaded, so nothing from dev leaks into a prod run: `eval "$(sekret env use staging)" && ./smoke-test`.
- **A subfolder:** add `--path /service` (and `--recursive` for everything beneath it) to `run` or `env use`.

## Rules

- **Never print secret values.**
  - Do not run `env`, `printenv`, `set`, `echo $SECRET` or `sekret secrets get`, nor `sekret secrets list --values` or `sekret export`, unless the user explicitly asks to see a value.
  - Never run `sekret env use` without `eval "$(...)"` around it, because the bare output is the values. The CLI refuses when stdout is a terminal, but not when it is captured.
  - To check that a variable is set, test it without showing it: `test -n "$DB_URL" && echo set`.
- **Never write values to files**, commit messages, logs or the conversation. Prefer `sekret run` over generating `.env` files. If a tool truly needs a file, write it to the scratchpad with mode 0600 and delete it afterwards.
- **Production needs a yes.** Running something with `-e prod` (or any environment the user calls production) acts on real systems. Confirm with the user first unless they have already said to do exactly that.
- **Skipped names stay skipped.** `run` and `env use` leave out names such as `PATH`, `GIT_*` or `*_PROXY` and say so on stderr. Never add `--allow` or an `allow` entry in `.sekret.toml` yourself; ask the user.
- **Changing secrets is the user's call.** Use `sekret secrets set` or `delete` and `sekret secrets rollback` only when asked. Reading key names with `sekret secrets list` is fine.

## For the user's own shell

`eval "$(sekret shell-init bash)"` (or `zsh` or `fish`) in their shell rc file defines `sekret-env`:
- `sekret-env prod` switches;
- `sekret-env off` unloads;
- `sekret-env` on its own shows what is loaded.

Offer this, but do not edit their rc files without asking.
