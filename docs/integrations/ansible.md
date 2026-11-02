# Ansible

The `sekret.secrets` collection has a lookup plugin for reading secrets into templates and variables, and a module for writing them. It uses only the Python standard library, so the controller needs nothing beyond Ansible.

## Install

```sh
git clone https://github.com/sam-ruff/sekret
cd sekret/integrations/ansible
ansible-galaxy collection build
ansible-galaxy collection install sekret-secrets-*.tar.gz
```

## Connect

When you run Ansible yourself, the lookup can use your own `sekret login`. Set the server and the project once, in `ansible.cfg`:

```ini
[sekret]
url = https://sekret.example.com
ca_path = trust/root.pem
project = app
environment = prod
```

With nothing else set, the lookup asks the CLI (`sekret token`) for the login it saved. When there is none, or it has expired, it runs `sekret login` itself: the browser opens on the approval page, the link and code also appear in Ansible's output, and the run carries on once you approve. Ansible runs tasks in several worker processes. Of those, only one logs in to a server at a time, through a lock kept for each server; the others wait for it and use the same login. If the server rejects a saved login, the lookup logs in again once and retries. If it then rejects the token that login just produced, or a login fails or is declined, the lookup does not ask again: that worker process remembers it, and other processes see a marker beside the lock for a minute, so a stuck setup costs one browser window, not one per task. The `sekret` CLI must be on the `PATH`, or named with `cli_path` or `SEKRET_CLI`.

The lookup tries these in order and uses the first that is set:

| Method | Options | Environment |
|---|---|---|
| Token | `token` | `SEKRET_TOKEN` |
| Universal auth | `client_id`, `client_secret` | `SEKRET_CLIENT_ID`, `SEKRET_CLIENT_SECRET` |
| OIDC | `identity_id` with `oidc_token` or `oidc_token_file` | `SEKRET_IDENTITY_ID`, `SEKRET_OIDC_TOKEN`, `SEKRET_OIDC_TOKEN_FILE` |
| Your `sekret login` (lookup only) | `auth_method: cli` to use nothing else | `SEKRET_AUTH_METHOD` |
| Kubernetes, only when asked for | `identity_id`, `auth_method: kubernetes` | `SEKRET_IDENTITY_ID`, `SEKRET_AUTH_METHOD` |

The module runs on the target host, so it never uses a CLI login; give it a token or a machine identity.

A login is cached in each worker process, so a template full of lookups logs in once there. For a private CA, set `ca_path` or `SEKRET_CA_PATH`. Without one, a lookup using a token or machine identity trusts the system's CAs. With your `sekret login`, the lookup checks the server against the same CA file as the CLI does: `ca_path` when it is set, otherwise the CLI's own `SEKRET_CA_FILE` or the `ca_file` in its user config. `ca_path` must then be a file, not a directory of certificates, since the CLI reads it too, and `validate_certs` must stay on: your login is never sent without checking the server's certificate.

The lookup runs the CLI without `SEKRET_TOKEN`, `SEKRET_CLIENT_ID`, `SEKRET_CLIENT_SECRET`, `SEKRET_IDENTITY_ID`, the OIDC and Kubernetes token variables, the GitHub Actions token variables or `SEKRET_URL`, so `sekret login` is always your own browser login, never a machine login, and a machine credential on the controller never reaches the CLI.

### Runs nobody is watching

A scheduled or CI run has nobody to approve a browser login. Set `cli_login = false` in `[sekret]`, or `SEKRET_CLI_LOGIN=false`, so a missing login fails at once instead of waiting, and better still give the run a machine identity of its own with universal, OIDC or Kubernetes auth.

### Where the lookup reads from

The server, project, environment, folder and CA file are each taken from the first of these that sets them:

| | Source | For example |
|---|---|---|
| 1 | The lookup's own arguments | `lookup('sekret.secrets.secret', 'KEY', environment='staging')` |
| 2 | Ansible variables | `sekret_url`, `sekret_project`, `sekret_environment`, `sekret_path`, `sekret_ca_path` in group_vars, host_vars or a play |
| 3 | Environment variables | `SEKRET_URL`, `SEKRET_PROJECT`, `SEKRET_ENVIRONMENT`, `SEKRET_PATH`, `SEKRET_CA_PATH`, which `sekret env use` sets |
| 4 | `ansible.cfg` | `url`, `project`, `environment`, `path`, `ca_path` in `[sekret]` |
| 5 | The sekret CLI's own settings | the nearest `.sekret.toml`, then the CLI's user config, read through `sekret token --context` |

The folder is `/` when nothing sets it. An empty value counts as unset wherever it comes from, so `sekret_url: ""` lets `SEKRET_URL` or `ansible.cfg` apply. The CLI's own settings are read only when the server, project or environment is still unset, so a lookup that names those needs no CLI at all. So `sekret env use staging` switches a run that relies on `ansible.cfg`, but not a play or group that names its environment in a variable: a group pinned to `prod` keeps reading `prod` whatever your shell has loaded. Like the CLI, the lookup refuses a `SEKRET_PROJECT`, `SEKRET_ENVIRONMENT` or `SEKRET_PATH` that `sekret env use` loaded under a different `.sekret.toml` from the one in the folder you run Ansible in, when this folder's `ansible.cfg` `[sekret]` section or its `.sekret.toml` names something else, rather than read another repository's secrets; run `sekret-env off`, or pass the project and environment to the lookup. The lookup makes this check itself, so it holds without the CLI too, except that Python 3.10 cannot read a `.sekret.toml`: there it asks the CLI to compare, and refuses when the CLI is not installed. It looks only at a `.sekret.toml` the CLI would use, one that is yours and that nobody else can change. Values you exported by hand, without `sekret env use`, are not checked. A `.sekret.toml` counts only once you have confirmed it, as for `sekret export`; until then a lookup that needs it fails and says so. Run with `-v` to see, once in each worker process, where the project and environment came from.

### What may choose the server

Whoever chooses the server is choosing where your credentials go, so the lookup is careful about who that is:

- `sekret_url` and `sekret_ca_path` are inventory variables, and anyone who can change the inventory or a group's variables can set them.
- The lookup never sends a token, client secret or OIDC token to a server `sekret_url` names, wherever the credential came from, even passed to the lookup itself, and says why. Only a login you already saved for that server is sent there, since it was only ever valid at that address, and the lookup never opens a browser login for it: run `sekret login --server=...` yourself if you trust it.
- A CA file is different: it replaces every other CA the server is checked against, so a `sekret_ca_path` of the inventory's choosing could let someone else pose as the server. The lookup sends nothing through one, neither your saved login nor any credential, unless `SEKRET_CA_PATH`, `ansible.cfg`, the lookup's own `ca_path=` or the CLI's own CA file names the same file, and then it loads that setting's file.
- A server that only a `.sekret.toml` names is used only once you have logged in to it, and then only with that saved login, never with a token or machine identity. One you have not logged in to is refused.
- A `.sekret.toml` can also choose the folder. Once you have confirmed its project and environment, it may pick any folder within them without asking again; you can still only read what your login can already read there.
- Set the server yourself, in `SEKRET_URL`, as the lookup's `url=` or in your own `ansible.cfg`, when anything else is to be sent to it.

A repository's own `ansible.cfg` is code you are trusting, like its playbooks: as well as `[sekret]` it can set plugin paths and so run anything. In a repository you have not reviewed, only `SEKRET_URL`, `SEKRET_CA_PATH`, an `ansible.cfg` of your own (through `ANSIBLE_CONFIG`) and the lookup's own arguments are safe places for the server and CA.

Errors and the `-v` line show anything a project file or an inventory chose with control and direction characters escaped, so such a value cannot rewrite your terminal.

## Read

```yaml
- name: One value
  ansible.builtin.copy:
    content: "{{ lookup('sekret.secrets.secret', 'DB_PASSWORD', project='app', environment='prod') }}"
    dest: /etc/app/db-password
    mode: "0600"

- name: A whole folder as a dict
  ansible.builtin.template:
    src: app.env.j2
    dest: /etc/app/app.env
    mode: "0600"
  vars:
    settings: "{{ lookup('sekret.secrets.secret', project='app', environment='prod', path='/app') }}"
```

A missing key fails the task unless you pass `default=`.

A whole folder is fetched once in each worker process and kept there, for each server, CA, login, project, environment and folder. So a variable set to a folder lookup in group_vars, which Ansible works out again every time it is used, costs one request in each worker process rather than one each time it is used.

## Write

```yaml
- name: Store an API key
  sekret.secrets.secret:
    project: app
    environment: prod
    key: API_KEY
    value: "{{ api_key }}"
  delegate_to: localhost
  no_log: true
```

The module reports a change only when the stored value differs, and supports check mode. It never returns the value.
