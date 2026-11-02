# sekret.secrets

Ansible collection for reading and writing secrets in a sekret server. It has a lookup for pulling values into templates and vars, and a module for setting or removing secrets. Everything uses the Python standard library, so the controller needs nothing beyond Ansible itself.

## Install

From this directory:

```sh
ansible-galaxy collection build
ansible-galaxy collection install sekret-secrets-*.tar.gz
```

Or point Ansible at a checkout by putting it under `ansible_collections/sekret/secrets` somewhere on `ANSIBLE_COLLECTIONS_PATH`.

## Connecting

Set `url` (or `SEKRET_URL`) to the server, plus one way of logging in. Every option can be passed to the lookup or module directly or picked up from the environment.

| Method | Options | Environment |
| --- | --- | --- |
| Token | `token` | `SEKRET_TOKEN` |
| Universal auth | `client_id`, `client_secret` | `SEKRET_CLIENT_ID`, `SEKRET_CLIENT_SECRET` |
| OIDC | `identity_id` with `oidc_token` or `oidc_token_file` | `SEKRET_IDENTITY_ID`, `SEKRET_OIDC_TOKEN`, `SEKRET_OIDC_TOKEN_FILE` |
| Your `sekret login` (lookup only) | `auth_method: cli`, `cli_path`, `cli_login` | `SEKRET_AUTH_METHOD`, `SEKRET_CLI`, `SEKRET_CLI_LOGIN` |
| Kubernetes | `identity_id`, `auth_method: kubernetes`, `kubernetes_token_file` | `SEKRET_IDENTITY_ID`, `SEKRET_AUTH_METHOD`, `SEKRET_KUBERNETES_TOKEN_FILE` |

When `auth_method` is left alone it tries them in that order, skipping Kubernetes, which you have to ask for. Kubernetes needs `kubernetes_token_file`: a projected token with the `sekret` audience, never the pod's default token. With none of the others set, the lookup uses the login the `sekret` CLI saved, and runs `sekret login` (which opens the browser) when there is none; set `cli_login: false` for runs nobody is watching.

The lookup also takes `url`, `project`, `environment`, `path` and `ca_path` from `sekret_*` variables, which come below its own arguments and above the environment, and from a `[sekret]` section in `ansible.cfg`, below the environment. Failing all of those, it takes the server, project and environment from the CLI's own settings, such as a `.sekret.toml`. See `docs/integrations/ansible.md` for the order.

A machine login is cached for the rest of the process, so a template full of lookups only logs in once.

If the server uses a certificate from your own CA, set `ca_path` (or `SEKRET_CA_PATH`) to the CA bundle. `validate_certs: false` turns checking off entirely, which is fine for a quick test and not much else: the lookup and the module warn when it is off, and the lookup takes it only from its own argument, `SEKRET_VALIDATE_CERTS` or `[sekret] validate_certs` in `ansible.cfg`, never from an inventory variable. With your `sekret login` it runs the CLI with `--insecure-skip-verify`.

`project` and `environment` can also come from `SEKRET_PROJECT` and `SEKRET_ENVIRONMENT`.

## Reading secrets

```yaml
- name: One value
  ansible.builtin.debug:
    msg: "{{ lookup('sekret.secrets.secret', 'DB_PASSWORD', project='app', environment='prod', path='/db') }}"

- name: Everything in a folder, as a dict
  ansible.builtin.template:
    src: app.env.j2
    dest: /etc/app/app.env
    mode: "0600"
  vars:
    settings: "{{ lookup('sekret.secrets.secret', project='app', environment='prod', path='/app') }}"
```

A key that doesn't exist fails the task. Pass `default=` if you would rather get a fallback value.

## Writing secrets

```yaml
- name: Store the API key
  sekret.secrets.secret:
    project: app
    environment: prod
    path: /api
    key: API_KEY
    value: "{{ api_key }}"
    tags: [external]
  delegate_to: localhost

- name: Drop an old one
  sekret.secrets.secret:
    project: app
    environment: prod
    key: LEGACY_TOKEN
    state: absent
  delegate_to: localhost
```

The module compares against what is stored before writing, so it only reports a change when there is one, and check mode works. It never returns the value, and `--diff` only tells you whether the value changed. The `comment` is attached to the new version when a write happens and isn't compared.

Like any module it runs on the target host, so `delegate_to: localhost` is usually what you want.

`examples/playbook.yml` shows both together: it stores a setting and renders a config file from a couple of lookups.

## Upgrading

The lookup now reads `sekret_url`, `sekret_project`, `sekret_environment`, `sekret_path` and `sekret_ca_path` variables, above the `SEKRET_*` environment variables. Inventories that already use those names, for instance to feed the module, change what the lookup reads, and a token or machine identity is refused for a server a `sekret_url` variable names. The lookup warns once in each worker process when such a variable overrides a different `SEKRET_*` value. Rename the variables or pass the values to the lookup to keep the old behaviour. A CA file is now added to the system's CAs instead of replacing them. See `docs/integrations/ansible.md` for the details.

## Development

```sh
uv sync
uv run pytest
uv run ruff check . && uv run ruff format --check .
```

`tests/run_integration.sh` starts a throwaway server from this repository and runs the integration tests against it. To use a server you already have, set `SEKRET_TEST_URL` and an organisation admin token in `SEKRET_TEST_TOKEN` and run `uv run pytest -m integration`.
