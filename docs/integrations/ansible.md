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

Set `SEKRET_URL` and one way to log in. Universal auth suits a controller or a host:

```sh
export SEKRET_URL=https://sekret.example.com
export SEKRET_CLIENT_ID=0192d4a8-0000-7000-8000-000000000000
export SEKRET_CLIENT_SECRET=$(cat ~/.config/sekret/ansible-client-secret)
```

| Method | Options | Environment |
|---|---|---|
| Token | `token` | `SEKRET_TOKEN` |
| Universal auth | `client_id`, `client_secret` | `SEKRET_CLIENT_ID`, `SEKRET_CLIENT_SECRET` |
| OIDC | `identity_id` with `oidc_token` or `oidc_token_file` | `SEKRET_IDENTITY_ID`, `SEKRET_OIDC_TOKEN`, `SEKRET_OIDC_TOKEN_FILE` |
| Kubernetes | `identity_id`, `auth_method: kubernetes` | `SEKRET_IDENTITY_ID`, `SEKRET_AUTH_METHOD` |

A login is cached for the rest of the run, so a template full of lookups logs in once. For a private CA, set `ca_path` or `SEKRET_CA_PATH`.

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
