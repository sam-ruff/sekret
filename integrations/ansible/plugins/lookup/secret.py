from __future__ import annotations

DOCUMENTATION = r"""
name: secret
author: sekret maintainers
version_added: 0.1.0
short_description: Read secrets from a sekret server
description:
  - Returns the value of each secret key given as a term.
  - With no terms, or O(all=true), returns a single dictionary of every readable secret under O(path).
  - Every option falls back to the matching C(SEKRET_*) environment variable.
extends_documentation_fragment:
  - sekret.secrets.connection
options:
  _terms:
    description:
      - Secret keys to read from O(path).
    type: list
    elements: str
    required: false
  all:
    description:
      - Return a dictionary of every readable secret under O(path) instead of single values.
    type: bool
    default: false
  recursive:
    description:
      - With O(all), also include secrets in folders below O(path).
      - Nested keys are returned relative to O(path), for example C(db/PASSWORD).
    type: bool
    default: false
  default:
    description:
      - Value returned for a key that does not exist instead of failing.
    type: raw
"""

EXAMPLES = r"""
- name: Read one secret
  ansible.builtin.debug:
    msg: "{{ lookup('sekret.secrets.secret', 'DB_PASSWORD', project='app', environment='prod', path='/db') }}"

- name: Read several secrets as a list
  ansible.builtin.set_fact:
    db_creds: >-
      {{ query('sekret.secrets.secret', 'DB_USER', 'DB_PASSWORD',
               project='app', environment='prod') }}

- name: Read every secret in a folder as a dictionary
  ansible.builtin.set_fact:
    app_env: "{{ lookup('sekret.secrets.secret', project='app', environment='prod', path='/api') }}"

- name: Fall back when a key is not set
  ansible.builtin.debug:
    msg: "{{ lookup('sekret.secrets.secret', 'FEATURE_FLAG', default='off') }}"

- name: Log in with a universal auth machine identity and a private CA
  ansible.builtin.debug:
    msg: >-
      {{ lookup('sekret.secrets.secret', 'API_KEY',
                url='https://sekret.example.com', project='app', environment='prod',
                client_id=sekret_client_id, client_secret=sekret_client_secret,
                ca_path='/etc/ssl/certs/private-root.pem') }}
"""

RETURN = r"""
_raw:
  description:
    - One value per key term.
    - With no terms or O(all=true), a single dictionary of key to value.
  type: list
  elements: raw
"""

from typing import Any  # noqa: E402

from ansible.errors import AnsibleError  # noqa: E402
from ansible.plugins.lookup import LookupBase  # noqa: E402

from ansible_collections.sekret.secrets.plugins.module_utils.sekret_client import (  # noqa: E402
    ConfigError,
    SekretClient,
    SekretError,
    Settings,
)

CONNECTION_OPTIONS = (
    "url",
    "project",
    "environment",
    "auth_method",
    "token",
    "client_id",
    "client_secret",
    "identity_id",
    "oidc_token",
    "oidc_token_file",
    "kubernetes_token_file",
    "validate_certs",
    "ca_path",
    "client_cert",
    "client_key",
    "timeout",
)

_MISSING = object()


def _relative_key(base: str, secret: dict) -> str:
    folder = secret.get("path") or "/"
    base = base.rstrip("/") or "/"
    if folder == base:
        return secret["key"]
    prefix = "/" if base == "/" else base + "/"
    rest = folder[len(prefix) :] if folder.startswith(prefix) else folder.lstrip("/")
    return f"{rest}/{secret['key']}"


def read_secrets(
    client: SekretClient,
    terms: list[str],
    project: str,
    environment: str,
    path: str = "/",
    all_keys: bool = False,
    recursive: bool = False,
    default: Any = _MISSING,
) -> list:
    if terms and all_keys:
        raise ConfigError("all=true reads the whole path, so do not pass key terms as well")
    if not terms:
        secrets = client.list_raw(project, environment, path, recursive)
        return [{_relative_key(path, s): s["value"] for s in secrets}]

    values = []
    for key in terms:
        record = client.get_secret(project, environment, key, path)
        if record is None:
            if default is _MISSING:
                raise SekretError(f"secret {key} not found in {project}/{environment} at {path}")
            values.append(default)
            continue
        if record.value_hidden:
            raise SekretError(f"not permitted to read the value of {key} in {project}/{environment}")
        values.append(record.value)
    return values


class LookupModule(LookupBase):
    client_factory = SekretClient

    def run(self, terms, variables=None, **kwargs):
        self.set_options(var_options=variables, direct=kwargs)
        options = {name: self.get_option(name) for name in CONNECTION_OPTIONS}
        project = options.get("project")
        environment = options.get("environment")
        if not project or not environment:
            raise AnsibleError(
                "sekret lookup needs project and environment (or SEKRET_PROJECT and SEKRET_ENVIRONMENT)"
            )
        try:
            client = self.client_factory(Settings.from_options(options))
            return read_secrets(
                client,
                list(terms or []),
                project,
                environment,
                path=self.get_option("path") or "/",
                all_keys=self.get_option("all"),
                recursive=self.get_option("recursive"),
                default=kwargs.get("default", _MISSING),
            )
        except SekretError as e:
            raise AnsibleError(e.message) from None
