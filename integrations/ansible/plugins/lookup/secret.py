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
  - O(url), O(project), O(environment), O(path) and O(ca_path) are taken from the first of the lookup's own
    arguments, a C(sekret_*) variable, a C(SEKRET_*) environment variable (which C(sekret env use) sets) and
    the C([sekret]) section of C(ansible.cfg). Any still unset come from the sekret CLI's own settings,
    above all the nearest C(.sekret.toml), when the CLI is installed.
  - With no token, machine identity or OIDC token, it uses the login C(sekret login) saved, running
    C(sekret login) once when there is none or it has expired.
extends_documentation_fragment:
  - sekret.secrets.connection
options:
  url:
    description:
      - Base URL of the sekret server, for example C(https://sekret.example.com).
    type: str
    env:
      - name: SEKRET_URL
    vars:
      - name: sekret_url
    ini:
      - section: sekret
        key: url
  project:
    description:
      - Project slug or ID.
    type: str
    env:
      - name: SEKRET_PROJECT
    vars:
      - name: sekret_project
    ini:
      - section: sekret
        key: project
  environment:
    description:
      - Environment slug within the project, for example C(prod).
    type: str
    env:
      - name: SEKRET_ENVIRONMENT
    vars:
      - name: sekret_environment
    ini:
      - section: sekret
        key: environment
  path:
    description:
      - Folder path holding the secrets. C(/) when nothing sets it.
    type: str
    default: null
    env:
      - name: SEKRET_PATH
    vars:
      - name: sekret_path
    ini:
      - section: sekret
        key: path
  ca_path:
    description:
      - CA bundle file, or directory of hashed certificates, used to verify the server.
    type: path
    env:
      - name: SEKRET_CA_PATH
    vars:
      - name: sekret_ca_path
    ini:
      - section: sekret
        key: ca_path
  auth_method:
    description:
      - How to authenticate.
      - V(auto) uses the first of O(token), O(client_id) and O(client_secret), O(identity_id) with an OIDC
        token, and then the login C(sekret login) saved.
      - V(cli) uses only the saved login. V(kubernetes) is never picked automatically.
    type: str
    choices: [auto, token, universal, oidc, kubernetes, cli]
    env:
      - name: SEKRET_AUTH_METHOD
  cli_path:
    description:
      - The sekret CLI to run for the saved login and the project file's settings.
    type: str
    default: sekret
    env:
      - name: SEKRET_CLI
  cli_login:
    description:
      - Whether to run C(sekret login), which opens the browser, when there is no usable saved login.
      - Turn it off for runs nobody is watching, so they fail at once instead of waiting for an approval.
    type: bool
    default: true
    env:
      - name: SEKRET_CLI_LOGIN
    ini:
      - section: sekret
        key: cli_login
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

import os  # noqa: E402
from typing import Any  # noqa: E402

from ansible import constants as C  # noqa: E402
from ansible.errors import AnsibleError  # noqa: E402
from ansible.plugins.lookup import LookupBase  # noqa: E402
from ansible.utils.display import Display  # noqa: E402

from ansible_collections.sekret.secrets.plugins.module_utils.sekret_cli import (  # noqa: E402
    CliTokens,
    cli_context,
)
from ansible_collections.sekret.secrets.plugins.module_utils.sekret_client import (  # noqa: E402
    CliLogin,
    ConfigError,
    SekretClient,
    SekretError,
    Settings,
    StaticToken,
    resolve_auth,
    terminal_safe,
)

display = Display()
CLI_ORIGIN = "the sekret CLI"
# Set by `sekret env use` to the project file it loaded under.
LOADED_FILE_VAR = "SEKRET_LOADED_FILE"
# The options each way of logging in sends to the server.
CREDENTIALS = {
    "universal": ("client_id", "client_secret"),
    "oidc": ("identity_id", "oidc_token", "oidc_token_file"),
    "kubernetes": ("identity_id", "kubernetes_token_file"),
}

# Where to read from: each can come from the lookup, a variable, the environment or ansible.cfg,
# and failing those from the CLI's own settings.
PLACE_OPTIONS = ("url", "project", "environment", "path", "ca_path")
CONTEXT_KEYS = {"url": "server", "project": "project", "environment": "environment", "path": "path"}

CONNECTION_OPTIONS = (
    "url",
    "project",
    "environment",
    "cli_path",
    "cli_login",
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


# Per process, so a variable Ansible templates on every use costs one request a run.
_FOLDERS: dict[tuple, dict] = {}
_CONTEXTS: dict[tuple, dict | None] = {}
_ANNOUNCED: set[tuple] = set()


SHELL_VARS = ("SEKRET_PROJECT", "SEKRET_ENVIRONMENT", LOADED_FILE_VAR)


def cached_context(cli_path: str, known: dict, read_context=cli_context) -> dict | None:
    shell = tuple(os.environ.get(name) for name in SHELL_VARS)
    key = (cli_path, os.getcwd(), shell, tuple(sorted((k, v or "") for k, v in known.items())))
    if key not in _CONTEXTS:
        _CONTEXTS[key] = read_context(cli_path, known)
    return _CONTEXTS[key]


def _from_shell(origins: dict) -> set[str]:
    """The project and environment `sekret env use` left in the environment, if it did."""
    if os.environ.get(LOADED_FILE_VAR) is None:
        return set()
    return {name for name in ("project", "environment") if (origins.get(name) or "").startswith("env:")}


def fill_from_cli(place: dict, origins: dict, cli_path: str, read_context=cli_context) -> None:
    """Takes whatever is still unset from the CLI's settings, above all the nearest .sekret.toml.
    A project or environment `sekret env use` set is left in the environment rather than passed as
    a flag, so the CLI's own check that it was meant for this folder's project file runs."""
    from_shell = _from_shell(origins)
    if all(place.get(name) for name in CONTEXT_KEYS) and not from_shell:
        return
    known = {name: place.get(name) for name in PLACE_OPTIONS if name not in from_shell}
    context = cached_context(cli_path, known, read_context)
    if not context:
        return
    if not place.get("url") and context.get("server") and context.get("server_confirmed") is not True:
        raise ConfigError(
            f"{context.get('project_file') or '.sekret.toml'} names {context['server']}, which you have "
            "not confirmed; set url, sekret_url, SEKRET_URL or url in the [sekret] section of ansible.cfg, "
            "or run `sekret login` at a terminal"
        )
    for name, field in CONTEXT_KEYS.items():
        if not place.get(name) and context.get(field):
            place[name] = context[field]
            origins[name] = f"{CLI_ORIGIN} ({context.get(field + '_source') or 'its settings'})"
    if not place.get("ca_path") and context.get("ca_file"):
        place["ca_path"] = context["ca_file"]
        origins["ca_path"] = CLI_ORIGIN


def _from_inventory(origin: str | None) -> bool:
    return (origin or "").startswith("var:")


def same_path(first: str | None, second: str | None) -> bool:
    if not first or not second:
        return False
    norm = lambda p: os.path.realpath(os.path.expanduser(p))  # noqa: E731
    return norm(first) == norm(second)


def check_destination(plan, place_origins: dict, credential_origins: dict, ca_vouched: bool = False) -> None:
    """Refuses to send a token or machine identity to a server, or through a CA, that the inventory
    or a project file chose, unless the same playbook passed the credential to the lookup itself.
    A CA the inventory chose replaces every other CA the server is checked against, so even the
    saved login is not sent through it unless a trusted setting names the same file."""
    ca_from_inventory = _from_inventory(place_origins.get("ca_path")) and not ca_vouched
    if isinstance(plan, CliLogin):
        if ca_from_inventory:
            raise ConfigError(
                "sekret_ca_path comes from an inventory variable, so your sekret login is not sent through "
                "it: it replaces the CAs the server is checked against. Set ca_path in SEKRET_CA_PATH, "
                "ansible.cfg or the lookup's own arguments; naming the same file there is enough"
            )
        return
    if (place_origins.get("url") or "").startswith(CLI_ORIGIN):
        raise ConfigError(
            "the server came from the sekret CLI's settings, so only your own `sekret login` is sent to it, "
            "never a token or machine identity; set url, SEKRET_URL or url in the [sekret] section of "
            "ansible.cfg to send those"
        )
    steered = ["sekret_url"] if _from_inventory(place_origins.get("url")) else []
    if ca_from_inventory:
        steered.append("sekret_ca_path")
    outside = {name: origin for name, origin in credential_origins.items() if origin != "Direct"}
    if steered and outside:
        sources = ", ".join(f"{name} ({origin})" for name, origin in sorted(outside.items()))
        raise ConfigError(
            f"{' and '.join(steered)} come from inventory variables, so {sources} is not sent there: an "
            "inventory could point it at any server. Pass the credential to the lookup itself, or set the "
            "server in SEKRET_URL or ansible.cfg"
        )


def credential_options(plan) -> tuple[str, ...]:
    if isinstance(plan, CliLogin):
        return ()
    if isinstance(plan, StaticToken):
        return ("token",)
    return CREDENTIALS.get(plan.method, ())


def announce(place: dict, origins: dict) -> None:
    """Says once a process, at -v, where the lookup reads from and why."""
    key = tuple((name, place.get(name), origins.get(name)) for name in PLACE_OPTIONS)
    if key in _ANNOUNCED:
        return
    _ANNOUNCED.add(key)
    safe = {name: terminal_safe(place.get(name)) for name in PLACE_OPTIONS}
    display.v(
        f"sekret: {safe['project']}/{safe['environment']} at {safe['path']} on {safe['url']} "
        f"(project from {terminal_safe(origins['project'])}, environment from "
        f"{terminal_safe(origins['environment'])})"
    )


class LookupModule(LookupBase):
    client_factory = SekretClient
    cli_tokens = CliTokens
    read_context = staticmethod(cli_context)

    def _token_source(self, settings: Settings, no_login_reason: str | None = None) -> CliTokens:
        return self.cli_tokens(
            settings.cli_path,
            settings.url,
            ca_path=settings.ca_path,
            login=settings.cli_login,
            notify=lambda message: display.display(terminal_safe(message)),
            no_login_reason=no_login_reason,
        )

    def _ca_vouched(self, place: dict, origins: dict) -> str | None:
        """The trusted setting naming the same file as a CA path an inventory variable gave: the
        lookup's own argument, SEKRET_CA_PATH, ansible.cfg, or the CLI's own CA file. That path,
        not the inventory's, is the one loaded, so a link swapped afterwards changes nothing."""
        if not _from_inventory(origins.get("ca_path")):
            return None
        trusted, _ = C.config.get_config_value_and_origin(
            "ca_path", plugin_type="lookup", plugin_name=self._load_name, variables={}
        )
        if same_path(trusted, place.get("ca_path")):
            return trusted
        known = {name: place.get(name) for name in ("url", "project", "environment")}
        try:
            context = cached_context(self.get_option("cli_path") or "sekret", known, self.read_context)
        except ConfigError:
            return None
        if context and same_path(context.get("ca_file"), place.get("ca_path")):
            return context["ca_file"]
        return None

    def _credential_origins(self, plan) -> dict:
        origins = {}
        for name in credential_options(plan):
            value, origin = self.get_option_and_origin(name)
            if value:
                origins[name] = origin
        return origins

    def _place(self) -> tuple[dict, dict]:
        place, origins = {}, {}
        for name in PLACE_OPTIONS:
            value, origin = self.get_option_and_origin(name)
            place[name] = value or None
            origins[name] = origin
        fill_from_cli(place, origins, self.get_option("cli_path") or "sekret", self.read_context)
        if not place.get("path"):
            place["path"], origins["path"] = "/", "default"
        return place, origins

    def run(self, terms, variables=None, **kwargs):
        self.set_options(var_options=variables, direct=kwargs)
        options = {name: self.get_option(name) for name in CONNECTION_OPTIONS}
        try:
            place, origins = self._place()
            options.update(place)
            if not place.get("project") or not place.get("environment"):
                raise AnsibleError(
                    "sekret lookup needs project and environment: pass them, set sekret_project and "
                    "sekret_environment, SEKRET_PROJECT and SEKRET_ENVIRONMENT, the [sekret] section of "
                    "ansible.cfg, or a .sekret.toml"
                )
            vouched_ca = self._ca_vouched(place, origins)
            if vouched_ca:
                place["ca_path"] = options["ca_path"] = vouched_ca
            settings = Settings.from_options(options)
            plan = resolve_auth(settings, allow_cli=True)
            check_destination(plan, origins, self._credential_origins(plan), vouched_ca is not None)
            # A browser login only to a server the person named, never one an inventory chose.
            no_login_reason = None
            if _from_inventory(origins.get("url")):
                no_login_reason = (
                    "the server or CA comes from an inventory variable, so the lookup will not open a "
                    f"browser login for it; run `sekret login --server={settings.url}` yourself if you "
                    "trust it"
                )
            client = self.client_factory(
                settings, token_source=lambda s: self._token_source(s, no_login_reason)
            )
            announce(place, origins)
            terms = list(terms or [])
            if terms:
                return read_secrets(
                    client,
                    terms,
                    place["project"],
                    place["environment"],
                    path=place["path"],
                    all_keys=self.get_option("all"),
                    recursive=self.get_option("recursive"),
                    default=kwargs.get("default", _MISSING),
                )
            recursive = bool(self.get_option("recursive"))
            key = (
                settings.url,
                client.identity(),
                place["project"],
                place["environment"],
                place["path"],
                recursive,
            )
            if key not in _FOLDERS:
                (_FOLDERS[key],) = read_secrets(
                    client, [], place["project"], place["environment"], place["path"], True, recursive
                )
            return [dict(_FOLDERS[key])]
        except SekretError as e:
            # Messages carry values a project file or an inventory chose.
            raise AnsibleError(terminal_safe(e.message)) from None
