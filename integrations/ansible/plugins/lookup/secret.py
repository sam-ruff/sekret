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
  validate_certs:
    description:
      - Whether to check the server's TLS certificate. Off, anyone on the network path can read your token
        and secrets, and the lookup warns once in each worker process.
      - With your C(sekret login), off passes C(--insecure-skip-verify) to the CLI.
      - There is deliberately no C(sekret_validate_certs) variable, so an inventory cannot turn checking off.
    type: bool
    default: true
    env:
      - name: SEKRET_VALIDATE_CERTS
    ini:
      - section: sekret
        key: validate_certs
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

import configparser  # noqa: E402
import os  # noqa: E402
from pathlib import Path  # noqa: E402
from typing import Any  # noqa: E402

try:
    import tomllib
except ImportError:  # Python 3.10; check_shell asks the CLI instead.
    tomllib = None

from ansible import constants as C  # noqa: E402
from ansible.errors import AnsibleError  # noqa: E402
from ansible.plugins.lookup import LookupBase  # noqa: E402
from ansible.utils.display import Display  # noqa: E402

from ansible_collections.sekret.secrets.plugins.module_utils.sekret_cli import (  # noqa: E402
    CliTokens,
    cli_context,
    nearest_project_file,
)
from ansible_collections.sekret.secrets.plugins.module_utils.sekret_client import (  # noqa: E402
    CliLogin,
    ConfigError,
    SekretClient,
    SekretError,
    Settings,
    resolve_auth,
    skip_verify_warning,
    terminal_safe,
)

display = Display()
CLI_ORIGIN = "the sekret CLI"
# Set by `sekret env use` to the project file it loaded under.
LOADED_FILE_VAR = "SEKRET_LOADED_FILE"
# Each place option's environment variable, for falling through an empty value.
PLACE_ENV = {
    "url": "SEKRET_URL",
    "project": "SEKRET_PROJECT",
    "environment": "SEKRET_ENVIRONMENT",
    "path": "SEKRET_PATH",
    "ca_path": "SEKRET_CA_PATH",
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


# Per Ansible worker process, so a variable Ansible templates on every use costs one request in
# each worker rather than one per use.
_FOLDERS: dict[tuple, dict] = {}
_CONTEXTS: dict[tuple, dict | None] = {}
_ANNOUNCED: set[tuple] = set()


# What `sekret env use` exports, by the option each sets.
SHELL_NAMES = {"project": "SEKRET_PROJECT", "environment": "SEKRET_ENVIRONMENT", "path": "SEKRET_PATH"}
PROJECT_FILE = ".sekret.toml"


def cached_context(cli_path: str, known: dict, read_context=cli_context) -> dict | None:
    shell = tuple(os.environ.get(name) for name in (*SHELL_NAMES.values(), LOADED_FILE_VAR))
    key = (cli_path, os.getcwd(), shell, tuple(sorted((k, v or "") for k, v in known.items())))
    if key not in _CONTEXTS:
        _CONTEXTS[key] = read_context(cli_path, known)
    return _CONTEXTS[key]


def project_file_values(path: Path, text: str) -> dict:
    """The project, environment and folder a .sekret.toml names. One that is not valid TOML is an
    error, as it is for the CLI, rather than a file naming nothing."""
    try:
        data = tomllib.loads(text)
    except ValueError as e:
        raise ConfigError(
            f"{path} is not valid TOML ({e}), so the settings `sekret-env` left cannot be checked against it"
        ) from None
    return {name: data[name] for name in SHELL_NAMES if isinstance(data.get(name), str)}


def ansible_cfg_values() -> dict:
    """The [sekret] settings in the ansible.cfg in use, with a relative ca_path taken from the
    config file's own folder, as Ansible does."""
    config_file = C.CONFIG_FILE
    if not config_file:
        return {}
    # As Ansible's own config manager reads it, so a `;` comment after a value is dropped here too.
    parser = configparser.ConfigParser(interpolation=None, inline_comment_prefixes=(";",))
    try:
        parser.read(config_file)
    except configparser.Error:
        return {}
    if not parser.has_section("sekret"):
        return {}
    values = {name: parser.get("sekret", name) for name in PLACE_OPTIONS if parser.has_option("sekret", name)}
    if values.get("ca_path"):
        ca_path = os.path.expanduser(values["ca_path"])
        values["ca_path"] = os.path.join(os.path.dirname(os.path.abspath(config_file)), ca_path)
    return values


def _ask_cli_about_the_shell(here: Path, loaded: str, place: dict, cli_path: str, read_context) -> None:
    """Without tomllib, lets the CLI compare the shell's values with the project file: they stay
    in the environment, not flags, so its own check runs."""
    known = {name: place.get(name) for name in ("url", "ca_path")}
    if cached_context(cli_path, known, read_context) is None:
        raise ConfigError(
            f"these settings were loaded by `sekret-env` under {loaded or 'no project file'}, and this "
            f"Python cannot read {here} to check they are meant for this folder, nor is the sekret CLI "
            "installed to check it instead. Install the CLI or Python 3.11, run `sekret-env off`, or pass "
            "project, environment and path to the lookup"
        )


def check_shell(
    place: dict,
    origins: dict,
    read_cfg=ansible_cfg_values,
    cwd: str | None = None,
    cli_path: str = "sekret",
    read_context=cli_context,
) -> None:
    """Refuses a project, environment or folder `sekret env use` left in the environment under
    another project file, when what this folder is set up for names something else, as the CLI
    does. Values exported by hand, without SEKRET_LOADED_FILE, are not checked."""
    loaded = os.environ.get(LOADED_FILE_VAR)
    if loaded is None:
        return
    from_shell = [name for name in SHELL_NAMES if (origins.get(name) or "").startswith("env:")]
    if not from_shell:
        return
    found = nearest_project_file(cwd or os.getcwd())
    here = found[0] if found else None
    if (not loaded and here is None) or (loaded and here is not None and same_path(loaded, str(here))):
        return
    sources = [("ansible.cfg", read_cfg())]
    if found is not None and tomllib is not None:
        sources.append((str(here), project_file_values(here, found[1])))
    elif found is not None:
        _ask_cli_about_the_shell(here, loaded, place, cli_path, read_context)
    clashes = [
        f"{SHELL_NAMES[name]} is {place[name]} in this shell but {source} says {values[name]}"
        for name in from_shell
        for source, values in sources
        if values.get(name) and values[name] != place[name]
    ]
    if clashes:
        raise ConfigError(
            f"{'; '.join(clashes)}; these were loaded by `sekret-env` under {loaded or 'no project file'}, "
            "so not using them here. Run `sekret-env off`, or pass project, environment and path to the "
            "lookup"
        )


def fill_from_cli(place: dict, origins: dict, cli_path: str, read_context=cli_context) -> None:
    """Takes the server, project or environment, when still unset, from the CLI's settings, above
    all the nearest .sekret.toml, and the folder with them. The folder alone never calls the CLI:
    it is / when nothing sets it."""
    if all(place.get(name) for name in ("url", "project", "environment")):
        return
    known = {name: place.get(name) for name in PLACE_OPTIONS}
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


def _from_inventory(origin: str | None) -> bool:
    return (origin or "").startswith("var:")


def same_path(first: str | None, second: str | None) -> bool:
    if not first or not second:
        return False
    norm = lambda p: os.path.realpath(os.path.expanduser(p))  # noqa: E731
    return norm(first) == norm(second)


def check_destination(plan, place_origins: dict, ca_vouched: bool = False) -> None:
    """Refuses to send anything through a CA the inventory chose, which would let any server it
    vouches for pass as this one, unless a trusted setting names the same file. Refuses to send a
    token or machine identity, however it was given, to a server the inventory or a project file
    chose: only the login `sekret login` saved for that server may go there."""
    if _from_inventory(place_origins.get("ca_path")) and not ca_vouched:
        raise ConfigError(
            "sekret_ca_path comes from an inventory variable, so nothing is sent through it, neither your "
            "sekret login nor a credential passed to the lookup: any server that CA vouches for would pass "
            "as this one. Set ca_path in SEKRET_CA_PATH, ansible.cfg or the lookup's own arguments; naming "
            "the same file there is enough"
        )
    if isinstance(plan, CliLogin):
        return
    url_origin = place_origins.get("url") or ""
    if url_origin.startswith(CLI_ORIGIN):
        raise ConfigError(
            "the server came from the sekret CLI's settings, so only your own `sekret login` is sent to it, "
            "never a token or machine identity; set url, SEKRET_URL or url in the [sekret] section of "
            "ansible.cfg to send those"
        )
    if _from_inventory(url_origin):
        raise ConfigError(
            "sekret_url comes from an inventory variable, so no token or machine identity is sent to it, "
            "not even one passed to the lookup: an inventory could point it at any server. Set the server "
            "in SEKRET_URL, ansible.cfg or the lookup's own url, or use your own sekret login, which only "
            "ever works for the server it was saved for"
        )


_WARNED: set[str] = set()


def warn_skip_verify(url: str) -> None:
    """Warns once a worker process for each server whose certificate is not being checked."""
    key = f"validate_certs:{url}"
    if key in _WARNED:
        return
    _WARNED.add(key)
    display.warning(skip_verify_warning(url))


def warn_overridden(name: str, from_inventory, from_environment) -> None:
    """Warns once a worker process when an inventory variable outranks a different SEKRET_* value,
    which before sekret_* variables were read was the one used. Names only, never values."""
    if from_environment in ("", None) or from_inventory == from_environment or name in _WARNED:
        return
    _WARNED.add(name)
    display.warning(
        terminal_safe(
            f"the inventory variable sekret_{name} overrides {PLACE_ENV[name]}, which is set to something "
            f"else; the sekret lookup ranks sekret_* variables above SEKRET_* ones. Remove or rename "
            f"sekret_{name} if the environment variable was meant"
        )
    )


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
    read_ansible_cfg = staticmethod(ansible_cfg_values)

    def _token_source(self, settings: Settings, no_login_reason: str | None = None) -> CliTokens:
        return self.cli_tokens(
            settings.cli_path,
            settings.url,
            ca_path=settings.ca_path,
            login=settings.cli_login,
            notify=lambda message: display.display(terminal_safe(message)),
            no_login_reason=no_login_reason,
            insecure_skip_verify=not settings.validate_certs,
        )

    def _validate_certs(self) -> bool:
        """validate_certs from the lookup's arguments, SEKRET_VALIDATE_CERTS or ansible.cfg, never an
        inventory variable, which must not be able to turn checking off."""
        value, origin = self.get_option_and_origin("validate_certs")
        if origin.startswith("var:"):
            value, _ = C.config.get_config_value_and_origin(
                "validate_certs", plugin_type="lookup", plugin_name=self._load_name, variables={}
            )
        return value is not False

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

    def _cli_ca(self, place: dict) -> str | None:
        """The CA file the CLI itself would use (SEKRET_CA_FILE or its user config, which it checks
        nobody else can change), or None."""
        known = {name: place.get(name) for name in ("url", "project", "environment")}
        context = cached_context(self.get_option("cli_path") or "sekret", known, self.read_context)
        return (context or {}).get("ca_file") or None

    def _option(self, name: str, variables: dict, direct: dict) -> tuple:
        """The option and where it came from, an empty value from any source counting as unset,
        so the next source is used, with its own origin. The raw value each source gave is what is
        checked, since Ansible turns an empty path into the current directory."""
        value, origin = self.get_option_and_origin(name)
        ranked = [
            ("Direct", direct.get(name), "Direct"),
            ("var:", (variables or {}).get(f"sekret_{name}"), f"var: sekret_{name}"),
            ("env:", os.environ.get(PLACE_ENV[name]), f"env: {PLACE_ENV[name]}"),
            ("ini:", self.read_ansible_cfg().get(name), f"ini: {C.CONFIG_FILE}"),
        ]
        position = next((i for i, (prefix, _, _) in enumerate(ranked) if origin.startswith(prefix)), None)
        if position is None:
            return value or None, origin
        if ranked[position][1] not in ("", None) and value not in ("", None):
            if origin.startswith("var:"):
                warn_overridden(name, ranked[1][1], ranked[2][1])
            return value, origin
        for _, candidate, label in ranked[position + 1 :]:
            if candidate not in ("", None):
                return candidate, label
        return None, "default"

    def _place(self, variables: dict, direct: dict) -> tuple[dict, dict]:
        place, origins = {}, {}
        for name in PLACE_OPTIONS:
            place[name], origins[name] = self._option(name, variables, direct)
        cli_path = self.get_option("cli_path") or "sekret"
        check_shell(place, origins, self.read_ansible_cfg, cli_path=cli_path, read_context=self.read_context)
        fill_from_cli(place, origins, cli_path, self.read_context)
        if not place.get("path"):
            place["path"], origins["path"] = "/", "default"
        return place, origins

    def run(self, terms, variables=None, **kwargs):
        self.set_options(var_options=variables, direct=kwargs)
        options = {name: self.get_option(name) for name in CONNECTION_OPTIONS}
        options["validate_certs"] = self._validate_certs()
        try:
            place, origins = self._place(variables, kwargs)
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
            if isinstance(plan, CliLogin) and not place.get("ca_path"):
                # The CLI checks the server with its own CA file; check it with the same one here.
                cli_ca = self._cli_ca(place)
                if cli_ca:
                    place["ca_path"] = options["ca_path"] = cli_ca
                    origins["ca_path"] = CLI_ORIGIN
                    settings = Settings.from_options(options)
                    plan = resolve_auth(settings, allow_cli=True)
            if not settings.validate_certs:
                warn_skip_verify(settings.url)
            if (
                isinstance(plan, CliLogin)
                and settings.validate_certs
                and settings.ca_path
                and os.path.isdir(settings.ca_path)
            ):
                raise ConfigError(
                    f"ca_path {settings.ca_path} is a directory, but the sekret CLI that holds your login "
                    "needs a CA file; name the file instead"
                )
            check_destination(plan, origins, vouched_ca is not None)
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
                settings.ca_path,
                settings.validate_certs,
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
