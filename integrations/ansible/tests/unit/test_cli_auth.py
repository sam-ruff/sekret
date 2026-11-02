"""The lookup's CLI login and where it reads from: the auth order, the saved login and logging in
once, the 401 retry, and the precedence of arguments, variables, environment, ansible.cfg and the
CLI's own settings."""

import fcntl
import http.server
import json
import multiprocessing
import os
import shutil
import stat
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path

import pytest
from ansible.errors import AnsibleError
from ansible.plugins.loader import lookup_loader
from conftest import COLLECTIONS_ROOT
from fake_server import FakeServer, error

from ansible_collections.sekret.secrets.plugins.module_utils import sekret_cli
from ansible_collections.sekret.secrets.plugins.module_utils.sekret_cli import (
    FAILED_FOR,
    CliTokens,
    cli_context,
    login_lock,
)
from ansible_collections.sekret.secrets.plugins.module_utils.sekret_client import (
    AuthenticationError,
    CliLogin,
    ConfigError,
    SekretClient,
    Settings,
    TokenCache,
    resolve_auth,
)

URL = "https://sekret.test"
FAKE_CLI = Path(__file__).with_name("fake_cli.py")
BIN = Path(sys.executable).parent
ENV_NAMES = (
    "SEKRET_URL",
    "SEKRET_TOKEN",
    "SEKRET_PROJECT",
    "SEKRET_ENVIRONMENT",
    "SEKRET_PATH",
    "SEKRET_CA_PATH",
    "SEKRET_CLIENT_ID",
    "SEKRET_CLIENT_SECRET",
    "SEKRET_IDENTITY_ID",
    "SEKRET_OIDC_TOKEN",
    "SEKRET_AUTH_METHOD",
    "SEKRET_CLI",
    "SEKRET_CLI_LOGIN",
)


class EchoServer(FakeServer):
    """Serves any project and environment, so a test can see which one was asked for."""

    def _scope_error(self, project, environment):
        return None

    def asked(self):
        raw = self.calls_to("GET", "/api/v1/secrets/raw")
        query = raw[-1].query
        return query["project"], query["environment"], query["path"]


@dataclass
class State:
    """The fake CLI's state directory and the fake CLI itself."""

    dir: Path
    cli: str

    def __truediv__(self, name):
        return self.dir / name

    def __str__(self):
        return str(self.dir)

    @property
    def parent(self):
        return self.dir.parent


@pytest.fixture
def state(tmp_path, monkeypatch):
    directory = tmp_path / "state"
    directory.mkdir()
    cli = tmp_path / "sekret"
    shutil.copy(FAKE_CLI, cli)
    cli.chmod(cli.stat().st_mode | stat.S_IXUSR)
    for name in ENV_NAMES:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("FAKE_SEKRET_STATE", str(directory))
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    sekret_cli._FAILED.clear()
    return State(directory, str(cli))


def logins(state):
    path = state / "logins"
    return path.read_text().splitlines() if path.exists() else []


def calls(state):
    path = state / "calls"
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


def tokens(state, notes=None, login=True):
    return CliTokens(
        state.cli,
        URL,
        login=login,
        notify=(notes.append if notes is not None else lambda _m: None),
        lock_dir=state.parent / "cache" / "sekret",
    )


class TestAuthOrder:
    def settings(self, **options):
        return Settings.from_options({"url": URL, **options}, environ={})

    def test_explicit_credentials_come_before_the_cli(self):
        assert type(resolve_auth(self.settings(token="t"), allow_cli=True)).__name__ == "StaticToken"
        plan = resolve_auth(self.settings(client_id="c", client_secret="s"), allow_cli=True)
        assert plan.method == "universal"
        plan = resolve_auth(self.settings(identity_id="i", oidc_token="jwt"), allow_cli=True)
        assert plan.method == "oidc"

    def test_the_cli_login_cache_key_covers_the_cli_and_the_ca(self):
        keys = {
            CliLogin().cache_key(URL),
            CliLogin("/other/sekret").cache_key(URL),
            CliLogin(ca_path="/ca.pem").cache_key(URL),
            CliLogin().cache_key("https://other.test"),
        }
        assert len(keys) == 4
        plan = resolve_auth(self.settings(cli_path="/x/sekret", ca_path="/ca.pem"), allow_cli=True)
        assert plan == CliLogin("/x/sekret", "/ca.pem")

    def test_the_cli_comes_last_and_only_where_it_may_run(self):
        assert resolve_auth(self.settings(), allow_cli=True) == CliLogin()
        with pytest.raises(ConfigError, match="no sekret credentials"):
            resolve_auth(self.settings())

    def test_cli_can_be_asked_for_but_not_by_the_module(self):
        assert resolve_auth(self.settings(token="t", auth_method="cli"), allow_cli=True) == CliLogin()
        with pytest.raises(ConfigError, match="only works in the lookup"):
            resolve_auth(self.settings(auth_method="cli"))

    def test_kubernetes_is_still_never_automatic(self):
        settings = self.settings(kubernetes_token_file="/tmp/token", identity_id="i")
        assert resolve_auth(settings, allow_cli=True) == CliLogin()


class TestSavedLogin:
    def test_a_saved_token_is_used_without_logging_in(self, state):
        (state / "token").write_text("saved\n")
        assert tokens(state).token() == "saved"
        assert logins(state) == []
        (argv,) = calls(state)
        assert argv == ["token", f"--server={URL}"]

    @pytest.mark.parametrize("expired", [False, True])
    def test_missing_or_expired_logs_in_and_relays_the_link(self, state, expired):
        if expired:
            (state / "token").write_text("old\n")
            (state / "expired").write_text("")
        notes = []
        assert tokens(state, notes).token() == "cli-token-1"
        assert logins(state) == [URL]
        assert any("approve" in n for n in notes)
        assert any("cli-login?code=WXYZ" in n for n in notes)
        assert any("Code: WXYZ" in n for n in notes)

    def test_cli_login_off_fails_at_once(self, state):
        with pytest.raises(AuthenticationError, match="cli_login is off"):
            tokens(state, login=False).token()
        assert logins(state) == []

    def test_a_failed_login_is_an_error(self, state):
        (state / "login_fails").write_text("")
        with pytest.raises(AuthenticationError, match="did not finish"):
            tokens(state).token()

    def test_a_cli_error_is_reported(self, state):
        (state / "token_error").write_text("sekret: the user config is writable by others\n")
        with pytest.raises(Exception, match="writable by others"):
            tokens(state).token()

    def test_a_missing_cli_says_how_to_point_at_it(self, state):
        missing = CliTokens(str(state / "nope"), URL, lock_dir=state.dir)
        with pytest.raises(ConfigError, match="cli_path or SEKRET_CLI"):
            missing.token()

    def test_the_ca_file_reaches_the_cli(self, state):
        (state / "token").write_text("saved\n")
        CliTokens(state.cli, URL, ca_path="/ca.pem", lock_dir=state.dir).token()
        assert calls(state)[-1][-1] == "--ca-file=/ca.pem"

    def test_a_value_starting_with_a_dash_stays_a_value(self, state):
        (state / "token").write_text("saved\n")
        CliTokens(state.cli, "-not-a-flag", ca_path="-odd.pem", lock_dir=state.dir).token()
        assert calls(state)[-1] == ["token", "--server=-not-a-flag", "--ca-file=-odd.pem"]


def _log_in_together(cli, lock_dir, barrier, results):
    barrier.wait()
    results.put(CliTokens(cli, URL, lock_dir=Path(lock_dir)).token())


class TestOneLoginForManyWorkers:
    def test_several_processes_log_in_exactly_once(self, state):
        context = multiprocessing.get_context("fork")
        workers = 6
        barrier = context.Barrier(workers)
        results = context.Queue()
        lock_dir = str(state.parent / "cache" / "sekret")
        processes = [
            context.Process(target=_log_in_together, args=(state.cli, lock_dir, barrier, results))
            for _ in range(workers)
        ]
        for process in processes:
            process.start()
        got = [results.get(timeout=15) for _ in processes]
        for process in processes:
            process.join(timeout=15)
        assert got == ["cli-token-1"] * workers
        assert logins(state) == [URL]


class TestLockDirectory:
    def test_a_symlinked_directory_is_refused(self, tmp_path):
        real = tmp_path / "real"
        real.mkdir(mode=0o700)
        link = tmp_path / "link"
        link.symlink_to(real)
        with pytest.raises(ConfigError, match="not a directory"), login_lock(link):
            pass

    def test_a_directory_others_can_write_is_refused(self, tmp_path):
        shared = tmp_path / "shared"
        shared.mkdir()
        shared.chmod(0o777)
        with pytest.raises(ConfigError, match="not private"), login_lock(shared):
            pass

    def test_a_new_directory_is_private(self, tmp_path):
        directory = tmp_path / "new" / "sekret"
        with login_lock(directory):
            assert stat.S_IMODE(os.stat(directory).st_mode) == 0o700


class Ticking:
    """A clock that moves on by `step` each time it is read."""

    def __init__(self, start=1000.0, step=1.0):
        self.now = start
        self.step = step

    def __call__(self):
        self.now += self.step
        return self.now


class TestStuckAndFailedLogins:
    def test_a_lock_held_too_long_gives_up_with_a_clear_error(self, tmp_path):
        directory = tmp_path / "sekret"
        with login_lock(directory):
            held = os.open(directory / sekret_cli.LOCK_NAME, os.O_RDWR)
        fcntl.flock(held, fcntl.LOCK_EX)
        try:
            waits = []
            with (
                pytest.raises(AuthenticationError, match="giving up"),
                login_lock(directory, wait=5, clock=Ticking(), sleep=waits.append),
            ):
                pass
            assert waits and len(waits) <= 6
        finally:
            os.close(held)

    def test_a_failed_login_is_not_tried_again_in_the_same_run(self, state):
        (state / "login_fails").write_text("")
        with pytest.raises(AuthenticationError, match="did not finish"):
            tokens(state).token()
        with pytest.raises(AuthenticationError, match="already failed in this run"):
            tokens(state).token()
        assert logins(state) == [URL]

    def test_other_runs_fail_fast_for_a_while_after_a_failed_login(self, state):
        (state / "login_fails").write_text("")
        with pytest.raises(AuthenticationError, match="did not finish"):
            tokens(state).token()
        sekret_cli._FAILED.clear()
        lock_dir = state.parent / "cache" / "sekret"
        soon = CliTokens(state.cli, URL, lock_dir=lock_dir, clock=lambda: time.time() + 1)
        with pytest.raises(AuthenticationError, match="failed less than"):
            soon.token()
        assert logins(state) == [URL]
        sekret_cli._FAILED.clear()
        (state / "login_fails").unlink()
        later = CliTokens(state.cli, URL, lock_dir=lock_dir, clock=lambda: time.time() + FAILED_FOR + 1)
        assert later.token() == "cli-token-2"
        assert not list(lock_dir.glob("*.failed"))

    def test_a_failure_marker_that_is_a_link_is_refused(self, state, tmp_path):
        lock_dir = state.parent / "cache" / "sekret"
        lock_dir.mkdir(parents=True, mode=0o700)
        marker = sekret_cli._marker(lock_dir, (state.cli, URL, None))
        marker.symlink_to(tmp_path / "elsewhere")
        with pytest.raises(ConfigError, match="symbolic link"):
            tokens(state).token()
        assert logins(state) == []

    def test_no_browser_login_when_the_caller_forbids_it(self, state):
        refusing = CliTokens(state.cli, URL, lock_dir=state.dir, no_login_reason="the inventory chose it")
        with pytest.raises(AuthenticationError, match="the inventory chose it"):
            refusing.token()
        assert logins(state) == []


class TestRetryAndRedaction:
    def client(self, state, server):
        settings = Settings.from_options({"url": URL, "cli_path": state.cli}, environ={})
        return SekretClient(
            settings,
            transport=server,
            cache=TokenCache(),
            token_source=lambda s: tokens(state),
        )

    def test_a_rejected_saved_token_logs_in_once_and_retries(self, state):
        server = FakeServer()
        server.put("KEY", "value")
        server.tokens = {"cli-token-1"}
        (state / "token").write_text("revoked\n")
        record = self.client(state, server).get_secret("app", "prod", "KEY")
        assert record.value == "value"
        assert logins(state) == [URL]

    def test_a_second_rejection_is_an_error_not_a_loop(self, state):
        server = FakeServer()
        server.tokens = set()
        (state / "token").write_text("revoked\n")
        with pytest.raises(AuthenticationError):
            self.client(state, server).get_secret("app", "prod", "KEY")
        assert logins(state) == [URL]

    def test_the_cli_token_never_appears_in_an_error(self, state):
        server = FakeServer()
        (state / "token").write_text("secret-cli-token\n")
        server.tokens = {"secret-cli-token"}
        server.override = lambda call: (
            None if call.path != "/api/v1/secrets/raw" else error(500, "boom", "bad token secret-cli-token")
        )
        with pytest.raises(Exception) as caught:
            self.client(state, server).list_raw("app", "prod")
        assert "secret-cli-token" not in str(caught.value)
        assert "********" in str(caught.value)


class FakeDisplay:
    def __init__(self):
        self.verbose = []
        self.shown = []

    def v(self, message):
        self.verbose.append(message)

    def display(self, message, *args, **kwargs):
        self.shown.append(message)


@pytest.fixture
def lookup(state, monkeypatch):
    server = EchoServer()
    server.put("WHERE", "here")
    plugin = lookup_loader.get("sekret.secrets.secret")
    plugin.client_factory = lambda settings, token_source=None: SekretClient(
        settings, transport=server, cache=TokenCache(), token_source=token_source
    )
    module = sys.modules[type(plugin).__module__]
    for cache in (module._FOLDERS, module._CONTEXTS, module._ANNOUNCED):
        cache.clear()
    shown = FakeDisplay()
    monkeypatch.setattr(module, "display", shown)
    monkeypatch.setenv("SEKRET_CLI", state.cli)
    plugin.server = server
    plugin.shown = shown
    return plugin


class TestPrecedence:
    """Arguments, then variables, then the environment; ansible.cfg is covered in a real run below."""

    def where(self, lookup, variables=None, **direct):
        lookup.run([], variables or {}, **{"url": URL, "token": "static-token", **direct})
        return lookup.server.asked()

    def test_arguments_beat_variables(self, lookup):
        variables = {"sekret_project": "var-p", "sekret_environment": "var-e"}
        assert self.where(lookup, variables, project="arg-p", environment="arg-e")[:2] == ("arg-p", "arg-e")

    def test_variables_beat_the_environment(self, lookup, monkeypatch):
        monkeypatch.setenv("SEKRET_PROJECT", "env-p")
        monkeypatch.setenv("SEKRET_ENVIRONMENT", "env-e")
        variables = {"sekret_project": "var-p", "sekret_environment": "var-e", "sekret_path": "/v"}
        assert self.where(lookup, variables) == ("var-p", "var-e", "/v")

    def test_the_environment_alone(self, lookup, monkeypatch):
        monkeypatch.setenv("SEKRET_PROJECT", "env-p")
        monkeypatch.setenv("SEKRET_ENVIRONMENT", "env-e")
        monkeypatch.setenv("SEKRET_PATH", "/e")
        assert self.where(lookup) == ("env-p", "env-e", "/e")

    def test_the_cli_fills_only_what_is_still_unset(self, lookup, state, monkeypatch):
        (state / "context.json").write_text(
            json.dumps(
                {
                    "project": "file-p",
                    "project_source": "project_file",
                    "environment": "file-e",
                    "environment_source": "project_file",
                    "path": "/f",
                    "path_source": "project_file",
                }
            )
        )
        assert self.where(lookup) == ("file-p", "file-e", "/f")
        monkeypatch.setenv("SEKRET_ENVIRONMENT", "env-e")
        lookup.server.calls.clear()
        assert self.where(lookup)[:2] == ("file-p", "env-e")
        (argv,) = [c for c in calls(state) if any(a.startswith("--env=") for a in c)]
        assert "--env=env-e" in argv

    def test_an_unconfirmed_project_file_is_refused(self, lookup, state):
        (state / "context_error").write_text(
            "sekret: .sekret.toml picks the project and environment here and has not been confirmed; "
            "run `sekret export` once at a terminal\n"
        )
        with pytest.raises(AnsibleError, match="sekret export"):
            self.where(lookup)

    def test_nothing_anywhere_says_what_to_set(self, lookup):
        with pytest.raises(AnsibleError, match="sekret_project"):
            self.where(lookup)

    def test_where_it_reads_from_is_said_once_at_verbose(self, lookup, monkeypatch):
        monkeypatch.setenv("SEKRET_ENVIRONMENT", "env-e")
        self.where(lookup, {"sekret_project": "var-p"})
        self.where(lookup, {"sekret_project": "var-p"})
        (note,) = lookup.shown.verbose
        assert "var-p/env-e" in note
        assert "sekret_project" in note and "SEKRET_ENVIRONMENT" in note


class TestCaching:
    def test_a_folder_is_fetched_once_a_run(self, lookup):
        for _ in range(3):
            lookup.run([], {}, url=URL, token="static-token", project="p", environment="e")
        assert len(lookup.server.calls_to("GET", "/api/v1/secrets/raw")) == 1

    def test_another_folder_or_identity_is_fetched_again(self, lookup):
        base = {"url": URL, "project": "p", "environment": "e"}
        lookup.server.tokens.add("other-token")
        lookup.run([], {}, token="static-token", **base)
        lookup.run([], {}, token="static-token", path="/other", **base)
        lookup.run([], {}, token="other-token", **base)
        assert len(lookup.server.calls_to("GET", "/api/v1/secrets/raw")) == 3

    def test_changing_a_result_does_not_change_the_cache(self, lookup):
        base = {"url": URL, "token": "static-token", "project": "p", "environment": "e"}
        (first,) = lookup.run([], {}, **base)
        first["WHERE"] = "changed"
        assert lookup.run([], {}, **base) == [{"WHERE": "here"}]

    def test_the_lookup_logs_in_with_the_cli_when_nothing_else_is_set(self, lookup, state):
        lookup.server.tokens = {"cli-token-1"}
        result = lookup.run([], {}, url=URL, project="p", environment="e")
        assert result == [{"WHERE": "here"}]
        assert logins(state) == [URL]
        assert any("approve" in note for note in lookup.shown.shown)


CONTEXT_SERVER = "https://named-by-file.test"


def context_naming(state, confirmed):
    (state / "context.json").write_text(
        json.dumps(
            {
                "server": CONTEXT_SERVER,
                "server_source": "logged_in" if confirmed else "project_file",
                "server_confirmed": confirmed,
                "project_file": "/repo/.sekret.toml",
            }
        )
    )


class TestWhereCredentialsGo:
    """Nothing chosen by an inventory or a project file is sent a token or machine identity."""

    def run(self, lookup, variables=None, **direct):
        return lookup.run([], variables or {}, **{"project": "p", "environment": "e", **direct})

    def test_an_unconfirmed_project_file_server_is_refused(self, lookup, state):
        context_naming(state, confirmed=False)
        with pytest.raises(AnsibleError, match="not confirmed") as caught:
            self.run(lookup)
        assert "/repo/.sekret.toml" in str(caught.value)
        assert lookup.server.calls == []

    def test_a_project_file_server_never_gets_a_token_from_the_environment(self, lookup, state, monkeypatch):
        context_naming(state, confirmed=True)
        monkeypatch.setenv("SEKRET_TOKEN", "static-token")
        with pytest.raises(AnsibleError, match="only your own `sekret login`"):
            self.run(lookup)
        monkeypatch.setenv("SEKRET_CLIENT_ID", "client-1")
        monkeypatch.setenv("SEKRET_CLIENT_SECRET", "client-secret-1")
        monkeypatch.delenv("SEKRET_TOKEN")
        with pytest.raises(AnsibleError, match="only your own `sekret login`"):
            self.run(lookup)
        assert lookup.server.calls == []

    def test_a_logged_in_project_file_server_gets_only_the_cli_login(self, lookup, state):
        context_naming(state, confirmed=True)
        (state / "token").write_text("cli-token-saved\n")
        lookup.server.tokens = {"cli-token-saved"}
        assert self.run(lookup) == [{"WHERE": "here"}]
        assert "--server=" + CONTEXT_SERVER in calls(state)[-1]

    def test_an_inventory_server_never_gets_the_environments_token(self, lookup, monkeypatch):
        monkeypatch.setenv("SEKRET_TOKEN", "static-token")
        with pytest.raises(AnsibleError, match="sekret_url come from inventory") as caught:
            self.run(lookup, {"sekret_url": URL})
        assert "SEKRET_TOKEN" in str(caught.value)
        assert lookup.server.calls == []

    def test_an_inventory_ca_never_gets_the_environments_machine_identity(self, lookup, monkeypatch):
        monkeypatch.setenv("SEKRET_CLIENT_ID", "client-1")
        monkeypatch.setenv("SEKRET_CLIENT_SECRET", "client-secret-1")
        with pytest.raises(AnsibleError, match="sekret_ca_path"):
            self.run(lookup, {"sekret_ca_path": "/attacker-ca.pem"}, url=URL)

    def test_an_inventory_server_with_a_credential_the_playbook_passed_is_fine(self, lookup):
        assert self.run(lookup, {"sekret_url": URL}, token="static-token") == [{"WHERE": "here"}]

    def test_the_environments_server_and_token_together_are_fine(self, lookup, monkeypatch):
        monkeypatch.setenv("SEKRET_URL", URL)
        monkeypatch.setenv("SEKRET_TOKEN", "static-token")
        assert self.run(lookup) == [{"WHERE": "here"}]

    def test_an_inventory_server_gets_a_saved_cli_login_but_no_browser_login(self, lookup, state):
        lookup.server.tokens = {"cli-token-saved"}
        with pytest.raises(AnsibleError, match="will not open a browser"):
            self.run(lookup, {"sekret_url": URL})
        assert logins(state) == []
        (state / "token").write_text("cli-token-saved\n")
        assert self.run(lookup, {"sekret_url": URL}) == [{"WHERE": "here"}]


class TestContextCommand:
    def test_known_settings_are_passed_as_flags(self, state):
        context = cli_context(state.cli, {"url": URL, "project": "p", "ca_path": "/ca.pem"})
        assert (context["server"], context["project"], context["ca_file"]) == (URL, "p", "/ca.pem")
        (argv,) = calls(state)
        assert argv[:2] == ["token", "--context"] and "--env" not in argv

    def test_no_cli_means_no_context(self, state):
        assert cli_context(str(state / "nope"), {}) is None


# Real Ansible runs, for ansible.cfg's place in the order and `sekret env use` beside it.


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        response = self.server.fake(
            "GET", f"http://{self.headers['Host']}{self.path}", dict(self.headers), None, 30
        )
        self.send_response(response.status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(response.body)

    def log_message(self, *args):
        pass


@pytest.fixture
def http_echo():
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    server.fake = EchoServer()
    server.fake.put("WHERE", "here")
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server
    server.shutdown()
    server.server_close()


def ansible_run(tmp_path, state, server, ini, env=None, extra=(), lookup_args=""):
    config = tmp_path / "ansible.cfg"
    config.write_text(f"[defaults]\ncollections_path = {COLLECTIONS_ROOT}\n\n[sekret]\n{ini}")
    environment = {
        "PATH": os.environ["PATH"],
        "HOME": str(tmp_path),
        "ANSIBLE_CONFIG": str(config),
        "ANSIBLE_LOCAL_TEMP": str(tmp_path / "ansible-tmp"),
        "SEKRET_TOKEN": "static-token",
        "SEKRET_URL": f"http://127.0.0.1:{server.server_address[1]}",
        "SEKRET_CLI": state.cli,
        "FAKE_SEKRET_STATE": str(state),
        **(env or {}),
    }
    expression = "{{ lookup('sekret.secrets.secret'" + lookup_args + ") }}"
    result = subprocess.run(
        [
            str(BIN / "ansible"),
            "localhost",
            "-i",
            "localhost,",
            "-c",
            "local",
            "-m",
            "debug",
            "-a",
            f"msg={expression}",
            *extra,
        ],
        env=environment,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    return server.fake.asked()


INI = "project = ini-p\nenvironment = ini-e\npath = /ini\n"


class TestAnsibleCfg:
    def test_ansible_cfg_is_the_default(self, tmp_path, state, http_echo):
        assert ansible_run(tmp_path, state, http_echo, INI) == ("ini-p", "ini-e", "/ini")

    def test_sekret_env_use_beats_ansible_cfg(self, tmp_path, state, http_echo):
        env = {"SEKRET_PROJECT": "env-p", "SEKRET_ENVIRONMENT": "env-e"}
        assert ansible_run(tmp_path, state, http_echo, INI, env)[:2] == ("env-p", "env-e")

    def test_a_variable_beats_sekret_env_use(self, tmp_path, state, http_echo):
        env = {"SEKRET_ENVIRONMENT": "env-e"}
        extra = ("-e", "sekret_environment=var-e")
        assert ansible_run(tmp_path, state, http_echo, INI, env, extra)[1] == "var-e"

    def test_an_argument_beats_a_variable(self, tmp_path, state, http_echo):
        extra = ("-e", "sekret_environment=var-e")
        assert ansible_run(tmp_path, state, http_echo, INI, extra=extra, lookup_args=", environment='arg-e'")[
            1
        ] == ("arg-e")

    def test_ansible_cfg_beats_the_project_file(self, tmp_path, state, http_echo):
        (state / "context.json").write_text(
            json.dumps({"project": "file-p", "project_source": "project_file"})
        )
        assert ansible_run(tmp_path, state, http_echo, INI)[0] == "ini-p"
