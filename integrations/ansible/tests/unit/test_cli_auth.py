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
    SekretError,
    Settings,
    TokenCache,
    resolve_auth,
    terminal_safe,
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
    "SEKRET_LOADED_FILE",
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
    sekret_cli._PRODUCED.clear()
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
        with pytest.raises(AuthenticationError, match="already failed in this Ansible worker process"):
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
        self.warnings = []

    def v(self, message):
        self.verbose.append(message)

    def warning(self, message, *args, **kwargs):
        self.warnings.append(message)

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
    for cache in (module._FOLDERS, module._CONTEXTS, module._ANNOUNCED, module._WARNED):
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
        with pytest.raises(AnsibleError, match="sekret_url comes from an inventory variable"):
            self.run(lookup, {"sekret_url": URL})
        assert lookup.server.calls == []

    def test_an_inventory_ca_never_gets_the_environments_machine_identity(self, lookup, monkeypatch):
        monkeypatch.setenv("SEKRET_CLIENT_ID", "client-1")
        monkeypatch.setenv("SEKRET_CLIENT_SECRET", "client-secret-1")
        with pytest.raises(AnsibleError, match="sekret_ca_path"):
            self.run(lookup, {"sekret_ca_path": "/attacker-ca.pem"}, url=URL)

    def test_an_inventory_server_never_gets_a_credential_the_playbook_passed_either(self, lookup):
        with pytest.raises(AnsibleError, match="not even one passed to the lookup"):
            self.run(lookup, {"sekret_url": URL}, token="static-token")
        with pytest.raises(AnsibleError, match="not even one passed to the lookup"):
            self.run(lookup, {"sekret_url": URL}, client_id="client-1", client_secret="client-secret-1")
        assert lookup.server.calls == []

    def test_a_server_passed_to_the_lookup_with_a_token_passed_too_is_fine(self, lookup):
        assert self.run(lookup, url=URL, token="static-token") == [{"WHERE": "here"}]

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


class TestInventoryCa:
    """A CA file replaces every other CA the server is checked against, so one an inventory chose
    must not carry even the saved login unless a trusted setting names the same file."""

    def run(self, lookup, **direct):
        return lookup.run(
            [], {"sekret_ca_path": "/repo/certs/ca.pem"}, project="p", environment="e", **direct
        )

    def test_an_inventory_ca_never_carries_the_saved_login(self, lookup, state, monkeypatch):
        (state / "token").write_text("cli-token-saved\n")
        lookup.server.tokens = {"cli-token-saved"}
        monkeypatch.setenv("SEKRET_URL", URL)
        with pytest.raises(AnsibleError, match="nothing is sent through it"):
            self.run(lookup)
        assert lookup.server.calls == []
        assert not [c for c in calls(state) if c[:1] == ["token"] and "--context" not in c]

    def test_an_inventory_ca_never_carries_a_token_the_playbook_passed(self, lookup, monkeypatch):
        monkeypatch.setenv("SEKRET_URL", URL)
        with pytest.raises(AnsibleError, match="nor a credential passed to the lookup"):
            self.run(lookup, token="static-token")
        assert lookup.server.calls == []

    def test_the_same_ca_in_the_environment_vouches_for_it(self, lookup, state, monkeypatch):
        (state / "token").write_text("cli-token-saved\n")
        lookup.server.tokens = {"cli-token-saved"}
        monkeypatch.setenv("SEKRET_URL", URL)
        monkeypatch.setenv("SEKRET_CA_PATH", "/repo/certs/../certs/ca.pem")
        assert self.run(lookup) == [{"WHERE": "here"}]

    def test_the_same_ca_in_the_clis_own_settings_vouches_for_it(self, lookup, state, monkeypatch):
        (state / "token").write_text("cli-token-saved\n")
        (state / "context.json").write_text(json.dumps({"ca_file": "/repo/certs/ca.pem"}))
        lookup.server.tokens = {"cli-token-saved"}
        monkeypatch.setenv("SEKRET_URL", URL)
        assert self.run(lookup) == [{"WHERE": "here"}]

    def test_another_ca_in_the_environment_does_not(self, lookup, state, monkeypatch):
        (state / "token").write_text("cli-token-saved\n")
        monkeypatch.setenv("SEKRET_URL", URL)
        monkeypatch.setenv("SEKRET_CA_PATH", "/etc/ssl/real-ca.pem")
        with pytest.raises(AnsibleError, match="nothing is sent through it"):
            self.run(lookup)


class TestTerminalSafety:
    def test_a_project_file_path_cannot_reach_the_terminal_raw(self, lookup, state):
        # The project comes from the CLI too, since the folder alone never calls it.
        (state / "context.json").write_text(
            json.dumps({"project": "p", "path": "/a\x1b[2J‮b", "path_source": "project_file"})
        )
        lookup.server.put("KEY", "value", path="/elsewhere")
        with pytest.raises(AnsibleError) as caught:
            lookup.run(["KEY"], {}, url=URL, token="static-token", environment="e")
        message = str(caught.value)
        assert "\x1b" not in message and "‮" not in message
        assert "\\u001b" in message and "\\u202e" in message
        (note,) = lookup.shown.verbose
        assert "\x1b" not in note and "‮" not in note

    def test_an_unconfirmed_server_with_controls_is_shown_escaped(self, lookup, state):
        (state / "context.json").write_text(
            json.dumps({"server": "https://x.test/\x9b31m", "server_confirmed": False})
        )
        with pytest.raises(AnsibleError) as caught:
            lookup.run([], {}, project="p", environment="e")
        assert "\x9b" not in str(caught.value) and "\\u009b" in str(caught.value)

    def test_login_lines_are_shown_escaped(self, lookup, state):
        lookup.server.tokens = {"cli-token-1"}
        # The login, and what it prints, comes before the request, which the odd URL fails.
        with pytest.raises(AnsibleError):
            lookup.run([], {}, url=URL + "/‮", project="p", environment="e")
        assert logins(state)
        assert lookup.shown.shown
        assert all("‮" not in line for line in lookup.shown.shown)
        assert any("\\u202e" in line for line in lookup.shown.shown)

    def test_terminal_safe_keeps_printable_text(self):
        assert terminal_safe("café /a b") == "café /a b"
        assert terminal_safe("a\nb\U0001f600") == "a\\u000ab\U0001f600"


def _log_in_then_be_rejected(cli, lock_dir, barrier, results):
    barrier.wait()
    source = CliTokens(cli, URL, lock_dir=Path(lock_dir))
    token = source.token()
    try:
        source.refresh(token)
        results.put("logged in again")
    except AuthenticationError as e:
        results.put(e.message)


class TestRejectedFreshTokens:
    """A server that rejects the token a login just produced, behind a proxy dropping the
    Authorization header say, gets one browser login, not one per lookup or worker."""

    def test_lookups_in_one_process_log_in_once(self, lookup, state):
        lookup.server.tokens = set()
        base = {"url": URL, "project": "p", "environment": "e"}
        with pytest.raises(AnsibleError, match="just produced"):
            lookup.run([], {}, **base)
        with pytest.raises(AnsibleError, match="already failed in this Ansible worker process"):
            lookup.run([], {}, path="/other", **base)
        assert logins(state) == [URL]

    def test_workers_in_several_processes_log_in_once(self, state):
        context = multiprocessing.get_context("fork")
        workers = 4
        barrier = context.Barrier(workers)
        results = context.Queue()
        lock_dir = str(state.parent / "cache" / "sekret")
        processes = [
            context.Process(target=_log_in_then_be_rejected, args=(state.cli, lock_dir, barrier, results))
            for _ in range(workers)
        ]
        for process in processes:
            process.start()
        got = [results.get(timeout=15) for _ in processes]
        for process in processes:
            process.join(timeout=15)
        assert all("just produced" in message for message in got), got
        assert logins(state) == [URL]

    def test_a_revoked_older_token_still_gets_a_new_login(self, state):
        (state / "token").write_text("revoked\n")
        assert tokens(state).refresh("revoked") == "cli-token-1"


class TestShellLoadedElsewhere:
    """`sekret env use` records the project file it loaded under; a lookup in another project's
    folder, set up by ansible.cfg or a .sekret.toml, must not quietly use what it left behind.
    The check is the lookup's own, so it holds with no CLI at all."""

    @pytest.fixture(autouse=True)
    def repo_b(self, tmp_path, monkeypatch, lookup, state):
        folder = tmp_path / "repo-b"
        folder.mkdir()
        monkeypatch.chdir(folder)
        # No CLI: whatever is refused here is refused by the lookup itself.
        monkeypatch.setenv("SEKRET_CLI", str(tmp_path / "no-such-sekret"))
        lookup.read_ansible_cfg = staticmethod(lambda: {"project": "b-project", "environment": "prod"})
        return folder

    def run(self, lookup):
        return lookup.run([], {}, url=URL, token="static-token")

    def shell(self, monkeypatch, loaded=None, project="a-project", environment="prod", path=None):
        monkeypatch.setenv("SEKRET_PROJECT", project)
        monkeypatch.setenv("SEKRET_ENVIRONMENT", environment)
        if path is not None:
            monkeypatch.setenv("SEKRET_PATH", path)
        if loaded is not None:
            monkeypatch.setenv("SEKRET_LOADED_FILE", loaded)

    def test_a_shell_loaded_under_another_file_is_refused_against_ansible_cfg(self, lookup, monkeypatch):
        self.shell(monkeypatch, "/repo-a/.sekret.toml")
        with pytest.raises(
            AnsibleError, match=r"SEKRET_PROJECT is a-project in this shell but ansible\.cfg"
        ) as caught:
            self.run(lookup)
        assert "sekret-env off" in str(caught.value)
        assert lookup.server.calls == []

    def test_the_same_values_are_used(self, lookup, monkeypatch):
        self.shell(monkeypatch, "/repo-a/.sekret.toml", project="b-project")
        assert self.run(lookup) == [{"WHERE": "here"}]

    def test_values_set_by_hand_are_used(self, lookup, monkeypatch):
        self.shell(monkeypatch)
        assert self.run(lookup) == [{"WHERE": "here"}]
        assert lookup.server.asked()[0] == "a-project"

    def test_a_stale_folder_is_refused(self, lookup, monkeypatch):
        lookup.read_ansible_cfg = staticmethod(lambda: {"path": "/b"})
        self.shell(monkeypatch, "/repo-a/.sekret.toml", path="/a")
        with pytest.raises(AnsibleError, match="SEKRET_PATH is /a"):
            self.run(lookup)

    @pytest.mark.skipif(sys.version_info < (3, 11), reason="reading .sekret.toml needs tomllib")
    def test_a_shell_loaded_under_another_file_is_refused_against_this_folders_file(
        self, lookup, monkeypatch, repo_b
    ):
        lookup.read_ansible_cfg = staticmethod(dict)
        (repo_b / ".sekret.toml").write_text('project = "b-project"\n')
        self.shell(monkeypatch, "/repo-a/.sekret.toml")
        with pytest.raises(AnsibleError, match=r"\.sekret\.toml says b-project"):
            self.run(lookup)
        monkeypatch.setenv("SEKRET_LOADED_FILE", str(repo_b / ".sekret.toml"))
        assert self.run(lookup) == [{"WHERE": "here"}]

    def test_loaded_with_no_project_file_and_none_here_is_the_same_place(self, lookup, monkeypatch):
        self.shell(monkeypatch, "")
        assert self.run(lookup) == [{"WHERE": "here"}]


class TestShellCheckWithoutTomllib:
    """Python 3.10 cannot read .sekret.toml, so the CLI compares the shell's values with it, which
    only works if they reach it through the environment; with no CLI the lookup refuses."""

    @pytest.fixture(autouse=True)
    def python_310(self, tmp_path, monkeypatch, lookup):
        folder = tmp_path / "repo-b"
        folder.mkdir()
        (folder / ".sekret.toml").write_text('project = "b-project"\n')
        monkeypatch.chdir(folder)
        monkeypatch.setattr(sys.modules[type(lookup).__module__], "tomllib", None)
        lookup.read_ansible_cfg = staticmethod(dict)
        monkeypatch.setenv("SEKRET_PROJECT", "a-project")
        monkeypatch.setenv("SEKRET_ENVIRONMENT", "prod")
        monkeypatch.setenv("SEKRET_LOADED_FILE", "/repo-a/.sekret.toml")

    def run(self, lookup):
        return lookup.run([], {}, url=URL, token="static-token")

    def test_with_no_cli_it_refuses_rather_than_guess(self, lookup, monkeypatch, tmp_path):
        monkeypatch.setenv("SEKRET_CLI", str(tmp_path / "no-such-sekret"))
        with pytest.raises(AnsibleError, match=r"cannot read .*\.sekret\.toml"):
            self.run(lookup)
        assert lookup.server.calls == []

    def test_the_clis_own_check_runs_with_the_values_left_in_the_environment(self, lookup, state):
        (state / "context_error").write_text(
            "sekret: SEKRET_PROJECT is a-project in this shell but .sekret.toml says b-project; these were "
            "loaded by `sekret-env` under /repo-a/.sekret.toml, so not using them here\n"
        )
        with pytest.raises(AnsibleError, match="loaded by `sekret-env`"):
            self.run(lookup)
        (argv,) = [c for c in calls(state) if "--context" in c]
        assert not any(a.startswith(("--project=", "--env=", "--path=")) for a in argv)
        assert lookup.server.calls == []

    def test_when_the_cli_agrees_the_lookup_goes_ahead(self, lookup, state):
        assert self.run(lookup) == [{"WHERE": "here"}]
        assert lookup.server.asked()[0] == "a-project"


class TestEmptyValuesFallThrough:
    def run(self, lookup, variables, **direct):
        return lookup.run([], variables, **{"environment": "e", **direct})

    def test_an_empty_inventory_url_falls_through_to_the_environment(self, lookup, monkeypatch):
        monkeypatch.setenv("SEKRET_URL", URL)
        monkeypatch.setenv("SEKRET_TOKEN", "static-token")
        assert self.run(lookup, {"sekret_url": ""}, project="p") == [{"WHERE": "here"}]

    def test_an_empty_inventory_ca_falls_through_to_the_environment(self, lookup, monkeypatch, tmp_path):
        monkeypatch.setenv("SEKRET_CA_PATH", str(tmp_path / "env-ca.pem"))
        used = []
        factory = lookup.client_factory
        lookup.client_factory = lambda settings, token_source=None: (
            used.append(settings.ca_path) or factory(settings, token_source=token_source)
        )
        self.run(lookup, {"sekret_ca_path": ""}, url=URL, token="static-token", project="p")
        assert used == [str(tmp_path / "env-ca.pem")]

    def test_an_empty_project_falls_through_to_the_environment_with_its_origin(self, lookup, monkeypatch):
        monkeypatch.setenv("SEKRET_PROJECT", "env-p")
        self.run(lookup, {"sekret_project": ""}, url=URL, token="static-token")
        assert lookup.server.asked()[0] == "env-p"
        (note,) = lookup.shown.verbose
        assert "project from env: SEKRET_PROJECT" in note

    def test_an_empty_environment_variable_falls_through_to_ansible_cfg(self, lookup, monkeypatch):
        monkeypatch.setenv("SEKRET_PROJECT", "")
        lookup.read_ansible_cfg = staticmethod(lambda: {"project": "ini-p"})
        self.run(lookup, {}, url=URL, token="static-token")
        assert lookup.server.asked()[0] == "ini-p"

    def test_an_empty_argument_falls_through_to_the_inventory(self, lookup):
        self.run(lookup, {"sekret_project": "var-p"}, project="", url=URL, token="static-token")
        assert lookup.server.asked()[0] == "var-p"


class TestInventoryOverridesEnvironmentWarning:
    """sekret_* variables now outrank SEKRET_*, which a playbook written before may not expect."""

    def run(self, lookup, variables):
        return lookup.run([], variables, url=URL, token="static-token", environment="e")

    def test_an_inventory_variable_beating_a_different_environment_value_warns_once(
        self, lookup, monkeypatch
    ):
        monkeypatch.setenv("SEKRET_PROJECT", "env-secret-project")
        self.run(lookup, {"sekret_project": "var-secret-project"})
        self.run(lookup, {"sekret_project": "var-secret-project"})
        (warning,) = lookup.shown.warnings
        assert "sekret_project" in warning and "SEKRET_PROJECT" in warning
        assert "env-secret-project" not in warning and "var-secret-project" not in warning
        assert lookup.server.asked()[0] == "var-secret-project"

    def test_the_same_value_or_no_environment_value_does_not_warn(self, lookup, monkeypatch):
        self.run(lookup, {"sekret_project": "p"})
        monkeypatch.setenv("SEKRET_PROJECT", "p")
        self.run(lookup, {"sekret_project": "p"})
        assert lookup.shown.warnings == []


class TestUnreadableProjectFile:
    """A .sekret.toml the CLI would trust but cannot read or parse stops the env use check, as it
    stops the CLI, rather than being passed over for a parent's or counted as naming nothing."""

    @pytest.fixture(autouse=True)
    def shell(self, tmp_path, monkeypatch, lookup):
        tmp_path.chmod(0o700)
        parent = tmp_path / ".sekret.toml"
        parent.write_text('project = "a-project"\n')
        parent.chmod(0o600)
        folder = tmp_path / "repo"
        folder.mkdir(mode=0o700)
        monkeypatch.chdir(folder)
        lookup.read_ansible_cfg = staticmethod(dict)
        monkeypatch.setenv("SEKRET_PROJECT", "a-project")
        monkeypatch.setenv("SEKRET_ENVIRONMENT", "prod")
        monkeypatch.setenv("SEKRET_LOADED_FILE", str(parent))
        return folder

    def write(self, folder, data: bytes):
        project_file = folder / ".sekret.toml"
        project_file.write_bytes(data)
        project_file.chmod(0o600)

    @pytest.mark.skipif(sys.version_info < (3, 11), reason="reading .sekret.toml needs tomllib")
    def test_invalid_toml_is_refused(self, lookup, shell):
        self.write(shell, b"project = [unterminated\n")
        with pytest.raises(AnsibleError, match="is not valid TOML"):
            lookup.run([], {}, url=URL, token="static-token")
        assert lookup.server.calls == []

    def test_a_file_that_is_not_utf8_is_refused(self, lookup, shell):
        self.write(shell, b'project = "\xff\xfe"\n')
        with pytest.raises(AnsibleError, match="is not UTF-8"):
            lookup.run([], {}, url=URL, token="static-token")
        assert lookup.server.calls == []


class TestProjectFileTrust:
    """The lookup reads .sekret.toml only where the CLI would, so a file planted in a shared folder
    cannot make it refuse or choose anything."""

    def me(self, private_group=False):
        return sekret_cli.Me(os.geteuid(), os.getegid(), private_group)

    def test_a_file_in_a_folder_everyone_can_write_is_skipped(self, tmp_path):
        tmp_path.chmod(0o700)
        (tmp_path / ".sekret.toml").write_text('project = "trusted"\n')
        (tmp_path / ".sekret.toml").chmod(0o600)
        shared = tmp_path / "shared"
        shared.mkdir()
        shared.chmod(0o777)
        (shared / ".sekret.toml").write_text('project = "planted"\n')
        found = sekret_cli.nearest_project_file(str(shared), self.me())
        assert found is not None and found[0] == tmp_path / ".sekret.toml"

    def test_a_file_its_group_can_write_is_skipped_unless_the_group_is_private(self, tmp_path):
        tmp_path.chmod(0o700)
        project_file = tmp_path / ".sekret.toml"
        project_file.write_text('project = "x"\n')
        project_file.chmod(0o660)
        assert sekret_cli.nearest_project_file(str(tmp_path), self.me()) is None
        assert sekret_cli.nearest_project_file(str(tmp_path), self.me(private_group=True)) is not None

    def test_another_users_file_or_folder_is_distrusted(self):
        me = self.me()
        mine = os.stat_result((0o100600, 0, 0, 1, me.uid, me.gid, 0, 0, 0, 0))
        folder = os.stat_result((0o040755, 0, 0, 1, me.uid, me.gid, 0, 0, 0, 0))
        assert sekret_cli.distrust_reason([me.uid], folder, mine, me) is None
        assert "another user" in sekret_cli.distrust_reason([me.uid + 1], folder, mine, me)
        others = os.stat_result((0o040755, 0, 0, 1, me.uid + 1, me.gid, 0, 0, 0, 0))
        assert "directory belongs to another user" in sekret_cli.distrust_reason([me.uid], others, mine, me)
        roots = os.stat_result((0o040755, 0, 0, 1, 0, 0, 0, 0, 0, 0))
        assert sekret_cli.distrust_reason([me.uid], roots, mine, me) is None

    def test_a_private_group_is_one_nobody_else_is_in(self):
        passwd = "me:x:1000:1000::/home/me:/bin/sh\nother:x:1001:1001::/home/other:/bin/sh\n"
        assert sekret_cli.group_holds_only("me:x:1000:\n", passwd, 1000, 1000)
        assert not sekret_cli.group_holds_only("me:x:1000:other\n", passwd, 1000, 1000)
        assert not sekret_cli.group_holds_only("staff:x:1001:\n", passwd, 1001, 1000)
        assert not sekret_cli.group_holds_only("", passwd, 1000, 1000)

    def test_a_planted_file_cannot_make_the_lookup_refuse(self, lookup, tmp_path, monkeypatch):
        shared = tmp_path / "shared"
        shared.mkdir()
        shared.chmod(0o777)
        (shared / ".sekret.toml").write_text('project = "planted"\n')
        monkeypatch.chdir(shared)
        lookup.read_ansible_cfg = staticmethod(dict)
        monkeypatch.setenv("SEKRET_PROJECT", "mine")
        monkeypatch.setenv("SEKRET_ENVIRONMENT", "prod")
        monkeypatch.setenv("SEKRET_LOADED_FILE", "")
        assert lookup.run([], {}, url=URL, token="static-token") == [{"WHERE": "here"}]


class TestContextOnlyWhenNeeded:
    """The CLI's settings are read only for a missing server, project or environment, so a token
    or machine identity lookup works whatever the CLI is, or thinks of the server."""

    @pytest.mark.parametrize("cli", ["missing", "old", "refuses"])
    def test_a_folder_alone_never_calls_the_cli(self, lookup, state, monkeypatch, tmp_path, cli):
        if cli == "missing":
            monkeypatch.setenv("SEKRET_CLI", str(tmp_path / "no-such-sekret"))
        elif cli == "old":
            monkeypatch.setenv("SEKRET_CLI", "false")
        else:
            (state / "context_error").write_text("sekret: http://remote.test is plain http\n")
        result = lookup.run(
            [], {}, url="http://remote.test", token="static-token", project="p", environment="e"
        )
        assert result == [{"WHERE": "here"}]
        assert lookup.server.asked() == ("p", "e", "/")
        assert calls(state) == []

    def test_a_missing_project_still_asks_and_a_refusal_is_fatal(self, lookup, state):
        (state / "context_error").write_text("sekret: no\n")
        with pytest.raises(AnsibleError, match="could not read the sekret CLI's settings"):
            lookup.run([], {}, url=URL, token="static-token", environment="e")


class TestCliLoginChecksCertificates:
    def test_the_cli_login_with_certificate_checks_off_is_refused(self, lookup, state):
        (state / "token").write_text("cli-token-saved\n")
        with pytest.raises(AnsibleError, match="validate_certs is off"):
            lookup.run([], {}, url=URL, project="p", environment="e", validate_certs=False)
        assert lookup.server.calls == []
        assert not [c for c in calls(state) if c[:1] == ["token"] and "--context" not in c]


class TestCachedTokensAreRedacted:
    def test_a_token_another_client_logged_in_for_is_still_redacted(self):
        server = FakeServer()
        cache = TokenCache()
        settings = Settings.from_options(
            {"url": URL, "client_id": "client-1", "client_secret": "client-secret-1"}, environ={}
        )
        SekretClient(settings, transport=server, cache=cache).list_raw("app", "prod")
        server.override = lambda call: (
            error(500, "boom", "your token issued-1 is odd") if call.path == "/api/v1/secrets/raw" else None
        )
        with pytest.raises(Exception) as caught:
            SekretClient(settings, transport=server, cache=cache).list_raw("app", "prod")
        assert "issued-1" not in str(caught.value)

    def test_a_cached_cli_token_is_still_redacted(self, state):
        (state / "token").write_text("cli-cached-token\n")
        server = FakeServer()
        server.tokens = {"cli-cached-token"}
        cache = TokenCache()
        settings = Settings.from_options({"url": URL}, environ={})

        def client():
            return SekretClient(settings, transport=server, cache=cache, token_source=lambda s: tokens(state))

        client().list_raw("app", "prod")
        server.override = lambda call: error(500, "boom", "bad cli-cached-token")
        with pytest.raises(Exception) as caught:
            client().list_raw("app", "prod")
        assert "cli-cached-token" not in str(caught.value)


class TestApprovedCaPath:
    def test_the_trusted_settings_path_is_loaded_not_the_inventorys(
        self, lookup, state, tmp_path, monkeypatch
    ):
        real = tmp_path / "real-ca.pem"
        real.write_text("ca")
        link = tmp_path / "inventory-ca.pem"
        link.symlink_to(real)
        monkeypatch.setenv("SEKRET_CA_PATH", str(real))
        (state / "token").write_text("cli-token-saved\n")
        lookup.server.tokens = {"cli-token-saved"}
        used = []
        factory = lookup.client_factory
        lookup.client_factory = lambda settings, token_source=None: (
            used.append(settings.ca_path) or factory(settings, token_source=token_source)
        )
        lookup.run([], {"sekret_ca_path": str(link)}, url=URL, project="p", environment="e")
        assert used == [str(real)]


class TestOddSettings:
    def test_the_lock_outlasts_a_login(self):
        assert sekret_cli.LOCK_WAIT > sekret_cli.LOGIN_WAIT

    def test_a_nul_in_a_setting_is_a_clear_error(self, state):
        with pytest.raises(ConfigError, match="NUL"):
            CliTokens(state.cli, URL + "\x00", lock_dir=state.dir).token()
        with pytest.raises(ConfigError, match="NUL"):
            cli_context(state.cli, {"url": URL, "project": "p\x00"})

    def test_a_file_error_beside_the_lock_is_a_sekret_error(self, state):
        lock_dir = state.parent / "cache" / "sekret"
        lock_dir.mkdir(parents=True, mode=0o700)
        sekret_cli._beside_lock(lock_dir, (state.cli, URL, None), "produced").mkdir()
        with pytest.raises(SekretError, match="could not") as caught:
            tokens(state).token()
        assert not isinstance(caught.value, OSError)


def envs(state):
    path = state / "envs"
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


class TestCliEnvironment:
    """The CLI runs without the controller's machine credentials, so `sekret login` is always the
    person's own browser login and nothing else reaches a server the CLI was pointed at."""

    def test_no_machine_credential_reaches_token_login_or_context(self, lookup, state, monkeypatch):
        for name in sekret_cli.MACHINE_CREDENTIALS:
            monkeypatch.setenv(name, "x")
        monkeypatch.setenv("SEKRET_AUTH_METHOD", "cli")
        monkeypatch.setenv("SEKRET_PROJECT", "p")
        monkeypatch.setenv("SEKRET_ENVIRONMENT", "e")
        monkeypatch.setenv("SEKRET_LOADED_FILE", "/repo/.sekret.toml")
        monkeypatch.setenv("SEKRET_CA_FILE", "/ca.pem")
        lookup.server.tokens = {"cli-token-1"}
        assert lookup.run([], {}, url=URL) == [{"WHERE": "here"}]
        kinds = {tuple(argv[:2]) for argv in calls(state)}
        assert {("token", "--context"), ("token", f"--server={URL}"), ("login", f"--server={URL}")} <= kinds
        assert logins(state) == [URL]
        for seen in envs(state):
            assert not set(seen) & set(sekret_cli.MACHINE_CREDENTIALS), seen
            assert {"SEKRET_PROJECT", "SEKRET_ENVIRONMENT", "SEKRET_LOADED_FILE", "SEKRET_CA_FILE"} <= set(
                seen
            )

    def test_the_environment_given_to_the_cli_keeps_everything_else(self):
        environ = {"PATH": "/bin", "SEKRET_CLIENT_SECRET": "s", "SEKRET_PATH": "/x", "SEKRET_URL": "u"}
        assert sekret_cli.cli_environment(environ) == {"PATH": "/bin", "SEKRET_PATH": "/x"}


class TestRefreshReadsTheSavedLoginFirst:
    """After a 401, a login saved since by another worker or by hand is used before any thought of
    logging in, even where the lookup could not log in itself."""

    @pytest.mark.parametrize("blocked", ["cli_login off", "inventory server"])
    def test_a_newer_saved_login_is_used(self, state, blocked):
        (state / "token").write_text("newer\n")
        source = CliTokens(
            state.cli,
            URL,
            lock_dir=state.dir,
            login=blocked != "cli_login off",
            no_login_reason="the inventory chose it" if blocked == "inventory server" else None,
        )
        assert source.refresh("older") == "newer"
        assert logins(state) == []

    def test_the_same_rejected_login_still_needs_a_new_one(self, state):
        (state / "token").write_text("older\n")
        source = CliTokens(state.cli, URL, lock_dir=state.dir, login=False)
        with pytest.raises(AuthenticationError, match="cli_login is off"):
            source.refresh("older")


class TestProducedTokensAcrossRuns:
    def test_a_token_another_process_produced_long_ago_gets_one_new_login(self, state):
        lock_dir = state.parent / "cache" / "sekret"
        first = tokens(state).token()
        sekret_cli._PRODUCED.clear()
        later = CliTokens(
            state.cli, URL, lock_dir=lock_dir, clock=lambda: time.time() + sekret_cli.PRODUCED_FOR + 1
        )
        assert later.refresh(first) == "cli-token-2"
        assert logins(state) == [URL, URL]

    def test_within_the_same_process_it_still_counts_however_old(self, state):
        lock_dir = state.parent / "cache" / "sekret"
        first = tokens(state).token()
        later = CliTokens(
            state.cli, URL, lock_dir=lock_dir, clock=lambda: time.time() + 10 * sekret_cli.PRODUCED_FOR
        )
        with pytest.raises(AuthenticationError, match="just produced"):
            later.refresh(first)
        assert logins(state) == [URL]


class TestLockPerServer:
    def test_a_pending_login_to_one_server_does_not_hold_up_another(self, state):
        lock_dir = state.parent / "cache" / "sekret"
        lock_dir.mkdir(parents=True, mode=0o700)
        other = "https://other.test"
        held = os.open(
            sekret_cli._beside_lock(lock_dir, (state.cli, other, None), "lock"), os.O_RDWR | os.O_CREAT, 0o600
        )
        fcntl.flock(held, fcntl.LOCK_EX)
        try:
            quick = CliTokens(state.cli, URL, lock_dir=lock_dir, lock_wait=5)
            assert quick.token() == "cli-token-1"
            # The fake CLI keeps one saved token for every server, so make the other one need a login.
            sekret_cli._PRODUCED.clear()
            blocked = CliTokens(state.cli, other, lock_dir=lock_dir, lock_wait=0)
            with pytest.raises(AuthenticationError, match="giving up"):
                blocked.refresh("cli-token-1")
        finally:
            os.close(held)


class TestFolderCacheAndCa:
    def test_a_folder_read_through_another_ca_is_fetched_again(self, lookup, tmp_path):
        base = {"url": URL, "token": "static-token", "project": "p", "environment": "e"}
        lookup.run([], {}, **base)
        lookup.run([], {}, ca_path=str(tmp_path / "ca.pem"), **base)
        lookup.run([], {}, validate_certs=False, **base)
        assert len(lookup.server.calls_to("GET", "/api/v1/secrets/raw")) == 3

    def test_the_cli_login_with_a_ca_directory_is_refused(self, lookup, state, tmp_path):
        (state / "token").write_text("cli-token-saved\n")
        with pytest.raises(AnsibleError, match="needs a CA file"):
            lookup.run([], {}, url=URL, project="p", environment="e", ca_path=str(tmp_path))
        assert lookup.server.calls == []

    def test_without_a_ca_path_the_cli_login_uses_the_clis_own_ca(self, lookup, state, monkeypatch):
        (state / "token").write_text("cli-token-saved\n")
        (state / "context.json").write_text(
            json.dumps({"ca_file": "/home/me/ca.pem", "ca_file_source": "user_config"})
        )
        lookup.server.tokens = {"cli-token-saved"}
        used = []
        factory = lookup.client_factory
        lookup.client_factory = lambda settings, token_source=None: (
            used.append(settings.ca_path) or factory(settings, token_source=token_source)
        )
        lookup.run([], {}, url=URL, project="p", environment="e")
        assert used == ["/home/me/ca.pem"]
        assert calls(state)[-1][-1] == "--ca-file=/home/me/ca.pem"

    def test_a_token_from_elsewhere_keeps_the_system_cas(self, lookup, state):
        (state / "context.json").write_text(json.dumps({"ca_file": "/home/me/ca.pem"}))
        used = []
        factory = lookup.client_factory
        lookup.client_factory = lambda settings, token_source=None: (
            used.append(settings.ca_path) or factory(settings, token_source=token_source)
        )
        lookup.run([], {}, url=URL, token="static-token", project="p", environment="e")
        assert used == [None]


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


def ansible_run(tmp_path, state, server, ini, env=None, extra=(), lookup_args="", refused=False):
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
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    if refused:
        assert result.returncode != 0, result.stdout
        return result.stdout + result.stderr
    assert result.returncode == 0, result.stdout + result.stderr
    return server.fake.asked()


INI = "project = ini-p\nenvironment = ini-e\npath = /ini\n"


class TestAnsibleCfg:
    def test_ansible_cfg_is_the_default(self, tmp_path, state, http_echo):
        assert ansible_run(tmp_path, state, http_echo, INI) == ("ini-p", "ini-e", "/ini")

    def test_sekret_env_use_beats_ansible_cfg(self, tmp_path, state, http_echo):
        env = {"SEKRET_PROJECT": "env-p", "SEKRET_ENVIRONMENT": "env-e"}
        assert ansible_run(tmp_path, state, http_echo, INI, env)[:2] == ("env-p", "env-e")

    def test_but_not_when_it_loaded_them_for_another_repository(self, tmp_path, state, http_echo):
        env = {
            "SEKRET_PROJECT": "env-p",
            "SEKRET_ENVIRONMENT": "env-e",
            "SEKRET_LOADED_FILE": "/elsewhere/repo-a/.sekret.toml",
        }
        output = ansible_run(tmp_path, state, http_echo, INI, env, refused=True)
        assert "SEKRET_PROJECT is env-p in this shell but ansible.cfg says ini-p" in output
        assert http_echo.fake.calls == []

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
