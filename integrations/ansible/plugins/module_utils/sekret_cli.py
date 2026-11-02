"""The sekret CLI on the controller: the login `sekret login` saved, and the project file's settings.

Only the lookup uses this. The token travels over a pipe from `sekret token`, never through an
argument, the environment or a file of ours.
"""

from __future__ import annotations

import contextlib
import fcntl
import json
import os
import stat
import subprocess
from collections.abc import Callable, Iterator, Mapping
from pathlib import Path

from ansible_collections.sekret.secrets.plugins.module_utils.sekret_client import (
    AuthenticationError,
    ConfigError,
    SekretError,
)

# `sekret token` exit codes.
EXIT_NOT_LOGGED_IN = 3
EXIT_EXPIRED = 4
LOCK_NAME = "ansible-login.lock"

Notify = Callable[[str], None]
Run = Callable[[list[str]], subprocess.CompletedProcess]
RunLogin = Callable[[list[str], Notify], int]


def run(argv: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True, text=True, check=False)


def run_login(argv: list[str], notify: Notify) -> int:
    """Runs `sekret login`, passing each line it prints (the link and the code) to `notify`."""
    with subprocess.Popen(
        argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
    ) as process:
        for line in process.stdout or ():
            if line.strip():
                notify(f"sekret: {line.rstrip()}")
        return process.wait()


def cache_dir(environ: Mapping[str, str] | None = None) -> Path:
    environ = os.environ if environ is None else environ
    base = environ.get("XDG_CACHE_HOME") or os.path.join(os.path.expanduser("~"), ".cache")
    return Path(base) / "sekret"


@contextlib.contextmanager
def login_lock(directory: Path) -> Iterator[None]:
    """Holds an exclusive lock so that of several Ansible workers, only one runs `sekret login`."""
    try:
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = os.lstat(directory)
    except OSError as e:
        raise ConfigError(f"could not create {directory}: {e.strerror}") from None
    if not stat.S_ISDIR(info.st_mode):
        raise ConfigError(f"{directory} is not a directory; not taking the sekret login lock there")
    if info.st_uid != os.getuid() or info.st_mode & 0o022:
        raise ConfigError(f"{directory} is not private to you; not taking the sekret login lock there")
    flags = os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        fd = os.open(directory / LOCK_NAME, flags, 0o600)
    except OSError as e:
        raise ConfigError(f"could not open the sekret login lock in {directory}: {e.strerror}") from None
    try:
        if os.fstat(fd).st_uid != os.getuid():
            raise ConfigError(f"the sekret login lock in {directory} belongs to someone else")
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def _missing_cli(cli_path: str) -> ConfigError:
    return ConfigError(
        f"the sekret CLI ({cli_path}) was not found; install it, or set cli_path or SEKRET_CLI"
    )


class CliTokens:
    """The saved login for one server, logging in through the browser when there is none."""

    def __init__(
        self,
        cli_path: str,
        url: str,
        ca_path: str | None = None,
        login: bool = True,
        notify: Notify = lambda _message: None,
        runner: Run = run,
        login_runner: RunLogin = run_login,
        lock_dir: Path | None = None,
    ):
        self._cli_path = cli_path
        self._url = url
        self._ca_path = ca_path
        self._login = login
        self._notify = notify
        self._run = runner
        self._run_login = login_runner
        self._lock_dir = lock_dir if lock_dir is not None else cache_dir()

    def _argv(self, *args: str) -> list[str]:
        argv = [self._cli_path, *args, "--server", self._url]
        if self._ca_path:
            argv += ["--ca-file", self._ca_path]
        return argv

    def _saved(self) -> str | None:
        """The saved token, or None when there is none or it has expired."""
        try:
            result = self._run(self._argv("token"))
        except FileNotFoundError:
            raise _missing_cli(self._cli_path) from None
        if result.returncode in (EXIT_NOT_LOGGED_IN, EXIT_EXPIRED):
            return None
        token = (result.stdout or "").strip()
        if result.returncode != 0 or not token:
            detail = (result.stderr or "").strip() or f"exit {result.returncode}"
            raise SekretError(f"`sekret token` failed: {detail}")
        return token

    def token(self) -> str:
        return self._saved() or self._log_in(None)

    def refresh(self, rejected: str | None) -> str:
        return self._log_in(rejected)

    def _log_in(self, rejected: str | None) -> str:
        if not self._login:
            raise AuthenticationError(
                f"no usable sekret login for {self._url} and cli_login is off; run "
                f"`sekret login --server {self._url}` first, or use a machine identity"
            )
        with login_lock(self._lock_dir):
            # Another worker may have logged in while this one waited for the lock.
            token = self._saved()
            if token and token != rejected:
                return token
            self._notify(f"sekret: logging in to {self._url}; approve the request in your browser")
            try:
                code = self._run_login(self._argv("login"), self._notify)
            except FileNotFoundError:
                raise _missing_cli(self._cli_path) from None
            if code != 0:
                raise AuthenticationError(f"`sekret login` to {self._url} did not finish (exit {code})")
            token = self._saved()
            if not token or token == rejected:
                raise AuthenticationError(f"`sekret login` to {self._url} saved no new token")
            return token


CONTEXT_FLAGS = {
    "url": "--server",
    "project": "--project",
    "environment": "--env",
    "path": "--path",
    "ca_path": "--ca-file",
}


def cli_context(cli_path: str, known: Mapping[str, str | None], runner: Run = run) -> dict | None:
    """What the CLI's settings (above all the nearest .sekret.toml) pick, with what is already known
    passed as flags so it stays as it is. None when the CLI is not installed."""
    argv = [cli_path, "token", "--context"]
    for name, flag in CONTEXT_FLAGS.items():
        value = known.get(name)
        if value:
            argv += [flag, str(value)]
    try:
        result = runner(argv)
    except FileNotFoundError:
        return None
    if result.returncode != 0:
        detail = (result.stderr or "").strip() or f"exit {result.returncode}"
        raise ConfigError(f"could not read the sekret CLI's settings: {detail}")
    try:
        context = json.loads(result.stdout)
    except ValueError:
        raise ConfigError("`sekret token --context` did not print JSON") from None
    if not isinstance(context, dict):
        raise ConfigError("`sekret token --context` did not print a JSON object")
    return context
