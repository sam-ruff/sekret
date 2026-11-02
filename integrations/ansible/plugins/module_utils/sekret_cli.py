"""The sekret CLI on the controller: the login `sekret login` saved, and the project file's settings.

Only the lookup uses this. The token travels over a pipe from `sekret token`, never through an
argument, the environment or a file of ours.
"""

from __future__ import annotations

import contextlib
import errno
import fcntl
import hashlib
import json
import os
import stat
import subprocess
import threading
import time
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
# How long a login may take before it is stopped.
LOGIN_WAIT = 600
# How long another worker waits for the lock: longer than a login, so it never gives up on one
# that is still allowed to finish.
LOCK_WAIT = LOGIN_WAIT + 60
LOCK_POLL = 0.5
# How long a failed or declined login stops other workers and runs from opening the browser again.
FAILED_FOR = 60
# How long a token a login produced counts as fresh: one rejected in that time means the login
# cannot help, so asking again would only open the browser again.
PRODUCED_FOR = 3600
NUL_IN_SETTING = "a sekret setting passed to the CLI holds a NUL character"

Notify = Callable[[str], None]
Run = Callable[[list[str]], subprocess.CompletedProcess]
RunLogin = Callable[[list[str], Notify], int]

# Logins that failed in this process, so later lookups fail at once instead of asking again.
_FAILED: set[tuple] = set()
# Digests of the tokens logins in this process produced.
_PRODUCED: set[str] = set()


def run(argv: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True, text=True, check=False)


def run_login(argv: list[str], notify: Notify, limit: float = LOGIN_WAIT) -> int:
    """Runs `sekret login`, passing each line it prints (the link and the code) to `notify`, and
    stops it after `limit` seconds."""
    with subprocess.Popen(
        argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
    ) as process:
        timer = threading.Timer(limit, process.kill)
        timer.start()
        try:
            for line in process.stdout or ():
                if line.strip():
                    notify(f"sekret: {line.rstrip()}")
            return process.wait()
        finally:
            timer.cancel()


def cache_dir(environ: Mapping[str, str] | None = None) -> Path:
    environ = os.environ if environ is None else environ
    base = environ.get("XDG_CACHE_HOME") or os.path.join(os.path.expanduser("~"), ".cache")
    return Path(base) / "sekret"


def _digest(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


@contextlib.contextmanager
def _file_errors(what: str, where: Path) -> Iterator[None]:
    """Turns an unexpected file error into a sekret error that says what was being done."""
    try:
        yield
    except OSError as e:
        raise SekretError(f"could not {what} in {where}: {e.strerror or e}") from None


def _cli_call(cli_path: str, call: Callable[[], object]):
    try:
        return call()
    except FileNotFoundError:
        raise _missing_cli(cli_path) from None
    except ValueError:
        # subprocess refuses an argument holding a NUL character.
        raise ConfigError(NUL_IN_SETTING) from None


def _private_directory(directory: Path) -> None:
    try:
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = os.lstat(directory)
    except OSError as e:
        raise ConfigError(f"could not create {directory}: {e.strerror}") from None
    if not stat.S_ISDIR(info.st_mode):
        raise ConfigError(f"{directory} is not a directory; not taking the sekret login lock there")
    if info.st_uid != os.getuid() or info.st_mode & 0o022:
        raise ConfigError(f"{directory} is not private to you; not taking the sekret login lock there")


def _open_own(path: Path, flags: int) -> int:
    """Opens a file of ours without following a link, refusing one someone else owns."""
    try:
        fd = os.open(path, flags | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    except OSError as e:
        if e.errno == errno.ELOOP:
            raise ConfigError(f"{path} is a symbolic link; not using it") from None
        raise
    info = os.fstat(fd)
    if info.st_uid != os.getuid() or not stat.S_ISREG(info.st_mode):
        os.close(fd)
        raise ConfigError(f"{path} is not a private file of yours; not using it")
    return fd


@contextlib.contextmanager
def login_lock(
    directory: Path,
    wait: float = LOCK_WAIT,
    clock: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> Iterator[None]:
    """Holds an exclusive lock so that of several Ansible workers, only one runs `sekret login`.
    Gives up after `wait` seconds rather than hang behind a login nobody finishes."""
    _private_directory(directory)
    try:
        fd = _open_own(directory / LOCK_NAME, os.O_RDWR | os.O_CREAT)
    except OSError as e:
        raise ConfigError(f"could not open the sekret login lock in {directory}: {e.strerror}") from None
    try:
        started = clock()
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if clock() - started >= wait:
                    raise AuthenticationError(
                        f"another Ansible worker has been logging in to sekret for {int(wait)} seconds; "
                        "giving up. Run `sekret login` yourself, then run again"
                    ) from None
                sleep(LOCK_POLL)
        yield
    finally:
        os.close(fd)


def _beside_lock(directory: Path, key: tuple, kind: str) -> Path:
    digest = hashlib.sha256(json.dumps(list(key)).encode()).hexdigest()[:16]
    return directory / f"ansible-login-{digest}.{kind}"


def _marker(directory: Path, key: tuple) -> Path:
    return _beside_lock(directory, key, "failed")


def _read_recent(path: Path, now: float, within: float) -> str | None:
    """The contents of a file of ours written less than `within` seconds ago, or None."""
    with _file_errors("read", path.parent):
        try:
            fd = _open_own(path, os.O_RDONLY)
        except FileNotFoundError:
            return None
        try:
            if now - os.fstat(fd).st_mtime >= within:
                return None
            return os.read(fd, 4096).decode(errors="replace")
        finally:
            os.close(fd)


def _write_own(path: Path, contents: str) -> None:
    with _file_errors("write", path.parent):
        fd = _open_own(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC)
        try:
            os.write(fd, contents.encode())
        finally:
            os.close(fd)
        os.utime(path, follow_symlinks=False)


def _remove(path: Path) -> None:
    with _file_errors("remove a file", path.parent), contextlib.suppress(FileNotFoundError):
        path.unlink()


def _failed_recently(marker: Path, now: float) -> bool:
    return _read_recent(marker, now, FAILED_FOR) is not None


def _mark_failed(marker: Path) -> None:
    _write_own(marker, "")


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
        no_login_reason: str | None = None,
        lock_wait: float = LOCK_WAIT,
        clock: Callable[[], float] = time.time,
    ):
        self._cli_path = cli_path
        self._url = url
        self._ca_path = ca_path
        self._login = login
        self._no_login_reason = no_login_reason
        self._notify = notify
        self._run = runner
        self._run_login = login_runner
        self._lock_dir = lock_dir if lock_dir is not None else cache_dir()
        self._lock_wait = lock_wait
        self._clock = clock
        self._key = (cli_path, url, ca_path)

    def _argv(self, *args: str) -> list[str]:
        # `--flag=value`, so a value starting with a dash is never read as a flag.
        argv = [self._cli_path, *args, f"--server={self._url}"]
        if self._ca_path:
            argv.append(f"--ca-file={self._ca_path}")
        return argv

    def _saved(self) -> str | None:
        """The saved token, or None when there is none or it has expired."""
        result = _cli_call(self._cli_path, lambda: self._run(self._argv("token")))
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

    def _fail(self, marker: Path, message: str) -> AuthenticationError:
        _FAILED.add(self._key)
        _mark_failed(marker)
        return AuthenticationError(message)

    def _log_in(self, rejected: str | None) -> str:
        yourself = f"run `sekret login --server={self._url}` yourself, then run again"
        rejected_fresh = (
            f"sekret rejected the token a login in this run just produced, so logging in again will not "
            f"help; something between here and {self._url}, such as a proxy dropping the Authorization "
            "header or a clock far out, needs fixing"
        )
        if not self._login:
            raise AuthenticationError(
                f"no usable sekret login for {self._url} and cli_login is off; {yourself}, or use a "
                "machine identity"
            )
        if self._no_login_reason:
            raise AuthenticationError(f"no usable sekret login for {self._url}; {self._no_login_reason}")
        if self._key in _FAILED:
            raise AuthenticationError(f"`sekret login` to {self._url} already failed in this run; {yourself}")
        with login_lock(self._lock_dir, self._lock_wait):
            marker = _marker(self._lock_dir, self._key)
            produced = _beside_lock(self._lock_dir, self._key, "produced")
            if rejected is not None and (
                _digest(rejected) in _PRODUCED
                or _read_recent(produced, self._clock(), PRODUCED_FOR) == _digest(rejected)
            ):
                raise self._fail(marker, rejected_fresh)
            # Another worker may have logged in while this one waited for the lock.
            token = self._saved()
            if token and token != rejected:
                return token
            if _failed_recently(marker, self._clock()):
                _FAILED.add(self._key)
                raise AuthenticationError(
                    f"`sekret login` to {self._url} failed less than {FAILED_FOR} seconds ago; {yourself}"
                )
            self._notify(f"sekret: logging in to {self._url}; approve the request in your browser")
            code = _cli_call(self._cli_path, lambda: self._run_login(self._argv("login"), self._notify))
            token = self._saved() if code == 0 else None
            if code != 0:
                raise self._fail(marker, f"`sekret login` to {self._url} did not finish (exit {code})")
            if not token or token == rejected:
                raise self._fail(marker, f"`sekret login` to {self._url} saved no new token")
            _PRODUCED.add(_digest(token))
            _write_own(produced, _digest(token))
            _remove(marker)
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
            argv.append(f"{flag}={value}")
    try:
        result = runner(argv)
    except FileNotFoundError:
        return None
    except ValueError:
        raise ConfigError(NUL_IN_SETTING) from None
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
