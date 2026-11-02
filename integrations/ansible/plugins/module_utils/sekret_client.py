"""Minimal sekret API client built on the Python standard library."""

from __future__ import annotations

import hashlib
import json
import os
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any, NamedTuple, Protocol

DEFAULT_KUBERNETES_TOKEN_FILE = "/var/run/secrets/kubernetes.io/serviceaccount/token"
DEFAULT_TIMEOUT = 30
AUTH_METHODS = ("auto", "token", "universal", "oidc", "kubernetes", "cli")
# A CLI login can be days old; a rejected one is replaced on the first 401 whatever this says.
CLI_TOKEN_TTL = 3600
REDACTED = "********"

# Refresh tokens a little before they expire so in-flight requests do not race expiry.
EXPIRY_MARGIN = 30

ENV_VARS = {
    "url": "SEKRET_URL",
    "token": "SEKRET_TOKEN",
    "auth_method": "SEKRET_AUTH_METHOD",
    "client_id": "SEKRET_CLIENT_ID",
    "client_secret": "SEKRET_CLIENT_SECRET",
    "identity_id": "SEKRET_IDENTITY_ID",
    "oidc_token": "SEKRET_OIDC_TOKEN",
    "oidc_token_file": "SEKRET_OIDC_TOKEN_FILE",
    "kubernetes_token_file": "SEKRET_KUBERNETES_TOKEN_FILE",
    "validate_certs": "SEKRET_VALIDATE_CERTS",
    "ca_path": "SEKRET_CA_PATH",
    "client_cert": "SEKRET_CLIENT_CERT",
    "client_key": "SEKRET_CLIENT_KEY",
    "timeout": "SEKRET_TIMEOUT",
    "project": "SEKRET_PROJECT",
    "environment": "SEKRET_ENVIRONMENT",
    "cli_path": "SEKRET_CLI",
    "cli_login": "SEKRET_CLI_LOGIN",
}


class SekretError(Exception):
    def __init__(self, message: str, status: int | None = None, code: str | None = None):
        super().__init__(message)
        self.message = message
        self.status = status
        self.code = code


class ConfigError(SekretError):
    pass


class AuthenticationError(SekretError):
    pass


class PermissionDeniedError(SekretError):
    pass


class NotFoundError(SekretError):
    pass


class TransportError(SekretError):
    pass


class HttpResponse(NamedTuple):
    status: int
    body: bytes


Transport = Callable[[str, str, Mapping[str, str], "bytes | None", float], HttpResponse]


def terminal_safe(value: Any) -> str:
    """The text with anything that is not printable, such as escape sequences, C1 controls and
    direction overrides, written as an escape, for messages that reach a terminal."""
    out = []
    for c in str(value):
        if c.isprintable():
            out.append(c)
        elif ord(c) > 0xFFFF:
            out.append(f"\\U{ord(c):08x}")
        else:
            out.append(f"\\u{ord(c):04x}")
    return "".join(out)


def _to_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ("1", "true", "yes", "on", "y")


def option_or_env(options: Mapping[str, Any], name: str, environ: Mapping[str, str] | None = None) -> Any:
    value = options.get(name)
    if value is not None and value != "":
        return value
    env_name = ENV_VARS.get(name)
    if env_name is None:
        return None
    environ = os.environ if environ is None else environ
    return environ.get(env_name) or None


@dataclass(frozen=True)
class Settings:
    url: str
    auth_method: str = "auto"
    token: str | None = field(default=None, repr=False)
    client_id: str | None = None
    client_secret: str | None = field(default=None, repr=False)
    identity_id: str | None = None
    oidc_token: str | None = field(default=None, repr=False)
    oidc_token_file: str | None = None
    kubernetes_token_file: str | None = None
    validate_certs: bool = True
    ca_path: str | None = None
    client_cert: str | None = None
    client_key: str | None = None
    timeout: float = DEFAULT_TIMEOUT
    cli_path: str = "sekret"
    cli_login: bool = True

    @classmethod
    def from_options(cls, options: Mapping[str, Any], environ: Mapping[str, str] | None = None) -> Settings:
        """Builds settings from plugin options, falling back to SEKRET_* environment variables."""

        def pick(name: str) -> Any:
            return option_or_env(options, name, environ)

        url = pick("url")
        if not url:
            raise ConfigError("the sekret server URL is required (url option or SEKRET_URL)")
        auth_method = (pick("auth_method") or "auto").lower()
        if auth_method not in AUTH_METHODS:
            raise ConfigError(f"auth_method must be one of {', '.join(AUTH_METHODS)}")
        validate_certs = pick("validate_certs")
        timeout = pick("timeout")
        try:
            timeout = float(timeout) if timeout is not None else DEFAULT_TIMEOUT
        except ValueError as e:
            raise ConfigError("timeout must be a number of seconds") from e
        client_cert, client_key = pick("client_cert"), pick("client_key")
        if bool(client_cert) != bool(client_key):
            raise ConfigError("client_cert and client_key must be set together")
        cli_login = pick("cli_login")
        return cls(
            url=str(url).rstrip("/"),
            auth_method=auth_method,
            token=pick("token"),
            client_id=pick("client_id"),
            client_secret=pick("client_secret"),
            identity_id=pick("identity_id"),
            oidc_token=pick("oidc_token"),
            oidc_token_file=pick("oidc_token_file"),
            kubernetes_token_file=pick("kubernetes_token_file"),
            validate_certs=True if validate_certs is None else _to_bool(validate_certs),
            ca_path=pick("ca_path"),
            client_cert=client_cert,
            client_key=client_key,
            timeout=timeout,
            cli_path=pick("cli_path") or "sekret",
            cli_login=True if cli_login is None else _to_bool(cli_login),
        )

    def sensitive_values(self) -> list[str]:
        return [v for v in (self.token, self.client_secret, self.oidc_token) if v]


@dataclass(frozen=True)
class StaticToken:
    token: str = field(repr=False)


@dataclass(frozen=True)
class CliLogin:
    """The login `sekret login` saved, read through the CLI on the controller."""

    cli_path: str = "sekret"
    ca_path: str | None = None

    def cache_key(self, url: str) -> str:
        return hashlib.sha256(json.dumps(["cli", url, self.cli_path, self.ca_path]).encode()).hexdigest()


class TokenSource(Protocol):
    def token(self) -> str: ...
    def refresh(self, rejected: str | None) -> str: ...


@dataclass(frozen=True)
class Login:
    method: str
    path: str
    payload: dict = field(repr=False)

    def cache_key(self, url: str) -> str:
        material = json.dumps([url, self.method, self.payload], sort_keys=True).encode()
        return hashlib.sha256(material).hexdigest()


def read_token_file(path: str) -> str:
    try:
        with open(path, encoding="utf-8") as handle:
            token = handle.read().strip()
    except OSError as e:
        raise ConfigError(f"could not read token file {path}: {e.strerror}") from None
    if not token:
        raise ConfigError(f"token file {path} is empty")
    return token


def _require_identity(settings: Settings, method: str) -> str:
    if not settings.identity_id:
        raise ConfigError(f"{method} auth needs identity_id (or SEKRET_IDENTITY_ID)")
    return settings.identity_id


def _universal(settings: Settings) -> Login:
    if not (settings.client_id and settings.client_secret):
        raise ConfigError("universal auth needs client_id and client_secret")
    return Login(
        "universal",
        "/api/v1/auth/universal/login",
        {"client_id": settings.client_id, "client_secret": settings.client_secret},
    )


def _oidc(settings: Settings, read_file: Callable[[str], str]) -> Login:
    identity_id = _require_identity(settings, "oidc")
    token = settings.oidc_token
    if not token and settings.oidc_token_file:
        token = read_file(settings.oidc_token_file)
    if not token:
        raise ConfigError("oidc auth needs oidc_token or oidc_token_file")
    return Login("oidc", "/api/v1/auth/oidc/login", {"identity_id": identity_id, "token": token})


def _kubernetes(settings: Settings, read_file: Callable[[str], str]) -> Login:
    identity_id = _require_identity(settings, "kubernetes")
    # The pod's default token reaches the Kubernetes API, so it is never sent unless named.
    if not settings.kubernetes_token_file:
        raise ConfigError(
            "kubernetes auth needs kubernetes_token_file: a projected token with the sekret audience, "
            f"not the pod's default {DEFAULT_KUBERNETES_TOKEN_FILE}"
        )
    token = read_file(settings.kubernetes_token_file)
    return Login(
        "kubernetes",
        "/api/v1/auth/kubernetes/login",
        {"identity_id": identity_id, "token": token},
    )


def resolve_auth(
    settings: Settings, read_file: Callable[[str], str] = read_token_file, allow_cli: bool = False
) -> StaticToken | Login | CliLogin:
    """Picks how to authenticate: an explicit auth_method, otherwise token, universal, OIDC, then
    the CLI's saved login where the caller can run the CLI (the lookup, on the controller)."""
    method = settings.auth_method
    if method == "cli":
        if not allow_cli:
            raise ConfigError("cli auth only works in the lookup, which runs where `sekret login` was run")
        return CliLogin(settings.cli_path, settings.ca_path)
    if method == "token":
        if not settings.token:
            raise ConfigError("token auth needs token (or SEKRET_TOKEN)")
        return StaticToken(settings.token)
    if method == "universal":
        return _universal(settings)
    if method == "oidc":
        return _oidc(settings, read_file)
    if method == "kubernetes":
        return _kubernetes(settings, read_file)

    if settings.token:
        return StaticToken(settings.token)
    if settings.client_id or settings.client_secret:
        return _universal(settings)
    if settings.identity_id and (settings.oidc_token or settings.oidc_token_file):
        return _oidc(settings, read_file)
    if allow_cli:
        return CliLogin(settings.cli_path, settings.ca_path)
    raise ConfigError(
        "no sekret credentials found: set token, client_id and client_secret, "
        "identity_id with oidc_token or oidc_token_file, or auth_method=kubernetes"
    )


class TokenCache:
    """Process-wide access token cache keyed by server and credentials."""

    def __init__(self, clock: Callable[[], float] = time.monotonic):
        self._clock = clock
        self._entries: dict[str, tuple[str, float]] = {}
        self._lock = threading.Lock()

    def get(self, key: str) -> str | None:
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                return None
            token, expires_at = entry
            if self._clock() >= expires_at - EXPIRY_MARGIN:
                del self._entries[key]
                return None
            return token

    def put(self, key: str, token: str, expires_in: float) -> None:
        with self._lock:
            self._entries[key] = (token, self._clock() + expires_in)

    def discard(self, key: str) -> None:
        with self._lock:
            self._entries.pop(key, None)

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()


TOKEN_CACHE = TokenCache()


def ssl_context(
    validate_certs: bool,
    ca_path: str | None,
    client_cert: str | None = None,
    client_key: str | None = None,
) -> ssl.SSLContext:
    context = _verifying_context(validate_certs, ca_path)
    if client_cert and client_key:
        try:
            context.load_cert_chain(certfile=client_cert, keyfile=client_key)
        except (OSError, ssl.SSLError) as e:
            raise ConfigError(f"could not load client certificate {client_cert}: {e}") from None
    return context


def _verifying_context(validate_certs: bool, ca_path: str | None) -> ssl.SSLContext:
    if not validate_certs:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        return context
    # The system's CAs, with the given one added to them rather than in their place, as the CLI does.
    context = ssl.create_default_context()
    if not ca_path:
        return context
    try:
        if os.path.isdir(ca_path):
            context.load_verify_locations(capath=ca_path)
        else:
            context.load_verify_locations(cafile=ca_path)
    except (OSError, ssl.SSLError) as e:
        raise ConfigError(f"could not load CA bundle {ca_path}: {e}") from None
    return context


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """urllib would replay the Authorization header to wherever a redirect points."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class UrllibTransport:
    def __init__(self, context: ssl.SSLContext):
        https = urllib.request.HTTPSHandler(context=context)
        self._opener = urllib.request.build_opener(https, _NoRedirect())

    def __call__(
        self, method: str, url: str, headers: Mapping[str, str], body: bytes | None, timeout: float
    ) -> HttpResponse:
        request = urllib.request.Request(url, data=body, headers=dict(headers), method=method)
        try:
            with self._opener.open(request, timeout=timeout) as response:
                return HttpResponse(response.status, response.read())
        except urllib.error.HTTPError as e:
            with e:
                return HttpResponse(e.code, e.read())
        except urllib.error.URLError as e:
            raise TransportError(f"could not reach sekret server at {_origin(url)}: {e.reason}") from None
        except (OSError, ValueError) as e:
            raise TransportError(f"could not reach sekret server at {_origin(url)}: {e}") from None


def _origin(url: str) -> str:
    parts = urllib.parse.urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}"


def default_transport(settings: Settings) -> Transport:
    return UrllibTransport(
        ssl_context(settings.validate_certs, settings.ca_path, settings.client_cert, settings.client_key)
    )


@dataclass(frozen=True)
class SecretRecord:
    key: str
    value: str | None = field(repr=False)
    value_hidden: bool
    version: int
    tags: list[str]
    comment: str = ""


def _redact(message: str, sensitive: list[str]) -> str:
    for value in sorted(sensitive, key=len, reverse=True):
        if value:
            message = message.replace(value, REDACTED)
    return message


def _quote(segment: str) -> str:
    return urllib.parse.quote(segment, safe="")


class SekretClient:
    def __init__(
        self,
        settings: Settings,
        transport: Transport | None = None,
        cache: TokenCache = TOKEN_CACHE,
        read_file: Callable[[str], str] = read_token_file,
        token_source: Callable[[Settings], TokenSource] | None = None,
    ):
        self._settings = settings
        self._transport = transport if transport is not None else default_transport(settings)
        self._cache = cache
        self._read_file = read_file
        self._token_source_factory = token_source
        self._token_source: TokenSource | None = None
        self._auth: StaticToken | Login | CliLogin | None = None
        self._rejected: str | None = None
        self._sensitive = settings.sensitive_values()

    def _redacted(self, message: str, extra: list[str] | None = None) -> str:
        return _redact(message, self._sensitive + (extra or []))

    def _send(self, method: str, path: str, body: Any = None, token: str | None = None) -> HttpResponse:
        headers = {"Accept": "application/json", "User-Agent": "sekret-ansible"}
        data = None
        if body is not None:
            headers["Content-Type"] = "application/json"
            data = json.dumps(body).encode()
        if token is not None:
            headers["Authorization"] = f"Bearer {token}"
        try:
            return self._transport(method, self._settings.url + path, headers, data, self._settings.timeout)
        except SekretError:
            raise
        except Exception as e:
            raise TransportError(f"request to sekret failed: {self._redacted(str(e))}") from None

    def _error(self, response: HttpResponse, extra_sensitive: list[str] | None = None) -> SekretError:
        code = None
        message = ""
        try:
            payload = json.loads(response.body)
            code = payload.get("error")
            message = payload.get("message") or ""
        except (ValueError, AttributeError):
            pass
        status = response.status
        detail = self._redacted(message or f"HTTP {status}", extra_sensitive)
        if status == 401:
            return AuthenticationError(f"sekret authentication failed: {detail}", status, code)
        if status == 403:
            return PermissionDeniedError(f"sekret denied the request: {detail}", status, code)
        if status == 404:
            return NotFoundError(f"sekret: {detail}", status, code)
        return SekretError(f"sekret request failed ({status}): {detail}", status, code)

    @staticmethod
    def _json(response: HttpResponse) -> Any:
        try:
            return json.loads(response.body)
        except ValueError:
            raise SekretError("sekret returned a response that is not JSON", response.status) from None

    def _auth_plan(self) -> StaticToken | Login | CliLogin:
        if self._auth is None:
            allow_cli = self._token_source_factory is not None
            self._auth = resolve_auth(self._settings, self._read_file, allow_cli=allow_cli)
            if isinstance(self._auth, Login):
                self._sensitive.append(self._auth.payload.get("token") or "")
        return self._auth

    def identity(self) -> str:
        """Stands for whoever the requests run as, without holding a credential."""
        plan = self._auth_plan()
        if isinstance(plan, StaticToken):
            return hashlib.sha256(plan.token.encode()).hexdigest()
        return plan.cache_key(self._settings.url)

    def _cli_token(self, plan: CliLogin) -> str:
        if self._token_source is None and self._token_source_factory is not None:
            self._token_source = self._token_source_factory(self._settings)
        if self._token_source is None:
            raise ConfigError("cli auth needs the sekret CLI, which only the lookup runs")
        key = plan.cache_key(self._settings.url)
        if self._rejected is not None:
            rejected, self._rejected = self._rejected, None
            token = self._token_source.refresh(rejected)
        else:
            cached = self._cache.get(key)
            if cached is not None:
                self._sensitive.append(cached)
                return cached
            token = self._token_source.token()
        self._sensitive.append(token)
        self._cache.put(key, token, CLI_TOKEN_TTL)
        return token

    def access_token(self) -> str:
        plan = self._auth_plan()
        if isinstance(plan, StaticToken):
            return plan.token
        if isinstance(plan, CliLogin):
            return self._cli_token(plan)
        key = plan.cache_key(self._settings.url)
        cached = self._cache.get(key)
        if cached is not None:
            # Another client in this process logged in; this one must still keep it out of errors.
            self._sensitive.append(cached)
            return cached
        response = self._send("POST", plan.path, plan.payload)
        if response.status != 200:
            raise self._error(response)
        payload = self._json(response)
        token = payload.get("access_token") if isinstance(payload, dict) else None
        if not token:
            raise SekretError("sekret login response had no access token")
        self._sensitive.append(token)
        self._cache.put(key, token, float(payload.get("expires_in") or 0))
        return token

    def _invalidate(self, rejected: str) -> bool:
        plan = self._auth_plan()
        if isinstance(plan, StaticToken):
            return False
        self._cache.discard(plan.cache_key(self._settings.url))
        if isinstance(plan, CliLogin):
            self._rejected = rejected
        return True

    def request(self, method: str, path: str, body: Any = None, sensitive: list[str] | None = None) -> Any:
        """Sends an authenticated request, logging in again once if a cached token was rejected."""
        token = self.access_token()
        response = self._send(method, path, body, token)
        if response.status == 401 and self._invalidate(token):
            response = self._send(method, path, body, self.access_token())
        if not 200 <= response.status < 300:
            raise self._error(response, sensitive)
        if not response.body:
            return None
        return self._json(response)

    def list_raw(
        self, project: str, environment: str, path: str = "/", recursive: bool = False
    ) -> list[dict]:
        query = urllib.parse.urlencode(
            {
                "project": project,
                "environment": environment,
                "path": path,
                "recursive": "true" if recursive else "false",
            }
        )
        payload = self.request("GET", f"/api/v1/secrets/raw?{query}")
        return list(payload.get("secrets") or [])

    def get_secret(self, project: str, environment: str, key: str, path: str = "/") -> SecretRecord | None:
        """Returns the secret, or None when it does not exist or has been deleted."""
        url = (
            f"/api/v1/projects/{_quote(project)}/environments/{_quote(environment)}"
            f"/secrets/{_quote(key)}?{urllib.parse.urlencode({'path': path})}"
        )
        try:
            payload = self.request("GET", url)
        except NotFoundError as e:
            if e.message.endswith("secret not found"):
                return None
            raise
        hidden = bool(payload.get("value_hidden"))
        value = payload.get("value")
        # Deleted secrets come back with no value even though the caller may read values.
        if value is None and not hidden:
            return None
        return SecretRecord(
            key=payload.get("key", key),
            value=value,
            value_hidden=hidden,
            version=int(payload.get("version") or 0),
            tags=list(payload.get("tags") or []),
            comment=payload.get("comment") or "",
        )

    def batch(
        self,
        project: str,
        environment: str,
        path: str = "/",
        upserts: list[dict] | None = None,
        deletes: list[str] | None = None,
    ) -> dict:
        upserts = upserts or []
        body = {"path": path, "upserts": upserts, "deletes": deletes or []}
        values = [u["value"] for u in upserts if u.get("value")]
        url = f"/api/v1/projects/{_quote(project)}/environments/{_quote(environment)}/secrets/batch"
        return self.request("POST", url, body, sensitive=values)
