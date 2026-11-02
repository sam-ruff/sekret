import contextlib
import datetime
import http.server
import io
import json
import socket
import ssl
import threading
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from fake_server import FakeServer, error, respond

from ansible_collections.sekret.secrets.plugins.module_utils.sekret_client import (
    DEFAULT_KUBERNETES_TOKEN_FILE,
    AuthenticationError,
    ConfigError,
    HttpResponse,
    Login,
    NotFoundError,
    PermissionDeniedError,
    SekretClient,
    SekretError,
    Settings,
    StaticToken,
    TokenCache,
    TransportError,
    UrllibTransport,
    bypasses_proxy,
    resolve_auth,
    ssl_context,
)

URL = "https://sekret.test"


@dataclass
class LocalCa:
    ca_file: Path
    server_context: ssl.SSLContext


def make_ca(directory: Path, name: str) -> LocalCa:
    """A CA and a localhost server certificate it signed, as files and a server context."""
    now = datetime.datetime.now(datetime.timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"{name} CA")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(True, False, False, False, False, True, True, False, False), critical=True
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    key = ec.generate_private_key(ec.SECP256R1())
    leaf = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]))
        .issuer_name(ca_name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False
        )
        .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    ca_file = directory / f"{name}-ca.pem"
    ca_file.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    chain = directory / f"{name}-server.pem"
    chain.write_bytes(
        leaf.public_bytes(serialization.Encoding.PEM)
        + key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
    )
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(chain)
    return LocalCa(ca_file, server_context)


def handshake(client: ssl.SSLContext, ca: LocalCa) -> bool:
    """Whether `client` accepts a localhost server whose certificate `ca` signed."""
    listener = socket.create_server(("127.0.0.1", 0))
    port = listener.getsockname()[1]

    def serve():
        connection, _ = listener.accept()
        with contextlib.suppress(OSError), ca.server_context.wrap_socket(connection, server_side=True):
            pass

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        with (
            socket.create_connection(("127.0.0.1", port), timeout=15) as raw,
            client.wrap_socket(raw, server_hostname="localhost"),
        ):
            return True
    except ssl.SSLCertVerificationError:
        return False
    finally:
        thread.join(timeout=15)
        listener.close()


class FakeClock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


def settings(**overrides):
    return Settings.from_options({"url": URL, **overrides}, environ={})


def client(server, cache=None, read_file=None, **overrides):
    return SekretClient(
        settings(**overrides),
        transport=server,
        cache=cache or TokenCache(),
        read_file=read_file or (lambda path: pytest.fail(f"unexpected read of {path}")),
    )


@pytest.fixture
def server():
    fake = FakeServer()
    fake.put("DB_PASSWORD", "hunter2")
    return fake


def bearer(call):
    return call.headers["Authorization"].removeprefix("Bearer ")


class TestSettings:
    def test_environment_fallback(self):
        result = Settings.from_options(
            {"url": None, "token": ""},
            environ={
                "SEKRET_URL": "https://env.test/",
                "SEKRET_TOKEN": "env-token",
                "SEKRET_VALIDATE_CERTS": "false",
                "SEKRET_TIMEOUT": "5",
                "SEKRET_CA_PATH": "/etc/ca.pem",
            },
        )
        assert result.url == "https://env.test"
        assert result.token == "env-token"
        assert result.validate_certs is False
        assert result.timeout == 5.0
        assert result.ca_path == "/etc/ca.pem"

    def test_options_win_over_environment(self):
        result = Settings.from_options({"url": URL, "token": "opt"}, environ={"SEKRET_TOKEN": "env"})
        assert result.token == "opt"

    def test_defaults(self):
        result = settings()
        assert result.validate_certs is True
        assert result.kubernetes_token_file is None
        assert result.auth_method == "auto"

    def test_url_required(self):
        with pytest.raises(ConfigError, match="URL is required"):
            Settings.from_options({}, environ={})

    def test_rejects_unknown_auth_method(self):
        with pytest.raises(ConfigError, match="auth_method"):
            settings(auth_method="ldap")

    def test_repr_hides_credentials(self):
        text = repr(settings(token="tok-123", client_secret="cs-456", oidc_token="jwt-789"))
        for secret in ("tok-123", "cs-456", "jwt-789"):
            assert secret not in text


class TestAuthResolution:
    def test_token_first(self):
        plan = resolve_auth(settings(token="t", client_id="c", client_secret="s"))
        assert plan == StaticToken("t")

    def test_universal_before_oidc(self):
        plan = resolve_auth(settings(client_id="c", client_secret="s", identity_id="i", oidc_token="j"))
        assert isinstance(plan, Login)
        assert plan.method == "universal"

    def test_oidc_from_file(self):
        plan = resolve_auth(
            settings(identity_id="i", oidc_token_file="/jwt"),
            read_file=lambda path: "file-jwt" if path == "/jwt" else "",
        )
        assert plan.method == "oidc"
        assert plan.payload == {"identity_id": "i", "token": "file-jwt"}

    def test_kubernetes_is_never_automatic(self):
        with pytest.raises(ConfigError, match="no sekret credentials"):
            resolve_auth(settings(identity_id="i"), read_file=lambda path: "sa-jwt")

    def test_kubernetes_never_sends_the_pods_default_token(self):
        read = []
        with pytest.raises(ConfigError, match=DEFAULT_KUBERNETES_TOKEN_FILE):
            resolve_auth(
                settings(identity_id="i", auth_method="kubernetes"),
                read_file=lambda path: read.append(path) or "sa-jwt",
            )
        assert read == []

    def test_kubernetes_uses_the_named_token_file(self):
        read = []
        plan = resolve_auth(
            settings(identity_id="i", auth_method="kubernetes", kubernetes_token_file="/sa/sekret"),
            read_file=lambda path: read.append(path) or "sa-jwt",
        )
        assert read == ["/sa/sekret"]
        assert plan.path == "/api/v1/auth/kubernetes/login"
        assert plan.payload == {"identity_id": "i", "token": "sa-jwt"}

    def test_explicit_method_overrides_order(self):
        plan = resolve_auth(settings(token="t", client_id="c", client_secret="s", auth_method="universal"))
        assert plan.method == "universal"

    def test_explicit_method_reports_missing_pieces(self):
        with pytest.raises(ConfigError, match="identity_id"):
            resolve_auth(settings(auth_method="oidc", oidc_token="j"))
        with pytest.raises(ConfigError, match="client_id and client_secret"):
            resolve_auth(settings(client_id="only-id"))

    def test_missing_token_file_is_a_config_error(self, tmp_path):
        missing = tmp_path / "nope"
        with pytest.raises(ConfigError, match="could not read token file"):
            resolve_auth(settings(identity_id="i", oidc_token_file=str(missing)))


class TestLogins:
    def test_static_token_skips_login(self, server):
        records = client(server, token="static-token").list_raw("app", "prod")
        assert records == [{"path": "/", "key": "DB_PASSWORD", "value": "hunter2"}]
        assert server.logins == []
        assert bearer(server.calls[0]) == "static-token"

    def test_universal_login(self, server):
        c = client(server, client_id="client-1", client_secret="client-secret-1")
        c.list_raw("app", "prod")
        (login,) = server.logins
        assert login.body == {"client_id": "client-1", "client_secret": "client-secret-1"}
        assert bearer(server.calls[-1]) == "issued-1"

    def test_oidc_login(self, server):
        client(server, identity_id="identity-1", oidc_token="jwt-1").list_raw("app", "prod")
        assert server.logins[0].path == "/api/v1/auth/oidc/login"
        assert server.logins[0].body == {"identity_id": "identity-1", "token": "jwt-1"}

    def test_kubernetes_login(self, server):
        c = client(
            server,
            read_file=lambda path: "jwt-1",
            identity_id="identity-1",
            auth_method="kubernetes",
            kubernetes_token_file="/sa/token",
        )
        c.list_raw("app", "prod")
        assert server.logins[0].path == "/api/v1/auth/kubernetes/login"

    def test_bad_credentials(self, server):
        c = client(server, client_id="client-1", client_secret="wrong-secret")
        with pytest.raises(AuthenticationError, match="login failed") as caught:
            c.list_raw("app", "prod")
        assert caught.value.status == 401
        assert "wrong-secret" not in str(caught.value)

    def test_timeout_is_passed_to_transport(self, server):
        client(server, token="static-token", timeout=7).list_raw("app", "prod")
        assert server.calls[0].timeout == 7.0


class TestTokenCache:
    def test_logs_in_once_across_clients(self, server):
        cache = TokenCache()
        for _ in range(3):
            client(server, cache, client_id="client-1", client_secret="client-secret-1").list_raw(
                "app", "prod"
            )
        assert len(server.logins) == 1

    def test_separate_credentials_get_separate_tokens(self, server):
        server.universal.add(("client-2", "client-secret-2"))
        cache = TokenCache()
        client(server, cache, client_id="client-1", client_secret="client-secret-1").list_raw("app", "prod")
        client(server, cache, client_id="client-2", client_secret="client-secret-2").list_raw("app", "prod")
        assert len(server.logins) == 2

    def test_relogs_in_near_expiry(self, server):
        clock = FakeClock()
        cache = TokenCache(clock)
        server.expires_in = 120
        c = client(server, cache, client_id="client-1", client_secret="client-secret-1")
        c.list_raw("app", "prod")
        clock.now += 60
        c.list_raw("app", "prod")
        assert len(server.logins) == 1
        clock.now += 40
        c.list_raw("app", "prod")
        assert len(server.logins) == 2

    def test_rejected_cached_token_triggers_one_relogin(self, server):
        cache = TokenCache()
        c = client(server, cache, client_id="client-1", client_secret="client-secret-1")
        c.list_raw("app", "prod")
        server.tokens.clear()
        c.list_raw("app", "prod")
        assert len(server.logins) == 2

    def test_rejected_static_token_is_not_retried(self, server):
        with pytest.raises(AuthenticationError, match="authentication required"):
            client(server, token="revoked").list_raw("app", "prod")
        assert len(server.calls) == 1


class TestErrors:
    def test_not_found(self, server):
        with pytest.raises(NotFoundError, match="project not found") as caught:
            client(server, token="static-token").list_raw("other", "prod")
        assert caught.value.status == 404

    def test_forbidden(self, server):
        server.override = lambda call: error(403, "forbidden", "you do not have permission to do that")
        with pytest.raises(PermissionDeniedError):
            client(server, token="static-token").list_raw("app", "prod")

    def test_non_json_error(self, server):
        server.override = lambda call: HttpResponse(502, b"<html>bad gateway</html>")
        with pytest.raises(SekretError, match=r"\(502\): HTTP 502"):
            client(server, token="static-token").list_raw("app", "prod")

    def test_non_json_success(self, server):
        server.override = lambda call: HttpResponse(200, b"not json")
        with pytest.raises(SekretError, match="not JSON"):
            client(server, token="static-token").list_raw("app", "prod")

    def test_transport_exceptions_are_wrapped(self):
        def broken(*args):
            raise RuntimeError("socket exploded")

        with pytest.raises(TransportError, match="socket exploded"):
            client(broken, token="static-token").list_raw("app", "prod")

    def test_unreachable_server(self):
        c = SekretClient(settings(url="http://127.0.0.1:9", token="t", timeout=2), cache=TokenCache())
        with pytest.raises(TransportError, match=r"could not reach sekret server at http://127\.0\.0\.1:9"):
            c.list_raw("app", "prod")

    def test_values_and_credentials_are_redacted(self, server):
        def echo(call):
            if call.path.endswith("/batch"):
                return error(400, "bad_request", f"cannot store {call.body['upserts'][0]['value']}")
            return None

        server.override = echo
        c = client(server, client_id="client-1", client_secret="client-secret-1")
        with pytest.raises(SekretError) as caught:
            c.batch("app", "prod", upserts=[{"key": "K", "value": "super-secret-value"}])
        assert "super-secret-value" not in str(caught.value)
        assert "********" in str(caught.value)

    def test_credentials_echoed_by_server_are_redacted(self, server):
        server.override = lambda call: error(401, "login_failed", f"bad {call.body['client_secret']}")
        with pytest.raises(AuthenticationError) as caught:
            client(server, client_id="client-1", client_secret="client-secret-1").list_raw("app", "prod")
        assert "client-secret-1" not in str(caught.value)

    def test_transport_errors_are_redacted(self):
        def leaky(method, url, headers, body, timeout):
            raise RuntimeError(f"failed sending {headers['Authorization']}")

        with pytest.raises(TransportError) as caught:
            client(leaky, token="tok-abc").list_raw("app", "prod")
        assert "tok-abc" not in str(caught.value)


class TestSecrets:
    def test_get_secret(self, server):
        server.put("API_KEY", "abc", path="/api", tags=["web"])
        record = client(server, token="static-token").get_secret("app", "prod", "API_KEY", "/api")
        assert record.value == "abc"
        assert record.tags == ["web"]
        assert server.calls[0].query == {"path": "/api"}
        assert "abc" not in repr(record)

    def test_get_missing_secret(self, server):
        assert client(server, token="static-token").get_secret("app", "prod", "NOPE") is None

    def test_get_deleted_secret(self, server):
        server.secrets[("/", "DB_PASSWORD")].deleted = True
        assert client(server, token="static-token").get_secret("app", "prod", "DB_PASSWORD") is None

    def test_get_secret_in_missing_project_raises(self, server):
        with pytest.raises(NotFoundError, match="project not found"):
            client(server, token="static-token").get_secret("nope", "prod", "DB_PASSWORD")

    def test_keys_are_url_quoted(self, server):
        client(server, token="static-token").get_secret("app", "prod", "A/B")
        assert server.calls[0].path.endswith("/secrets/A%2FB")

    def test_batch_body(self, server):
        result = client(server, token="static-token").batch(
            "app", "prod", "/", upserts=[{"key": "NEW", "value": "v"}], deletes=["DB_PASSWORD"]
        )
        assert result["created"] == ["NEW"]
        assert result["deleted"] == ["DB_PASSWORD"]
        body = server.writes[0].body
        assert body == {"path": "/", "upserts": [{"key": "NEW", "value": "v"}], "deletes": ["DB_PASSWORD"]}


class TestTls:
    def test_validation_can_be_disabled(self):
        context = ssl_context(False, None)
        assert context.verify_mode == ssl.CERT_NONE
        assert context.check_hostname is False

    def test_default_verifies(self):
        assert ssl_context(True, None).verify_mode == ssl.CERT_REQUIRED

    def test_bad_ca_path(self, tmp_path):
        with pytest.raises(ConfigError, match="CA"):
            ssl_context(True, str(tmp_path / "missing.pem"))

    def test_ca_directory(self, tmp_path):
        assert ssl_context(True, str(tmp_path)).verify_mode == ssl.CERT_REQUIRED

    def test_a_ca_file_is_added_to_the_system_cas_not_in_their_place(self, tmp_path, monkeypatch):
        private = make_ca(tmp_path, "private")
        system = make_ca(tmp_path, "system")
        unknown = make_ca(tmp_path, "unknown")
        # OpenSSL's default paths honour SSL_CERT_FILE, which stands in for the system store here.
        monkeypatch.setenv("SSL_CERT_FILE", str(system.ca_file))
        monkeypatch.delenv("SSL_CERT_DIR", raising=False)
        context = ssl_context(True, str(private.ca_file))
        assert handshake(context, private)
        assert handshake(context, system)
        assert not handshake(context, unknown)

    def test_client_certificate_is_loaded(self, monkeypatch):
        loaded = []
        monkeypatch.setattr(
            ssl.SSLContext,
            "load_cert_chain",
            lambda self, certfile, keyfile: loaded.append((certfile, keyfile)),
        )
        ssl_context(True, None, "/etc/sekret/client.pem", "/etc/sekret/client-key.pem")
        assert loaded == [("/etc/sekret/client.pem", "/etc/sekret/client-key.pem")]

    def test_missing_client_certificate(self, tmp_path):
        with pytest.raises(ConfigError, match="client certificate"):
            ssl_context(True, None, str(tmp_path / "nope.pem"), str(tmp_path / "nope-key.pem"))

    def test_client_cert_needs_its_key(self):
        with pytest.raises(ConfigError, match="together"):
            settings(client_cert="/etc/sekret/client.pem")


def test_urllib_transport_does_not_follow_redirects():
    seen_auth = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/start":
                self.send_response(302)
                self.send_header("Location", "/elsewhere")
                self.end_headers()
                return
            seen_auth.append(self.headers.get("Authorization"))
            self.send_response(200)
            self.end_headers()

        def log_message(self, *args):
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        transport = UrllibTransport(ssl_context(True, None))
        url = f"http://127.0.0.1:{server.server_port}/start"
        response = transport("GET", url, {"Authorization": "Bearer secret"}, None, 5)
    finally:
        server.shutdown()
    assert response.status == 302
    assert seen_auth == []


def _recording_server():
    seen = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            seen.append((self.path, self.headers.get("Authorization")))
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"{}")

        def log_message(self, *args):
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, seen


def test_plain_http_never_goes_through_a_proxy(monkeypatch):
    target, reached = _recording_server()
    proxy, proxied = _recording_server()
    try:
        for name in ("HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"):
            monkeypatch.setenv(name, f"http://127.0.0.1:{proxy.server_port}")
        monkeypatch.delenv("NO_PROXY", raising=False)
        monkeypatch.delenv("no_proxy", raising=False)
        url = f"http://127.0.0.1:{target.server_port}/api"
        transport = UrllibTransport(ssl_context(True, None), url)
        assert transport("GET", url, {"Authorization": "Bearer saved-login"}, None, 15).status == 200
    finally:
        target.shutdown()
        proxy.shutdown()
    assert proxied == []
    assert reached == [("/api", "Bearer saved-login")]


@pytest.mark.parametrize(
    ("url", "bypass"),
    [
        ("http://sekret.example.com", True),
        ("http://127.0.0.1:8080", True),
        ("https://localhost", True),
        ("https://app.localhost.", True),
        ("https://127.0.0.2", True),
        ("https://[::1]:8443", True),
        ("https://[::ffff:127.0.0.1]", True),
        ("https://sekret.example.com", False),
        ("https://192.168.1.10", False),
    ],
)
def test_only_https_to_another_host_may_use_a_proxy(url, bypass):
    assert bypasses_proxy(url) is bypass


def test_https_to_another_host_keeps_the_environments_proxy(monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.example.com:3128")
    remote = UrllibTransport(ssl_context(True, None), "https://sekret.example.com")
    local = UrllibTransport(ssl_context(True, None), "https://127.0.0.1:8443")

    def proxies(transport):
        handlers = [h for h in transport._opener.handlers if isinstance(h, urllib.request.ProxyHandler)]
        return [h.proxies for h in handlers]

    assert proxies(remote) and proxies(remote)[0].get("https") == "http://proxy.example.com:3128"
    # An empty ProxyHandler registers nothing, but stops build_opener adding the environment's.
    assert not any(proxies(local))


def test_urllib_transport_returns_error_bodies(monkeypatch):
    transport = UrllibTransport(ssl_context(True, None))

    def fail(request, timeout):
        body = json.dumps({"error": "not_found", "message": "secret not found"}).encode()
        raise urllib.error.HTTPError(request.full_url, 404, "Not Found", {}, io.BytesIO(body))

    monkeypatch.setattr(transport._opener, "open", fail)
    response = transport("GET", URL + "/x", {}, None, 1)
    assert response == respond(404, {"error": "not_found", "message": "secret not found"})
