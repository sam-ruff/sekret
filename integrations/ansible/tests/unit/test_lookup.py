import pytest
from ansible.errors import AnsibleError
from ansible.plugins.loader import lookup_loader
from fake_server import FakeServer

from ansible_collections.sekret.secrets.plugins.lookup.secret import read_secrets
from ansible_collections.sekret.secrets.plugins.module_utils.sekret_client import (
    SekretClient,
    Settings,
    TokenCache,
)

CONNECTION = {"url": "https://sekret.test", "token": "static-token"}


@pytest.fixture
def server():
    fake = FakeServer()
    fake.put("DB_PASSWORD", "hunter2", path="/db")
    fake.put("DB_USER", "app", path="/db")
    fake.put("REPLICA_PASSWORD", "replica", path="/db/replica")
    fake.put("ROOT_KEY", "root")
    return fake


@pytest.fixture
def lookup(server, monkeypatch):
    for name in ("SEKRET_URL", "SEKRET_TOKEN", "SEKRET_PROJECT", "SEKRET_ENVIRONMENT", "SEKRET_PATH"):
        monkeypatch.delenv(name, raising=False)
    plugin = lookup_loader.get("sekret.secrets.secret")
    plugin.client_factory = lambda settings, token_source=None: SekretClient(
        settings, transport=server, cache=TokenCache(), token_source=token_source
    )
    # No sekret CLI here: these tests name everything themselves.
    plugin.read_context = staticmethod(lambda cli_path, known: None)
    return plugin


@pytest.fixture
def client(server):
    return SekretClient(Settings.from_options(CONNECTION, environ={}), transport=server, cache=TokenCache())


class TestReadSecrets:
    def test_single_key(self, client):
        assert read_secrets(client, ["DB_PASSWORD"], "app", "prod", "/db") == ["hunter2"]

    def test_several_keys_keep_order(self, client):
        assert read_secrets(client, ["DB_USER", "DB_PASSWORD"], "app", "prod", "/db") == ["app", "hunter2"]

    def test_whole_path(self, client):
        assert read_secrets(client, [], "app", "prod", "/db") == [
            {"DB_PASSWORD": "hunter2", "DB_USER": "app"}
        ]

    def test_recursive_keys_are_relative(self, client):
        result = read_secrets(client, [], "app", "prod", "/db", all_keys=True, recursive=True)
        assert result == [{"DB_PASSWORD": "hunter2", "DB_USER": "app", "replica/REPLICA_PASSWORD": "replica"}]

    def test_recursive_from_root(self, client):
        (result,) = read_secrets(client, [], "app", "prod", "/", recursive=True)
        assert result["ROOT_KEY"] == "root"
        assert result["db/replica/REPLICA_PASSWORD"] == "replica"

    def test_missing_key_fails(self, client):
        with pytest.raises(Exception, match="secret NOPE not found in app/prod at /db"):
            read_secrets(client, ["NOPE"], "app", "prod", "/db")

    def test_missing_key_default(self, client):
        assert read_secrets(client, ["NOPE", "DB_USER"], "app", "prod", "/db", default="") == ["", "app"]

    def test_default_can_be_none(self, client):
        assert read_secrets(client, ["NOPE"], "app", "prod", "/db", default=None) == [None]

    def test_default_does_not_hide_missing_project(self, client):
        with pytest.raises(Exception, match="project not found"):
            read_secrets(client, ["DB_USER"], "nope", "prod", "/db", default="x")

    def test_hidden_value(self, client, server):
        server.hidden.add(("/db", "DB_PASSWORD"))
        with pytest.raises(Exception, match="not permitted to read the value of DB_PASSWORD"):
            read_secrets(client, ["DB_PASSWORD"], "app", "prod", "/db")

    def test_all_with_terms_is_rejected(self, client):
        with pytest.raises(Exception, match="all=true"):
            read_secrets(client, ["DB_USER"], "app", "prod", all_keys=True)


class TestLookupPlugin:
    def test_single_value(self, lookup):
        result = lookup.run(["DB_PASSWORD"], {}, project="app", environment="prod", path="/db", **CONNECTION)
        assert result == ["hunter2"]

    def test_whole_path_with_all(self, lookup):
        result = lookup.run([], {}, project="app", environment="prod", path="/db", all=True, **CONNECTION)
        assert result == [{"DB_PASSWORD": "hunter2", "DB_USER": "app"}]

    def test_environment_fallback(self, lookup, monkeypatch):
        monkeypatch.setenv("SEKRET_URL", "https://sekret.test")
        monkeypatch.setenv("SEKRET_TOKEN", "static-token")
        monkeypatch.setenv("SEKRET_PROJECT", "app")
        monkeypatch.setenv("SEKRET_ENVIRONMENT", "prod")
        assert lookup.run(["ROOT_KEY"], {}) == ["root"]

    def test_missing_key_raises_ansible_error(self, lookup):
        with pytest.raises(AnsibleError, match="secret NOPE not found"):
            lookup.run(["NOPE"], {}, project="app", environment="prod", **CONNECTION)

    def test_missing_key_with_default(self, lookup):
        result = lookup.run(["NOPE"], {}, project="app", environment="prod", default="fallback", **CONNECTION)
        assert result == ["fallback"]

    def test_requires_project_and_environment(self, lookup):
        with pytest.raises(AnsibleError, match="needs project and environment"):
            lookup.run(["DB_PASSWORD"], {}, **CONNECTION)

    def test_auth_failure_is_an_ansible_error(self, lookup):
        with pytest.raises(AnsibleError, match="authentication failed") as caught:
            lookup.run(
                ["ROOT_KEY"],
                {},
                project="app",
                environment="prod",
                url="https://sekret.test",
                client_id="client-1",
                client_secret="bad-secret-value",
            )
        assert "bad-secret-value" not in str(caught.value)
