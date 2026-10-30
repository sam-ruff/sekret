import json

import pytest
from fake_server import FakeServer, error

from ansible_collections.sekret.secrets.plugins.module_utils.sekret_client import (
    ConfigError,
    SekretClient,
    SekretError,
    Settings,
    TokenCache,
)
from ansible_collections.sekret.secrets.plugins.modules import secret as secret_module
from ansible_collections.sekret.secrets.plugins.modules.secret import ensure

CONNECTION = {"url": "https://sekret.test", "token": "static-token"}


@pytest.fixture
def server():
    fake = FakeServer()
    fake.put("DB_PASSWORD", "old-value", path="/db", tags=["db"])
    return fake


@pytest.fixture
def client(server):
    return SekretClient(Settings.from_options(CONNECTION, environ={}), transport=server, cache=TokenCache())


def params(**overrides):
    base = {"project": "app", "environment": "prod", "path": "/db", "key": "DB_PASSWORD", "state": "present"}
    return {**base, **overrides}


def assert_no_value(result, *values):
    text = json.dumps(result)
    for value in values:
        assert value not in text


class TestPresent:
    def test_create(self, client, server):
        result, warnings = ensure(client, params(key="NEW", value="new-value", tags=["web ", "web", "db"]))
        assert result["changed"] is True
        assert result["operation"] == "created"
        assert result["snapshot_id"]
        assert server.secrets[("/db", "NEW")].value == "new-value"
        assert server.writes[0].body["upserts"][0]["tags"] == ["db", "web"]
        assert warnings == []
        assert_no_value(result, "new-value")

    def test_update_value(self, client, server):
        result, _ = ensure(client, params(value="new-value", comment="rotated"))
        assert result["changed"] is True
        assert result["operation"] == "updated"
        assert server.secrets[("/db", "DB_PASSWORD")].comment == "rotated"
        assert result["diff"] == {
            "before": {"value": "(hidden)", "tags": ["db"]},
            "after": {"value": "(hidden, changed)", "tags": ["db"]},
        }
        assert_no_value(result, "new-value", "old-value")

    def test_unchanged_makes_no_write(self, client, server):
        result, _ = ensure(client, params(value="old-value"))
        assert result["changed"] is False
        assert result["operation"] == "unchanged"
        assert server.writes == []

    def test_comment_alone_is_not_a_change(self, client, server):
        result, _ = ensure(client, params(value="old-value", comment="new note"))
        assert result["changed"] is False
        assert server.writes == []

    def test_tags_change(self, client, server):
        result, _ = ensure(client, params(value="old-value", tags=["db", "prod"]))
        assert result["changed"] is True
        assert result["diff"]["after"] == {"value": "(hidden)", "tags": ["db", "prod"]}
        assert server.secrets[("/db", "DB_PASSWORD")].tags == ["db", "prod"]

    def test_unset_tags_keep_existing(self, client, server):
        ensure(client, params(value="new-value"))
        assert "tags" not in server.writes[0].body["upserts"][0]
        assert server.secrets[("/db", "DB_PASSWORD")].tags == ["db"]

    def test_server_reports_unchanged(self, client, server):
        server.hidden.add(("/db", "DB_PASSWORD"))
        result, warnings = ensure(client, params(value="old-value", comment="note"))
        assert result["changed"] is False
        assert result["operation"] == "unchanged"
        assert server.writes[0].body["upserts"][0]["comment"] == ""
        assert warnings == ["comment was not applied because this identity cannot read the current value"]

    def test_recreate_deleted_secret(self, client, server):
        server.secrets[("/db", "DB_PASSWORD")].deleted = True
        result, _ = ensure(client, params(value="again"))
        assert result["operation"] == "created"
        assert result["changed"] is True


class TestCheckMode:
    def test_create_reports_change_without_writing(self, client, server):
        result, _ = ensure(client, params(key="NEW", value="v"), check_mode=True)
        assert result["changed"] is True
        assert result["operation"] == "created"
        assert result["diff"]["before"] == {}
        assert server.writes == []

    def test_update_reports_change_without_writing(self, client, server):
        result, _ = ensure(client, params(value="different"), check_mode=True)
        assert result["changed"] is True
        assert server.writes == []
        assert server.secrets[("/db", "DB_PASSWORD")].value == "old-value"

    def test_unchanged(self, client, server):
        result, _ = ensure(client, params(value="old-value"), check_mode=True)
        assert result["changed"] is False
        assert server.writes == []

    def test_absent(self, client, server):
        result, _ = ensure(client, params(state="absent"), check_mode=True)
        assert result["changed"] is True
        assert result["operation"] == "deleted"
        assert server.writes == []


class TestAbsent:
    def test_delete(self, client, server):
        result, _ = ensure(client, params(state="absent"))
        assert result["changed"] is True
        assert result["operation"] == "deleted"
        assert result["diff"]["after"] == {}
        assert server.secrets[("/db", "DB_PASSWORD")].deleted
        assert_no_value(result, "old-value")

    def test_already_absent(self, client, server):
        result, _ = ensure(client, params(key="NOPE", state="absent"))
        assert result == {
            "changed": False,
            "operation": "absent",
            "diff": {"before": {}, "after": {}},
            "key": "NOPE",
            "path": "/db",
        }
        assert server.writes == []

    def test_previously_deleted(self, client, server):
        ensure(client, params(state="absent"))
        result, _ = ensure(client, params(state="absent"))
        assert result["changed"] is False
        assert len(server.writes) == 1

    def test_deleted_concurrently(self, client, server):
        server.override = lambda call: (
            error(404, "not_found", "secret DB_PASSWORD not found") if call.path.endswith("/batch") else None
        )
        result, _ = ensure(client, params(state="absent"))
        assert result["changed"] is False


class TestErrors:
    def test_requires_project(self, client, monkeypatch):
        monkeypatch.delenv("SEKRET_PROJECT", raising=False)
        with pytest.raises(ConfigError, match="project and environment are required"):
            ensure(client, params(project=None, value="v"))

    def test_project_from_environment(self, client):
        result, _ = ensure(client, params(project=None, value="old-value"), environ={"SEKRET_PROJECT": "app"})
        assert result["changed"] is False

    def test_missing_environment(self, client):
        with pytest.raises(SekretError, match="environment not found"):
            ensure(client, params(environment="staging", value="v"))

    def test_write_error_does_not_leak_value(self, client, server):
        server.override = lambda call: (
            error(400, "bad_request", f"rejected {call.body['upserts'][0]['value']}")
            if call.path.endswith("/batch")
            else None
        )
        with pytest.raises(SekretError) as caught:
            ensure(client, params(value="leaky-value"))
        assert "leaky-value" not in caught.value.message


def run_main(monkeypatch, capsys, server, args):
    from ansible.module_utils.testing import patch_module_args

    monkeypatch.setattr(
        secret_module,
        "SekretClient",
        lambda settings: SekretClient(settings, transport=server, cache=TokenCache()),
    )
    with patch_module_args(args), pytest.raises(SystemExit):
        secret_module.main()
    return json.loads(capsys.readouterr().out)


class TestMain:
    def test_output_never_contains_value(self, monkeypatch, capsys, server):
        out = run_main(
            monkeypatch,
            capsys,
            server,
            {**CONNECTION, **params(value="brand-new-value"), "_ansible_diff": True},
        )
        assert out["changed"] is True
        assert out["operation"] == "updated"
        assert "diff" in out
        assert "brand-new-value" not in json.dumps(out)
        assert "static-token" not in json.dumps(out)

    def test_diff_left_out_unless_asked(self, monkeypatch, capsys, server):
        out = run_main(monkeypatch, capsys, server, {**CONNECTION, **params(value="old-value")})
        assert out["changed"] is False
        assert "diff" not in out

    def test_check_mode(self, monkeypatch, capsys, server):
        out = run_main(
            monkeypatch, capsys, server, {**CONNECTION, **params(value="x"), "_ansible_check_mode": True}
        )
        assert out["changed"] is True
        assert server.writes == []

    def test_failure(self, monkeypatch, capsys, server):
        args = {**CONNECTION, **params(value="x"), "token": "wrong-token"}
        out = run_main(monkeypatch, capsys, server, args)
        assert out["failed"] is True
        assert "authentication failed" in out["msg"]
        assert "wrong-token" not in json.dumps(out)

    def test_value_required_when_present(self, monkeypatch, capsys, server):
        out = run_main(monkeypatch, capsys, server, {**CONNECTION, **params()})
        assert out["failed"] is True
        assert "value" in out["msg"]
