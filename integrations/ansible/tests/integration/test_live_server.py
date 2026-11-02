"""Runs the collection against a real sekret server.

Needs SEKRET_TEST_URL and an organisation admin token in SEKRET_TEST_TOKEN; see run_integration.sh.
"""

import os
import shutil
import subprocess
import sys
import uuid
from pathlib import Path

import pytest

from ansible_collections.sekret.secrets.plugins.module_utils.sekret_client import (
    AuthenticationError,
    NotFoundError,
    SekretClient,
    Settings,
    TokenCache,
)

URL = os.environ.get("SEKRET_TEST_URL")
TOKEN = os.environ.get("SEKRET_TEST_TOKEN")
# The sekret binary the lookup runs for the saved login.
CLI = os.environ.get("SEKRET_TEST_CLI")
COLLECTION_DIR = Path(__file__).resolve().parents[2]
ENVIRONMENT = "prod"
BIN = Path(sys.executable).parent

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not (URL and TOKEN), reason="SEKRET_TEST_URL and SEKRET_TEST_TOKEN are not set"),
]


def make_client(cache=None, **auth):
    options = {"url": URL, **(auth or {"token": TOKEN})}
    return SekretClient(Settings.from_options(options, environ={}), cache=cache or TokenCache())


@pytest.fixture(scope="module")
def admin():
    return make_client()


@pytest.fixture(scope="module")
def project(admin):
    slug = f"ansible-{uuid.uuid4().hex[:8]}"
    admin.request("POST", "/api/v1/projects", {"slug": slug, "name": f"Ansible test {slug}"})
    admin.batch(slug, ENVIRONMENT, "/db", upserts=[{"key": "DB_PASSWORD", "value": "db-pass-7f3a"}])
    admin.batch(slug, ENVIRONMENT, "/app", upserts=[{"key": "API_URL", "value": "https://api.test"}])
    yield slug
    admin.request("DELETE", f"/api/v1/projects/{slug}")


@pytest.fixture(scope="module")
def machine(admin, project):
    identity = admin.request("POST", "/api/v1/identities", {"name": f"{project}-runner"})
    admin.request("PUT", f"/api/v1/identities/{identity['id']}/auth/universal", {"kind": "universal"})
    created = admin.request("POST", f"/api/v1/identities/{identity['id']}/client-secrets", {})
    admin.request(
        "POST",
        f"/api/v1/projects/{project}/members",
        {"principal_kind": "identity", "principal_id": identity["id"], "role": "developer"},
    )
    yield {"client_id": created["client_id"], "client_secret": created["client_secret"]}
    admin.request("DELETE", f"/api/v1/identities/{identity['id']}")


@pytest.fixture(scope="module")
def collections_path(tmp_path_factory):
    root = tmp_path_factory.mktemp("collections")
    dist = root / "dist"
    galaxy = str(BIN / "ansible-galaxy")
    subprocess.run(
        [galaxy, "collection", "build", "--output-path", str(dist), str(COLLECTION_DIR)],
        check=True,
        capture_output=True,
    )
    (archive,) = dist.glob("*.tar.gz")
    subprocess.run(
        [galaxy, "collection", "install", "-p", str(root / "install"), str(archive)],
        check=True,
        capture_output=True,
    )
    return root / "install"


def run_playbook(playbook, collections_path, extra_env, *args, cwd=None):
    env = {k: v for k, v in os.environ.items() if not k.startswith("SEKRET_")}
    env.update(
        ANSIBLE_COLLECTIONS_PATH=str(collections_path),
        ANSIBLE_NOCOLOR="1",
        ANSIBLE_LOCALHOST_WARNING="false",
        ANSIBLE_INVENTORY_UNPARSED_WARNING="false",
        SEKRET_URL=URL,
        **extra_env,
    )
    return subprocess.run(
        [str(BIN / "ansible-playbook"), str(playbook), *args],
        env=env,
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=300,
    )


def recap_changed(stdout):
    line = next(line for line in stdout.splitlines() if line.startswith("localhost"))
    return int(line.split("changed=")[1].split()[0])


class TestClient:
    def test_reads_seeded_secrets(self, admin, project):
        assert admin.list_raw(project, ENVIRONMENT, "/db") == [
            {"path": "/db", "key": "DB_PASSWORD", "value": "db-pass-7f3a"}
        ]
        record = admin.get_secret(project, ENVIRONMENT, "DB_PASSWORD", "/db")
        assert record.value == "db-pass-7f3a"

    def test_identical_write_is_unchanged(self, admin, project):
        upsert = {"key": "DB_PASSWORD", "value": "db-pass-7f3a"}
        result = admin.batch(project, ENVIRONMENT, "/db", upserts=[upsert])
        assert result["unchanged"] == ["DB_PASSWORD"]
        assert result["snapshot_id"] is None

    def test_deleted_secret_reads_as_missing(self, admin, project):
        admin.batch(project, ENVIRONMENT, "/tmp", upserts=[{"key": "SHORT_LIVED", "value": "x"}])
        admin.batch(project, ENVIRONMENT, "/tmp", deletes=["SHORT_LIVED"])
        assert admin.get_secret(project, ENVIRONMENT, "SHORT_LIVED", "/tmp") is None
        assert admin.get_secret(project, ENVIRONMENT, "NEVER_EXISTED", "/tmp") is None

    def test_missing_project(self, admin):
        with pytest.raises(NotFoundError, match="project not found"):
            admin.list_raw("does-not-exist", ENVIRONMENT)

    def test_universal_login_is_cached(self, project, machine):
        cache = TokenCache()
        for _ in range(3):
            assert make_client(cache, **machine).get_secret(project, ENVIRONMENT, "DB_PASSWORD", "/db")
        assert len(cache._entries) == 1

    def test_bad_client_secret(self, machine):
        client = make_client(client_id=machine["client_id"], client_secret="wrong-secret-value")
        with pytest.raises(AuthenticationError, match="login failed") as caught:
            client.list_raw("anything", ENVIRONMENT)
        assert "wrong-secret-value" not in str(caught.value)


class TestPlaybooks:
    def test_example_playbook(self, project, collections_path, tmp_path):
        workdir = tmp_path / "example"
        shutil.copytree(COLLECTION_DIR / "examples", workdir)
        dest = workdir / "app.env"
        extra = ["-e", f"sekret_project={project}", "-e", f"sekret_environment={ENVIRONMENT}"]

        first = run_playbook(workdir / "playbook.yml", collections_path, {"SEKRET_TOKEN": TOKEN}, *extra)
        assert first.returncode == 0, first.stdout + first.stderr
        assert dest.read_text().splitlines() == [
            "# Managed by Ansible",
            "DATABASE_PASSWORD=db-pass-7f3a",
            "API_URL=https://api.test",
            "LOG_LEVEL=info",
        ]
        assert recap_changed(first.stdout) == 2

        second = run_playbook(workdir / "playbook.yml", collections_path, {"SEKRET_TOKEN": TOKEN}, *extra)
        assert second.returncode == 0, second.stdout + second.stderr
        assert recap_changed(second.stdout) == 0

    @pytest.mark.skipif(not CLI, reason="SEKRET_TEST_CLI is not set")
    @pytest.mark.parametrize("expired", [False, True])
    def test_lookup_uses_the_cli_login_and_ansible_cfg(self, project, collections_path, tmp_path, expired):
        config = tmp_path / "config" / "sekret"
        config.mkdir(parents=True, mode=0o700)
        credentials = config / "credentials.toml"
        expires_at = 1 if expired else 4_102_444_800
        credentials.write_text(f'[servers."{URL}"]\ntoken = "{TOKEN}"\nexpires_at = {expires_at}\n')
        credentials.chmod(0o600)
        ansible_cfg = tmp_path / "ansible.cfg"
        ansible_cfg.write_text(
            f"[sekret]\nproject = {project}\nenvironment = {ENVIRONMENT}\ncli_login = false\n"
        )
        playbook = tmp_path / "cli.yml"
        playbook.write_text(
            "- hosts: localhost\n"
            "  gather_facts: false\n"
            "  tasks:\n"
            "    - ansible.builtin.assert:\n"
            "        that: lookup('sekret.secrets.secret', 'DB_PASSWORD', path='/db') == 'db-pass-7f3a'\n"
            "      no_log: true\n"
        )
        result = run_playbook(
            playbook,
            collections_path,
            {
                "ANSIBLE_CONFIG": str(ansible_cfg),
                "SEKRET_CLI": CLI,
                "XDG_CONFIG_HOME": str(tmp_path / "config"),
                "XDG_CACHE_HOME": str(tmp_path / "cache"),
            },
        )
        output = result.stdout + result.stderr
        assert TOKEN not in output
        if expired:
            assert result.returncode != 0
            assert "cli_login is off" in output
        else:
            assert result.returncode == 0, output

    @pytest.mark.skipif(not CLI, reason="SEKRET_TEST_CLI is not set")
    @pytest.mark.parametrize("loaded", ["elsewhere", "here", "by hand"])
    def test_a_shell_loaded_for_another_project_file_is_refused(
        self, project, collections_path, tmp_path, loaded
    ):
        config = tmp_path / "config" / "sekret"
        config.mkdir(parents=True, mode=0o700)
        credentials = config / "credentials.toml"
        credentials.write_text(f'[servers."{URL}"]\ntoken = "{TOKEN}"\nexpires_at = 4102444800\n')
        credentials.chmod(0o600)
        work = tmp_path / "repo-b"
        work.mkdir()
        project_file = work / ".sekret.toml"
        project_file.write_text('project = "repo-b-project"\nenvironment = "staging"\n')
        playbook = work / "read.yml"
        playbook.write_text(
            "- hosts: localhost\n"
            "  gather_facts: false\n"
            "  tasks:\n"
            "    - ansible.builtin.assert:\n"
            "        that: lookup('sekret.secrets.secret', 'DB_PASSWORD', path='/db') == 'db-pass-7f3a'\n"
            "      no_log: true\n"
        )
        env = {
            "SEKRET_CLI": CLI,
            "SEKRET_CLI_LOGIN": "false",
            "SEKRET_PROJECT": project,
            "SEKRET_ENVIRONMENT": ENVIRONMENT,
            "XDG_CONFIG_HOME": str(tmp_path / "config"),
            "XDG_CACHE_HOME": str(tmp_path / "cache"),
        }
        if loaded == "elsewhere":
            env["SEKRET_LOADED_FILE"] = str(tmp_path / "repo-a" / ".sekret.toml")
        elif loaded == "here":
            env["SEKRET_LOADED_FILE"] = str(project_file)
        result = run_playbook(playbook, collections_path, env, cwd=work)
        output = result.stdout + result.stderr
        if loaded == "elsewhere":
            assert result.returncode != 0
            assert "sekret-env" in output, output
        else:
            assert result.returncode == 0, output

    def test_module_and_lookup_as_machine_identity(self, project, machine, collections_path):
        values = {"value_one": f"first-{uuid.uuid4().hex}", "value_two": f"second-{uuid.uuid4().hex}"}
        result = run_playbook(
            COLLECTION_DIR / "tests/integration/playbooks/exercise.yml",
            collections_path,
            {"SEKRET_CLIENT_ID": machine["client_id"], "SEKRET_CLIENT_SECRET": machine["client_secret"]},
            "-e",
            f"project={project}",
            "-e",
            f"sekret_environment={ENVIRONMENT}",
            "-e",
            f"value_one={values['value_one']}",
            "-e",
            f"value_two={values['value_two']}",
            "--diff",
            "-v",
        )
        output = result.stdout + result.stderr
        assert result.returncode == 0, output
        assert "(hidden, changed)" in output
        for value in [*values.values(), machine["client_secret"]]:
            assert value not in output
