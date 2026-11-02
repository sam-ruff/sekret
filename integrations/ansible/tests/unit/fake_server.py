"""In-memory stand-in for the sekret HTTP API, used as an injected transport."""

import json
import re
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, unquote, urlsplit

from ansible_collections.sekret.secrets.plugins.module_utils.sekret_client import HttpResponse

SECRET_RE = re.compile(r"^/api/v1/projects/([^/]+)/environments/([^/]+)/secrets/([^/]+)$")
ACCESS_RE = re.compile(r"^/api/v1/projects/([^/]+)/environments/([^/]+)/secrets/([^/]+)/access$")
ACTIONS = ("read", "read-value", "edit", "delete")
LOGIN_PATHS = {
    "/api/v1/auth/universal/login": "universal",
    "/api/v1/auth/oidc/login": "oidc",
    "/api/v1/auth/kubernetes/login": "kubernetes",
}


@dataclass
class Call:
    method: str
    path: str
    query: dict
    headers: dict
    body: object
    timeout: float


@dataclass
class StoredSecret:
    value: str | None
    tags: list = field(default_factory=list)
    comment: str = ""
    version: int = 1
    deleted: bool = False
    restricted: bool = False
    # (kind, id) to the actions granted.
    grants: dict = field(default_factory=dict)


def respond(status, payload=None):
    return HttpResponse(status, b"" if payload is None else json.dumps(payload).encode())


def error(status, code, message):
    return respond(status, {"error": code, "message": message})


class FakeServer:
    def __init__(self, project="app", environment="prod"):
        self.project = project
        self.environment = environment
        self.calls: list[Call] = []
        self.secrets: dict[tuple[str, str], StoredSecret] = {}
        self.hidden: set[tuple[str, str]] = set()
        self.tokens = {"static-token"}
        self.universal = {("client-1", "client-secret-1")}
        self.jwt_logins = {("identity-1", "jwt-1")}
        self.expires_in = 3600
        self.override = None
        self._issued = 0
        # Per-secret access for the project, and whether callers are its admins.
        self.secret_access = True
        self.admin = True
        # Behaves like a server from before per-secret access, which drops the field.
        self.ignore_restricted = False

    def put(self, key, value, path="/", tags=None, comment=""):
        self.secrets[(path, key)] = StoredSecret(value, sorted(tags or []), comment)

    def calls_to(self, method, prefix=""):
        return [c for c in self.calls if c.method == method and c.path.startswith(prefix)]

    @property
    def logins(self):
        return [c for c in self.calls if c.path in LOGIN_PATHS]

    @property
    def writes(self):
        return [c for c in self.calls if c.path.endswith("/secrets/batch")]

    @property
    def access_changes(self):
        return [c for c in self.calls if c.method == "PATCH" and c.path.endswith("/access")]

    def __call__(self, method, url, headers, body, timeout):
        parts = urlsplit(url)
        call = Call(
            method,
            parts.path,
            dict(parse_qsl(parts.query)),
            dict(headers),
            json.loads(body) if body else None,
            timeout,
        )
        self.calls.append(call)
        if self.override is not None:
            response = self.override(call)
            if response is not None:
                return response
        return self._route(call)

    def _issue(self):
        self._issued += 1
        token = f"issued-{self._issued}"
        self.tokens.add(token)
        return respond(200, {"access_token": token, "token_type": "Bearer", "expires_in": self.expires_in})

    def _route(self, call):
        kind = LOGIN_PATHS.get(call.path)
        if kind == "universal":
            pair = (call.body.get("client_id"), call.body.get("client_secret"))
            return self._issue() if pair in self.universal else error(401, "login_failed", "login failed")
        if kind is not None:
            pair = (call.body.get("identity_id"), call.body.get("token"))
            return self._issue() if pair in self.jwt_logins else error(401, "login_failed", "login failed")

        bearer = call.headers.get("Authorization", "").removeprefix("Bearer ")
        if bearer not in self.tokens:
            return error(401, "unauthorised", "authentication required")

        if call.path == "/api/v1/secrets/raw":
            return self._raw(call)
        if call.path.endswith("/secrets/batch"):
            return self._batch(call)
        match = ACCESS_RE.match(call.path)
        if match:
            return self._access(call, *(unquote(g) for g in match.groups()))
        match = SECRET_RE.match(call.path)
        if match and call.method == "GET":
            return self._get(call, *(unquote(g) for g in match.groups()))
        return error(404, "not_found", "route not found")

    def _scope_error(self, project, environment):
        if project != self.project:
            return error(404, "not_found", "project not found")
        if environment != self.environment:
            return error(404, "not_found", "environment not found")
        return None

    def _raw(self, call):
        failed = self._scope_error(call.query.get("project"), call.query.get("environment"))
        if failed:
            return failed
        base = call.query.get("path", "/")
        recursive = call.query.get("recursive") == "true"
        prefix = "/" if base == "/" else base + "/"
        secrets = [
            {"path": path, "key": key, "value": s.value}
            for (path, key), s in sorted(self.secrets.items())
            if not s.deleted
            and (path, key) not in self.hidden
            and (path == base or (recursive and path.startswith(prefix)))
        ]
        return respond(200, {"project": self.project, "environment": self.environment, "secrets": secrets})

    def _get(self, call, project, environment, key):
        failed = self._scope_error(project, environment)
        if failed:
            return failed
        path = call.query.get("path", "/")
        stored = self.secrets.get((path, key))
        if stored is None:
            return error(404, "not_found", "secret not found")
        hidden = (path, key) in self.hidden
        return respond(
            200,
            {
                "key": key,
                "path": path,
                "value": None if hidden or stored.deleted else stored.value,
                "value_hidden": hidden,
                "version": stored.version,
                "tags": stored.tags,
                "comment": stored.comment,
                "restricted": stored.restricted,
            },
        )

    @staticmethod
    def _listing(stored):
        grants = [
            {
                "principal_kind": kind,
                "principal_id": principal_id,
                "principal_name": principal_id,
                "actions": actions,
                "created_at": 1,
            }
            for (kind, principal_id), actions in sorted(stored.grants.items())
        ]
        return {"restricted": stored.restricted, "grants": grants}

    def _access(self, call, project, environment, key):
        failed = self._scope_error(project, environment)
        if failed:
            return failed
        if not self.admin:
            return error(
                403, "forbidden", "only a project admin or an organisation admin can manage per-secret access"
            )
        stored = self.secrets.get((call.query.get("path", "/"), key))
        if stored is None:
            return error(404, "not_found", "secret not found")
        if call.method == "GET":
            return respond(200, self._listing(stored))
        body = call.body or {}
        if (body.get("restricted") is True or body.get("grant")) and not self.secret_access:
            return error(409, "secret_access_off", "per-secret access is off for this project")
        for actions in (g.get("actions") or [] for g in body.get("grant", [])):
            if any(a not in ACTIONS for a in actions):
                return error(400, "bad_request", "an access list cannot grant that")
        if body.get("restricted") is False and stored.restricted:
            # Unrestricting clears the list before the request's grants apply.
            stored.grants = {}
        if body.get("restricted") is not None:
            stored.restricted = body["restricted"]
        for revoked in body.get("revoke", []):
            stored.grants.pop((revoked["principal_kind"], revoked["principal_id"]), None)
        for granted in body.get("grant", []):
            actions = [a for a in ACTIONS if a == "read" or a in granted["actions"]]
            stored.grants[(granted["principal_kind"], granted["principal_id"])] = actions
        return respond(200, self._listing(stored))

    def _batch(self, call):
        project, environment = call.path.split("/")[4], call.path.split("/")[6]
        failed = self._scope_error(project, environment)
        if failed:
            return failed
        path = call.body.get("path", "/")
        result = {
            "created": [],
            "updated": [],
            "deleted": [],
            "unchanged": [],
            "restricted": [],
            "snapshot_id": None,
        }
        for upsert in call.body.get("upserts", []):
            key = upsert["key"]
            current = self.secrets.get((path, key))
            live = current if current and not current.deleted else None
            tags = sorted(upsert["tags"]) if upsert.get("tags") is not None else (live.tags if live else [])
            comment = upsert.get("comment", "")
            wanted = upsert.get("restricted")
            # A deleted secret can come back restricted; a live one changes only through its access route.
            if live is not None and wanted is not None and wanted != live.restricted:
                return error(400, "bad_request", f"{key} already exists")
            if wanted and live is None and not self.secret_access:
                return error(409, "secret_access_off", "per-secret access is off for this project")
            if self.ignore_restricted:
                wanted = None
            if live and live.value == upsert["value"] and live.tags == tags and not comment:
                result["unchanged"].append(key)
                continue
            result["updated" if live else "created"].append(key)
            version = current.version + 1 if current else 1
            restricted = bool(wanted) or (current.restricted if current else False)
            grants = current.grants if current else {}
            self.secrets[(path, key)] = StoredSecret(
                upsert["value"], tags, comment, version, restricted=restricted, grants=grants
            )
            if wanted and restricted:
                result["restricted"].append(key)
        for key in call.body.get("deletes", []):
            current = self.secrets.get((path, key))
            if current is None or current.deleted:
                return error(404, "not_found", f"secret {key} not found")
            current.deleted = True
            current.version += 1
            result["deleted"].append(key)
        if result["created"] or result["updated"] or result["deleted"]:
            result["snapshot_id"] = f"snap-{len(self.calls)}"
        if self.ignore_restricted:
            del result["restricted"]
        return respond(200, result)
