#!/usr/bin/python
from __future__ import annotations

DOCUMENTATION = r"""
module: secret
author: sekret maintainers
version_added: 0.1.0
short_description: Set or delete a secret in a sekret server
description:
  - Creates, updates or deletes one secret.
  - The current value is read first, so nothing is written when the secret already matches.
  - The secret value is never returned and diffs only say whether it changed.
  - "Connection options fall back to the matching C(SEKRET_*) environment variables on the host the module
    runs on, so this module is usually run with C(delegate_to: localhost)."
extends_documentation_fragment:
  - sekret.secrets.connection
options:
  key:
    description:
      - Secret key, for example C(DB_PASSWORD).
    type: str
    required: true
  value:
    description:
      - Secret value. Required when O(state=present).
    type: str
  state:
    description:
      - Whether the secret should exist.
    type: str
    choices: [present, absent]
    default: present
  comment:
    description:
      - Note stored with the new version when the secret is written.
      - Not compared, so changing only the comment does not cause a write.
    type: str
  tags:
    description:
      - Tags for the secret. Leave unset to keep the existing tags.
      - Tags are lowercase slugs and are compared ignoring order and duplicates.
    type: list
    elements: str
  restricted:
    description:
      - Whether only the principals on the secret's access list, project admins and organisation admins may
        reach it. Leave unset to keep it as it is.
      - A new secret created with C(true) is restricted in the same write, so it is never open even briefly.
      - Restricting needs per-secret access turned on for the project, and changing it needs a project or
        organisation admin.
      - Ignored when O(state=absent).
    type: bool
  access:
    description:
      - The secret's access list. When set, the list is made to match exactly, adding, changing and removing
        entries in one request. Leave unset to keep the list as it is.
      - An empty list removes every entry.
      - Entries only narrow what each principal's roles allow and never widen it. They apply while the secret
        is restricted.
      - Reading and changing the list needs a project or organisation admin, and adding entries needs
        per-secret access turned on for the project.
      - Ignored when O(state=absent).
    type: list
    elements: dict
    suboptions:
      kind:
        description:
          - What the entry names.
        type: str
        choices: [identity, user, group]
        required: true
      id:
        description:
          - The id of the machine identity or user, or the name of the group.
        type: str
        required: true
      allow:
        description:
          - What the principal may do with the secret. C(read) is always included.
        type: list
        elements: str
        choices: [read, read-value, edit, delete]
        default: [read, read-value]
attributes:
  check_mode:
    support: full
  diff_mode:
    support: full
    details: The value itself is never shown, only whether it changed.
"""

EXAMPLES = r"""
- name: Store a generated password
  sekret.secrets.secret:
    url: https://sekret.example.com
    project: app
    environment: prod
    path: /db
    key: DB_PASSWORD
    value: "{{ lookup('ansible.builtin.password', '/dev/null length=32') }}"
    comment: rotated by ansible
    tags: [database]
  delegate_to: localhost

- name: Keep a payment key to the one workload that needs it
  sekret.secrets.secret:
    project: app
    environment: prod
    path: /payments
    key: STRIPE_KEY
    value: "{{ stripe_key }}"
    restricted: true
    access:
      - kind: identity
        id: 0b9f2c1e-5d4a-4c7e-9a51-2f8d6e3b7c10
        allow: [read, read-value]
  delegate_to: localhost

- name: Remove a secret that is no longer used
  sekret.secrets.secret:
    project: app
    environment: prod
    key: OLD_API_KEY
    state: absent
  delegate_to: localhost
"""

RETURN = r"""
key:
  description: The secret key.
  returned: always
  type: str
  sample: DB_PASSWORD
path:
  description: Folder path of the secret.
  returned: always
  type: str
  sample: /db
operation:
  description: What happened, or would happen in check mode.
  returned: always
  type: str
  sample: updated
  choices: [created, updated, unchanged, deleted, absent]
snapshot_id:
  description: ID of the environment snapshot recorded for the write.
  returned: when a write was made
  type: str
restricted:
  description: Whether the secret is restricted to its access list afterwards.
  returned: when O(state=present)
  type: bool
access_changed:
  description: Whether the restricted flag or the access list changed, or would change in check mode.
  returned: when O(state=present)
  type: bool
"""

from dataclasses import dataclass  # noqa: E402

from ansible.module_utils.basic import AnsibleModule  # noqa: E402

from ansible_collections.sekret.secrets.plugins.module_utils.sekret_client import (  # noqa: E402
    ConfigError,
    NotFoundError,
    SecretRecord,
    SekretClient,
    SekretError,
    Settings,
    option_or_env,
    skip_verify_warning,
)

HIDDEN = "(hidden)"
HIDDEN_CHANGED = "(hidden, changed)"

CONNECTION_SPEC = {
    "url": {"type": "str"},
    "project": {"type": "str"},
    "environment": {"type": "str"},
    "path": {"type": "str", "default": "/"},
    "auth_method": {"type": "str", "choices": ["auto", "token", "universal", "oidc", "kubernetes"]},
    "token": {"type": "str", "no_log": True},
    "client_id": {"type": "str"},
    "client_secret": {"type": "str", "no_log": True},
    "identity_id": {"type": "str"},
    "oidc_token": {"type": "str", "no_log": True},
    "oidc_token_file": {"type": "path"},
    "kubernetes_token_file": {"type": "path"},
    "validate_certs": {"type": "bool"},
    "ca_path": {"type": "path"},
    "client_cert": {"type": "path"},
    "client_key": {"type": "path"},
    "timeout": {"type": "float"},
}

ARGUMENT_SPEC = {
    **CONNECTION_SPEC,
    "key": {"type": "str", "required": True, "no_log": False},
    "value": {"type": "str", "no_log": True},
    "state": {"type": "str", "choices": ["present", "absent"], "default": "present"},
    "comment": {"type": "str"},
    "tags": {"type": "list", "elements": "str"},
    "restricted": {"type": "bool"},
    "access": {
        "type": "list",
        "elements": "dict",
        "options": {
            "kind": {"type": "str", "choices": ["identity", "user", "group"], "required": True},
            "id": {"type": "str", "required": True},
            "allow": {
                "type": "list",
                "elements": "str",
                "choices": ["read", "read-value", "edit", "delete"],
                "default": ["read", "read-value"],
            },
        },
    },
}

ACTIONS = ("read", "read-value", "edit", "delete")


@dataclass(frozen=True)
class Target:
    project: str
    environment: str
    path: str
    key: str


def normalise_tags(tags: list[str]) -> list[str]:
    return sorted({t.strip() for t in tags if t and t.strip()})


def _describe(record: SecretRecord | None, changed_value: bool = False) -> dict:
    if record is None:
        return {}
    return {"value": HIDDEN_CHANGED if changed_value else HIDDEN, "tags": record.tags}


Principal = tuple[str, str]


def normalise_allow(allow: list[str] | None) -> list[str]:
    """The actions an entry grants, in a fixed order, with read always included."""
    wanted = set(allow or []) | {"read"}
    unknown = sorted(wanted - set(ACTIONS))
    if unknown:
        raise ConfigError(f"access allows unknown actions: {', '.join(unknown)}; use {', '.join(ACTIONS)}")
    return [a for a in ACTIONS if a in wanted]


def desired_access(entries: list[dict]) -> dict[Principal, list[str]]:
    wanted: dict[Principal, list[str]] = {}
    for entry in entries:
        kind, principal_id = entry.get("kind"), entry.get("id")
        if kind not in ("identity", "user", "group") or not principal_id:
            raise ConfigError("each access entry needs a kind (identity, user or group) and an id")
        if (kind, principal_id) in wanted:
            raise ConfigError(f"access names {kind} {principal_id} more than once")
        allow = entry["allow"] if entry.get("allow") is not None else ["read", "read-value"]
        wanted[(kind, principal_id)] = normalise_allow(allow)
    return wanted


def current_access(grants: list[dict]) -> dict[Principal, list[str]]:
    return {
        (g["principal_kind"], g["principal_id"]): [a for a in ACTIONS if a in (g.get("actions") or [])]
        for g in grants
    }


def plan_access(have: dict[Principal, list[str]], want: dict[Principal, list[str]]) -> tuple[list, list]:
    """Grants and revocations that turn `have` into `want`."""
    grant = [
        {"principal_kind": kind, "principal_id": principal_id, "actions": actions}
        for (kind, principal_id), actions in sorted(want.items())
        if have.get((kind, principal_id)) != actions
    ]
    revoke = [
        {"principal_kind": kind, "principal_id": principal_id}
        for kind, principal_id in sorted(have)
        if (kind, principal_id) not in want
    ]
    return grant, revoke


def _entries(access: dict[Principal, list[str]]) -> list[dict]:
    return [
        {"kind": kind, "id": principal_id, "allow": allow}
        for (kind, principal_id), allow in sorted(access.items())
    ]


def _apply_access(
    client: SekretClient, target: Target, restricted: bool | None, want: dict[Principal, list[str]] | None
) -> None:
    """Brings a secret that now exists to the requested flag and list, in one request."""
    listing = client.get_access(target.project, target.environment, target.key, target.path)
    change: dict = {}
    if restricted is not None and restricted != bool(listing.get("restricted")):
        change["restricted"] = restricted
    if want is not None:
        grant, revoke = plan_access(current_access(listing.get("grants") or []), want)
        if grant:
            change["grant"] = grant
        if revoke:
            change["revoke"] = revoke
    if change:
        client.change_access(target.project, target.environment, target.key, target.path, change)


def _ensure_present(
    client: SekretClient, target: Target, params: dict, check_mode: bool
) -> tuple[dict, list[str]]:
    warnings = []
    value = params["value"]
    tags = None if params.get("tags") is None else normalise_tags(params["tags"])
    comment = params.get("comment") or ""
    restricted = params.get("restricted")
    want = None if params.get("access") is None else desired_access(params["access"])
    current = client.get_secret(target.project, target.environment, target.key, target.path)

    after_tags = tags if tags is not None else (current.tags if current else [])
    if current is None:
        operation = "created"
    elif current.value_hidden:
        # The value cannot be compared, so let the server decide and skip the comment,
        # which it would otherwise treat as a change.
        operation = "updated"
        if comment:
            warnings.append("comment was not applied because this identity cannot read the current value")
        comment = ""
    elif current.value != value or (tags is not None and tags != current.tags):
        operation = "updated"
    else:
        operation = "unchanged"

    value_changed = current is None or current.value_hidden or current.value != value
    diff = {
        "before": _describe(current),
        "after": {"value": HIDDEN_CHANGED if value_changed else HIDDEN, "tags": after_tags},
    }

    # The list is only read when it is managed, since reading it needs an admin.
    before_restricted = current.restricted if current else False
    have: dict[Principal, list[str]] = {}
    if current is not None and want is not None:
        listing = client.get_access(target.project, target.environment, target.key, target.path)
        before_restricted = bool(listing.get("restricted"))
        have = current_access(listing.get("grants") or [])
    after_restricted = before_restricted if restricted is None else restricted
    grant, revoke = plan_access(have, want) if want is not None else ([], [])
    access_changed = after_restricted != before_restricted or bool(grant or revoke)
    if restricted is not None:
        if current is not None:
            diff["before"]["restricted"] = before_restricted
        diff["after"]["restricted"] = after_restricted
    if want is not None:
        if current is not None:
            diff["before"]["access"] = _entries(have)
        diff["after"]["access"] = _entries(want)

    result = {
        "changed": operation != "unchanged" or access_changed,
        "operation": operation,
        "restricted": after_restricted,
        "access_changed": access_changed,
        "diff": diff,
    }
    if check_mode:
        return result, warnings

    if operation != "unchanged":
        upsert = {"key": target.key, "value": value, "comment": comment}
        if tags is not None:
            upsert["tags"] = tags
        if current is None and restricted:
            # Restricted in the same write, so the new secret is never open.
            upsert["restricted"] = True
        outcome = client.batch(target.project, target.environment, target.path, upserts=[upsert])
        if target.key in outcome.get("created", []):
            operation = "created"
        elif target.key in outcome.get("updated", []):
            operation = "updated"
        else:
            operation = "unchanged"
        if outcome.get("snapshot_id"):
            result["snapshot_id"] = outcome["snapshot_id"]
    if access_changed:
        _apply_access(client, target, restricted, want)
    result.update(changed=operation != "unchanged" or access_changed, operation=operation)
    return result, warnings


def _ensure_absent(client: SekretClient, target: Target, check_mode: bool) -> tuple[dict, list[str]]:
    current = client.get_secret(target.project, target.environment, target.key, target.path)
    if current is None:
        return {"changed": False, "operation": "absent", "diff": {"before": {}, "after": {}}}, []
    result = {"changed": True, "operation": "deleted", "diff": {"before": _describe(current), "after": {}}}
    if check_mode:
        return result, []
    try:
        outcome = client.batch(target.project, target.environment, target.path, deletes=[target.key])
    except NotFoundError:
        result.update(changed=False, operation="absent")
        return result, []
    if target.key not in outcome.get("deleted", []):
        result.update(changed=False, operation="absent")
    if outcome.get("snapshot_id"):
        result["snapshot_id"] = outcome["snapshot_id"]
    return result, []


def ensure(
    client: SekretClient, params: dict, check_mode: bool = False, environ=None
) -> tuple[dict, list[str]]:
    """Brings one secret to the requested state and reports what changed."""
    project = option_or_env(params, "project", environ)
    environment = option_or_env(params, "environment", environ)
    if not project or not environment:
        raise ConfigError("project and environment are required (or SEKRET_PROJECT and SEKRET_ENVIRONMENT)")
    target = Target(project, environment, params.get("path") or "/", params["key"])
    if params.get("state", "present") == "absent":
        result, warnings = _ensure_absent(client, target, check_mode)
    else:
        result, warnings = _ensure_present(client, target, params, check_mode)
    result.update(key=target.key, path=target.path)
    return result, warnings


def main():
    module = AnsibleModule(
        argument_spec=ARGUMENT_SPEC,
        required_if=[("state", "present", ("value",))],
        supports_check_mode=True,
    )
    try:
        settings = Settings.from_options(module.params)
    except SekretError as e:
        module.fail_json(msg=e.message)
    # Before anything can fail, so a failed run still says the certificate went unchecked.
    if not settings.validate_certs:
        module.warn(skip_verify_warning(settings.url))
    try:
        client = SekretClient(settings)
        result, warnings = ensure(client, module.params, module.check_mode)
    except SekretError as e:
        module.fail_json(msg=e.message)
    for warning in warnings:
        module.warn(warning)
    if not module._diff:
        result.pop("diff", None)
    module.exit_json(**result)


if __name__ == "__main__":
    main()
