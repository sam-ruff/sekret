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
}


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


def _ensure_present(
    client: SekretClient, target: Target, params: dict, check_mode: bool
) -> tuple[dict, list[str]]:
    warnings = []
    value = params["value"]
    tags = None if params.get("tags") is None else normalise_tags(params["tags"])
    comment = params.get("comment") or ""
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
    result = {"changed": operation != "unchanged", "operation": operation, "diff": diff}
    if check_mode or operation == "unchanged":
        return result, warnings

    upsert = {"key": target.key, "value": value, "comment": comment}
    if tags is not None:
        upsert["tags"] = tags
    outcome = client.batch(target.project, target.environment, target.path, upserts=[upsert])
    if target.key in outcome.get("created", []):
        operation = "created"
    elif target.key in outcome.get("updated", []):
        operation = "updated"
    else:
        operation = "unchanged"
    result.update(changed=operation != "unchanged", operation=operation)
    if outcome.get("snapshot_id"):
        result["snapshot_id"] = outcome["snapshot_id"]
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
        client = SekretClient(Settings.from_options(module.params))
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
