# Audit log

sekret records every change and every read of a value: who, when, from which address, which project, environment, folder and key, and what happened. Values are never written to the log, only key names and counts.

Each project has its own log under *Audit* in the project, readable with the project `audit-log` permission. The organisation log under *Organisation > Audit log* covers everything, including sign-ins, identity changes and role changes, and needs the `org-audit-log` permission.

The project log only shows what the reader could see in the secrets view. If a role lets someone read the log but not a particular key, entries about that key appear with the key name, folder and details hidden.

![The audit log, filtered to secret actions](../assets/screenshots/audit-light.png)

## Searching and filtering

The log page has a search box and filters for action, actor type, environment and a date range, and can be sorted oldest or newest first. The same filters work over the API:

```sh
curl -fsS -H "Authorization: Bearer $SEKRET_TOKEN" \
  "$SEKRET_URL/api/v1/projects/web/audit?action=secret.&environment=prod&since=1767225600&order=desc&limit=100"
```

| Parameter | Meaning |
|---|---|
| `q` | Text matched anywhere in the action, actor, environment, folder, key or address, ignoring case. |
| `action` | Action prefix: `secret.` for every secret action, `secret.read` for reads. |
| `actor_id`, `actor_kind` | One actor, or `user` or `identity`. |
| `environment`, `key` | Exact matches. |
| `path` | Folder prefix. |
| `since`, `until` | Unix seconds, both inclusive. |
| `order` | `desc` (newest first, the default) or `asc`. |
| `limit` | Page size, 1 to 500, default 50. |
| `cursor` | The `next_cursor` from the previous page. |

Each response holds `entries`, the `total` matching the filters, and a `next_cursor` when there is another page. Paging by cursor never skips or repeats entries that share a timestamp.

## Actions

The actions you will see most are `secret.read`, `secret.write`, `secret.rollback`, `secret.generate`, `secret.rotate`, `snapshot.restore`, `auth.login`, `auth.machine-login`, `auth.cli-login`, `auth.token-renew`, `identity.update`, `member.add` and `role.put`. Every action name has the form `area.verb`.
