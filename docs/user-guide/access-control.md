# Access control

Access is granted by roles. A role is a list of rules, each of which allows or denies some actions on one kind of thing, optionally only where certain conditions hold. People, groups from your OIDC provider, and machine identities all receive roles the same way.

There are two scopes. Organisation roles cover projects in general, machine identities, users and the organisation audit log. Project roles cover everything inside one project.

## Built-in roles

| Role | Scope | What it allows |
|---|---|---|
| `org-admin` | organisation | Everything, in the organisation and in every project. |
| `org-member` | organisation | Create projects, and read identities, users and organisation roles. Everyone who signs in gets this unless `--default-org-role` says otherwise. |
| `backup-reader` | organisation | Download encrypted backups and nothing else. Meant for a machine identity on a backup host; see [Deployment](../deployment.md#pulling-backups-from-another-host). |
| `admin` | project | Everything in the project. |
| `developer` | project | Read, write and delete secrets, read history, restore snapshots and manage folders. |
| `viewer` | project | Read secrets and their values, and read the rest of the project's metadata. |
| `no-access` | project | Nothing. Useful for an explicit membership. |

Whoever creates a project becomes its `admin`. People in one of the `--oidc-admin-groups` groups are `org-admin` from their first sign-in.

## Rules

A rule has an effect (`allow` or `deny`), a subject, a list of actions and optional conditions.

The actions are `read`, `read-value`, `create`, `edit` and `delete`. `read` on secrets shows key names and metadata; `read-value` is needed to see values.

Project subjects are `secrets`, `secret-versions`, `snapshots`, `folders`, `environments`, `members`, `roles`, `audit-log` and `settings`. Organisation subjects are `projects`, `identities`, `org-members`, `org-roles`, `org-audit-log` and `backups`, where `read` on `backups` allows downloading an encrypted backup.

Not every action means something for every subject. The role editor in the web interface only offers the ones sekret checks:

| Subject | Actions that do something |
|---|---|
| `secrets` | `read`, `read-value`, `create`, `edit`, `delete` |
| `secret-versions` | `read`, `read-value` (old values also need `read-value` on `secrets`) |
| `snapshots` | `read`, `edit` (restoring a snapshot) |
| `folders`, `members` | `read`, `create`, `delete` |
| `environments`, `roles`, `identities`, `org-members`, `org-roles` | `read`, `create`, `edit`, `delete` |
| `settings` | `read`, `edit`, `delete` (deleting the project) |
| `audit-log`, `org-audit-log`, `backups` | `read` |
| `projects` | `create` |

A role saved earlier with another action keeps it, and the editor shows it so it can be removed.

A secret's history and rollback also need `read` on the secret itself; a secret someone cannot read answers as not found, the same as one that does not exist. In the history, a version whose own tags the reader may not read keeps its number and date, but its comment, tags and author are left blank. Snapshot descriptions leave out the folder when the reader cannot read that folder. Someone who cannot read every secret in the environment sees "secrets changed" in place of the counts of created, updated and deleted secrets, and a snapshot's secret count only includes the secrets they can read.

`read` on `environments` lists an environment in the interface. A deny on it hides the environment completely: its secrets, folders and snapshots answer as not found, even where `secrets` rules would allow them, and its entries in the audit log are redacted. Without a deny, `secrets` rules alone decide who reaches secrets, so a role for a machine that only fetches values need not grant `environments` as well.

Conditions narrow a rule to some secrets:

| Condition | Matches |
|---|---|
| `environments` | Environment slugs, such as `["dev", "staging"]`. |
| `paths` | Folder globs. `*` matches within one folder, `**` across folders. `/payments/**` covers `/payments` itself and every folder below it. |
| `keys` | Key globs, such as `DB_*`. |
| `tags` | Secrets carrying any of these tags. |

All conditions in one rule must hold for it to apply. Lists of patterns are limited to 50 entries of 256 characters.

This custom role lets a team read and change everything in `dev` and `staging`, read key names in `prod` but not values, and never read anything tagged `restricted`:

```json
{
  "name": "Payments team",
  "rules": [
    {"effect": "allow", "subject": "secrets", "actions": ["read", "read-value", "create", "edit", "delete"],
     "conditions": {"environments": ["dev", "staging"]}},
    {"effect": "allow", "subject": "secrets", "actions": ["read"], "conditions": {"environments": ["prod"]}},
    {"effect": "deny", "subject": "secrets", "actions": ["read-value"], "conditions": {"tags": ["restricted"]}},
    {"effect": "allow", "subject": "environments", "actions": ["read"]}
  ]
}
```

The web interface has an editor for this, with a grid of subjects and actions and a conditions builder for each rule.

![The role editor](../assets/screenshots/roles-light.png)

## How a decision is made

For a given action on a given secret, sekret collects every rule from every role the person holds, through their own membership, their groups and their organisation roles. If any matching rule denies, the answer is no. Otherwise, if any matching rule allows, the answer is yes. Otherwise it is no.

A deny whose condition cannot be checked, for example a tag condition when the tags are not known yet, counts as matching. An allow in the same position does not. Both mistakes fail closed. Checks that are not about one secret, such as on a whole environment, a folder or an audit log entry, never know the tags, so a deny scoped by tag applies to them too: someone denied reading `restricted` secrets also sees key names hidden in the project audit log.

## Nobody can hand out more than they hold

Granting a role, editing one or adding someone to a project is only allowed when everything the role allows is something you already hold, without a deny on it. Removing a restriction counts the same way, so someone held back by a deny cannot remove that deny from themselves, delete the role it comes from, or edit it away. The same applies to machine identities: you can only mint credentials for, edit or delete an identity whose access you already cover.
