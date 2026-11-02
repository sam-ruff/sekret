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

Organisation roles are granted under *Organisation > Access control*. The web interface will not remove the last `org-admin` grant listed there; grant it to someone else first. Removing a role that applies to you, directly or through a group, says so before you confirm.

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
| `settings` | `read`, `edit`, `delete` (deleting the project, which also needs `delete` on secrets, folders and environments and `edit` on snapshots, with no deny on any of them) |
| `audit-log`, `org-audit-log`, `backups` | `read` |
| `projects` | `create` |

A role saved earlier with another action keeps it, and the editor shows it so it can be removed.

A secret's history and rollback also need `read` on the secret itself; a secret someone cannot read answers as not found, the same as one that does not exist. Writes work the same way: setting, generating, importing or deleting a secret needs `read` on it as well as `create`, `edit` or `delete`, so a role that can write but not read gets "not found" whether or not the key is there, and never overwrites it. A new secret is judged by the folder and tags it would have. Restoring a snapshot leaves out every secret the person cannot read and never names one in its result. A folder someone cannot read answers as not found when they try to create or delete it, and a hidden folder inside one they delete stops the delete like a secret in it would. Creating an environment that a deny hides from you is refused the same way whether or not it already exists. A deny by tag cannot hide everything: a key that is taken by a secret you cannot read still cannot be created again beside it. In the history, a version whose own tags the reader may not read keeps its number and date, but its comment, tags and author are left blank. Snapshot descriptions leave out the folder when the reader cannot read that folder. Someone who cannot read every secret in the environment sees "secrets changed" in place of the counts of created, updated and deleted secrets, and a snapshot's secret count only includes the secrets they can read.

`read` on `environments` lists an environment in the interface. A deny on it hides the environment completely: its secrets, folders and snapshots answer as not found, even where `secrets` rules would allow them, and its entries in the audit log are redacted. Without a deny, `secrets` rules alone decide who reaches secrets, so a role for a machine that only fetches values need not grant `environments` as well.

Conditions narrow a rule to some secrets:

| Condition | Matches |
|---|---|
| `environments` | Environment slugs, such as `["dev", "staging"]`. |
| `paths` | Folder globs. `*` matches within one folder, `**` across folders. `/payments/**` covers `/payments` itself and every folder below it. |
| `keys` | Key globs, such as `DB_*`. |
| `tags` | Secrets carrying any of these tags. |

`environments` and `tags` match exactly, so they must be lowercase slugs, and a role with `prod*` or `Restricted` in them is refused rather than saved as a rule that never applies. Paths and keys are checked the same way: a folder pattern must start with `/` and may not end with `/` (other than `/` itself) or contain `//`, `.` or `..` segments, and a key pattern must be able to match a key, so `payments/**`, `/payments/` and `1KEY` are refused. All conditions in one rule must hold for it to apply. Lists of patterns are limited to 50 entries of 256 characters. A role may hold at most 200 path and key patterns across all its rules, deny rules included, and one member may hold at most 400 across every role that reaches them in a project, directly or through their groups. Adding a member or group, or changing a role someone already holds, is refused if it would take anyone past that, judged by the groups people had at their last sign-in. If the identity provider later gives someone groups that take them past it, listing secrets in that project answers `too_many_patterns` until an admin simplifies their roles.

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

The web interface has an editor for this, with a grid of subjects and actions and a conditions builder for each rule. The builder refuses a folder or key pattern that can never match as you add it, and the editor asks before Escape or a click outside throws away unsaved changes. An org admin sees the role, binding and member controls even where another role denies them, since the server lets them through. A role made only of deny rules grants nothing on its own, and the editor says so; give it alongside a role that allows access. On the secrets page, values your roles hide show as *No access to value*, with a note under the list that a deny in any role wins.

![The role editor](../assets/screenshots/roles-light.png)

Roles are not secret. Anyone with `read` on `roles` can see every rule, and everyone can see their own, so the environment slugs, folder globs and tags named in conditions are visible even where those rules hide the things themselves. Keep confidential words out of slugs, folder names and tags.

## Members

A project's *Members* tab lists who holds which project role. Someone can hold more than one role in a project, one row each. *Change role* swaps one of those roles for another in a single step: the new role is added before the old one is removed, so a failure part way never leaves them without access. If the removal fails, the page says so and both rows stay listed until you remove the old one.

## How a decision is made

For a given action on a given secret, sekret collects every rule from every role the person holds, through their own membership, their groups and their organisation roles. If any matching rule denies, the answer is no. Otherwise, if any matching rule allows, the answer is yes. Otherwise it is no.

A deny whose condition cannot be checked, for example a tag condition when the tags are not known yet, counts as matching. An allow in the same position does not. Both mistakes fail closed. Checks that are not about one secret, such as on a whole environment, a folder or an audit log entry, never know the tags, so a deny scoped by tag applies to them too: someone denied reading `restricted` secrets also sees key names hidden in the project audit log.

## Nobody can hand out more than they hold

Granting a role, editing one or adding someone to a project is only allowed when everything the role allows is something you already hold, without a deny on it. Removing a restriction counts the same way, so someone held back by a deny cannot remove that deny from themselves, delete the role it comes from, or edit it away. The same applies to machine identities: you can only mint credentials for, edit or delete an identity whose access you already cover.

Nobody with delegated rights can lock an admin out. Only an admin (an `org-admin`, or in a project its `admin`) may add deny rules to a role that reaches an admin, directly or through a group, or grant a role with deny rules to one. And when an `org-admin` lists, grants, edits or removes roles, bindings and members, in the organisation or any project, only the `org-admin` role is considered, so a deny bound to them through another role never stops them repairing access; it still limits what they do elsewhere until they lift it. A project `admin` is held to a deny an org admin binds to them, so an org admin can give someone a project while keeping, for example, values in `prod` out of their reach.
