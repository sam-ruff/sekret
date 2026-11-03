# Per-secret access

Per-secret access lets a project admin restrict one secret to a short list of users, groups and machine identities, so a Kubernetes pod can be given the three secrets it runs on and nothing else in the folder. It is a project setting and it is off by default. With it off, roles alone decide who reaches a secret, exactly as described in [Access control](access-control.md).

A list only ever narrows what roles allow. Someone on a list still needs a role that permits the action, so putting a `viewer` on a list with `edit` does not let them write. Project admins and organisation admins are never kept off a restricted secret, so a secret cannot be left with nobody able to reach it.

## Turning it on

Only a project admin or an organisation admin can turn the setting on or off, and each change is recorded in the project audit log as `project.secret-access`. In the web interface it is in the project's settings. From the command line:

```sh
sekret projects secret-access -p payments          # shows the setting and every restricted secret
sekret projects secret-access on -p payments
```

Everyone who can see the project can see whether the setting is on, through the `secret_access` field of the project. The list of restricted secrets is for admins only.

Turning the setting off is refused while any secret in the project is restricted, deleted secrets included, with an answer that says how many there are. This is deliberate: switching it off must never quietly open a secret that someone restricted. Unrestrict them first; the setting page and `sekret projects secret-access` both list them, with their environment, folder, whether they are deleted and how many entries their list holds. An admin whose own roles hide a folder does not see the secrets in it, and the CLI says how many more there are. Once it is off, every access list in the project is cleared, so turning it on again starts from nothing.

## Restricting a secret

A restricted secret can be reached only by the principals on its list, for the actions listed there, and by project and organisation admins. Everyone else is treated as if the secret did not exist.

```sh
sekret secrets access restrict STRIPE_KEY -p payments -e prod --path /stripe
sekret secrets access grant STRIPE_KEY --identity checkout-pod -p payments -e prod --path /stripe
sekret secrets access list STRIPE_KEY -p payments -e prod --path /stripe
```

Restricting needs the setting on. So does granting, which also works on an open secret, so a list can be ready before the secret is restricted and nobody loses access in between. Unrestricting and revoking always work, so a project can be cleaned up before the setting is switched off. Unrestricting clears the list, and the audit entry records who was on it; a list never comes back to life when a secret is restricted again later.

Restricting an existing secret leaves a moment when it was open, and does nothing about what was read before. To avoid that, create it restricted in the same write: `sekret secrets set --restricted KEY=-`, `sekret secrets generate --restricted KEY`, the restricted option in the web interface's new secret form, or `"restricted": true` in a `PUT`, batch or generate request. The answer to such a write lists the keys that are now restricted; the CLI, the web interface and the Ansible module fail if a key is missing from it, since a server from before per-secret access ignores the request and writes the secret open. A secret created that way starts with an empty list, so only admins can reach it until someone is granted access. Only a project admin can create a secret restricted, and the same goes for bringing a deleted secret back restricted. On a live secret the field must match what it is now, and anything else is refused with a pointer to the access settings, so a routine write never changes who can see a secret.

Restrictions belong to one secret in one environment. Restricting `STRIPE_KEY` in `prod` does nothing to `STRIPE_KEY` in `dev`.

## Access lists

Each entry names a user, a group from your identity provider, or a machine identity, and the actions it allows:

| Action | Allows |
|---|---|
| `read` | Seeing that the secret exists, with its metadata. Every entry has it. |
| `read-value` | Reading the value, through any route, including history. |
| `edit` | Writing a new value, rolling back, and bringing the secret back after it was deleted. |
| `delete` | Deleting it. |

`sekret secrets access grant` takes `--identity` (an id or a name), `--user` (an id or an email), `--group` (a group name) and `--allow`, which defaults to `read,read-value`. Each flag can be repeated, and granting someone already on the list replaces their actions. `revoke` takes the same principal flags, matched against the secret's own list by id or by the name it shows, and revoking someone who is not on the list is refused rather than reported as done. Without the right to look up identities or users, give their ids to `grant`. A name that matches more principals than one search returns is refused, so give the id. Users must have signed in once before they can be listed, and an identity that is deleted leaves the lists it was on. Group names are not checked, so a typo grants nothing.

A restricted secret tells each caller on its list what their entry allows, in the `granted` field, so the web interface only offers what will work.

A list holds at most 100 entries. Seeing a list and changing it are for project and organisation admins only, and only for secrets their own roles let them read. Every change is recorded as `secret.access`, with the entries added and removed.

Admin here means the built-in `org-admin` role, or the project's built-in `admin` role held directly or through a group. A custom role that allows everything is not enough, and since the built-in admin roles carry this exemption, only an admin can grant them; someone whose custom role merely matches them is refused. Admins are still held to their own deny rules, so a deny on `/payments/**` keeps an admin out of a restricted secret there as it would any other.

A write is planned against a secret as it stands. If its restriction or list changes before the write lands, the write is refused as a conflict and has to be tried again, so a change of access always takes effect at once.

## What someone off the list sees

Nothing. Every route answers for a restricted secret exactly as for a key that does not exist:

- Reading it, with `sekret secrets get` or the API, answers not found.
- Folder listings, recursive reads, `sekret export`, `sekret run`, `sekret env use` and the `raw` endpoint the operator and Ansible use leave it out.
- The project overview leaves out its row.
- Its history, rollback, generation, and its rotation policy answer not found.
- Writing to it or deleting it answers exactly as for a missing key, and never changes it. A malformed batch fails before any key in it is looked up.
- Snapshot secret counts leave it out, a snapshot's list of changes never names it, and restoring a snapshot leaves it as it is. A snapshot that only changed secrets hidden from you is not listed at all, and a rollback's reason does not give the version number.

Someone listed with only `read` sees the key with its value hidden, and needs `read-value` before it appears in `export`, `run` or the `raw` endpoint.

There is one thing a hidden secret cannot hide from someone allowed to create secrets in its folder: creating a secret with the same environment, folder and key fails, so they learn the name is taken. Anyone who could not create it there gets exactly the answer a missing key gives. Each of these refusals is recorded as `secret.write-refused`, which only admins see. Folder names are not hidden either: a folder holding only restricted secrets is still listed, and still cannot be deleted while those secrets are in it.

## The audit log

Entries about a restricted secret are marked when they are written. Readers off its list never get them: the log, its totals, filters and search all behave as if they were never written. Someone on the list gets the entries that name the secret, but not access-list changes, and not batch writes or folder reads that touched it, since those can name other restricted secrets. Admins get everything. Entries written before a secret was restricted stay as they were, and entries written while it was restricted stay hidden after it is opened again. Entries are matched to a secret by environment, folder and key, so a secret created later in the same place, after an environment was deleted and made again, shares them. See [Audit log](audit-log.md#searching-and-filtering).

The organisation audit log leaves the same entries out for everyone but organisation admins. No audit entry ever holds a value.

## Deleting and backing up

Deleting a project, or an environment, destroys the history of every secret in it. When any of those secrets is restricted, only a project admin or an organisation admin can do it.

Downgrading to a release from before per-secret access is refused: an older server will not start on a database that has this release's schema, since it would ignore every restriction.

Backups hold the whole database, restricted secrets and their lists included. Anyone who can download and decrypt a backup can read everything in it, so treat `backup-reader` as access to every secret.

Automatic [rotation](rotation.md) is not bound by lists. It replaces the value of a restricted secret on schedule and keeps its list as it was. Because of that, while per-secret access is on only a project admin can change the project's default rotation policy, which every inheriting secret follows. A policy set before the setting was turned on, or on a secret before it was restricted, keeps running, so check the project default and each secret's policy when you restrict it.

## Example: one pod, three secrets

The `payments` project holds dozens of secrets in `prod`. The checkout service runs as the Kubernetes service account `checkout` and needs `STRIPE_KEY`, `STRIPE_WEBHOOK_SECRET` and `DATABASE_URL`, all in `/checkout`. The rest of the folder belongs to other services.

First, give the service account a [machine identity](machine-identities.md#kubernetes) called `checkout-pod`, and make it a `viewer` of the project, as for any [Kubernetes workload](../integrations/kubernetes.md). On its own, that role would let it read every secret in the project.

Then turn the setting on, restrict everything in `/checkout`, and list the pod on just the three secrets it needs:

```sh
set -e
export SEKRET_PROJECT=payments SEKRET_ENVIRONMENT=prod SEKRET_PATH=/checkout
sekret projects secret-access on
# Grant first, so the pod never loses a secret it reads while the restrictions go on.
for key in STRIPE_KEY STRIPE_WEBHOOK_SECRET DATABASE_URL; do
  sekret secrets access grant "$key" --identity checkout-pod
done
for key in STRIPE_KEY STRIPE_WEBHOOK_SECRET DATABASE_URL REFUNDS_KEY LEDGER_TOKEN; do
  sekret secrets access restrict "$key"
done
```

The `SekretSecret` for the pod can then ask for the whole folder. The operator logs in as `checkout-pod`, the server hands back only the three secrets on its list, and the `Secret` it writes holds those three:

```yaml
apiVersion: sekret.sam-ruff.github.io/v1alpha1
kind: SekretSecret
metadata:
  name: checkout-config
  namespace: checkout
spec:
  project: payments
  environment: prod
  path: /checkout
  target:
    name: checkout-env
    type: Opaque
  auth:
    identityId: 0192d4a8-0000-7000-8000-000000000000
    serviceAccountName: checkout
```

Naming a key the identity cannot see in `spec.keys` makes the sync fail with `KeysNotFound`, as it does for a key that does not exist. A failed sync leaves the `Secret` as it was, so restricting a key that a `SekretSecret` already names stops its updates but does not remove the copy in the cluster; a sync of a whole folder drops it on the next refresh. Delete or rotate the copy if it must go at once. The project admins still see and manage all five secrets. Developers on the project see none of them until someone puts them on a list.
