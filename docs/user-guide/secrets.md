# Secrets, history and snapshots

A secret is a key, a value and some metadata: a comment and tags. Keys start with a letter or underscore and may contain letters, digits, `_`, `-` and `.`, up to 256 characters. Values can be up to 64 KiB of text.

Every change writes a new version. Nothing is ever edited in place, so the history of a secret is complete, and rolling back is itself a new version that copies an old value.

## Setting and reading

```sh
sekret secrets set DATABASE_URL=postgres://db/app API_KEY=-   # `-` reads the value from standard input
sekret secrets set --from-dotenv .env.example
sekret secrets list --values
sekret secrets get DATABASE_URL
sekret secrets delete OLD_KEY
```

In the web interface, values are masked until you reveal them, and every reveal is recorded in the audit log. A copied value is cleared from the clipboard after 45 seconds if it is still there. Pasting a `.env` file into the import dialog creates or updates every key in it in one write.

Reading a key name and reading its value are separate permissions, so a role can let someone see which keys exist without seeing any values.

## History and rollback

```sh
sekret secrets history DATABASE_URL --values
sekret secrets history DATABASE_URL --diff 3 5
sekret secrets rollback DATABASE_URL 3
```

The web interface shows the same history in a drawer, with a button to roll back. Values stay hidden until you choose "Show values", which is recorded in the audit log; then it shows each version's value and a line diff between any two versions. Closing the drawer or opening another secret hides them again.

![A secret's history, with a diff between two versions](../assets/screenshots/history-light.png)

## Snapshots

Every write to an environment, whether one secret or a hundred, records a snapshot of that environment's state afterwards. Restoring a snapshot puts the environment, or one folder of it, back the way it was: changed secrets go back to their old values, added ones are deleted and deleted ones come back. The restore is one new write, so it can be undone by restoring the snapshot before it.

```sh
sekret snapshots list
sekret snapshots restore 0192d4a8-... --path /payments
```

The server keeps the newest 200 snapshots per environment by default (`--snapshots-to-keep`). Pruning a snapshot does not delete any secret versions.

## Tags

Tags are short labels such as `pii` or `rotating`. They show in the interface and, more usefully, they can be matched by access rules: a deny on reading values tagged `restricted` applies to every secret carrying the tag, wherever it lives.
