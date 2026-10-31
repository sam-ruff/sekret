# Unlocking

In passphrase mode the root key is stored wrapped under your passphrase, and the server has to get it back into memory every time it starts. Until it does, the server is sealed: it answers `GET /api/v1/sys/status` and health checks, and refuses everything else with 503. The unlock policy decides how a sealed server gets unlocked.

The web interface calls a sealed server locked, and sealing it locking it.

There are three policies. Choose one at setup, change it later on the Server page under Organisation or with `sekret sys unlock-policy`, or fix it in configuration with `seal.unlock`, in which case configuration wins and the interface shows it as set there. When configuration fixes the policy before setup, the setup page names it instead of offering a choice. Key-file mode has no policy, because the key file is read on every start; when configuration names a key file, the setup page asks only for the setup code.

![Choosing the passphrase and unlock policy during setup](assets/screenshots/setup-light.png)

## Manual

Someone unlocks the server by hand after every start, on the unlock page or with `sekret sys unseal`. The passphrase is typed, used and wiped; the unwrapped root key exists only in the server's memory and nowhere else. Anyone who opens the web interface while the server is sealed lands on the unlock page, and goes back to where they were heading once it is unlocked. A tab that was already open moves there too, drops every secret it had loaded or revealed on the way, and says the server was locked while you were using it. Someone without the passphrase can sign out from the unlock page. After several wrong passphrases from one address the server makes that address wait before its next try; it says to try again shortly, without the exact wait. Others are not held back: an address that has never got the passphrase wrong waits its turn in a short line instead, so people guessing from elsewhere cannot simply crowd you out. A determined flood from many networks can still make network unlocks slow or busy, though.

!!! tip "Unlock through the Unix socket on the host"
    Set `server.unix_socket` on any server you can log in to. On the server itself, `sekret sys unseal --socket /run/sekret/sekret.sock` then unlocks through that socket, which the network's rate limits, back-off and queue do not apply to, so nobody on the network can hold you up. File permissions on the socket decide who may use it, and its directory must belong to the server's user and be closed to writes from other users. See [Deployment](deployment.md) for a systemd setup.

![The unlock page](assets/screenshots/unlock-dark.png)

This is the default and the strongest choice. Someone who walks off with the disk, the database, a backup or the whole powered-down machine gets nothing they can read without the passphrase. The cost is availability: after a power cut, a kernel update or a crash, every application that reads secrets from sekret waits until a person unlocks it. Pair it with an alert on the status endpoint (see [Deployment](deployment.md#alerting-when-sealed)) so that person knows.

It suits a home lab or small team where someone is usually around, and anything where a stolen disk would be a real problem.

## Remember

Someone unlocks the server by hand once, and from then on it unlocks itself on every start, until the remember file is lost or deliberately forgotten.

On the first manual unlock under this policy, the server generates a random 32-byte device key and writes it to the remember file with mode 0600. It refuses to write through a symlink or over an existing file it did not just remove. It then stores a second copy of the root key in the database, wrapped under that device key. On each start it reads the file, unwraps that copy and is unlocked. Neither half is any use alone: the database copy needs the file, and the file is only a random key.

There is no default location for the remember file. Set `seal.remember_file` (or `--remember-file`, `SEKRET_REMEMBER_FILE`) before choosing this policy; setup and the API refuse `remember` without it. It may not be the database or any file beside it that sekret uses, the root key file, a passphrase file or another file the server writes. The server warns at start when it sits in the database's directory or any folder beneath it, or on the same filesystem as the database, because then one copy of that directory or disk unlocks the server. Relative paths, files that do not exist yet and symlinked folders are all resolved before comparing. Keep it on a different disk from the database if you can, and keep it out of backups; `.skb` backups never include the database copy.

The file is opened without following symlinks and without blocking, and anything that is not a regular file is refused. When the server replaces or forgets it, it only deletes a regular file the size of a device key (or a symlink, never its target), so a mistyped path cannot delete something else.

After a power cut the server comes back unlocked, as long as the file and the database are both still there. If the file is missing, or does not match because it is from another server or was changed, the server stays sealed and logs why. The next manual unlock writes a fresh file.

The trade-off is the threat model. Someone with the server's disk, both the file and the database, can unlock it, just as with a key file. Someone with only a database dump or only a backup cannot. So this policy protects against leaked backups and database dumps, not against a stolen machine, unless you add a remember secret.

### Remember secret

A remember secret closes the stolen-disk gap. Set `seal.remember_secret_file` (or `--remember-secret-file`, `SEKRET_REMEMBER_SECRET_FILE`) to a file holding at least 32 random characters, or pass the value itself in `SEKRET_REMEMBER_SECRET`. The server then wraps the remembered root key under a key derived from the device key and the secret together (HKDF-SHA256), so the database and the remember file alone cannot unlock it. Deliver the secret from somewhere that is not the data disk, such as a systemd credential or a secret mounted from elsewhere.

A leading byte order mark and one trailing line ending are dropped, the same as for passphrases, and the environment variable's value is wiped from the process as soon as it is read. If the secret is missing or wrong, the server stays sealed and says so in its log. Unlocking by hand with a wrong secret configured writes a fresh remember file under the secret now configured.

Once an unlock has been remembered with a secret, the signed seal configuration records that, and the server never replaces it with a weaker wrap. If the secret goes missing from the configuration, unlocking by hand still works, but nothing is remembered: the server logs an error, records `sys.remember.refused` in the audit log, and the next start needs the passphrase again. To stop using a remember secret on purpose, forget the unlock (`sekret sys forget-unlock`) first; that is the only thing that clears the record.

### Locking by hand

"Lock now" on the Server page and `sekret sys seal` drop the root key from memory but keep the remembered unlock, so the next restart unlocks itself again. The admin status (`sekret sys status` as an admin, or the Server page) keeps reporting `remembered: true` while that is so. To make the next start need the passphrase, forget the unlock as well.

To stop remembering, choose another policy or run `sekret sys forget-unlock` (or "Forget remembered unlock" on the Server page, which asks you to confirm). Both delete the file and the database copy, and the next start needs the passphrase.

## Passphrase file

The server unlocks itself at start with a passphrase read from `seal.passphrase_file` or the `SEKRET_UNLOCK_PASSPHRASE` environment variable. It reads either one only when this policy is in force, once, at start, and drops a leading byte order mark and one trailing line ending. Automatic setup under this policy also takes the first passphrase from it; under `manual` or `remember` automatic setup needs `setup.passphrase_file`, so the passphrase does not have to sit in an unlock source the policy never uses.

Prefer the file. The server overwrites the value of `SEKRET_UNLOCK_PASSPHRASE` in its own environment block and removes the variable as soon as it starts, so it no longer shows in `/proc/<pid>/environ` and nothing the server runs inherits it. Whatever started the server, such as the unit file or container definition, still holds it. The server also logs a warning when this policy itself comes from the environment rather than the configuration file.

This keeps the passphrase on disk or in the process environment, which is about as strong as key-file mode: anyone who can read that file or the service's environment can unlock the server. It exists for setups that already deliver secrets from somewhere else, such as a vault agent or a systemd credential, and want one way of doing things. If the passphrase is wrong or missing, the server stays sealed and logs why.

## What an attacker gets

| Has | Manual | Remember | Passphrase file | Key-file mode |
|---|---|---|---|---|
| A `.skb` backup | Nothing without the passphrase | Nothing without the passphrase | Nothing without the passphrase | Nothing without the key file |
| A database dump | Metadata only | Metadata only | Metadata only | Metadata only |
| The server's disk | Metadata only | Every secret, unless a remember secret is set and kept elsewhere | Every secret if the passphrase file is on it | Every secret if the key file is on it |
| A running server as root | Every secret | Every secret | Every secret | Every secret |

"Metadata" means key names, folder paths, comments, tags, users, identities and the audit log, which are stored in plain text; see [Security model](security.md#what-the-database-and-backups-contain). No policy protects a running server from whoever controls it.

## After a power cut

- **Manual**: the server comes up sealed. The status endpoint reports `sealed`, monitoring alerts, someone unlocks it, and applications retry until they succeed.
- **Remember**: the server unlocks itself. If the remember file did not survive, it behaves like manual until someone unlocks it once.
- **Passphrase file**: the server unlocks itself as long as the passphrase source is still there.

Clients see 503 with the error `sealed` while the server is sealed. The Kubernetes operator keeps the Secrets it already wrote and tries again on its next pass; scripts and CI jobs should retry. Nothing needs restarting once the server is unlocked.

## Changing the policy

```sh
sekret sys unlock-policy remember          # asks for the current passphrase
sekret sys unlock-policy manual
```

`remember` and `passphrase-file` make the server easier to unlock without a person, so they need the current passphrase as well as an organisation admin (`passphrase` in the body of `PUT /api/v1/sys/unlock-policy`, `--passphrase-file` on the CLI, or the confirmation dialog on the Server page). Going back to `manual` makes things stricter and needs no passphrase. Moving to `remember` while unlocked writes the remember file straight away. Moving away from it forgets the remembered unlock. When `seal.unlock` is set in configuration, change it there and restart; the API refuses to change it.

## The policy cannot be changed behind your back

The stored policy, mode, root key fingerprint, the passphrase wrap, the remembered wrap and two one-way flags (whether the remembered unlock uses a remember secret, and whether old-format Kubernetes reviewer tokens have been moved) are signed together with an HMAC under a key derived from the root key, along with a counter that goes up with every change. The server checks the signature each time it recovers the root key. Someone who can write to the database but does not hold the root key cannot switch `manual` to `remember` and wait for your next unlock: the signature fails, the server falls back to `manual`, writes no remember file, logs an error and records `sys.seal_config.tampered` in the audit log. A server that would have unlocked itself stays sealed instead.

The server never signs fields a database writer chose. A tampered configuration is only repaired, and signed again as `manual` with nothing remembered, when someone unlocks with the passphrase, which proves the stored passphrase wrap. Until then, for instance on a key-file start or a `remember` start that found the tampering, it is used as `manual` in memory and left unsigned in the database, and changes that would sign it, such as forgetting the unlock or choosing `manual`, are refused with `seal_config_tampered`. So are backups: a backup checks the signature and the marks first and refuses, records `sys.backup.refused` and the tampering in the audit log, rather than sign a copy that a restore would then trust.

A configuration with no signature at all is only accepted if it grants nothing and no epoch mark exists yet: the `manual` policy with nothing remembered, as a database from before signing has. That one is signed on its first unlock. An unsigned configuration that asks for `remember` or `passphrase-file`, or holds a remembered wrap, or sits beside a mark, is treated exactly like a bad signature, because otherwise clearing the signature would be a way round it.

Every save also raises a mark outside the database: a small `<file>.epoch` file, mode 0600, beside the SQLite database, the remember file and the root key file, whichever there are. When the server recovers the root key it refuses a configuration whose counter is lower than the mark, even with a good signature: someone has put back an older copy, perhaps one from before you switched `passphrase-file` back to `manual`. It falls back to `manual` the same way, signs the reset above the mark, logs an error and records `sys.seal_config.rolled_back`. A mark that exists but cannot be read, is not a valid mark, or is a symlink counts as a rollback too, and is written again afterwards. Offline commands (`sekret admin rotate-root-key` and `set-seal-mode`) read the same marks, treat an older configuration the same way and always sign above the highest mark. A Postgres server with no remember file and no key file has nowhere to keep the mark, so there only the signature protects it.

Nothing the database can trigger lowers a mark: setting up a wiped database, or a key-file server finding its configuration row gone, starts the new configuration above the existing marks. The one way to lower them is `sekret admin reset-epoch`, run on the host with the server stopped. It checks the configuration with the root key (asking for the passphrase in passphrase mode), signs it again, resetting a tampered one to `manual`, and sets every mark to its counter. Use it after restoring an older backup over the same database path, which otherwise counts as a rollback, or after a mark is damaged.

Backups take a counter of their own. The copy inside a backup is signed one step above the live configuration, and the live configuration then moves one step past the copy, so a backup's configuration put back into the live database is always older than the mark and counts as a rollback.

Changing the passphrase replaces the root key, so a configuration from before the change no longer matches the data at all.

## Forgetting the passphrase

There is no recovery key, and nobody, including the people who wrote sekret, can reset a passphrase. If it is lost, the data is gone, and so is every backup taken under it. A server that is unlocked at the time keeps working until it is sealed or restarted, and a remember file keeps letting it start, so export anything you need while you still can and set up a new server. Store the passphrase somewhere that does not depend on sekret.
