# Deployment

A production install is one binary, a database and a reverse proxy for TLS, plus a root key file if you use key-file mode. SQLite is enough for a team of a few dozen people; use Postgres if you already run one or want point-in-time recovery. Both are supported equally, and the test suite runs against each.

Upgrades are a binary swap. The server applies database migrations on start, so stop it, replace the binary or image, and start it again. There is no downgrade path once a newer version has migrated the database, so back up first.

## As a systemd service

```sh
curl -fsSL https://raw.githubusercontent.com/sam-ruff/sekret/main/install.sh | sh
sudo useradd --system --home /var/lib/sekret --create-home sekret
sudo install -d -m 0700 -o sekret /etc/sekret
```

`/etc/systemd/system/sekret.service`:

```ini
[Unit]
Description=sekret secrets manager
After=network-online.target
Wants=network-online.target

[Service]
User=sekret
Group=sekret
ExecStart=/usr/local/bin/sekret server
Environment=SEKRET_PUBLIC_URL=https://sekret.example.com
Environment=SEKRET_LISTEN=127.0.0.1:8080
Environment=SEKRET_DATABASE_URL=sqlite:///var/lib/sekret/sekret.db?mode=rwc
Environment=SEKRET_OIDC_ISSUER=https://auth.example.com/realms/main
Environment=SEKRET_OIDC_CLIENT_SECRET_FILE=/etc/sekret/oidc-client-secret
Environment=SEKRET_TRUSTED_PROXIES=127.0.0.1/32
Restart=on-failure
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/var/lib/sekret
RuntimeDirectory=sekret
RuntimeDirectoryMode=0750
CapabilityBoundingSet=
MemoryDenyWriteExecute=true

[Install]
WantedBy=multi-user.target
```

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now sekret
sudo journalctl -u sekret | grep 'setup code'
```

Put Caddy, nginx or Traefik in front for TLS and point it at `127.0.0.1:8080`, then open `https://sekret.example.com/setup` and enter the setup code, or run `sekret sys init --server https://sekret.example.com`. The same settings can live in a [configuration file](configuration.md#the-configuration-file) instead: `ExecStart=/usr/local/bin/sekret server --config /etc/sekret/sekret.yaml`.

For key-file mode, generate the key and add `Environment=SEKRET_ROOT_KEY_FILE=/etc/sekret/root.key`:

```sh
sudo -u sekret sh -c 'sekret admin generate-root-key > /etc/sekret/root.key && chmod 600 /etc/sekret/root.key'
```

## Unlocking after a restart

In passphrase mode with the default `manual` [unlock policy](unlocking.md), the server starts sealed after every restart, including a power cut. Unlock it on the web interface, which shows an unlock page while sealed, or from anywhere that can reach it:

```sh
sekret sys unseal --server https://sekret.example.com
```

No sign-in is needed: the passphrase is the credential. Applications get 503 until then and should retry.

!!! tip "Set up the Unix socket"
    Network unlocks are rate limited, backed off and queued so that guessing is slow, and a large enough flood of guesses from many networks can still keep them busy. The Unix socket below is not, so set `server.unix_socket` on every server whose host you can log in to.

On the server host you can also unlock through a Unix socket, which is not subject to the network's rate limits, back-off or queue, so nobody guessing over the network can hold you up. This is the recommended way to unlock on a host you can log in to. Set `server.unix_socket` (and `server.unix_socket_mode: "0660"` if a group should be able to use it), in a directory that belongs to the server's user and that neither its group nor other users can write to, such as `RuntimeDirectory=sekret` with `RuntimeDirectoryMode=0750` in the unit above. To share the socket with a group, give the directory that group and the setgid bit (mode 2750) so the socket inherits it; do not make the directory group-writable, since any member could then swap the socket for their own. Every directory above it must also be closed to other users, apart from sticky ones such as `/tmp` where the entry on the way down belongs to root or the server's user. The server refuses to start otherwise. The CLI refuses to send a passphrase to a socket in a directory its group or others can write to, below a directory another user could rearrange, owned by someone other than the directory's owner, or whose listening process is not the socket's owner. It also needs the socket to belong to root, to you, or to the user you name with `--socket-owner` or `SEKRET_SOCKET_OWNER`, and it sends the passphrase over the connection it checked. With the unit above, sekret runs as `sekret`, so:

```sh
sekret sys unseal --socket /run/sekret/sekret.sock --socket-owner sekret
```

The server serves only status and unseal on the socket. It holds a lock on its database for as long as it runs (a `flock` on the SQLite file and on `<db>.lock` beside it, an advisory lock on Postgres), so `sekret admin init`, `rotate-root-key`, `set-seal-mode` and `restore` refuse to run until it stops. `sekret admin bootstrap` still works alongside it, as long as it is the same sekret version as the server. A starting server waits up to 30 seconds for the lock, and a running server exits with an error if it loses it, so keep `Restart=on-failure`. See [One server per database](configuration.md#one-server-per-database).

## Alerting when sealed

`GET /api/v1/sys/status` needs no authentication and always answers 200:

```json
{"state": "sealed", "seal_mode": null, "unlock_policy": null, "configured": false, "remembered": false, "unsealed_by": null, "web_setup": true, "version": "1.2.0"}
```

`state` is `uninitialised`, `sealed` or `unsealed`, which is all monitoring needs. The other fields are only filled in for organisation admins, at `GET /api/v1/sys/status/detail` (or `sekret sys status` when signed in as one), so the public endpoint does not tell anyone how the server unlocks. There, while unsealed, `unsealed_by` says how: `passphrase`, `remember`, `passphrase-file` or `key-file`; `key-file` with a `seal_mode` of `passphrase` means a root key file overrode the passphrase. Before setup the public endpoint also shows what configuration has already decided. Every wrong passphrase is in the audit log as `sys.unseal.failed`, with a count of consecutive failures from that address, which is the simplest thing to alert on if someone may be guessing. `sekret sys status` exits 0 when unsealed, 2 when sealed and 3 when not set up, which suits shell checks. In Home Assistant, a REST sensor and an automation send a notification when the server is sealed:

```yaml
sensor:
  - platform: rest
    name: sekret state
    resource: https://sekret.example.com/api/v1/sys/status
    value_template: "{{ value_json.state }}"
    scan_interval: 60

automation:
  - alias: sekret is sealed
    trigger:
      - platform: state
        entity_id: sensor.sekret_state
        to: sealed
    action:
      - service: notify.whatsapp
        data:
          message: "sekret restarted and is sealed; unlock it at https://sekret.example.com/unlock"
```

## As a container

The image is `ghcr.io/sam-ruff/sekret`, tagged with each release version and `latest`. It is built `FROM scratch`: the static binary, CA certificates and nothing else, running as user 65532. The database lives in `/data`.

```sh
docker run -d --name sekret -p 8080:8080 \
  -v sekret-data:/data \
  -e SEKRET_PUBLIC_URL=https://sekret.example.com \
  ghcr.io/sam-ruff/sekret:latest
docker logs sekret 2>&1 | grep 'setup code'
```

For key-file mode, mount the key and add `-e SEKRET_ROOT_KEY_FILE=/run/secrets/root.key`; the file must be readable by user 65532. With the `remember` unlock policy, set `SEKRET_REMEMBER_FILE`, ideally on a different volume from `/data`, and consider a remember secret mounted from elsewhere (`SEKRET_REMEMBER_SECRET_FILE`) so the data volume alone cannot unlock the server. The image has no `/tmp`; backups are staged in a private directory under `/data` instead. The image's command is `sekret server`, so any other subcommand works too: `docker run --rm ghcr.io/sam-ruff/sekret:latest --version`.

## Postgres

```sh
SEKRET_DATABASE_URL='postgres://sekret:password@db.example.com/sekret?sslmode=require'
```

The URL holds the database password, so prefer `SEKRET_DATABASE_URL_FILE` (or `database.url_file`) naming a file only the sekret user can read, such as a systemd credential or a mounted secret. The server removes `SEKRET_DATABASE_URL` from its own environment once read, but whatever started it still holds it.

Connect directly or through PgBouncer in session pooling mode. Transaction and statement pooling are not supported, because the server's lock on the database is tied to one session.

Set `SEKRET_EPOCH_FILE` (or `seal.epoch_file`) to a file on the server's host, such as `/var/lib/sekret/seal.epoch`, in a directory the sekret user can write and the database's users cannot reach. It holds the seal epoch mark that stops someone who can only write to the database from rolling back the seal configuration or swapping in a root key of their own. Without a remember file or root key file, the server and the `admin` commands refuse to start until it is set, and they must all be given the same file. See [Unlocking](unlocking.md#the-policy-cannot-be-changed-behind-your-back).

Create an empty database owned by the sekret user; the server creates its tables on first start. Values are encrypted before they reach the database, so a Postgres backup holds ciphertext, but key names, folder paths, comments, tags and the audit log are stored in plain text.

## Backups

With SQLite, `sekret sys backup` downloads an encrypted backup of the whole database from the running server:

```sh
sekret sys backup -o sekret-$(date +%F).skb
```

The same file is available from "Download encrypted backup" on the Server page under Organisation in the web interface. The API endpoint is `POST /api/v1/sys/backup`, one at a time.

The `.skb` file is encrypted under the root key and carries the passphrase-wrapped root key in its header, so it can only be restored with the passphrase (or the key file, in key-file mode). Anyone holding it can still try passphrases against that header offline, so it is only as safe as the passphrase is strong; see [what a backup header reveals](security.md#what-the-database-and-backups-contain). Keep it in private storage, such as a private bucket, rather than anywhere public. A raw copy of the SQLite file is not safe to share: its values are encrypted, but key names, users, identities and the audit log are plain text. Keep raw copies on the host, or encrypt them, for example with age.

Changing the passphrase does not reach backups already taken. They open with the old passphrase and hold the secrets as they were. After a passphrase leak, change the passphrase, rotate the secrets themselves, and delete the old backups and any older versions in versioned storage.

Postgres servers answer 501 to a backup request. Use `pg_dump`; the values in it are already encrypted, but the same metadata caveat applies. In key-file mode, back up the key file separately.

### Pulling backups from another host

Downloading a backup needs the `backups` read permission. Organisation admins have it, and the built-in `backup-reader` role holds that and nothing else, so a backup host can pull nightly without an admin token anywhere.

Create the identity once, in the web interface (a machine identity with universal auth, its trusted CIDRs set to the backup host's address, and the organisation role `backup-reader`), or with an admin token against the API:

```sh
api() { curl -fsS -H "Authorization: Bearer $SEKRET_TOKEN" -H 'content-type: application/json' "$@"; }
id=$(api -d '{"name": "backup-host", "trusted_cidrs": ["192.0.2.10/32"]}' \
  "$SEKRET_URL/api/v1/identities" | jq -r .id)
api -X PUT -d '{"kind": "universal"}' "$SEKRET_URL/api/v1/identities/$id/auth/universal"
api -d '{}' "$SEKRET_URL/api/v1/identities/$id/client-secrets" | jq -r .client_secret > client-secret
api -d "{\"principal_kind\": \"identity\", \"principal_id\": \"$id\", \"role\": \"backup-reader\"}" \
  "$SEKRET_URL/api/v1/org/bindings"
echo "$id"
```

Copy `client-secret` to the backup host with mode 0600. Then, on the backup host, from cron:

```sh
#!/bin/sh
set -eu
export SEKRET_URL=https://sekret.example.com
export SEKRET_TOKEN=$(sekret login --client-id "$SEKRET_BACKUP_ID" \
  --client-secret-file /etc/sekret-backup/client-secret --print-token)
sekret sys backup -o "/backups/sekret-$(date +%F).skb"
```

### Restoring

Restore offline, on any host, into a new SQLite file:

```sh
sekret admin restore --backup sekret-2026-10-30.skb --database-url 'sqlite:///var/lib/sekret/sekret.db?mode=rwc'
```

It asks for the passphrase (or reads `--passphrase-file`; `--root-key-file` for key-file backups), checks it matches the backup, and only once the backup has decrypted prints when it was taken and its root key fingerprint, with any control characters removed. It refuses to overwrite an existing file, or to write where a `-wal`, `-shm` or `-journal` file from another database is waiting beside the target. It writes into a new private directory in the same folder, checks the copy is intact and belongs to the backup's root key, makes sure the file it checked is still the one it wrote, and only then links it into place; anything an interrupted restore left behind is removed first. The restore is recorded in the restored database's audit log as `admin.restore`. Start the server on the restored database and unlock it with the same passphrase. It also starts the restored database's own epoch mark at the backup's root key. If you put the restored file in place of a database that had a newer seal configuration, run `sekret admin reset-epoch` on it before starting the server, or the server takes the older configuration for a rollback and falls back to the manual unlock policy; `reset-epoch` resets it to `manual` too, so set the unlock policy again afterwards. If the backup was taken before a passphrase change, a root key rotation or a mode switch, the marks name the later key and the server refuses the restored one; run `sekret admin reset-epoch --adopt-root-key` once you are sure that is the backup you meant. Tokens, users and identities come back as they were. A remembered unlock does not, so the first start needs the passphrase.

## Health checks

`GET /api/v1/health` returns 200 while the process is up, sealed or not. `GET /api/v1/ready` returns 200 only when the server is unlocked and can read its database, and 503 otherwise. Neither needs authentication. Point liveness checks at `health`: a sealed server is alive and should not be restarted, because a restart seals it again. In Kubernetes, a readiness probe on `ready` takes a sealed pod out of its Service, which also hides the unlock page, so in passphrase mode either use `health` for readiness or unlock through a port-forward.

## Kubernetes

Run the server wherever suits you; the [Kubernetes integration](integrations/kubernetes.md) is about the operator that syncs secrets into a cluster, which only needs to reach the server over HTTPS.
