# Deployment

A production install is one binary, a root key file, a database and a reverse proxy for TLS. SQLite is enough for a team of a few dozen people; use Postgres if you already run one or want point-in-time recovery. Both are supported equally, and the test suite runs against each.

Upgrades are a binary swap. The server applies database migrations on start, so stop it, replace the binary or image, and start it again. There is no downgrade path once a newer version has migrated the database, so back up first.

## As a systemd service

```sh
curl -fsSL https://raw.githubusercontent.com/sam-ruff/sekret/main/install.sh | sh
sudo useradd --system --home /var/lib/sekret --create-home sekret
sudo install -d -m 0700 -o sekret /etc/sekret
sudo -u sekret sh -c 'sekret admin generate-root-key > /etc/sekret/root.key && chmod 600 /etc/sekret/root.key'
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
Environment=SEKRET_ROOT_KEY_FILE=/etc/sekret/root.key
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
CapabilityBoundingSet=
MemoryDenyWriteExecute=true

[Install]
WantedBy=multi-user.target
```

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now sekret
curl -fsS http://127.0.0.1:8080/api/v1/ready
```

Put Caddy, nginx or Traefik in front for TLS and point it at `127.0.0.1:8080`.

## As a container

The image is `ghcr.io/sam-ruff/sekret`, tagged with each release version and `latest`. It is built `FROM scratch`: the static binary, CA certificates and nothing else, running as user 65532. The database lives in `/data`.

```sh
docker run -d --name sekret -p 8080:8080 \
  -v sekret-data:/data \
  -v /etc/sekret/root.key:/run/secrets/root.key:ro \
  -e SEKRET_PUBLIC_URL=https://sekret.example.com \
  -e SEKRET_ROOT_KEY_FILE=/run/secrets/root.key \
  ghcr.io/sam-ruff/sekret:latest
```

The root key file must be readable by user 65532. The image's command is `sekret server`, so any other subcommand works too: `docker run --rm ghcr.io/sam-ruff/sekret:latest --version`.

## Postgres

```sh
SEKRET_DATABASE_URL='postgres://sekret:password@db.example.com/sekret?sslmode=require'
```

Create an empty database owned by the sekret user; the server creates its tables on first start. Values are encrypted before they reach the database, so a Postgres backup holds ciphertext, but key names, folder paths, comments, tags and the audit log are stored in plain text.

## Backups

Back up the database and the root key separately. The root key never changes unless you rotate it, so one offline copy is enough.

For SQLite, copy the file while the server runs with `sqlite3 /var/lib/sekret/sekret.db ".backup /backups/sekret.db"`, which takes a consistent copy. For Postgres, use `pg_dump` or your usual tooling.

To restore, stop the server, put the database back, and start it with the same root key. A mismatched key is refused at start-up.

## Health checks

`GET /api/v1/health` returns 200 while the process is up. `GET /api/v1/ready` also reads from the database and returns 200 only when that works. Neither needs authentication.

## Kubernetes

Run the server wherever suits you; the [Kubernetes integration](integrations/kubernetes.md) is about the operator that syncs secrets into a cluster, which only needs to reach the server over HTTPS.
