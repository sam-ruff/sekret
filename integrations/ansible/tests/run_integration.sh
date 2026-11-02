#!/usr/bin/env bash
# Starts a throwaway sekret server and runs the integration tests against it.
# Extra arguments are passed to pytest.
set -euo pipefail

collection_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
repo_root=$(cd "$collection_dir/../.." && pwd)

workdir=$(mktemp -d)
server_pid=""
cleanup() {
  if [ -n "$server_pid" ]; then
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi
  rm -rf "$workdir"
}
trap cleanup EXIT

sekret() {
  (cd "$repo_root" && cargo run --quiet -p sekret -- "$@")
}

port=$(python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')
url="http://127.0.0.1:$port"
database_url="sqlite://$workdir/sekret.db?mode=rwc"
key_file="$workdir/root.key"

echo "Building sekret" >&2
(cd "$repo_root" && cargo build --quiet -p sekret)

sekret admin generate-root-key >"$key_file"
chmod 600 "$key_file"

echo "Starting sekret on $url" >&2
sekret server \
  --database-url "$database_url" \
  --root-key-file "$key_file" \
  --listen "127.0.0.1:$port" \
  --public-url "$url" \
  --allow-insecure-http \
  >"$workdir/server.log" 2>&1 &
server_pid=$!

for _ in $(seq 1 120); do
  if curl -fsS "$url/api/v1/auth/config" >/dev/null 2>&1; then
    break
  fi
  if ! kill -0 "$server_pid" 2>/dev/null; then
    echo "sekret server exited early:" >&2
    cat "$workdir/server.log" >&2
    exit 1
  fi
  sleep 0.5
done
curl -fsS "$url/api/v1/auth/config" >/dev/null

token=$(sekret admin bootstrap --database-url "$database_url" --root-key-file "$key_file")

target_dir=$(cd "$repo_root" && cargo metadata --format-version 1 --no-deps |
  python3 -c 'import json, sys; print(json.load(sys.stdin)["target_directory"])')

cd "$collection_dir"
SEKRET_TEST_URL="$url" SEKRET_TEST_TOKEN="$token" SEKRET_TEST_CLI="$target_dir/debug/sekret" \
  uv run pytest -m integration -v "$@"
