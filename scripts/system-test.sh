#!/usr/bin/env bash
# Brings up Keycloak and Postgres, runs a real sekret server against them, then runs the
# system suites. Pick suites with SUITES="rust ansible playwright operator" (default: all).
set -euo pipefail

root=$(git rev-parse --show-toplevel)
cd "$root"
compose="docker compose -f deploy/system-test/docker-compose.yml"
suites=${SUITES:-"rust ansible playwright operator"}
work=$(mktemp -d)
server_pid=""

cleanup() {
  if [ -n "$server_pid" ]; then kill "$server_pid" 2>/dev/null || true; fi
  if [ "${KEEP_STACK:-0}" != 1 ]; then $compose down -v >/dev/null 2>&1 || true; fi
  rm -rf "$work"
}
trap cleanup EXIT

wait_for() {
  local url=$1
  for _ in $(seq 1 90); do
    if curl -sf "$url" >/dev/null; then return 0; fi
    sleep 2
  done
  echo "timed out waiting for $url" >&2
  return 1
}

$compose up -d
wait_for http://localhost:18081/realms/sekret-test/.well-known/openid-configuration
until $compose exec -T postgres pg_isready -U sekret >/dev/null 2>&1; do sleep 1; done
$compose exec -T postgres psql -q -U sekret -d sekret -c 'DROP SCHEMA public CASCADE; CREATE SCHEMA public;'

if [ "${SEKRET_SKIP_WEB:-0}" != 1 ]; then
  (cd web && npm ci --no-audit --no-fund && npm run build)
fi
# The static release binary is what ships, so that is what gets tested. SEKRET_BIN points at a
# prebuilt one; SEKRET_DEBUG_BUILD=1 trades fidelity for a faster debug build.
if [ -n "${SEKRET_BIN:-}" ]; then
  bin=$SEKRET_BIN
elif [ "${SEKRET_DEBUG_BUILD:-0}" = 1 ]; then
  cargo build -p sekret
  bin="$root/target/debug/sekret"
else
  CC_x86_64_unknown_linux_musl=musl-gcc \
    cargo build --release --locked --target x86_64-unknown-linux-musl -p sekret
  bin="$root/target/x86_64-unknown-linux-musl/release/sekret"
fi
export SEKRET_BIN=$bin

"$bin" admin generate-root-key > "$work/root.key"
printf 'sekret-test-client-secret' > "$work/oidc-secret"
db="postgres://sekret:sekret@127.0.0.1:15432/sekret"

SEKRET_LOG=warn "$bin" server \
  --listen 127.0.0.1:18080 \
  --public-url http://localhost:18080 \
  --database-url "$db" \
  --root-key-file "$work/root.key" \
  --oidc-issuer http://localhost:18081/realms/sekret-test \
  --oidc-client-secret-file "$work/oidc-secret" \
  --allow-insecure-http > "$work/server.log" 2>&1 &
server_pid=$!
wait_for http://localhost:18080/api/v1/health

export SEKRET_E2E_URL=http://localhost:18080
export SEKRET_E2E_KEYCLOAK=http://localhost:18081/realms/sekret-test
export SEKRET_E2E_ADMIN_TOKEN
SEKRET_E2E_ADMIN_TOKEN=$("$bin" admin bootstrap --database-url "$db" --root-key-file "$work/root.key")
export SEKRET_E2E_USER=alice SEKRET_E2E_PASSWORD=alice-password

status=0
for suite in $suites; do
  echo "== $suite"
  case $suite in
    rust) cargo test -p sekret --features system-tests --test system -- --test-threads=1 || status=1 ;;
    ansible)
      (cd integrations/ansible && SEKRET_TEST_URL=$SEKRET_E2E_URL SEKRET_TEST_TOKEN=$SEKRET_E2E_ADMIN_TOKEN \
        uv run pytest -m integration) || status=1 ;;
    playwright) (cd web && npm run e2e:live) || status=1 ;;
    operator) cargo test -p sekret-operator --features system-tests -- --test-threads=1 || status=1 ;;
    *) echo "unknown suite $suite" >&2; status=1 ;;
  esac
done

if [ $status -ne 0 ]; then
  echo "== server log"
  tail -n 100 "$work/server.log"
fi
exit $status
