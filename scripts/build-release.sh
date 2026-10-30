#!/usr/bin/env bash
# Builds the static release binary with the web interface embedded, plus its checksum.
set -euo pipefail

root=$(git rev-parse --show-toplevel)
cd "$root"
mkdir -p dist

(cd web && npm ci --no-audit --no-fund && npm run build)
if [ ! -f web/dist/index.html ]; then
  echo "web/dist/index.html is missing; the binary would ship without its interface" >&2
  exit 1
fi
CC_x86_64_unknown_linux_musl=musl-gcc \
  cargo build --release --locked --target x86_64-unknown-linux-musl -p sekret

binary=target/x86_64-unknown-linux-musl/release/sekret
if ldd "$binary" 2>&1 | grep -q '=>'; then
  echo "release binary is dynamically linked" >&2
  exit 1
fi
if ! "$binary" admin web-check; then
  echo "release binary does not embed the web interface" >&2
  exit 1
fi
cp "$binary" dist/sekret-linux-amd64
(cd dist && sha256sum sekret-linux-amd64 > sekret-linux-amd64.sha256)
