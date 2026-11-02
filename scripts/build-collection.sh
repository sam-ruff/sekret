#!/usr/bin/env bash
# Builds the sekret.secrets collection with the release's version and writes
# sekret-secrets-VERSION.tar.gz and its .sha256 into OUT_DIR.
# Usage: scripts/build-collection.sh VERSION OUT_DIR
set -euo pipefail

version=${1:?usage: build-collection.sh VERSION OUT_DIR}
out_dir=${2:?usage: build-collection.sh VERSION OUT_DIR}
if ! [[ $version =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "not a release version: $version" >&2
    exit 2
fi

root=$(cd "$(dirname "$0")/.." && pwd)
src="$root/integrations/ansible"
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT

cp -r "$src/galaxy.yml" "$src/README.md" "$src/meta" "$src/plugins" "$work/"
# galaxy.yml keeps a placeholder version; the release stamps its own on the copy.
sed -i "s/^version: .*/version: $version/" "$work/galaxy.yml"
grep -qx "version: $version" "$work/galaxy.yml"

mkdir -p "$out_dir"
out_dir=$(cd "$out_dir" && pwd)
(cd "$src" && uv run --frozen ansible-galaxy collection build "$work" --output-path "$out_dir" --force)
cd "$out_dir"
sha256sum "sekret-secrets-$version.tar.gz" > "sekret-secrets-$version.tar.gz.sha256"
