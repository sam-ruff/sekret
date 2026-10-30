#!/bin/sh
# Installs the sekret binary from a GitHub release and checks it against the published SHA-256.
#
#   curl -fsSL https://raw.githubusercontent.com/sam-ruff/sekret/main/install.sh | sh
#
# SEKRET_VERSION      release tag to install, such as v1.2.0 (default: the latest release)
# SEKRET_INSTALL_DIR  directory for the binary (default: /usr/local/bin if writable, else ~/.local/bin)
set -eu

repo="sam-ruff/sekret"
asset="sekret-linux-amd64"

fail() {
	echo "sekret install: $*" >&2
	exit 1
}

case "$(uname -s)-$(uname -m)" in
Linux-x86_64 | Linux-amd64) ;;
*) fail "releases are built for x86-64 Linux only, not $(uname -s) $(uname -m); build from source instead" ;;
esac

if [ -n "${SEKRET_VERSION:-}" ]; then
	base="https://github.com/$repo/releases/download/$SEKRET_VERSION"
else
	base="https://github.com/$repo/releases/latest/download"
fi

download() {
	if command -v curl >/dev/null 2>&1; then
		curl -fsSL --proto '=https' --tlsv1.2 -o "$2" "$1"
	elif command -v wget >/dev/null 2>&1; then
		wget -q --https-only -O "$2" "$1"
	else
		fail "curl or wget is needed"
	fi
}

sha256() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$1" | cut -d ' ' -f 1
	elif command -v shasum >/dev/null 2>&1; then
		shasum -a 256 "$1" | cut -d ' ' -f 1
	else
		fail "sha256sum or shasum is needed to check the download"
	fi
}

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM

download "$base/$asset" "$tmp/$asset" || fail "could not download $base/$asset"
download "$base/$asset.sha256" "$tmp/$asset.sha256" || fail "could not download the checksum"
expected=$(cut -d ' ' -f 1 "$tmp/$asset.sha256")
actual=$(sha256 "$tmp/$asset")
[ -n "$expected" ] && [ "$expected" = "$actual" ] || fail "checksum mismatch: expected $expected, got $actual"

if [ -n "${SEKRET_INSTALL_DIR:-}" ]; then
	dir=$SEKRET_INSTALL_DIR
elif [ -w /usr/local/bin ]; then
	dir=/usr/local/bin
else
	dir="$HOME/.local/bin"
fi
mkdir -p "$dir"
install -m 0755 "$tmp/$asset" "$dir/sekret" 2>/dev/null || {
	cp "$tmp/$asset" "$dir/sekret" && chmod 0755 "$dir/sekret"
} || fail "could not write to $dir; set SEKRET_INSTALL_DIR"

echo "Installed $("$dir/sekret" --version) to $dir/sekret"
case ":$PATH:" in
*":$dir:"*) ;;
*) echo "Add $dir to your PATH to run it as 'sekret'." ;;
esac
