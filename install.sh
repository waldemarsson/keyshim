#!/bin/sh
# Install keyshim from GitHub releases.
#
#   curl -fsSL https://raw.githubusercontent.com/waldemarsson/keyshim/main/install.sh | sh
#
# Environment:
#   KEYSHIM_VERSION      release tag to install, e.g. v0.2.0 (default: latest)
#   KEYSHIM_INSTALL_DIR  target directory (default: ~/.local/bin; no sudo needed)
#   KEYSHIM_VERIFY_ATTESTATION=1
#                         also verify the GitHub build provenance attestation
#                         with `gh attestation verify` (requires the gh CLI)
#   KEYSHIM_BASE_URL     download from another location; for mirrors and tests
#
# The archive is always checked against the release's SHA256SUMS.
set -eu

repo="waldemarsson/keyshim"
version="${KEYSHIM_VERSION:-latest}"
install_dir="${KEYSHIM_INSTALL_DIR:-$HOME/.local/bin}"

fail() {
  echo "keyshim install: $*" >&2
  exit 1
}

case "$(uname -s)" in
  Darwin) os=darwin ;;
  Linux) os=linux ;;
  *) fail "unsupported OS $(uname -s); keyshim supports macOS and Linux" ;;
esac
case "$(uname -m)" in
  x86_64 | amd64) arch=amd64 ;;
  arm64 | aarch64) arch=arm64 ;;
  *) fail "unsupported architecture $(uname -m)" ;;
esac
asset="keyshim_${os}_${arch}.tar.gz"

if [ -n "${KEYSHIM_BASE_URL:-}" ]; then
  base_url=$KEYSHIM_BASE_URL
  curl_proto=""
elif [ "$version" = latest ]; then
  base_url="https://github.com/$repo/releases/latest/download"
  curl_proto="--proto =https --tlsv1.2"
else
  base_url="https://github.com/$repo/releases/download/$version"
  curl_proto="--proto =https --tlsv1.2"
fi

download() {
  if command -v curl >/dev/null 2>&1; then
    # shellcheck disable=SC2086 # curl_proto is a list of flags
    curl -fsSL $curl_proto -o "$2" "$1" || fail "download failed: $1"
  elif command -v wget >/dev/null 2>&1; then
    wget -q --https-only -O "$2" "$1" || fail "download failed: $1"
  else
    fail "curl or wget is required"
  fi
}

sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -d ' ' -f 1
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | cut -d ' ' -f 1
  else
    fail "sha256sum or shasum is required to verify the download"
  fi
}

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM

echo "Downloading $asset ($version)"
download "$base_url/$asset" "$tmp/$asset"
download "$base_url/SHA256SUMS" "$tmp/SHA256SUMS"

expected=$(awk -v name="$asset" '$2 == name || $2 == "*" name { print $1 }' "$tmp/SHA256SUMS")
[ -n "$expected" ] || fail "$asset is not listed in SHA256SUMS"
actual=$(sha256 "$tmp/$asset")
[ "$expected" = "$actual" ] || fail "checksum mismatch for $asset (expected $expected, got $actual)"
echo "Checksum verified"

if [ "${KEYSHIM_VERIFY_ATTESTATION:-0}" = 1 ]; then
  command -v gh >/dev/null 2>&1 || fail "KEYSHIM_VERIFY_ATTESTATION=1 needs the gh CLI"
  gh attestation verify "$tmp/$asset" --repo "$repo" >/dev/null || fail "attestation verification failed for $asset"
  echo "Build provenance attestation verified"
fi

tar -xzf "$tmp/$asset" -C "$tmp" ./keyshim
mkdir -p "$install_dir"
# Install through a temporary name so a running binary is replaced atomically.
cp "$tmp/keyshim" "$install_dir/.keyshim.new"
chmod 0755 "$install_dir/.keyshim.new"
mv -f "$install_dir/.keyshim.new" "$install_dir/keyshim"

echo "Installed $("$install_dir/keyshim" version) to $install_dir/keyshim"
case ":$PATH:" in
  *":$install_dir:"*) ;;
  *) echo "Add $install_dir to your PATH to run keyshim directly." ;;
esac
echo "Next: run \`keyshim init\` to set up the configuration, master key and CA."
