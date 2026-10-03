#!/usr/bin/env bash
# Build release archives and SHA256SUMS.
#
# Usage: scripts/build-release.sh <version> <output-dir>
#
# Archives are named fullmakt_<os>_<arch>.tar.gz without the version, so
# install.sh can download the latest release by a stable name.
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 <version> <output-dir>" >&2
  exit 2
fi
readonly version=$1
readonly out=$2
# Windows is not supported yet: file permission checks rely on Unix modes.
readonly targets=(darwin/arm64 darwin/amd64 linux/amd64 linux/arm64)

root=$(cd "$(dirname "$0")/.." && pwd)
readonly root
# Timestamps from the last commit keep archives reproducible.
epoch=$(git -C "$root" log -1 --format=%ct 2>/dev/null || date +%s)
readonly epoch

rm -rf "$out"
mkdir -p "$out"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

for target in "${targets[@]}"; do
  os=${target%/*}
  arch=${target#*/}
  name="fullmakt_${os}_${arch}"
  mkdir -p "$work/$name"
  (
    cd "$root"
    CGO_ENABLED=0 GOOS=$os GOARCH=$arch go build \
      -trimpath \
      -ldflags "-s -w -X main.version=$version" \
      -o "$work/$name/fullmakt" \
      ./cmd/fullmakt
  )
  cp "$root/README.md" "$root/config.example.yaml" "$work/$name/"
  if [[ -f "$root/LICENSE" ]]; then
    cp "$root/LICENSE" "$work/$name/"
  fi
  tar --sort=name --owner=0 --group=0 --numeric-owner --mtime="@$epoch" \
    -C "$work/$name" -cf - . | gzip -n > "$out/$name.tar.gz"
  echo "built $out/$name.tar.gz"
done

(cd "$out" && sha256sum -- *.tar.gz > SHA256SUMS)
echo "wrote $out/SHA256SUMS"
