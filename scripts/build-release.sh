#!/usr/bin/env bash
# Build release archives and SHA256SUMS.
#
# Usage: scripts/build-release.sh <version> <output-dir>
#
# Archives are named keyshim_<os>_<arch>.tar.gz (.zip for Windows) without
# the version, so install.sh/install.ps1 can download the latest release by
# a stable name.
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 <version> <output-dir>" >&2
  exit 2
fi
readonly version=$1
readonly out=$2
readonly targets=(darwin/arm64 darwin/amd64 linux/amd64 linux/arm64 windows/amd64 windows/arm64)

root=$(cd "$(dirname "$0")/.." && pwd)
readonly root
# Timestamps from the last commit keep archives reproducible.
epoch=$(git -C "$root" log -1 --format=%ct 2>/dev/null || date +%s)
readonly epoch

rm -rf "$out"
mkdir -p "$out"
# zip runs from inside the staging directory, so it needs an absolute path.
out_abs=$(cd "$out" && pwd)
readonly out_abs
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

for target in "${targets[@]}"; do
  os=${target%/*}
  arch=${target#*/}
  name="keyshim_${os}_${arch}"
  bin=keyshim
  [[ $os == windows ]] && bin=keyshim.exe
  mkdir -p "$work/$name"
  (
    cd "$root"
    CGO_ENABLED=0 GOOS=$os GOARCH=$arch go build \
      -trimpath \
      -ldflags "-s -w -X main.version=$version" \
      -o "$work/$name/$bin" \
      ./cmd/keyshim
  )
  cp "$root/README.md" "$root/config.example.yaml" "$work/$name/"
  if [[ -f "$root/LICENSE" ]]; then
    cp "$root/LICENSE" "$work/$name/"
  fi
  # Fixed permissions and mtimes keep the archive reproducible regardless of
  # the build environment's umask or wall-clock time.
  chmod 755 "$work/$name/$bin"
  chmod 644 "$work/$name"/*.md "$work/$name"/*.yaml
  [[ -f "$work/$name/LICENSE" ]] && chmod 644 "$work/$name/LICENSE"
  find "$work/$name" -exec touch -d "@$epoch" {} +

  if [[ $os == windows ]]; then
    # zip has no --sort/--mtime/--owner equivalent. Fixed mtimes and
    # permissions above, -X, UTC (zip stores local-time DOS timestamps) and
    # C collation for the glob order keep it reproducible.
    (
      cd "$work/$name"
      export TZ=UTC LC_ALL=C
      zip -X -q "$out_abs/$name.zip" -- *
    )
    echo "built $out/$name.zip"
  else
    tar --sort=name --owner=0 --group=0 --numeric-owner --mtime="@$epoch" \
      -C "$work/$name" -cf - . | gzip -n > "$out/$name.tar.gz"
    echo "built $out/$name.tar.gz"
  fi
done

(cd "$out" && sha256sum -- *.tar.gz *.zip > SHA256SUMS)
echo "wrote $out/SHA256SUMS"
