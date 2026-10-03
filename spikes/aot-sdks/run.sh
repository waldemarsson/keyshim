#!/usr/bin/env bash
# Publish each spike project with Native AOT and summarize trim/AOT warnings.
set -euo pipefail

cd "$(dirname "$0")"
readonly rid="${RID:-linux-x64}"
readonly out=out
mkdir -p "$out"

for project in Baseline Azure Aws Gcp Yaml Web; do
  log="$out/$project.log"
  if dotnet publish "$project" -c Release -r "$rid" -o "$out/$project" \
    -p:CppCompilerAndLinker="${LINKER:-clang}" >"$log" 2>&1; then
    status=published
  else
    status=failed
  fi
  warnings=$(rg -o 'warning (IL[0-9]{4})' -r '$1' "$log" | sort | uniq -c | tr '\n' ' ' || true)
  printf '%-9s %-10s %s\n' "$project" "$status" "${warnings:-no IL warnings}"
done
