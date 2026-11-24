#!/bin/sh
# Builds a patched copy of the Titus module and points a go.work at it, so go.mod keeps
# requiring plain upstream github.com/praetorian-inc/titus. Run before `go build` / `go test`
# (the Dockerfile does). Output (third_party/, go.work, go.work.sum) is gitignored.
#
# patches/*.patch apply to the Titus version in go.mod. When bumping Titus, re-apply them on the
# new version (or delete them once the fix is upstream).
set -eu
cd "$(dirname "$0")/.."

rm -f go.work go.work.sum
rm -rf third_party/titus
src=$(GOWORK=off GOFLAGS=-mod=mod go mod download -json github.com/praetorian-inc/titus | sed -n 's/^[[:space:]]*"Dir": "\(.*\)",$/\1/p')
[ -n "$src" ] || { echo "apply.sh: could not locate the titus module" >&2; exit 1; }

mkdir -p third_party
cp -R "$src" third_party/titus
chmod -R u+w third_party/titus
for p in patches/*.patch; do
  patch -d third_party/titus -p1 --forward --quiet < "$p"
  echo "applied $(basename "$p")"
done
go work init . ./third_party/titus
