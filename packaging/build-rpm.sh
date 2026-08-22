#!/bin/sh
# Buduje pakiet .rpm agenta z gotowych binarek. Wymaga rpmbuild, czyli hosta
# z rodziny Fedory/RHEL.
set -eu

STAGE="${1:?podaj katalog z binarkami}"
VERSION="${2:-0.1.0}"
OUT="${3:-.}"

here="$(cd "$(dirname "$0")" && pwd)"
topdir="$(mktemp -d)"
trap 'rm -rf "$topdir"' EXIT

# Konfiguracja agenta jest czescia pakietu, a nie artefaktem budowania.
cp "$here/agent.env" "$STAGE/agent.env"

rpmbuild -bb "$here/rpm/flotestro-agent.spec" \
    --define "_topdir $topdir" \
    --define "_flotestro_version $VERSION" \
    --define "_flotestro_stage $STAGE" \
    --define "_flotestro_units $here/systemd" \
    > "$topdir/rpmbuild.log" 2>&1 || { cat "$topdir/rpmbuild.log" >&2; exit 1; }

pakiet="$(find "$topdir/RPMS" -name '*.rpm' | head -1)"
[ -n "$pakiet" ] || { echo "rpmbuild nie wyprodukowal pakietu" >&2; exit 1; }
cp "$pakiet" "$OUT/"
echo "$OUT/$(basename "$pakiet")"
