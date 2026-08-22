#!/bin/sh
# Buduje pakiet .rpm z gotowych binarek. Wymaga rpmbuild, czyli hosta
# z rodziny Fedory/RHEL.
#
#   build-rpm.sh agent         <stage> <wersja> <out>
#   build-rpm.sh control-plane <stage> <wersja> <out>
set -eu

SKLADNIK="${1:?podaj skladnik: agent albo control-plane}"
STAGE="${2:?podaj katalog z binarkami}"
VERSION="${3:-0.1.0}"
OUT="${4:-.}"

here="$(cd "$(dirname "$0")" && pwd)"
topdir="$(mktemp -d)"
trap 'rm -rf "$topdir"' EXIT

case "$SKLADNIK" in
agent)         cp "$here/agent.env" "$STAGE/agent.env" ;;
control-plane) cp "$here/control-plane.env" "$STAGE/control-plane.env" ;;
*) echo "nieznany skladnik: $SKLADNIK" >&2; exit 1 ;;
esac

rpmbuild -bb "$here/rpm/flotestro-$SKLADNIK.spec" \
    --define "_topdir $topdir" \
    --define "_flotestro_version $VERSION" \
    --define "_flotestro_stage $STAGE" \
    --define "_flotestro_units $here/systemd" \
    > "$topdir/rpmbuild.log" 2>&1 || { cat "$topdir/rpmbuild.log" >&2; exit 1; }

pakiet="$(find "$topdir/RPMS" -name "flotestro-$SKLADNIK-*.rpm" | head -1)"
[ -n "$pakiet" ] || { echo "rpmbuild nie wyprodukowal pakietu" >&2; exit 1; }
cp "$pakiet" "$OUT/"
echo "$OUT/$(basename "$pakiet")"
