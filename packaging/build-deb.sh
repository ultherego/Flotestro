#!/bin/sh
# Buduje pakiet .deb z gotowych binarek.
#
#   build-deb.sh agent         <stage> <wersja> <arch> <out>
#   build-deb.sh control-plane <stage> <wersja> <arch> <out>
#
# Skrypt nie kompiluje kodu: pakiet ma powstac dokladnie z tych artefaktow,
# ktore przeszly testy. Wymaga dpkg-deb, czyli hosta z rodziny Debiana.
set -eu

SKLADNIK="${1:?podaj skladnik: agent albo control-plane}"
STAGE="${2:?podaj katalog z binarkami}"
VERSION="${3:-0.1.0}"
ARCH="${4:-amd64}"
OUT="${5:-.}"

root="$(mktemp -d)"
trap 'rm -rf "$root"' EXIT
here="$(cd "$(dirname "$0")" && pwd)"

install -d -m 0755 "$root/DEBIAN"
sed -e "s/__WERSJA__/$VERSION/" -e "s/__ARCH__/$ARCH/" \
    "$here/deb/$SKLADNIK.control" > "$root/DEBIAN/control"
install -m 0644 "$here/deb/$SKLADNIK.conffiles" "$root/DEBIAN/conffiles"
for skrypt in postinst prerm postrm; do
    install -m 0755 "$here/deb/$SKLADNIK.$skrypt" "$root/DEBIAN/$skrypt"
done

install -d -m 0755 "$root/usr/bin" "$root/lib/systemd/system" "$root/etc/flotestro"

case "$SKLADNIK" in
agent)
    install -m 0755 "$STAGE/flotestro-agent"        "$root/usr/bin/flotestro-agent"
    install -m 0755 "$STAGE/flotestro-agent-helper" "$root/usr/bin/flotestro-agent-helper"
    for unit in flotestro-agent.service flotestro-helper.service flotestro-helper.socket; do
        install -m 0644 "$here/systemd/$unit" "$root/lib/systemd/system/$unit"
    done
    install -m 0640 "$here/agent.env" "$root/etc/flotestro/agent.env"
    install -d -m 0700 "$root/var/lib/flotestro-agent"
    nazwa="flotestro-agent"
    ;;
control-plane)
    install -m 0755 "$STAGE/flotestro-control-plane" "$root/usr/bin/flotestro-control-plane"
    install -m 0644 "$here/systemd/flotestro-control-plane.service" \
        "$root/lib/systemd/system/flotestro-control-plane.service"
    install -m 0640 "$here/control-plane.env" "$root/etc/flotestro/control-plane.env"
    install -d -m 0700 "$root/var/lib/flotestro"
    # Panel webowy jest budowany osobno; pakiet niesie gotowe pliki.
    if [ -d "$STAGE/web" ]; then
        install -d -m 0755 "$root/usr/share/flotestro/web"
        cp -r "$STAGE/web/." "$root/usr/share/flotestro/web/"
        find "$root/usr/share/flotestro/web" -type d -exec chmod 0755 {} +
        find "$root/usr/share/flotestro/web" -type f -exec chmod 0644 {} +
    fi
    nazwa="flotestro-control-plane"
    ;;
*)
    echo "nieznany skladnik: $SKLADNIK" >&2
    exit 1
    ;;
esac

dpkg-deb --root-owner-group --build "$root" "$OUT/${nazwa}_${VERSION}_${ARCH}.deb" >/dev/null
echo "$OUT/${nazwa}_${VERSION}_${ARCH}.deb"
