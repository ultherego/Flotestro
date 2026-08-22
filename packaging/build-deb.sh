#!/bin/sh
# Buduje pakiet .deb agenta z gotowych binarek.
#
# Skrypt nie kompiluje kodu: pakiet ma powstac dokladnie z tych artefaktow,
# ktore przeszly testy. Wymaga dpkg-deb, czyli hosta z rodziny Debiana.
set -eu

STAGE="${1:?podaj katalog z binarkami}"
VERSION="${2:-0.1.0}"
ARCH="${3:-amd64}"
OUT="${4:-.}"

root="$(mktemp -d)"
trap 'rm -rf "$root"' EXIT
here="$(cd "$(dirname "$0")" && pwd)"

install -d -m 0755 "$root/DEBIAN"
sed -e "s/__WERSJA__/$VERSION/" -e "s/__ARCH__/$ARCH/" "$here/deb/control" > "$root/DEBIAN/control"
install -m 0644 "$here/deb/conffiles" "$root/DEBIAN/conffiles"
for skrypt in postinst prerm postrm; do
    install -m 0755 "$here/deb/$skrypt" "$root/DEBIAN/$skrypt"
done

install -d -m 0755 "$root/usr/bin"
install -m 0755 "$STAGE/flotestro-agent"        "$root/usr/bin/flotestro-agent"
install -m 0755 "$STAGE/flotestro-agent-helper" "$root/usr/bin/flotestro-agent-helper"

install -d -m 0755 "$root/lib/systemd/system"
for unit in flotestro-agent.service flotestro-helper.service flotestro-helper.socket; do
    install -m 0644 "$here/systemd/$unit" "$root/lib/systemd/system/$unit"
done

install -d -m 0755 "$root/etc/flotestro"
install -m 0640 "$here/agent.env" "$root/etc/flotestro/agent.env"
install -d -m 0700 "$root/var/lib/flotestro-agent"

dpkg-deb --root-owner-group --build "$root" "$OUT/flotestro-agent_${VERSION}_${ARCH}.deb" >/dev/null
echo "$OUT/flotestro-agent_${VERSION}_${ARCH}.deb"
