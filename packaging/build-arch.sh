#!/usr/bin/env bash
# Buduje pakiet pacman z gotowych binarek. Wymaga makepkg, czyli hosta
# z rodziny Archa.
#
#   build-arch.sh <stage> <wersja> <arch> <out>
#
# Arch dostaje pakiet, a nie tarball: instalacja ma przechodzic ta sama
# droga co na pozostalych rodzinach - z rejestrem plikow, skryptletami
# i mozliwoscia deinstalacji.
set -euo pipefail

STAGE="${1:?podaj katalog z binarkami}"
WERSJA="${2:-0.1.0}"
ARCH="${3:-x86_64}"
OUT="${4:-.}"

here="$(cd "$(dirname "$0")" && pwd)"
build="$(mktemp -d)"
trap 'rm -rf "$build"' EXIT

# makepkg odmawia pracy jako root; zrodla ida do katalogu, ktory ma prawa
# uzytkownika budujacego.
cp "$STAGE/flotestro-agent" "$STAGE/flotestro-agentctl" \
   "$STAGE/flotestro-agent-helper" "$build/"
cp "$here/systemd/flotestro-agent.service" "$here/systemd/flotestro-enroll.service" \
   "$here/systemd/flotestro-helper.service" "$here/systemd/flotestro-helper.socket" "$build/"
cp "$here/arch/flotestro-agent.sysusers" "$here/arch/flotestro-agent.tmpfiles" \
   "$here/arch/flotestro-agent.install" "$build/"
cp "$here/agent.yaml" "$build/agent.yaml"

# Sumy sa wyliczane, a nie pomijane: "SKIP" oznaczaloby pakiet, ktorego
# zawartosci nikt nie sprawdzil, a to jest dokladnie ta wlasciwosc, dla
# ktorej pakiet w ogole robimy.
sumy=""
for plik in flotestro-agent flotestro-agentctl flotestro-agent-helper \
            flotestro-agent.service flotestro-enroll.service \
            flotestro-helper.service flotestro-helper.socket \
            flotestro-agent.sysusers flotestro-agent.tmpfiles agent.yaml; do
    sumy="$sumy'$(sha256sum "$build/$plik" | cut -d' ' -f1)' "
done

sed -e "s/__WERSJA__/$WERSJA/" -e "s/__SUMY__/${sumy% }/" \
    "$here/arch/PKGBUILD" > "$build/PKGBUILD"

( cd "$build" && CARCH="$ARCH" makepkg --nodeps --noconfirm --ignorearch >makepkg.log 2>&1 ) ||
    { cat "$build/makepkg.log" >&2; exit 1; }

pakiet="$(find "$build" -maxdepth 1 -name 'flotestro-agent-*.pkg.tar.*' | head -1)"
[ -n "$pakiet" ] || { echo "makepkg nie wyprodukowal pakietu" >&2; exit 1; }
cp "$pakiet" "$OUT/"
echo "$OUT/$(basename "$pakiet")"
