#!/usr/bin/env bash
# Buduje pakiet pacman z gotowych binarek. Wymaga makepkg, czyli hosta
# z rodziny Archa.
#
#   build-arch.sh [agent|relay] <stage> <wersja> <arch> <out>
#
# Skladnik jest pierwszym argumentem; bez niego budowany jest agent, bo tak
# to polecenie bylo wolane, zanim relay dostal wlasny pakiet.
#
# Arch dostaje pakiet, a nie tarball: instalacja ma przechodzic ta sama
# droga co na pozostalych rodzinach - z rejestrem plikow, skryptletami
# i mozliwoscia deinstalacji.
set -euo pipefail

case "${1:-}" in
agent|relay) SKLADNIK="$1"; shift ;;
*)           SKLADNIK=agent ;;
esac
STAGE="${1:?podaj katalog z binarkami}"
WERSJA="${2:-0.1.0}"
ARCH="${3:-x86_64}"
OUT="${4:-.}"

here="$(cd "$(dirname "$0")" && pwd)"
build="$(mktemp -d)"
trap 'rm -rf "$build"' EXIT

# makepkg odmawia pracy jako root; zrodla ida do katalogu, ktory ma prawa
# uzytkownika budujacego.
if [ "$SKLADNIK" = relay ]; then
    cp "$STAGE/flotestro-relay" "$build/"
    cp "$here/systemd/flotestro-relay.service" "$build/"
    cp "$here/arch/flotestro-relay.sysusers" "$here/arch/flotestro-relay.tmpfiles" \
       "$here/arch/flotestro-relay.install" "$build/"
    cp "$here/relay.yaml" "$build/relay.yaml"
    PLIKI="flotestro-relay flotestro-relay.service flotestro-relay.sysusers"
    PLIKI="$PLIKI flotestro-relay.tmpfiles relay.yaml"
    SZABLON="$here/arch/relay-PKGBUILD"
else
    cp "$STAGE/flotestro-agent" "$STAGE/flotestro-agentctl" \
       "$STAGE/flotestro-agent-helper" "$build/"
    cp "$here/systemd/flotestro-agent.service" "$here/systemd/flotestro-enroll.service" \
       "$here/systemd/flotestro-helper.service" "$here/systemd/flotestro-helper.socket" "$build/"
    cp "$here/arch/flotestro-agent.sysusers" "$here/arch/flotestro-agent.tmpfiles" \
       "$here/arch/flotestro-agent.install" "$build/"
    cp "$here/agent.yaml" "$build/agent.yaml"
    PLIKI="flotestro-agent flotestro-agentctl flotestro-agent-helper"
    PLIKI="$PLIKI flotestro-agent.service flotestro-enroll.service"
    PLIKI="$PLIKI flotestro-helper.service flotestro-helper.socket"
    PLIKI="$PLIKI flotestro-agent.sysusers flotestro-agent.tmpfiles agent.yaml"
    SZABLON="$here/arch/PKGBUILD"
fi

# Sumy sa wyliczane, a nie pomijane: "SKIP" oznaczaloby pakiet, ktorego
# zawartosci nikt nie sprawdzil, a to jest dokladnie ta wlasciwosc, dla
# ktorej pakiet w ogole robimy.
sumy=""
for plik in $PLIKI; do
    sumy="$sumy'$(sha256sum "$build/$plik" | cut -d' ' -f1)' "
done

sed -e "s/__WERSJA__/$WERSJA/" -e "s/__SUMY__/${sumy% }/" \
    "$SZABLON" > "$build/PKGBUILD"

( cd "$build" && CARCH="$ARCH" makepkg --nodeps --noconfirm --ignorearch >makepkg.log 2>&1 ) ||
    { cat "$build/makepkg.log" >&2; exit 1; }

# Pakiet debug ma nazwe tak podobna, ze wchodzi w ten sam wzorzec. Wydanie
# z pusta binarka wygladaloby poprawnie az do instalacji.
pakiet="$(find "$build" -maxdepth 1 -name "flotestro-$SKLADNIK-*.pkg.tar.*" \
    ! -name "flotestro-$SKLADNIK-debug-*" | head -1)"
[ -n "$pakiet" ] || { echo "makepkg nie wyprodukowal pakietu" >&2; exit 1; }
cp "$pakiet" "$OUT/"
echo "$OUT/$(basename "$pakiet")"
