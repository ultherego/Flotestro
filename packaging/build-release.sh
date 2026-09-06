#!/usr/bin/env bash
# Buduje wydanie: binarki dla wskazanych architektur, pakiety, sumy kontrolne
# i opis pochodzenia.
#
#   build-release.sh binarki  <wersja> <katalog> [arch ...]   # wymaga Go
#
# Pakiet .deb powstaje dla dowolnej architektury na dowolnej maszynie: dpkg-deb
# tylko pakuje gotowe pliki. rpmbuild sprawdza zgodnosc z maszyna budujaca
# i dla obcej architektury odmawia, wiec .rpm dla arm64 wymaga maszyny arm64.
#   build-release.sh pakiety  <wersja> <katalog> [arch ...]   # wymaga dpkg-deb/rpmbuild
#   build-release.sh wszystko <wersja> <katalog> [arch ...]
#
# Kroki sa rozdzielone, bo rozdzielone sa maszyny: toolchain Go stoi gdzie
# indziej niz narzedzia pakietowania danej dystrybucji, a pakiet ma powstac
# natywnie - tylko wtedy sprawdzamy to, co dostanie klient.
#
# Skrypt nie podpisuje niczego. Podpis jest osobnym krokiem i osobnym
# kluczem: maszyna budujaca nie musi go miec i lepiej, zeby nie miala.
set -euo pipefail

TRYB="${1:?podaj tryb: binarki, pakiety albo wszystko}"
WERSJA="${2:?podaj wersje wydania}"
WYNIK="${3:?podaj katalog wynikowy}"
shift 3
ARCHITEKTURY=("$@")
[ ${#ARCHITEKTURY[@]} -gt 0 ] || ARCHITEKTURY=(amd64 arm64)

here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/.." && pwd)"
GO="${GO:-go}"
mkdir -p "$WYNIK"

# Nazwy architektur roznia sie miedzy Go, Debianem i RPM-em. Tlumaczymy je
# w jednym miejscu, bo pomylka konczy sie pakietem, ktory instaluje sie na
# niewlasciwej maszynie.
# Arch nazywa architektury tak samo jak RPM, ale osobna funkcja mowi wprost,
# ze to zbieg okolicznosci, a nie wspolny slownik.
nazwaARCH() { nazwaRPM "$1"; }

nazwaRPM() {
    case "$1" in
    amd64) echo x86_64 ;;
    arm64) echo aarch64 ;;
    *)     echo "$1" ;;
    esac
}

zbudujBinarki() {
    local arch="$1" stage="$WYNIK/stage-$arch"
    echo "==> binarki $arch"
    rm -rf "$stage"
    mkdir -p "$stage"
    for skladnik in agent agent-helper agentctl control-plane; do
        # CGO wylaczone: pakiet ma dzialac na kazdej maszynie danej
        # architektury, a nie tylko na tej, ktora ma te same biblioteki.
        # -trimpath usuwa sciezki maszyny budujacej, zeby ta sama binarka
        # powstawala niezaleznie od tego, gdzie lezy katalog roboczy.
        # Wersja jest wpisywana w binarke: panel porownuje ja z wersja
        # docelowa po aktualizacji, wiec musi pochodzic z wydania, a nie
        # z zaszytej stalej.
        CGO_ENABLED=0 GOOS=linux GOARCH="$arch" \
            "$GO" -C "$repo" build -trimpath \
            -ldflags "-s -w -X github.com/ultherego/flotestro/internal/agent.Version=$WERSJA" \
            -o "$stage/flotestro-$skladnik" "./cmd/$skladnik"
    done
    # Panel webowy jest niezalezny od architektury; wchodzi do pakietu
    # control plane, gdy zostal wczesniej zbudowany.
    if [ -d "${FLOTESTRO_WEB:-/usr/share/flotestro/web}" ]; then
        mkdir -p "$stage/web"
        cp -r "${FLOTESTRO_WEB:-/usr/share/flotestro/web}/." "$stage/web/"
    fi
    # Lista modulow wchodzacych w binarke. To nie jest pelny SBOM i nie
    # udajemy, ze jest: to dokladnie ta informacja, ktora niesie sama
    # binarka, i po niej da sie sprawdzic, czy wydanie zawiera podatna
    # wersje zaleznosci.
    "$GO" version -m "$stage/flotestro-agent" > "$WYNIK/moduly-$arch.txt"
}

zbudujPakiety() {
    local arch="$1" stage="$WYNIK/stage-$arch" zbudowano=false
    [ -d "$stage" ] || { echo "brak binarek w $stage" >&2; exit 1; }
    if command -v dpkg-deb >/dev/null; then
        echo "==> pakiety .deb $arch"
        for skladnik in agent control-plane; do
            "$here/build-deb.sh" "$skladnik" "$stage" "$WERSJA" "$arch" "$WYNIK" >/dev/null
        done
        zbudowano=true
    fi
    if command -v makepkg >/dev/null; then
        # makepkg pakuje gotowe pliki, wiec architektura jest kwestia nazwy
        # pakietu, a nie maszyny budujacej.
        echo "==> pakiet pacman $(nazwaARCH "$arch")"
        "$here/build-arch.sh" "$stage" "$WERSJA" "$(nazwaARCH "$arch")" "$WYNIK" >/dev/null
        zbudowano=true
    fi
    if command -v rpmbuild >/dev/null; then
        # rpmbuild nie buduje dla obcej architektury: sprawdza zgodnosc
        # z maszyna budujaca i odmawia. Pakiet .rpm dla arm64 wymaga wiec
        # maszyny arm64 (natywnej albo emulowanej przez mock/qemu). Mowimy
        # o tym wprost, zamiast wydawac wydanie niepelne po cichu.
        if [ "$(nazwaRPM "$arch")" = "$(uname -m)" ]; then
            echo "==> pakiety .rpm $(nazwaRPM "$arch")"
            for skladnik in agent control-plane; do
                "$here/build-rpm.sh" "$skladnik" "$stage" "$WERSJA" "$(nazwaRPM "$arch")" "$WYNIK" >/dev/null
            done
            zbudowano=true
        else
            echo "!!! .rpm $(nazwaRPM "$arch") wymaga maszyny $(nazwaRPM "$arch"); ta jest $(uname -m)" >&2
            echo "$(nazwaRPM "$arch")" >> "$WYNIK/brakujace-rpm.txt"
        fi
    fi
    # Brak narzedzi to blad; sama odmowa rpmbuilda dla obcej architektury
    # nim nie jest - wtedy pakiety tej architektury po prostu robi inna
    # maszyna, a tu zostaje slad w brakujace-rpm.txt.
    if [ "$zbudowano" = false ] && [ ! -s "$WYNIK/brakujace-rpm.txt" ]; then
        echo "brak dpkg-deb i rpmbuild - nie ma czym zbudowac pakietow" >&2
        exit 1
    fi
}

# pochodzenie zapisuje sie tam, gdzie stoi zrodlo - czyli przy budowaniu
# binarek. Maszyna pakujaca ma tylko kopie plikow bez historii i bez
# toolchainu, wiec spisany tam commit bylby zgadywaniem.
pochodzenie() {
    echo "==> pochodzenie"
    local commit opis
    # safe.directory: katalog ze zrodlami czesto nalezy do innego uzytkownika
    # niz proces budujacy, a git odmawia wtedy odczytu. Bez tego pochodzenie
    # wychodzi puste i nie widac tego az do zajrzenia do pliku.
    local gitopt=(-C "$repo" -c "safe.directory=$repo")
    commit="$(git "${gitopt[@]}" rev-parse HEAD 2>/dev/null || echo nieznany)"
    opis="$(git "${gitopt[@]}" describe --tags --always --dirty 2>/dev/null || echo nieznany)"
    cat > "$WYNIK/pochodzenie.json" <<EOF
{
  "wersja": "$WERSJA",
  "commit": "$commit",
  "opis": "$opis",
  "toolchain": "$("$GO" version 2>/dev/null || echo nieznany)",
  "flagi": "-trimpath -ldflags '-s -w' CGO_ENABLED=0",
  "architektury": "${ARCHITEKTURY[*]}",
  "zbudowano": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF
}

# sumy licza sie po nazwie pliku, wiec liczymy je z tego, co naprawde trafi
# do repozytorium - a nie z artefaktow posrednich.
sumy() {
    echo "==> sumy kontrolne"
    ( cd "$WYNIK" && sha256sum ./*.deb ./*.rpm 2>/dev/null > SHA256SUMS ) || true
}

for arch in "${ARCHITEKTURY[@]}"; do
    case "$TRYB" in
    binarki)  zbudujBinarki "$arch" ;;
    pakiety)  zbudujPakiety "$arch" ;;
    wszystko) zbudujBinarki "$arch"; zbudujPakiety "$arch" ;;
    *) echo "nieznany tryb: $TRYB" >&2; exit 1 ;;
    esac
done

case "$TRYB" in
binarki) pochodzenie ;;
pakiety) sumy ;;
wszystko) pochodzenie; sumy ;;
esac
echo "==> gotowe: $WYNIK"
ls -1 "$WYNIK"
