#!/usr/bin/env bash
# Sklada podpisane repozytoria z gotowego wydania.
#
#   sign-repo.sh <katalog-wydania> <klucz-gpg> <katalog-repo>
#
# HTTPS chroni transport, ale nie zastepuje podpisanych metadanych: host
# instaluje pakiet dopiero wtedy, gdy jego menedzer potrafi zweryfikowac
# podpis. Bez tego kroku kazde lustro repozytorium jest droga do floty.
#
# Klucz podpisujacy nie nalezy do maszyny budujacej. Skrypt bierze jego
# identyfikator z wiersza polecen i niczego nie generuje.
set -euo pipefail

WYDANIE="${1:?podaj katalog wydania}"
KLUCZ="${2:?podaj identyfikator klucza GPG}"
REPO="${3:?podaj katalog repozytorium}"
KANAL="${FLOTESTRO_KANAL:-stable}"

command -v gpg >/dev/null || { echo "brak gpg" >&2; exit 1; }
mkdir -p "$REPO"

# --- APT ---------------------------------------------------------------
# Uklad "flat repository": jeden katalog na kanal, bez komponentow. Flota
# ma jedno zrodlo pakietow, a nie drzewo dystrybucji.
if ls "$WYDANIE"/*.deb >/dev/null 2>&1; then
    echo "==> repozytorium APT ($KANAL)"
    apt_dir="$REPO/deb/dists/$KANAL/main"
    mkdir -p "$apt_dir/binary-amd64" "$apt_dir/binary-arm64" "$REPO/deb/pool"
    cp "$WYDANIE"/*.deb "$REPO/deb/pool/"

    for arch in amd64 arm64; do
        # --multiversion: w indeksie zostaja takze poprzednie wersje. Bez tego
        # repozytorium ma tylko najnowsza, a wycofanie sie z wydania wymaga
        # recznego szukania pakietu - czyli nie jest wycofaniem.
        ( cd "$REPO/deb" && dpkg-scanpackages --multiversion --arch "$arch" pool /dev/null ) \
            > "$apt_dir/binary-$arch/Packages"
        gzip -9fk "$apt_dir/binary-$arch/Packages"
    done

    ( cd "$REPO/deb/dists/$KANAL" && cat > Release <<EOF
Origin: Flotestro
Label: Flotestro
Suite: $KANAL
Codename: $KANAL
Architectures: amd64 arm64
Components: main
Date: $(date -Ru)
EOF
      # Sumy plikow indeksu sa czescia podpisu: bez nich podpis obejmowalby
      # sam naglowek, a nie liste pakietow.
      {
          echo "SHA256:"
          find main -type f \( -name Packages -o -name Packages.gz \) | sort | while read -r plik; do
              printf " %s %16d %s\n" "$(sha256sum "$plik" | cut -d' ' -f1)" \
                  "$(stat -c%s "$plik")" "$plik"
          done
      } >> Release
      gpg --batch --yes --local-user "$KLUCZ" --clearsign -o InRelease Release
      gpg --batch --yes --local-user "$KLUCZ" -abs -o Release.gpg Release )
fi

# --- RPM ---------------------------------------------------------------
if ls "$WYDANIE"/*.rpm >/dev/null 2>&1; then
    echo "==> repozytorium RPM ($KANAL)"
    rpm_dir="$REPO/rpm/$KANAL"
    mkdir -p "$rpm_dir"
    cp "$WYDANIE"/*.rpm "$rpm_dir/"
    # Podpis pakietu i podpis metadanych to dwie rozne rzeczy: pierwszy
    # chroni sam plik, drugi liste plikow. Menedzer sprawdza oba, wiec brak
    # narzedzia jest bledem, a nie powodem do cichego pominiecia - repozytorium
    # z niepodpisanymi pakietami wyglada na gotowe i odmawia dopiero na hoscie.
    command -v rpmsign >/dev/null || { echo "brak rpmsign - nie ma czym podpisac pakietow" >&2; exit 1; }
    rpmsign --define "_gpg_name $KLUCZ" --addsign "$rpm_dir"/*.rpm >/dev/null
    command -v createrepo_c >/dev/null || { echo "brak createrepo_c" >&2; exit 1; }
    createrepo_c --quiet "$rpm_dir"
    gpg --batch --yes --local-user "$KLUCZ" -abs \
        -o "$rpm_dir/repodata/repomd.xml.asc" "$rpm_dir/repodata/repomd.xml"
fi

# Klucz publiczny lezy obok repozytorium: host musi go dodac, zanim
# cokolwiek zainstaluje, i musi miec skad go wziac.
gpg --batch --yes --armor --export "$KLUCZ" > "$REPO/flotestro-repo.asc"
cp "$WYDANIE/SHA256SUMS" "$REPO/SHA256SUMS" 2>/dev/null || true
cp "$WYDANIE/pochodzenie.json" "$REPO/pochodzenie.json" 2>/dev/null || true
echo "==> gotowe: $REPO"
