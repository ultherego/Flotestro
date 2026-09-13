#!/usr/bin/env bash
# Composes signed repositories from a ready release.
#
#   sign-repo.sh <release-dir> <gpg-key> <repo-dir>
#
# HTTPS protects the transport, but does not replace signed metadata: a host
# installs a package only once its manager can verify the signature. Without
# this step every repository mirror is a way into the fleet.
#
# The signing key does not belong to the build machine. The script takes its
# identifier from the command line and generates nothing.
set -euo pipefail

RELEASE="${1:?give the release directory}"
KEY="${2:?give the GPG key identifier}"
REPO="${3:?give the repository directory}"
CHANNEL="${FLOTESTRO_CHANNEL:-stable}"

command -v gpg >/dev/null || { echo "gpg is missing" >&2; exit 1; }
mkdir -p "$REPO"

# --- APT ---------------------------------------------------------------
# The "flat repository" layout: one directory per channel, without
# components. The fleet has one package source, not a distribution tree.
if ls "$RELEASE"/*.deb >/dev/null 2>&1; then
    echo "==> APT repository ($CHANNEL)"
    apt_dir="$REPO/deb/dists/$CHANNEL/main"
    mkdir -p "$apt_dir/binary-amd64" "$apt_dir/binary-arm64" "$REPO/deb/pool"
    cp "$RELEASE"/*.deb "$REPO/deb/pool/"

    for arch in amd64 arm64; do
        # --multiversion: the previous versions stay in the index too.
        # Without it the repository has only the newest one, and backing out
        # of a release requires hunting for the package by hand - that is
        # not a rollback.
        ( cd "$REPO/deb" && dpkg-scanpackages --multiversion --arch "$arch" pool /dev/null ) \
            > "$apt_dir/binary-$arch/Packages"
        gzip -9fk "$apt_dir/binary-$arch/Packages"
    done

    ( cd "$REPO/deb/dists/$CHANNEL" && cat > Release <<EOF
Origin: Flotestro
Label: Flotestro
Suite: $CHANNEL
Codename: $CHANNEL
Architectures: amd64 arm64
Components: main
Date: $(date -Ru)
EOF
      # The checksums of the index files are part of the signature: without
      # them the signature would cover the header alone, not the package
      # list.
      {
          echo "SHA256:"
          find main -type f \( -name Packages -o -name Packages.gz \) | sort | while read -r file; do
              printf " %s %16d %s\n" "$(sha256sum "$file" | cut -d' ' -f1)" \
                  "$(stat -c%s "$file")" "$file"
          done
      } >> Release
      gpg --batch --yes --local-user "$KEY" --clearsign -o InRelease Release
      gpg --batch --yes --local-user "$KEY" -abs -o Release.gpg Release )
fi

# --- RPM ---------------------------------------------------------------
if ls "$RELEASE"/*.rpm >/dev/null 2>&1; then
    echo "==> RPM repository ($CHANNEL)"
    rpm_dir="$REPO/rpm/$CHANNEL"
    mkdir -p "$rpm_dir"
    cp "$RELEASE"/*.rpm "$rpm_dir/"
    # The package signature and the metadata signature are two different
    # things: the first protects the file itself, the second the file list.
    # The manager checks both, so a missing tool is an error, not a reason
    # for a quiet skip - a repository with unsigned packages looks ready and
    # refuses only on the host.
    command -v rpmsign >/dev/null || { echo "rpmsign is missing - nothing to sign the packages with" >&2; exit 1; }
    rpmsign --define "_gpg_name $KEY" --addsign "$rpm_dir"/*.rpm >/dev/null
    command -v createrepo_c >/dev/null || { echo "createrepo_c is missing" >&2; exit 1; }
    createrepo_c --quiet "$rpm_dir"
    gpg --batch --yes --local-user "$KEY" -abs \
        -o "$rpm_dir/repodata/repomd.xml.asc" "$rpm_dir/repodata/repomd.xml"
fi

# --- pacman ------------------------------------------------------------
if ls "$RELEASE"/*.pkg.tar.* >/dev/null 2>&1; then
    echo "==> pacman repository ($CHANNEL)"
    arch_dir="$REPO/arch/$CHANNEL"
    mkdir -p "$arch_dir"
    cp "$RELEASE"/*.pkg.tar.* "$arch_dir/"
    command -v repo-add >/dev/null || { echo "repo-add is missing" >&2; exit 1; }
    # repo-add --sign signs the package database, and --key says with what.
    # The packages themselves are signed separately: pacman checks both.
    for package in "$arch_dir"/*.pkg.tar.*; do
        case "$package" in *.sig) continue ;; esac
        gpg --batch --yes --local-user "$KEY" --detach-sign --no-armor "$package"
    done
    # The package database is what pacman reads first. A repo-add error
    # would leave a repository with bare files and no index - the client
    # would see an empty repository, not an error.
    # The order matters: repo-add records in the database the package it
    # got last, not the one with the highest version. The shell glob sorts
    # alphabetically, so 0.9.0 won over 0.13.0 and the repository announced
    # an old version as current. Sorting by version puts the newest last.
    mapfile -t packages < <(printf '%s\n' "$arch_dir"/*.pkg.tar.zst | sort -V)
    ( cd "$arch_dir" && repo-add --sign --key "$KEY" flotestro.db.tar.gz "${packages[@]}" >/dev/null )
    [ -e "$arch_dir/flotestro.db" ] || { echo "repo-add did not build the package database" >&2; exit 1; }
fi

# The public key lies next to the repository: the host must add it before
# it installs anything, and must have somewhere to take it from.
gpg --batch --yes --armor --export "$KEY" > "$REPO/flotestro-repo.asc"
cp "$RELEASE/SHA256SUMS" "$REPO/SHA256SUMS" 2>/dev/null || true
cp "$RELEASE/provenance.json" "$REPO/provenance.json" 2>/dev/null || true
echo "==> done: $REPO"
