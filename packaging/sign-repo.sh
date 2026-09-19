#!/usr/bin/env bash
# Composes signed repositories from a ready release.
#
#   sign-repo.sh <release-dir> <gpg-key> <repo-dir> [version]
#
# HTTPS protects the transport, but does not replace signed metadata: a host
# installs a package only once its manager can verify the signature. Without
# this step every repository mirror is a way into the fleet.
#
# The signing key does not belong to the build machine. The script takes its
# identifier from the command line and generates nothing.
#
# The repository is added to, never rewritten. A release drops its packages
# beside the ones already there and every index is composed again over all of
# them, so a host still on an older version keeps finding it. Run twice over
# the same release the script changes nothing, which is what makes a failed
# publish something one can simply repeat.
set -euo pipefail

RELEASE="${1:?give the release directory}"
KEY="${2:?give the GPG key identifier}"
REPO="${3:?give the repository directory}"
VERSION="${4:-}"
CHANNEL="${FLOTESTRO_CHANNEL:-stable}"

command -v gpg >/dev/null || { echo "gpg is missing" >&2; exit 1; }
# The channel is a suite name, a directory name and a word in a host's
# command file; the panel checks it the same way before it writes it.
case "$CHANNEL" in
    ""|*[!a-z0-9-]*) echo "the channel is a bare word: '$CHANNEL' is not" >&2; exit 1 ;;
esac
mkdir -p "$REPO"

# place copies a release file into the repository once. A name that is
# already published with other bytes stops everything: the host that fetched
# it yesterday would get something else today and never learn. It answers 0
# for a file it placed and 1 for one that was already there, so the caller
# knows what is new and what it must leave alone.
place() {
    local from="$1" to="$2"
    if [ -e "$to" ]; then
        if cmp -s "$from" "$to"; then
            return 1
        fi
        echo "$to is already published with different content" >&2
        echo "a published package is never replaced; publish the correction as a new version" >&2
        exit 1
    fi
    cp "$from" "$to"
    return 0
}

# --- APT ---------------------------------------------------------------
# The "flat repository" layout: one directory per channel, without
# components. The fleet has one package source, not a distribution tree.
if ls "$RELEASE"/*.deb >/dev/null 2>&1; then
    echo "==> APT repository ($CHANNEL)"
    apt_dir="$REPO/deb/dists/$CHANNEL/main"
    # The pool belongs to the channel. One pool shared by all of them would
    # put a pre-release .deb into the stable index the next time that index
    # was composed, and a stable host would install it without asking.
    pool="pool/$CHANNEL"
    mkdir -p "$apt_dir/binary-amd64" "$apt_dir/binary-arm64" "$REPO/deb/$pool"
    for package in "$RELEASE"/*.deb; do
        place "$package" "$REPO/deb/$pool/$(basename "$package")" || true
    done

    for arch in amd64 arm64; do
        # --multiversion: the previous versions stay in the index too.
        # Without it the repository has only the newest one, and backing out
        # of a release requires hunting for the package by hand - that is
        # not a rollback. apt installs the highest version it finds, so the
        # older entries are an offer, not a default.
        ( cd "$REPO/deb" && dpkg-scanpackages --multiversion --arch "$arch" "$pool" /dev/null ) \
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
    # The package signature and the metadata signature are two different
    # things: the first protects the file itself, the second the file list.
    # The manager checks both, so a missing tool is an error, not a reason
    # for a quiet skip - a repository with unsigned packages looks ready and
    # refuses only on the host.
    command -v rpmsign >/dev/null || { echo "rpmsign is missing - nothing to sign the packages with" >&2; exit 1; }
    command -v createrepo_c >/dev/null || { echo "createrepo_c is missing" >&2; exit 1; }
    # --addsign writes the signature into the header, so it changes the file.
    # A package already in the repository is therefore left exactly as it
    # was published; only what arrives now is signed. The two files cannot be
    # compared byte for byte - one is signed and the other is not - so what
    # is compared is the payload digest, which signing does not touch.
    fresh=()
    for package in "$RELEASE"/*.rpm; do
        name="$(basename "$package")"
        if [ -e "$rpm_dir/$name" ]; then
            if [ "$(rpm -qp --qf '%{SIGMD5}' "$package" 2>/dev/null)" \
                != "$(rpm -qp --qf '%{SIGMD5}' "$rpm_dir/$name" 2>/dev/null)" ]; then
                echo "$rpm_dir/$name is already published with a different package" >&2
                echo "a published package is never replaced; publish the correction as a new version" >&2
                exit 1
            fi
            continue
        fi
        cp "$package" "$rpm_dir/$name"
        fresh+=("$rpm_dir/$name")
    done
    [ ${#fresh[@]} -eq 0 ] || rpmsign --define "_gpg_name $KEY" --addsign "${fresh[@]}" >/dev/null
    # The metadata is composed over the whole directory, so the index offers
    # every version the channel ever carried and dnf takes the highest.
    createrepo_c --quiet "$rpm_dir"
    gpg --batch --yes --local-user "$KEY" -abs \
        -o "$rpm_dir/repodata/repomd.xml.asc" "$rpm_dir/repodata/repomd.xml"
fi

# --- pacman ------------------------------------------------------------
if ls "$RELEASE"/*.pkg.tar.* >/dev/null 2>&1; then
    command -v repo-add >/dev/null || { echo "repo-add is missing" >&2; exit 1; }
    # One database serves one architecture: pacman reads a single
    # <Server>/flotestro.db, and a foreign architecture in it is an entry
    # every host refuses. x86_64 - the architecture Arch Linux itself has -
    # stands at the root of the channel, where the panel's command points;
    # any other one gets its own directory beside it.
    touched="$(mktemp)"
    for package in "$RELEASE"/*.pkg.tar.*; do
        case "$package" in *.sig) continue ;; esac
        name="$(basename "$package")"
        arch="${name%.pkg.tar.*}"; arch="${arch##*-}"
        arch_dir="$REPO/arch/$CHANNEL"
        [ "$arch" = x86_64 ] || arch_dir="$arch_dir/$arch"
        mkdir -p "$arch_dir"
        printf '%s\n' "$arch_dir" >> "$touched"
        # The packages themselves are signed separately from the database:
        # pacman checks both. The signature is detached, so it is written
        # beside a package that has just arrived and never over one that is
        # already published.
        if place "$package" "$arch_dir/$name"; then
            gpg --batch --yes --local-user "$KEY" --detach-sign --no-armor "$arch_dir/$name"
        fi
    done
    while read -r arch_dir; do
        label="${arch_dir##*/}"
        if [ "$label" = "$CHANNEL" ]; then label=x86_64; fi
        echo "==> pacman repository ($CHANNEL, $label)"
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
    done < <(sort -u "$touched")
    rm -f "$touched"
fi

# The public key lies next to the repository: the host must add it before
# it installs anything, and must have somewhere to take it from.
gpg --batch --yes --armor --export "$KEY" > "$REPO/flotestro-repo.asc"
# The manifests describe one release, so they stand under its version rather
# than as a file the next release overwrites. They cover the release as it
# was built: the .rpm files in the repository carry a signature the loose
# assets do not, and `rpm --checksig` is what answers for those.
if [ -n "$VERSION" ]; then
    mkdir -p "$REPO/releases/$VERSION"
    for manifest in SHA256SUMS SHA256SUMS.asc provenance.json; do
        [ -f "$RELEASE/$manifest" ] || continue
        place "$RELEASE/$manifest" "$REPO/releases/$VERSION/$manifest" || true
    done
else
    cp "$RELEASE/SHA256SUMS" "$REPO/SHA256SUMS" 2>/dev/null || true
    cp "$RELEASE/provenance.json" "$REPO/provenance.json" 2>/dev/null || true
fi
echo "==> done: $REPO"
