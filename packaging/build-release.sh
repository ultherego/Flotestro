#!/usr/bin/env bash
# Builds a release: the binaries for the given architectures, the packages,
# the checksums and the provenance description.
#
#   build-release.sh binaries <version> <dir> [arch ...]   # requires Go
#
# A .deb package is made for any architecture on any machine: dpkg-deb only
# packs ready files. rpmbuild checks conformance with the build machine and
# refuses for a foreign architecture, so an .rpm for arm64 requires an arm64
# machine.
#   build-release.sh packages <version> <dir> [arch ...]   # requires dpkg-deb/rpmbuild
#   build-release.sh all      <version> <dir> [arch ...]
#
# The steps are separate because the machines are separate: the Go toolchain
# stands elsewhere than the packaging tools of a given distribution, and the
# package is to be made natively - only then is what the customer gets
# checked.
#
# The script signs nothing. Signing is a separate step and a separate key:
# the build machine does not have to hold it and had better not.
set -euo pipefail

MODE="${1:?give the mode: binaries, packages or all}"
VERSION="${2:?give the release version}"
OUT="${3:?give the output directory}"
shift 3
ARCHITECTURES=("$@")
[ ${#ARCHITECTURES[@]} -gt 0 ] || ARCHITECTURES=(amd64 arm64)

here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/.." && pwd)"
GO="${GO:-go}"
mkdir -p "$OUT"
# The output directory is made absolute: the bill of materials is written by
# a tool run from the repository directory, and a relative path would then
# point somewhere else.
OUT="$(cd "$OUT" && pwd)"

# The architecture names differ between Go, Debian and RPM. They are
# translated in one place, because a mistake ends with a package that
# installs on the wrong machine.
# Arch names architectures the same way as RPM, but a separate function says
# outright that it is a coincidence, not a shared vocabulary.
archName() { rpmName "$1"; }

rpmName() {
    case "$1" in
    amd64) echo x86_64 ;;
    arm64) echo aarch64 ;;
    *)     echo "$1" ;;
    esac
}

# stamp composes the linker flags that write the provenance into the binary.
#
# The version number alone is not enough when a package behaves differently
# than it should: the first question is then "which commit is this from" and
# it has to be answerable on the host, without access to the release
# machine.
stamp() {
    local pkg=github.com/ultherego/flotestro/internal/buildinfo
    local commit date
    # safe.directory: the source directory often belongs to a different user
    # than the building process, and git then refuses to read it.
    commit="$(git -C "$repo" -c "safe.directory=$repo" rev-parse HEAD 2>/dev/null || true)"
    date="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf -- "-X %s.Version=%s -X %s.Commit=%s -X %s.Date=%s" \
        "$pkg" "$VERSION" "$pkg" "$commit" "$pkg" "$date"
}

buildBinaries() {
    local arch="$1" stage="$OUT/stage-$arch"
    echo "==> binaries $arch"
    rm -rf "$stage"
    mkdir -p "$stage"
    for component in agent agent-helper agentctl relay relayctl control-plane auditverify; do
        # CGO disabled: the package is to work on every machine of the given
        # architecture, not only on one with the same libraries.
        # -trimpath removes the build machine paths, so that the same binary
        # comes out regardless of where the working directory lies.
        # The version is written into the binary: the panel compares it with
        # the target version after an update, so it must come from the
        # release, not from a hard-coded constant.
        CGO_ENABLED=0 GOOS=linux GOARCH="$arch" \
            "$GO" -C "$repo" build -trimpath \
            -ldflags "-s -w $(stamp)" \
            -o "$stage/flotestro-$component" "./cmd/$component"
    done
    # The web panel is architecture-independent; it enters the control plane
    # package when it was built earlier.
    if [ -d "${FLOTESTRO_WEB:-/usr/share/flotestro/web}" ]; then
        mkdir -p "$stage/web"
        cp -r "${FLOTESTRO_WEB:-/usr/share/flotestro/web}/." "$stage/web/"
    fi
    # The list of modules that enter the binaries, as the toolchain prints
    # it: exactly the information the binaries themselves carry.
    "$GO" version -m "$stage"/flotestro-* > "$OUT/modules-$arch.txt"
    sboms "$arch"
}

# sboms writes the bill of materials of every binary of an architecture:
# CycloneDX 1.5 JSON, one module per component, read from the build
# metadata of the binary itself - so the bill describes the artefact and
# not the go.mod of the working tree. The bills stand next to the packages
# under the package name, and a copy goes into the stage, from where every
# package ships its own under /usr/share/doc.
sboms() {
    local arch="$1" stage="$OUT/stage-$arch" bills
    echo "==> sbom $arch"
    bills="$(mktemp -d)"
    local args=()
    local binary
    for binary in "$stage"/flotestro-*; do
        [ -f "$binary" ] || continue
        args+=(-binary "$binary")
    done
    # SOURCE_DATE_EPOCH: the bills of one release carry one timestamp, and
    # a rebuild of the same commit gives the same files.
    SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(date -u +%s)}" \
        "$GO" -C "$repo" run ./cmd/sbom -version "$VERSION" -out-dir "$bills" \
        "${args[@]}" >/dev/null
    mkdir -p "$stage/sbom"
    local bill component
    for bill in "$bills"/*.cdx.json; do
        component="$(basename "$bill" .cdx.json)"
        cp "$bill" "$stage/sbom/$component.cdx.json"
        cp "$bill" "$OUT/${component}_${VERSION}_${arch}.cdx.json"
    done
    rm -rf "$bills"
}

buildPackages() {
    local arch="$1" stage="$OUT/stage-$arch" built=false
    [ -d "$stage" ] || { echo "no binaries in $stage" >&2; exit 1; }
    if command -v dpkg-deb >/dev/null; then
        echo "==> .deb packages $arch"
        for component in agent relay control-plane; do
            "$here/build-deb.sh" "$component" "$stage" "$VERSION" "$arch" "$OUT" >/dev/null
        done
        built=true
    fi
    if command -v makepkg >/dev/null; then
        # makepkg packs ready files, so the architecture is a matter of the
        # package name, not of the build machine.
        echo "==> pacman packages $(archName "$arch")"
        for component in agent relay; do
            "$here/build-arch.sh" "$component" "$stage" "$VERSION" \
                "$(archName "$arch")" "$OUT" >/dev/null
        done
        built=true
    fi
    if command -v rpmbuild >/dev/null; then
        # rpmbuild does not build for a foreign architecture: it checks
        # conformance with the build machine and refuses. An .rpm for arm64
        # therefore requires an arm64 machine (native or emulated through
        # mock/qemu). This is said outright instead of quietly issuing an
        # incomplete release.
        if [ "$(rpmName "$arch")" = "$(uname -m)" ]; then
            echo "==> .rpm packages $(rpmName "$arch")"
            for component in agent relay control-plane; do
                "$here/build-rpm.sh" "$component" "$stage" "$VERSION" "$(rpmName "$arch")" "$OUT" >/dev/null
            done
            built=true
        else
            echo "!!! .rpm $(rpmName "$arch") requires a $(rpmName "$arch") machine; this one is $(uname -m)" >&2
            echo "$(rpmName "$arch")" >> "$OUT/missing-rpm.txt"
        fi
    fi
    # Missing tools are an error; rpmbuild's refusal for a foreign
    # architecture alone is not - then the packages of that architecture are
    # simply made by another machine, and a trace stays here in
    # missing-rpm.txt.
    if [ "$built" = false ] && [ ! -s "$OUT/missing-rpm.txt" ]; then
        echo "neither dpkg-deb nor rpmbuild is available - nothing to build the packages with" >&2
        exit 1
    fi
}

# The provenance is recorded where the source stands - that is when
# building the binaries. The packaging machine has only a copy of the files
# without the history and without the toolchain, so a commit written there
# would be a guess.
provenance() {
    echo "==> provenance"
    local commit description
    # safe.directory: the source directory often belongs to a different user
    # than the building process, and git then refuses to read it. Without
    # this the provenance comes out empty and it is not visible until one
    # looks into the file.
    local gitopt=(-C "$repo" -c "safe.directory=$repo")
    commit="$(git "${gitopt[@]}" rev-parse HEAD 2>/dev/null || echo unknown)"
    description="$(git "${gitopt[@]}" describe --tags --always --dirty 2>/dev/null || echo unknown)"
    # The manifest names the bills, so whoever reads it knows which files
    # describe the release and does not have to guess from the directory.
    local bills="" bill
    for bill in "$OUT"/*.cdx.json; do
        [ -e "$bill" ] || continue
        bills="$bills${bills:+, }\"$(basename "$bill")\""
    done
    cat > "$OUT/provenance.json" <<EOF
{
  "version": "$VERSION",
  "commit": "$commit",
  "description": "$description",
  "toolchain": "$("$GO" version 2>/dev/null || echo unknown)",
  "flags": "-trimpath -ldflags '-s -w' CGO_ENABLED=0",
  "architectures": "${ARCHITECTURES[*]}",
  "sbom_format": "CycloneDX 1.5",
  "sbom": [$bills],
  "built_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF
}

# The checksums are computed by file name, so they are computed from what
# really goes into the repository - not from intermediate artefacts. The list
# is the same one the release publishes: a file left out of it is a file the
# customer has no way to check.
checksums() {
    echo "==> checksums"
    local published=() file
    for file in "$OUT"/*.deb "$OUT"/*.rpm "$OUT"/*.pkg.tar.* "$OUT"/*.cdx.json \
                "$OUT"/modules-*.txt "$OUT"/provenance.json; do
        [ -f "$file" ] && published+=("$(basename "$file")")
    done
    [ ${#published[@]} -gt 0 ] || { echo "nothing to write the checksums of" >&2; return 1; }
    ( cd "$OUT" && sha256sum "${published[@]}" > SHA256SUMS )
}

for arch in "${ARCHITECTURES[@]}"; do
    case "$MODE" in
    binaries) buildBinaries "$arch" ;;
    packages) buildPackages "$arch" ;;
    all)      buildBinaries "$arch"; buildPackages "$arch" ;;
    *) echo "unknown mode: $MODE" >&2; exit 1 ;;
    esac
done

case "$MODE" in
binaries) provenance ;;
packages) checksums ;;
all)      provenance; checksums ;;
esac
echo "==> done: $OUT"
ls -1 "$OUT"
