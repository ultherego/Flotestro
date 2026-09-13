#!/usr/bin/env bash
# Builds a pacman package from ready binaries. Requires makepkg, that is a
# host of the Arch family.
#
#   build-arch.sh [agent|relay] <stage> <version> <arch> <out>
#
# The component is the first argument; without it the agent is built,
# because that is how this command was called before the relay got its own
# package.
#
# Arch gets a package, not a tarball: the installation is to go the same way
# as on the other families - with a file registry, scriptlets and the
# possibility of uninstalling.
set -euo pipefail

case "${1:-}" in
agent|relay) COMPONENT="$1"; shift ;;
*)           COMPONENT=agent ;;
esac
STAGE="${1:?give the directory with the binaries}"
VERSION="${2:-0.1.0}"
ARCH="${3:-x86_64}"
OUT="${4:-.}"

here="$(cd "$(dirname "$0")" && pwd)"
build="$(mktemp -d)"
trap 'rm -rf "$build"' EXIT

# makepkg refuses to work as root; the sources go into a directory owned by
# the building user.
if [ "$COMPONENT" = relay ]; then
    cp "$STAGE/flotestro-relay" "$build/"
    cp "$here/systemd/flotestro-relay.service" "$build/"
    cp "$here/arch/flotestro-relay.sysusers" "$here/arch/flotestro-relay.tmpfiles" \
       "$here/arch/flotestro-relay.install" "$build/"
    cp "$here/relay.yaml" "$build/relay.yaml"
    FILES="flotestro-relay flotestro-relay.service flotestro-relay.sysusers"
    FILES="$FILES flotestro-relay.tmpfiles relay.yaml"
    TEMPLATE="$here/arch/relay-PKGBUILD"
else
    cp "$STAGE/flotestro-agent" "$STAGE/flotestro-agentctl" \
       "$STAGE/flotestro-agent-helper" "$build/"
    cp "$here/systemd/flotestro-agent.service" "$here/systemd/flotestro-enroll.service" \
       "$here/systemd/flotestro-helper.service" "$here/systemd/flotestro-helper.socket" "$build/"
    cp "$here/arch/flotestro-agent.sysusers" "$here/arch/flotestro-agent.tmpfiles" \
       "$here/arch/flotestro-agent.install" "$build/"
    cp "$here/agent.yaml" "$build/agent.yaml"
    FILES="flotestro-agent flotestro-agentctl flotestro-agent-helper"
    FILES="$FILES flotestro-agent.service flotestro-enroll.service"
    FILES="$FILES flotestro-helper.service flotestro-helper.socket"
    FILES="$FILES flotestro-agent.sysusers flotestro-agent.tmpfiles agent.yaml"
    TEMPLATE="$here/arch/PKGBUILD"
fi

# The checksums are computed, not skipped: "SKIP" would mean a package whose
# content nobody checked, and that is exactly the property the package is
# made for in the first place.
sums=""
for file in $FILES; do
    sums="$sums'$(sha256sum "$build/$file" | cut -d' ' -f1)' "
done

sed -e "s/__VERSION__/$VERSION/" -e "s/__SUMS__/${sums% }/" \
    "$TEMPLATE" > "$build/PKGBUILD"

( cd "$build" && CARCH="$ARCH" makepkg --nodeps --noconfirm --ignorearch >makepkg.log 2>&1 ) ||
    { cat "$build/makepkg.log" >&2; exit 1; }

# The debug package has a name so similar that it matches the same pattern.
# A release with an empty binary would look correct until installation.
package="$(find "$build" -maxdepth 1 -name "flotestro-$COMPONENT-*.pkg.tar.*" \
    ! -name "flotestro-$COMPONENT-debug-*" | head -1)"
[ -n "$package" ] || { echo "makepkg produced no package" >&2; exit 1; }
cp "$package" "$OUT/"
echo "$OUT/$(basename "$package")"
