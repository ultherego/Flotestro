#!/bin/sh
# Builds an .rpm package from ready binaries. Requires rpmbuild, that is a
# host of the Fedora/RHEL family.
#
#   build-rpm.sh agent         <stage> <version> <arch> <out>
#   build-rpm.sh relay         <stage> <version> <arch> <out>
#   build-rpm.sh control-plane <stage> <version> <arch> <out>
#
# The architecture is explicit, not taken from the build machine: the
# package for arm64 is made on the same machine as the one for x86_64,
# because the binary is already ready.
set -eu

COMPONENT="${1:?give the component: agent, relay or control-plane}"
STAGE="${2:?give the directory with the binaries}"
VERSION="${3:-0.1.0}"
ARCH="${4:-x86_64}"
OUT="${5:-.}"

here="$(cd "$(dirname "$0")" && pwd)"
topdir="$(mktemp -d)"
trap 'rm -rf "$topdir"' EXIT

# rpm refuses a hyphen in Version, and a pre-release belongs in Release
# anyway: Release "0.rc1" sorts before the "1" of the finished version, so a
# host that tried the candidate is offered the release as an upgrade.
case "$VERSION" in
*-*) RPM_VERSION="${VERSION%%-*}"; RPM_RELEASE="0.${VERSION#*-}" ;;
*)   RPM_VERSION="$VERSION";       RPM_RELEASE="1" ;;
esac

case "$COMPONENT" in
agent)         cp "$here/agent.env" "$STAGE/agent.env"
               cp "$here/agent.yaml" "$STAGE/agent.yaml"
               cp "$here/helper.yaml" "$STAGE/helper.yaml" ;;
relay)         cp "$here/relay.yaml" "$STAGE/relay.yaml" ;;
control-plane) cp "$here/control-plane.env" "$STAGE/control-plane.env" ;;
*) echo "unknown component: $COMPONENT" >&2; exit 1 ;;
esac

rpmbuild -bb "$here/rpm/flotestro-$COMPONENT.spec" \
    --target "$ARCH" \
    --define "_topdir $topdir" \
    --define "_flotestro_version $RPM_VERSION" \
    --define "_flotestro_release $RPM_RELEASE" \
    --define "_flotestro_stage $STAGE" \
    --define "_flotestro_units $here/systemd" \
    > "$topdir/rpmbuild.log" 2>&1 || { cat "$topdir/rpmbuild.log" >&2; exit 1; }

package="$(find "$topdir/RPMS" -name "flotestro-$COMPONENT-*.rpm" | head -1)"
[ -n "$package" ] || { echo "rpmbuild produced no package" >&2; exit 1; }
cp "$package" "$OUT/"
echo "$OUT/$(basename "$package")"
