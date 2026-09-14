#!/bin/sh
# Builds a .deb package from ready binaries.
#
#   build-deb.sh agent         <stage> <version> <arch> <out>
#   build-deb.sh relay         <stage> <version> <arch> <out>
#   build-deb.sh control-plane <stage> <version> <arch> <out>
#
# The script compiles no code: the package is to be made exactly from the
# artefacts that passed the tests. Requires dpkg-deb, that is a host of the
# Debian family.
set -eu

COMPONENT="${1:?give the component: agent, relay or control-plane}"
STAGE="${2:?give the directory with the binaries}"
VERSION="${3:-0.1.0}"
ARCH="${4:-amd64}"
OUT="${5:-.}"

root="$(mktemp -d)"
trap 'rm -rf "$root"' EXIT
here="$(cd "$(dirname "$0")" && pwd)"

install -d -m 0755 "$root/DEBIAN"
sed -e "s/__VERSION__/$VERSION/" -e "s/__ARCH__/$ARCH/" \
    "$here/deb/$COMPONENT.control" > "$root/DEBIAN/control"
install -m 0644 "$here/deb/$COMPONENT.conffiles" "$root/DEBIAN/conffiles"
for script in postinst prerm postrm; do
    install -m 0755 "$here/deb/$COMPONENT.$script" "$root/DEBIAN/$script"
done

install -d -m 0755 "$root/usr/bin" "$root/lib/systemd/system" "$root/etc/flotestro"

# installSBOM ships the bill of materials of the package's binaries under
# /usr/share/doc/<package>: the first binary's bill as sbom.cdx.json, the
# others under their own names. The bills are written when the binaries are
# built; a stage without them makes a package without them, which the
# release checklist is to notice rather than the package script to hide.
#
#   installSBOM <package> <binary> [binary ...]
installSBOM() {
    package="$1"
    first="$2"
    shift
    for binary in "$@"; do
        [ -f "$STAGE/sbom/$binary.cdx.json" ] || continue
        target="sbom-$binary.cdx.json"
        [ "$binary" = "$first" ] && target="sbom.cdx.json"
        install -d -m 0755 "$root/usr/share/doc/$package"
        install -m 0644 "$STAGE/sbom/$binary.cdx.json" "$root/usr/share/doc/$package/$target"
    done
}

case "$COMPONENT" in
agent)
    install -m 0755 "$STAGE/flotestro-agent"        "$root/usr/bin/flotestro-agent"
    install -m 0755 "$STAGE/flotestro-agent-helper" "$root/usr/bin/flotestro-agent-helper"
    install -m 0755 "$STAGE/flotestro-agentctl"     "$root/usr/bin/flotestro-agentctl"
    for unit in flotestro-agent.service flotestro-enroll.service \
                flotestro-helper.service flotestro-helper.socket; do
        install -m 0644 "$here/systemd/$unit" "$root/lib/systemd/system/$unit"
    done
    install -m 0640 "$here/agent.yaml" "$root/etc/flotestro/agent.yaml"
    # The service account is declared for systemd-sysusers, the same way as
    # on Arch; the maintainer script falls back to adduser where sysusers
    # is not available. Debian keeps the shell at /usr/sbin/nologin.
    install -d -m 0755 "$root/usr/lib/sysusers.d"
    sed 's#/usr/bin/nologin#/usr/sbin/nologin#' "$here/arch/flotestro-agent.sysusers" \
        > "$root/usr/lib/sysusers.d/flotestro-agent.conf"
    chmod 0644 "$root/usr/lib/sysusers.d/flotestro-agent.conf"
    # agent.env stays for hosts set up before the YAML was introduced and as
    # the place for explicit overrides; the enrollment token has no place in
    # it - the daemon does not enroll.
    install -m 0640 "$here/agent.env" "$root/etc/flotestro/agent.env"
    install -d -m 0700 "$root/var/lib/flotestro-agent"
    name="flotestro-agent"
    installSBOM flotestro-agent flotestro-agent flotestro-agent-helper flotestro-agentctl
    ;;
relay)
    install -m 0755 "$STAGE/flotestro-relay"    "$root/usr/bin/flotestro-relay"
    install -m 0755 "$STAGE/flotestro-relayctl" "$root/usr/bin/flotestro-relayctl"
    install -m 0644 "$here/systemd/flotestro-relay.service" \
        "$root/lib/systemd/system/flotestro-relay.service"
    install -m 0640 "$here/relay.yaml" "$root/etc/flotestro/relay.yaml"
    install -d -m 0700 "$root/var/lib/flotestro-relay"
    name="flotestro-relay"
    installSBOM flotestro-relay flotestro-relay flotestro-relayctl
    ;;
control-plane)
    install -m 0755 "$STAGE/flotestro-control-plane" "$root/usr/bin/flotestro-control-plane"
    install -m 0644 "$here/systemd/flotestro-control-plane.service" \
        "$root/lib/systemd/system/flotestro-control-plane.service"
    install -m 0640 "$here/control-plane.env" "$root/etc/flotestro/control-plane.env"
    install -d -m 0700 "$root/var/lib/flotestro"
    # The web panel is built separately; the package carries the ready files.
    if [ -d "$STAGE/web" ]; then
        install -d -m 0755 "$root/usr/share/flotestro/web"
        cp -r "$STAGE/web/." "$root/usr/share/flotestro/web/"
        find "$root/usr/share/flotestro/web" -type d -exec chmod 0755 {} +
        find "$root/usr/share/flotestro/web" -type f -exec chmod 0644 {} +
    fi
    name="flotestro-control-plane"
    installSBOM flotestro-control-plane flotestro-control-plane
    ;;
*)
    echo "unknown component: $COMPONENT" >&2
    exit 1
    ;;
esac

dpkg-deb --root-owner-group --build "$root" "$OUT/${name}_${VERSION}_${ARCH}.deb" >/dev/null
echo "$OUT/${name}_${VERSION}_${ARCH}.deb"
