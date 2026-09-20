Name:           flotestro-relay
Version:        %{?_flotestro_version}%{!?_flotestro_version:0.1.0}
Release:        %{?_flotestro_release}%{!?_flotestro_release:1}%{?dist}
Summary:        Flotestro site relay
License:        Proprietary
URL:            https://github.com/ultherego/flotestro
BuildArch:      %{_target_cpu}

Requires:       systemd
Requires:       ca-certificates
Requires(post): systemd, shadow-utils
Requires(preun): systemd

# The binaries are built earlier and given by directory; the spec compiles
# no code, so that the package is made from exactly the same artefacts that
# passed the tests.
# rpm outside Fedora has no systemd-rpm-macros, so the macro is undefined
# and every unit path expands to a name rpm refuses.
%{!?_unitdir: %global _unitdir /usr/lib/systemd/system}
# Upstream rpm reads _sharedstatedir as /usr/com; every rpm distribution keeps
# the state under /var/lib, so the path must not follow the build machine.
%global _sharedstatedir /var/lib
# The scriptlet macros come from the same package: undefined, they stay literal
# and the host runs them as commands, so a fallback stands in for them.
%if 0%{!?systemd_post:1}
%global systemd_post() \
if [ $1 -eq 1 ]; then systemctl preset %{?*} >/dev/null 2>&1 || :; fi \
%{nil}
%global systemd_preun() \
if [ $1 -eq 0 ]; then systemctl --no-reload disable --now %{?*} >/dev/null 2>&1 || :; fi \
%{nil}
%global systemd_postun_with_restart() \
systemctl daemon-reload >/dev/null 2>&1 || : \
if [ $1 -ge 1 ]; then systemctl try-restart %{?*} >/dev/null 2>&1 || :; fi \
%{nil}
%endif
%global _build_id_links none
%global __strip /bin/true

%description
The relay mediates between the agents of one site and the centre: it keeps
one upstream connection instead of hundreds, buffers results for the
duration of a link outage and does not forward jobs whose time to live has
passed.

The relay is a separate trust boundary. It has its own certificate of a
different kind than a host certificate, its own service account and its own
state directory; it signs no certificate and carries out no operations on
hosts.

%install
rm -rf %{buildroot}
install -d -m 0755 %{buildroot}%{_bindir}
install -m 0755 %{_flotestro_stage}/flotestro-relay    %{buildroot}%{_bindir}/flotestro-relay
install -m 0755 %{_flotestro_stage}/flotestro-relayctl %{buildroot}%{_bindir}/flotestro-relayctl

install -d -m 0755 %{buildroot}%{_unitdir}
install -m 0644 %{_flotestro_units}/flotestro-relay.service %{buildroot}%{_unitdir}/

install -d -m 0755 %{buildroot}%{_sysconfdir}/flotestro
install -m 0640 %{_flotestro_stage}/relay.yaml %{buildroot}%{_sysconfdir}/flotestro/relay.yaml

install -d -m 0700 %{buildroot}%{_sharedstatedir}/flotestro-relay
# The bill of materials of the binaries: written when they were built,
# read from the build metadata they carry. A stage without it makes a
# package without it; the release checklist notices, not this file.
install -d -m 0755 %{buildroot}%{_docdir}/flotestro-relay
[ -f %{_flotestro_stage}/sbom/flotestro-relay.cdx.json ] && \
    install -m 0644 %{_flotestro_stage}/sbom/flotestro-relay.cdx.json %{buildroot}%{_docdir}/flotestro-relay/sbom.cdx.json || :
[ -f %{_flotestro_stage}/sbom/flotestro-relayctl.cdx.json ] && \
    install -m 0644 %{_flotestro_stage}/sbom/flotestro-relayctl.cdx.json %{buildroot}%{_docdir}/flotestro-relay/sbom-flotestro-relayctl.cdx.json || :

%files
%{_docdir}/flotestro-relay
%{_bindir}/flotestro-relay
%{_bindir}/flotestro-relayctl
%{_unitdir}/flotestro-relay.service
%dir %{_sysconfdir}/flotestro
# The configuration must not be overwritten on an update: it holds the
# centre addresses and the names the relay presents to the agents under.
%config(noreplace) %attr(0640, root, flotestro-relay) %{_sysconfdir}/flotestro/relay.yaml
%dir %attr(0700, flotestro-relay, flotestro-relay) %{_sharedstatedir}/flotestro-relay

%pre
# A service account separate from the agent account: an ordinary agent may
# also run on the relay machine, and its identity must not be readable by
# the relay.
getent group flotestro-relay >/dev/null || groupadd --system flotestro-relay
getent passwd flotestro-relay >/dev/null || \
    useradd --system --gid flotestro-relay --no-create-home \
        --home-dir %{_sharedstatedir}/flotestro-relay --shell /sbin/nologin \
        flotestro-relay
exit 0

%post
%systemd_post flotestro-relay.service
systemctl enable flotestro-relay.service || :
if [ -e %{_sharedstatedir}/flotestro-relay/identity/current/agent.pem ]; then
    systemctl start flotestro-relay.service || :
else
    echo "flotestro-relay: fill in %{_sysconfdir}/flotestro/relay.yaml and enroll the relay" >&2
    echo "  sudo -u flotestro-relay flotestro-relayctl enroll --token-file <file>" >&2
    echo "  systemctl start flotestro-relay.service" >&2
fi

%preun
%systemd_preun flotestro-relay.service

%postun
%systemd_postun_with_restart flotestro-relay.service
# The relay identity stays on an update and on an ordinary removal: a
# reinstall is to recover it without enrollment.

%changelog
