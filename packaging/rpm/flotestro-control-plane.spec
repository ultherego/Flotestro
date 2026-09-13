Name:           flotestro-control-plane
Version:        %{?_flotestro_version}%{!?_flotestro_version:0.1.0}
Release:        1%{?dist}
Summary:        Flotestro Linux fleet management panel
License:        Proprietary
URL:            https://github.com/ultherego/flotestro
BuildArch:      %{_target_cpu}

Requires:       systemd
Requires(post): systemd, shadow-utils
Requires(preun): systemd
Recommends:     postgresql

%global _build_id_links none
%global __strip /bin/true

%description
The control plane accepts agent sessions over mTLS, plans typed operations
and runs campaigns on the fleet. It serves the web panel and the REST API.

PostgreSQL is the only source of truth; the schema is created and migrated
at startup. The database may be local or remote - the package does not
install it.

The identity directory integration and the OIDC login provider are optional.
Without them the panel works on API tokens and manages the local accounts of
the hosts.

%install
rm -rf %{buildroot}
install -d -m 0755 %{buildroot}%{_bindir}
install -m 0755 %{_flotestro_stage}/flotestro-control-plane %{buildroot}%{_bindir}/flotestro-control-plane

install -d -m 0755 %{buildroot}%{_unitdir}
install -m 0644 %{_flotestro_units}/flotestro-control-plane.service %{buildroot}%{_unitdir}/

install -d -m 0755 %{buildroot}%{_sysconfdir}/flotestro
install -m 0640 %{_flotestro_stage}/control-plane.env %{buildroot}%{_sysconfdir}/flotestro/control-plane.env

install -d -m 0700 %{buildroot}%{_sharedstatedir}/flotestro

# The web panel is built separately; the package carries the ready files.
install -d -m 0755 %{buildroot}%{_datadir}/flotestro/web
if [ -d %{_flotestro_stage}/web ]; then
    cp -r %{_flotestro_stage}/web/. %{buildroot}%{_datadir}/flotestro/web/
    find %{buildroot}%{_datadir}/flotestro/web -type d -exec chmod 0755 {} +
    find %{buildroot}%{_datadir}/flotestro/web -type f -exec chmod 0644 {} +
fi

%files
%{_bindir}/flotestro-control-plane
%{_unitdir}/flotestro-control-plane.service
%dir %{_sysconfdir}/flotestro
# The configuration must not be overwritten on an update: it holds the
# credentials to the database and to the identity provider.
%config(noreplace) %attr(0640, root, flotestro) %{_sysconfdir}/flotestro/control-plane.env
%dir %attr(0700, flotestro, flotestro) %{_sharedstatedir}/flotestro
%{_datadir}/flotestro/web

%pre
getent group flotestro >/dev/null || groupadd --system flotestro
getent passwd flotestro >/dev/null || \
    useradd --system --gid flotestro --no-create-home \
        --home-dir %{_sharedstatedir}/flotestro --shell /sbin/nologin flotestro
exit 0

%post
%systemd_post flotestro-control-plane.service
# A panel without a database has nowhere to keep the fleet state. Running it
# in a restart loop would litter the journal; the installation then ends
# with a hint.
if grep -qs '^FLOTESTRO_DATABASE_URL=.*change-me' %{_sysconfdir}/flotestro/control-plane.env; then
    systemctl enable flotestro-control-plane.service || :
    echo "flotestro-control-plane: set FLOTESTRO_DATABASE_URL in" >&2
    echo "  %{_sysconfdir}/flotestro/control-plane.env and run" >&2
    echo "  systemctl start flotestro-control-plane.service" >&2
else
    systemctl enable --now flotestro-control-plane.service || :
fi

%preun
%systemd_preun flotestro-control-plane.service

%postun
%systemd_postun_with_restart flotestro-control-plane.service
# The state directory with the fleet CA key stays: without it no agent is
# recognised and the whole fleet needs enrolling again.

%changelog
