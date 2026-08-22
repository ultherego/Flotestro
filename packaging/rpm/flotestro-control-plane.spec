Name:           flotestro-control-plane
Version:        %{?_flotestro_version}%{!?_flotestro_version:0.1.0}
Release:        1%{?dist}
Summary:        Panel zarzadzania flota Linux Flotestro
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
Control plane przyjmuje sesje agentow przez mTLS, planuje operacje typowane
i prowadzi kampanie na flocie. Wystawia panel webowy oraz API REST.

PostgreSQL jest jedynym zrodlem prawdy; schemat jest zakladany i migrowany
przy starcie. Baza moze byc lokalna lub zdalna - pakiet jej nie instaluje.

Integracja z katalogiem tozsamosci i z dostawca logowania OIDC sa opcjonalne.
Bez nich panel dziala na tokenach API i zarzadza kontami lokalnymi hostow.

%install
rm -rf %{buildroot}
install -d -m 0755 %{buildroot}%{_bindir}
install -m 0755 %{_flotestro_stage}/flotestro-control-plane %{buildroot}%{_bindir}/flotestro-control-plane

install -d -m 0755 %{buildroot}%{_unitdir}
install -m 0644 %{_flotestro_units}/flotestro-control-plane.service %{buildroot}%{_unitdir}/

install -d -m 0755 %{buildroot}%{_sysconfdir}/flotestro
install -m 0640 %{_flotestro_stage}/control-plane.env %{buildroot}%{_sysconfdir}/flotestro/control-plane.env

install -d -m 0700 %{buildroot}%{_sharedstatedir}/flotestro

# Panel webowy jest budowany osobno; pakiet niesie gotowe pliki.
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
# Konfiguracja nie moze zostac nadpisana przy aktualizacji: zawiera
# poswiadczenia do bazy i do dostawcy tozsamosci.
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
# Panel bez bazy nie ma gdzie trzymac stanu floty. Uruchamianie go w petli
# restartow zasmiecaloby dziennik; instalacja konczy sie wtedy wskazowka.
if grep -qs '^FLOTESTRO_DATABASE_URL=.*zmien-to' %{_sysconfdir}/flotestro/control-plane.env; then
    systemctl enable flotestro-control-plane.service || :
    echo "flotestro-control-plane: ustaw FLOTESTRO_DATABASE_URL w" >&2
    echo "  %{_sysconfdir}/flotestro/control-plane.env i uruchom" >&2
    echo "  systemctl start flotestro-control-plane.service" >&2
else
    systemctl enable --now flotestro-control-plane.service || :
fi

%preun
%systemd_preun flotestro-control-plane.service

%postun
%systemd_postun_with_restart flotestro-control-plane.service
# Katalog stanu z kluczem CA floty zostaje: bez niego zaden agent nie
# zostanie rozpoznany i cala flota wymaga ponownego enrollmentu.

%changelog
