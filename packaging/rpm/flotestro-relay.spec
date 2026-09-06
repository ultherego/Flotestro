Name:           flotestro-relay
Version:        %{?_flotestro_version}%{!?_flotestro_version:0.1.0}
Release:        1%{?dist}
Summary:        Relay lokalizacji Flotestro
License:        Proprietary
URL:            https://github.com/ultherego/flotestro
BuildArch:      %{_target_cpu}

Requires:       systemd
Requires(post): systemd, shadow-utils
Requires(preun): systemd

# Binarki sa budowane wczesniej i podawane katalogiem; spec nie kompiluje
# kodu, zeby pakiet powstawal z dokladnie tych samych artefaktow, ktore
# przeszly testy.
%global _build_id_links none
%global __strip /bin/true

%description
Relay posredniczy miedzy agentami jednej lokalizacji a centrala: utrzymuje
jedno polaczenie w gore zamiast setek, buforuje wyniki na czas awarii lacza
i nie przekazuje zadan, ktorym uplynal czas zycia.

Relay jest osobna granica zaufania. Ma wlasny certyfikat innego rodzaju niz
certyfikat hosta, wlasne konto uslugowe i wlasny katalog stanu; nie podpisuje
zadnego certyfikatu i nie wykonuje operacji na hostach.

%install
rm -rf %{buildroot}
install -d -m 0755 %{buildroot}%{_bindir}
install -m 0755 %{_flotestro_stage}/flotestro-relay %{buildroot}%{_bindir}/flotestro-relay

install -d -m 0755 %{buildroot}%{_unitdir}
install -m 0644 %{_flotestro_units}/flotestro-relay.service %{buildroot}%{_unitdir}/

install -d -m 0755 %{buildroot}%{_sysconfdir}/flotestro
install -m 0640 %{_flotestro_stage}/relay.yaml %{buildroot}%{_sysconfdir}/flotestro/relay.yaml

install -d -m 0700 %{buildroot}%{_sharedstatedir}/flotestro-relay

%files
%{_bindir}/flotestro-relay
%{_unitdir}/flotestro-relay.service
%dir %{_sysconfdir}/flotestro
# Konfiguracja nie moze zostac nadpisana przy aktualizacji: zawiera adresy
# centrali i nazwy, pod ktorymi relay wystepuje wobec agentow.
%config(noreplace) %attr(0640, root, flotestro-relay) %{_sysconfdir}/flotestro/relay.yaml
%dir %attr(0700, flotestro-relay, flotestro-relay) %{_sharedstatedir}/flotestro-relay

%pre
# Konto uslugowe osobne od konta agenta: na maszynie relaya moze stac takze
# zwykly agent, a jego tozsamosc nie moze byc czytelna dla relaya.
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
    echo "flotestro-relay: uzupelnij %{_sysconfdir}/flotestro/relay.yaml i zarejestruj relay" >&2
    echo "  sudo -u flotestro-relay flotestro-relay enroll -token-file <plik>" >&2
    echo "  systemctl start flotestro-relay.service" >&2
fi

%preun
%systemd_preun flotestro-relay.service

%postun
%systemd_postun_with_restart flotestro-relay.service
# Tozsamosc relaya zostaje przy aktualizacji i przy zwyklym usunieciu:
# ponowna instalacja ma ja odzyskac bez enrollmentu.

%changelog
