Name:           flotestro-agent
Version:        %{?_flotestro_version}%{!?_flotestro_version:0.1.0}
Release:        1%{?dist}
Summary:        Agent floty Flotestro
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
Agent laczy hosta z panelem zarzadzania flota Linux. Utrzymuje sesje mTLS
do control plane, raportuje inventory i wykonuje wylacznie operacje typowane
- kontrakt nie zna pola z dowolnym poleceniem powloki.

Operacje wymagajace roota realizuje osobny proces pomocniczy uruchamiany
przez gniazdo systemd, ktory weryfikuje wolajacego po SO_PEERCRED. Sam agent
dziala bez uprawnien roota.

%install
rm -rf %{buildroot}
install -d -m 0755 %{buildroot}%{_bindir}
install -m 0755 %{_flotestro_stage}/flotestro-agent        %{buildroot}%{_bindir}/flotestro-agent
install -m 0755 %{_flotestro_stage}/flotestro-agent-helper %{buildroot}%{_bindir}/flotestro-agent-helper

install -d -m 0755 %{buildroot}%{_unitdir}
install -m 0644 %{_flotestro_units}/flotestro-agent.service  %{buildroot}%{_unitdir}/
install -m 0644 %{_flotestro_units}/flotestro-helper.service %{buildroot}%{_unitdir}/
install -m 0644 %{_flotestro_units}/flotestro-helper.socket  %{buildroot}%{_unitdir}/

install -d -m 0755 %{buildroot}%{_sysconfdir}/flotestro
install -m 0640 %{_flotestro_stage}/agent.env %{buildroot}%{_sysconfdir}/flotestro/agent.env

install -d -m 0700 %{buildroot}%{_sharedstatedir}/flotestro-agent

%files
%{_bindir}/flotestro-agent
%{_bindir}/flotestro-agent-helper
%{_unitdir}/flotestro-agent.service
%{_unitdir}/flotestro-helper.service
%{_unitdir}/flotestro-helper.socket
%dir %{_sysconfdir}/flotestro
# Konfiguracja nie moze zostac nadpisana przy aktualizacji: zawiera adres
# panelu i token enrollmentu tego hosta.
%config(noreplace) %attr(0640, root, flotestro-agent) %{_sysconfdir}/flotestro/agent.env
%dir %attr(0700, flotestro-agent, flotestro-agent) %{_sharedstatedir}/flotestro-agent

%pre
# Konto uslugowe bez powloki i bez katalogu domowego: agent nie jest
# tozsamoscia, ktora ktokolwiek loguje sie na hoscie.
getent group flotestro-agent >/dev/null || groupadd --system flotestro-agent
getent passwd flotestro-agent >/dev/null || \
    useradd --system --gid flotestro-agent --no-create-home \
        --home-dir %{_sharedstatedir}/flotestro-agent --shell /sbin/nologin \
        flotestro-agent
exit 0

%post
# Odczyt dziennika bez roota wymaga czlonkostwa w grupie systemd-journal.
# Brak grupy nie jest bledem instalacji - odczyt dziennika bedzie wtedy
# niedostepny, a agent to zglosi zamiast udawac, ze dziennik jest pusty.
if getent group systemd-journal >/dev/null; then
    usermod --append --groups systemd-journal flotestro-agent || :
fi
%systemd_post flotestro-agent.service flotestro-helper.socket
# Gniazdo helpera musi istniec, zanim agent sprobuje sie z nim polaczyc.
systemctl enable --now flotestro-helper.socket || :

# Agent bez adresu panelu nie ma dokad sie polaczyc. Uruchamianie go w petli
# restartow zasmiecaloby dziennik hosta; instalacja konczy sie wtedy
# wskazowka, a nie cichym bledem.
if grep -qs '^FLOTESTRO_GATEWAY_URL=.\+' %{_sysconfdir}/flotestro/agent.env; then
    systemctl enable --now flotestro-agent.service || :
else
    systemctl enable flotestro-agent.service || :
    echo "flotestro-agent: uzupelnij %{_sysconfdir}/flotestro/agent.env i uruchom" >&2
    echo "  systemctl start flotestro-agent.service" >&2
fi

%preun
%systemd_preun flotestro-agent.service flotestro-helper.socket

%postun
%systemd_postun_with_restart flotestro-agent.service
# Tozsamosc agenta i klucz prywatny zostaja przy aktualizacji i przy zwyklym
# usunieciu: ponowna instalacja ma odzyskac te sama tozsamosc bez enrollmentu.

%changelog
