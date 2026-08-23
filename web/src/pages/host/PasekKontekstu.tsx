import { useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api, type Collection } from "../../lib/api";
import type { Host } from "../../lib/types";
import { Czas, StanPolaczenia } from "../../components/ui";
import { modul as znajdzModul, MODUL_DOMYSLNY } from "./moduly";
import type { Capabilities as ZdolnosciInstalacji } from "../../lib/capabilities";

/**
 * Staly pasek kontekstu hosta. Operator zmieniajacy zakladki musi bez
 * sprawdzania czegokolwiek wiedziec, na ktorej maszynie pracuje - dlatego
 * tozsamosc celu jest czescia layoutu, a nie tekstem powtarzanym przez
 * poszczegolne ekrany.
 */
export function PasekKontekstu({
  host, segment, instalacja,
}: { host: Host; segment: string; instalacja: ZdolnosciInstalacji }) {
  return (
    <div className="pasek-hosta">
      <div className="pasek-hosta-tozsamosc">
        <StanPolaczenia stan={host.connection_state} />
        <span className="nazwa">{host.hostname}</span>
        <AdresZarzadzania host={host} />
      </div>
      <div className="pasek-hosta-fakty">
        <span>{host.site} / {host.environment}</span>
        <span>{host.os_distribution || host.os_family || "unknown OS"} {host.os_version}</span>
        <span>{host.architecture || "unknown arch"} · agent {host.agent_version || "unknown"}</span>
        <span>seen <Czas wartosc={host.last_seen_at} /></span>
      </div>
      <PrzelacznikHosta host={host} segment={segment} instalacja={instalacja} />
    </div>
  );
}

/**
 * Adres zarzadzania z jego pochodzeniem. Nieustalony adres jest pokazywany
 * jako nieustalony: host moze miec wiele adresow i podanie dowolnego z nich
 * jako adresu zarzadzania wprowadzaloby operatora w blad.
 */
function AdresZarzadzania({ host }: { host: Host }) {
  if (!host.management_address) {
    return (
      <span className="znacznik nieznany" title="no address has been observed for this host yet">
        address unknown
      </span>
    );
  }
  const opis =
    host.management_address_source === "session"
      ? "address seen by the control plane on its end of the connection"
      : host.management_address_source === "agent"
        ? "address reported by the host itself; it connects through a relay"
        : "address set manually by an operator";
  return (
    <span className="adres" title={opis}>
      {host.management_address}
      <span className="zrodlo-adresu">{host.management_address_source}</span>
    </span>
  );
}

/**
 * Przelacznik hostow zachowuje otwarty modul, jesli nowy host go obsluguje.
 * W przeciwnym razie prowadzi do przegladu i mowi, czego zabraklo - cicha
 * zmiana zakladki wygladalaby jak blad interfejsu.
 */
function PrzelacznikHosta({
  host, segment, instalacja,
}: { host: Host; segment: string; instalacja: ZdolnosciInstalacji }) {
  const navigate = useNavigate();
  const lista = useQuery({
    queryKey: ["hosts", "switcher"],
    queryFn: () => api.get<Collection<Host>>("/api/v1/hosts?limit=500"),
    staleTime: 30_000,
  });

  function przelacz(id: string) {
    if (!id || id === host.id) return;
    const cel = lista.data?.items.find((pozycja) => pozycja.id === id);
    const otwarty = znajdzModul(segment);
    const powod = cel && otwarty ? otwarty.powod(cel, instalacja) : "";
    if (powod) {
      navigate(`/hosts/${id}/${MODUL_DOMYSLNY}`, {
        state: { odrzucony: otwarty?.nazwa, powod },
      });
      return;
    }
    navigate(`/hosts/${id}/${segment}`);
  }

  return (
    <label className="przelacznik-hosta">
      <span>Switch host</span>
      <select value={host.id} onChange={(event) => przelacz(event.target.value)}>
        {(lista.data?.items ?? [host]).map((pozycja) => (
          <option key={pozycja.id} value={pozycja.id}>
            {pozycja.hostname}
          </option>
        ))}
      </select>
    </label>
  );
}
