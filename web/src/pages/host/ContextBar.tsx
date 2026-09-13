import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, type Collection } from "../../lib/api";
import type { Host, Job } from "../../lib/types";
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
        <OknoSerwisowe host={host} />
      </div>
      <div className="pasek-hosta-fakty">
        <span>{host.site} / {host.environment}</span>
        <span>{host.os_distribution || host.os_family || "unknown OS"} {host.os_version}</span>
        <span>{host.architecture || "unknown arch"} · agent {host.agent_version || "unknown"}</span>
        <span>seen <Czas wartosc={host.last_seen_at} /></span>
        <OdswiezInwentarz host={host} segment={segment} />
      </div>
      <PrzelacznikHosta host={host} segment={segment} instalacja={instalacja} />
    </div>
  );
}

/**
 * Odswiezenie inwentarza na zadanie.
 *
 * Panel pokazuje obraz sprzed ostatniego cyklu, wiec operator, ktory wlasnie
 * zmienil cos na hoscie recznie albo szykuje kampanie, musi umiec zapytac
 * "jak jest teraz". Przycisk jest w pasku, a nie w zakladce, bo dotyczy
 * calego hosta; zakres wynika z otwartej zakladki - odswiezamy to, na co
 * operator patrzy, a nie caly host przy kazdym kliknieciu.
 */
function OdswiezInwentarz({ host, segment }: { host: Host; segment: string }) {
  const queryClient = useQueryClient();
  const [zadanie, setZadanie] = useState("");
  const [komunikat, setKomunikat] = useState("");
  // Zakres bierzemy z rejestru zakladek: to on wie, z ktorego modulu
  // inwentarza zyje otwarty widok. Zakladka bez modulu (Jobs, Overview)
  // odswieza caly host - zawezenie do czegos, czego nie ma, nie odswiezyloby
  // niczego.
  const zakres = znajdzModul(segment)?.inwentarz;

  // Zadanie konczy sie dopiero po zapisaniu nowej rewizji, wiec przycisk
  // sledzi je do konca. Inaczej "odswiezono" znaczyloby tylko "zlecono",
  // a operator patrzylby na stary obraz w przekonaniu, ze jest nowy.
  const stan = useQuery({
    queryKey: ["job", zadanie],
    queryFn: () => api.get<Job>(`/api/v1/jobs/${zadanie}`),
    enabled: zadanie !== "",
    refetchInterval: (zapytanie) =>
      zakonczone((zapytanie.state.data as Job | undefined)?.state) ? false : 2000,
  });

  useEffect(() => {
    const wynik = stan.data;
    if (!wynik || !zakonczone(wynik.state)) return;
    setZadanie("");
    if (wynik.state !== "succeeded") {
      setKomunikat(wynik.result_error_code || wynik.result_message || wynik.state);
      return;
    }
    setKomunikat(wynik.result_message || "inventory refreshed");
    // Nowy obraz jest w panelu, wiec widoki tego hosta maja go pokazac.
    // Nie ma jednego klucza inwentarza: kazda zakladka czyta swoj, wiec
    // uniewazniamy wszystko, co dotyczy tej maszyny.
    queryClient.invalidateQueries({
      predicate: (zapytanie) => zapytanie.queryKey.includes(host.id),
    });
  }, [stan.data, host.id, queryClient]);

  const zlec = useMutation({
    mutationFn: () =>
      api.post<Job>(`/api/v1/hosts/${host.id}/operations`, {
        action: "inventory.refresh",
        payload: { inventory: zakres ? { modules: [zakres] } : {} },
      }),
    onSuccess: (nowe) => {
      setKomunikat("");
      setZadanie(nowe.id);
      queryClient.invalidateQueries({ queryKey: ["jobs", host.id] });
    },
    onError: (error) => setKomunikat(error instanceof Error ? error.message : String(error)),
  });

  const trwa = zlec.isPending || zadanie !== "";
  const opis = zakres
    ? `ask the host to re-read its ${zakres} module now`
    : "ask the host to re-read its whole inventory now";
  return (
    <span className="odswiezenie-inwentarza">
      <button
        type="button"
        className="link"
        disabled={trwa || host.connection_state !== "online"}
        title={host.connection_state === "online" ? opis : "the host is not connected"}
        onClick={() => zlec.mutate()}
      >
        {trwa ? "refreshing…" : "refresh"}
      </button>
      {komunikat && <span className="komunikat">{komunikat}</span>}
    </span>
  );
}

/** Stany koncowe zadania. Poza nimi warto pytac dalej. */
function zakonczone(stan: string | undefined): boolean {
  return ["succeeded", "failed", "timed_out", "canceled", "expired"].includes(stan ?? "");
}

/**
 * Znacznik okna serwisowego. Jest w pasku, a nie w zakladce zasilania, bo
 * dotyczy kazdej operacji na tym hoscie: kto zaczyna cokolwiek robic, ma
 * wiedziec, ze ktos inny juz przy tej maszynie pracuje.
 */
function OknoSerwisowe({ host }: { host: Host }) {
  if (!host.maintenance) return null;
  const doKiedy = new Date(host.maintenance.until);
  if (Number.isNaN(doKiedy.getTime()) || doKiedy.getTime() <= Date.now()) return null;
  const opis = [host.maintenance.reason, host.maintenance.set_by && `set by ${host.maintenance.set_by}`]
    .filter(Boolean)
    .join(" · ");
  return (
    <span className="znacznik uwaga" title={opis || "maintenance window"}>
      maintenance until {doKiedy.toISOString().slice(0, 16).replace("T", " ")} UTC
    </span>
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
