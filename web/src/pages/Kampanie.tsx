import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { api, type Collection } from "../lib/api";
import type { Campaign } from "../lib/types";
import { Blad, Czas, Pusto, StanZadania } from "../components/ui";

export function Kampanie() {
  const [budowanie, setBudowanie] = useState(false);
  const { data, error } = useQuery({
    queryKey: ["campaigns"],
    queryFn: () => api.get<Collection<Campaign>>("/api/v1/campaigns?limit=50"),
  });
  if (error) return <Blad error={error} />;

  return (
    <>
      <h1>Campaigns</h1>
      <p className="podtytul">Campaigns are the main mechanism for fleet-wide change.</p>

      <button onClick={() => setBudowanie(!budowanie)}>
        {budowanie ? "Ukryj kreator" : "New campaign"}
      </button>

      {budowanie && <Kreator onGotowe={() => setBudowanie(false)} />}

      <h2>List</h2>
      {!data?.items.length ? (
        <Pusto>No campaigns.</Pusto>
      ) : (
        <table>
          <thead>
            <tr><th>Name</th><th>State</th><th>Operation</th><th>Canary/wave</th><th>Requested by</th><th>Approved by</th><th>Created</th></tr>
          </thead>
          <tbody>
            {data.items.map((kampania) => (
              <tr key={kampania.id}>
                <td><Link to={`/campaigns/${kampania.id}`}>{kampania.name}</Link></td>
                <td><StanZadania stan={kampania.state} /></td>
                <td>{kampania.action_type}</td>
                <td>{kampania.canary_size} / {kampania.wave_size}</td>
                <td>{kampania.created_by}</td>
                <td>{kampania.approved_by || "—"}</td>
                <td><Czas wartosc={kampania.created_at} /></td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </>
  );
}

/** Operacja w rejestrze: to serwer mowi, co wolno robic masowo. */
type Operacja = {
  action: string;
  mutating: boolean;
  campaign_mode: string;
  campaign_ready: boolean;
};

/**
 * Operacje, dla ktorych kreator umie zbudowac payload. Rejestr moze
 * dopuszczac wiecej, niz ten formularz potrafi opisac - i wtedy operacja jest
 * widoczna, ale nieaktywna. Ukrycie jej wygladaloby jak brak funkcji.
 */
const OPERACJE_KREATORA = [
  "unit.start", "unit.stop", "unit.restart", "unit.reload", "packages.upgrade",
];

/** Operacje, ktore biora nazwe jednostki systemd. */
const OPERACJE_JEDNOSTKI = ["unit.start", "unit.stop", "unit.restart", "unit.reload"];

/**
 * Kreator kampanii. Ostatni krok pokazuje dokladnie, ile hostow zostanie
 * objetych zmiana, zanim cokolwiek powstanie.
 */
function Kreator({ onGotowe }: { onGotowe: () => void }) {
  const queryClient = useQueryClient();
  const [nazwa, setNazwa] = useState("");
  const [akcja, setAkcja] = useState("unit.restart");
  const [jednostka, setJednostka] = useState("");
  const [site, setSite] = useState("");
  const [environment, setEnvironment] = useState("");
  const [canary, setCanary] = useState(1);
  const [fala, setFala] = useState(5);
  const [rownolegle, setRownolegle] = useState(2);
  const [progProcent, setProgProcent] = useState(20);
  const [progLiczba, setProgLiczba] = useState(0);
  const [politykaRestartu, setPolitykaRestartu] = useState("never");
  const [tylkoBezpieczenstwo, setTylkoBezpieczenstwo] = useState(true);
  const [blad, setBlad] = useState("");

  // Lista operacji masowych pochodzi z serwera, a nie z tego pliku. To rejestr
  // operacji decyduje, co wolno robic cala flota, i to on wie, ze nowa
  // operacja nie otwiera sie masowo sama z siebie.
  const operacje = useQuery({
    queryKey: ["actions"],
    queryFn: () => api.get<{ items: Operacja[] }>("/api/v1/actions"),
  });
  const masowe = (operacje.data?.items ?? []).filter((pozycja) => pozycja.campaign_ready);

  // Podglad celow: liczbe liczy serwer, a nie dlugosc pierwszej strony listy
  // hostow. Operator zatwierdza zmiane na tylu maszynach, ile mu pokazano.
  const parametry = new URLSearchParams();
  if (site) parametry.set("site", site);
  if (environment) parametry.set("environment", environment);
  const podglad = useQuery({
    queryKey: ["campaign-preview", parametry.toString()],
    queryFn: () =>
      api.get<{ count: number; sample: string[]; limit: number }>(
        `/api/v1/campaigns/preview?${parametry}`,
      ),
  });

  const utworz = useMutation({
    mutationFn: () =>
      api.post<Campaign>("/api/v1/campaigns", {
        name: nazwa,
        action: akcja,
        payload: OPERACJE_JEDNOSTKI.includes(akcja)
          ? { unit: { unit: jednostka } }
          : { package_upgrade: { security_only: tylkoBezpieczenstwo } },
        selector: { site: site || undefined, environment: environment || undefined },
        canary_size: canary,
        wave_size: fala,
        max_concurrent: rownolegle,
        failure_threshold_percent: progProcent,
        failure_threshold_absolute: progLiczba,
        reboot_policy: politykaRestartu,
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["campaigns"] });
      onGotowe();
    },
    onError: (error) => setBlad(error instanceof Error ? error.message : String(error)),
  });

  const liczbaCelow = podglad.data?.count ?? 0;
  const probka = podglad.data?.sample ?? [];
  const wymagaJednostki = OPERACJE_JEDNOSTKI.includes(akcja);
  const gotowe = nazwa && (!wymagaJednostki || jednostka) && liczbaCelow > 0;

  return (
    <div className="kafelek" style={{ marginTop: 16, maxWidth: 760 }}>
      <h2 style={{ marginTop: 0 }}>New campaign</h2>
      <div className="filtry">
        <input placeholder="campaign name" value={nazwa} onChange={(e) => setNazwa(e.target.value)} style={{ minWidth: 240 }} />
        <select value={akcja} onChange={(e) => setAkcja(e.target.value)}>
          {masowe.map((pozycja) => (
            <option
              key={pozycja.action}
              value={pozycja.action}
              disabled={!OPERACJE_KREATORA.includes(pozycja.action)}
            >
              {pozycja.action}
              {OPERACJE_KREATORA.includes(pozycja.action) ? "" : " — no bulk form yet"}
            </option>
          ))}
        </select>
        {wymagaJednostki ? (
          <input placeholder="unit, e.g. cron.service" value={jednostka} onChange={(e) => setJednostka(e.target.value)} />
        ) : (
          <label>
            <input
              type="checkbox"
              checked={tylkoBezpieczenstwo}
              onChange={(e) => setTylkoBezpieczenstwo(e.target.checked)}
            />{" "}
            security updates only
          </label>
        )}
      </div>
      {/* Operacja, ktora liczy inny plan na kazdym hoscie, przechodzi przez
          faze planowania - a nie udaje jednego payloadu. Operacje, dla ktorych
          panel nie ma jeszcze plannera, nie sa ukryte: sa odmowione z powodem. */}
      <p className="podtytul">
        {wymagaJednostki
          ? "The same payload means the same thing on every host; each host still runs its own preflight."
          : "Every host computes its own plan first. You approve the set of plans, not one payload, and a host whose plan changed in the meantime refuses the change."}
      </p>
      <div className="filtry">
        <input placeholder="site" value={site} onChange={(e) => setSite(e.target.value)} />
        <input placeholder="environment" value={environment} onChange={(e) => setEnvironment(e.target.value)} />
      </div>
      <div className="filtry">
        <label>canary <input type="number" min={0} value={canary} onChange={(e) => setCanary(+e.target.value)} style={{ width: 70 }} /></label>
        <label>wave <input type="number" min={1} value={fala} onChange={(e) => setFala(+e.target.value)} style={{ width: 70 }} /></label>
        <label>concurrent <input type="number" min={1} value={rownolegle} onChange={(e) => setRownolegle(+e.target.value)} style={{ width: 70 }} /></label>
        <label>threshold % <input type="number" min={0} max={100} value={progProcent} onChange={(e) => setProgProcent(+e.target.value)} style={{ width: 70 }} /></label>
        <label>threshold count <input type="number" min={0} value={progLiczba} onChange={(e) => setProgLiczba(+e.target.value)} style={{ width: 70 }} /></label>
        <select value={politykaRestartu} onChange={(e) => setPolitykaRestartu(e.target.value)}>
          <option value="never">reboot: never</option>
          <option value="if_required">reboot: when required</option>
          <option value="always">reboot: always</option>
        </select>
      </div>

      <h2>Cele</h2>
      {podglad.isLoading ? (
        <Pusto>Counting targets…</Pusto>
      ) : (
        <>
          <p className="podtytul">
            The selector matches <strong>{liczbaCelow}</strong> hosts. The snapshot is taken
            when the campaign is created; hosts added later will not join it.
          </p>
          <div className="zrodlo">
            {probka.join(", ")}
            {liczbaCelow > probka.length && ` i ${liczbaCelow - probka.length} wiecej`}
          </div>
        </>
      )}

      {blad && <p className="blad-strony" style={{ marginTop: 12 }}>{blad}</p>}
      <div style={{ marginTop: 16 }}>
        <button onClick={() => utworz.mutate()} disabled={!gotowe || utworz.isPending}>
          {utworz.isPending ? "Creating…" : `Utworz kampanie na ${liczbaCelow} hostach`}
        </button>{" "}
        <button className="wtorny" onClick={onGotowe}>Cancel</button>
      </div>
    </div>
  );
}
