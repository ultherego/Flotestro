import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { api, type Collection } from "../lib/api";
import type { Campaign, Host } from "../lib/types";
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
      <h1>Kampanie</h1>
      <p className="podtytul">Kampania jest glownym mechanizmem zmian flotowych.</p>

      <button onClick={() => setBudowanie(!budowanie)}>
        {budowanie ? "Ukryj kreator" : "Nowa kampania"}
      </button>

      {budowanie && <Kreator onGotowe={() => setBudowanie(false)} />}

      <h2>Lista</h2>
      {!data?.items.length ? (
        <Pusto>Brak kampanii.</Pusto>
      ) : (
        <table>
          <thead>
            <tr><th>Nazwa</th><th>Stan</th><th>Operacja</th><th>Canary/fala</th><th>Zlecil</th><th>Zatwierdzil</th><th>Utworzona</th></tr>
          </thead>
          <tbody>
            {data.items.map((kampania) => (
              <tr key={kampania.id}>
                <td><Link to={`/kampanie/${kampania.id}`}>{kampania.name}</Link></td>
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
  const [blad, setBlad] = useState("");

  // Podglad celow: operator widzi liste hostow przed utworzeniem kampanii.
  const parametry = new URLSearchParams({ limit: "500" });
  if (site) parametry.set("site", site);
  if (environment) parametry.set("environment", environment);
  const podglad = useQuery({
    queryKey: ["hosts", "preview", parametry.toString()],
    queryFn: () => api.get<Collection<Host>>(`/api/v1/hosts?${parametry}`),
  });

  const utworz = useMutation({
    mutationFn: () =>
      api.post<Campaign>("/api/v1/campaigns", {
        name: nazwa,
        action: akcja,
        payload: akcja === "unit.restart" ? { unit: { unit: jednostka } } : { package_upgrade: {} },
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
  const gotowe = nazwa && (akcja !== "unit.restart" || jednostka) && liczbaCelow > 0;

  return (
    <div className="kafelek" style={{ marginTop: 16, maxWidth: 760 }}>
      <h2 style={{ marginTop: 0 }}>Nowa kampania</h2>
      <div className="filtry">
        <input placeholder="nazwa kampanii" value={nazwa} onChange={(e) => setNazwa(e.target.value)} style={{ minWidth: 240 }} />
        <select value={akcja} onChange={(e) => setAkcja(e.target.value)}>
          <option value="unit.restart">unit.restart</option>
          <option value="packages.upgrade">packages.upgrade</option>
        </select>
        {akcja === "unit.restart" && (
          <input placeholder="jednostka, np. cron.service" value={jednostka} onChange={(e) => setJednostka(e.target.value)} />
        )}
      </div>
      <div className="filtry">
        <input placeholder="lokalizacja" value={site} onChange={(e) => setSite(e.target.value)} />
        <input placeholder="srodowisko" value={environment} onChange={(e) => setEnvironment(e.target.value)} />
      </div>
      <div className="filtry">
        <label>canary <input type="number" min={0} value={canary} onChange={(e) => setCanary(+e.target.value)} style={{ width: 70 }} /></label>
        <label>fala <input type="number" min={1} value={fala} onChange={(e) => setFala(+e.target.value)} style={{ width: 70 }} /></label>
        <label>rownolegle <input type="number" min={1} value={rownolegle} onChange={(e) => setRownolegle(+e.target.value)} style={{ width: 70 }} /></label>
        <label>prog % <input type="number" min={0} max={100} value={progProcent} onChange={(e) => setProgProcent(+e.target.value)} style={{ width: 70 }} /></label>
        <label>prog szt. <input type="number" min={0} value={progLiczba} onChange={(e) => setProgLiczba(+e.target.value)} style={{ width: 70 }} /></label>
        <select value={politykaRestartu} onChange={(e) => setPolitykaRestartu(e.target.value)}>
          <option value="never">restart: nigdy</option>
          <option value="if_required">restart: gdy wymagany</option>
          <option value="always">restart: zawsze</option>
        </select>
      </div>

      <h2>Cele</h2>
      {podglad.isLoading ? (
        <Pusto>Liczenie celow…</Pusto>
      ) : (
        <>
          <p className="podtytul">
            Selektor obejmuje <strong>{liczbaCelow}</strong> hostow. Migawka powstanie w chwili
            utworzenia kampanii; hosty dodane pozniej do niej nie wejda.
          </p>
          <div className="zrodlo">
            {(podglad.data?.items ?? []).slice(0, 12).map((host) => host.hostname).join(", ")}
            {liczbaCelow > 12 && ` i ${liczbaCelow - 12} wiecej`}
          </div>
        </>
      )}

      {blad && <p className="blad-strony" style={{ marginTop: 12 }}>{blad}</p>}
      <div style={{ marginTop: 16 }}>
        <button onClick={() => utworz.mutate()} disabled={!gotowe || utworz.isPending}>
          {utworz.isPending ? "Tworzenie…" : `Utworz kampanie na ${liczbaCelow} hostach`}
        </button>{" "}
        <button className="wtorny" onClick={onGotowe}>Anuluj</button>
      </div>
    </div>
  );
}
