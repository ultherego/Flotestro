import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../../lib/api";
import type { Job } from "../../lib/types";
import { Blad, Czas, Pusto } from "../../components/ui";
import { useHost } from "./wspolne";

type Zrodlo = {
  name: string;
  configured: boolean;
  healthy: boolean;
  url?: string;
  reason?: string;
  latency_millis?: number;
  checked_at?: string;
};

type Alert = {
  name: string;
  severity?: string;
  state?: string;
  summary?: string;
  description?: string;
  labels?: Record<string, string>;
  starts_at?: string;
  silenced_by?: string[];
  generator_url?: string;
};

type Cisza = {
  id: string;
  starts_at: string;
  ends_at: string;
  created_by: string;
  comment: string;
  status?: string;
  matchers?: { name: string; value: string }[];
};

type Punkt = { at: string; value: number };

type Szereg = {
  name: string;
  unit?: string;
  points?: Punkt[];
  last?: number;
  query?: string;
  unavailable_reason?: string;
};

type Raport = {
  host_id: string;
  sources: Zrodlo[];
  label: string;
  links: { dashboard?: string; logs?: string };
  alerts: Alert[];
  silences: Cisza[];
  series: Szereg[];
  from: string;
  to: string;
  alerts_unavailable_reason?: string;
  metrics_unavailable_reason?: string;
};

type WynikSondy = {
  kind: string;
  target: string;
  reachable: boolean;
  passed: boolean;
  status_code?: number;
  duration_millis: number;
  body_matched?: boolean;
  tls_expiry?: string;
  tls_issuer?: string;
  error?: string;
};

type Proba = { status?: string; message?: string; detail?: { probe?: WynikSondy } };

/**
 * Wykres z punktow. Prosty, bo ma odpowiadac na jedno pytanie: czy w tym
 * oknie czasu cos sie zmienilo. Po szczegoly panel prowadzi do dashboardu -
 * nie udaje wlasnej bazy szeregow czasowych.
 */
function Iskra({ szereg }: { szereg: Szereg }) {
  const punkty = szereg.points ?? [];
  if (szereg.unavailable_reason) {
    return <span className="znacznik nieznany">{szereg.unavailable_reason}</span>;
  }
  if (!punkty.length) {
    return <span className="znacznik nieznany">no data in this window</span>;
  }
  const wartosci = punkty.map((punkt) => punkt.value);
  const minimum = Math.min(...wartosci);
  const maksimum = Math.max(...wartosci);
  const zakres = maksimum - minimum || 1;
  const szerokosc = 240;
  const wysokosc = 40;
  const sciezka = punkty
    .map((punkt, indeks) => {
      const x = (indeks / Math.max(1, punkty.length - 1)) * szerokosc;
      const y = wysokosc - ((punkt.value - minimum) / zakres) * wysokosc;
      return `${indeks === 0 ? "M" : "L"}${x.toFixed(1)},${y.toFixed(1)}`;
    })
    .join(" ");
  return (
    <svg width={szerokosc} height={wysokosc} role="img" aria-label={szereg.name}>
      <path d={sciezka} fill="none" stroke="currentColor" strokeWidth="1.5" />
    </svg>
  );
}

/**
 * Monitoring hosta.
 *
 * Panel nie ma wlasnych metryk ani wlasnych regul alertowych: czyta cudze
 * i mowi, skad je wzial oraz z jakiego okna czasu. Awaria monitoringu nie
 * moze zabrac operatorowi zarzadzania hostem, wiec kazde pytanie ma limit
 * czasu, a zrodlo, ktore milczy, jest opisane wprost.
 */
export function Monitoring() {
  const host = useHost();
  const queryClient = useQueryClient();
  const [okno, setOkno] = useState("3h");
  const [komunikat, setKomunikat] = useState("");
  const [powodCiszy, setPowodCiszy] = useState("");
  const [minuty, setMinuty] = useState("120");
  const [sonda, setSonda] = useState("");
  const [zadanieSondy, setZadanieSondy] = useState("");

  const raport = useQuery({
    queryKey: ["monitoring", host.id, okno],
    queryFn: () => api.get<Raport>(`/api/v1/hosts/${host.id}/monitoring?range=${okno}`),
    refetchInterval: 30000,
  });

  const wyniki = useQuery({
    queryKey: ["job-attempts", zadanieSondy],
    queryFn: () => api.get<{ items: Proba[] }>(`/api/v1/jobs/${zadanieSondy}/attempts`),
    enabled: zadanieSondy !== "",
    refetchInterval: (zapytanie) => {
      const proby = (zapytanie.state.data as { items?: Proba[] } | undefined)?.items;
      return proby?.[proby.length - 1]?.status ? false : 2000;
    },
  });
  const proby = wyniki.data?.items ?? [];
  const wynikSondy = proby[proby.length - 1]?.detail?.probe;

  const ucisz = useMutation({
    mutationFn: (tresc: Record<string, unknown>) =>
      api.post<Cisza>(`/api/v1/hosts/${host.id}/monitoring/silences`, tresc),
    onSuccess: (cisza) => {
      setKomunikat(`Silence ${cisza.id.slice(0, 8)} runs until ${new Date(cisza.ends_at).toLocaleString()}.`);
      setPowodCiszy("");
      queryClient.invalidateQueries({ queryKey: ["monitoring", host.id] });
    },
    onError: (error) => setKomunikat(error instanceof Error ? error.message : String(error)),
  });

  const odcisz = useMutation({
    mutationFn: (id: string) =>
      api.del(`/api/v1/hosts/${host.id}/monitoring/silences/${encodeURIComponent(id)}`),
    onSuccess: () => {
      setKomunikat("Silence ended.");
      queryClient.invalidateQueries({ queryKey: ["monitoring", host.id] });
    },
    onError: (error) => setKomunikat(error instanceof Error ? error.message : String(error)),
  });

  const zlecSonde = useMutation({
    mutationFn: (cel: string) =>
      api.post<Job>(`/api/v1/hosts/${host.id}/operations`, {
        action: "monitoring.probe.run",
        payload: {
          monitoring: {
            kind: cel.startsWith("http") ? "http" : "tcp",
            target: cel,
          },
        },
      }),
    onSuccess: (zadanie) => {
      setZadanieSondy(zadanie.id);
      setKomunikat(`Probe queued as job ${zadanie.id.slice(0, 8)}.`);
    },
    onError: (error) => setKomunikat(error instanceof Error ? error.message : String(error)),
  });

  if (raport.error) return <Blad error={raport.error} />;
  const dane = raport.data;

  return (
    <>
      <p className="podtytul">
        Metrics and alerts come from the systems that already collect them. The
        panel shows where each number is from and for what window of time — it
        has no time series database of its own, and no alerting rules of its own.
      </p>

      <div className="filtry">
        {(dane?.sources ?? []).map((zrodlo) => (
          <span
            key={zrodlo.name}
            className={`znacznik ${!zrodlo.configured ? "nieznany" : zrodlo.healthy ? "ok" : "blad"}`}
            title={zrodlo.reason || zrodlo.url}
          >
            {zrodlo.name}
            {!zrodlo.configured
              ? " · not configured"
              : zrodlo.healthy
                ? ` · ${zrodlo.latency_millis ?? "?"} ms`
                : " · not answering"}
          </span>
        ))}
        {dane?.label && <span className="zrodlo">seen as {dane.label}</span>}
        {dane?.links.dashboard && (
          <a href={dane.links.dashboard} target="_blank" rel="noreferrer">Dashboard</a>
        )}
        {dane?.links.logs && (
          <a href={dane.links.logs} target="_blank" rel="noreferrer">Logs</a>
        )}
        <select value={okno} onChange={(e) => setOkno(e.target.value)}>
          <option value="1h">last hour</option>
          <option value="3h">last 3 hours</option>
          <option value="12h">last 12 hours</option>
          <option value="24h">last day</option>
        </select>
      </div>
      {komunikat && <p className="zrodlo" style={{ marginBottom: 12 }}>{komunikat}</p>}

      <h2>Active alerts</h2>
      {dane?.alerts_unavailable_reason ? (
        <p className="ostrzezenie">
          <span>Alerts could not be read: {dane.alerts_unavailable_reason}</span>
        </p>
      ) : !(dane?.alerts ?? []).length ? (
        <Pusto>No alert is firing for this host.</Pusto>
      ) : (
        <table>
          <thead>
            <tr><th>Alert</th><th>Severity</th><th>Since</th><th>Summary</th><th>Silence</th></tr>
          </thead>
          <tbody>
            {(dane?.alerts ?? []).map((alert, indeks) => (
              <tr key={`${alert.name}-${indeks}`}>
                <td>
                  {alert.generator_url ? (
                    <a href={alert.generator_url} target="_blank" rel="noreferrer">{alert.name}</a>
                  ) : (
                    alert.name
                  )}
                  {alert.silenced_by?.length ? (
                    <div className="zrodlo">silenced</div>
                  ) : null}
                </td>
                <td>
                  <span
                    className={`znacznik ${alert.severity === "critical" ? "blad" : alert.severity === "warning" ? "uwaga" : ""}`}
                  >
                    {alert.severity || "unknown"}
                  </span>
                </td>
                <td><Czas wartosc={alert.starts_at} /></td>
                <td className="zrodlo">{alert.summary || alert.description}</td>
                <td>
                  <button
                    className="wtorny"
                    disabled={powodCiszy.trim().length < 8 || ucisz.isPending}
                    onClick={() =>
                      ucisz.mutate({
                        duration_minutes: Number(minuty) || 0,
                        comment: powodCiszy,
                        alert_name: alert.name,
                      })
                    }
                  >
                    Silence this
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      <div className="formularz" style={{ marginTop: 12 }}>
        <h2>Silence</h2>
        <p className="podtytul" style={{ margin: 0 }}>
          A silence turns a sensor off, so it always ends: no open-ended silences
          from here, at most a day, and always with a reason and an owner in the
          audit trail.
        </p>
        <div className="filtry">
          <input value={powodCiszy} onChange={(e) => setPowodCiszy(e.target.value)}
                 placeholder="Reason (at least 8 characters)" style={{ minWidth: 320 }} />
          <input value={minuty} onChange={(e) => setMinuty(e.target.value)}
                 placeholder="Minutes" style={{ width: 110 }} />
          <button
            disabled={powodCiszy.trim().length < 8 || ucisz.isPending}
            onClick={() => ucisz.mutate({ duration_minutes: Number(minuty) || 0, comment: powodCiszy })}
          >
            Silence every alert of this host
          </button>
        </div>
      </div>

      {(dane?.silences ?? []).length > 0 && (
        <>
          <h2>Silences in force</h2>
          <table>
            <thead>
              <tr><th>Until</th><th>Scope</th><th>Reason</th><th>By</th><th></th></tr>
            </thead>
            <tbody>
              {(dane?.silences ?? []).map((cisza) => (
                <tr key={cisza.id}>
                  <td><Czas wartosc={cisza.ends_at} /></td>
                  <td className="zrodlo">
                    {(cisza.matchers ?? []).map((m) => `${m.name}="${m.value}"`).join(", ")}
                  </td>
                  <td>{cisza.comment}</td>
                  <td className="zrodlo">{cisza.created_by}</td>
                  <td>
                    <button className="wtorny" onClick={() => odcisz.mutate(cisza.id)}>
                      End now
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}

      <h2>Metrics</h2>
      {dane?.metrics_unavailable_reason ? (
        <Pusto>{dane.metrics_unavailable_reason}</Pusto>
      ) : (
        <>
          <table>
            <thead><tr><th>Series</th><th>Last</th><th>Window</th><th>Query</th></tr></thead>
            <tbody>
              {(dane?.series ?? []).map((szereg) => (
                <tr key={szereg.name}>
                  <td>{szereg.name}</td>
                  <td>
                    {szereg.last === undefined
                      ? <span className="znacznik nieznany">unknown</span>
                      : `${szereg.last.toFixed(2)}${szereg.unit ?? ""}`}
                  </td>
                  <td><Iskra szereg={szereg} /></td>
                  <td className="zrodlo" style={{ maxWidth: 420, overflowWrap: "anywhere" }}>
                    {szereg.query}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {dane && (
            <p className="zrodlo">
              Source: {(dane.sources.find((z) => z.name === "prometheus")?.url) || "—"} ·
              window <Czas wartosc={dane.from} /> to <Czas wartosc={dane.to} />
            </p>
          )}
        </>
      )}

      <h2>Probe from this host</h2>
      <p className="podtytul">
        What the host itself sees. An alert can say a service is down while it
        answers from here — and then the problem is the network between them,
        not the service.
      </p>
      <div className="filtry">
        <input value={sonda} onChange={(e) => setSonda(e.target.value)}
               placeholder="https://service.example.test/health or db.example.test:5432"
               style={{ minWidth: 380 }} />
        <button
          disabled={!sonda || zlecSonde.isPending || host.connection_state !== "online"}
          onClick={() => zlecSonde.mutate(sonda)}
        >
          Probe
        </button>
      </div>
      {wynikSondy && (
        <table>
          <tbody>
            <tr>
              <td>Result</td>
              <td>
                {wynikSondy.passed ? (
                  <span className="znacznik ok">as expected</span>
                ) : wynikSondy.reachable ? (
                  <span className="znacznik uwaga">answers, but not as expected</span>
                ) : (
                  <span className="znacznik blad">no answer</span>
                )}
              </td>
            </tr>
            <tr><td>Target</td><td className="zrodlo">{wynikSondy.target}</td></tr>
            <tr><td>Took</td><td>{wynikSondy.duration_millis} ms</td></tr>
            {wynikSondy.status_code !== undefined && (
              <tr><td>Status</td><td>{wynikSondy.status_code}</td></tr>
            )}
            {wynikSondy.tls_expiry && (
              <tr>
                <td>Certificate</td>
                <td>
                  valid until <Czas wartosc={wynikSondy.tls_expiry} />
                  <div className="zrodlo">{wynikSondy.tls_issuer}</div>
                </td>
              </tr>
            )}
            {wynikSondy.error && <tr><td>Detail</td><td className="zrodlo">{wynikSondy.error}</td></tr>}
          </tbody>
        </table>
      )}
    </>
  );
}
