import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api } from "../lib/api";
import { Blad, Czas, Pusto } from "../components/ui";

type Zrodlo = {
  name: string;
  configured: boolean;
  healthy: boolean;
  url?: string;
  reason?: string;
  latency_millis?: number;
};

type Pozycja = {
  host_id?: string;
  hostname?: string;
  alert: {
    name: string;
    severity?: string;
    summary?: string;
    starts_at?: string;
    silenced_by?: string[];
  };
};

type Widok = {
  sources: Zrodlo[];
  items: Pozycja[];
  hosts_visible?: number;
  alerts_outside_fleet?: number;
  host_label?: string;
  alerts_unavailable_reason?: string;
};

/**
 * Alerty floty.
 *
 * Panel nie ma wlasnych regul alertowych: pokazuje alerty systemu, ktory je
 * generuje, i doklada do nich to, czego ten system nie wie - ktory host
 * z floty to jest i czy wolno go temu operatorowi pokazac.
 */
export function MonitoringFloty() {
  const { data, error } = useQuery({
    queryKey: ["monitoring", "fleet"],
    queryFn: () => api.get<Widok>("/api/v1/monitoring"),
    refetchInterval: 30000,
  });

  if (error) return <Blad error={error} />;
  if (!data) return <Pusto>Reading alerts…</Pusto>;

  return (
    <>
      <h1>Monitoring</h1>
      <p className="podtytul">
        Alerts from the system that raises them, mapped onto the fleet by the{" "}
        <code>{data.host_label ?? "instance"}</code> label. A failing integration
        does not block anything here — it just says so.
      </p>

      <div className="filtry">
        {data.sources.map((zrodlo) => (
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
        {data.hosts_visible !== undefined && (
          <span className="zrodlo">{data.hosts_visible} hosts visible</span>
        )}
        {!!data.alerts_outside_fleet && (
          <span className="zrodlo">
            {data.alerts_outside_fleet} alerts from outside this fleet, not shown
          </span>
        )}
      </div>

      {data.alerts_unavailable_reason ? (
        <p className="ostrzezenie"><span>{data.alerts_unavailable_reason}</span></p>
      ) : !data.items.length ? (
        <Pusto>Nothing is firing on the hosts you can see.</Pusto>
      ) : (
        <table>
          <thead>
            <tr><th>Severity</th><th>Alert</th><th>Host</th><th>Since</th><th>Summary</th></tr>
          </thead>
          <tbody>
            {data.items.map((pozycja, indeks) => (
              <tr key={`${pozycja.host_id}-${pozycja.alert.name}-${indeks}`}>
                <td>
                  <span
                    className={`znacznik ${pozycja.alert.severity === "critical" ? "blad" : pozycja.alert.severity === "warning" ? "uwaga" : ""}`}
                  >
                    {pozycja.alert.severity || "unknown"}
                  </span>
                  {pozycja.alert.silenced_by?.length ? (
                    <div className="zrodlo">silenced</div>
                  ) : null}
                </td>
                <td>{pozycja.alert.name}</td>
                <td>
                  {pozycja.host_id ? (
                    <Link to={`/hosts/${pozycja.host_id}/monitoring`}>{pozycja.hostname}</Link>
                  ) : (
                    <span className="znacznik nieznany">outside the fleet</span>
                  )}
                </td>
                <td><Czas wartosc={pozycja.alert.starts_at} /></td>
                <td className="zrodlo">{pozycja.alert.summary}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </>
  );
}
