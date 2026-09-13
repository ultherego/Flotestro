import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api } from "../lib/api";
import { ErrorBox, Time, Empty } from "../components/ui";
import { useT } from "../i18n";

type Source = {
  name: string;
  configured: boolean;
  healthy: boolean;
  url?: string;
  reason?: string;
  latency_millis?: number;
};

type Item = {
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

type View = {
  sources: Source[];
  items: Item[];
  hosts_visible?: number;
  alerts_outside_fleet?: number;
  host_label?: string;
  alerts_unavailable_reason?: string;
};

/**
 * Fleet alerts.
 *
 * The panel has no alert rules of its own: it shows the alerts of the system
 * that raises them and adds what that system does not know - which fleet
 * host this is and whether this operator may be shown it.
 */
export function FleetMonitoring() {
  const t = useT();
  const { data, error } = useQuery({
    queryKey: ["monitoring", "fleet"],
    queryFn: () => api.get<View>("/api/v1/monitoring"),
    refetchInterval: 30000,
  });

  if (error) return <ErrorBox error={error} />;
  if (!data) return <Empty>{t("Reading alerts…")}</Empty>;

  return (
    <>
      <h1>{t("Monitoring")}</h1>
      <p className="subtitle">
        {t("Alerts from the system that raises them, mapped onto the fleet by the {label} label. A failing integration does not block anything here — it just says so.", { label: data.host_label ?? "instance" })}
      </p>

      <div className="filters">
        {data.sources.map((source) => (
          <span
            key={source.name}
            className={`badge ${!source.configured ? "unknown" : source.healthy ? "ok" : "error"}`}
            title={source.reason || source.url}
          >
            {source.name}
            {!source.configured
              ? ` · ${t("not configured")}`
              : source.healthy
                ? ` · ${source.latency_millis ?? "?"} ms`
                : ` · ${t("not answering")}`}
          </span>
        ))}
        {data.hosts_visible !== undefined && (
          <span className="source">{t("{n} hosts visible", { n: data.hosts_visible })}</span>
        )}
        {!!data.alerts_outside_fleet && (
          <span className="source">
            {t("{n} alerts from outside this fleet, not shown", { n: data.alerts_outside_fleet })}
          </span>
        )}
      </div>

      {data.alerts_unavailable_reason ? (
        <p className="warning"><span>{data.alerts_unavailable_reason}</span></p>
      ) : !data.items.length ? (
        <Empty>{t("Nothing is firing on the hosts you can see.")}</Empty>
      ) : (
        <table>
          <thead>
            <tr><th>{t("Severity")}</th><th>{t("Alert")}</th><th>{t("Host")}</th><th>{t("Since")}</th><th>{t("Summary")}</th></tr>
          </thead>
          <tbody>
            {data.items.map((item, index) => (
              <tr key={`${item.host_id}-${item.alert.name}-${index}`}>
                <td>
                  <span
                    className={`badge ${item.alert.severity === "critical" ? "error" : item.alert.severity === "warning" ? "warn" : ""}`}
                  >
                    {item.alert.severity || t("unknown")}
                  </span>
                  {item.alert.silenced_by?.length ? (
                    <div className="source">{t("silenced")}</div>
                  ) : null}
                </td>
                <td>{item.alert.name}</td>
                <td>
                  {item.host_id ? (
                    <Link to={`/hosts/${item.host_id}/monitoring`}>{item.hostname}</Link>
                  ) : (
                    <span className="badge unknown">{t("outside the fleet")}</span>
                  )}
                </td>
                <td><Time value={item.alert.starts_at} /></td>
                <td className="source">{item.alert.summary}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </>
  );
}
