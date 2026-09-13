import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api } from "../lib/api";
import { ErrorBox, Time, Empty } from "../components/ui";
import { Card, PageHeader, Stat, StatGrid } from "../components/layout";
import { Breakdown, StatusBar } from "../components/widgets";
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

  const firing = data.items.length;
  // While the alert source does not answer, the alerts are not known:
  // the bar shows dashes, not a fleet with nothing firing.
  const known = !data.alerts_unavailable_reason;
  const severity = (kinds: string[]) => (known ? data.items.filter((item) => kinds.includes(item.alert.severity ?? "")).length : undefined);
  const silenced = known ? data.items.filter((item) => item.alert.silenced_by?.length).length : undefined;
  // The firing alerts by host, the loudest host first; an alert without a
  // host of the fleet is counted under its own label.
  const byHost = Object.entries(
    data.items.reduce<Record<string, { host_id?: string; count: number }>>((acc, item) => {
      const key = item.hostname || (item.host_id ? item.host_id.slice(0, 8) : t("outside the fleet"));
      acc[key] = { host_id: item.host_id, count: (acc[key]?.count ?? 0) + 1 };
      return acc;
    }, {}),
  ).sort((x, y) => y[1].count - x[1].count).slice(0, 10);

  return (
    <>
      <PageHeader
        title={t("Monitoring")}
        description={t("Alerts from the system that raises them, mapped onto the fleet by the {label} label. A failing integration does not block anything here — it just says so.", { label: data.host_label ?? "instance" })}
      />

      <div className="widgets">
        <Card
          className="span-8"
          title={t("Alert")}
          description={[
            known ? t("{n} firing", { n: firing }) : t("The alert source did not answer."),
            data.hosts_visible === undefined ? "" : t("{n} hosts visible", { n: data.hosts_visible }),
          ].filter(Boolean).join(" · ")}
        >
          <StatusBar segments={[
            { label: t("Critical"), value: severity(["critical"]), tone: "error" },
            { label: t("Warning"), value: severity(["warning"]), tone: "warn" },
            { label: t("Other"), value: known ? firing - (severity(["critical"]) ?? 0) - (severity(["warning"]) ?? 0) : undefined, tone: "unknown" },
            { label: t("Silenced"), value: silenced, tone: "neutral" },
          ]} />
        </Card>

        {/* One tile per source: whether it answers and how fast. A source
            that is not configured is not a broken one. */}
        <Card className="span-4" title={t("Sources")} description={t("Whether each one answers, and how fast.")}>
          <StatGrid compact>
            {data.sources.map((source) => (
              <Stat
                key={source.name}
                label={source.name}
                value={!source.configured
                  ? t("not configured")
                  : source.healthy
                    ? `${source.latency_millis ?? "?"} ms`
                    : t("not answering")}
                hint={source.reason || source.url}
                tone={!source.configured ? "unknown" : source.healthy ? "ok" : "error"}
              />
            ))}
          </StatGrid>
        </Card>

        <Card
          className="span-9"
          flush
          footer={!!data.alerts_outside_fleet && (
            <p>{t("{n} alerts from outside this fleet, not shown", { n: data.alerts_outside_fleet })}</p>
          )}
        >
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
        </Card>

        <Card className="span-3" title={t("By host")} description={t("The hosts with the most alerts firing.")}>
          {!known ? (
            <p className="fp-blank">{t("The alerts could not be read.")}</p>
          ) : byHost.length === 0 ? (
            <p className="fp-blank">{t("Nothing is firing on the hosts you can see.")}</p>
          ) : (
            <div className="fp-links">
              <Breakdown tone="warn" items={byHost.map(([label, entry]) => ({
                label: entry.host_id ? <Link to={`/hosts/${entry.host_id}/monitoring`}>{label}</Link> : label,
                value: entry.count,
              }))} />
            </div>
          )}
        </Card>
      </div>
    </>
  );
}
