import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../../lib/api";
import type { Job } from "../../lib/types";
import { ErrorBox, Time, Empty } from "../../components/ui";
import { useHost } from "./shared";
import { useT } from "../../i18n";

type Source = {
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

type Silence = {
  id: string;
  starts_at: string;
  ends_at: string;
  created_by: string;
  comment: string;
  status?: string;
  matchers?: { name: string; value: string }[];
};

type Point = { at: string; value: number };

type Series = {
  name: string;
  unit?: string;
  points?: Point[];
  last?: number;
  query?: string;
  unavailable_reason?: string;
};

type Report = {
  host_id: string;
  sources: Source[];
  label: string;
  links: { dashboard?: string; logs?: string };
  alerts: Alert[];
  silences: Silence[];
  series: Series[];
  from: string;
  to: string;
  alerts_unavailable_reason?: string;
  metrics_unavailable_reason?: string;
};

type ProbeResult = {
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

type Attempt = { status?: string; message?: string; detail?: { probe?: ProbeResult } };

/**
 * A chart from points. Simple, because it is to answer one question: did
 * anything change in this time window. For details the panel leads to the
 * dashboard - it does not pretend to be a time series database.
 */
function Sparkline({ series }: { series: Series }) {
  const t = useT();
  const points = series.points ?? [];
  if (series.unavailable_reason) {
    return <span className="badge unknown">{series.unavailable_reason}</span>;
  }
  if (!points.length) {
    return <span className="badge unknown">{t("no data in this window")}</span>;
  }
  const values = points.map((point) => point.value);
  const minimum = Math.min(...values);
  const maximum = Math.max(...values);
  const range = maximum - minimum || 1;
  const width = 240;
  const height = 40;
  const path = points
    .map((point, index) => {
      const x = (index / Math.max(1, points.length - 1)) * width;
      const y = height - ((point.value - minimum) / range) * height;
      return `${index === 0 ? "M" : "L"}${x.toFixed(1)},${y.toFixed(1)}`;
    })
    .join(" ");
  return (
    <svg width={width} height={height} role="img" aria-label={series.name}>
      <path d={path} fill="none" stroke="currentColor" strokeWidth="1.5" />
    </svg>
  );
}

/**
 * Host monitoring.
 *
 * The panel has no metrics and no alert rules of its own: it reads other
 * systems' and says where it took them from and from which time window. A
 * monitoring failure must not take host management away from the operator,
 * so every question has a timeout, and a source that stays silent is
 * described plainly.
 */
export function Monitoring() {
  const t = useT();
  const host = useHost();
  const queryClient = useQueryClient();
  const [range, setRange] = useState("3h");
  const [message, setMessage] = useState("");
  const [silenceReason, setSilenceReason] = useState("");
  const [minutes, setMinutes] = useState("120");
  const [probe, setProbe] = useState("");
  const [probeJob, setProbeJob] = useState("");

  const report = useQuery({
    queryKey: ["monitoring", host.id, range],
    queryFn: () => api.get<Report>(`/api/v1/hosts/${host.id}/monitoring?range=${range}`),
    refetchInterval: 30000,
  });

  const results = useQuery({
    queryKey: ["job-attempts", probeJob],
    queryFn: () => api.get<{ items: Attempt[] }>(`/api/v1/jobs/${probeJob}/attempts`),
    enabled: probeJob !== "",
    refetchInterval: (query) => {
      const attempts = (query.state.data as { items?: Attempt[] } | undefined)?.items;
      return attempts?.[attempts.length - 1]?.status ? false : 2000;
    },
  });
  const attempts = results.data?.items ?? [];
  const probeResult = attempts[attempts.length - 1]?.detail?.probe;

  const silence = useMutation({
    mutationFn: (body: Record<string, unknown>) =>
      api.post<Silence>(`/api/v1/hosts/${host.id}/monitoring/silences`, body),
    onSuccess: (created) => {
      setMessage(t("Silence {id} runs until {until}.", { id: created.id.slice(0, 8), until: new Date(created.ends_at).toLocaleString() }));
      setSilenceReason("");
      queryClient.invalidateQueries({ queryKey: ["monitoring", host.id] });
    },
    onError: (error) => setMessage(error instanceof Error ? error.message : String(error)),
  });

  const unsilence = useMutation({
    mutationFn: (id: string) =>
      api.del(`/api/v1/hosts/${host.id}/monitoring/silences/${encodeURIComponent(id)}`),
    onSuccess: () => {
      setMessage(t("Silence ended."));
      queryClient.invalidateQueries({ queryKey: ["monitoring", host.id] });
    },
    onError: (error) => setMessage(error instanceof Error ? error.message : String(error)),
  });

  const runProbe = useMutation({
    mutationFn: (target: string) =>
      api.post<Job>(`/api/v1/hosts/${host.id}/operations`, {
        action: "monitoring.probe.run",
        payload: {
          monitoring: {
            kind: target.startsWith("http") ? "http" : "tcp",
            target,
          },
        },
      }),
    onSuccess: (job) => {
      setProbeJob(job.id);
      setMessage(t("Probe queued as job {id}.", { id: job.id.slice(0, 8) }));
    },
    onError: (error) => setMessage(error instanceof Error ? error.message : String(error)),
  });

  if (report.error) return <ErrorBox error={report.error} />;
  const data = report.data;

  return (
    <>
      <p className="subtitle">
        {t("Metrics and alerts come from the systems that already collect them. The panel shows where each number is from and for what window of time — it has no time series database of its own, and no alerting rules of its own.")}
      </p>

      <div className="filters">
        {(data?.sources ?? []).map((source) => (
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
        {data?.label && <span className="source">{t("seen as {label}", { label: data.label })}</span>}
        {data?.links.dashboard && (
          <a href={data.links.dashboard} target="_blank" rel="noreferrer">{t("Dashboard")}</a>
        )}
        {data?.links.logs && (
          <a href={data.links.logs} target="_blank" rel="noreferrer">{t("Logs")}</a>
        )}
        <select value={range} onChange={(e) => setRange(e.target.value)}>
          <option value="1h">{t("last hour")}</option>
          <option value="3h">{t("last 3 hours")}</option>
          <option value="12h">{t("last 12 hours")}</option>
          <option value="24h">{t("last day")}</option>
        </select>
      </div>
      {message && <p className="source" style={{ marginBottom: 12 }}>{message}</p>}

      <h2>{t("Active alerts")}</h2>
      {data?.alerts_unavailable_reason ? (
        <p className="warning">
          <span>{t("Alerts could not be read: {reason}", { reason: data.alerts_unavailable_reason })}</span>
        </p>
      ) : !(data?.alerts ?? []).length ? (
        <Empty>{t("No alert is firing for this host.")}</Empty>
      ) : (
        <table>
          <thead>
            <tr><th>{t("Alert")}</th><th>{t("Severity")}</th><th>{t("Since")}</th><th>{t("Summary")}</th><th>{t("Silence")}</th></tr>
          </thead>
          <tbody>
            {(data?.alerts ?? []).map((alert, index) => (
              <tr key={`${alert.name}-${index}`}>
                <td>
                  {alert.generator_url ? (
                    <a href={alert.generator_url} target="_blank" rel="noreferrer">{alert.name}</a>
                  ) : (
                    alert.name
                  )}
                  {alert.silenced_by?.length ? (
                    <div className="source">{t("silenced")}</div>
                  ) : null}
                </td>
                <td>
                  <span
                    className={`badge ${alert.severity === "critical" ? "error" : alert.severity === "warning" ? "warn" : ""}`}
                  >
                    {alert.severity || t("unknown")}
                  </span>
                </td>
                <td><Time value={alert.starts_at} /></td>
                <td className="source">{alert.summary || alert.description}</td>
                <td>
                  <button
                    className="secondary"
                    disabled={silenceReason.trim().length < 8 || silence.isPending}
                    onClick={() =>
                      silence.mutate({
                        duration_minutes: Number(minutes) || 0,
                        comment: silenceReason,
                        alert_name: alert.name,
                      })
                    }
                  >
                    {t("Silence this")}
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      <div className="form" style={{ marginTop: 12 }}>
        <h2>{t("Silence")}</h2>
        <p className="subtitle" style={{ margin: 0 }}>
          {t("A silence turns a sensor off, so it always ends: no open-ended silences from here, at most a day, and always with a reason and an owner in the audit trail.")}
        </p>
        <div className="filters">
          <input value={silenceReason} onChange={(e) => setSilenceReason(e.target.value)}
                 placeholder={t("Reason (at least 8 characters)")} style={{ minWidth: 320 }} />
          <input value={minutes} onChange={(e) => setMinutes(e.target.value)}
                 placeholder={t("Minutes")} style={{ width: 110 }} />
          <button
            disabled={silenceReason.trim().length < 8 || silence.isPending}
            onClick={() => silence.mutate({ duration_minutes: Number(minutes) || 0, comment: silenceReason })}
          >
            {t("Silence every alert of this host")}
          </button>
        </div>
      </div>

      {(data?.silences ?? []).length > 0 && (
        <>
          <h2>{t("Silences in force")}</h2>
          <table>
            <thead>
              <tr><th>{t("Until")}</th><th>{t("Scope")}</th><th>{t("Reason")}</th><th>{t("By")}</th><th></th></tr>
            </thead>
            <tbody>
              {(data?.silences ?? []).map((entry) => (
                <tr key={entry.id}>
                  <td><Time value={entry.ends_at} /></td>
                  <td className="source">
                    {(entry.matchers ?? []).map((m) => `${m.name}="${m.value}"`).join(", ")}
                  </td>
                  <td>{entry.comment}</td>
                  <td className="source">{entry.created_by}</td>
                  <td>
                    <button className="secondary" onClick={() => unsilence.mutate(entry.id)}>
                      {t("End now")}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}

      <h2>{t("Metrics")}</h2>
      {data?.metrics_unavailable_reason ? (
        <Empty>{data.metrics_unavailable_reason}</Empty>
      ) : (
        <>
          <table>
            <thead><tr><th>{t("Series")}</th><th>{t("Last")}</th><th>{t("Window")}</th><th>{t("Query")}</th></tr></thead>
            <tbody>
              {(data?.series ?? []).map((series) => (
                <tr key={series.name}>
                  <td>{series.name}</td>
                  <td>
                    {series.last === undefined
                      ? <span className="badge unknown">{t("unknown")}</span>
                      : `${series.last.toFixed(2)}${series.unit ?? ""}`}
                  </td>
                  <td><Sparkline series={series} /></td>
                  <td className="source" style={{ maxWidth: 420, overflowWrap: "anywhere" }}>
                    {series.query}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {data && (
            <p className="source">
              {t("Source")}: {(data.sources.find((s) => s.name === "prometheus")?.url) || "—"} ·{" "}
              {t("window")} <Time value={data.from} /> {t("to")} <Time value={data.to} />
            </p>
          )}
        </>
      )}

      <h2>{t("Probe from this host")}</h2>
      <p className="subtitle">
        {t("What the host itself sees. An alert can say a service is down while it answers from here — and then the problem is the network between them, not the service.")}
      </p>
      <div className="filters">
        <input value={probe} onChange={(e) => setProbe(e.target.value)}
               placeholder="https://service.example.test/health or db.example.test:5432"
               style={{ minWidth: 380 }} />
        <button
          disabled={!probe || runProbe.isPending || host.connection_state !== "online"}
          onClick={() => runProbe.mutate(probe)}
        >
          {t("Probe")}
        </button>
      </div>
      {probeResult && (
        <table>
          <tbody>
            <tr>
              <td>{t("Result")}</td>
              <td>
                {probeResult.passed ? (
                  <span className="badge ok">{t("as expected")}</span>
                ) : probeResult.reachable ? (
                  <span className="badge warn">{t("answers, but not as expected")}</span>
                ) : (
                  <span className="badge error">{t("no answer")}</span>
                )}
              </td>
            </tr>
            <tr><td>{t("Target")}</td><td className="source">{probeResult.target}</td></tr>
            <tr><td>{t("Took")}</td><td>{probeResult.duration_millis} ms</td></tr>
            {probeResult.status_code !== undefined && (
              <tr><td>{t("Status")}</td><td>{probeResult.status_code}</td></tr>
            )}
            {probeResult.tls_expiry && (
              <tr>
                <td>{t("Certificate")}</td>
                <td>
                  {t("valid until")} <Time value={probeResult.tls_expiry} />
                  <div className="source">{probeResult.tls_issuer}</div>
                </td>
              </tr>
            )}
            {probeResult.error && <tr><td>{t("Detail")}</td><td className="source">{probeResult.error}</td></tr>}
          </tbody>
        </table>
      )}
    </>
  );
}
