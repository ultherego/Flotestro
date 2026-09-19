import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ApiError } from "../lib/api";
import type { Relay, RelayDetail, RelayHost, RelayState, Whoami } from "../lib/types";
import { bytes } from "../lib/format";
import { ErrorBox, Time, Empty, Pairs, Pair } from "../components/ui";
import { Actions, Card, Field, FieldGrid, PageHeader } from "../components/layout";
import { AreaChart, Breakdown, ChartLegend, StatusBar, type AreaSeries } from "../components/widgets";
import { useT } from "../i18n";

/** How long before the end of a relay certificate the expiry is a warning. */
const EXPIRY_WARNING_MS = 24 * 60 * 60 * 1000;

function StateBadge({ state }: { state: RelayState }) {
  const t = useT();
  switch (state) {
    case "active":
      return <span className="badge ok">{t("active")}</span>;
    case "silent":
      return <span className="badge error">{t("silent")}</span>;
    case "never_seen":
      return <span className="badge unknown">{t("never seen")}</span>;
    default:
      return <span className="badge error">{t("revoked")}</span>;
  }
}

/** The end of the certificate, with a warning when the renewal is late. */
function Expiry({ value, revoked }: { value?: string; revoked: boolean }) {
  const t = useT();
  if (!value) return <span className="badge unknown">{t("unknown")}</span>;
  const left = new Date(value).getTime() - Date.now();
  const cls = revoked ? "source" : left < 0 ? "badge error" : left < EXPIRY_WARNING_MS ? "badge warn" : "";
  return (
    <span className={cls}>
      {left < 0 && !revoked ? t("expired") : <Time value={value} />}
    </span>
  );
}

/**
 * The fill of the buffer as the relay last reported it.
 */
function BufferCell({ relay }: { relay: Relay }) {
  const t = useT();
  const buffer = relay.buffer;
  if (!buffer) return <span className="source">{t("not reported")}</span>;
  const share = buffer.buffer_max_bytes > 0 ? buffer.buffer_bytes / buffer.buffer_max_bytes : 0;
  const cls = buffer.buffer_dropped > 0 ? "badge error" : share > 0.7 ? "badge warn" : "";
  return (
    <>
      <span className={cls}>
        {bytes(buffer.buffer_bytes)} / {bytes(buffer.buffer_max_bytes)}
      </span>
      <div className="source">
        {t("{n} items", { n: buffer.buffered_items })}
        {buffer.buffer_dropped > 0 && <> · {t("{n} dropped", { n: buffer.buffer_dropped })}</>}
      </div>
    </>
  );
}

/**
 * The relays of the sites.
 */
export function Relays() {
  const t = useT();
  const { data, error } = useQuery({
    queryKey: ["relays"],
    queryFn: () => api.get<{ items: Relay[] }>("/api/v1/relays"),
    refetchInterval: 30 * 1000,
  });

  if (error) return <ErrorBox error={error} />;
  const loaded = data !== undefined;
  const relays = data?.items ?? [];
  const count = (state: RelayState) => (loaded ? relays.filter((relay) => relay.state === state).length : undefined);
  const bySite = Object.entries(
    relays.reduce<Record<string, number>>((acc, relay) => { acc[relay.site] = (acc[relay.site] ?? 0) + 1; return acc; }, {}),
  ).sort((x, y) => y[1] - x[1]);
  const attested = relays.reduce((sum, relay) => sum + relay.hosts_attested, 0);

  return (
    <>
      <PageHeader
        icon="relays"
        title={t("Relays")}
        description={t("The relays of the sites: one connection upwards per site, a buffer for the results while the link is down, and the route a host in an isolated site installs through. A relay reports itself every minute; ten minutes of silence is a site cut off from the panel.")}
      />

      <div className="widgets">
        <Card className="span-8" title={t("State")} description={t("{n} relays, {hosts} hosts attested", { n: relays.length, hosts: attested })}>
          <StatusBar segments={[
            { label: t("Active"), value: count("active"), tone: "ok" },
            { label: t("Silent"), value: count("silent"), tone: "error" },
            { label: t("Never seen"), value: count("never_seen"), tone: "unknown" },
            { label: t("Revoked"), value: count("revoked"), tone: "neutral" },
          ]} />
        </Card>
        <Card className="span-4" title={t("By site")} description={t("Where the relays stand.")}>
          {!loaded ? (
            <Empty>{t("Loading…")}</Empty>
          ) : bySite.length === 0 ? (
            <p className="fp-blank">{t("No relay is registered in this installation.")}</p>
          ) : (
            <Breakdown tone="info" items={bySite.map(([site, n]) => ({ label: <span className="mono">{site}</span>, value: n }))} />
          )}
        </Card>

        <Card className="span-12" flush>
          {!loaded ? (
            <Empty>{t("Loading…")}</Empty>
          ) : relays.length === 0 ? (
            <Empty>
              {t("No relay is registered. A relay is added from the add-host screen with a relay token; a site that sees the panel directly needs none.")}
            </Empty>
          ) : (
            <table>
              <thead>
                <tr>
                  <th>{t("Name")}</th><th>{t("Site")}</th><th>{t("State")}</th><th>{t("Last seen")}</th>
                  <th className="num">{t("Hosts attested")}</th><th>{t("Buffer")}</th><th>{t("Certificate expires")}</th>
                </tr>
              </thead>
              <tbody>
                {relays.map((relay) => (
                  <tr key={relay.id}>
                    <td>
                      <Link to={`/relays/${relay.id}`}>{relay.name}</Link>
                      {relay.advertised_names && relay.advertised_names.length > 0 && (
                        <div className="source mono">{relay.advertised_names.join(", ")}</div>
                      )}
                    </td>
                    <td>
                      {relay.site}
                      {relay.environment && <div className="source">{relay.environment}</div>}
                    </td>
                    <td><StateBadge state={relay.state} /></td>
                    <td><Time value={relay.last_seen_at} /></td>
                    <td className="num">{relay.hosts_attested}</td>
                    <td><BufferCell relay={relay} /></td>
                    <td><Expiry value={relay.certificate_not_after ?? relay.not_after} revoked={!!relay.revoked_at} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Card>
      </div>
    </>
  );
}

/**
 * One point of the buffer history: a single report on a short window, a
 * quarter-hour of reports on a long one.
 */
export type RelayBufferPoint = {
  at: string;
  instance_id?: string;
  bytes_used: number;
  bytes_used_max: number;
  bytes_limit: number;
  item_count: number;
  item_count_max: number;
  dropped_total: number;
  /** The growth since the previous point; null across a restart, where the counter starts again. */
  dropped_delta: number | null;
  active_sessions: number;
  upstream_state?: string;
  disconnected: boolean;
  restarted: boolean;
  version?: string;
  samples: number;
};

export type RelayBufferAlert = {
  id: string;
  rule_name: string;
  metric: string;
  severity: string;
  value: number;
  detail?: string;
  started_at: string;
  fired_at?: string;
};

export type RelayBufferHistory = {
  relay_id: string;
  range: string;
  step_seconds: number;
  rollup: boolean;
  points: RelayBufferPoint[];
  latest: RelayBufferPoint | null;
  alerts: RelayBufferAlert[];
  raw_retention_hours: number;
  rollup_retention_days: number;
};

/** The windows the history offers, from the minute-by-minute to the quarter of a year. */
export const BUFFER_RANGES = ["3h", "24h", "7d", "30d", "90d"] as const;
export type BufferRangeName = (typeof BUFFER_RANGES)[number];

export function historyAddress(relayID: string, range: BufferRangeName): string {
  return `/api/v1/relays/${relayID}/buffer-history?range=${range}`;
}

/**
 * What the window as a whole says, read off the points.
 */
export function bufferSummary(points: RelayBufferPoint[], stepSeconds: number) {
  let dropped = 0;
  let offlineSteps = 0;
  let restarts = 0;
  let peakPercent: number | undefined;
  for (const point of points) {
    if (point.dropped_delta !== null && point.dropped_delta > 0) dropped += point.dropped_delta;
    if (point.disconnected) offlineSteps += 1;
    if (point.restarted) restarts += 1;
    if (point.bytes_limit > 0) {
      const share = (point.bytes_used_max / point.bytes_limit) * 100;
      peakPercent = peakPercent === undefined ? share : Math.max(peakPercent, share);
    }
  }
  return { dropped, restarts, peakPercent, offlineMinutes: Math.round((offlineSteps * stepSeconds) / 60) };
}

/**
 * The buffer of a relay over a window. The last heartbeat answers "how full
 * is it now" and nothing else.
 */
function BufferHistory({ relay }: { relay: Relay }) {
  const t = useT();
  const [range, setRange] = useState<BufferRangeName>("24h");
  const { data, error } = useQuery({
    queryKey: ["relays", relay.id, "buffer-history", range],
    queryFn: () => api.get<RelayBufferHistory>(historyAddress(relay.id, range)),
    refetchInterval: 60 * 1000,
  });

  const points = data?.points ?? [];
  const times = points.map((point) => point.at);
  const summary = bufferSummary(points, data?.step_seconds ?? 60);
  // The top of the chart is the largest limit the window saw, so the fill
  // is read against the room it had rather than against itself.
  const limit = Math.max(0, ...points.map((point) => point.bytes_limit));
  const ceiling = limit > 0 ? limit : undefined;
  const band = ceiling ?? Math.max(1, ...points.map((point) => point.bytes_used_max));

  const fillSeries: AreaSeries[] = [
    { name: t("Buffered"), tone: "accent", values: points.map((point) => point.bytes_used) },
  ];
  if (limit > 0) {
    fillSeries.push({ name: t("Limit"), tone: "neutral", line: true, values: points.map((point) => point.bytes_limit) });
  }
  // The outage is drawn as a band the height of the chart over the points
  // that had no upstream, and a restart as a single mark: both are stretches
  // of the same time axis, so they belong on the same picture rather than in
  fillSeries.push({
    name: t("No upstream"), tone: "error",
    values: points.map((point) => (point.disconnected ? band : undefined)),
  });
  fillSeries.push({
    name: t("Relay restarted"), tone: "warn", line: true,
    values: points.map((point) => (point.restarted ? band : undefined)),
  });

  const waitingSeries: AreaSeries[] = [
    { name: t("Items waiting"), tone: "info", values: points.map((point) => point.item_count) },
    {
      name: t("Results dropped"), tone: "error", line: true,
      values: points.map((point) => (point.dropped_delta === null ? undefined : point.dropped_delta)),
    },
  ];

  return (
    <Card
      className="span-12"
      title={t("Buffer history")}
      description={t("What the relay reported about its spool over the window. The raw reports are kept for {raw} h and the quarter-hour rollups for {rollup} days; a window reaching further back shows nothing because nothing is kept, not because the relay was quiet.", {
        raw: data?.raw_retention_hours ?? 0, rollup: data?.rollup_retention_days ?? 0,
      })}
      footer={
        <Actions>
          <div className="segmented" role="group" aria-label={t("Window")} data-testid="buffer-range">
            {BUFFER_RANGES.map((name) => (
              <button key={name} className={range === name ? "active" : ""} onClick={() => setRange(name)}>
                {name}
              </button>
            ))}
          </div>
        </Actions>
      }
    >
      {error ? (
        <ErrorBox error={error} />
      ) : !data ? (
        <Empty>{t("Loading…")}</Empty>
      ) : points.length === 0 ? (
        <p className="fp-blank">
          {t("The relay reported nothing in this window. A relay reports every minute while it reaches the centre; a silent relay is on the state above, not here.")}
        </p>
      ) : (
        <>
          <div data-testid="buffer-summary">
            <StatusBar segments={[
              {
                label: t("Peak fill"),
                value: summary.peakPercent === undefined ? undefined : Math.round(summary.peakPercent),
                tone: summary.peakPercent !== undefined && summary.peakPercent > 85 ? "error"
                  : summary.peakPercent !== undefined && summary.peakPercent > 70 ? "warn" : "ok",
              },
              { label: t("Minutes without upstream"), value: summary.offlineMinutes, tone: summary.offlineMinutes > 0 ? "warn" : "ok" },
              { label: t("Results dropped"), value: summary.dropped, tone: summary.dropped > 0 ? "error" : "ok" },
              { label: t("Restarts"), value: summary.restarts, tone: summary.restarts > 0 ? "warn" : "neutral" },
            ]} />
          </div>
          <AreaChart times={times} series={fillSeries} max={ceiling} format={bytes}
            peak={data.rollup ? points.map((point) => point.bytes_used_max) : undefined} />
          <ChartLegend items={[
            { name: t("Buffered"), tone: "accent" },
            ...(limit > 0 ? [{ name: t("Limit"), tone: "neutral" as const }] : []),
            { name: t("No upstream"), tone: "error" },
            { name: t("Relay restarted"), tone: "warn" },
            ...(data.rollup ? [{ name: t("peak of the step"), tone: "accent" as const, dashed: true }] : []),
          ]} />
          <AreaChart times={times} series={waitingSeries} height={110}
            format={(value) => String(Math.round(value))} />
          <ChartLegend items={[
            { name: t("Items waiting"), tone: "info" },
            { name: t("Results dropped between two reports"), tone: "error" },
          ]} />
          {data.alerts.length > 0 && (
            <Pairs>
              {data.alerts.map((alert) => (
                <Pair key={alert.id} label={alert.rule_name}>
                  <span className={alert.severity === "critical" ? "badge error" : "badge warn"}>
                    {alert.severity}
                  </span>
                  {alert.detail && <div className="source">{alert.detail}</div>}
                  <div className="source">
                    {t("since")} <Time value={alert.fired_at ?? alert.started_at} />
                  </div>
                </Pair>
              ))}
            </Pairs>
          )}
        </>
      )}
    </Card>
  );
}

/**
 * One relay: what it is, what it reported, the hosts that come through it,
 * and the way to cut it off.
 */
export function RelayPage() {
  const t = useT();
  const { id = "" } = useParams();
  const { data, error } = useQuery({
    queryKey: ["relays", id],
    queryFn: () => api.get<RelayDetail>(`/api/v1/relays/${id}`),
    refetchInterval: 30 * 1000,
  });
  const whoami = useQuery({
    queryKey: ["whoami"],
    queryFn: () => api.get<Whoami>("/api/v1/whoami"),
    staleTime: 5 * 60 * 1000,
  });
  const canManage = (whoami.data?.permissions ?? []).includes("relay.manage");

  if (error) return <ErrorBox error={error} />;
  if (!data) return <Empty>{t("Loading…")}</Empty>;
  const { relay, hosts } = data;
  const buffer = relay.buffer;

  return (
    <>
      <PageHeader
        icon="relays"
        breadcrumb={[{ label: t("Relays"), to: "/relays" }]}
        title={relay.name}
        description={t("Site {site}. A relay attests the identity of the hosts behind it to the panel, so what it reports about itself is what the panel knows about the site.", { site: relay.site })}
      />

      <div className="widgets">
        <Card className="span-12" title={t("State")}>
          <StatusBar segments={[
            { label: t("Hosts attested"), value: hosts.length, tone: "info" },
            { label: t("Sessions reported"), value: buffer?.sessions, tone: "neutral" },
            { label: t("Buffered items"), value: buffer?.buffered_items, tone: buffer && buffer.buffered_items > 0 ? "warn" : "ok" },
            { label: t("Dropped results"), value: buffer?.buffer_dropped, tone: buffer && buffer.buffer_dropped > 0 ? "error" : "ok" },
          ]} />
        </Card>

        <Card className="span-6" title={t("Details")}>
          <Pairs>
            <Pair label={t("State")}><StateBadge state={relay.state} /></Pair>
            <Pair label={t("Site")}>{relay.site}{relay.environment ? ` / ${relay.environment}` : ""}</Pair>
            <Pair label={t("Network names")}>
              {relay.advertised_names && relay.advertised_names.length > 0
                ? <span className="mono">{relay.advertised_names.join(", ")}</span>
                : "—"}
            </Pair>
            <Pair label={t("Enrolled")}><Time value={relay.enrolled_at} /></Pair>
            <Pair label={t("Last seen")}><Time value={relay.last_seen_at} /></Pair>
            <Pair label={t("Certificate expires")}>
              <Expiry value={relay.certificate_not_after ?? relay.not_after} revoked={!!relay.revoked_at} />
              {relay.serial && <div className="source mono">{t("serial {serial}", { serial: relay.serial })}</div>}
            </Pair>
            {relay.revoked_at && (
              <Pair label={t("Revoked")}>
                <Time value={relay.revoked_at} />
                {relay.revocation_reason && <div className="source">{relay.revocation_reason}</div>}
              </Pair>
            )}
          </Pairs>
        </Card>
        <Card className="span-6" title={t("Last report")} description={t("What the relay said about itself at its last heartbeat.")}>
          {!buffer ? (
            <p className="fp-blank">{t("The relay has not reported since the panel started. A relay reports every minute while it reaches the centre.")}</p>
          ) : (
            <Pairs>
              <Pair label={t("Reported")}><Time value={buffer.reported_at} /></Pair>
              <Pair label={t("Buffer")}><BufferCell relay={relay} /></Pair>
              <Pair label={t("Sessions at the relay")}>{buffer.sessions}</Pair>
              <Pair label={t("Relay version")}>{buffer.relay_version || "—"}</Pair>
            </Pairs>
          )}
        </Card>

        <BufferHistory relay={relay} />

        <Card className="span-12" title={t("Hosts attested")} description={t("The hosts whose open session came through this relay. A host connects directly one day and through the relay the next; only the open session says which is true now.")} flush>
          <HostsTable hosts={hosts} />
        </Card>

        {canManage && !relay.revoked_at && <RevokeRelay relay={relay} hosts={hosts.length} />}
      </div>
    </>
  );
}

function HostsTable({ hosts }: { hosts: RelayHost[] }) {
  const t = useT();
  if (hosts.length === 0) {
    return <Empty>{t("No host has an open session through this relay.")}</Empty>;
  }
  return (
    <table>
      <thead>
        <tr>
          <th>{t("Host")}</th><th>{t("Site")}</th><th>{t("Lifecycle")}</th>
          <th>{t("Agent")}</th><th>{t("Connected")}</th><th>{t("Last heartbeat")}</th>
        </tr>
      </thead>
      <tbody>
        {hosts.map((host) => (
          <tr key={host.host_id}>
            <td><Link to={`/hosts/${host.host_id}`}>{host.hostname}</Link></td>
            <td>{host.site}{host.environment ? ` / ${host.environment}` : ""}</td>
            <td>{host.lifecycle_state}</td>
            <td className="source mono">{host.agent_version || "—"}</td>
            <td><Time value={host.connected_at} /></td>
            <td><Time value={host.last_heartbeat_at} /></td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

/**
 * Revoking the relay. From this moment the relay is refused: its heartbeat,
 * its renewal and every new session through it.
 */
function RevokeRelay({ relay, hosts }: { relay: Relay; hosts: number }) {
  const t = useT();
  const queryClient = useQueryClient();
  const [open, setOpen] = useState(false);
  const [reason, setReason] = useState("");
  const [message, setMessage] = useState("");

  const revoke = useMutation({
    mutationFn: () => api.post<{ sessions_closed: number }>(`/api/v1/relays/${relay.id}/revoke`, { reason }),
    onSuccess: (result) => {
      setOpen(false);
      setMessage(t("The relay is revoked; {n} sessions were closed.", { n: result.sessions_closed }));
      queryClient.invalidateQueries({ queryKey: ["relays"] });
    },
    onError: (error) => {
      if (error instanceof ApiError && error.unauthenticated) {
        setMessage(t("Fresh authentication is required: sign in again and repeat the revocation."));
        return;
      }
      setMessage(error instanceof Error ? error.message : String(error));
    },
  });

  return (
    <Card
      className="span-12"
      title={t("Revoke the relay")}
      description={t("The relay stops being recognised at once and cannot renew its certificate. The {n} hosts behind it lose their sessions and reconnect over the paths they still have.", { n: hosts })}
      footer={
        <Actions>
          {!open ? (
            <button className="danger" onClick={() => setOpen(true)}>{t("Revoke…")}</button>
          ) : (
            <>
              <button className="danger" onClick={() => revoke.mutate()} disabled={reason.trim().length < 8 || revoke.isPending}>
                {t("Revoke {name}", { name: relay.name })}
              </button>
              <button className="secondary" onClick={() => { setOpen(false); setReason(""); }}>{t("Cancel")}</button>
            </>
          )}
          {message && <span className="source">{message}</span>}
        </Actions>
      }
    >
      {open && (
        <FieldGrid>
          <Field label={t("Reason (kept in the audit trail)")} hint={t("At least 8 characters. A host in an isolated site has no other path: it stays offline until a new relay is enrolled.")} wide>
            <input value={reason} onChange={(e) => setReason(e.target.value)} />
          </Field>
        </FieldGrid>
      )}
    </Card>
  );
}
