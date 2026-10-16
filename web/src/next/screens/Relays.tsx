import { useState } from "react";
import { Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ApiError } from "../../lib/api";
import { useDebounced } from "../../lib/debounce";
import { absoluteTime, bytes, relativeTime } from "../../lib/format";
import type { Relay, RelayDetail, RelayHost, RelayState, Whoami } from "../../lib/types";
import { useToast } from "../../components/Toast";
import { useT } from "../../i18n";
import { Board } from "../Board";
import type { BoardEntry } from "../../components/board";
import {
  Band, Bars, Card, Chart, Empty, Fact, Facts, Field, Fields, Fig, Figs, Find, Kpi, Meter, Modal, Note, Pill, Problem, Seg, type Segment, type Series, Stack, Table, type Tone, TwoLine,
} from "../kit";

/**
 * The relays: one connection upwards per site, and the plumbing a whole
 * site hangs on once it is there.
 *
 * Everything on this screen is what a relay said about itself. That is
 * why a buffer nobody has reported is an em dash and not a nought: a
 * relay the panel has never heard from is not a relay with an empty
 * spool, and drawing it as one would turn a cut site into a quiet one.
 *
 * The list narrows by site on the server, so a fleet of four hundred
 * sites is not read in order to look at one.
 */

/** How long before the end of a relay certificate the expiry is a warning. */
const EXPIRY_WARNING_MS = 24 * 60 * 60 * 1000;

/** The windows the history offers, from minute by minute to a quarter of a year. */
export const BUFFER_RANGES = ["3h", "24h", "7d", "30d", "90d"] as const;
export type BufferRangeName = (typeof BUFFER_RANGES)[number];

/** One point of the buffer history: one report on a short window, a quarter-hour of them on a long one. */
export type RelayBufferPoint = {
  at: string;
  instance_id?: string;
  bytes_used: number;
  bytes_used_max: number;
  bytes_limit: number;
  item_count: number;
  item_count_max: number;
  dropped_total: number;
  /** The growth since the point before; null across a restart, where the counter starts again. */
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

export function historyAddress(relayID: string, range: BufferRangeName): string {
  return `/api/v1/relays/${relayID}/buffer-history?range=${range}`;
}

export function Relays() {
  const t = useT();
  const toast = useToast();
  const queryClient = useQueryClient();
  const [site, setSite] = useState("");
  const [picked, setPicked] = useState("");
  const [range, setRange] = useState<BufferRangeName>("24h");
  const [revoking, setRevoking] = useState(false);
  const [reason, setReason] = useState("");
  const settledSite = useDebounced(site.trim());

  const query = new URLSearchParams();
  if (settledSite) query.set("site", settledSite);
  const address = `/api/v1/relays${query.toString() ? `?${query}` : ""}`;

  const list = useQuery({
    queryKey: ["relays", query.toString()],
    queryFn: () => api.get<{ items: Relay[] }>(address),
    // A relay reports itself every minute; ten minutes of silence is a
    // site cut off, and nobody should have to reload to learn that.
    refetchInterval: 30 * 1000,
  });

  const me = useQuery({
    queryKey: ["whoami"],
    queryFn: () => api.get<Whoami>("/api/v1/whoami"),
    staleTime: 5 * 60 * 1000,
    retry: false,
  });
  const canManage = (me.data?.permissions ?? []).includes("relay.manage");

  const relays = list.data?.items ?? [];
  const loaded = list.data !== undefined;
  // The one being read: whichever was chosen, or the first of the list, so
  // the cards under the table are never empty for no reason.
  const chosenID = relays.some((one) => one.id === picked) ? picked : relays[0]?.id ?? "";
  const chosen = relays.find((one) => one.id === chosenID);

  const detail = useQuery({
    queryKey: ["relays", chosenID, "detail"],
    queryFn: () => api.get<RelayDetail>(`/api/v1/relays/${chosenID}`),
    enabled: chosenID !== "",
    refetchInterval: 30 * 1000,
  });

  const history = useQuery({
    queryKey: ["relays", chosenID, "buffer-history", range],
    queryFn: () => api.get<RelayBufferHistory>(historyAddress(chosenID, range)),
    enabled: chosenID !== "",
    refetchInterval: 60 * 1000,
  });

  const revoke = useMutation({
    mutationFn: () => api.post<{ sessions_closed: number }>(`/api/v1/relays/${chosenID}/revoke`, { reason: reason.trim() }),
    onSuccess: (result) => {
      setRevoking(false);
      setReason("");
      void queryClient.invalidateQueries({ queryKey: ["relays"] });
      toast.success(t("The relay is revoked; {n} sessions were closed.", { n: result.sessions_closed }));
    },
    onError: (error) => {
      // A revocation asks for a fresh sign-in; that is not a fault of the
      // relay, and the operator is told what to do rather than what broke.
      if (error instanceof ApiError && error.unauthenticated) {
        toast.error(t("Fresh authentication is required: sign in again and repeat the revocation."));
        return;
      }
      toast.error(error instanceof Error ? error.message : String(error));
    },
  });

  if (list.error) return <Problem>{String(list.error)}</Problem>;

  const count = (state: RelayState) => (loaded ? relays.filter((one) => one.state === state).length : undefined);
  const states: Segment[] = [
    { label: t("active"), value: count("active"), tone: "ok" },
    { label: t("silent"), value: count("silent"), tone: "error" },
    { label: t("never seen"), value: count("never_seen"), tone: "unknown" },
    { label: t("revoked"), value: count("revoked"), tone: "neutral" },
  ];

  const bySite = Object.entries(
    relays.reduce<Record<string, number>>((all, one) => { all[one.site] = (all[one.site] ?? 0) + 1; return all; }, {}),
  ).sort((x, y) => y[1] - x[1]);

  const attested = loaded ? relays.reduce((sum, one) => sum + one.hosts_attested, 0) : null;
  // Summed over the relays that reported. Nobody having reported is not a
  // fleet with nothing waiting: it is a fleet nobody has heard from.
  const reported = relays.filter((one) => one.buffer);
  const sumReported = (read: (relay: Relay) => number) =>
    (reported.length === 0 ? null : reported.reduce((sum, one) => sum + read(one), 0));
  const waiting = sumReported((one) => one.buffer?.buffered_items ?? 0);
  const dropped = sumReported((one) => one.buffer?.buffer_dropped ?? 0);

  const points = history.data?.points ?? [];
  const summary = bufferSummary(points, history.data?.step_seconds ?? 60);
  const everyLabel = Math.max(1, Math.ceil(points.length / 8));
  const timeLabels = points.map((one) => new Date(one.at).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }));
  // The spool is drawn in KiB: the axis of a chart is read, and a figure
  // of nine digits is not.
  const spool: Series[] = [
    { name: t("Buffered, KiB"), tone: "accent", values: points.map((one) => Math.round(one.bytes_used / 1024)) },
  ];
  const flow: Series[] = [
    { name: t("Items waiting"), tone: "info", values: points.map((one) => one.item_count) },
    { name: t("Results dropped"), tone: "error", values: points.map((one) => one.dropped_delta ?? 0) },
  ];

  const hosts = detail.data?.hosts ?? [];

  return (
    <>
      

      <Board screen={RELAYS_SCREEN} catalogue={RELAYS} drawn={{
        count: (
          <Kpi hero icon="relays" label={t("Relays")} value={loaded ? relays.length : null}
               note={settledSite ? t("in site {site}", { site: settledSite }) : t("of every site")} />
        ),
        attested: (
          <Kpi icon="hosts" label={t("Hosts attested")} value={attested}
               note={t("hosts whose open session comes through a relay")} />
        ),
        waiting: (
          <Kpi icon="time" label={t("Items waiting")} value={waiting}
               tone={waiting ? "warn" : "ok"}
               note={reported.length === 0 ? t("no relay has reported its spool") : t("in the spools last reported")} />
        ),
        dropped: (
          <Kpi icon="monitoring" label={t("Results dropped")} value={dropped}
               tone={dropped ? "error" : "ok"}
               note={reported.length === 0 ? t("no relay has reported its spool") : t("since each relay last started")} />
        ),
        state: (
          <Card title={t("State")} note={t("Ten minutes of silence is a site cut off from the panel.")}>
            <Band segments={states} testId="relay-states" />
          </Card>
        ),
        sites: (
          <Card title={t("By site")} note={t("Where the relays stand.")}>
            {!loaded
              ? <Empty>{t("Reading the relays…")}</Empty>
              : bySite.length === 0
                ? <Empty>{t("No relay answers this.")}</Empty>
                : <Bars items={bySite.map(([one, n]) => ({ label: one, value: n, tone: "info" as Tone }))} />}
          </Card>
        ),
        list: (
          <Card
            title={t("Relays")}
            flush
            tools={<Find value={site} onChange={setSite} placeholder={t("Site")} testId="site" />}
            foot={t("{n} relays", { n: relays.length })}
          >
            <Table
              rows={relays}
              keyOf={(one) => one.id}
              rowTestId={(one) => `relay-${one.name}`}
              testId="relays"
              empty={list.isLoading
                ? t("Reading the relays…")
                : t("No relay is registered. A relay is enrolled from the add-host screen with a relay token; a site that reaches the panel directly needs none.")}
              columns={[
                { key: "name", head: t("Name"), cell: (one) => (
                  <TwoLine sub={one.advertised_names && one.advertised_names.length > 0
                    ? <code>{one.advertised_names.join(", ")}</code>
                    : undefined}>
                    <button type="button" className="fl-word" onClick={() => setPicked(one.id)}
                            data-testid={`pick-${one.name}`}>{one.name}</button>
                  </TwoLine>
                ) },
                { key: "site", head: t("Site"), cell: (one) => (
                  <TwoLine sub={one.environment || undefined}>{one.site}</TwoLine>
                ) },
                { key: "state", head: t("State"), cell: (one) => (
                  <Pill tone={relayTone(one.state)}>{t(stateWord(one.state))}</Pill>
                ) },
                { key: "seen", head: t("Last seen"), cell: (one) => (
                  one.last_seen_at
                    ? <span title={absoluteTime(one.last_seen_at)}>{relativeTime(one.last_seen_at)}</span>
                    : <span className="fl-faint">{t("— never reported")}</span>
                ) },
                { key: "hosts", head: t("Hosts"), num: true, cell: (one) => one.hosts_attested },
                { key: "buffer", head: t("Spool"), cell: (one) => <BufferCell relay={one} /> },
                { key: "expiry", head: t("Certificate"), minor: true, cell: (one) => (
                  <Expiry value={one.certificate_not_after ?? one.not_after} revoked={!!one.revoked_at} />
                ) },
              ]}
            />
          </Card>
        ),
        relay: (
          <Card
            title={chosen ? chosen.name : t("The relay")}
            note={chosen ? t("Site {site}. What the relay attests is what the panel knows about the site.", { site: chosen.site }) : undefined}
            foot={chosen && canManage && !chosen.revoked_at
              ? (
                <button type="button" className="fl-danger fl-small" onClick={() => setRevoking(true)} data-testid="revoke">
                  {t("Revoke…")}
                </button>
              )
              : undefined}
          >
            {!chosen
              ? <Empty>{t("Choose a relay to read what it reported.")}</Empty>
              : (
                <Stack>
                  <Facts>
                    <Fact label={t("State")}><Pill tone={relayTone(chosen.state)}>{t(stateWord(chosen.state))}</Pill></Fact>
                    <Fact label={t("Site")}>{chosen.environment ? `${chosen.site} / ${chosen.environment}` : chosen.site}</Fact>
                    <Fact label={t("Network names")}>
                      {chosen.advertised_names && chosen.advertised_names.length > 0
                        ? <code>{chosen.advertised_names.join(", ")}</code>
                        : <span className="fl-faint">{t("— not advertised")}</span>}
                    </Fact>
                    <Fact label={t("Enrolled")}>{absoluteTime(chosen.enrolled_at)}</Fact>
                    <Fact label={t("Last seen")}>
                      {chosen.last_seen_at
                        ? <span title={absoluteTime(chosen.last_seen_at)}>{relativeTime(chosen.last_seen_at)}</span>
                        : <span className="fl-faint">{t("— never reported")}</span>}
                    </Fact>
                    <Fact label={t("Certificate expires")}>
                      <TwoLine sub={chosen.serial ? <code>{t("serial {serial}", { serial: chosen.serial })}</code> : undefined}>
                        <Expiry value={chosen.certificate_not_after ?? chosen.not_after} revoked={!!chosen.revoked_at} />
                      </TwoLine>
                    </Fact>
                    {chosen.revoked_at && (
                      <Fact label={t("Revoked")}>
                        <TwoLine sub={chosen.revocation_reason || undefined}>{absoluteTime(chosen.revoked_at)}</TwoLine>
                      </Fact>
                    )}
                  </Facts>
                  {/* The last heartbeat answers "how full is it now" and
                      nothing else; what the site went through is below. */}
                  {!chosen.buffer
                    ? <Note>{t("The relay has not reported since the panel started. A relay reports every minute while it reaches the centre.")}</Note>
                    : (
                      <Figs>
                        <Fig label={t("Reported")} value={relativeTime(chosen.buffer.reported_at)} />
                        <Fig label={t("Sessions at the relay")} value={chosen.buffer.sessions} />
                        <Fig label={t("Items waiting")} value={chosen.buffer.buffered_items}
                             tone={chosen.buffer.buffered_items > 0 ? "warn" : "ok"} />
                        <Fig label={t("Results dropped")} value={chosen.buffer.buffer_dropped}
                             tone={chosen.buffer.buffer_dropped > 0 ? "error" : "ok"} />
                        <Fig label={t("Relay version")} value={chosen.buffer.relay_version || undefined} />
                      </Figs>
                    )}
                </Stack>
              )}
          </Card>
        ),
        hosts: (
          <Card
            title={t("Hosts attested")}
            flush
            note={t("The hosts whose open session comes through this relay. A host connects directly one day and through the relay the next; only the open session says which is true now.")}
          >
            <Table
              rows={hosts}
              keyOf={(one) => one.host_id}
              rowTestId={(one: RelayHost) => `attested-${one.hostname}`}
              empty={!chosen
                ? t("Choose a relay to read what it reported.")
                : detail.isLoading
                  ? t("Reading the relays…")
                  : t("No host has an open session through this relay.")}
              columns={[
                { key: "host", head: t("Host"), cell: (one) => (
                  <TwoLine sub={one.environment ? `${one.site} / ${one.environment}` : one.site}>
                    <Link to={`/next/hosts/${one.host_id}`}>{one.hostname}</Link>
                  </TwoLine>
                ) },
                { key: "lifecycle", head: t("Lifecycle"), minor: true, cell: (one) => one.lifecycle_state },
                { key: "agent", head: t("Agent"), minor: true, tight: true, cell: (one) => (
                  one.agent_version ? <code>{one.agent_version}</code> : <span className="fl-faint">{t("— unknown")}</span>
                ) },
                { key: "connected", head: t("Connected"), cell: (one) => (
                  <span title={absoluteTime(one.connected_at)}>{relativeTime(one.connected_at)}</span>
                ) },
                { key: "heartbeat", head: t("Last heartbeat"), cell: (one) => (
                  one.last_heartbeat_at
                    ? <span title={absoluteTime(one.last_heartbeat_at)}>{relativeTime(one.last_heartbeat_at)}</span>
                    : <span className="fl-faint">{t("— never reported")}</span>
                ) },
              ]}
            />
          </Card>
        ),
        buffer: (
          <Card
            title={t("The spool over time")}
            note={t("What the relay reported about its spool. The reports themselves are kept for {raw} h and the quarter-hour rollups for {rollup} days; a window reaching further back shows nothing because nothing is kept, not because the relay was quiet.", {
              raw: history.data?.raw_retention_hours ?? 0, rollup: history.data?.rollup_retention_days ?? 0,
            })}
            tools={
              <Seg
                value={range}
                onChange={setRange}
                options={BUFFER_RANGES.map((one) => ({ value: one, label: one }))}
              />
            }
          >
            {!chosen
              ? <Empty>{t("Choose a relay to read what it reported.")}</Empty>
              : history.error
                ? <Problem>{String(history.error)}</Problem>
                : !history.data
                  ? <Empty>{t("Reading the relays…")}</Empty>
                  : points.length === 0
                    ? <Empty>{t("The relay reported nothing in this window. A relay reports every minute while it reaches the centre; a silent relay is on the state above, not here.")}</Empty>
                    : (
                      <Stack>
                        <Figs>
                          {/* A fill is a share of a limit, and a relay that
                              never reported one has no share to show. */}
                          <Fig
                            label={t("Peak fill")}
                            value={summary.peakPercent === undefined ? undefined : `${Math.round(summary.peakPercent)}%`}
                            tone={summary.peakPercent === undefined ? undefined
                              : summary.peakPercent > 85 ? "error" : summary.peakPercent > 70 ? "warn" : "ok"}
                          />
                          <Fig label={t("Minutes without upstream")} value={summary.offlineMinutes}
                               tone={summary.offlineMinutes > 0 ? "warn" : "ok"} />
                          <Fig label={t("Results dropped")} value={summary.dropped}
                               tone={summary.dropped > 0 ? "error" : "ok"} />
                          <Fig label={t("Restarts")} value={summary.restarts}
                               tone={summary.restarts > 0 ? "warn" : "neutral"} />
                        </Figs>
                        <Chart labels={timeLabels} series={spool} everyLabel={everyLabel} height={120} />
                        <Chart labels={timeLabels} series={flow} everyLabel={everyLabel} height={120} />
                        {history.data.alerts.length > 0 && (
                          <Facts>
                            {history.data.alerts.map((alert) => (
                              <Fact key={alert.id} label={alert.rule_name}>
                                <TwoLine sub={`${alert.detail ? `${alert.detail} · ` : ""}${relativeTime(alert.fired_at ?? alert.started_at)}`}>
                                  <Pill tone={alert.severity === "critical" ? "error" : "warn"}>{t(alert.severity)}</Pill>
                                </TwoLine>
                              </Fact>
                            ))}
                          </Facts>
                        )}
                      </Stack>
                    )}
          </Card>
        ),
      }} />

      {/* Cutting a site off is a decision, not a form: from this moment the
          relay's heartbeat, its renewal and every new session are refused. */}
      {revoking && chosen && (
        <Modal
          title={t("Revoke {name}", { name: chosen.name })}
          onClose={() => { setRevoking(false); setReason(""); }}
          actions={
            <>
              <button type="button" className="fl-quiet" onClick={() => { setRevoking(false); setReason(""); }}>
                {t("Cancel")}
              </button>
              <button
                type="button"
                className="fl-danger"
                data-testid="revoke-confirm"
                disabled={reason.trim().length < 8 || revoke.isPending}
                onClick={() => revoke.mutate()}
              >
                {revoke.isPending ? t("Revoking…") : t("Revoke the relay")}
              </button>
            </>
          }
        >
          <Stack>
            <Note>
              {t("The relay stops being recognised at once and cannot renew its certificate. The {n} hosts behind it lose their sessions and reconnect over the paths they still have.", { n: hosts.length })}
            </Note>
            <Fields>
              <Field
                label={t("Reason (kept in the trail)")}
                hint={t("At least 8 characters. A host in an isolated site has no other path: it stays offline until a new relay is enrolled.")}
                wide
              >
                <input value={reason} onChange={(event) => setReason(event.target.value)} data-testid="revoke-reason" />
              </Field>
            </Fields>
          </Stack>
        </Modal>
      )}
    </>
  );
}

/** The fill of the spool as the relay last reported it, or an em dash where it never did. */
function BufferCell({ relay }: { relay: Relay }) {
  const t = useT();
  const buffer = relay.buffer;
  if (!buffer) return <span className="fl-faint">{t("— not reported")}</span>;
  const share = buffer.buffer_max_bytes > 0 ? buffer.buffer_bytes / buffer.buffer_max_bytes : 0;
  const tone: Tone = buffer.buffer_dropped > 0 ? "error" : share > 0.7 ? "warn" : "ok";
  return (
    <TwoLine
      sub={buffer.buffer_dropped > 0
        ? t("{n} items · {dropped} dropped", { n: buffer.buffered_items, dropped: buffer.buffer_dropped })
        : t("{n} items", { n: buffer.buffered_items })}
    >
      <Meter
        share={share}
        tone={tone}
        text={buffer.buffer_max_bytes > 0
          ? `${bytes(buffer.buffer_bytes)} / ${bytes(buffer.buffer_max_bytes)}`
          : bytes(buffer.buffer_bytes)}
      />
    </TwoLine>
  );
}

/** The end of the certificate, with a warning where the renewal is late. */
function Expiry({ value, revoked }: { value?: string; revoked: boolean }) {
  const t = useT();
  if (!value) return <span className="fl-faint">{t("— unknown")}</span>;
  const left = new Date(value).getTime() - Date.now();
  if (left < 0 && !revoked) return <Pill tone="error">{t("expired")}</Pill>;
  const tone: Tone = revoked ? "neutral" : left < EXPIRY_WARNING_MS ? "warn" : "ok";
  return <Pill tone={tone} title={absoluteTime(value)} dot={false}>{relativeTime(value)}</Pill>;
}

/** The state of a relay as a tone: silence is a fault, a revocation is a decision. */
export function relayTone(state: RelayState): Tone {
  if (state === "active") return "ok";
  if (state === "silent") return "error";
  if (state === "never_seen") return "unknown";
  return "neutral";
}

/** The state of a relay in the words it is read in. */
export function stateWord(state: RelayState): string {
  return state === "never_seen" ? "never seen" : state;
}

/**
 * What the window as a whole says, read off the points.
 *
 * The drops are summed from the deltas rather than from the counter: the
 * counter starts again at every restart, and a window with a restart in
 * it would otherwise report fewer drops than it held.
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

export const RELAYS_SCREEN = "next_relays";

export const RELAYS: BoardEntry[] = [
  { key: "count", title: "How many relays", width: 3, height: 1 },
  { key: "attested", title: "Hosts attested", width: 3, height: 1 },
  { key: "waiting", title: "Items waiting", width: 3, height: 1 },
  { key: "dropped", title: "Results dropped", width: 3, height: 1 },
  { key: "state", title: "State", width: 8, height: 2 },
  { key: "sites", title: "By site", width: 4, height: 2 },
  { key: "list", title: "Relays", width: 12, height: 4 },
  { key: "relay", title: "The relay", width: 6, height: 3 },
  { key: "hosts", title: "Hosts behind the relay", width: 6, height: 3 },
  { key: "buffer", title: "The spool over time", width: 12, height: 4 },
];
