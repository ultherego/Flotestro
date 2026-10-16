import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../../../lib/api";
import { useAllowed, useModuleAccess } from "../../../lib/actions";
import { absoluteTime, bytes, relativeTime } from "../../../lib/format";
import { capability } from "../../../lib/modules";
import type {
  Alert, Host, HostMetrics, HostMonitoring, MetricPoint, MetricRange, RuleCatalogue,
} from "../../../lib/types";
import { useT } from "../../../i18n";
import {
  alertStateName, alertStateTone, metricValue, severityTone, uptime, type ScopedSilence,
} from "../Monitoring";
import { Board } from "../../Board";
import type { BoardEntry } from "../../../components/board";
import {
  Actions, Band, Banner, Bones, Button, Card, Chart, Check, Empty, Fact, Facts, Field, Fields,
  HeadActions, Meter, Note, Pill, Problem, Seg, Stack, Table, Tags, type Segment, type Tone,
  stacked,
} from "../../kit";

/**
 * What this machine has been doing, as the product measures it itself.
 *
 * There is no Prometheus under this: the agent samples itself every minute
 * and the panel keeps the readings. That is why the one rule of this screen
 * is about holes. A stretch the host never reported is not a stretch at
 * zero, so a reading the server did not send is dropped from the drawing
 * rather than pushed into it as a nought - and the number of holes is said
 * in words beside the chart, where a flat line would have lied about them.
 */

/** The one order this module places; refused, it leaves a read of the samples already taken. */
const MONITORING_READS = ["monitoring.probe.run"];

const RANGES: { value: MetricRange; label: string }[] = [
  { value: "3h", label: "3 hours" },
  { value: "24h", label: "24 hours" },
  { value: "7d", label: "7 days" },
  { value: "30d", label: "30 days" },
];

/** At most this many silence minutes the server takes. */
export const MAX_SILENCE_MINUTES = 1440;
/** The shortest reason a silence is recorded with. */
export const MIN_REASON = 8;

/**
 * How an instant reads on the time axis: the hour in a short window, the
 * day in a long one.
 */
export function axisLabel(range: MetricRange): (iso: string) => string {
  const time = (iso: string) => absoluteTime(iso).slice(11, 16);
  const day = (iso: string) => absoluteTime(iso).slice(5, 10);
  if (range === "3h" || range === "24h") return time;
  if (range === "7d") return (iso) => `${day(iso)} ${time(iso)}`;
  return day;
}

/**
 * The points of one drawing: only those the host actually reported every
 * one of the asked-for readings for.
 *
 * A point the server did not send is left out of the labels and out of
 * every series, which is the whole difference between "the machine was
 * quiet" and "the machine was idle". Nothing here ever substitutes a nought
 * for a reading nobody took.
 */
export function readings(
  points: MetricPoint[],
  reads: ((point: MetricPoint) => number | undefined)[],
): { labels: string[]; values: number[][] } {
  const labels: string[] = [];
  const values: number[][] = reads.map(() => []);
  for (const point of points) {
    const taken = reads.map((read) => read(point));
    if (taken.some((one) => one === undefined || !Number.isFinite(one))) continue;
    labels.push(point.at);
    taken.forEach((one, index) => values[index].push(one as number));
  }
  return { labels, values };
}

/**
 * The busiest interface of the window: the one that moved the most bytes in
 * both directions.
 */
export function busiestInterface(points: MetricPoint[]): { name: string; count: number } | undefined {
  const totals = new Map<string, number>();
  for (const point of points) {
    for (const link of point.interfaces ?? []) {
      totals.set(link.name, (totals.get(link.name) ?? 0) + (link.rx_bytes_per_second ?? 0) + (link.tx_bytes_per_second ?? 0));
    }
  }
  const sorted = [...totals.entries()].sort((a, b) => b[1] - a[1]);
  return sorted.length ? { name: sorted[0][0], count: sorted.length } : undefined;
}

/** The tone of a share of a whole: four fifths is a warning, nine tenths a fault. */
export function usageTone(used?: number, total?: number): Tone {
  if (used === undefined || total === undefined || total <= 0) return "neutral";
  const share = used / total;
  if (share >= 0.9) return "error";
  if (share >= 0.8) return "warn";
  return "ok";
}

/** A count of what satisfies a test, or undefined where the list itself is unknown. */
function countWhere<T>(items: T[] | undefined, test: (item: T) => boolean): number | undefined {
  return items === undefined ? undefined : items.filter(test).length;
}

export function Monitoring({ host }: { host: Host }) {
  const t = useT();
  const queryClient = useQueryClient();
  const [range, setRange] = useState<MetricRange>("3h");
  const [message, setMessage] = useState("");
  const [silenceReason, setSilenceReason] = useState("");
  const [minutes, setMinutes] = useState("60");
  const [silenceRule, setSilenceRule] = useState("");
  const [sendSummary, setSendSummary] = useState(false);

  const metrics = useQuery({
    queryKey: ["monitoring", host.id, "metrics", range],
    queryFn: () => api.get<HostMetrics>(`/api/v1/hosts/${host.id}/metrics?range=${range}`),
    refetchInterval: 60000,
    retry: false,
  });
  const report = useQuery({
    queryKey: ["monitoring", host.id, "state"],
    queryFn: () => api.get<HostMonitoring>(`/api/v1/hosts/${host.id}/monitoring`),
    refetchInterval: 30000,
    retry: false,
  });
  // The rule catalogue names the rules a silence can be narrowed to; a
  // viewer who may not read it still silences every rule of the host.
  const rules = useQuery({
    queryKey: ["monitoring", "rules"],
    queryFn: () => api.get<RuleCatalogue>("/api/v1/monitoring/rules"),
    retry: false,
  });

  const access = useModuleAccess(host.id, MONITORING_READS);
  const refresh = () => queryClient.invalidateQueries({ queryKey: ["monitoring"] });

  const silence = useMutation({
    mutationFn: (ruleID: string) =>
      api.post<ScopedSilence>(`/api/v1/hosts/${host.id}/monitoring/silences`, {
        reason: silenceReason.trim(),
        minutes: Number(minutes) || 60,
        send_summary: sendSummary,
        ...(ruleID ? { rule_id: ruleID } : {}),
      }),
    onSuccess: (created) => {
      setMessage(t("{rule} is silenced until {until}.", {
        rule: created.rule_name ?? t("Every rule"),
        until: absoluteTime(created.until),
      }));
      setSilenceReason("");
      void refresh();
    },
    onError: (error) => setMessage(error instanceof Error ? error.message : String(error)),
  });

  // A silence that names no host is in force here but belongs to no host,
  // so it is ended on the fleet path.
  const unsilence = useMutation({
    mutationFn: (entry: ScopedSilence) =>
      api.del(entry.host_id
        ? `/api/v1/hosts/${host.id}/monitoring/silences/${encodeURIComponent(entry.id)}`
        : `/api/v1/monitoring/silences/${encodeURIComponent(entry.id)}`),
    onSuccess: () => {
      setMessage(t("Silence ended."));
      void refresh();
    },
    onError: (error) => setMessage(error instanceof Error ? error.message : String(error)),
  });

  const state = report.data;
  const series = metrics.data;
  const points = series?.points ?? [];
  const gaps = series?.gaps ?? [];
  const explained = gaps.find((gap) => gap.reason);
  const clock = state?.clock_substitution ?? null;
  const refused = state?.refused ?? [];
  const refusedSamples = refused.reduce((sum, one) => sum + one.samples, 0);
  const latest = series?.latest ?? state?.latest ?? null;
  const lastSampleAt = series?.last_sample_at ?? state?.last_sample_at ?? undefined;
  const rollup = (series?.step_seconds ?? 60) > 60;
  const label = axisLabel(range);
  // Unread alerts are not zero alerts: the band shows dashes then.
  const knownAlerts: Alert[] | undefined = state?.alerts;
  const alerts = knownAlerts ?? [];
  const silences = (state?.silences ?? []) as ScopedSilence[];
  const reasonReady = silenceReason.trim().length >= MIN_REASON
    && Number(minutes) > 0 && Number(minutes) <= MAX_SILENCE_MINUTES;
  // The rules a silence can name: the catalogue when it is readable, else
  // the ones already alerting on this host.
  const ruleOptions = rules.data
    ? rules.data.items.map((one) => ({ id: one.id, name: one.name }))
    : alerts
      .filter((one, index, list) => list.findIndex((other) => other.rule_id === one.rule_id) === index)
      .map((one) => ({ id: one.rule_id, name: one.rule_name }));

  const link = busiestInterface(points);
  const cpu = readings(points, [(one) => one.cpu_percent]);
  const load = readings(points, [(one) => one.load1, (one) => one.load5, (one) => one.load15]);
  const memory = readings(points, [(one) => one.memory_used, (one) => one.swap_used]);
  const network = link
    ? readings(points, [
        (one) => one.interfaces?.find((item) => item.name === link.name)?.rx_bytes_per_second,
        (one) => one.interfaces?.find((item) => item.name === link.name)?.tx_bytes_per_second,
      ])
    : { labels: [], values: [[], []] };
  const agentMemory = readings(points, [(one) => one.agent_rss_bytes]);
  const helperMemory = readings(points, [(one) => one.helper_rss_bytes]);
  const agentCPU = readings(points, [(one) => one.agent_cpu_percent]);
  const agentReported = agentMemory.labels.length > 0 || agentCPU.labels.length > 0;

  const everyLabel = (count: number) => Math.max(1, Math.ceil(count / 8));
  const axis = (labels: string[]) => labels.map(label);
  /* A measure with a ceiling is drawn to that ceiling. A CPU chart scaled
     to its own highest reading says a host at 4% is as loaded as one at
     99%; memory drawn against the host's total says how much of the
     machine is gone. The axis is written in the measure's own units: a
     memory axis labelled 4294967296 is a number nobody reads. */
  const memoryTop = Math.max(0, ...points.map((one) => one.memory_total ?? 0));
  const percent = (value: number) => `${Math.round(value)}%`;
  const rate = (value: number) => `${bytes(value)}/s`;

  /**
   * What stands where a drawing would, while there is nothing to draw: the
   * refusal, the shape of what is coming, or the reason the window is
   * empty. A chart is never drawn over an answer nobody has given.
   */
  const blank = metrics.error
    ? <Problem>{String(metrics.error)}</Problem>
    : !series
      ? <Bones rows={4} height={22} />
      : !latest
        ? <Empty icon="monitoring">{t("The agent has not sent a sample yet")}</Empty>
        : points.length === 0
          ? (
            <Empty icon="monitoring">
              {explained
                ? t("No sample in this window: the panel refused {n} ({reason}).", {
                    n: explained.refused_samples ?? 0, reason: explained.reason ?? t("unknown"),
                  })
                : t("No sample in this window.")}
            </Empty>
          )
          : null;

  const holes = gaps.length > 0
    ? t("{n} gaps in this window; the points the host never sent are left out rather than drawn at nought.", { n: gaps.length })
    : undefined;

  const readOnly = access.known && !access.anyAllowed
    ? access.permissions.length > 0 && access.reasons.length === 0
      ? t("You can read this module; changing it needs the permission {permissions}.", {
          permissions: access.permissions.join(", "),
        })
      : t("You can read this module; changing it is not possible here: {reasons}", {
          reasons: [
            ...access.reasons,
            ...access.permissions.map((one) => t("missing permission {permission}", { permission: one })),
          ].join("; "),
        })
    : "";

  const alertBand: Segment[] = [
    { label: t("Critical"), value: countWhere(knownAlerts, (one) => one.state === "firing" && one.severity === "critical" && !one.silenced), tone: "error" },
    { label: t("Warning"), value: countWhere(knownAlerts, (one) => one.state === "firing" && one.severity === "warning" && !one.silenced), tone: "warn" },
    { label: t("Info"), value: countWhere(knownAlerts, (one) => one.state === "firing" && one.severity === "info" && !one.silenced), tone: "info" },
    { label: t("Pending"), value: countWhere(knownAlerts, (one) => one.state === "pending"), tone: "unknown" },
    { label: t("Silenced"), value: countWhere(knownAlerts, (one) => one.state !== "resolved" && one.silenced), tone: "neutral" },
  ];

  if (report.error && metrics.error) return <Problem>{String(report.error)}</Problem>;

  const probeAllowed = capability(host, "monitoring")?.available === true;

  return (
    <>
      <HeadActions>
        <Seg
          value={range}
          onChange={setRange}
          label={t("Window")}
          options={RANGES.map((one) => ({ value: one.value, label: t(one.label) }))}
        />
      </HeadActions>

      <Board screen={HOST_MONITORING_SCREEN} catalogue={HOST_MONITORING} drawn={{
        notices: stacked(
          readOnly && <Banner tone="info">{readOnly}</Banner>,
          message && <Banner tone="info">{message}</Banner>,
          // A hole in the data and a quiet machine read alike on a chart,
          // so the holes and their cause are named before the charts.
          holes && (
            <Banner tone="warn">
              {holes}
              {explained?.reason ? ` ${t("Cause: {reason}.", { reason: explained.reason })}` : ""}
            </Banner>
          ),
          refusedSamples > 0 && (
            <Banner tone="error">
              {t("{n} samples refused", { n: refusedSamples })}
              {refused[0]?.reason ? ` \u00b7 ${refused[0].reason}` : ""}
            </Banner>
          ),
          clock && (
            <Banner tone="warn">
              {t("The panel stamped {n} readings of this host with its own time; the host's clock stood {skew} from the panel's.", {
                n: clock.samples, skew: uptime(Math.round(Math.abs(clock.skew_millis) / 1000)),
              })}
            </Banner>
          ),
        ),
        alerts_band: (
          <Card
            title={t("Alerts")}
            note={t("Firing for this host, by severity; the pending and the silenced ones counted apart.")}
          >
            <Band segments={alertBand} testId="alert-states" />
          </Card>
        ),
        freshness: (
          <Card title={t("Sampling")}>
            {!series && !state ? <Bones rows={3} /> : (
              <Facts>
                <Fact label={t("Last sample")}>
                  {lastSampleAt
                    ? <span title={absoluteTime(lastSampleAt)}>{relativeTime(lastSampleAt)}</span>
                    : <span className="fl-faint">{t("The agent has not sent a sample yet")}</span>}
                </Fact>
                <Fact label={t("Sampling interval")}>
                  {series ? t("every {n} s", { n: series.sampling_interval_seconds }) : <span className="fl-faint">—</span>}
                </Fact>
                <Fact label={t("Steps")}>
                  {!series
                    ? <span className="fl-faint">—</span>
                    : rollup
                      ? t("15-minute rollups with the peak of each step")
                      : t("raw samples")}
                </Fact>
                <Fact label={t("Gaps in this window")}>
                  {series ? gaps.length : <span className="fl-faint">—</span>}
                </Fact>
              </Facts>
            )}
          </Card>
        ),
        cpu: (
          <Card
            title={t("CPU")}
            note={t("Busy time across all cores, in percent.")}
            tools={latest && <span className="fl-mono">{t("now {value}", { value: metricValue("cpu_percent", latest.cpu_percent) })}</span>}
            foot={holes}
          >
            {blank ?? (cpu.labels.length === 0
              ? <Empty icon="monitoring">{t("No reading in this window.")}</Empty>
              : (
                <Chart
                  shape="area"
                  testId="cpu-chart"
                  labels={axis(cpu.labels)}
                  everyLabel={everyLabel(cpu.labels.length)}
                  max={100}
                  format={percent}
                  series={[{ name: t("CPU"), tone: "accent", values: cpu.values[0] }]}
                />
              ))}
          </Card>
        ),
        load: (
          <Card
            title={t("Load")}
            note={t("Load average over 1, 5 and 15 minutes.")}
            tools={latest && (
              <span className="fl-mono">
                {`${latest.load1.toFixed(2)} · ${latest.load5.toFixed(2)} · ${latest.load15.toFixed(2)}`}
              </span>
            )}
            foot={holes}
          >
            {blank ?? (load.labels.length === 0
              ? <Empty icon="monitoring">{t("No reading in this window.")}</Empty>
              : (
                <Chart
                  shape="line"
                  testId="load-chart"
                  labels={axis(load.labels)}
                  everyLabel={everyLabel(load.labels.length)}
                  format={(value) => String(Math.round(value * 100) / 100)}
                  series={[
                    { name: t("1 min"), tone: "accent", values: load.values[0] },
                    { name: t("5 min"), tone: "warn", values: load.values[1] },
                    { name: t("15 min"), tone: "unknown", values: load.values[2] },
                  ]}
                />
              ))}
          </Card>
        ),
        memory: (
          <Card
            title={t("Memory")}
            note={t("Used memory against the total, with swap as a second line.")}
            tools={latest && <span className="fl-mono">{`${bytes(latest.memory_used)} / ${bytes(latest.memory_total)}`}</span>}
            foot={holes}
          >
            {blank ?? (memory.labels.length === 0
              ? <Empty icon="monitoring">{t("No reading in this window.")}</Empty>
              : (
                <Chart
                  shape="line"
                  testId="memory-chart"
                  labels={axis(memory.labels)}
                  everyLabel={everyLabel(memory.labels.length)}
                  max={memoryTop > 0 ? memoryTop : undefined}
                  format={bytes}
                  series={[
                    { name: t("Memory used"), tone: "accent", values: memory.values[0] },
                    { name: t("Swap used"), tone: "warn", values: memory.values[1] },
                  ]}
                />
              ))}
          </Card>
        ),
        network: (
          <Card
            title={t("Network")}
            note={link && link.count > 1
              ? t("{name}, the busiest of {n} interfaces; bytes per second.", { name: link.name, n: link.count })
              : t("Bytes per second, received and sent.")}
            foot={holes}
          >
            {blank ?? (!link || network.labels.length === 0
              ? <Empty icon="network">{t("No interface rates in this window: a rate needs two samples.")}</Empty>
              : (
                <Chart
                  shape="line"
                  testId="network-chart"
                  labels={axis(network.labels)}
                  everyLabel={everyLabel(network.labels.length)}
                  format={rate}
                  series={[
                    { name: t("{name} received", { name: link.name }), tone: "ok", values: network.values[0] },
                    { name: t("{name} sent", { name: link.name }), tone: "accent", values: network.values[1] },
                  ]}
                />
              ))}
          </Card>
        ),
        agent: (
          // The agent measured by itself: what it costs the host it watches.
          // The release gate reads the same numbers off the fleet.
          <Card
            title={t("Agent")}
            note={t("The agent's own footprint: resident memory, with the helper's while it runs, and CPU as a share of one core.")}
            tools={latest?.agent_rss_bytes !== undefined && (
              <span className="fl-mono">{t("now {value}", { value: bytes(latest.agent_rss_bytes) })}</span>
            )}
            foot={holes}
          >
            {blank ?? (!agentReported
              ? <Empty icon="monitoring">{t("The agent does not report its footprint; an older agent does not.")}</Empty>
              : (
                <Stack>
                  {agentMemory.labels.length > 0 && (
                    <Chart
                      shape="line"
                      testId="agent-memory-chart"
                      labels={axis(agentMemory.labels)}
                      everyLabel={everyLabel(agentMemory.labels.length)}
                      format={bytes}
                      series={[
                        { name: t("Agent RSS"), tone: "accent", values: agentMemory.values[0] },
                        // The helper sleeps between orders, so it is drawn
                        // over its own points: the stretches where it was
                        // not running are not the same as nought bytes.
                        ...(helperMemory.labels.length === agentMemory.labels.length
                          ? [{ name: t("Helper RSS"), tone: "warn" as const, values: helperMemory.values[0] }]
                          : []),
                      ]}
                    />
                  )}
                  {agentCPU.labels.length > 0 && (
                    <Chart
                      shape="area"
                      testId="agent-cpu-chart"
                      labels={axis(agentCPU.labels)}
                      everyLabel={everyLabel(agentCPU.labels.length)}
                      format={(value) => `${Math.round(value * 10) / 10}%`}
                      series={[{ name: t("Agent CPU, percent of one core"), tone: "accent", values: agentCPU.values[0] }]}
                    />
                  )}
                </Stack>
              ))}
          </Card>
        ),
        agent_facts: (
          <Card title={t("Agent facts")} note={t("As of the last sample.")}>
            <Facts>
              <Fact label={t("Agent RSS")}>
                {latest?.agent_rss_bytes !== undefined ? bytes(latest.agent_rss_bytes) : <span className="fl-faint">—</span>}
              </Fact>
              <Fact label={t("Agent CPU")}>
                {latest?.agent_cpu_percent !== undefined
                  ? `${Math.round(latest.agent_cpu_percent * 10) / 10}%`
                  : <span className="fl-faint">—</span>}
              </Fact>
              <Fact label={t("Goroutines")}>
                {latest?.agent_goroutines ?? <span className="fl-faint">—</span>}
              </Fact>
              <Fact label={t("Open descriptors")}>
                {latest?.agent_open_fds ?? <span className="fl-faint">—</span>}
              </Fact>
              {/* The helper sleeps between orders, so most samples carry
                  nothing for it; an absent value is also what an agent that
                  could not read its PID sends, so the two are not told
                  apart here. */}
              <Fact label={t("Helper RSS")}>
                {latest?.helper_rss_bytes !== undefined
                  ? bytes(latest.helper_rss_bytes)
                  : <span className="fl-faint">{t("not running, or not measured")}</span>}
              </Fact>
            </Facts>
          </Card>
        ),
        filesystems: (
          <Card title={t("Filesystems")} note={t("As of the last sample.")} flush>
            <Table
              rows={latest?.filesystems ?? []}
              keyOf={(one) => one.mount}
              testId="filesystems"
              loading={!latest && !metrics.error && !series}
              empty={latest ? t("The sample lists no filesystem.") : t("The agent has not sent a sample yet")}
              columns={[
                { key: "mount", head: t("Mount"), tight: true, cell: (one) => (
                  <span className="fl-mono" title={one.mount}>{one.mount}</span>
                ) },
                { key: "inodes", head: t("Inodes"), minor: true, num: true, cell: (one) => (
                  one.inodes_total > 0
                    ? `${Math.round((one.inodes_used / one.inodes_total) * 100)}%`
                    : <span className="fl-faint">—</span>
                ) },
                { key: "used", head: t("Used"), cell: (one) => (
                  <Meter
                    share={one.total_bytes > 0 ? one.used_bytes / one.total_bytes : 0}
                    tone={usageTone(one.used_bytes, one.total_bytes)}
                    text={`${bytes(one.used_bytes)} / ${bytes(one.total_bytes)}`}
                  />
                ) },
              ]}
            />
          </Card>
        ),
        facts: (
          <Card title={t("Facts")}>
            <Facts>
              <Fact label={t("Uptime")}>
                {latest ? uptime(latest.uptime_seconds) : <span className="fl-faint">—</span>}
              </Fact>
              <Fact label={t("Last sample")}>
                {lastSampleAt
                  ? <span title={absoluteTime(lastSampleAt)}>{relativeTime(lastSampleAt)}</span>
                  : <span className="fl-faint">—</span>}
              </Fact>
              <Fact label={t("Samples in window")}>
                {!series
                  ? <span className="fl-faint">—</span>
                  : rollup
                    ? t("{n} steps of 15 minutes", { n: points.length })
                    : t("{n} samples", { n: points.length })}
              </Fact>
              <Fact label={t("Rules watching this host")}>
                {state ? state.rules_matching : <span className="fl-faint">—</span>}
              </Fact>
              <Fact label={t("Memory total")}>
                {latest ? bytes(latest.memory_total) : <span className="fl-faint">—</span>}
              </Fact>
              {/* A refused reading leaves a hole with a cause; a host that
                  never sent one leaves a hole with none. */}
              <Fact label={t("Refused samples")}>
                {!state
                  ? <span className="fl-faint">—</span>
                  : refused.length === 0
                    ? <span className="fl-faint">{t("none")}</span>
                    : (
                      <Tags>
                        <Pill tone="error" title={refused[0].reason}>{refusedSamples}</Pill>
                        <span className="fl-note" title={absoluteTime(refused[0].last_sample_at)}>
                          {relativeTime(refused[0].last_sample_at)}
                        </span>
                      </Tags>
                    )}
              </Fact>
            </Facts>
          </Card>
        ),
        silence: (
          <Card
            title={t("Silence")}
            note={t("A silence turns a sensor off, so it always ends: at most a day, with a reason and an owner in the audit trail.")}
            foot={t("The reason above is also used by the Silence buttons in the alerts table.")}
          >
            <Stack>
              <Fields>
                <Field label={t("Reason (at least 8 characters)")} wide>
                  <input
                    value={silenceReason}
                    onChange={(event) => setSilenceReason(event.target.value)}
                    data-testid="silence-reason"
                  />
                </Field>
                <Field label={t("Minutes")} hint={t("At most 1440.")}>
                  <input
                    type="number"
                    min={1}
                    max={MAX_SILENCE_MINUTES}
                    value={minutes}
                    onChange={(event) => setMinutes(event.target.value)}
                    data-testid="silence-minutes"
                  />
                </Field>
                <Field label={t("Rule")}>
                  <select
                    value={silenceRule}
                    onChange={(event) => setSilenceRule(event.target.value)}
                    data-testid="silence-rule"
                  >
                    <option value="">{t("every rule")}</option>
                    {ruleOptions.map((one) => <option key={one.id} value={one.id}>{one.name}</option>)}
                  </select>
                </Field>
                <Field label={t("When it ends")}>
                  <Check checked={sendSummary} onChange={setSendSummary}>
                    {t("send one summary per channel")}
                  </Check>
                </Field>
              </Fields>
              <Actions>
                <Button
                  disabled={!reasonReady || silence.isPending}
                  onClick={() => silence.mutate(silenceRule)}
                  testId="silence"
                >
                  {silence.isPending
                    ? t("Silencing…")
                    : silenceRule ? t("Silence this rule") : t("Silence every rule of this host")}
                </Button>
              </Actions>
            </Stack>
          </Card>
        ),
        alerts: (
          <Card title={t("Alerts")} flush>
            {report.error ? <Problem>{String(report.error)}</Problem> : (
              <Table
                rows={alerts}
                keyOf={(one) => one.id}
                rowTestId={(one) => `alert-${one.id}`}
                testId="alerts"
                loading={!state}
                empty={t("No alert is pending or firing for this host.")}
                columns={[
                  { key: "rule", head: t("Rule"), cell: (one) => (
                    <span title={one.metric}>{one.rule_name}</span>
                  ) },
                  { key: "metric", head: t("Metric"), minor: true, tight: true, cell: (one) => (
                    <code title={one.metric}>{one.metric}</code>
                  ) },
                  { key: "severity", head: t("Severity"), cell: (one) => (
                    <Pill tone={severityTone(one.severity)}>{t(one.severity)}</Pill>
                  ) },
                  { key: "state", head: t("State"), cell: (one) => (
                    <Pill tone={alertStateTone(one.state, one.silenced)}>
                      {t(alertStateName(one.state, one.silenced))}
                    </Pill>
                  ) },
                  { key: "value", head: t("Value"), num: true, cell: (one) => metricValue(one.metric, one.value) },
                  { key: "detail", head: t("Detail"), minor: true, tight: true, cell: (one) => one.detail },
                  { key: "since", head: t("Since"), cell: (one) => {
                    const at = one.fired_at || one.started_at;
                    return at
                      ? <span title={absoluteTime(at)}>{relativeTime(at)}</span>
                      : <span className="fl-faint">—</span>;
                  } },
                  { key: "do", actions: true, cell: (one) => (
                    // A resolved alert has nothing left to silence; the
                    // button would order a silence for a rule that is quiet.
                    one.state === "resolved"
                      ? <span className="fl-faint" title={t("The alert is resolved; there is nothing to silence.")}>—</span>
                      : (
                        <Button
                          kind="quiet"
                          disabled={one.silenced || !reasonReady || silence.isPending}
                          title={one.silenced
                            ? t("Already silenced.")
                            : reasonReady ? undefined : t("Write a reason in the silence form first.")}
                          onClick={() => silence.mutate(one.rule_id)}
                          testId={`silence-${one.rule_id}`}
                        >
                          {t("Silence this")}
                        </Button>
                      )
                  ) },
                ]}
              />
            )}
          </Card>
        ),
        silences: (
          <Card title={t("Silences in force")} flush>
            <Table
              rows={silences}
              keyOf={(one) => one.id}
              rowTestId={(one) => `silence-${one.id}`}
              testId="silences"
              loading={!state}
              empty={t("No silence is in force for this host.")}
              columns={[
                { key: "until", head: t("Until"), cell: (one) => (
                  <span title={absoluteTime(one.until)}>{relativeTime(one.until)}</span>
                ) },
                { key: "rule", head: t("Rule"), cell: (one) => (
                  one.rule_name || <span className="fl-faint">{t("every rule")}</span>
                ) },
                { key: "scope", head: t("Scope"), cell: (one) => (
                  <Tags>
                    {!one.host_id && <Pill tone="neutral">{t("every host")}</Pill>}
                    {one.global && (
                      <Pill tone="warn" title={t("Keeps back the security alerts of the whole installation.")}>
                        {t("global")}
                      </Pill>
                    )}
                    {one.send_summary && (
                      <Pill dot={false} title={t("When it ends, every channel gets one message naming what it kept back.")}>
                        {t("summary")}
                      </Pill>
                    )}
                  </Tags>
                ) },
                { key: "reason", head: t("Reason"), cell: (one) => one.reason },
                { key: "by", head: t("By"), minor: true, tight: true, cell: (one) => one.created_by },
                { key: "do", actions: true, cell: (one) => (
                  <Button
                    kind="quiet"
                    disabled={unsilence.isPending}
                    onClick={() => unsilence.mutate(one)}
                    testId={`unsilence-${one.id}`}
                  >
                    {t("End now")}
                  </Button>
                ) },
              ]}
            />
          </Card>
        ),
        probe: probeAllowed ? <ProbeNow host={host} /> : undefined,
      }} />
    </>
  );
}

/** What the host saw when it probed the target, as the attempt carries it. */
type ProbeResult = {
  kind?: string;
  message?: string;
  probe?: {
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
    observed_at?: string;
  };
};

/** One attempt of a job as a result view reads it. */
type ReadAttempt<T> = { status?: string; error_code?: string; message?: string; detail?: T };

/**
 * A probe on demand: the host checks a service from where it stands and
 * reports what it saw - reachable or not, the answer it got, and whether
 * that answer met the expectation.
 */
function ProbeNow({ host }: { host: Host }) {
  const t = useT();
  const queryClient = useQueryClient();
  const [kind, setKind] = useState<"http" | "tcp">("http");
  const [target, setTarget] = useState("");
  const [expectStatus, setExpectStatus] = useState("");
  const [expectBody, setExpectBody] = useState("");
  const [job, setJob] = useState("");
  const [message, setMessage] = useState("");
  const may = useAllowed(host.id, "monitoring.probe.run");

  const order = useMutation({
    mutationFn: (body: Record<string, unknown>) =>
      api.post<{ id: string }>(`/api/v1/hosts/${host.id}/operations`, body),
    onSuccess: (created) => {
      setMessage("");
      setJob(created.id);
      void queryClient.invalidateQueries({ queryKey: ["jobs", host.id] });
    },
    onError: (error) => setMessage(error instanceof Error ? error.message : String(error)),
  });

  const attempts = useQuery({
    queryKey: ["job-attempts", job],
    queryFn: () => api.get<{ items: ReadAttempt<ProbeResult>[] }>(`/api/v1/jobs/${job}/attempts`),
    enabled: job !== "",
    refetchInterval: (query) => {
      const items = (query.state.data as { items?: { status?: string }[] } | undefined)?.items;
      return items?.[items.length - 1]?.status ? false : 2000;
    },
  });

  const items = attempts.data?.items ?? [];
  const last = items.length > 0 ? items[items.length - 1] : undefined;
  const attempt = last?.status ? last : undefined;
  const busy = order.isPending || (job !== "" && !attempt);
  const result = attempt?.detail?.probe;
  const refused = attempt && attempt.status !== "succeeded" && !result;

  const address = target.trim();
  const valid = address !== "" && !/\s/.test(address)
    && (kind === "http" ? /^https?:\/\/\S+$/.test(address) : /^\S+:\d{1,5}$/.test(address));

  return (
    <Card
      title={t("Run a probe now")}
      note={t("The host checks a service from where it stands: an HTTP address or a host:port. The answer is the host's view at this moment and belongs to the job, not to the inventory.")}
    >
      <Stack>
        <Fields>
          <Field label={t("Kind")}>
            <select value={kind} onChange={(event) => setKind(event.target.value as "http" | "tcp")} data-testid="probe-kind">
              <option value="http">HTTP</option>
              <option value="tcp">TCP</option>
            </select>
          </Field>
          <Field
            label={t("Target")}
            wide
            hint={kind === "http" ? t("http:// or https://, as the host would reach it.") : t("host:port, as the host would reach it.")}
          >
            <input
              value={target}
              onChange={(event) => setTarget(event.target.value)}
              placeholder={kind === "http" ? "https://app.example.internal/health" : "db.example.internal:5432"}
              data-testid="probe-target"
            />
          </Field>
          {kind === "http" && (
            <>
              <Field label={t("Expected status")} hint={t("Empty accepts any 2xx or 3xx.")}>
                <input
                  type="number"
                  min={100}
                  max={599}
                  value={expectStatus}
                  onChange={(event) => setExpectStatus(event.target.value)}
                  data-testid="probe-status"
                />
              </Field>
              <Field label={t("Expected body fragment")} hint={t("Optional; the answer must contain it.")}>
                <input
                  value={expectBody}
                  onChange={(event) => setExpectBody(event.target.value)}
                  data-testid="probe-body"
                />
              </Field>
            </>
          )}
        </Fields>
        <Actions>
          {/* The one button of the card stays on the screen when the probe
              is refused, with the reason: a form without its button would
              read as broken. */}
          {(may.allowed || may.known) && (
            <Button
              disabled={!may.allowed || !valid || busy || host.connection_state !== "online"}
              title={may.allowed ? undefined : may.reason || t("This action is not available.")}
              onClick={() => order.mutate({
                action: "monitoring.probe.run",
                payload: {
                  monitoring: {
                    kind, target: address,
                    ...(kind === "http" && Number(expectStatus) ? { expect_status: Number(expectStatus) } : {}),
                    ...(kind === "http" && expectBody.trim() ? { expect_body: expectBody.trim() } : {}),
                  },
                },
              })}
              testId="probe"
            >
              {busy ? t("Probing…") : t("Run the probe")}
            </Button>
          )}
        </Actions>
        {!may.allowed && !may.pending && may.known && (
          <Note>{may.reason || t("This action is not available.")}</Note>
        )}
        {message && <Problem>{message}</Problem>}
        {refused && (
          <Problem>{attempt?.message || attempt?.error_code || t("The host refused the probe.")}</Problem>
        )}
        {result && (
          <Facts>
            <Fact label={t("Verdict")}>
              {result.passed
                ? <Pill tone="ok">{t("passed")}</Pill>
                : result.reachable
                  ? <Pill tone="warn">{t("answered, but not as expected")}</Pill>
                  : <Pill tone="error">{t("unreachable")}</Pill>}
            </Fact>
            <Fact label={t("Duration")}>{`${result.duration_millis} ms`}</Fact>
            {result.status_code !== undefined && <Fact label={t("Status")}>{result.status_code}</Fact>}
            {result.body_matched !== undefined && (
              <Fact label={t("Body matched")}>{result.body_matched ? t("yes") : t("no")}</Fact>
            )}
            {result.tls_expiry && (
              <Fact label={t("TLS certificate")}>
                <span title={absoluteTime(result.tls_expiry)}>
                  {t("expires {when}", { when: relativeTime(result.tls_expiry) })}
                </span>
                {result.tls_issuer ? ` · ${result.tls_issuer}` : ""}
              </Fact>
            )}
            {result.error && <Fact label={t("Error")}><code>{result.error}</code></Fact>}
            {result.observed_at && (
              <Fact label={t("Observed")}>
                <span title={absoluteTime(result.observed_at)}>{relativeTime(result.observed_at)}</span>
              </Fact>
            )}
          </Facts>
        )}
      </Stack>
    </Card>
  );
}

/** The name this screen's arrangement is stored under. */
export const HOST_MONITORING_SCREEN = "next_host_monitoring";

/** The containers this screen can draw, and the shape each ships with. */
export const HOST_MONITORING: BoardEntry[] = [
  { key: "notices", title: "Notices", width: 12, height: 1 },
  { key: "alerts_band", title: "Alerts", width: 8, height: 2 },
  { key: "freshness", title: "Sampling", width: 4, height: 2 },
  { key: "cpu", title: "CPU", width: 6, height: 3 },
  { key: "load", title: "Load", width: 6, height: 3 },
  { key: "memory", title: "Memory", width: 6, height: 3 },
  { key: "network", title: "Network", width: 6, height: 3 },
  { key: "agent", title: "Agent", width: 8, height: 4 },
  { key: "agent_facts", title: "Agent facts", width: 4, height: 2 },
  { key: "filesystems", title: "Filesystems", width: 8, height: 3 },
  { key: "facts", title: "Facts", width: 4, height: 3 },
  { key: "silence", title: "Silence", width: 4, height: 3 },
  { key: "alerts", title: "Alerts", width: 12, height: 4 },
  { key: "probe", title: "Run a probe now", width: 12, height: 3 },
  { key: "silences", title: "Silences in force", width: 12, height: 3 },
];
