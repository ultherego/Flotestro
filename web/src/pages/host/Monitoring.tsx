import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../../lib/api";
import type { Alert, Host, HostMetrics, HostMonitoring, MetricPoint, MetricRange, RuleCatalogue, Silence } from "../../lib/types";
import { absoluteTime, bytes } from "../../lib/format";
import { ErrorBox, Time, Empty } from "../../components/ui";
import { AreaChart, ChartLegend, Meter, type AreaSeries } from "../../components/widgets";
import {
  Fact, Facts, Field, Fields, Form, FormActions, FormNote, Message, ModuleHeader, ModulePage, Section, Summary, Table,
  Unknown, Widgets, countWhere, usageTone, useHost, useReadOperation,
} from "./shared";
import { capability } from "./modules";
import { AlertStateBadge, SeverityBadge, duration, metricValue } from "../Monitoring";
import { useT } from "../../i18n";

const RANGES: { value: MetricRange; label: string }[] = [
  { value: "3h", label: "3 hours" },
  { value: "24h", label: "24 hours" },
  { value: "7d", label: "7 days" },
  { value: "30d", label: "30 days" },
];

/**
 * How an instant reads on the time axis: the hour in a short window, the
 * day in a long one. The parts are cut from the same absolute time every
 * other screen shows - the 24-hour clock, in the zone the operator
 * prefers - so a chart and the trail beside it agree on when.
 */
export function axisLabel(range: MetricRange): (iso: string) => string {
  const time = (iso: string) => absoluteTime(iso).slice(11, 16);
  const day = (iso: string) => absoluteTime(iso).slice(5, 10);
  if (range === "3h" || range === "24h") return time;
  if (range === "7d") return (iso) => `${day(iso)} ${time(iso)}`;
  return day;
}

const percent = (value: number) => `${Math.round(value)}%`;
const rate = (value: number) => `${bytes(value)}/s`;

/**
 * The busiest interface of the window: the one that moved the most bytes
 * in both directions. A host with one interface has it; a host with ten
 * gets the one worth a chart, named, and the count of the rest.
 */
function busiestInterface(points: MetricPoint[]): { name: string; count: number } | undefined {
  const totals = new Map<string, number>();
  for (const point of points) {
    for (const link of point.interfaces ?? []) {
      totals.set(link.name, (totals.get(link.name) ?? 0) + (link.rx_bytes_per_second ?? 0) + (link.tx_bytes_per_second ?? 0));
    }
  }
  const sorted = [...totals.entries()].sort((a, b) => b[1] - a[1]);
  return sorted.length ? { name: sorted[0][0], count: sorted.length } : undefined;
}

/**
 * Host monitoring.
 *
 * The agent samples the host once a minute and the panel keeps the samples:
 * what the charts show is what the agent saw, with the time it saw it. A
 * host that has not sent a sample yet has no numbers, and is shown as
 * such - a chart of zeros would say the host is idle, which nobody knows.
 * The alerts are the panel's own rules applied to the same samples.
 */
export function Monitoring() {
  const t = useT();
  const host = useHost();
  const queryClient = useQueryClient();
  const [range, setRange] = useState<MetricRange>("3h");
  const [message, setMessage] = useState("");
  const [silenceReason, setSilenceReason] = useState("");
  const [minutes, setMinutes] = useState("60");
  const [silenceRule, setSilenceRule] = useState("");

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

  const refresh = () => queryClient.invalidateQueries({ queryKey: ["monitoring"] });

  const silence = useMutation({
    mutationFn: (ruleID: string) =>
      api.post<Silence>(`/api/v1/hosts/${host.id}/monitoring/silences`, {
        reason: silenceReason.trim(),
        minutes: Number(minutes) || 60,
        ...(ruleID ? { rule_id: ruleID } : {}),
      }),
    onSuccess: (created) => {
      setMessage(t("{rule} is silenced until {until}.", {
        rule: created.rule_name ?? t("Every rule"),
        until: absoluteTime(created.until),
      }));
      setSilenceReason("");
      refresh();
    },
    onError: (error) => setMessage(error instanceof Error ? error.message : String(error)),
  });

  const unsilence = useMutation({
    mutationFn: (id: string) =>
      api.del(`/api/v1/hosts/${host.id}/monitoring/silences/${encodeURIComponent(id)}`),
    onSuccess: () => {
      setMessage(t("Silence ended."));
      refresh();
    },
    onError: (error) => setMessage(error instanceof Error ? error.message : String(error)),
  });

  if (report.error && metrics.error) return <ErrorBox error={report.error} />;

  const state = report.data;
  const series = metrics.data;
  const points = series?.points ?? [];
  const times = points.map((point) => point.at);
  const latest = series?.latest ?? state?.latest ?? null;
  const lastSampleAt = series?.last_sample_at ?? state?.last_sample_at ?? undefined;
  const rollup = (series?.step_seconds ?? 60) > 60;
  const label = axisLabel(range);
  // Unread alerts are not zero alerts: the bar shows dashes then.
  const knownAlerts: Alert[] | undefined = state?.alerts;
  const alerts = knownAlerts ?? [];
  const silences = state?.silences ?? [];
  const reasonReady = silenceReason.trim().length >= 8 && Number(minutes) > 0 && Number(minutes) <= 1440;
  // The rules a silence can name: the catalogue when it is readable, else
  // the ones already alerting on this host.
  const ruleOptions = rules.data
    ? rules.data.items.map((rule) => ({ id: rule.id, name: rule.name }))
    : alerts.filter((alert, i, list) => list.findIndex((other) => other.rule_id === alert.rule_id) === i)
      .map((alert) => ({ id: alert.rule_id, name: alert.rule_name }));

  const link = busiestInterface(points);
  const memoryTop = Math.max(0, ...points.map((point) => point.memory_total));
  const cpuSeries: AreaSeries[] = [{ name: t("CPU"), tone: "accent", values: points.map((point) => point.cpu_percent) }];
  const loadSeries: AreaSeries[] = [
    // The accent and the info tone are the same blue on the light theme,
    // so the second line of every chart takes a hue of its own.
    { name: t("1 min"), tone: "accent", values: points.map((point) => point.load1) },
    { name: t("5 min"), tone: "warn", values: points.map((point) => point.load5), line: true },
    { name: t("15 min"), tone: "unknown", values: points.map((point) => point.load15), line: true },
  ];
  const memorySeries: AreaSeries[] = [
    { name: t("Memory used"), tone: "accent", values: points.map((point) => point.memory_used) },
    { name: t("Swap used"), tone: "warn", values: points.map((point) => point.swap_used), line: true },
  ];
  // The agent's own cost, drawn like the host's: a gap where the agent
  // did not report the value, never a zero. The helper is a second line
  // that exists only while it runs.
  const agentMemorySeries: AreaSeries[] = [
    { name: t("Agent RSS"), tone: "accent", values: points.map((point) => point.agent_rss_bytes) },
    { name: t("Helper RSS"), tone: "warn", values: points.map((point) => point.helper_rss_bytes), line: true },
  ];
  const agentCPUSeries: AreaSeries[] = [{ name: t("Agent CPU"), tone: "accent", values: points.map((point) => point.agent_cpu_percent) }];
  const agentReported = points.some((point) => point.agent_rss_bytes !== undefined || point.agent_cpu_percent !== undefined);
  const networkSeries: AreaSeries[] = link ? [
    { name: t("{name} received", { name: link.name }), tone: "ok", values: points.map((point) => point.interfaces?.find((item) => item.name === link.name)?.rx_bytes_per_second) },
    { name: t("{name} sent", { name: link.name }), tone: "accent", values: points.map((point) => point.interfaces?.find((item) => item.name === link.name)?.tx_bytes_per_second), line: true },
  ] : [];

  // What stands in a chart section while there is no line to draw.
  const blank = metrics.error
    ? <ErrorBox error={metrics.error} />
    : !series
      ? <Empty>{t("Loading…")}</Empty>
      : !latest
        ? <Empty>{t("The agent has not sent a sample yet")}</Empty>
        : points.length === 0
          ? <Empty>{t("No sample in this window.")}</Empty>
          : null;

  return (
    <ModulePage>
      <ModuleHeader
        title={t("Monitoring")}
        description={t("Metrics the agent samples every minute; alerts by the panel's own rules.")}
        actions={
          <div className="segmented" role="group" aria-label={t("Window")}>
            {RANGES.map((item) => (
              <button
                key={item.value}
                type="button"
                className={item.value === range ? "active" : undefined}
                onClick={() => setRange(item.value)}
              >
                {t(item.label)}
              </button>
            ))}
          </div>
        }
      />
      <p className="hm-freshness">
        {series || state ? (
          lastSampleAt
            ? <span>{t("Last sample")} <Time value={lastSampleAt} /></span>
            : <span className="unread">{t("The agent has not sent a sample yet")}</span>
        ) : (
          <span>{t("Loading…")}</span>
        )}
        {series && <span>{t("sampled every {n} s", { n: series.sampling_interval_seconds })}</span>}
        {series && rollup && <span>{t("15-minute rollups with the peak of each step")}</span>}
      </p>
      <Message text={message} />

      <Widgets>
        {/* The alerts by severity, the silenced ones set apart: a silenced
            alert is still firing, only nobody is told. */}
        <Summary
          title={t("Alerts")}
          description={t("Firing for this host, by severity; the pending and the silenced ones counted apart.")}
          span={12}
          segments={[
            { label: t("Critical"), value: countWhere(knownAlerts, (alert) => alert.state === "firing" && alert.severity === "critical" && !alert.silenced), tone: "error" },
            { label: t("Warning"), value: countWhere(knownAlerts, (alert) => alert.state === "firing" && alert.severity === "warning" && !alert.silenced), tone: "warn" },
            { label: t("Info"), value: countWhere(knownAlerts, (alert) => alert.state === "firing" && alert.severity === "info" && !alert.silenced), tone: "info" },
            { label: t("Pending"), value: countWhere(knownAlerts, (alert) => alert.state === "pending"), tone: "unknown" },
            { label: t("Silenced"), value: countWhere(knownAlerts, (alert) => alert.state !== "resolved" && alert.silenced), tone: "neutral" },
          ]}
        />

        <Section
          title={t("CPU")}
          description={t("Busy time across all cores, in percent.")}
          tools={latest && <span className="hm-mono">{t("now {value}", { value: metricValue("cpu_percent", latest.cpu_percent) })}</span>}
          span={6}
          flush={blank !== null}
        >
          {blank ?? (
            <>
              <AreaChart times={times} series={cpuSeries} max={100} format={percent} label={label} peak={rollup ? points.map((point) => point.cpu_percent_max) : undefined} />
              {rollup && <ChartLegend items={[{ name: t("mean of the step"), tone: "accent" }, { name: t("peak of the step"), tone: "accent", dashed: true }]} />}
            </>
          )}
        </Section>

        <Section
          title={t("Load")}
          description={t("Load average over 1, 5 and 15 minutes.")}
          tools={latest && <span className="hm-mono">{`${latest.load1.toFixed(2)} · ${latest.load5.toFixed(2)} · ${latest.load15.toFixed(2)}`}</span>}
          span={6}
          flush={blank !== null}
        >
          {blank ?? (
            <>
              <AreaChart times={times} series={loadSeries} format={(value) => String(Math.round(value * 100) / 100)} label={label} />
              <ChartLegend items={loadSeries.map((item) => ({ name: item.name, tone: item.tone }))} />
            </>
          )}
        </Section>

        <Section
          title={t("Memory")}
          description={t("Used memory against the total, with swap as a second line.")}
          tools={latest && <span className="hm-mono">{`${bytes(latest.memory_used)} / ${bytes(latest.memory_total)}`}</span>}
          span={6}
          flush={blank !== null}
        >
          {blank ?? (
            <>
              <AreaChart times={times} series={memorySeries} max={memoryTop > 0 ? memoryTop : undefined} format={bytes} label={label} peak={rollup ? points.map((point) => point.memory_used_max) : undefined} />
              <ChartLegend items={[
                ...memorySeries.map((item) => ({ name: item.name, tone: item.tone })),
                ...(rollup ? [{ name: t("peak of the step"), tone: "accent" as const, dashed: true }] : []),
              ]} />
            </>
          )}
        </Section>

        <Section
          title={t("Network")}
          description={link && link.count > 1
            ? t("{name}, the busiest of {n} interfaces; bytes per second.", { name: link.name, n: link.count })
            : t("Bytes per second, received and sent.")}
          span={6}
          flush={blank !== null || !link}
        >
          {blank ?? (!link ? (
            <Empty>{t("No interface rates in this window: a rate needs two samples.")}</Empty>
          ) : (
            <>
              <AreaChart times={times} series={networkSeries} format={rate} label={label} />
              <ChartLegend items={networkSeries.map((item) => ({ name: item.name, tone: item.tone }))} />
            </>
          ))}
        </Section>

        {/* The agent measured by itself: what it costs the host it watches.
            The release gate reads the same numbers off the fleet. */}
        <Section
          title={t("Agent")}
          description={t("The agent's own footprint: resident memory, with the helper's while it runs, and CPU as a share of one core.")}
          tools={latest && latest.agent_rss_bytes !== undefined && (
            <span className="hm-mono">{t("now {value}", { value: bytes(latest.agent_rss_bytes) })}</span>
          )}
          span={6}
          flush={blank !== null || !agentReported}
        >
          {blank ?? (!agentReported ? (
            <Empty>{t("The agent does not report its footprint; an older agent does not.")}</Empty>
          ) : (
            <>
              <AreaChart times={times} series={agentMemorySeries} format={bytes} label={label} peak={rollup ? points.map((point) => point.agent_rss_bytes_max) : undefined} />
              <ChartLegend items={[
                ...agentMemorySeries.map((item) => ({ name: item.name, tone: item.tone })),
                ...(rollup ? [{ name: t("peak of the step"), tone: "accent" as const, dashed: true }] : []),
              ]} />
              <AreaChart times={times} series={agentCPUSeries} height={110} format={(value) => `${Math.round(value * 10) / 10}%`} label={label} peak={rollup ? points.map((point) => point.agent_cpu_percent_max) : undefined} />
              <ChartLegend items={[
                { name: t("Agent CPU, percent of one core"), tone: "accent" },
                ...(rollup ? [{ name: t("peak of the step"), tone: "accent" as const, dashed: true }] : []),
              ]} />
            </>
          ))}
        </Section>

        <Section title={t("Agent facts")} description={t("As of the last sample.")} span={6}>
          <Facts>
            <Fact label={t("Agent RSS")}>{latest?.agent_rss_bytes !== undefined ? bytes(latest.agent_rss_bytes) : <Unknown />}</Fact>
            <Fact label={t("Agent CPU")}>{latest?.agent_cpu_percent !== undefined ? `${Math.round(latest.agent_cpu_percent * 10) / 10}%` : <Unknown />}</Fact>
            <Fact label={t("Goroutines")}>{latest?.agent_goroutines !== undefined ? latest.agent_goroutines : <Unknown />}</Fact>
            <Fact label={t("Open descriptors")}>{latest?.agent_open_fds !== undefined ? latest.agent_open_fds : <Unknown />}</Fact>
            {/* The helper sleeps between orders, so most samples carry
                nothing for it; an absent value is also what an agent
                that could not read its PID sends, so the two are not told
                apart here. */}
            <Fact label={t("Helper RSS")}>
              {latest?.helper_rss_bytes !== undefined
                ? bytes(latest.helper_rss_bytes)
                : <span className="source">{t("not running, or not measured")}</span>}
            </Fact>
          </Facts>
        </Section>

        <Section title={t("Filesystems")} description={t("As of the last sample.")} span={4} flush>
          {!latest ? (
            <Empty>{metrics.error || series ? t("The agent has not sent a sample yet") : t("Loading…")}</Empty>
          ) : !(latest.filesystems ?? []).length ? (
            <Empty>{t("The sample lists no filesystem.")}</Empty>
          ) : (
            <Table>
              <thead><tr><th>{t("Mount")}</th><th>{t("Used")}</th></tr></thead>
              <tbody>
                {(latest.filesystems ?? []).map((fs) => (
                  <tr key={fs.mount}>
                    <td>
                      <span className="hm-primary hm-mono">{fs.mount}</span>
                      {fs.inodes_total > 0 && (
                        <div className="source">{t("inodes {value}", { value: percent((fs.inodes_used / fs.inodes_total) * 100) })}</div>
                      )}
                    </td>
                    <td>
                      <Meter
                        value={fs.used_bytes}
                        max={fs.total_bytes}
                        tone={usageTone(fs.used_bytes, fs.total_bytes)}
                        text={`${bytes(fs.used_bytes)} / ${bytes(fs.total_bytes)}`}
                      />
                    </td>
                  </tr>
                ))}
              </tbody>
            </Table>
          )}
        </Section>

        <Section title={t("Facts")} span={4}>
          <Facts>
            <Fact label={t("Uptime")}>{latest ? duration(latest.uptime_seconds) : <Unknown />}</Fact>
            <Fact label={t("Last sample")}>{lastSampleAt ? <Time value={lastSampleAt} /> : <Unknown />}</Fact>
            <Fact label={t("Sampling interval")}>{series ? t("every {n} s", { n: series.sampling_interval_seconds }) : <Unknown />}</Fact>
            <Fact label={t("Samples in window")}>
              {!series ? <Unknown /> : rollup ? t("{n} steps of 15 minutes", { n: points.length }) : t("{n} samples", { n: points.length })}
            </Fact>
            <Fact label={t("Rules watching this host")}>{state ? state.rules_matching : <Unknown />}</Fact>
            <Fact label={t("Memory total")}>{latest ? bytes(latest.memory_total) : <Unknown />}</Fact>
          </Facts>
        </Section>

        {/* The silence form beside the tables it adds to. */}
        <Section
          title={t("Silence")}
          span={4}
          description={t("A silence turns a sensor off, so it always ends: at most a day, with a reason and an owner in the audit trail.")}
        >
          <Form>
            <Fields>
              <Field label={t("Reason (at least 8 characters)")} wide>
                <input value={silenceReason} onChange={(e) => setSilenceReason(e.target.value)} />
              </Field>
              <Field label={t("Minutes")} narrow help={t("At most 1440.")}>
                <input type="number" min={1} max={1440} value={minutes} onChange={(e) => setMinutes(e.target.value)} />
              </Field>
              <Field label={t("Rule")}>
                <select value={silenceRule} onChange={(e) => setSilenceRule(e.target.value)}>
                  <option value="">{t("every rule")}</option>
                  {ruleOptions.map((rule) => <option key={rule.id} value={rule.id}>{rule.name}</option>)}
                </select>
              </Field>
            </Fields>
            <FormActions>
              <button disabled={!reasonReady || silence.isPending} onClick={() => silence.mutate(silenceRule)}>
                {silence.isPending ? t("Silencing…") : silenceRule ? t("Silence this rule") : t("Silence every rule of this host")}
              </button>
            </FormActions>
            <FormNote>{t("The reason above is also used by the Silence buttons in the alerts table.")}</FormNote>
          </Form>
        </Section>

        <Section title={t("Alerts")} count={knownAlerts?.length} span={12} flush>
          {report.error ? (
            <ErrorBox error={report.error} />
          ) : !state ? (
            <Empty>{t("Loading…")}</Empty>
          ) : alerts.length === 0 ? (
            <Empty>{t("No alert is pending or firing for this host.")}</Empty>
          ) : (
            <Table>
              <thead>
                <tr>
                  <th>{t("Rule")}</th><th>{t("Severity")}</th><th>{t("State")}</th><th className="hm-num">{t("Value")}</th>
                  <th>{t("Detail")}</th><th>{t("Since")}</th><th></th>
                </tr>
              </thead>
              <tbody>
                {alerts.map((alert) => (
                  <tr key={alert.id}>
                    <td>
                      <span className="hm-primary">{alert.rule_name}</span>
                      <div className="source hm-mono">{alert.metric}</div>
                    </td>
                    <td><SeverityBadge severity={alert.severity} /></td>
                    <td><AlertStateBadge state={alert.state} silenced={alert.silenced} /></td>
                    <td className="hm-num">{metricValue(alert.metric, alert.value)}</td>
                    <td className="source">{alert.detail}</td>
                    <td><Time value={alert.fired_at || alert.started_at} /></td>
                    <td>
                      {/* A resolved alert has nothing left to silence; the
                          button would order a silence for a rule that is quiet. */}
                      {alert.state === "resolved" ? (
                        <span className="source" title={t("The alert is resolved; there is nothing to silence.")}>—</span>
                      ) : (
                        <button
                          className="secondary"
                          disabled={alert.silenced || !reasonReady || silence.isPending}
                          title={alert.silenced ? t("Already silenced.") : reasonReady ? undefined : t("Write a reason in the silence form first.")}
                          onClick={() => silence.mutate(alert.rule_id)}
                        >
                          {t("Silence this")}
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </Table>
          )}
        </Section>

        {capability(host, "monitoring")?.available && <ProbeNow host={host} />}

        <Section title={t("Silences in force")} count={state ? silences.length : undefined} span={12} flush>
          {!state ? (
            <Empty>{t("Loading…")}</Empty>
          ) : silences.length === 0 ? (
            <Empty>{t("No silence is in force for this host.")}</Empty>
          ) : (
            <Table>
              <thead>
                <tr><th>{t("Until")}</th><th>{t("Rule")}</th><th>{t("Reason")}</th><th>{t("By")}</th><th></th></tr>
              </thead>
              <tbody>
                {silences.map((entry) => (
                  <tr key={entry.id}>
                    <td><Time value={entry.until} /></td>
                    <td>{entry.rule_name || <span className="source">{t("every rule")}</span>}</td>
                    <td>{entry.reason}</td>
                    <td className="source">{entry.created_by}</td>
                    <td>
                      <button className="secondary" disabled={unsilence.isPending} onClick={() => unsilence.mutate(entry.id)}>
                        {t("End now")}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </Table>
          )}
        </Section>
      </Widgets>
    </ModulePage>
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

/**
 * A probe on demand: the host checks a service from where it stands and
 * reports what it saw - reachable or not, the answer it got, and whether
 * that answer met the expectation. The probe takes an address, not a rule:
 * the alert rules judge the samples, and this asks a question the samples
 * do not answer, "does this service answer from this host right now". The
 * result belongs to the job and is shown here, not in the inventory.
 */
function ProbeNow({ host }: { host: Host }) {
  const t = useT();
  const [kind, setKind] = useState<"http" | "tcp">("http");
  const [target, setTarget] = useState("");
  const [expectStatus, setExpectStatus] = useState("");
  const [expectBody, setExpectBody] = useState("");
  const read = useReadOperation<ProbeResult>(host);
  const result = read.attempt?.detail?.probe;
  const refused = read.attempt && read.attempt.status !== "succeeded" && !result;
  const address = target.trim();
  const valid = address !== "" && !/\s/.test(address)
    && (kind === "http" ? /^https?:\/\/\S+$/.test(address) : /^\S+:\d{1,5}$/.test(address));

  return (
    <Section
      title={t("Run a probe now")}
      span={12}
      description={t("The host checks a service from where it stands: an HTTP address or a host:port. The answer is the host's view at this moment and belongs to the job, not to the inventory.")}
    >
      <Form>
        <Fields>
          <Field label={t("Kind")} narrow>
            <select value={kind} onChange={(e) => setKind(e.target.value as "http" | "tcp")}>
              <option value="http">HTTP</option>
              <option value="tcp">TCP</option>
            </select>
          </Field>
          <Field label={t("Target")} help={kind === "http" ? t("http:// or https://, as the host would reach it.") : t("host:port, as the host would reach it.")} wide>
            <input value={target} onChange={(e) => setTarget(e.target.value)} placeholder={kind === "http" ? "https://app.example.internal/health" : "db.example.internal:5432"} />
          </Field>
          {kind === "http" && (
            <>
              <Field label={t("Expected status")} help={t("Empty accepts any 2xx or 3xx.")} narrow>
                <input type="number" min={100} max={599} value={expectStatus} onChange={(e) => setExpectStatus(e.target.value)} />
              </Field>
              <Field label={t("Expected body fragment")} help={t("Optional; the answer must contain it.")}>
                <input value={expectBody} onChange={(e) => setExpectBody(e.target.value)} />
              </Field>
            </>
          )}
        </Fields>
        <FormActions>
          <button
            disabled={!valid || read.busy || host.connection_state !== "online"}
            onClick={() =>
              read.order({
                action: "monitoring.probe.run",
                payload: {
                  monitoring: {
                    kind, target: address,
                    ...(kind === "http" && Number(expectStatus) ? { expect_status: Number(expectStatus) } : {}),
                    ...(kind === "http" && expectBody.trim() ? { expect_body: expectBody.trim() } : {}),
                  },
                },
              })
            }
          >
            {read.busy ? t("Probing…") : t("Run the probe")}
          </button>
        </FormActions>
        <Message text={read.message} error />
        {refused && (
          <Message text={read.attempt?.message || read.attempt?.error_code || t("The host refused the probe.")} error />
        )}
        {result && (
          <Facts>
            <Fact label={t("Verdict")}>
              {result.passed
                ? <span className="badge ok">{t("passed")}</span>
                : result.reachable
                  ? <span className="badge warn">{t("answered, but not as expected")}</span>
                  : <span className="badge error">{t("unreachable")}</span>}
            </Fact>
            <Fact label={t("Duration")}>{result.duration_millis} ms</Fact>
            {result.status_code !== undefined && <Fact label={t("Status")}>{result.status_code}</Fact>}
            {result.body_matched !== undefined && <Fact label={t("Body matched")}>{result.body_matched ? t("yes") : t("no")}</Fact>}
            {result.tls_expiry && (
              <Fact label={t("TLS certificate")}>
                {t("expires")} <Time value={result.tls_expiry} />{result.tls_issuer ? ` · ${result.tls_issuer}` : ""}
              </Fact>
            )}
            {result.error && <Fact label={t("Error")} wide><span className="hm-mono">{result.error}</span></Fact>}
            {result.observed_at && <Fact label={t("Observed")}><Time value={result.observed_at} /></Fact>}
          </Facts>
        )}
      </Form>
    </Section>
  );
}
