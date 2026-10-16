import { useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, fetchWithCredentials, type Collection, type Page } from "../../lib/api";
import { exportAddress, exportFileName } from "../../components/ExportButton";
import { PARTIAL_REASONS } from "../../components/FleetCoverage";
import { useToast } from "../../components/Toast";
import { absoluteTime, bytes, relativeTime } from "../../lib/format";
import { expressionSuggestions, parseExpression } from "../../lib/targets";
import type {
  Alert, AlertRule, AlertRuleInput, AlertSeverity, AlertState, FleetFootprint,
  FleetMonitoring, RuleCatalogue, RuleOperator, RuleSelector, Silence, Whoami,
} from "../../lib/types";
import { t as translate, useT } from "../../i18n";
import { Board } from "../Board";
import type { BoardEntry } from "../../components/board";
import {
  Actions, Band, Banner, Bones, Card, Check, Empty, Field, Fields, Fig, Figs, Kpi, Modal, Pill, Problem, Row, Table, Toolbar, TwoLine, type Segment, type Tone,
} from "../kit";

/**
 * What the agents' samples turned into alerts.
 *
 * Every agent samples its host once a minute and the panel keeps the
 * samples; the rules on this screen are the whole of what turns them into
 * alerts, so a fleet with no rule is a fleet nobody is watching rather
 * than a quiet one.
 *
 * Three things this screen must never say. A reading that stopped is not
 * a reading of nought, so a no-data episode carries no value at all. A
 * fleet the server has not answered for yet is not a fleet with nothing
 * firing, so the counts are unknown until it does. And the board of
 * firing alerts is bounded by the server, so what narrows it narrows on
 * the server too - the alert list below takes its filters to the API,
 * and nothing on this screen sifts a loaded page and calls it the answer.
 */

/* ------------------------------------------------------- the vocabulary */

/** The sign of an operator, as a rule reads in one line. */
export const OPERATOR_SIGNS: Record<RuleOperator, string> = { gt: ">", lt: "<", gte: "≥", lte: "≤" };

/** What each metric measures, in words; the key itself stays beside it. */
const METRIC_LABELS: Record<string, string> = {
  cpu_percent: "CPU busy, percent",
  load1_per_core: "load average (1 min) per core",
  memory_used_percent: "memory used, percent",
  swap_used_percent: "swap used, percent",
  filesystem_used_percent: "filesystem used, percent (any mount)",
  inodes_used_percent: "inodes used, percent (any mount)",
  host_offline: "minutes without a sample",
  uptime_seconds: "uptime, seconds",
  agent_rss_bytes: "agent resident memory, bytes",
  agent_cpu_percent: "agent CPU, percent of one core",
};

/** What each no-data policy does, in the words the rule list uses. */
const POLICY_LABELS: Record<string, string> = {
  alert: "alert on a gap",
  unknown: "mark unknown",
  ignore: "ignore gaps",
};

/** The policies the form offers, in the order the server lists them. */
export const NO_DATA_POLICIES = ["alert", "unknown", "ignore"];

/** A no-data policy in words; a rule that carries none ignores gaps. */
export function policyLabel(policy: string | undefined): string {
  return translate(POLICY_LABELS[policy ?? "ignore"] ?? POLICY_LABELS.ignore);
}

/** A number of seconds as the operator reads it: seconds, minutes or hours. */
export function everySeconds(seconds: number): string {
  if (seconds % 3600 === 0) return translate("{n} h", { n: seconds / 3600 });
  if (seconds % 60 === 0) return translate("{n} min", { n: seconds / 60 });
  return translate("{n} s", { n: seconds });
}

export function metricLabel(metric: string): string {
  const label = METRIC_LABELS[metric];
  return label ? translate(label) : metric;
}

function roundTo(value: number, digits: number): number {
  const factor = Math.pow(10, digits);
  return Math.round(value * factor) / factor;
}

/** A length of time in the units an operator counts an uptime in. */
export function uptime(seconds: number): string {
  const whole = Math.max(0, Math.floor(seconds));
  const days = Math.floor(whole / 86400);
  const hours = Math.floor((whole % 86400) / 3600);
  const minutes = Math.floor((whole % 3600) / 60);
  if (days > 0) return `${days}d ${hours}h`;
  if (hours > 0) return `${hours}h ${minutes}m`;
  if (minutes > 0) return `${minutes}m`;
  return `${whole}s`;
}

/** A value of a metric with its unit: a percent, a load, minutes, an uptime, a size. */
export function metricValue(metric: string, value: number): string {
  if (metric.endsWith("_percent")) return `${roundTo(value, 1)}%`;
  if (metric.endsWith("_bytes")) return bytes(value);
  if (metric === "uptime_seconds") return uptime(value);
  if (metric === "host_offline") return translate("{n} min", { n: roundTo(value, 0) });
  return String(roundTo(value, 2));
}

/** The condition of a rule in one line: the metric, the sign and the threshold. */
export function describeCondition(rule: { metric: string; operator: RuleOperator; threshold: number }): string {
  return `${rule.metric} ${OPERATOR_SIGNS[rule.operator] ?? rule.operator} ${metricValue(rule.metric, rule.threshold)}`;
}

/**
 * The scope of a rule as the server takes it: the flat fields, the tags the
 * host has to carry, the groups it may be in, its owner, and an expression
 * in the text form of a campaign selector for what the fields cannot say.
 */
export type RuleScope = RuleSelector & { tags?: string[]; groups?: string[]; owner?: string; expression?: string };

/** Which hosts a rule selects, in one line; nothing chosen is the whole fleet. */
export function describeSelector(selector: RuleScope | undefined): string {
  const parts = [
    selector?.site ? `site=${selector.site}` : "",
    selector?.environment ? `environment=${selector.environment}` : "",
    selector?.os_family ? `os=${selector.os_family}` : "",
    ...(selector?.tags ?? []).map((tag) => `tag=${tag}`),
    selector?.groups?.length ? `group=${selector.groups.join("|")}` : "",
    selector?.owner ? `owner=${selector.owner}` : "",
    selector?.expression ?? "",
    selector?.host_ids?.length ? translate("{n} named hosts", { n: selector.host_ids.length }) : "",
  ].filter(Boolean);
  return parts.length ? parts.join(", ") : translate("whole fleet");
}

/** The words of a list field - tags, groups - cut at commas and spaces. */
function words(text: string): string[] {
  return text.split(/[\s,]+/).map((word) => word.trim()).filter(Boolean);
}

/** The colour of a severity. Critical is a fault, info is a note. */
export function severityTone(severity: AlertSeverity | string): Tone {
  return severity === "critical" ? "error" : severity === "warning" ? "warn" : "info";
}

/**
 * The colour of an alert's state.
 *
 * A no-data episode is the one worth being careful about: the readings
 * stopped, so the condition may well still hold, and colouring it as
 * resolved would say the panel knows something it does not.
 */
export function alertStateTone(state: AlertState | string, silenced = false): Tone {
  if (state === "resolved") return "ok";
  if (state === "pending") return "unknown";
  if (state === "no_data") return "warn";
  return silenced ? "neutral" : "error";
}

/** An alert's state in the words the list uses. */
export function alertStateName(state: AlertState | string, silenced = false): string {
  if (state === "resolved") return "resolved";
  if (state === "pending") return "pending";
  if (state === "no_data") return "no data";
  return silenced ? "firing, silenced" : "firing";
}

/* ------------------------------------------------------------ the shapes */

/** The fleet view with the bound of its board and the counts it stands on. */
type Counts = FleetMonitoring["counts"] & { acknowledged?: number; no_data?: number };
type FleetView = Omit<FleetMonitoring, "counts"> & { counts: Counts };

/** An alert with what an operator wrote on it. */
export type NotedAlert = Alert & { acknowledged_by?: string; acknowledged_at?: string | null; note?: string };

/**
 * A silence with the two decisions of its policy: global marks the one that
 * may keep back a security alert of the installation, send_summary asks for
 * one message per channel when it ends instead of the flood it held.
 */
export type ScopedSilence = Silence & { global?: boolean; send_summary?: boolean };

/** The silence list, with what the reader is allowed to write. */
type SilenceList = Collection<ScopedSilence> & { can_silence_fleet?: boolean; can_silence_global?: boolean };

/** Whether the server is asked for what waits, for what somebody took, or for both. */
type Taken = "" | "waiting" | "acknowledged";

/** The page of the alert list the screen reads; the file carries the rest. */
export const HISTORY_PAGE = 50;

function errorText(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/* ------------------------------------------------------------ the screen */

export function Monitoring() {
  const t = useT();
  const toast = useToast();
  const queryClient = useQueryClient();

  const [notice, setNotice] = useState("");
  const [editing, setEditing] = useState<AlertRule | "new" | null>(null);
  const [deleting, setDeleting] = useState<AlertRule | null>(null);
  const [silencing, setSilencing] = useState<NotedAlert | null>(null);
  const [acknowledging, setAcknowledging] = useState<NotedAlert | null>(null);
  const [noting, setNoting] = useState<NotedAlert | null>(null);
  const [fleetSilence, setFleetSilence] = useState(false);
  const [state, setState] = useState<AlertState | "">("");
  const [taken, setTaken] = useState<Taken>("");

  const whoami = useQuery({
    queryKey: ["whoami"],
    queryFn: () => api.get<Whoami>("/api/v1/whoami"),
    staleTime: 5 * 60 * 1000,
  });
  const permissions = new Set(whoami.data?.permissions ?? []);
  const canWrite = permissions.has("monitoring.rules.write");
  // Taking an alert is the right of a silence: both are a decision about
  // one sensor of one host.
  const canAcknowledge = permissions.has("monitoring.silence.write");

  const overview = useQuery({
    queryKey: ["monitoring", "fleet"],
    queryFn: () => api.get<FleetView>("/api/v1/monitoring"),
    refetchInterval: 30000,
  });
  const rules = useQuery({
    queryKey: ["monitoring", "rules"],
    queryFn: () => api.get<RuleCatalogue>("/api/v1/monitoring/rules"),
    retry: false,
  });
  // The filters go to the server, so the answer is taken over every alert
  // there is and the total beside it is the total of what was asked for.
  const listParams = new URLSearchParams();
  if (state) listParams.set("state", state);
  if (taken) listParams.set("acknowledged", taken === "acknowledged" ? "true" : "false");
  const history = useQuery({
    queryKey: ["monitoring", "alerts", state, taken],
    queryFn: () => {
      const params = new URLSearchParams(listParams);
      params.set("limit", String(HISTORY_PAGE));
      return api.get<Page<NotedAlert>>(`/api/v1/monitoring/alerts?${params}`);
    },
    refetchInterval: 30000,
  });
  const silences = useQuery({
    queryKey: ["monitoring", "silences"],
    queryFn: () => api.get<SilenceList>("/api/v1/monitoring/silences"),
    refetchInterval: 30000,
  });

  const refresh = () => queryClient.invalidateQueries({ queryKey: ["monitoring"] });
  const said = (text: string) => { setNotice(text); toast.success(text); };
  const failed = (error: unknown) => { setNotice(errorText(error)); toast.error(errorText(error)); };

  const toggleRule = useMutation({
    mutationFn: (rule: AlertRule) =>
      api.put<AlertRule>(`/api/v1/monitoring/rules/${rule.id}`, ruleBody({ ...rule, enabled: !rule.enabled })),
    onSuccess: (rule) => {
      said(rule.enabled ? t("Rule {name} is enabled.", { name: rule.name }) : t("Rule {name} is disabled.", { name: rule.name }));
      refresh();
    },
    onError: failed,
  });
  const removeRule = useMutation({
    mutationFn: (rule: AlertRule) => api.del(`/api/v1/monitoring/rules/${rule.id}`),
    onSuccess: (_, rule) => {
      said(t("Rule {name} is deleted; its alerts resolve on the next evaluation.", { name: rule.name }));
      setDeleting(null);
      refresh();
    },
    onError: failed,
  });
  // A silence that names no host belongs to no host, so it is ended on the
  // fleet path; the host path would not find it.
  const endSilence = useMutation({
    mutationFn: (silence: ScopedSilence) =>
      api.del(silence.host_id
        ? `/api/v1/hosts/${silence.host_id}/monitoring/silences/${encodeURIComponent(silence.id)}`
        : `/api/v1/monitoring/silences/${encodeURIComponent(silence.id)}`),
    onSuccess: () => { said(t("Silence ended.")); refresh(); },
    onError: failed,
  });
  const acknowledge = useMutation({
    mutationFn: ({ alert, note }: { alert: NotedAlert; note: string }) =>
      api.post<NotedAlert>(`/api/v1/monitoring/alerts/${alert.id}/acknowledge`, { note }),
    onSuccess: (alert) => {
      said(t("{host}: {rule} is acknowledged; it keeps firing until the host says otherwise.",
        { host: alert.hostname, rule: alert.rule_name }));
      setAcknowledging(null);
      refresh();
    },
    onError: failed,
  });
  const annotate = useMutation({
    mutationFn: ({ alert, note }: { alert: NotedAlert; note: string }) =>
      api.post<NotedAlert>(`/api/v1/monitoring/alerts/${alert.id}/annotate`, { note }),
    onSuccess: (alert) => {
      said(alert.note
        ? t("The note on {rule} at {host} is saved.", { rule: alert.rule_name, host: alert.hostname })
        : t("The note on {rule} at {host} is removed.", { rule: alert.rule_name, host: alert.hostname }));
      setNoting(null);
      refresh();
    },
    onError: failed,
  });
  const silenceAlert = useMutation({
    mutationFn: ({ alert, reason, minutes, summary }: { alert: NotedAlert; reason: string; minutes: number; summary: boolean }) =>
      api.post<ScopedSilence>(`/api/v1/hosts/${alert.host_id}/monitoring/silences`,
        { reason, minutes, rule_id: alert.rule_id, send_summary: summary }),
    onSuccess: (created) => {
      said(t("{host}: {rule} is silenced until {until}.", {
        host: created.hostname ?? t("every host"),
        rule: created.rule_name ?? t("every rule"),
        until: absoluteTime(created.until),
      }));
      setSilencing(null);
      refresh();
    },
    onError: failed,
  });
  const silenceFleet = useMutation({
    mutationFn: (body: { reason: string; minutes: number; global: boolean; send_summary: boolean }) =>
      api.post<ScopedSilence>("/api/v1/monitoring/silences", body),
    onSuccess: (created) => {
      const until = absoluteTime(created.until);
      said(created.global
        ? t("Every host is silenced until {until}, the security alerts of the installation with them.", { until })
        : t("Every host is silenced until {until}; the security alerts keep going out.", { until }));
      setFleetSilence(false);
      refresh();
    },
    onError: failed,
  });

  if (overview.error) return <Problem>{errorText(overview.error)}</Problem>;

  const data = overview.data;
  // The counts are unknown until the server answers: a fleet nobody has
  // asked and a fleet with nothing firing are different answers.
  const counts = data?.counts;
  const firing = (data?.firing ?? []) as NotedAlert[];
  // What the headline answers: an alert somebody has taken is not one that
  // waits for a person, and neither is a pending one.
  const waiting = counts ? counts.critical + counts.warning + counts.info : undefined;
  const ruleItems = rules.data?.items ?? [];
  const silenceItems = silences.data?.items ?? [];
  // Who may write what is the server's answer, not a guess from the roles:
  // a silence of the whole fleet needs the right over the whole fleet, and
  // the global one the right to manage the notification channels with it.
  const canSilenceFleet = silences.data?.can_silence_fleet ?? false;
  const canSilenceGlobal = silences.data?.can_silence_global ?? false;
  // A full board is not a whole board: the server caps it, and the counts
  // above it were taken over all of it, so the two need not agree.
  const capped = data?.partial === true;
  const historyTotal = history.data?.total;
  const historyShown = history.data?.items.length ?? 0;

  const severities: Segment[] = [
    { label: t("critical"), value: counts?.critical, tone: "error" },
    { label: t("warning"), value: counts?.warning, tone: "warn" },
    { label: t("info"), value: counts?.info, tone: "info" },
  ];

  /** A host as a cell: the name where there is one, else the head of its id. */
  const host = (id: string, hostname?: string) => (
    <Link to={`/hosts/${id}/monitoring`}>{hostname || id.slice(0, 8)}</Link>
  );
  /** A moment, said the way a reader asks for it, with the exact one on hover. */
  const when = (value?: string | null) =>
    value ? <span title={absoluteTime(value)}>{relativeTime(value)}</span> : <span className="fl-faint">—</span>;
  /**
   * The reading an alert stands on. A no-data episode has none: the last
   * one it saw is not the value now, and printing it would be a lie with
   * a decimal point on it.
   */
  const reading = (alert: NotedAlert) =>
    alert.state === "no_data"
      ? <span className="fl-faint" title={t("The host stopped reporting the metric; the panel does not know whether the condition holds.")}>{t("unknown")}</span>
      : <span className="fl-nowrap">{metricValue(alert.metric, alert.value)}</span>;

  return (
    <>
      <Board
        screen={MONITORING_SCREEN}
        catalogue={MONITORING}
        notices={notice !== "" && (
          <Banner tone="info" actions={<button type="button" className="fl-plain fl-small" onClick={() => setNotice("")}>{t("Dismiss")}</button>}>
            {notice}
          </Banner>
        )}
        drawn={{
        waiting: (
          <Kpi
            hero
            icon="notifications"
            label={t("Waiting for somebody")}
            value={waiting ?? null}
            tone={waiting === undefined ? undefined : waiting === 0 ? "ok" : (counts?.critical ?? 0) > 0 ? "error" : "warn"}
            note={data ? t("as of {when}", { when: relativeTime(data.generated_at) }) : t("Reading alerts…")}
          />
        ),
        reporting: (
          <Kpi
            icon="hosts"
            label={t("Hosts reporting")}
            value={data?.hosts_reporting ?? null}
            note={t("a sample within the last three intervals")}
          />
        ),
        quiet: (
          // An enrolled host with no recent sample is the failure this
          // screen exists to show, not a host with nothing wrong.
          <Kpi
            icon="power"
            label={t("Gone quiet")}
            value={data?.hosts_silent ?? null}
            tone={data === undefined ? undefined : data.hosts_silent > 0 ? "warn" : "ok"}
            note={t("enrolled, and no sample came")}
          />
        ),
        watching: (
          <Kpi
            icon="monitoring"
            label={t("Rules enabled")}
            value={data?.rules ?? null}
            tone={data === undefined ? undefined : data.rules === 0 ? "warn" : undefined}
            note={data?.rules === 0 ? t("nothing turns a sample into an alert") : t("what turns a sample into an alert")}
          />
        ),
        severity: (
          <Card title={t("Firing now")} note={t("By severity, across the hosts you can see.")}>
            {/* Severity first and on its own. What has been done about an
                alert - taken, silenced, still filling its window - is not a
                severity, and a band that mixed the two would ask the eye to
                compare "critical" with "silenced". */}
            <Band segments={severities} testId="severities" />
            <Figs>
              <Fig label={t("acknowledged")} value={counts?.acknowledged} />
              <Fig label={t("pending")} value={counts?.pending} />
              <Fig label={t("silenced")} value={counts?.silenced} />
              {/* A rule whose readings stopped did not pass: it was never
                  evaluated, and the count of those is its own figure. */}
              <Fig label={t("no data")} value={counts?.no_data} tone={counts?.no_data ? "warn" : undefined} />
            </Figs>
          </Card>
        ),
        footprint: <Footprint footprint={data?.agent_footprint} loaded={data !== undefined} host={host} />,
        firing: (
          <Card
            title={t("Firing alerts")}
            note={t("What tripped, where, and whether somebody has it.")}
            flush
            foot={capped
              ? (
                <span data-testid="board-capped">
                  <Pill tone="warn">{t("partial answer")}</Pill>{" "}
                  {t("{shown} of {total} shown", { shown: firing.length, total: data?.firing_total ?? firing.length })}
                  {" · "}
                  {PARTIAL_REASONS[data?.partial_reason ?? ""]
                    ? t(PARTIAL_REASONS[data?.partial_reason ?? ""])
                    : data?.partial_reason}
                </span>
              )
              : undefined}
          >
            <Table
              rows={firing}
              keyOf={(one) => one.id}
              rowTestId={(one) => `firing-${one.id}`}
              testId="firing"
              empty={data === undefined ? t("Reading alerts…") : t("Nothing is firing on the hosts you can see.")}
              columns={[
                { key: "host", head: t("Host"), tight: true, cell: (one) => host(one.host_id, one.hostname) },
                { key: "rule", head: t("Rule"), cell: (one) => (
                  <TwoLine sub={<code>{one.metric}</code>}>{one.rule_name}</TwoLine>
                ) },
                { key: "state", head: t("State"), cell: (one) => (
                  <Pill tone={alertStateTone(one.state, one.silenced)}>{t(alertStateName(one.state, one.silenced))}</Pill>
                ) },
                { key: "severity", head: t("Severity"), cell: (one) => (
                  <Pill tone={severityTone(one.severity)}>{t(one.severity)}</Pill>
                ) },
                { key: "value", head: t("Value"), num: true, cell: reading },
                { key: "detail", head: t("Detail"), minor: true, cell: (one) => (
                  one.note
                    ? <TwoLine sub={t("note: {note}", { note: one.note })}>{one.detail || "—"}</TwoLine>
                    : <span>{one.detail || <span className="fl-faint">—</span>}</span>
                ) },
                { key: "since", head: t("Since"), tight: true, cell: (one) => when(one.fired_at || one.started_at) },
                { key: "taken", head: t("Taken"), cell: (one) => (
                  one.acknowledged_at
                    ? (
                      <TwoLine sub={<>{one.acknowledged_by} · {relativeTime(one.acknowledged_at)}</>}>
                        <Pill tone="ok">{t("acknowledged")}</Pill>
                      </TwoLine>
                    )
                    : <span className="fl-faint">{t("nobody")}</span>
                ) },
                { key: "do", head: "", actions: true, cell: (one) => (
                  <Actions>
                    <button type="button" className="fl-quiet fl-small" disabled={one.silenced} onClick={() => setSilencing(one)}>
                      {t("Silence")}
                    </button>
                    {canAcknowledge && (
                      <>
                        <button type="button" className="fl-quiet fl-small" onClick={() => setAcknowledging(one)}>
                          {one.acknowledged_at ? t("Take over") : t("Acknowledge")}
                        </button>
                        <button type="button" className="fl-quiet fl-small" onClick={() => setNoting(one)}>{t("Note")}</button>
                      </>
                    )}
                  </Actions>
                ) },
              ]}
            />
          </Card>
        ),
        rules: (
          <Card
            title={t("Rules")}
            note={t("A rule fires when a metric stays past its threshold for the given minutes on every host its scope selects. Nothing fires without one.")}
            flush
            tools={canWrite
              ? <button type="button" className="fl-small" onClick={() => setEditing("new")} data-testid="new-rule">{t("New rule")}</button>
              : undefined}
            foot={rules.data ? t("{n} rules", { n: ruleItems.length }) : undefined}
          >
            {rules.error
              ? <Problem>{errorText(rules.error)}</Problem>
              : (
                <Table
                  rows={ruleItems}
                  keyOf={(one) => one.id}
                  rowTestId={(one) => `rule-${one.name}`}
                  testId="rules"
                  loading={rules.data === undefined}
                  empty={t("No rules yet: the agents sample, but nothing turns the samples into alerts.")}
                  columns={[
                    { key: "name", head: t("Rule"), cell: (one) => (
                      <TwoLine sub={metricLabel(one.metric)}>{one.name}</TwoLine>
                    ) },
                    { key: "condition", head: t("Condition"), tight: true, cell: (one) => (
                      <code title={describeCondition(one)}>{describeCondition(one)}</code>
                    ) },
                    // A rule that waits no minutes fires on the first sample
                    // past the threshold; "0 min" would read as a gap.
                    { key: "for", head: t("For"), cell: (one) => (
                      one.for_minutes > 0 ? t("{n} min", { n: one.for_minutes }) : t("at once")
                    ) },
                    // What the rule makes of its readings stopping, and the
                    // hole in them it still reads as one run.
                    { key: "nodata", head: t("No data"), minor: true, cell: (one) => (
                      <TwoLine sub={t("gap ≤ {gap}", { gap: everySeconds(one.max_gap_seconds || 120) })}>
                        {policyLabel(one.no_data_policy)}
                      </TwoLine>
                    ) },
                    { key: "severity", head: t("Severity"), cell: (one) => (
                      <Pill tone={severityTone(one.severity)}>{t(one.severity)}</Pill>
                    ) },
                    { key: "scope", head: t("Scope"), minor: true, tight: true, cell: (one) => (
                      <span title={describeSelector(one.selector)}>{describeSelector(one.selector)}</span>
                    ) },
                    { key: "enabled", head: t("Enabled"), cell: (one) => (
                      <Check
                        checked={one.enabled}
                        disabled={!canWrite || toggleRule.isPending}
                        onChange={() => toggleRule.mutate(one)}
                      >
                        {one.enabled ? t("on") : t("off")}
                      </Check>
                    ) },
                    { key: "updated", head: t("Updated"), minor: true, cell: (one) => when(one.updated_at) },
                    { key: "do", head: "", actions: true, cell: (one) => canWrite ? (
                      <Actions>
                        <button type="button" className="fl-quiet fl-small" onClick={() => setEditing(one)}>{t("Edit")}</button>
                        <button type="button" className="fl-danger fl-small" onClick={() => setDeleting(one)}>{t("Delete")}</button>
                      </Actions>
                    ) : null },
                  ]}
                />
              )}
          </Card>
        ),
        rule_form: editing !== null && (
          <RuleForm
            rule={editing === "new" ? undefined : editing}
            catalogue={rules.data}
            onDone={(text) => { setEditing(null); if (text) said(text); refresh(); }}
          />
        ),
        history: (
          <Card
            title={t("Alerts")}
            note={t("The newest fifty the server has, narrowed where you narrow it.")}
            flush
            foot={historyTotal !== undefined && historyTotal > historyShown
              ? <span data-testid="history-shown">{t("{shown} of {total} shown", { shown: historyShown, total: historyTotal })}</span>
              : undefined}
          >
            <Toolbar end={<ExportCsv params={listParams} />}>
              <select
                value={state}
                onChange={(event) => setState(event.target.value as AlertState | "")}
                aria-label={t("state: any")}
                data-testid="alert-state"
              >
                <option value="">{t("state: any")}</option>
                <option value="firing">{t("firing")}</option>
                <option value="pending">{t("pending")}</option>
                <option value="no_data">{t("no data")}</option>
                <option value="resolved">{t("resolved")}</option>
              </select>
              <select
                value={taken}
                onChange={(event) => setTaken(event.target.value as Taken)}
                aria-label={t("taken or not")}
                data-testid="alert-taken"
              >
                <option value="">{t("taken or not")}</option>
                <option value="waiting">{t("not acknowledged")}</option>
                <option value="acknowledged">{t("acknowledged")}</option>
              </select>
            </Toolbar>
            {history.error
              ? <Problem>{errorText(history.error)}</Problem>
              : (
                <Table
                  rows={history.data?.items ?? []}
                  keyOf={(one) => one.id}
                  rowTestId={(one) => `alert-${one.id}`}
                  testId="alerts"
                  loading={history.data === undefined} empty={t("No alert is recorded in this state.")}
                  columns={[
                    { key: "host", head: t("Host"), tight: true, cell: (one) => host(one.host_id, one.hostname) },
                    { key: "rule", head: t("Rule"), cell: (one) => one.rule_name },
                    { key: "severity", head: t("Severity"), cell: (one) => (
                      <Pill tone={severityTone(one.severity)}>{t(one.severity)}</Pill>
                    ) },
                    { key: "state", head: t("State"), cell: (one) => (
                      <Pill tone={alertStateTone(one.state, one.silenced)}>{t(alertStateName(one.state, one.silenced))}</Pill>
                    ) },
                    { key: "value", head: t("Value"), num: true, cell: reading },
                    { key: "started", head: t("Started"), tight: true, cell: (one) => when(one.started_at) },
                    { key: "resolved", head: t("Resolved"), tight: true, minor: true, cell: (one) => when(one.resolved_at) },
                    { key: "note", head: t("Note"), minor: true, cell: (one) => (
                      one.note ? <span title={one.note}>{one.note}</span> : <span className="fl-faint">—</span>
                    ) },
                  ]}
                />
              )}
          </Card>
        ),
        silences: (
          <Card
            title={t("Silences in force")}
            note={t("Every silence ends by itself.")}
            flush
            tools={canSilenceFleet
              ? <button type="button" className="fl-quiet fl-small" onClick={() => setFleetSilence(true)} data-testid="silence-fleet">{t("Silence every host")}</button>
              : undefined}
          >
            {silences.error
              ? <Problem>{errorText(silences.error)}</Problem>
              : (
                <Table
                  rows={silenceItems}
                  keyOf={(one) => one.id}
                  rowTestId={(one) => `silence-${one.id}`}
                  testId="silences"
                  loading={silences.data === undefined} empty={t("No silence is in force.")}
                  columns={[
                    { key: "host", head: t("Host"), tight: true, cell: (one) => (
                      one.host_id ? host(one.host_id, one.hostname) : <span className="fl-faint">{t("every host")}</span>
                    ) },
                    { key: "rule", head: t("Rule"), cell: (one) => (
                      <TwoLine sub={
                        <>
                          {one.global && <Pill tone="warn" title={t("Keeps back the security alerts of the whole installation.")}>{t("global")}</Pill>}
                          {one.send_summary && <Pill tone="neutral" title={t("When it ends, every channel gets one message naming what it kept back.")}>{t("summary")}</Pill>}
                        </>
                      }>
                        {one.rule_name || <span className="fl-faint">{t("every rule")}</span>}
                      </TwoLine>
                    ) },
                    { key: "until", head: t("Until"), tight: true, cell: (one) => when(one.until) },
                    { key: "reason", head: t("Reason"), cell: (one) => (
                      <TwoLine sub={one.created_by}>{one.reason}</TwoLine>
                    ) },
                    { key: "do", head: "", actions: true, cell: (one) => (
                      <button type="button" className="fl-quiet fl-small" disabled={endSilence.isPending} onClick={() => endSilence.mutate(one)}>
                        {t("End now")}
                      </button>
                    ) },
                  ]}
                />
              )}
          </Card>
        ),
      }} />

      {deleting && (
        <Modal
          title={t("Delete the rule")}
          onClose={() => setDeleting(null)}
          actions={
            <>
              <button type="button" className="fl-quiet" onClick={() => setDeleting(null)}>{t("Cancel")}</button>
              <button type="button" className="fl-danger" disabled={removeRule.isPending} onClick={() => removeRule.mutate(deleting)} data-testid="confirm-delete">
                {t("Delete")}
              </button>
            </>
          }
        >
          <p>{t("Delete the rule {name}? Its alerts resolve on the next evaluation.", { name: deleting.name })}</p>
        </Modal>
      )}

      {acknowledging && (
        <ReasonModal
          title={t("Acknowledge {rule} on {host}", { rule: acknowledging.rule_name, host: acknowledging.hostname })}
          body={t("The alert keeps firing - only the host ends it - but it leaves the counts of what waits for a person, under your name. Write what is being done about it.")}
          label={t("Note (at least 8 characters)")}
          placeholder={t("what is being done about it")}
          confirm={t("Acknowledge")}
          busy={acknowledge.isPending}
          onClose={() => setAcknowledging(null)}
          onConfirm={(note) => acknowledge.mutate({ alert: acknowledging, note })}
        />
      )}

      {noting && (
        <ReasonModal
          title={t("Note on {rule} at {host}", { rule: noting.rule_name, host: noting.hostname })}
          body={t("The note stays with the alert in its history; an empty one removes it.")}
          label={t("Note")}
          placeholder={t("where the cause was found, which change is on its way")}
          confirm={t("Save the note")}
          initial={noting.note ?? ""}
          optional
          busy={annotate.isPending}
          onClose={() => setNoting(null)}
          onConfirm={(note) => annotate.mutate({ alert: noting, note })}
        />
      )}

      {silencing && (
        <SilenceModal
          title={t("Silence {rule} on {host}", { rule: silencing.rule_name, host: silencing.hostname })}
          body={t("The alert goes on firing; the silence only keeps it out of the way, and it ends by itself.")}
          busy={silenceAlert.isPending}
          onClose={() => setSilencing(null)}
          onConfirm={(reason, minutes, summary) => silenceAlert.mutate({ alert: silencing, reason, minutes, summary })}
        />
      )}

      {fleetSilence && (
        <SilenceModal
          title={t("Silence every host")}
          body={t("A silence that names no host covers every host of the installation. The reason stays on it and in the audit trail.")}
          summaryDefault
          global={canSilenceGlobal}
          busy={silenceFleet.isPending}
          onClose={() => setFleetSilence(false)}
          onConfirm={(reason, minutes, summary, blind) =>
            silenceFleet.mutate({ reason, minutes, global: blind === true, send_summary: summary })}
        />
      )}
    </>
  );
}

/* --------------------------------------------------------- the footprint */

/**
 * What the agents cost the hosts they run on: the release gate of the agent
 * asks for its memory and CPU on a real fleet, and this is where the fleet
 * answers. A figure no agent sent is an em dash, because an older agent
 * sends none and nought would read as an agent that costs nothing.
 */
function Footprint({ footprint, loaded, host }: {
  footprint?: FleetFootprint;
  loaded: boolean;
  host: (id: string, hostname?: string) => ReactNode;
}) {
  const t = useT();
  const measured = footprint?.hosts_measured;
  const over = footprint?.over_budget ?? [];
  const size = (value?: number) => (value === undefined ? undefined : bytes(value));
  const share = (value?: number) => (value === undefined ? undefined : `${Math.round(value * 10) / 10}%`);
  const overRSS = footprint !== undefined && footprint.rss_bytes_max !== undefined
    && footprint.rss_bytes_max > footprint.rss_budget_bytes;
  const overCPU = footprint !== undefined && footprint.cpu_percent_max !== undefined
    && footprint.cpu_percent_max > footprint.cpu_budget_percent;
  return (
    <Card
      title={t("Agent footprint")}
      note={footprint
        ? t("Budget {rss} and {cpu}% of one core.", { rss: bytes(footprint.rss_budget_bytes), cpu: footprint.cpu_budget_percent })
        : t("What the agents cost the hosts they run on.")}
    >
      <Figs>
        <Fig label={t("Hosts measured")} value={measured} />
        <Fig label={t("Median RSS")} value={size(footprint?.rss_bytes_median)} />
        <Fig label={t("Max RSS")} value={size(footprint?.rss_bytes_max)} tone={overRSS ? "warn" : undefined} />
        <Fig label={t("Median CPU")} value={share(footprint?.cpu_percent_median)} />
        <Fig label={t("Max CPU")} value={share(footprint?.cpu_percent_max)} tone={overCPU ? "warn" : undefined} />
        <Fig label={t("Helper RSS, max")} value={size(footprint?.helper_rss_bytes_max)} />
      </Figs>
      {!loaded ? (
        <Bones rows={4} />
      ) : !footprint || measured === 0 ? (
        <Empty>{t("No agent has sent its footprint yet; an older agent does not.")}</Empty>
      ) : over.length === 0 ? (
        <Empty>{t("Every measured agent is within the budget.")}</Empty>
      ) : (
        <Table
          rows={over}
          keyOf={(one) => one.host_id}
          rowTestId={(one) => `over-${one.host_id}`}
          testId="over-budget"
          columns={[
            { key: "host", head: t("Host"), tight: true, cell: (one) => host(one.host_id, one.hostname) },
            { key: "rss", head: t("Agent RSS"), num: true, cell: (one) => (
              one.agent_rss_bytes === undefined ? <span className="fl-faint">—</span> : bytes(one.agent_rss_bytes)
            ) },
            { key: "cpu", head: t("Agent CPU"), num: true, cell: (one) => (
              one.agent_cpu_percent === undefined
                ? <span className="fl-faint">—</span>
                : `${Math.round(one.agent_cpu_percent * 10) / 10}%`
            ) },
          ]}
        />
      )}
    </Card>
  );
}

/* ------------------------------------------------------------ the export */

/** The alert list as a file: every row the filter selects, not this page. */
function ExportCsv({ params }: { params: URLSearchParams }) {
  const t = useT();
  const toast = useToast();
  const [busy, setBusy] = useState(false);
  const download = async () => {
    setBusy(true);
    try {
      const response = await fetchWithCredentials(exportAddress("/api/v1/monitoring/alerts", params));
      if (!response.ok) throw new Error(response.statusText);
      const blob = await response.blob();
      const href = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = href;
      anchor.download = exportFileName(response.headers.get("Content-Disposition"));
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      URL.revokeObjectURL(href);
    } catch (error) {
      toast.error(t("The export failed: {message}", { message: errorText(error) }));
    } finally {
      setBusy(false);
    }
  };
  return (
    <button type="button" className="fl-quiet fl-small" onClick={download} disabled={busy} data-testid="export-csv">
      {busy ? t("Exporting…") : t("Export CSV")}
    </button>
  );
}

/* ----------------------------------------------------------- the dialogs */

/** A decision that needs a sentence for the trail before it is taken. */
function ReasonModal({ title, body, label, placeholder, confirm, initial = "", optional = false, busy, onClose, onConfirm }: {
  title: string;
  body: string;
  label: string;
  placeholder: string;
  confirm: string;
  initial?: string;
  /** A note may be emptied; a reason may not. */
  optional?: boolean;
  busy: boolean;
  onClose: () => void;
  onConfirm: (text: string) => void;
}) {
  const t = useT();
  const [text, setText] = useState(initial);
  const ready = optional || text.trim().length >= 8;
  return (
    <Modal
      title={title}
      onClose={onClose}
      actions={
        <>
          <button type="button" className="fl-quiet" onClick={onClose} disabled={busy}>{t("Cancel")}</button>
          <button type="button" disabled={!ready || busy} onClick={() => onConfirm(text.trim())} data-testid="confirm-reason">
            {busy ? t("Saving…") : confirm}
          </button>
        </>
      }
    >
      <p>{body}</p>
      <Fields>
        <Field label={label} wide>
          <input value={text} onChange={(event) => setText(event.target.value)} placeholder={placeholder} data-testid="reason" />
        </Field>
      </Fields>
    </Modal>
  );
}

/** Turning a sensor off for a while: a reason, a length, and what is told after. */
function SilenceModal({ title, body, summaryDefault = false, global: offerGlobal = false, busy, onClose, onConfirm }: {
  title: string;
  body: string;
  summaryDefault?: boolean;
  /** Only whoever may manage the channels everywhere is offered the global one. */
  global?: boolean;
  busy: boolean;
  onClose: () => void;
  onConfirm: (reason: string, minutes: number, summary: boolean, blind?: boolean) => void;
}) {
  const t = useT();
  const [reason, setReason] = useState("");
  const [minutes, setMinutes] = useState("60");
  const [summary, setSummary] = useState(summaryDefault);
  const [blind, setBlind] = useState(false);
  const length = Number(minutes);
  const ready = reason.trim().length >= 8 && length > 0 && length <= 1440;
  return (
    <Modal
      title={title}
      onClose={onClose}
      actions={
        <>
          <button type="button" className="fl-quiet" onClick={onClose} disabled={busy}>{t("Cancel")}</button>
          <button type="button" disabled={!ready || busy} onClick={() => onConfirm(reason.trim(), length, summary, blind)} data-testid="confirm-silence">
            {busy ? t("Silencing…") : t("Silence")}
          </button>
        </>
      }
    >
      <p>{body}</p>
      <Fields>
        <Field label={t("Reason")} hint={t("At least 8 characters; it stays on the silence and in the audit trail.")} wide>
          <input value={reason} onChange={(event) => setReason(event.target.value)} data-testid="silence-reason" />
        </Field>
        <Field label={t("Minutes")} hint={t("At most 1440: a silence always ends.")}>
          <input type="number" min={1} max={1440} value={minutes} onChange={(event) => setMinutes(event.target.value)} data-testid="silence-minutes" />
        </Field>
      </Fields>
      <Row>
        <Check checked={summary} onChange={setSummary}>{t("Send one summary per channel when it ends")}</Check>
        {offerGlobal && (
          <Check checked={blind} onChange={setBlind}>{t("Keep back the security alerts of the installation too")}</Check>
        )}
      </Row>
    </Modal>
  );
}

/* -------------------------------------------------------- the rule form */

/** A rule as the form sends it: the input of the API with the wider scope. */
type RuleDraft = Omit<AlertRuleInput, "selector"> & { selector: RuleScope };

/** The body the server takes for a rule, from a rule or a form. */
function ruleBody(rule: RuleDraft): RuleDraft {
  const selector: RuleScope = {};
  if (rule.selector.site) selector.site = rule.selector.site;
  if (rule.selector.environment) selector.environment = rule.selector.environment;
  if (rule.selector.os_family) selector.os_family = rule.selector.os_family;
  if (rule.selector.tags?.length) selector.tags = rule.selector.tags;
  if (rule.selector.groups?.length) selector.groups = rule.selector.groups;
  if (rule.selector.owner) selector.owner = rule.selector.owner;
  if (rule.selector.expression) selector.expression = rule.selector.expression;
  if (rule.selector.host_ids?.length) selector.host_ids = rule.selector.host_ids;
  return {
    name: rule.name.trim(),
    metric: rule.metric,
    operator: rule.operator,
    threshold: rule.threshold,
    for_minutes: rule.for_minutes,
    severity: rule.severity,
    selector,
    enabled: rule.enabled,
    expected_cadence_seconds: rule.expected_cadence_seconds,
    max_gap_seconds: rule.max_gap_seconds,
    no_data_policy: rule.no_data_policy,
  };
}

/**
 * The form of a rule, new or edited. It stands on the screen rather than
 * over it: a rule is written while its neighbours are being read, which
 * is the one thing a dialog would take away.
 */
function RuleForm({ rule, catalogue, onDone }: {
  rule?: AlertRule;
  catalogue?: RuleCatalogue;
  onDone: (message?: string) => void;
}) {
  const t = useT();
  const metrics = catalogue?.metrics ?? Object.keys(METRIC_LABELS);
  const operators = (catalogue?.operators ?? ["gt", "lt", "gte", "lte"]) as RuleOperator[];
  const severities = (catalogue?.severities ?? ["critical", "warning", "info"]) as AlertSeverity[];

  const [name, setName] = useState(rule?.name ?? "");
  const [metric, setMetric] = useState(rule?.metric ?? metrics[0] ?? "cpu_percent");
  const [operator, setOperator] = useState<RuleOperator>(rule?.operator ?? "gt");
  const [threshold, setThreshold] = useState(rule ? String(rule.threshold) : "");
  const [forMinutes, setForMinutes] = useState(rule ? String(rule.for_minutes) : "5");
  const [severity, setSeverity] = useState<AlertSeverity>(rule?.severity ?? "warning");
  // The defaults are the ones a rule written before these settings existed
  // carries: the interval the agents sample at, two of them, and no word
  // about a gap.
  const [cadence, setCadence] = useState(String(rule?.expected_cadence_seconds || 60));
  const [maxGap, setMaxGap] = useState(String(rule?.max_gap_seconds || 120));
  const [noDataPolicy, setNoDataPolicy] = useState(rule?.no_data_policy || "ignore");
  const scope = rule?.selector as RuleScope | undefined;
  const [site, setSite] = useState(scope?.site ?? "");
  const [environment, setEnvironment] = useState(scope?.environment ?? "");
  const [osFamily, setOsFamily] = useState(scope?.os_family ?? "");
  const [tags, setTags] = useState(scope?.tags?.join(" ") ?? "");
  const [groups, setGroups] = useState(scope?.groups?.join(", ") ?? "");
  const [owner, setOwner] = useState(scope?.owner ?? "");
  const [expression, setExpression] = useState(scope?.expression ?? "");
  const [enabled, setEnabled] = useState(rule?.enabled ?? true);
  const [problem, setProblem] = useState("");

  // The expression is read the way the server reads it; an empty one is
  // no scope rather than a mistake.
  const expressionCheck = expression.trim() === "" ? undefined : parseExpression(expression.trim());
  const suggestions = expressionSuggestions(expression);

  const body = (): RuleDraft => ruleBody({
    name,
    metric,
    operator,
    threshold: Number(threshold),
    for_minutes: Number(forMinutes),
    severity,
    expected_cadence_seconds: Number(cadence),
    max_gap_seconds: Number(maxGap),
    no_data_policy: noDataPolicy,
    selector: {
      site, environment, os_family: osFamily,
      tags: words(tags), groups: words(groups), owner: owner.trim(), expression: expression.trim(),
      host_ids: scope?.host_ids,
    },
    enabled,
  });

  const save = useMutation({
    mutationFn: () => (rule
      ? api.put<AlertRule>(`/api/v1/monitoring/rules/${rule.id}`, body())
      : api.post<AlertRule>("/api/v1/monitoring/rules", body())),
    onSuccess: (saved) => onDone(rule
      ? t("Rule {name} is updated.", { name: saved.name })
      : t("Rule {name} is created; it applies from the next evaluation.", { name: saved.name })),
    onError: (error) => setProblem(errorText(error)),
  });

  // The same three checks the server makes, so the operator sees the
  // contradiction before the round trip rather than as a refusal code.
  const thresholdNumber = Number(threshold);
  const cadenceNumber = Number(cadence);
  const gapNumber = Number(maxGap);
  const cadenceError = !Number.isInteger(cadenceNumber) || cadenceNumber < 60 || cadenceNumber > 86400
    ? t("The agents sample once a minute, so a rule expects a reading every 60 s at the soonest and every 24 h at the latest.")
    : "";
  const gapError = !Number.isInteger(gapNumber) || gapNumber > 86400
    ? t("The widest gap has to be a whole number of seconds, at most 24 h.")
    : gapNumber < cadenceNumber
      ? t("A gap narrower than the expected cadence opens one after every reading that arrives on time.")
      : "";
  const ready = name.trim() !== "" && metric !== "" && threshold.trim() !== "" && Number.isFinite(thresholdNumber)
    && Number.isInteger(Number(forMinutes)) && Number(forMinutes) >= 0
    && cadenceError === "" && gapError === ""
    && (expressionCheck === undefined || expressionCheck.ok);

  return (
    <Card
      title={rule ? t("Edit rule {name}", { name: rule.name }) : t("New rule")}
      note={t("The condition must hold for the whole of “for” before the alert fires; zero fires on the first sample past the threshold.")}
    >
      <Fields>
        <Field label={t("Name")}>
          <input value={name} onChange={(event) => setName(event.target.value)} placeholder={t("e.g. root filesystem nearly full")} data-testid="rule-name" />
        </Field>
        <Field label={t("Metric")} hint={metricLabel(metric)}>
          <select value={metric} onChange={(event) => setMetric(event.target.value)} data-testid="rule-metric">
            {metrics.map((one) => <option key={one} value={one}>{one}</option>)}
          </select>
        </Field>
        <Field label={t("Operator")}>
          <select value={operator} onChange={(event) => setOperator(event.target.value as RuleOperator)}>
            {operators.map((one) => <option key={one} value={one}>{OPERATOR_SIGNS[one] ?? one} ({one})</option>)}
          </select>
        </Field>
        <Field
          label={t("Threshold")}
          hint={threshold.trim() !== "" && Number.isFinite(thresholdNumber)
            ? describeCondition({ metric, operator, threshold: thresholdNumber })
            : undefined}
        >
          <input type="number" step="any" value={threshold} onChange={(event) => setThreshold(event.target.value)} data-testid="rule-threshold" />
        </Field>
        <Field label={t("For (minutes)")}>
          <input type="number" min={0} step={1} value={forMinutes} onChange={(event) => setForMinutes(event.target.value)} />
        </Field>
        <Field label={t("Severity")}>
          <select value={severity} onChange={(event) => setSeverity(event.target.value as AlertSeverity)}>
            {severities.map((one) => <option key={one} value={one}>{t(one)}</option>)}
          </select>
        </Field>
        {/* How often the rule expects a reading, how wide a hole in the
            readings it still reads as one run, and what a wider one means. */}
        <Field
          label={t("Expects a reading every (seconds)")}
          hint={cadenceError || t("Every {every}; the agents sample once a minute.", { every: everySeconds(cadenceNumber) })}
        >
          <input type="number" min={60} max={86400} step={1} value={cadence} onChange={(event) => setCadence(event.target.value)} />
        </Field>
        <Field
          label={t("Widest gap (seconds)")}
          hint={gapError || t("A hole of up to {gap} still counts as one continuous run, so “for” is not filled by silence.", { gap: everySeconds(gapNumber) })}
        >
          <input type="number" min={60} max={86400} step={1} value={maxGap} onChange={(event) => setMaxGap(event.target.value)} />
        </Field>
        <Field
          label={t("When the readings stop")}
          hint={t("Alert raises an episode and tells the channels; unknown only shows it here; ignore judges what arrives and says nothing.")}
        >
          <select value={noDataPolicy} onChange={(event) => setNoDataPolicy(event.target.value as AlertRuleInput["no_data_policy"])}>
            {NO_DATA_POLICIES.map((one) => <option key={one} value={one}>{policyLabel(one)} ({one})</option>)}
          </select>
        </Field>
        <Field label={t("Site")} hint={t("Empty: every site.")}>
          <input value={site} onChange={(event) => setSite(event.target.value)} />
        </Field>
        <Field label={t("Environment")} hint={t("Empty: every environment.")}>
          <input value={environment} onChange={(event) => setEnvironment(event.target.value)} />
        </Field>
        <Field label={t("System family")} hint={t("Empty: every family (debian, rhel, arch…).")}>
          <input value={osFamily} onChange={(event) => setOsFamily(event.target.value)} />
        </Field>
        <Field label={t("Tags")} hint={t("Every listed tag has to be on the host; key or key=value, separated by spaces.")}>
          <input value={tags} onChange={(event) => setTags(event.target.value)} placeholder="role=db tier=gold" />
        </Field>
        <Field label={t("Groups")} hint={t("The host has to be in one of the listed groups; names separated by commas.")}>
          <input value={groups} onChange={(event) => setGroups(event.target.value)} placeholder="databases, caches" />
        </Field>
        <Field label={t("Owner")} hint={t("Empty: every owner.")}>
          <input value={owner} onChange={(event) => setOwner(event.target.value)} />
        </Field>
        {/* The expression takes what the fields cannot say - a version
            comparison, a health fact, an alternative - in the text form a
            campaign selector has. The list under the field offers what may
            come next; the hint shows where the text stops parsing. */}
        <Field
          label={t("Expression")}
          wide
          hint={expressionCheck && !expressionCheck.ok
            ? expressionCheck.error
            : t("Selector text for what the fields cannot say, e.g. agent_version < 0.49.0 or reboot_required = true; and, or, not and parentheses combine conditions.")}
        >
          <input
            className="fl-mono"
            value={expression}
            onChange={(event) => setExpression(event.target.value)}
            list="next-rule-expression-words"
            spellCheck={false}
            placeholder="security_updates = true and connection = online"
          />
          <datalist id="next-rule-expression-words">
            {suggestions.map((word) => (
              <option key={word} value={`${expression.replace(/[A-Za-z0-9_=!<>]*$/, "")}${word} `} />
            ))}
          </datalist>
        </Field>
      </Fields>
      <Row>
        <Check checked={enabled} onChange={setEnabled}>{t("Enabled")}</Check>
      </Row>
      {problem !== "" && <Problem>{problem}</Problem>}
      <Actions>
        <button type="button" onClick={() => save.mutate()} disabled={!ready || save.isPending} data-testid="save-rule">
          {save.isPending ? t("Saving…") : rule ? t("Save rule") : t("Create rule")}
        </button>
        <button type="button" className="fl-quiet" onClick={() => onDone()} disabled={save.isPending}>{t("Cancel")}</button>
      </Actions>
    </Card>
  );
}

export const MONITORING_SCREEN = "next_monitoring";

export const MONITORING: BoardEntry[] = [
  { key: "waiting", title: "Waiting for somebody", width: 3, height: 1 },
  { key: "reporting", title: "Hosts reporting", width: 3, height: 1 },
  { key: "quiet", title: "Gone quiet", width: 3, height: 1 },
  { key: "watching", title: "Rules enabled", width: 3, height: 1 },
  { key: "severity", title: "Firing now", width: 5, height: 2 },
  { key: "footprint", title: "Agent footprint", width: 7, height: 2 },
  { key: "firing", title: "Firing alerts", width: 12, height: 5 },
  { key: "rule_form", title: "Rule", width: 12, height: 6 },
  { key: "rules", title: "Rules", width: 12, height: 4 },
  { key: "history", title: "Alerts", width: 8, height: 4 },
  { key: "silences", title: "Silences in force", width: 4, height: 3 },
];
