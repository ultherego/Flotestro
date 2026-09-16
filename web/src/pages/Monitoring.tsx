import { useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, type Collection } from "../lib/api";
import type {
  Alert, AlertRule, AlertRuleInput, AlertSeverity, AlertState, FleetFootprint, FleetMonitoring as FleetView,
  RuleCatalogue, RuleOperator, RuleSelector, Silence, Whoami,
} from "../lib/types";
import { ErrorBox, Time, Empty } from "../components/ui";
import { Actions, Card, EmptyState, Field, FieldGrid, PageHeader, Stat, StatGrid, Toolbar } from "../components/layout";
import { ExportButton } from "../components/ExportButton";
import { StatusBar } from "../components/widgets";
import { useConfirm } from "../components/Modal";
import { useToast } from "../components/Toast";
import { bytes } from "../lib/format";
import { expressionSuggestions, parseExpression } from "../lib/targets";
import { t as translate, useT } from "../i18n";

/* ---------------------------------------------------------------------- */
/* The vocabulary of the rules, shared with the host page.                 */
/* ---------------------------------------------------------------------- */

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

export function metricLabel(metric: string): string {
  const label = METRIC_LABELS[metric];
  return label ? translate(label) : metric;
}

/** A length of time in the units an operator counts it in. */
export function duration(seconds: number): string {
  const whole = Math.max(0, Math.floor(seconds));
  const days = Math.floor(whole / 86400);
  const hours = Math.floor((whole % 86400) / 3600);
  const minutes = Math.floor((whole % 3600) / 60);
  if (days > 0) return `${days}d ${hours}h`;
  if (hours > 0) return `${hours}h ${minutes}m`;
  if (minutes > 0) return `${minutes}m`;
  return `${whole}s`;
}

/** A value of a metric with its unit: a percent, a load, a count of minutes, an uptime, a size. */
export function metricValue(metric: string, value: number): string {
  if (metric.endsWith("_percent")) return `${roundTo(value, 1)}%`;
  if (metric.endsWith("_bytes")) return bytes(value);
  if (metric === "uptime_seconds") return duration(value);
  if (metric === "host_offline") return translate("{n} min", { n: roundTo(value, 0) });
  return String(roundTo(value, 2));
}

function roundTo(value: number, digits: number): number {
  const factor = Math.pow(10, digits);
  return Math.round(value * factor) / factor;
}

/** The condition of a rule in one line: the metric, the sign and the threshold. */
export function describeCondition(rule: { metric: string; operator: RuleOperator; threshold: number }): string {
  return `${rule.metric} ${OPERATOR_SIGNS[rule.operator] ?? rule.operator} ${metricValue(rule.metric, rule.threshold)}`;
}

/**
 * The scope of a rule as the server takes it: the flat fields, the tags
 * the host has to carry, the groups it may be in, its owner, and an
 * expression in the text form of a campaign selector for what the fields
 * cannot say. Every set field holds at once.
 */
export type RuleScope = RuleSelector & {
  tags?: string[];
  groups?: string[];
  owner?: string;
  expression?: string;
};

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

/** The words of a list field - tags, groups - cut at commas and spaces, empty ones dropped. */
function words(text: string): string[] {
  return text.split(/[\s,]+/).map((word) => word.trim()).filter(Boolean);
}

export function severityTone(severity: AlertSeverity): "error" | "warn" | "info" {
  return severity === "critical" ? "error" : severity === "warning" ? "warn" : "info";
}

export function SeverityBadge({ severity }: { severity: AlertSeverity }) {
  const t = useT();
  const names: Record<AlertSeverity, string> = { critical: t("critical"), warning: t("warning"), info: t("info") };
  return <span className={`badge ${severityTone(severity)}`}>{names[severity] ?? severity}</span>;
}

/** The state of an alert; a silenced one is still firing, only nobody is told. */
export function AlertStateBadge({ state, silenced }: { state: AlertState; silenced: boolean }) {
  const t = useT();
  if (state === "resolved") return <span className="badge ok">{t("resolved")}</span>;
  if (state === "pending") return <span className="badge unknown">{t("pending")}</span>;
  return silenced
    ? <span className="badge">{t("firing, silenced")}</span>
    : <span className="badge error">{t("firing")}</span>;
}

/**
 * An alert with what an operator wrote on it. The acknowledgement says
 * somebody took it: the alert keeps firing, the counts of what waits for
 * a person leave it out, and the row names who and what they wrote.
 */
export type NotedAlert = Alert & {
  acknowledged_by?: string;
  acknowledged_at?: string | null;
  note?: string;
};

/** The filter of the firing table: everything, what waits, or what somebody took. */
export type FiringFilter = "" | "waiting" | "acknowledged";

/** The firing alerts the filter keeps. */
export function filterFiring<T extends NotedAlert>(alerts: T[], filter: FiringFilter): T[] {
  if (filter === "waiting") return alerts.filter((alert) => !alert.acknowledged_at);
  if (filter === "acknowledged") return alerts.filter((alert) => Boolean(alert.acknowledged_at));
  return alerts;
}

/** Who took the alert, as a chip; nothing for an alert nobody took. */
export function AcknowledgedChip({ alert }: { alert: NotedAlert }) {
  const t = useT();
  if (!alert.acknowledged_at) return null;
  return (
    <span className="badge ok" title={alert.acknowledged_by ? t("taken by {who}", { who: alert.acknowledged_by }) : undefined}>
      {t("acknowledged")}
    </span>
  );
}

function usePermissions(): Set<string> {
  const whoami = useQuery({
    queryKey: ["whoami"],
    queryFn: () => api.get<Whoami>("/api/v1/whoami"),
    staleTime: 5 * 60 * 1000,
  });
  return new Set(whoami.data?.permissions ?? []);
}

function errorText(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/**
 * Fleet monitoring.
 *
 * Every agent samples its host once a minute and the panel keeps the
 * samples; the rules written here turn them into alerts. There is no
 * other system behind this page: what fires, fires by a rule an operator
 * can read on the same screen, and a silence is a decision with a reason
 * and an owner, never an open-ended one.
 */
export function FleetMonitoring() {
  const t = useT();
  const queryClient = useQueryClient();
  const permissions = usePermissions();
  const canWrite = permissions.has("monitoring.rules.write");
  // Taking an alert is the right of a silence: both are a decision about
  // a sensor of one host.
  const canAcknowledge = permissions.has("monitoring.silence.write");
  const [editing, setEditing] = useState<AlertRule | "new" | null>(null);
  const [historyState, setHistoryState] = useState<AlertState | "">("");
  const [historyTaken, setHistoryTaken] = useState<FiringFilter>("");
  const [firingFilter, setFiringFilter] = useState<FiringFilter>("");
  const [message, setMessage] = useState("");
  const confirm = useConfirm();
  const toast = useToast();

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
  const historyParams = new URLSearchParams();
  if (historyState) historyParams.set("state", historyState);
  if (historyTaken) historyParams.set("acknowledged", historyTaken === "acknowledged" ? "true" : "false");
  const history = useQuery({
    queryKey: ["monitoring", "alerts", historyState, historyTaken],
    queryFn: () => {
      const params = new URLSearchParams(historyParams);
      params.set("limit", "50");
      return api.get<Collection<NotedAlert>>(`/api/v1/monitoring/alerts?${params}`);
    },
    refetchInterval: 30000,
  });
  const silences = useQuery({
    queryKey: ["monitoring", "silences"],
    queryFn: () => api.get<Collection<Silence>>("/api/v1/monitoring/silences"),
    refetchInterval: 30000,
  });

  const refresh = () => queryClient.invalidateQueries({ queryKey: ["monitoring"] });

  const toggleRule = useMutation({
    mutationFn: (rule: AlertRule) => api.put<AlertRule>(`/api/v1/monitoring/rules/${rule.id}`, ruleBody({ ...rule, enabled: !rule.enabled })),
    onSuccess: (rule) => {
      setMessage(rule.enabled ? t("Rule {name} is enabled.", { name: rule.name }) : t("Rule {name} is disabled.", { name: rule.name }));
      refresh();
    },
    onError: (error) => setMessage(errorText(error)),
  });
  // The rule table is below the message strip, so the outcome of a delete
  // is also announced where the button was pressed.
  const removeRule = useMutation({
    mutationFn: (rule: AlertRule) => api.del(`/api/v1/monitoring/rules/${rule.id}`),
    onSuccess: (_, rule) => {
      const text = t("Rule {name} is deleted; its alerts resolve on the next evaluation.", { name: rule.name });
      setMessage(text);
      toast.success(text);
      refresh();
    },
    onError: (error) => {
      setMessage(errorText(error));
      toast.error(errorText(error));
    },
  });
  const askToDeleteRule = async (rule: AlertRule) => {
    const answer = await confirm({
      title: t("Delete the rule"),
      body: t("Delete the rule {name}? Its alerts resolve on the next evaluation.", { name: rule.name }),
      confirmLabel: t("Delete"),
      danger: true,
    });
    if (answer.ok) removeRule.mutate(rule);
  };
  const endSilence = useMutation({
    mutationFn: (silence: Silence) =>
      api.del(`/api/v1/hosts/${silence.host_id}/monitoring/silences/${encodeURIComponent(silence.id)}`),
    onSuccess: () => {
      setMessage(t("Silence ended."));
      refresh();
    },
    onError: (error) => setMessage(errorText(error)),
  });

  if (overview.error) return <ErrorBox error={overview.error} />;
  const data = overview.data;
  // The counts are unknown until the server answers: the bar shows dashes
  // then, not a fleet with nothing firing.
  const counts = data?.counts as (FleetView["counts"] & { acknowledged?: number }) | undefined;
  const firing = filterFiring((data?.firing ?? []) as NotedAlert[], firingFilter);
  const ruleItems = rules.data?.items ?? [];
  const silenceItems = silences.data?.items ?? [];

  return (
    <>
      <PageHeader
        title={t("Monitoring")}
        description={t("Every agent samples its host once a minute; the rules on this page turn the samples into alerts. Nothing fires without a rule an operator can read here.")}
        actions={canWrite && editing === null && (
          <button className="primary" onClick={() => setEditing("new")}>{t("New rule")}</button>
        )}
      />

      <div className="widgets">
        <Card
          className="span-8"
          title={t("Firing now")}
          description={t("Alerts by severity across the hosts you can see, without the ones somebody took; the taken, silenced and pending ones counted apart.")}
        >
          <StatusBar segments={[
            { label: t("Critical"), value: counts?.critical, tone: "error" },
            { label: t("Warning"), value: counts?.warning, tone: "warn" },
            { label: t("Info"), value: counts?.info, tone: "info" },
            { label: t("Acknowledged"), value: counts?.acknowledged, tone: "ok" },
            { label: t("Pending"), value: counts?.pending, tone: "unknown" },
            { label: t("Silenced"), value: counts?.silenced, tone: "neutral" },
          ]} />
        </Card>

        <Card className="span-4" title={t("Coverage")} description={t("Who reports, who has gone quiet, and how many rules watch them.")}>
          <StatGrid compact>
            <Stat label={t("Hosts reporting")} value={data ? data.hosts_reporting : "—"} tone="ok" hint={t("a sample within the last few minutes")} />
            <Stat label={t("Hosts silent")} value={data ? data.hosts_silent : "—"} tone={(data?.hosts_silent ?? 0) > 0 ? "warn" : undefined} hint={t("enrolled, but no recent sample")} />
            <Stat label={t("Enabled rules")} value={data ? data.rules : "—"} hint={data ? <>{t("as of")} <Time value={data.generated_at} /></> : undefined} />
          </StatGrid>
        </Card>

        <AgentFootprintCard footprint={data?.agent_footprint} loaded={data !== undefined} />

        {message && (
          <div className="span-12">
            <p className="hm-message">{message}</p>
          </div>
        )}

        <Card
          className="span-12"
          title={t("Firing alerts")}
          description={t("Each one names the rule and the value that tripped it; a silence here covers that rule on that host, and an acknowledgement says somebody is on it while the sensor stays on.")}
          actions={
            <select value={firingFilter} onChange={(e) => setFiringFilter(e.target.value as FiringFilter)}>
              <option value="">{t("every firing alert")}</option>
              <option value="waiting">{t("waiting for somebody")}</option>
              <option value="acknowledged">{t("acknowledged")}</option>
            </select>
          }
          flush
        >
          {!data ? (
            <Empty>{t("Reading alerts…")}</Empty>
          ) : firing.length === 0 ? (
            <Empty>{firingFilter ? t("No firing alert matches the filter.") : t("Nothing is firing on the hosts you can see.")}</Empty>
          ) : (
            <FiringTable alerts={firing} canAcknowledge={canAcknowledge} onChanged={refresh} onMessage={setMessage} />
          )}
        </Card>

        {editing !== null && (
          <div className="span-12">
            <RuleForm
              rule={editing === "new" ? undefined : editing}
              catalogue={rules.data}
              onDone={(text) => {
                setEditing(null);
                if (text) setMessage(text);
                refresh();
              }}
            />
          </div>
        )}

        <Card
          className="span-12"
          title={t("Rules")}
          description={t("A rule fires when a metric stays past its threshold for the given minutes on every host its scope selects. A disabled rule is listed because it would apply the moment somebody enables it.")}
          flush
        >
          {rules.error ? (
            <ErrorBox error={rules.error} />
          ) : !rules.data ? (
            <Empty>{t("Loading…")}</Empty>
          ) : ruleItems.length === 0 ? (
            <EmptyState action={canWrite && editing === null && (
              <button className="secondary" onClick={() => setEditing("new")}>{t("New rule")}</button>
            )}>
              {t("No rules yet: the agents sample, but nothing turns the samples into alerts.")}
            </EmptyState>
          ) : (
            <table>
              <thead>
                <tr>
                  <th>{t("Rule")}</th><th>{t("Condition")}</th><th>{t("For")}</th><th>{t("Severity")}</th>
                  <th>{t("Scope")}</th><th>{t("Enabled")}</th><th>{t("Updated")}</th>{canWrite && <th></th>}
                </tr>
              </thead>
              <tbody>
                {ruleItems.map((rule) => (
                  <tr key={rule.id}>
                    <td>
                      <div className="fp-host-cell">
                        <span>{rule.name}</span>
                        <span className="source">{metricLabel(rule.metric)}</span>
                      </div>
                    </td>
                    <td className="hm-mono">{describeCondition(rule)}</td>
                    {/* A rule that waits no minutes fires on the first
                        sample past the threshold; "0 min" reads as a gap. */}
                    <td>{rule.for_minutes > 0 ? t("{n} min", { n: rule.for_minutes }) : t("at once")}</td>
                    <td><SeverityBadge severity={rule.severity} /></td>
                    <td className="source">{describeSelector(rule.selector)}</td>
                    <td>
                      <label className="toggle" style={{ margin: 0 }}>
                        <input
                          type="checkbox"
                          checked={rule.enabled}
                          disabled={!canWrite || toggleRule.isPending}
                          onChange={() => toggleRule.mutate(rule)}
                        />
                        <span>{rule.enabled ? t("on") : t("off")}</span>
                      </label>
                    </td>
                    <td><Time value={rule.updated_at} /></td>
                    {canWrite && (
                      <td>
                        <Actions>
                          <button className="secondary" onClick={() => setEditing(rule)}>{t("Edit")}</button>
                          <button
                            className="secondary"
                            disabled={removeRule.isPending}
                            onClick={() => askToDeleteRule(rule)}
                          >
                            {t("Delete")}
                          </button>
                        </Actions>
                      </td>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Card>

        <Card
          className="span-7"
          title={t("Recent alerts")}
          description={t("The last fifty, newest first: what fired, when, and whether it has resolved.")}
          actions={
            <>
              <select value={historyState} onChange={(e) => setHistoryState(e.target.value as AlertState | "")}>
                <option value="">{t("every state")}</option>
                <option value="firing">{t("firing")}</option>
                <option value="pending">{t("pending")}</option>
                <option value="resolved">{t("resolved")}</option>
              </select>
              <select value={historyTaken} onChange={(e) => setHistoryTaken(e.target.value as FiringFilter)}>
                <option value="">{t("taken or not")}</option>
                <option value="waiting">{t("not acknowledged")}</option>
                <option value="acknowledged">{t("acknowledged")}</option>
              </select>
              <ExportButton path="/api/v1/monitoring/alerts" params={historyParams} />
            </>
          }
          flush
        >
          {history.error ? (
            <ErrorBox error={history.error} />
          ) : !history.data ? (
            <Empty>{t("Loading…")}</Empty>
          ) : history.data.items.length === 0 ? (
            <Empty>{t("No alerts recorded in this state.")}</Empty>
          ) : (
            <table>
              <thead>
                <tr><th>{t("Host")}</th><th>{t("Rule")}</th><th>{t("Severity")}</th><th>{t("State")}</th><th className="num">{t("Value")}</th><th>{t("Started")}</th><th>{t("Resolved")}</th><th>{t("Note")}</th></tr>
              </thead>
              <tbody>
                {history.data.items.map((alert) => (
                  <tr key={alert.id}>
                    <td><Link to={`/hosts/${alert.host_id}/monitoring`}>{alert.hostname || alert.host_id.slice(0, 8)}</Link></td>
                    <td>{alert.rule_name}</td>
                    <td><SeverityBadge severity={alert.severity} /></td>
                    <td><AlertStateBadge state={alert.state} silenced={alert.silenced} /> <AcknowledgedChip alert={alert} /></td>
                    <td className="num">{metricValue(alert.metric, alert.value)}</td>
                    <td><Time value={alert.started_at} /></td>
                    <td>{alert.resolved_at ? <Time value={alert.resolved_at} /> : <span className="source">—</span>}</td>
                    <td className="source">{alert.note || "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Card>

        <Card
          className="span-5"
          title={t("Silences in force")}
          description={t("Every silence ends by itself; ending one here brings the alert back at once.")}
          flush
        >
          {silences.error ? (
            <ErrorBox error={silences.error} />
          ) : !silences.data ? (
            <Empty>{t("Loading…")}</Empty>
          ) : silenceItems.length === 0 ? (
            <Empty>{t("No silence is in force.")}</Empty>
          ) : (
            <table>
              <thead>
                <tr><th>{t("Host")}</th><th>{t("Rule")}</th><th>{t("Until")}</th><th>{t("Reason")}</th><th></th></tr>
              </thead>
              <tbody>
                {silenceItems.map((silence) => (
                  <tr key={silence.id}>
                    <td><Link to={`/hosts/${silence.host_id}/monitoring`}>{silence.hostname || silence.host_id.slice(0, 8)}</Link></td>
                    <td>{silence.rule_name || <span className="source">{t("every rule")}</span>}</td>
                    <td><Time value={silence.until} /></td>
                    <td>
                      <div className="fp-host-cell">
                        <span>{silence.reason}</span>
                        <span className="source">{silence.created_by}</span>
                      </div>
                    </td>
                    <td>
                      <button className="secondary" disabled={endSilence.isPending} onClick={() => endSilence.mutate(silence)}>
                        {t("End now")}
                      </button>
                    </td>
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
 * What the agents cost the hosts they run on: the release gate of the
 * agent asks for its memory and CPU on a real fleet, and this is where the
 * fleet answers. The median says what an agent costs, the maximum where
 * one is out of line, and the list names the hosts over the budget so a
 * leak is a host to look at rather than a number to wonder about. A fleet
 * where no agent reports its footprint yet shows dashes, not zeros.
 */
function AgentFootprintCard({ footprint, loaded }: { footprint?: FleetFootprint; loaded: boolean }) {
  const t = useT();
  const measured = footprint?.hosts_measured ?? 0;
  const over = footprint?.over_budget ?? [];
  const size = (value?: number) => (value === undefined ? "—" : bytes(value));
  const share = (value?: number) => (value === undefined ? "—" : `${Math.round(value * 10) / 10}%`);
  const budget = footprint
    ? t("budget {rss} and {cpu}% of one core", { rss: bytes(footprint.rss_budget_bytes), cpu: footprint.cpu_budget_percent })
    : undefined;
  const overRSS = footprint?.rss_bytes_max !== undefined && footprint.rss_bytes_max > footprint.rss_budget_bytes;
  const overCPU = footprint?.cpu_percent_max !== undefined && footprint.cpu_percent_max > footprint.cpu_budget_percent;
  return (
    <Card
      className="span-12"
      title={t("Agent footprint")}
      description={t("Memory and CPU of the agent itself, from the newest sample of every reporting host; the hosts over the budget are named.")}
      actions={budget && <span className="source">{budget}</span>}
    >
      <StatGrid compact>
        <Stat label={t("Hosts measured")} value={footprint ? measured : "—"} hint={t("reporting hosts whose agent sends its footprint")} />
        <Stat label={t("Median RSS")} value={size(footprint?.rss_bytes_median)} hint={t("what an agent costs")} />
        <Stat label={t("Max RSS")} value={size(footprint?.rss_bytes_max)} tone={overRSS ? "warn" : undefined} hint={t("the heaviest agent")} />
        <Stat label={t("Median CPU")} value={share(footprint?.cpu_percent_median)} hint={t("of one core, last minute")} />
        <Stat label={t("Max CPU")} value={share(footprint?.cpu_percent_max)} tone={overCPU ? "warn" : undefined} hint={t("the busiest agent")} />
        <Stat label={t("Helper RSS, max")} value={size(footprint?.helper_rss_bytes_max)} hint={t("only while a helper is running")} />
      </StatGrid>
      {!loaded ? (
        <Empty>{t("Loading…")}</Empty>
      ) : !footprint || measured === 0 ? (
        <Empty>{t("No agent has sent its footprint yet; an older agent does not.")}</Empty>
      ) : over.length === 0 ? (
        <Empty>{t("Every measured agent is within the budget.")}</Empty>
      ) : (
        <table>
          <thead>
            <tr><th>{t("Host")}</th><th className="num">{t("Agent RSS")}</th><th className="num">{t("Agent CPU")}</th></tr>
          </thead>
          <tbody>
            {over.map((host) => (
              <tr key={host.host_id}>
                <td><Link to={`/hosts/${host.host_id}/monitoring`}>{host.hostname || host.host_id.slice(0, 8)}</Link></td>
                <td className="num">{host.agent_rss_bytes === undefined ? <span className="source">—</span> : bytes(host.agent_rss_bytes)}</td>
                <td className="num">{host.agent_cpu_percent === undefined ? <span className="source">—</span> : share(host.agent_cpu_percent)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </Card>
  );
}

/**
 * The firing alerts with a silence at each row. The reason is asked for
 * in the row itself: the operator silences what they are looking at, and
 * the audit trail gets a sentence about why.
 */
function FiringTable({ alerts, canAcknowledge, onChanged, onMessage }: {
  alerts: NotedAlert[]; canAcknowledge: boolean; onChanged: () => void; onMessage: (text: string) => void;
}) {
  const t = useT();
  const confirm = useConfirm();
  const toast = useToast();
  const [silencing, setSilencing] = useState<string | null>(null);
  const [reason, setReason] = useState("");
  const [minutes, setMinutes] = useState("60");

  // The acknowledgement and the note go through the dialog: the note is
  // the reason of the acknowledgement, and the trail keeps it.
  const acknowledge = useMutation({
    mutationFn: ({ alert, note }: { alert: NotedAlert; note: string }) =>
      api.post<NotedAlert>(`/api/v1/monitoring/alerts/${alert.id}/acknowledge`, { note }),
    onSuccess: (taken) => {
      const text = t("{host}: {rule} is acknowledged; it keeps firing until the host says otherwise.", { host: taken.hostname, rule: taken.rule_name });
      onMessage(text);
      toast.success(text);
      onChanged();
    },
    onError: (error) => {
      onMessage(errorText(error));
      toast.error(errorText(error));
    },
  });
  const annotate = useMutation({
    mutationFn: ({ alert, note }: { alert: NotedAlert; note: string }) =>
      api.post<NotedAlert>(`/api/v1/monitoring/alerts/${alert.id}/annotate`, { note }),
    onSuccess: (noted) => {
      onMessage(noted.note ? t("The note on {rule} at {host} is saved.", { rule: noted.rule_name, host: noted.hostname }) : t("The note on {rule} at {host} is removed.", { rule: noted.rule_name, host: noted.hostname }));
      onChanged();
    },
    onError: (error) => onMessage(errorText(error)),
  });
  const askToAcknowledge = async (alert: NotedAlert) => {
    const answer = await confirm({
      title: t("Acknowledge {rule} on {host}", { rule: alert.rule_name, host: alert.hostname }),
      body: <p>{t("The alert keeps firing - only the host ends it - but it leaves the counts of what waits for a person, under your name. Write what is being done about it.")}</p>,
      confirmLabel: t("Acknowledge"),
      reason: { required: true, label: t("Note (at least 8 characters)"), placeholder: t("what is being done about it") },
    });
    if (answer.ok && answer.reason) acknowledge.mutate({ alert, note: answer.reason });
  };
  const askToAnnotate = async (alert: NotedAlert) => {
    const answer = await confirm({
      title: t("Note on {rule} at {host}", { rule: alert.rule_name, host: alert.hostname }),
      body: <p>{t("The note stays with the alert in its history; an empty one removes it.")}</p>,
      confirmLabel: t("Save the note"),
      input: { label: t("Note"), initial: alert.note ?? "", placeholder: t("where the cause was found, which change is on its way") },
    });
    if (answer.ok) annotate.mutate({ alert, note: answer.value ?? "" });
  };

  const silence = useMutation({
    mutationFn: (alert: Alert) =>
      api.post<Silence>(`/api/v1/hosts/${alert.host_id}/monitoring/silences`, {
        reason: reason.trim(),
        minutes: Number(minutes) || 60,
        rule_id: alert.rule_id,
      }),
    onSuccess: (created) => {
      onMessage(t("{host}: {rule} is silenced until {until}.", { host: created.hostname, rule: created.rule_name ?? t("every rule"), until: new Date(created.until).toLocaleString() }));
      setSilencing(null);
      setReason("");
      onChanged();
    },
    onError: (error) => onMessage(errorText(error)),
  });

  const ready = reason.trim().length >= 8 && Number(minutes) > 0 && Number(minutes) <= 1440;

  return (
    <table>
      <thead>
        <tr>
          <th>{t("Host")}</th><th>{t("Rule")}</th><th>{t("Severity")}</th><th className="num">{t("Value")}</th>
          <th>{t("Detail")}</th><th>{t("Since")}</th><th>{t("Silenced")}</th><th>{t("Taken")}</th><th></th>
        </tr>
      </thead>
      <tbody>
        {alerts.map((alert) => (
          <FiringRow
            key={alert.id}
            alert={alert}
            open={silencing === alert.id}
            onOpen={() => setSilencing(silencing === alert.id ? null : alert.id)}
            canAcknowledge={canAcknowledge}
            busy={acknowledge.isPending || annotate.isPending}
            onAcknowledge={() => askToAcknowledge(alert)}
            onAnnotate={() => askToAnnotate(alert)}
          >
            <Toolbar end={
              <>
                <button disabled={!ready || silence.isPending} onClick={() => silence.mutate(alert)}>
                  {silence.isPending ? t("Silencing…") : t("Silence {rule} on {host}", { rule: alert.rule_name, host: alert.hostname })}
                </button>
                <button className="secondary" onClick={() => setSilencing(null)}>{t("Cancel")}</button>
              </>
            }>
              <input
                placeholder={t("Reason (at least 8 characters)")}
                value={reason}
                onChange={(e) => setReason(e.target.value)}
                style={{ minWidth: 280 }}
              />
              <input
                type="number"
                min={1}
                max={1440}
                value={minutes}
                onChange={(e) => setMinutes(e.target.value)}
                title={t("Minutes, at most 1440")}
                style={{ width: 90 }}
              />
              <span>{t("minutes")}</span>
            </Toolbar>
          </FiringRow>
        ))}
      </tbody>
    </table>
  );
}

function FiringRow({ alert, open, onOpen, canAcknowledge, busy, onAcknowledge, onAnnotate, children }: {
  alert: NotedAlert; open: boolean; onOpen: () => void; canAcknowledge: boolean; busy: boolean;
  onAcknowledge: () => void; onAnnotate: () => void; children: ReactNode;
}) {
  const t = useT();
  return (
    <>
      <tr>
        <td><Link to={`/hosts/${alert.host_id}/monitoring`}>{alert.hostname || alert.host_id.slice(0, 8)}</Link></td>
        <td>
          <div className="fp-host-cell">
            <span>{alert.rule_name}</span>
            <span className="source hm-mono">{alert.metric}</span>
          </div>
        </td>
        <td><SeverityBadge severity={alert.severity} /></td>
        <td className="num">{metricValue(alert.metric, alert.value)}</td>
        <td className="source">
          {alert.detail}
          {alert.note && <div className="source">{t("note:")} {alert.note}</div>}
        </td>
        <td><Time value={alert.fired_at || alert.started_at} /></td>
        <td>{alert.silenced ? <span className="badge">{t("silenced")}</span> : <span className="source">{t("no")}</span>}</td>
        <td>
          {alert.acknowledged_at ? (
            <div className="fp-host-cell">
              <AcknowledgedChip alert={alert} />
              <span className="source">{alert.acknowledged_by} · <Time value={alert.acknowledged_at} /></span>
            </div>
          ) : <span className="source">{t("no")}</span>}
        </td>
        <td>
          <Actions>
            <button className="secondary" onClick={onOpen} disabled={alert.silenced}>{open ? t("Close") : t("Silence")}</button>
            {canAcknowledge && (
              <>
                <button className="secondary" onClick={onAcknowledge} disabled={busy}>
                  {alert.acknowledged_at ? t("Take over") : t("Acknowledge")}
                </button>
                <button className="secondary" onClick={onAnnotate} disabled={busy}>{t("Note")}</button>
              </>
            )}
          </Actions>
        </td>
      </tr>
      {open && (
        <tr>
          <td colSpan={9}>{children}</td>
        </tr>
      )}
    </>
  );
}

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
  };
}

/**
 * The form of a rule, new or edited. The metric, the operator and the
 * severity are chosen from what the server accepts, so a typo cannot make
 * a rule that never fires. The scope is by site, environment, system
 * family, tags, groups, owner and an expression for the rest; a rule with
 * none of them watches the whole fleet. The expression is checked as it
 * is typed, with the same grammar the server reads, so a scope the server
 * would refuse is said so under the field rather than after the save.
 */
function RuleForm({ rule, catalogue, onDone }: { rule?: AlertRule; catalogue?: RuleCatalogue; onDone: (message?: string) => void }) {
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
  const scope = rule?.selector as RuleScope | undefined;
  const [site, setSite] = useState(scope?.site ?? "");
  const [environment, setEnvironment] = useState(scope?.environment ?? "");
  const [osFamily, setOsFamily] = useState(scope?.os_family ?? "");
  const [tags, setTags] = useState(scope?.tags?.join(" ") ?? "");
  const [groups, setGroups] = useState(scope?.groups?.join(", ") ?? "");
  const [owner, setOwner] = useState(scope?.owner ?? "");
  const [expression, setExpression] = useState(scope?.expression ?? "");
  const [enabled, setEnabled] = useState(rule?.enabled ?? true);
  const [errorMessage, setErrorMessage] = useState("");

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
    onError: (error) => setErrorMessage(errorText(error)),
  });

  const thresholdNumber = Number(threshold);
  const ready = name.trim() !== "" && metric !== "" && threshold.trim() !== "" && Number.isFinite(thresholdNumber)
    && Number.isInteger(Number(forMinutes)) && Number(forMinutes) >= 0
    && (expressionCheck === undefined || expressionCheck.ok);

  return (
    <Card
      title={rule ? t("Edit rule {name}", { name: rule.name }) : t("New rule")}
      description={t("The condition must hold for the whole of “for” before the alert fires; zero fires on the first sample past the threshold.")}
    >
      <FieldGrid>
        <Field label={t("Name")}>
          <input value={name} onChange={(e) => setName(e.target.value)} placeholder={t("e.g. root filesystem nearly full")} />
        </Field>
        <Field label={t("Metric")} hint={metricLabel(metric)}>
          <select value={metric} onChange={(e) => setMetric(e.target.value)}>
            {metrics.map((item) => <option key={item} value={item}>{item}</option>)}
          </select>
        </Field>
        <Field label={t("Operator")}>
          <select value={operator} onChange={(e) => setOperator(e.target.value as RuleOperator)}>
            {operators.map((item) => <option key={item} value={item}>{OPERATOR_SIGNS[item] ?? item} ({item})</option>)}
          </select>
        </Field>
        <Field label={t("Threshold")} hint={threshold.trim() !== "" && Number.isFinite(thresholdNumber) ? describeCondition({ metric, operator, threshold: thresholdNumber }) : undefined}>
          <input type="number" step="any" value={threshold} onChange={(e) => setThreshold(e.target.value)} />
        </Field>
        <Field label={t("For (minutes)")}>
          <input type="number" min={0} step={1} value={forMinutes} onChange={(e) => setForMinutes(e.target.value)} />
        </Field>
        <Field label={t("Severity")}>
          <select value={severity} onChange={(e) => setSeverity(e.target.value as AlertSeverity)}>
            {severities.map((item) => <option key={item} value={item}>{item}</option>)}
          </select>
        </Field>
        <Field label={t("Site")} hint={t("Empty: every site.")}>
          <input value={site} onChange={(e) => setSite(e.target.value)} />
        </Field>
        <Field label={t("Environment")} hint={t("Empty: every environment.")}>
          <input value={environment} onChange={(e) => setEnvironment(e.target.value)} />
        </Field>
        <Field label={t("System family")} hint={t("Empty: every family (debian, rhel, arch…).")}>
          <input value={osFamily} onChange={(e) => setOsFamily(e.target.value)} />
        </Field>
        <Field label={t("Tags")} hint={t("Every listed tag has to be on the host; key or key=value, separated by spaces.")}>
          <input value={tags} onChange={(e) => setTags(e.target.value)} placeholder="role=db tier=gold" />
        </Field>
        <Field label={t("Groups")} hint={t("The host has to be in one of the listed groups; names separated by commas.")}>
          <input value={groups} onChange={(e) => setGroups(e.target.value)} placeholder="databases, caches" />
        </Field>
        <Field label={t("Owner")} hint={t("Empty: every owner.")}>
          <input value={owner} onChange={(e) => setOwner(e.target.value)} />
        </Field>
        {/* The expression takes what the fields cannot say - a version
            comparison, a health fact, an alternative - in the text form a
            campaign selector has. The list under the field offers what may
            come next; the hint shows the error where the text stops
            parsing, in the server's words. */}
        <Field
          label={t("Expression")}
          wide
          hint={expressionCheck && !expressionCheck.ok
            ? <span className="page-error">{expressionCheck.error}</span>
            : t("Selector text for what the fields cannot say, e.g. agent_version < 0.49.0 or reboot_required = true; and, or, not and parentheses combine conditions.")}
        >
          <input
            className="mono"
            value={expression}
            onChange={(e) => setExpression(e.target.value)}
            list="alert-rule-expression-words"
            spellCheck={false}
            placeholder="security_updates = true and connection = online"
          />
          <datalist id="alert-rule-expression-words">
            {suggestions.map((word) => (
              <option key={word} value={`${expression.replace(/[A-Za-z0-9_=!<>]*$/, "")}${word} `} />
            ))}
          </datalist>
        </Field>
        <label className="toggle">
          <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />
          <span>{t("Enabled")}</span>
        </label>
      </FieldGrid>
      <Actions>
        <button onClick={() => save.mutate()} disabled={!ready || save.isPending}>
          {save.isPending ? t("Saving…") : rule ? t("Save rule") : t("Create rule")}
        </button>
        <button className="secondary" onClick={() => onDone()} disabled={save.isPending}>{t("Cancel")}</button>
        {errorMessage && <p className="page-error">{errorMessage}</p>}
      </Actions>
    </Card>
  );
}
