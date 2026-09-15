import { useMemo, useState, type ReactNode } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api } from "../lib/api";
import type { Whoami } from "../lib/types";
import { absoluteTime, toInstant } from "../lib/format";
import { toLocalInput } from "./Audit";
import { ErrorBox, Empty, OptionalFlag, OptionalNumber } from "../components/ui";
import { Card, PageHeader, Toolbar } from "../components/layout";
import { ExportButton } from "../components/ExportButton";
import { Breakdown, StatusBar, type WidgetTone } from "../components/widgets";
import { FacetList, useFleetFacets } from "./Bulk";
import { useT } from "../i18n";

/**
 * The management reports: the patch status of the fleet, the campaigns
 * of a period and the compliance with the policies.
 *
 * A report is the same records the other screens show, read over one
 * period and narrowed to a part of the fleet, laid out to be handed on:
 * printed as a document with a head that says what it is a report of, or
 * exported as a file a spreadsheet opens. The page computes nothing of
 * its own - every number comes from the server, the way the screens it
 * summarises get theirs - so a report never disagrees with the list it
 * stands for.
 */

/** The periods offered with one click, and the one typed by hand. */
export type Preset = "7d" | "30d" | "this_month" | "previous_month" | "custom";

export const PRESETS: { key: Preset; label: string }[] = [
  { key: "7d", label: "Last 7 days" },
  { key: "30d", label: "Last 30 days" },
  { key: "this_month", label: "This month" },
  { key: "previous_month", label: "Previous month" },
  { key: "custom", label: "Custom" },
];

/**
 * The bounds of a preset as instants: the last days end now; a month
 * runs from its first midnight to the next one in the browser's clock,
 * because "September" is the operator's September, not the server's.
 * The custom preset keeps what the operator typed.
 */
export function presetRange(preset: Preset, now: Date, custom: { from: string; to: string }): { from: string; to: string } {
  const monthStart = (shift: number) => new Date(now.getFullYear(), now.getMonth() + shift, 1);
  switch (preset) {
    case "7d":
      return { from: new Date(now.getTime() - 7 * 24 * 3600 * 1000).toISOString(), to: now.toISOString() };
    case "30d":
      return { from: new Date(now.getTime() - 30 * 24 * 3600 * 1000).toISOString(), to: now.toISOString() };
    case "this_month":
      return { from: monthStart(0).toISOString(), to: monthStart(1).toISOString() };
    case "previous_month":
      return { from: monthStart(-1).toISOString(), to: monthStart(0).toISOString() };
    default:
      return { from: toInstant(custom.from), to: toInstant(custom.to) };
  }
}

/** The filter of the page: the period and the part of the fleet. */
export type ReportFilters = {
  from: string;
  to: string;
  site: string;
  environment: string;
};

/**
 * The query every report and every export is asked with: the bounds
 * and the filter, and nothing when a bound is missing - a half period
 * is refused by the server, and the page does not ask until both ends
 * are set.
 */
export function reportParams(filters: ReportFilters): URLSearchParams {
  const params = new URLSearchParams();
  if (filters.from && filters.to) {
    params.set("from", filters.from);
    params.set("to", filters.to);
  }
  if (filters.site.trim()) params.set("site", filters.site.trim());
  if (filters.environment.trim()) params.set("environment", filters.environment.trim());
  return params;
}

/** A rate as a percentage with one decimal; a dash for no rate. */
export function percent(rate?: number | null): string {
  if (rate === null || rate === undefined) return "—";
  return `${(rate * 100).toFixed(1)}%`;
}

/** A duration in the largest units that read at a glance: 2d 03h, 1h 05m, 45s. */
export function duration(seconds?: number | null): string {
  if (seconds === null || seconds === undefined) return "—";
  const pad = (number: number) => String(number).padStart(2, "0");
  if (seconds >= 86400) return `${Math.floor(seconds / 86400)}d ${pad(Math.floor((seconds % 86400) / 3600))}h`;
  if (seconds >= 3600) return `${Math.floor(seconds / 3600)}h ${pad(Math.floor((seconds % 3600) / 60))}m`;
  if (seconds >= 60) return `${Math.floor(seconds / 60)}m ${pad(seconds % 60)}s`;
  return `${seconds}s`;
}

/** The tone of a campaign's terminal state on the report. */
export function campaignStateTone(state: string): WidgetTone {
  switch (state) {
    case "completed":
      return "ok";
    case "completed_with_issues":
      return "warn";
    case "failed":
    case "plan_failed":
      return "error";
    case "canceled":
    case "expired":
      return "neutral";
    default:
      return "unknown";
  }
}

/* The documents, as the server writes them. */

type Envelope = {
  report: string;
  from: string;
  to: string;
  site?: string;
  environment?: string;
  generated_at: string;
  generated_by: string;
};

type PatchCounts = {
  hosts: number;
  fully_patched: number;
  security_unknown: number;
  patched_in_period: number;
  reboot_backlog: number;
  reboot_unknown: number;
  pending_updates: number;
  pending_security_updates: number;
};

type PatchHost = {
  host_id: string;
  hostname: string;
  site: string;
  environment: string;
  lifecycle_state: string;
  connection_state: string;
  agent_version?: string;
  last_seen_at?: string;
  pending_updates: number | null;
  pending_security_updates: number | null;
  reboot_required: boolean | null;
  last_upgrade_at?: string;
  campaigns?: number;
};

type PatchStatus = Envelope & {
  totals: PatchCounts;
  by_site: ({ key: string } & PatchCounts)[];
  by_environment: ({ key: string } & PatchCounts)[];
  hosts: PatchHost[];
  hosts_listed: number;
  hosts_truncated: boolean;
  campaigns_read: boolean;
};

type Outcome = {
  targets: number;
  succeeded: number;
  no_change: number;
  failed: number;
  unknown: number;
  skipped: number;
  canceled: number;
};

type CampaignRow = Outcome & {
  id: string;
  name: string;
  operation: string;
  state: string;
  requester: string;
  approver?: string;
  created_at: string;
  started_at?: string;
  finished_at: string;
  duration_seconds: number | null;
  success_rate: number | null;
  by_site: ({ key: string } & Outcome)[];
};

type CampaignsReport = Envelope & {
  campaigns: CampaignRow[];
  totals: Outcome & { campaigns: number; by_state: Record<string, number>; success_rate: number | null };
  by_site: ({ key: string } & Outcome)[];
};

type PolicyRow = {
  id: string;
  name: string;
  version: number;
  enabled: boolean;
  remediation_mode: string;
  last_evaluated_at?: string;
  hosts: number;
  compliant: number;
  drift: number;
  error: number;
  not_applicable: number;
  unknown: number;
  rules: Record<string, number>;
  drift_hosts: { host_id: string; hostname: string; site: string }[];
};

type DriftHost = { host_id: string; hostname: string; site: string; environment: string; policies: number; rules: number };

type SecurityCounts = { failed: number; passed: number; unknown: number; not_applicable: number };

type ComplianceReport = Envelope & {
  policies: {
    policies: PolicyRow[];
    drift_hosts: DriftHost[];
    totals: { policies: number; compliant: number; drift: number; error: number; not_applicable: number; unknown: number; hosts_in_drift: number };
  } | null;
  security: {
    hosts: number;
    hosts_with_findings: number;
    by_severity: ({ severity: string; checks: number } & SecurityCounts)[];
    checks: ({ check_id: string; title: string; severity: string } & SecurityCounts)[];
    evaluated_at: string;
  } | null;
};

/** The states of a closed campaign in the order the summary shows them,
 *  with the words the page uses for them. */
const CAMPAIGN_STATES: { state: string; label: string }[] = [
  { state: "completed", label: "completed" },
  { state: "completed_with_issues", label: "completed with issues" },
  { state: "failed", label: "failed" },
  { state: "plan_failed", label: "plan failed" },
  { state: "expired", label: "expired" },
  { state: "canceled", label: "canceled" },
];

/** The word for a state, the state itself for one the list does not know. */
export function campaignStateLabel(state: string): string {
  return CAMPAIGN_STATES.find((entry) => entry.state === state)?.label ?? state;
}

/* The page prints as a document: the shell around it - the navigation,
   the top bar, the toolbar and the buttons - is not part of the report,
   and the head that says what the document is appears only on paper. */
const PRINT_STYLES = `
.report-print-head { display: none; }
@media print {
  .layout { display: block; }
  .sidebar, .sidebar-backdrop, .topbar, .no-print { display: none !important; }
  .content { padding: 0; overflow: visible; }
  .page { max-width: none; }
  .report-print-head { display: block; margin: 0 0 16px; padding: 0 0 12px; border-bottom: 2px solid #000; }
  .report-print-head h1 { margin: 0 0 4px; font-size: 20px; }
  .report-print-head dl { display: grid; grid-template-columns: max-content 1fr; gap: 2px 12px; margin: 0; font-size: 12px; }
  .report-print-head dt { font-weight: 600; }
  .report-print-head dd { margin: 0; }
  .widgets { display: block; }
  .widgets > .card { margin: 0 0 16px; box-shadow: none; border: 1px solid #999; break-inside: avoid; }
  .card-actions { display: none; }
  table { font-size: 11px; }
  a { color: inherit; text-decoration: none; }
}`;

export function Reports() {
  const t = useT();
  const [params, setParams] = useSearchParams();
  const [preset, setPreset] = useState<Preset>((PRESETS.find((p) => p.key === params.get("preset"))?.key) ?? "30d");
  const [custom, setCustom] = useState({ from: toLocalInput(params.get("from")), to: toLocalInput(params.get("to")) });
  const [site, setSite] = useState(params.get("site") ?? "");
  const [environment, setEnvironment] = useState(params.get("environment") ?? "");
  const facets = useFleetFacets();
  const whoami = useQuery({
    queryKey: ["whoami"],
    queryFn: () => api.get<Whoami>("/api/v1/whoami"),
    staleTime: 5 * 60 * 1000,
  });
  const permissions = new Set(whoami.data?.permissions ?? []);

  // The bounds are fixed when the choice is made, not on every render:
  // "the last 30 days" is the thirty days before the click, and the
  // three reports of one page are asked with the same instant.
  const range = useMemo(() => presetRange(preset, new Date(), custom), [preset, custom]);
  const filters: ReportFilters = { from: range.from, to: range.to, site, environment };
  const query = reportParams(filters);
  const ready = query.has("from");

  const change = (next: { preset?: Preset; custom?: { from: string; to: string }; site?: string; environment?: string }) => {
    const merged = { preset, custom, site, environment, ...next };
    setPreset(merged.preset);
    setCustom(merged.custom);
    setSite(merged.site);
    setEnvironment(merged.environment);
    // The address keeps the choice, so a link to "last month in warsaw"
    // opens on last month in warsaw.
    const address = new URLSearchParams();
    address.set("preset", merged.preset);
    if (merged.preset === "custom") {
      if (merged.custom.from) address.set("from", toInstant(merged.custom.from));
      if (merged.custom.to) address.set("to", toInstant(merged.custom.to));
    }
    if (merged.site) address.set("site", merged.site);
    if (merged.environment) address.set("environment", merged.environment);
    setParams(address, { replace: true });
  };

  const key = query.toString();
  const patch = useQuery({
    queryKey: ["reports", "patch-status", key],
    queryFn: () => api.get<PatchStatus>(`/api/v1/reports/patch-status?${key}`),
    enabled: ready,
    retry: false,
  });
  const seesCampaigns = permissions.has("campaign.read");
  const campaigns = useQuery({
    queryKey: ["reports", "campaigns", key],
    queryFn: () => api.get<CampaignsReport>(`/api/v1/reports/campaigns?${key}`),
    enabled: ready && seesCampaigns,
    retry: false,
  });
  const compliance = useQuery({
    queryKey: ["reports", "compliance", key],
    queryFn: () => api.get<ComplianceReport>(`/api/v1/reports/compliance?${key}`),
    enabled: ready,
    retry: false,
  });

  const scope = [site.trim() && t("site {site}", { site: site.trim() }), environment.trim() && t("environment {environment}", { environment: environment.trim() })]
    .filter(Boolean).join(", ") || t("the whole visible fleet");
  const generatedAt = patch.data?.generated_at ?? campaigns.data?.generated_at ?? compliance.data?.generated_at;
  const author = whoami.data?.display_name || whoami.data?.subject || "";

  return (
    <>
      <style>{PRINT_STYLES}</style>
      <PageHeader
        icon="audit"
        title={t("Reports")}
        description={t("The patch status, the campaigns and the compliance of the fleet over a period, as a document to print or a file to open in a spreadsheet. Every number is the server's, the same one the screens show.")}
        actions={
          <button type="button" className="secondary no-print" onClick={() => window.print()} disabled={!ready}>
            {t("Print")}
          </button>
        }
      />

      {/* The head of the printed document: what it is a report of, and
          who made it when. On the screen the toolbar says the same. */}
      <div className="report-print-head">
        <h1>{t("Flotestro fleet report")}</h1>
        <dl>
          <dt>{t("Fleet")}</dt><dd>{window.location.host}</dd>
          <dt>{t("Scope")}</dt><dd>{scope}</dd>
          <dt>{t("Period")}</dt><dd>{absoluteTime(range.from)} – {absoluteTime(range.to)}</dd>
          <dt>{t("Generated")}</dt><dd>{generatedAt ? absoluteTime(generatedAt) : "—"}</dd>
          <dt>{t("Generated by")}</dt><dd>{author}</dd>
        </dl>
      </div>

      <Card className="no-print">
        <Toolbar>
          <div className="segmented" role="group" aria-label={t("Period")}>
            {PRESETS.map((option) => (
              <button
                key={option.key}
                type="button"
                className={preset === option.key ? "active" : ""}
                onClick={() => change({ preset: option.key })}
              >
                {t(option.label)}
              </button>
            ))}
          </div>
          {preset === "custom" && (
            <>
              <label className="toggle">
                {t("Since")}{" "}
                <input type="datetime-local" value={custom.from} onChange={(e) => change({ custom: { ...custom, from: e.target.value } })} />
              </label>
              <label className="toggle">
                {t("Until")}{" "}
                <input type="datetime-local" value={custom.to} onChange={(e) => change({ custom: { ...custom, to: e.target.value } })} />
              </label>
            </>
          )}
          <input placeholder={t("site: any")} value={site} list="report-sites" onChange={(e) => change({ site: e.target.value })} />
          <FacetList id="report-sites" facets={facets.data?.by_site} />
          <input placeholder={t("environment: any")} value={environment} list="report-environments" onChange={(e) => change({ environment: e.target.value })} />
          <FacetList id="report-environments" facets={facets.data?.by_environment} />
        </Toolbar>
        <p className="fp-note">
          {ready
            ? t("{scope}, {from} – {to}.", { scope, from: absoluteTime(range.from), to: absoluteTime(range.to) })
            : t("Set both ends of the period to read the reports.")}
        </p>
      </Card>

      <div className="widgets">
        <PatchStatusCard report={patch.data} error={patch.error} ready={ready} params={query} />
        {seesCampaigns && <CampaignsCard report={campaigns.data} error={campaigns.error} ready={ready} params={query} />}
        <ComplianceCard report={compliance.data} error={compliance.error} ready={ready} params={query} />
      </div>
    </>
  );
}

/** What a report card shows while its document is not there yet. */
function Pending({ ready, error, children }: { ready: boolean; error: unknown; children?: ReactNode }) {
  const t = useT();
  if (error) return <ErrorBox error={error} />;
  if (!ready) return <Empty>{t("Waiting for the period.")}</Empty>;
  return <>{children ?? <Empty>{t("Reading the report…")}</Empty>}</>;
}

function PatchStatusCard({ report, error, ready, params }: { report?: PatchStatus; error: unknown; ready: boolean; params: URLSearchParams }) {
  const t = useT();
  const totals = report?.totals;
  const pendingSecurity = totals ? totals.hosts - totals.fully_patched - totals.security_unknown : undefined;
  return (
    <Card
      className="span-12"
      title={t("Patch status")}
      description={t("The pending updates as the hosts last reported them, and the upgrades and campaigns of the period.")}
      actions={<ExportButton path="/api/v1/reports/patch-status" params={params} disabled={!ready} />}
    >
      <Pending ready={ready} error={error}>
        {report && totals && (
          <>
            <StatusBar segments={[
              { label: t("Fully patched"), value: totals.fully_patched, tone: "ok" },
              { label: t("Security updates pending"), value: pendingSecurity, tone: pendingSecurity ? "warn" : "ok" },
              { label: t("Not reported"), value: totals.security_unknown, tone: "unknown" },
              { label: t("Patched in period"), value: totals.patched_in_period, tone: "info" },
              { label: t("Reboot backlog"), value: totals.reboot_backlog, tone: totals.reboot_backlog ? "warn" : "ok" },
              { label: t("Reboot not reported"), value: totals.reboot_unknown, tone: "unknown" },
            ]} />
            <p className="fp-note">
              {t("{hosts} hosts · {updates} pending updates of which {security} security · a host that reported nothing is counted apart, never as patched.", {
                hosts: totals.hosts, updates: totals.pending_updates, security: totals.pending_security_updates,
              })}
            </p>
            <div className="columns">
              <GroupBreakdown title={t("Security updates pending, by site")} groups={report.by_site} />
              <GroupBreakdown title={t("Security updates pending, by environment")} groups={report.by_environment} />
            </div>
            {report.hosts.length === 0 ? (
              <Empty>{t("No host in this part of the fleet.")}</Empty>
            ) : (
              <table data-testid="patch-hosts">
                <thead>
                  <tr>
                    <th>{t("Host")}</th><th>{t("Site")}</th><th>{t("Environment")}</th>
                    <th className="num">{t("Pending")}</th><th className="num">{t("Security")}</th><th>{t("Reboot")}</th>
                    <th>{t("Last upgrade")}</th>
                    {report.campaigns_read && <th className="num">{t("Campaigns")}</th>}
                    <th>{t("Agent")}</th><th>{t("Last seen")}</th>
                  </tr>
                </thead>
                <tbody>
                  {report.hosts.map((host) => (
                    <tr key={host.host_id}>
                      <td><Link to={`/hosts/${host.host_id}`}>{host.hostname}</Link></td>
                      <td>{host.site}</td>
                      <td>{host.environment}</td>
                      <td className="num"><OptionalNumber value={host.pending_updates} /></td>
                      <td className="num"><OptionalNumber value={host.pending_security_updates} /></td>
                      <td><OptionalFlag value={host.reboot_required} /></td>
                      <td>{host.last_upgrade_at ? absoluteTime(host.last_upgrade_at) : <span className="badge unknown">{t("none in period")}</span>}</td>
                      {report.campaigns_read && <td className="num">{host.campaigns ?? "—"}</td>}
                      <td>{host.agent_version || "—"}</td>
                      <td>{host.last_seen_at ? absoluteTime(host.last_seen_at) : "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
            {report.hosts_truncated && (
              <p className="fp-note">
                {t("The table shows the first {listed} of {total} hosts; the file carries them all.", { listed: report.hosts_listed, total: totals.hosts })}
              </p>
            )}
          </>
        )}
      </Pending>
    </Card>
  );
}

/** The hosts with security updates pending in each site or environment. */
function GroupBreakdown({ title, groups }: { title: string; groups: ({ key: string } & PatchCounts)[] }) {
  const t = useT();
  if (groups.length === 0) return null;
  return (
    <div>
      <h3 className="card-title">{title}</h3>
      <Breakdown tone="warn" items={groups.map((group) => ({
        label: t("{key} ({hosts} hosts)", { key: group.key || "—", hosts: group.hosts }),
        value: group.hosts - group.fully_patched - group.security_unknown,
      }))} />
    </div>
  );
}

function CampaignsCard({ report, error, ready, params }: { report?: CampaignsReport; error: unknown; ready: boolean; params: URLSearchParams }) {
  const t = useT();
  const totals = report?.totals;
  return (
    <Card
      className="span-12"
      title={t("Campaigns")}
      description={t("The campaigns that closed in the period, however they ended, with the outcome of their hosts.")}
      actions={<ExportButton path="/api/v1/reports/campaigns" params={params} disabled={!ready} />}
    >
      <Pending ready={ready} error={error}>
        {report && totals && (
          <>
            <StatusBar segments={CAMPAIGN_STATES.map(({ state, label }) => ({
              label: t(label), value: totals.by_state[state] ?? 0, tone: campaignStateTone(state),
            }))} />
            <StatusBar compact segments={[
              { label: t("Succeeded"), value: totals.succeeded, tone: "ok" },
              { label: t("Failed"), value: totals.failed, tone: "error" },
              { label: t("Unknown"), value: totals.unknown, tone: "unknown" },
              { label: t("Skipped"), value: totals.skipped, tone: "neutral" },
              { label: t("Canceled"), value: totals.canceled, tone: "neutral" },
            ]} />
            <p className="fp-note">
              {t("{campaigns} campaigns · {targets} hosts targeted · success rate {rate} over the hosts attempted; {no_change} of the successes changed nothing.", {
                campaigns: totals.campaigns, targets: totals.targets, rate: percent(totals.success_rate), no_change: totals.no_change,
              })}
            </p>
            {report.by_site.length > 0 && (
              <>
                <h3 className="card-title">{t("Succeeded hosts by site")}</h3>
                <Breakdown tone="ok" items={report.by_site.map((group) => ({
                  label: t("{key} ({targets} targeted)", { key: group.key || "—", targets: group.targets }), value: group.succeeded,
                }))} />
              </>
            )}
            {report.campaigns.length === 0 ? (
              <Empty>{t("No campaign closed in the period.")}</Empty>
            ) : (
              <table data-testid="report-campaigns">
                <thead>
                  <tr>
                    <th>{t("Campaign")}</th><th>{t("Operation")}</th><th>{t("State")}</th>
                    <th>{t("Requested by")}</th><th>{t("Approved by")}</th><th>{t("Finished")}</th><th>{t("Duration")}</th>
                    <th className="num">{t("Targets")}</th><th className="num">{t("Succeeded")}</th><th className="num">{t("Failed")}</th>
                    <th className="num">{t("Unknown")}</th><th className="num">{t("Skipped")}</th><th className="num">{t("Rate")}</th>
                  </tr>
                </thead>
                <tbody>
                  {report.campaigns.map((row) => (
                    <tr key={row.id}>
                      <td>
                        <Link to={`/campaigns/${row.id}`}>{row.name}</Link>
                        {row.by_site.length > 1 && (
                          <div className="fp-note">{row.by_site.map((group) => `${group.key}: ${group.succeeded}/${group.targets}`).join(" · ")}</div>
                        )}
                      </td>
                      <td>{row.operation}</td>
                      <td><span className={`badge ${campaignStateTone(row.state)}`}>{t(campaignStateLabel(row.state))}</span></td>
                      <td>{row.requester}</td>
                      <td>{row.approver || "—"}</td>
                      <td>{absoluteTime(row.finished_at)}</td>
                      <td>{duration(row.duration_seconds)}</td>
                      <td className="num">{row.targets}</td>
                      <td className="num">{row.succeeded}</td>
                      <td className="num">{row.failed}</td>
                      <td className="num">{row.unknown}</td>
                      <td className="num">{row.skipped + row.canceled}</td>
                      <td className="num">{percent(row.success_rate)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </>
        )}
      </Pending>
    </Card>
  );
}

/** The tone of a severity of the security checks. */
function severityTone(severity: string): WidgetTone {
  switch (severity) {
    case "high":
      return "error";
    case "medium":
      return "warn";
    case "low":
      return "neutral";
    default:
      return "info";
  }
}

function ComplianceCard({ report, error, ready, params }: { report?: ComplianceReport; error: unknown; ready: boolean; params: URLSearchParams }) {
  const t = useT();
  const policies = report?.policies;
  const security = report?.security;
  const exportParams = (section: string) => {
    const withSection = new URLSearchParams(params);
    withSection.set("section", section);
    return withSection;
  };
  return (
    <Card
      className="span-12"
      title={t("Compliance")}
      description={t("Where the hosts stand against the policies at the end of the period, and the findings of the security checks now.")}
      actions={
        <>
          {policies && <ExportButton path="/api/v1/reports/compliance" params={exportParams("policies")} disabled={!ready} label={t("Export policies CSV")} />}
          {policies && <ExportButton path="/api/v1/reports/compliance" params={exportParams("hosts")} disabled={!ready} label={t("Export drift hosts CSV")} />}
          {security && <ExportButton path="/api/v1/reports/compliance" params={exportParams("security")} disabled={!ready} label={t("Export security CSV")} />}
        </>
      }
    >
      <Pending ready={ready} error={error}>
        {report && (
          <>
            {!policies ? (
              <Empty>{t("The policy section needs the right to read policies.")}</Empty>
            ) : (
              <>
                <StatusBar segments={[
                  { label: t("Compliant"), value: policies.totals.compliant, tone: "ok" },
                  { label: t("Drift"), value: policies.totals.drift, tone: "error" },
                  { label: t("Error"), value: policies.totals.error, tone: "warn" },
                  { label: t("Not applicable"), value: policies.totals.not_applicable, tone: "neutral" },
                  { label: t("Unknown"), value: policies.totals.unknown, tone: "unknown" },
                ]} />
                <p className="fp-note">
                  {t("{policies} policies · {hosts} distinct hosts in drift · a host under several policies is counted under each. A verdict recorded after the end of the period is unknown for it: the panel keeps the latest evaluation only.", {
                    policies: policies.totals.policies, hosts: policies.totals.hosts_in_drift,
                  })}
                </p>
                {policies.policies.length === 0 ? (
                  <Empty>{t("No policy is declared.")}</Empty>
                ) : (
                  <table data-testid="report-policies">
                    <thead>
                      <tr>
                        <th>{t("Policy")}</th><th className="num">{t("Version")}</th><th>{t("Mode")}</th>
                        <th className="num">{t("Hosts")}</th><th className="num">{t("Compliant")}</th><th className="num">{t("Drift")}</th>
                        <th className="num">{t("Error")}</th><th className="num">{t("Not applicable")}</th><th className="num">{t("Unknown")}</th>
                        <th>{t("Hosts in drift")}</th>
                      </tr>
                    </thead>
                    <tbody>
                      {policies.policies.map((row) => (
                        <tr key={row.id}>
                          <td>
                            <Link to={`/policies/${row.id}`}>{row.name}</Link>
                            {!row.enabled && <span className="badge unknown">{t("disabled")}</span>}
                          </td>
                          <td className="num">{row.version || "—"}</td>
                          <td>{row.remediation_mode}</td>
                          <td className="num">{row.hosts}</td>
                          <td className="num">{row.compliant}</td>
                          <td className="num">{row.drift ? <span className="badge error">{row.drift}</span> : 0}</td>
                          <td className="num">{row.error ? <span className="badge warn">{row.error}</span> : 0}</td>
                          <td className="num">{row.not_applicable}</td>
                          <td className="num">{row.unknown ? <span className="badge unknown">{row.unknown}</span> : 0}</td>
                          <td>
                            {row.drift_hosts.map((host) => host.hostname).join(", ")}
                            {row.drift > row.drift_hosts.length && ` ${t("and {n} more", { n: row.drift - row.drift_hosts.length })}`}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
                {policies.drift_hosts.length > 0 && (
                  <>
                    <h3 className="card-title">{t("Hosts in drift")}</h3>
                    <table data-testid="report-drift-hosts">
                      <thead>
                        <tr><th>{t("Host")}</th><th>{t("Site")}</th><th>{t("Environment")}</th><th className="num">{t("Policies")}</th><th className="num">{t("Rules")}</th></tr>
                      </thead>
                      <tbody>
                        {policies.drift_hosts.map((host) => (
                          <tr key={host.host_id}>
                            <td><Link to={`/hosts/${host.host_id}/policies`}>{host.hostname}</Link></td>
                            <td>{host.site}</td>
                            <td>{host.environment}</td>
                            <td className="num">{host.policies}</td>
                            <td className="num">{host.rules}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </>
                )}
              </>
            )}

            <h3 className="card-title">{t("Security checks")}</h3>
            {!security ? (
              <Empty>{t("The security section needs the right to read the security module.")}</Empty>
            ) : (
              <>
                <StatusBar compact segments={security.by_severity.map((row) => ({
                  label: t("{severity} failed", { severity: row.severity }), value: row.failed, tone: row.failed ? severityTone(row.severity) : "ok",
                }))} />
                <p className="fp-note">
                  {t("{hosts} hosts judged from their last reported facts, {failing} with at least one failed check.", {
                    hosts: security.hosts, failing: security.hosts_with_findings,
                  })}
                </p>
                <table data-testid="report-security">
                  <thead>
                    <tr>
                      <th>{t("Check")}</th><th>{t("Severity")}</th><th className="num">{t("Failed")}</th>
                      <th className="num">{t("Passed")}</th><th className="num">{t("Unknown")}</th><th className="num">{t("Not applicable")}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {security.checks.map((check) => (
                      <tr key={check.check_id}>
                        <td>{check.title}<div className="fp-note">{check.check_id}</div></td>
                        <td><span className={`badge ${severityTone(check.severity)}`}>{check.severity}</span></td>
                        <td className="num">{check.failed ? <span className="badge error">{check.failed}</span> : 0}</td>
                        <td className="num">{check.passed}</td>
                        <td className="num">{check.unknown}</td>
                        <td className="num">{check.not_applicable}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </>
            )}
          </>
        )}
      </Pending>
    </Card>
  );
}
