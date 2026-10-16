import { useMemo, useState, type ReactNode } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { useInfiniteQuery, useQuery } from "@tanstack/react-query";
import { api } from "../../lib/api";
import type { Whoami } from "../../lib/types";
import { absoluteTime, toInstant } from "../../lib/format";
import {
  coverageSentence, unknownBreakdown, PARTIAL_REASONS, type Coverage,
} from "../../components/FleetCoverage";
import type { BoardEntry } from "../../components/board";
import { FacetList, useFleetFacets } from "../../pages/Bulk";
import {
  campaignStateLabel, campaignStateTone, duration, FOLDED_ROWS, percent,
  presetRange, PRESETS, reportParams, type Preset, type ReportFilters,
} from "../../pages/Reports";
import { toLocalInput } from "./Audit";
import { Board } from "../Board";
import { useT } from "../../i18n";
import {
  Band, Bars, Bones, Card, Download, Empty, Fact, Facts, Field, Fields, Note, Pill, Problem, Screen, Seg, Stack, Table, TwoLine, printPage, type Segment, type Tone,
} from "../kit";

/**
 * The management reports: where the fleet stands on its patches, what the
 * campaigns of a period did, and how the hosts sit against the policies
 * and the security checks.
 *
 * Every number here is the server's own - the same one the daily screens
 * show - read over one period and one part of the fleet. The period is
 * fixed at the moment it is chosen, so the three reports of one page are
 * three answers about the same window rather than three about "now".
 *
 * A host that reported nothing is counted apart from a host that is
 * clean: "not reported" is its own column everywhere, and never folded
 * into a nought.
 */

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
  // The page ends before the last host; the cursor asks for the next page,
  // and the file carries them all.
  hosts_truncated: boolean;
  next_cursor?: string;
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

type SecuritySection = Coverage & {
  hosts: number;
  hosts_with_findings: number;
  by_severity: ({ severity: string; checks: number } & SecurityCounts)[];
  checks: ({ check_id: string; title: string; severity: string } & SecurityCounts)[];
  evaluated_at: string;
};

type ComplianceReport = Envelope & {
  policies: {
    policies: PolicyRow[];
    // A sample of the hosts in drift; totals.hosts_in_drift is the count.
    drift_hosts: DriftHost[];
    drift_hosts_truncated: boolean;
    totals: {
      policies: number; compliant: number; drift: number; error: number;
      not_applicable: number; unknown: number; hosts_in_drift: number;
    };
  } | null;
  // The section carries the head of a fleet view: the sweep stops at its
  // time budget on a large fleet, and the hosts it never read are unknown,
  // not clean.
  security: SecuritySection | null;
};

/** The states of a closed campaign, in the order the summary shows them. */
const CAMPAIGN_STATES = ["completed", "completed_with_issues", "failed", "plan_failed", "expired", "canceled"];

/** The name the arrangement of this screen is stored under. */
export const REPORTS_SCREEN = "next_reports";

/** The containers of the board, and the width each ships with. */
export const REPORTS: BoardEntry[] = [
  { key: "patch_status", title: "Patch status", width: 12, height: 6 },
  { key: "campaigns", title: "Campaigns", width: 12, height: 6 },
  { key: "compliance", title: "Compliance", width: 12, height: 7 },
];

export function Reports() {
  const t = useT();
  const [params, setParams] = useSearchParams();
  const [preset, setPreset] = useState<Preset>(PRESETS.find((one) => one.key === params.get("preset"))?.key ?? "30d");
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

  // The bounds are fixed when the choice is made, not on every render: "the
  // last 30 days" is the thirty days before the click, and the three reports
  // of one page are asked with the same instant.
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
  // The host rows of the patch status are paged like the fleet lists: the
  // first page carries the document, the next ones only more rows.
  const patch = useInfiniteQuery({
    queryKey: ["reports", "patch-status", key],
    queryFn: ({ pageParam }) => api.get<PatchStatus>(`/api/v1/reports/patch-status?${key}`
      + (pageParam ? `&cursor=${encodeURIComponent(pageParam)}` : "")),
    initialPageParam: "",
    getNextPageParam: (last) => last.next_cursor || undefined,
    enabled: ready,
    retry: false,
  });
  const patchReport = patch.data?.pages[0];
  const patchHosts = patch.data?.pages.flatMap((page) => page.hosts) ?? [];
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

  const scope = [
    site.trim() && t("site {site}", { site: site.trim() }),
    environment.trim() && t("environment {environment}", { environment: environment.trim() }),
  ].filter(Boolean).join(", ") || t("the whole visible fleet");
  const generatedAt = patchReport?.generated_at ?? campaigns.data?.generated_at ?? compliance.data?.generated_at;
  const author = whoami.data?.display_name || whoami.data?.subject || "";

  return (
    <Screen
      title={t("Reports")}
      lead={t("The fleet over a period, to print or to open in a spreadsheet.")}
      icon="audit"
      help={
        <p>
          {t("The patch status, the campaigns and the compliance of the fleet over one period, as a document to read or a file to open in a spreadsheet. Every number is the server's own, the same one the daily screens show: this page asks the same questions over a window you choose and a part of the fleet you name. A host that never reported is counted apart from a host that is clean, everywhere on this page.")}
        </p>
      }
      actions={
        <button type="button" className="fl-quiet" onClick={printPage} disabled={!ready}>
          {t("Print")}
        </button>
      }
    >
      <Card
        title={t("What the reports cover")}
        note={t("The period is fixed when you choose it, so the three reports below answer about the same window.")}
        tools={
          <Seg
            value={preset}
            label={t("Period")}
            onChange={(next: Preset) => change({ preset: next })}
            options={PRESETS.map((one) => ({ value: one.key, label: t(one.label) }))}
          />
        }
        foot={
          ready
            ? t("{scope}, {from} – {to}.", { scope, from: absoluteTime(range.from), to: absoluteTime(range.to) })
            : t("Set both ends of the period to read the reports.")
        }
      >
        <Fields>
          {preset === "custom" && (
            <>
              <Field label={t("Since")} hint={t("Local time; both ends are needed before anything is read.")}>
                <input
                  type="datetime-local"
                  value={custom.from}
                  data-testid="report-from"
                  onChange={(event) => change({ custom: { ...custom, from: event.target.value } })}
                />
              </Field>
              <Field label={t("Until")} hint={t("Local time; a half period is refused by the server.")}>
                <input
                  type="datetime-local"
                  value={custom.to}
                  data-testid="report-to"
                  onChange={(event) => change({ custom: { ...custom, to: event.target.value } })}
                />
              </Field>
            </>
          )}
          <Field label={t("Site")} hint={t("Pick one the fleet has, or type any; empty means every site.")}>
            <input
              placeholder={t("site: any")}
              value={site}
              list="next-report-sites"
              data-testid="report-site"
              onChange={(event) => change({ site: event.target.value })}
            />
            <FacetList id="next-report-sites" facets={facets.data?.by_site} />
          </Field>
          <Field label={t("Environment")} hint={t("Pick one the fleet has, or type any; empty means every environment.")}>
            <input
              placeholder={t("environment: any")}
              value={environment}
              list="next-report-environments"
              data-testid="report-environment"
              onChange={(event) => change({ environment: event.target.value })}
            />
            <FacetList id="next-report-environments" facets={facets.data?.by_environment} />
          </Field>
        </Fields>
      </Card>

      {/* What the printed document used to say in its own head: what this
          is a report of, and who made it when. */}
      <Card title={t("This document")} note={t("What a copy of this page is a report of.")}>
        <Facts>
          <Fact label={t("Fleet")}>{window.location.host}</Fact>
          <Fact label={t("Scope")}>{scope}</Fact>
          <Fact label={t("Period")}>{`${absoluteTime(range.from)} – ${absoluteTime(range.to)}`}</Fact>
          <Fact label={t("Generated")}>
            {generatedAt ? absoluteTime(generatedAt) : <Unknown />}
          </Fact>
          <Fact label={t("Generated by")}>{author || <Unknown />}</Fact>
        </Facts>
      </Card>

      <Board
        screen={REPORTS_SCREEN}
        catalogue={REPORTS}
        drawn={{
          patch_status: (
            <PatchStatusCard
              report={patchReport}
              hosts={patchHosts}
              more={patch.hasNextPage ? () => patch.fetchNextPage() : undefined}
              loading={patch.isFetchingNextPage}
              error={patch.error}
              ready={ready}
              params={query}
            />
          ),
          // The campaign report needs the right to read campaigns; without
          // it the container is left off the board rather than drawn empty.
          campaigns: seesCampaigns && (
            <CampaignsCard report={campaigns.data} error={campaigns.error} ready={ready} params={query} />
          ),
          compliance: (
            <ComplianceCard report={compliance.data} error={compliance.error} ready={ready} params={query} />
          ),
        }}
      />
    </Screen>
  );
}

/** A value nobody reported: the em dash, never a nought. */
function Unknown() {
  const t = useT();
  return <span className="fl-faint" title={t("unknown")}>—</span>;
}

/** A count the host may never have reported, warned above a threshold. */
function Count({ value, warnFrom = 1 }: { value: number | null | undefined; warnFrom?: number }) {
  if (value === null || value === undefined) return <Unknown />;
  if (value >= warnFrom) return <Pill tone="warn" dot={false}>{value}</Pill>;
  return <>{value}</>;
}

/** A flag the host may never have reported. */
function Flag({ value }: { value: boolean | null | undefined }) {
  const t = useT();
  if (value === null || value === undefined) return <Unknown />;
  return value ? <Pill tone="warn" dot={false}>{t("yes")}</Pill> : <>{t("no")}</>;
}

/** A number that is only ever drawn as a pill when it is not at zero. */
function Marked({ value, tone }: { value: number; tone: Tone }) {
  if (value === 0) return <>0</>;
  return <Pill tone={tone} dot={false}>{value}</Pill>;
}

/**
 * What a report card shows while its document is not there yet: the
 * refusal, the missing period, or the shape of what is coming.
 */
function Pending({ ready, error, children }: { ready: boolean; error: unknown; children?: ReactNode }) {
  const t = useT();
  if (error) return <Problem>{String(error)}</Problem>;
  if (!ready) return <Empty icon="time">{t("Waiting for the period.")}</Empty>;
  return <>{children ?? <Bones rows={4} />}</>;
}

function PatchStatusCard({ report, hosts, more, loading, error, ready, params }: {
  report?: PatchStatus;
  hosts: PatchHost[];
  more?: () => void;
  loading: boolean;
  error: unknown;
  ready: boolean;
  params: URLSearchParams;
}) {
  const t = useT();
  const totals = report?.totals;
  const pendingSecurity = totals ? totals.hosts - totals.fully_patched - totals.security_unknown : undefined;
  return (
    <Card
      title={t("Patch status")}
      note={t("The pending updates as the hosts last reported them, and the upgrades and campaigns of the period.")}
      tools={<Download path="/api/v1/reports/patch-status" params={params} disabled={!ready} />}
      foot={
        totals && hosts.length < totals.hosts
          ? (
            <>
              {t("The table shows the first {listed} of {total} hosts; the file carries them all.", {
                listed: hosts.length, total: totals.hosts,
              })}
              {more && (
                <button type="button" className="fl-quiet fl-small" onClick={more} disabled={loading}
                        data-testid="patch-more">
                  {loading ? t("loading…") : t("Load more")}
                </button>
              )}
            </>
          )
          : undefined
      }
    >
      <Pending ready={ready} error={error}>
        {report && totals && pendingSecurity !== undefined && (
          <Stack>
            <Band
              testId="patch-bands"
              segments={[
                { label: t("Fully patched"), value: totals.fully_patched, tone: "ok" },
                { label: t("Security updates pending"), value: pendingSecurity, tone: pendingSecurity ? "warn" : "ok" },
                { label: t("Not reported"), value: totals.security_unknown, tone: "unknown" },
                { label: t("Patched in period"), value: totals.patched_in_period, tone: "info" },
                { label: t("Reboot backlog"), value: totals.reboot_backlog, tone: totals.reboot_backlog ? "warn" : "ok" },
                { label: t("Reboot not reported"), value: totals.reboot_unknown, tone: "unknown" },
              ]}
            />
            <Note>
              {t("{hosts} hosts · {updates} pending updates of which {security} security · a host that reported nothing is counted apart, never as patched.", {
                hosts: totals.hosts, updates: totals.pending_updates, security: totals.pending_security_updates,
              })}
            </Note>
            <GroupBreakdown title={t("Security updates pending, by site")} groups={report.by_site} />
            <GroupBreakdown title={t("Security updates pending, by environment")} groups={report.by_environment} />
            <Table
              rows={hosts}
              keyOf={(one) => one.host_id}
              rowTestId={(one) => `patch-${one.hostname}`}
              testId="patch-hosts"
              empty={t("No host in this part of the fleet.")}
              columns={[
                {
                  key: "host",
                  head: t("Host"),
                  cell: (one) => <Link to={`/next/hosts/${one.host_id}`}>{one.hostname}</Link>,
                },
                { key: "site", head: t("Site"), minor: true, cell: (one) => one.site || <Unknown /> },
                { key: "environment", head: t("Environment"), minor: true, cell: (one) => one.environment || <Unknown /> },
                { key: "pending", head: t("Pending"), num: true, cell: (one) => <Count value={one.pending_updates} warnFrom={1} /> },
                { key: "security", head: t("Security"), num: true, cell: (one) => <Count value={one.pending_security_updates} warnFrom={1} /> },
                { key: "reboot", head: t("Reboot"), cell: (one) => <Flag value={one.reboot_required} /> },
                {
                  key: "upgrade",
                  head: t("Last upgrade"),
                  minor: true,
                  cell: (one) => one.last_upgrade_at
                    ? absoluteTime(one.last_upgrade_at)
                    : <Pill tone="unknown" dot={false}>{t("none in period")}</Pill>,
                },
                ...(report.campaigns_read
                  ? [{
                    key: "campaigns",
                    head: t("Campaigns"),
                    num: true,
                    cell: (one: PatchHost) => (one.campaigns === undefined ? <Unknown /> : <>{one.campaigns}</>),
                  }]
                  : []),
                { key: "agent", head: t("Agent"), minor: true, tight: true, cell: (one) => one.agent_version || <Unknown /> },
                {
                  key: "seen",
                  head: t("Last seen"),
                  minor: true,
                  cell: (one) => one.last_seen_at ? absoluteTime(one.last_seen_at) : <Unknown />,
                },
              ]}
            />
          </Stack>
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
      <h3 className="fl-subhead">{title}</h3>
      <Bars
        items={groups.map((group) => ({
          label: t("{key} ({hosts} hosts)", { key: group.key || "—", hosts: group.hosts }),
          value: group.hosts - group.fully_patched - group.security_unknown,
          tone: "warn" as Tone,
        }))}
      />
    </div>
  );
}

function CampaignsCard({ report, error, ready, params }: {
  report?: CampaignsReport; error: unknown; ready: boolean; params: URLSearchParams;
}) {
  const t = useT();
  const totals = report?.totals;
  /* Every campaign of the period is on the page, and that is the point:
     what is not in the document is not on the paper either, and this
     report is printed. The panel this replaces kept every row for that
     reason and the first draft of this one dropped all but the first
     twenty-five, so a printed month of a busy fleet stopped at row 25
     with nothing to say it had.

     The reader may still fold it back to the first rows for a quick
     read; the table scrolls inside its own card either way, and the
     file carries them all whatever is folded. */
  const [unfolded, setUnfolded] = useState(true);
  const all = report?.campaigns ?? [];
  const folded = Math.max(0, all.length - FOLDED_ROWS);
  const rows = unfolded ? all : all.slice(0, FOLDED_ROWS);
  return (
    <Card
      title={t("Campaigns")}
      note={t("The campaigns that closed in the period, however they ended, with the outcome of their hosts.")}
      tools={<Download path="/api/v1/reports/campaigns" params={params} disabled={!ready} />}
      foot={
        folded > 0
          ? (
            <>
              {unfolded
                ? t("All {n} campaigns are shown, so a printed copy carries them all.", { n: all.length })
                : t("The first {shown} of {total} campaigns are shown; the file carries them all, a printed copy only these.", { shown: FOLDED_ROWS, total: all.length })}
              <button type="button" className="fl-quiet fl-small" onClick={() => setUnfolded(!unfolded)}
                      data-testid="campaigns-fold">
                {unfolded ? t("Show the first {n} only", { n: FOLDED_ROWS }) : t("Show all {n}", { n: all.length })}
              </button>
            </>
          )
          : undefined
      }
    >
      <Pending ready={ready} error={error}>
        {report && totals && (
          <Stack>
            <Band
              testId="campaign-states"
              segments={CAMPAIGN_STATES.map((state): Segment => ({
                label: t(campaignStateLabel(state)),
                value: totals.by_state[state] ?? 0,
                tone: campaignStateTone(state),
              }))}
            />
            <Band
              testId="campaign-outcomes"
              segments={[
                { label: t("Succeeded"), value: totals.succeeded, tone: "ok" },
                { label: t("Failed"), value: totals.failed, tone: "error" },
                { label: t("Unknown"), value: totals.unknown, tone: "unknown" },
                { label: t("Skipped"), value: totals.skipped, tone: "neutral" },
                { label: t("Canceled"), value: totals.canceled, tone: "neutral" },
              ]}
            />
            <Note>
              {t("{campaigns} campaigns · {targets} hosts targeted · success rate {rate} over the hosts attempted; {no_change} of the successes changed nothing.", {
                campaigns: totals.campaigns, targets: totals.targets,
                rate: percent(totals.success_rate), no_change: totals.no_change,
              })}
            </Note>
            {report.by_site.length > 0 && (
              <div>
                <h3 className="fl-subhead">{t("Succeeded hosts by site")}</h3>
                <Bars
                  items={report.by_site.map((group) => ({
                    label: t("{key} ({targets} targeted)", { key: group.key || "—", targets: group.targets }),
                    value: group.succeeded,
                    tone: "ok" as Tone,
                  }))}
                />
              </div>
            )}
            <Table
              rows={rows}
              keyOf={(one) => one.id}
              rowTestId={(one) => `campaign-${one.id}`}
              testId="report-campaigns"
              empty={t("No campaign closed in the period.")}
              columns={[
                {
                  key: "campaign",
                  head: t("Campaign"),
                  cell: (one) => (
                    <TwoLineCampaign row={one} />
                  ),
                },
                { key: "operation", head: t("Operation"), tight: true, cell: (one) => <code>{one.operation}</code> },
                {
                  key: "state",
                  head: t("State"),
                  cell: (one) => (
                    <Pill tone={campaignStateTone(one.state)}>{t(campaignStateLabel(one.state))}</Pill>
                  ),
                },
                { key: "requester", head: t("Requested by"), minor: true, cell: (one) => one.requester || <Unknown /> },
                { key: "approver", head: t("Approved by"), minor: true, cell: (one) => one.approver || <Unknown /> },
                { key: "finished", head: t("Finished"), minor: true, cell: (one) => absoluteTime(one.finished_at) },
                { key: "duration", head: t("Duration"), num: true, cell: (one) => duration(one.duration_seconds) },
                { key: "targets", head: t("Targets"), num: true, cell: (one) => one.targets },
                { key: "succeeded", head: t("Succeeded"), num: true, cell: (one) => one.succeeded },
                { key: "failed", head: t("Failed"), num: true, cell: (one) => <Marked value={one.failed} tone="error" /> },
                { key: "unknown", head: t("Unknown"), num: true, cell: (one) => <Marked value={one.unknown} tone="unknown" /> },
                { key: "skipped", head: t("Skipped"), num: true, cell: (one) => one.skipped + one.canceled },
                { key: "rate", head: t("Rate"), num: true, cell: (one) => percent(one.success_rate) },
              ]}
            />
          </Stack>
        )}
      </Pending>
    </Card>
  );
}

/** The campaign's name, and under it how its sites fared when several did. */
function TwoLineCampaign({ row }: { row: CampaignRow }) {
  return (
    <TwoLine
      sub={row.by_site.length > 1
        ? row.by_site.map((group) => `${group.key}: ${group.succeeded}/${group.targets}`).join(" · ")
        : undefined}
    >
      <Link to={`/next/campaigns/${row.id}`}>{row.name}</Link>
    </TwoLine>
  );
}

/** The tone of a severity of the security checks. */
export function severityTone(severity: string): Tone {
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

function ComplianceCard({ report, error, ready, params }: {
  report?: ComplianceReport; error: unknown; ready: boolean; params: URLSearchParams;
}) {
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
      title={t("Compliance")}
      note={t("Where the hosts stand against the policies at the end of the period, and the findings of the security checks now.")}
      tools={
        <>
          {policies && (
            <Download path="/api/v1/reports/compliance" params={exportParams("policies")}
                      disabled={!ready} label={t("Export policies CSV")} />
          )}
          {policies && (
            <Download path="/api/v1/reports/compliance" params={exportParams("hosts")}
                      disabled={!ready} label={t("Export drift hosts CSV")} />
          )}
          {security && (
            <Download path="/api/v1/reports/compliance" params={exportParams("security")}
                      disabled={!ready} label={t("Export security CSV")} />
          )}
        </>
      }
    >
      <Pending ready={ready} error={error}>
        {report && (
          <Stack>
            {!policies ? (
              <Empty icon="access">{t("The policy section needs the right to read policies.")}</Empty>
            ) : (
              <>
                <Band
                  testId="policy-states"
                  segments={[
                    { label: t("Compliant"), value: policies.totals.compliant, tone: "ok" },
                    { label: t("Drift"), value: policies.totals.drift, tone: "error" },
                    { label: t("Error"), value: policies.totals.error, tone: "warn" },
                    { label: t("Not applicable"), value: policies.totals.not_applicable, tone: "neutral" },
                    { label: t("Unknown"), value: policies.totals.unknown, tone: "unknown" },
                  ]}
                />
                <Note>
                  {t("{policies} policies · {hosts} distinct hosts in drift · a host under several policies is counted under each. A verdict recorded after the end of the period is unknown for it: the panel keeps the latest evaluation only.", {
                    policies: policies.totals.policies, hosts: policies.totals.hosts_in_drift,
                  })}
                </Note>
                <Table
                  rows={policies.policies}
                  keyOf={(one) => one.id}
                  rowTestId={(one) => `policy-${one.id}`}
                  testId="report-policies"
                  empty={t("No policy is declared.")}
                  columns={[
                    {
                      key: "policy",
                      head: t("Policy"),
                      cell: (one) => (
                        <>
                          <Link to={`/next/policies/${one.id}`}>{one.name}</Link>
                          {!one.enabled && <Pill tone="unknown" dot={false}>{t("disabled")}</Pill>}
                        </>
                      ),
                    },
                    { key: "version", head: t("Version"), num: true, cell: (one) => one.version || <Unknown /> },
                    { key: "mode", head: t("Mode"), minor: true, cell: (one) => one.remediation_mode || <Unknown /> },
                    { key: "hosts", head: t("Hosts"), num: true, cell: (one) => one.hosts },
                    { key: "compliant", head: t("Compliant"), num: true, cell: (one) => one.compliant },
                    { key: "drift", head: t("Drift"), num: true, cell: (one) => <Marked value={one.drift} tone="error" /> },
                    { key: "error", head: t("Error"), num: true, cell: (one) => <Marked value={one.error} tone="warn" /> },
                    { key: "na", head: t("Not applicable"), num: true, minor: true, cell: (one) => one.not_applicable },
                    { key: "unknown", head: t("Unknown"), num: true, cell: (one) => <Marked value={one.unknown} tone="unknown" /> },
                    {
                      key: "drift_hosts",
                      head: t("Hosts in drift"),
                      minor: true,
                      cell: (one) => {
                        const named = one.drift_hosts.map((host) => host.hostname).join(", ");
                        const rest = one.drift - one.drift_hosts.length;
                        if (!named) return <Unknown />;
                        return <>{rest > 0 ? `${named} ${t("and {n} more", { n: rest })}` : named}</>;
                      },
                    },
                  ]}
                />
                {policies.drift_hosts.length > 0 && (
                  <div>
                    <h3 className="fl-subhead">{t("Hosts in drift")}</h3>
                    <Table
                      rows={policies.drift_hosts}
                      keyOf={(one) => one.host_id}
                      rowTestId={(one) => `drift-${one.hostname}`}
                      testId="report-drift-hosts"
                      columns={[
                        {
                          key: "host",
                          head: t("Host"),
                          cell: (one) => <Link to={`/next/hosts/${one.host_id}/policies`}>{one.hostname}</Link>,
                        },
                        { key: "site", head: t("Site"), minor: true, cell: (one) => one.site || <Unknown /> },
                        { key: "environment", head: t("Environment"), minor: true, cell: (one) => one.environment || <Unknown /> },
                        { key: "policies", head: t("Policies"), num: true, cell: (one) => one.policies },
                        { key: "rules", head: t("Rules"), num: true, cell: (one) => one.rules },
                      ]}
                    />
                    {policies.drift_hosts_truncated && (
                      <Note>
                        {t("The table shows the first {listed} of {total} hosts in drift; the file carries them all.", {
                          listed: policies.drift_hosts.length, total: policies.totals.hosts_in_drift,
                        })}
                      </Note>
                    )}
                  </div>
                )}
              </>
            )}

            <h3 className="fl-subhead">{t("Security checks")}</h3>
            {!security
              ? <Empty icon="access">{t("The security section needs the right to read the security module.")}</Empty>
              : <SecurityChecks security={security} />}
          </Stack>
        )}
      </Pending>
    </Card>
  );
}

/** The findings of the security checks, and how much of the fleet they cover. */
function SecurityChecks({ security }: { security: SecuritySection }) {
  const t = useT();
  return (
    <Stack>
      <Band
        testId="security-severities"
        segments={security.by_severity.map((row): Segment => ({
          label: t("{severity} failed", { severity: row.severity }),
          value: row.failed,
          tone: row.failed ? severityTone(row.severity) : "ok",
        }))}
      />
      <Coverage coverage={security} />
      <Note>
        {t("{hosts} hosts judged from their last reported facts, {failing} with at least one failed check.", {
          hosts: security.evaluated_hosts, failing: security.hosts_with_findings,
        })}
      </Note>
      <Table
        rows={security.checks}
        keyOf={(one) => one.check_id}
        rowTestId={(one) => `check-${one.check_id}`}
        testId="report-security"
        empty={t("No security check ran on this part of the fleet.")}
        columns={[
          {
            key: "check",
            head: t("Check"),
            cell: (one) => <TwoLine sub={<code>{one.check_id}</code>}>{one.title}</TwoLine>,
          },
          {
            key: "severity",
            head: t("Severity"),
            cell: (one) => <Pill tone={severityTone(one.severity)}>{one.severity}</Pill>,
          },
          { key: "failed", head: t("Failed"), num: true, cell: (one) => <Marked value={one.failed} tone="error" /> },
          { key: "passed", head: t("Passed"), num: true, cell: (one) => one.passed },
          { key: "unknown", head: t("Unknown"), num: true, cell: (one) => <Marked value={one.unknown} tone="unknown" /> },
          { key: "na", head: t("Not applicable"), num: true, minor: true, cell: (one) => one.not_applicable },
        ]}
      />
    </Stack>
  );
}

/**
 * How much of the fleet an answer is about.
 *
 * A sweep that stopped at its time budget answered about part of the
 * fleet; the hosts it never read are unknown, not clean, and the line
 * says so rather than letting the numbers read as the whole.
 */
function Coverage({ coverage }: { coverage: Coverage }) {
  const t = useT();
  const breakdown = unknownBreakdown(coverage, t);
  const reason = coverage.partial_reason ?? "";
  return (
    <span className="fl-note" data-testid="fleet-coverage">
      <span title={breakdown || undefined}>{coverageSentence(coverage, t)}</span>
      {breakdown && <span>{` (${breakdown})`}</span>}
      {coverage.partial && (
        <>
          {" "}
          <Pill tone="warn" dot={false}>{t("partial answer")}</Pill>
          {" "}
          <span>{PARTIAL_REASONS[reason] ? t(PARTIAL_REASONS[reason]) : reason}</span>
        </>
      )}
    </span>
  );
}
