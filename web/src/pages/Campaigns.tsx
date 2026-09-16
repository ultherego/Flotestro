import { useEffect, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link, useSearchParams } from "react-router-dom";
import { api } from "../lib/api";
import type { Campaign } from "../lib/types";
import { ErrorBox, Time, Empty, JobState, stateName } from "../components/ui";
import { Card, EmptyState, PageHeader, Toolbar } from "../components/layout";
import {
  ColumnChooser, PageSizeSelect, Td, Th, useColumns, usePageSize, useSort, type ColumnDef,
} from "../components/SortableTable";
import { Breakdown, StatusBar, type WidgetTone } from "../components/widgets";
import { useDebounced } from "../lib/debounce";
import { toInstant } from "../lib/format";
import { useOperations } from "./Bulk";
import { useT } from "../i18n";

/** The tally of a campaign's hosts as the list carries it, per row. */
type Progress = {
  total: number;
  succeeded: number;
  failed: number;
  unknown: number;
  skipped: number;
  pending: number;
};

/** One page of the list: the rows and where they stand in the whole. */
type CampaignPage = {
  items: (Campaign & { progress?: Progress })[];
  count: number;
  total: number;
  limit: number;
  offset: number;
};

/** The states the filter offers, in the order a campaign moves through them. */
const CAMPAIGN_STATES = [
  "planning", "planned", "awaiting_approval", "canary", "manual_gate", "running", "pausing", "paused", "canceling",
  "completed", "completed_with_issues", "failed", "plan_failed", "expired", "canceled",
];

/** How many rows one page holds unless the operator chose otherwise. */
const PAGE = 50;

/**
 * The campaign list. The filters run on the server and live in the
 * address, so a page filtered to "the failed ones since Monday" can be
 * sent as a link; the rows come one page at a time with the count of the
 * whole. A new campaign is ordered in the Bulk workspace: the wizard there
 * knows the reason, the offline policy and the typed selector, and a
 * second, smaller wizard here would order campaigns without them.
 */
export function Campaigns() {
  const t = useT();
  const [params, setParams] = useSearchParams();
  const [state, setState] = useState(params.get("state") ?? "");
  const [action, setAction] = useState(params.get("action") ?? "");
  const [requester, setRequester] = useState(params.get("requester") ?? "");
  const [since, setSince] = useState(params.get("since") ?? "");
  const [offset, setOffset] = useState(Math.max(0, Number(params.get("offset")) || 0));
  const settledRequester = useDebounced(requester.trim());
  const sinceInstant = toInstant(since);
  // The page size is the operator's preference, kept in the browser; a
  // change of it starts from the first page, because an offset measured
  // in pages of fifty means nothing in pages of two hundred.
  const [pageSize, setStoredPageSize] = usePageSize("campaigns", PAGE);
  const setPageSize = (next: number) => { setStoredPageSize(next); setOffset(0); };

  // The address follows the filter, not the other way round: what the
  // operator narrowed the list to is what the link they copy carries.
  useEffect(() => {
    const next = new URLSearchParams();
    if (state) next.set("state", state);
    if (action) next.set("action", action);
    if (settledRequester) next.set("requester", settledRequester);
    if (since) next.set("since", since);
    if (offset > 0) next.set("offset", String(offset));
    if (next.toString() !== params.toString()) setParams(next, { replace: true });
  }, [state, action, settledRequester, since, offset, params, setParams]);

  const query = new URLSearchParams({ limit: String(pageSize) });
  if (state) query.set("state", state);
  if (action) query.set("action", action);
  if (settledRequester) query.set("requester", settledRequester);
  if (sinceInstant) query.set("since", sinceInstant);
  if (offset > 0) query.set("offset", String(offset));
  const { data, error } = useQuery({
    queryKey: ["campaigns", query.toString()],
    queryFn: () => api.get<CampaignPage>(`/api/v1/campaigns?${query}`),
  });
  // The operations the filter offers come from the catalogue, so the
  // list names what can be ordered rather than what this file knows.
  const operations = useOperations();
  const actions = (operations.data?.items ?? []).filter((item) => item.campaign_ready).map((item) => item.action);
  if (action && !actions.includes(action)) actions.push(action);
  actions.sort();
  // The page comes newest first from the server; a click on a heading
  // reorders the rows of this page in the browser, and a cleared sort
  // goes back to the server's order. The list is one page of at most two
  // hundred rows, so the browser can afford it.
  const columns = useColumns("campaigns", [
    { key: "name", label: t("Name"), sort: "name", fixed: true },
    { key: "state", label: t("State"), sort: "state" },
    { key: "operation", label: t("Operation"), sort: "operation" },
    // The heading spells the three numbers of the cell out; a bare
    // "progress" over "2 / 0 / 4" leaves the reader to guess the order.
    { key: "progress", label: t("Done / failed / pending") },
    { key: "canary", label: t("Canary / wave size"), sort: "canary", className: "num", secondary: true },
    { key: "requested_by", label: t("Requested by"), sort: "requested_by", secondary: true },
    { key: "approved_by", label: t("Approved by"), sort: "approved_by", secondary: true },
    { key: "created", label: t("Created"), sort: "created" },
  ] satisfies ColumnDef[]);
  const { sort, setSort, sorted } = useSort(data?.items ?? [], (campaign, column) => {
    switch (column) {
      case "name": return campaign.name;
      case "state": return campaign.state;
      case "operation": return campaign.action_type;
      case "canary": return campaign.canary_size;
      case "requested_by": return campaign.created_by;
      case "approved_by": return campaign.approved_by || null;
      default: return campaign.created_at;
    }
  });

  if (error) return <ErrorBox error={error} />;

  // The bar counts the listed campaigns: this page, not the whole
  // history, and the caption says so. Before the list arrives nothing is
  // known, and the segments show dashes.
  const campaigns = data?.items ?? [];
  const count = (states: string[]) => (data ? campaigns.filter((campaign) => states.includes(campaign.state)).length : undefined);
  const awaiting = count(["awaiting_approval", "planned"]);
  const inProgress = count(["planning", "canary", "running"]);
  const paused = count(["paused", "manual_gate"]);
  const completed = count(["completed"]);
  // A campaign that got through with hosts failed or unknown is neither a
  // clean completion nor a failure; it has a segment of its own, because
  // it is the one the operator has hosts to look at in.
  const withIssues = count(["completed_with_issues"]);
  const failed = count(["failed", "plan_failed", "expired", "partially_applied"]);
  // A canceling campaign still has hosts at work; it is counted with the
  // canceled ones because its fate is decided, not because it has ended.
  const canceled = count(["canceled", "canceling", "cancelled"]);
  const listed = data
    ? t("{shown} of {total} shown", { shown: campaigns.length, total: data.total })
    : t("among the {n} listed", { n: campaigns.length });
  // How the listed campaigns ended, and what they did: a fleet whose
  // campaigns mostly end canceled has a planning problem, not a rollout
  // problem, and that is read here rather than row by row.
  const tally = (key: (campaign: Campaign) => string) => Object.entries(
    campaigns.reduce<Record<string, number>>((acc, campaign) => { const k = key(campaign); acc[k] = (acc[k] ?? 0) + 1; return acc; }, {}),
  ).sort((x, y) => y[1] - x[1]);
  const outcomes = tally((campaign) => campaign.state);
  const byOperation = tally((campaign) => campaign.action_type);
  const outcomeTone = (value: string): WidgetTone =>
    value === "completed" ? "ok" : ["failed", "plan_failed", "expired", "partially_applied"].includes(value) ? "error"
      : ["pausing", "paused", "manual_gate", "awaiting_approval", "planned", "completed_with_issues"].includes(value) ? "warn"
        : ["canceled", "canceling", "cancelled"].includes(value) ? "unknown" : "info";
  const filtering = Boolean(state || action || settledRequester || since);
  const resetFilters = () => { setState(""); setAction(""); setRequester(""); setSince(""); setOffset(0); };
  const narrow = (delta: () => void) => { delta(); setOffset(0); };
  const lastPage = data ? offset + campaigns.length >= data.total : true;

  return (
    <>
      <PageHeader
        title={t("Campaigns")}
        description={t("Campaigns are the main mechanism for fleet-wide change.")}
        actions={
          <>
            <Link className="button secondary" to="/campaigns/schedules">{t("Schedules")}</Link>
            <Link className="button primary" to="/bulk" title={t("The Bulk workspace: the targets, the reason, the offline policy and the whole rollout, step by step.")}>
              {t("New campaign")}
            </Link>
          </>
        }
      />

      <div className="widgets">
        <Card className="span-12" title={t("State")} description={listed}>
          <StatusBar segments={[
            { label: t("Awaiting approval"), value: awaiting, tone: "warn" },
            { label: t("In progress"), value: inProgress, tone: "info" },
            { label: t("Paused"), value: paused, tone: "warn" },
            { label: t("Completed"), value: completed, tone: "ok" },
            { label: t("With issues"), value: withIssues, tone: "warn" },
            { label: t("Failed"), value: failed, tone: "error" },
            { label: t("Canceled"), value: canceled, tone: "unknown" },
          ]} />
        </Card>

        <Card className="span-9" title={t("List")} flush>
          {/* The filter runs on the server and the rows arrive page by
              page: the screen shows what the operator asked about, not
              the newest fifty of everything. */}
          <Toolbar end={<>
            {filtering && <button className="secondary" onClick={resetFilters}>{t("Clear the filters")}</button>}
            <PageSizeSelect value={pageSize} onChange={setPageSize} />
            <ColumnChooser columns={columns} />
          </>}>
            <select value={state} onChange={(e) => narrow(() => setState(e.target.value))}>
              <option value="">{t("state: any")}</option>
              {CAMPAIGN_STATES.map((value) => <option key={value} value={value}>{t(stateName(value))}</option>)}
            </select>
            <select value={action} onChange={(e) => narrow(() => setAction(e.target.value))}>
              <option value="">{t("operation: any")}</option>
              {actions.map((value) => <option key={value} value={value}>{value}</option>)}
            </select>
            <input placeholder={t("Requested by")} value={requester} onChange={(e) => narrow(() => setRequester(e.target.value))} />
            <input type="datetime-local" value={since} onChange={(e) => narrow(() => setSince(e.target.value))} title={t("Created since")} />
          </Toolbar>
          {!data ? (
            <Empty>{t("Loading…")}</Empty>
          ) : !data.items.length ? (
            <EmptyState action={filtering
              ? <button className="secondary" onClick={resetFilters}>{t("Clear the filters")}</button>
              : <Link className="button primary" to="/bulk">{t("New campaign")}</Link>}
            >
              {filtering ? t("No campaign matches the filter.") : t("No campaigns.")}
            </EmptyState>
          ) : (
            <table>
              <thead>
                <tr>
                  {columns.visible.map((column) => (
                    <Th key={column.key} columns={columns} name={column.key} sort={sort} onSort={setSort} />
                  ))}
                </tr>
              </thead>
              <tbody>
                {sorted.map((campaign) => (
                  <tr key={campaign.id}>
                    <Td columns={columns} name="name"><Link to={`/campaigns/${campaign.id}`}>{campaign.name}</Link></Td>
                    <Td columns={columns} name="state"><JobState state={campaign.state} /></Td>
                    <Td columns={columns} name="operation" className="mono">{campaign.action_type}</Td>
                    {/* The tally of the hosts, the same colours as the
                        campaign's own bar: unknown is its own number and
                        never folded into failed or succeeded. */}
                    <Td columns={columns} name="progress">
                      {campaign.progress ? (
                        <ProgressCells progress={campaign.progress} />
                      ) : (
                        "—"
                      )}
                    </Td>
                    <Td columns={columns} name="canary">{campaign.canary_size} / {campaign.wave_size}</Td>
                    <Td columns={columns} name="requested_by">{campaign.created_by}</Td>
                    <Td columns={columns} name="approved_by">{campaign.approved_by || "—"}</Td>
                    <Td columns={columns} name="created"><Time value={campaign.created_at} /></Td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          {data && data.total > pageSize && (
            <Toolbar end={<span>{t("{shown} of {total} shown", { shown: Math.min(offset + campaigns.length, data.total), total: data.total })}</span>}>
              <button className="secondary" onClick={() => setOffset(Math.max(0, offset - pageSize))} disabled={offset === 0}>{t("Newer")}</button>
              <button className="secondary" onClick={() => setOffset(offset + pageSize)} disabled={lastPage}>{t("Older")}</button>
            </Toolbar>
          )}
        </Card>

        {/* The side widget reads the outcomes and operations of the page,
            not the fleet's history: it is the shape of what is listed. */}
        <Card className="span-3" title={t("Outcomes")} description={listed}>
          {!data ? (
            <Empty>{t("Loading…")}</Empty>
          ) : campaigns.length === 0 ? (
            <p className="fp-blank">{t("No campaigns.")}</p>
          ) : (
            <>
              <Breakdown items={outcomes.map(([value, n]) => ({ label: <JobState state={value} />, value: n, tone: outcomeTone(value) }))} />
              <h4 className="widget-subhead">{t("By operation")}</h4>
              <Breakdown tone="neutral" items={byOperation.map(([value, n]) => ({ label: <span className="mono">{value}</span>, value: n }))} />
            </>
          )}
        </Card>
      </div>
    </>
  );
}

/**
 * The progress of one row: succeeded, failed and pending as numbers with
 * the campaign's colours, the unknown and skipped ones named where there
 * are any. A row of zeros is a campaign that has not started; a dash
 * would read as "not known".
 */
function ProgressCells({ progress }: { progress: Progress }) {
  const t = useT();
  return (
    <span className="mono" title={t("{total} hosts: {succeeded} succeeded, {failed} failed, {unknown} unknown, {skipped} skipped, {pending} pending", progress)}>
      <span style={{ color: "var(--ok-text)" }}>{progress.succeeded}</span>
      {" / "}
      <span style={progress.failed > 0 ? { color: "var(--error-text)" } : undefined}>{progress.failed}</span>
      {" / "}
      <span>{progress.pending}</span>
      {progress.unknown > 0 && <span style={{ color: "var(--warn-text)" }}> · {t("{n} unknown", { n: progress.unknown })}</span>}
      {progress.skipped > 0 && <span className="source"> · {t("{n} skipped", { n: progress.skipped })}</span>}
    </span>
  );
}
