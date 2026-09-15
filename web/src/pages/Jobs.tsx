import { Fragment, useEffect, useRef, useState } from "react";
import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useSearchParams } from "react-router-dom";
import { api, loadedItems, LIST_PAGE, type Collection, type Page } from "../lib/api";
import { useDebounced } from "../lib/debounce";
import { bytes, toInstant } from "../lib/format";
import { PlanSummary } from "../components/plan";
import type { Attempt, FleetActivity, Job } from "../lib/types";
import { ErrorBox, ErrorCode, Time, ProgressBar, Empty, JobState } from "../components/ui";
import { Actions, Card, PageHeader, Toolbar } from "../components/layout";
import { ExportButton } from "../components/ExportButton";
import { BarChart, Breakdown, StatusBar } from "../components/widgets";
import { OPERATIONS_INTERVAL, REFRESH_INTERVAL, useProgress } from "../lib/stream";
import { bulkPrefill } from "./Bulk";
import { useT } from "../i18n";

/** The states the filter offers. */
const JOB_STATES = ["awaiting_approval", "queued", "dispatched", "running", "succeeded", "failed", "timed_out", "canceled", "expired"];

/** The states after which an order can be placed again: the job is over and did not do its work. */
export const REORDERABLE_STATES = ["failed", "timed_out", "canceled", "expired"];

/** The shortest reason the API records with a cancel. */
export const MIN_REASON = 8;

/**
 * The filters of the list, as they stand in the address bar. Every one of
 * them is a string so the address and the screen say the same thing; the
 * instants stay in the local form the datetime input speaks and turn into
 * RFC 3339 only for the request.
 */
export type JobFilters = {
  state: string;
  action: string;
  actor: string;
  hostname: string;
  host_id: string;
  fanout_id: string;
  campaign_id: string;
  error_code: string;
  since: string;
  until: string;
};

const FILTER_KEYS: (keyof JobFilters)[] = [
  "state", "action", "actor", "hostname", "host_id", "fanout_id", "campaign_id", "error_code", "since", "until",
];

export const EMPTY_FILTERS: JobFilters = {
  state: "", action: "", actor: "", hostname: "", host_id: "", fanout_id: "", campaign_id: "", error_code: "", since: "", until: "",
};

/** The filters read off the address: a link from a tile, a read fan-out or a bookmark sets them. */
export function readFilters(params: URLSearchParams): JobFilters {
  const filters = { ...EMPTY_FILTERS };
  for (const key of FILTER_KEYS) filters[key] = params.get(key) ?? "";
  return filters;
}

/** The address the filters make: only the set ones, so an empty screen is a plain /jobs. */
export function filterParams(filters: JobFilters): URLSearchParams {
  const params = new URLSearchParams();
  for (const key of FILTER_KEYS) {
    if (filters[key]) params.set(key, filters[key]);
  }
  return params;
}

/** Whether any filter narrows the list. */
export function anyFilter(filters: JobFilters): boolean {
  return FILTER_KEYS.some((key) => filters[key] !== "");
}

/**
 * The moment a number of hours ago, in the form a datetime-local input
 * takes: the browser's local time to the minute, with no zone. The value
 * goes through toInstant like a typed one, so a preset and a typed bound
 * follow the same path to the request.
 */
export function localInput(at: Date): string {
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${at.getFullYear()}-${pad(at.getMonth() + 1)}-${pad(at.getDate())}T${pad(at.getHours())}:${pad(at.getMinutes())}`;
}

export function hoursAgo(hours: number, now: Date = new Date()): string {
  return localInput(new Date(now.getTime() - hours * 3600 * 1000));
}

/**
 * The address of the Bulk workspace with the same order written in again:
 * the operation, the payload and the one host of the job. The operator
 * decides there whether to send it as it was or to change it first; a
 * failed job is not repeated blind.
 */
export function orderAgainAddress(job: Pick<Job, "action_type" | "payload" | "host_id" | "hostname">): string {
  const name = `${job.action_type} again on ${job.hostname || job.host_id.slice(0, 8)}`;
  return bulkPrefill(job.action_type, name, job.payload ?? {}, undefined, [job.host_id]);
}

/** Whether a cancel reason is long enough for the trail. */
export function reasonAccepted(reason: string): boolean {
  return reason.trim().length >= MIN_REASON;
}

/** The payload as the operator reads it: indented JSON, whatever shape it came in. */
export function prettyJSON(value: unknown): string {
  if (value === undefined || value === null) return "";
  if (typeof value === "string") {
    try {
      return JSON.stringify(JSON.parse(value), null, 2);
    } catch {
      return value;
    }
  }
  return JSON.stringify(value, null, 2);
}

/**
 * The job list with approvals. An approval confirms the plan hash.
 *
 * The filters run on the server and the list grows page by page: the fleet
 * orders thousands of tasks a week, and "the failed ones since Monday" is a
 * question the database answers better than a screen scanning a list.
 */
export function Jobs() {
  const t = useT();
  // The address carries the filters: a tile on the dashboard and a read
  // fan-out link here with one already set, and a bookmark brings back a
  // view. Every change goes back into the address for the same reason.
  const [searchParams, setSearchParams] = useSearchParams();
  const [filters, setFilters] = useState<JobFilters>(() => readFilters(searchParams));
  const setFilter = (key: keyof JobFilters, value: string) => setFilters((previous) => ({ ...previous, [key]: value }));
  // The address last written or adopted: it tells a change typed on the
  // screen from a link followed to this page, so each side follows the
  // other without the two chasing each other.
  const written = useRef(searchParams.toString());
  useEffect(() => {
    const next = filterParams(filters).toString();
    if (next !== written.current) {
      written.current = next;
      setSearchParams(new URLSearchParams(next), { replace: true });
    }
  }, [filters, setSearchParams]);
  useEffect(() => {
    const current = searchParams.toString();
    if (current !== written.current) {
      written.current = current;
      setFilters(readFilters(searchParams));
    }
  }, [searchParams]);

  const [expanded, setExpanded] = useState<string>("");
  // The row whose payload is on screen for approval, and the row whose
  // cancel reason is being typed: one of each at a time.
  const [reviewing, setReviewing] = useState<string>("");
  const [canceling, setCanceling] = useState<string>("");
  const [cancelReason, setCancelReason] = useState("");
  // The jobs ticked for a batch decision, by identifier.
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [batchReason, setBatchReason] = useState("");
  const [batchError, setBatchError] = useState<string>("");
  const queryClient = useQueryClient();
  // The typed filters reach the server after a pause, not per keystroke.
  const settledAction = useDebounced(filters.action.trim());
  const settledActor = useDebounced(filters.actor.trim());
  const settledHostname = useDebounced(filters.hostname.trim());
  const settledCampaign = useDebounced(filters.campaign_id.trim());
  const settledError = useDebounced(filters.error_code.trim());

  const params = new URLSearchParams({ limit: String(LIST_PAGE) });
  if (filters.state) params.set("state", filters.state);
  if (settledAction) params.set("action", settledAction);
  if (settledActor) params.set("actor", settledActor);
  if (settledHostname) params.set("hostname", settledHostname);
  if (filters.host_id) params.set("host_id", filters.host_id);
  if (filters.fanout_id) params.set("fanout_id", filters.fanout_id);
  if (settledCampaign) params.set("campaign_id", settledCampaign);
  if (settledError) params.set("error_code", settledError);
  if (toInstant(filters.since)) params.set("since", toInstant(filters.since));
  if (toInstant(filters.until)) params.set("until", toInstant(filters.until));

  const list = useInfiniteQuery({
    queryKey: ["jobs", params.toString()],
    queryFn: ({ pageParam }) => {
      const page = new URLSearchParams(params);
      if (pageParam) page.set("cursor", pageParam);
      return api.get<Page<Job>>(`/api/v1/jobs?${page}`);
    },
    initialPageParam: "",
    getNextPageParam: (last) => last.next_cursor || undefined,
    // The operation list has no stream of its own, because its content also
    // changes through other operators' operations and through jobs expiring.
    refetchInterval: OPERATIONS_INTERVAL,
  });

  // One stream per tab carries the progress of all the running operations
  // and wakes the list when one of them changes state.
  const progress = useProgress("/api/v1/events");
  // The chart is the whole fleet's last day, counted in the database: it
  // does not depend on the filters or on how many pages are loaded.
  const activity = useQuery({
    queryKey: ["fleet-activity"],
    queryFn: () => api.get<FleetActivity>("/api/v1/fleet/activity?hours=24"),
    refetchInterval: REFRESH_INTERVAL,
  });

  const approve = useMutation({
    mutationFn: (job: Job) =>
      api.post(`/api/v1/jobs/${job.id}/approve`, { payload_hash: job.payload_hash }),
    onSuccess: () => {
      setReviewing("");
      queryClient.invalidateQueries({ queryKey: ["jobs"] });
    },
  });
  const cancel = useMutation({
    mutationFn: ({ job, reason }: { job: Job; reason: string }) =>
      api.post(`/api/v1/jobs/${job.id}/cancel`, { reason: reason.trim() }),
    onSuccess: () => {
      setCanceling("");
      setCancelReason("");
      queryClient.invalidateQueries({ queryKey: ["jobs"] });
    },
  });
  // A batch decision is the per-job call repeated: the trail then carries
  // one record per job, as it would had the operator clicked them one by
  // one. The loop stops at the first refusal so the operator sees which
  // job refused and why, with the rest still ticked.
  const batch = useMutation({
    mutationFn: async ({ operation, jobs, reason }: { operation: "approve" | "cancel"; jobs: Job[]; reason: string }) => {
      setBatchError("");
      for (const job of jobs) {
        try {
          if (operation === "approve") {
            await api.post(`/api/v1/jobs/${job.id}/approve`, { payload_hash: job.payload_hash, reason: reason.trim() || undefined });
          } else {
            await api.post(`/api/v1/jobs/${job.id}/cancel`, { reason: reason.trim() });
          }
          setSelected((previous) => {
            const copy = new Set(previous);
            copy.delete(job.id);
            return copy;
          });
        } catch (error) {
          const message = error instanceof Error ? error.message : String(error);
          setBatchError(t("{operation} of {job} on {host} refused: {message}", {
            operation: job.action_type, job: job.id.slice(0, 8), host: job.hostname || job.host_id.slice(0, 8), message,
          }));
          throw error;
        } finally {
          queryClient.invalidateQueries({ queryKey: ["jobs"] });
        }
      }
    },
  });

  if (list.error) return <ErrorBox error={list.error} />;

  // The bar counts what is on the list, nothing more: the list is the
  // pages loaded so far of the newest jobs, and the caption says so. While
  // the list has not arrived the counts are not known, and the segments
  // show dashes rather than zeros.
  const jobs = loadedItems(list.data);
  const loaded = list.data !== undefined;
  const count = (states: string[]) => (loaded ? jobs.filter((job) => states.includes(job.state)).length : undefined);
  const awaiting = count(["awaiting_approval"]);
  const queued = count(["queued", "leased", "dispatched"]);
  const running = count(["running"]);
  const failed = count(["failed", "timed_out", "expired"]);
  const succeeded = count(["succeeded"]);
  const canceled = count(["canceled", "cancelled", "rejected"]);
  const listed = t("among the {n} listed", { n: jobs.length });
  // The listed jobs by operation, the most frequent first. The list is
  // one page of the newest jobs, so this is what the fleet did lately,
  // not what it does in general.
  const byOperation = Object.entries(
    jobs.reduce<Record<string, number>>((acc, job) => { acc[job.action_type] = (acc[job.action_type] ?? 0) + 1; return acc; }, {}),
  ).sort((x, y) => y[1] - x[1]);
  const shownOperations = byOperation.slice(0, 10);
  const a = activity.data;
  const hourLabel = (iso: string) => new Date(iso).toLocaleTimeString([], { hour: "2-digit" });

  // The batch works on the ticked jobs still awaiting approval on the
  // list: a job approved by someone else in the meantime drops out.
  const awaitingJobs = jobs.filter((job) => job.state === "awaiting_approval");
  const selectedJobs = awaitingJobs.filter((job) => selected.has(job.id));
  const allSelected = awaitingJobs.length > 0 && selectedJobs.length === awaitingJobs.length;
  const toggleAll = () => setSelected(allSelected ? new Set() : new Set(awaitingJobs.map((job) => job.id)));
  const toggle = (id: string) => setSelected((previous) => {
    const copy = new Set(previous);
    if (copy.has(id)) copy.delete(id); else copy.add(id);
    return copy;
  });
  const columns = 9;

  return (
    <>
      <PageHeader
        title={t("Jobs")}
        description={t("Approval confirms the plan hash, so tampering with its content is detectable.")}
      />

      <div className="widgets">
        <Card className="span-12" title={t("State")} description={listed}>
          <StatusBar segments={[
            { label: t("Awaiting approval"), value: awaiting, tone: "warn" },
            { label: t("Queued"), value: queued, tone: "neutral" },
            { label: t("Running"), value: running, tone: "info" },
            { label: t("Succeeded"), value: succeeded, tone: "ok" },
            { label: t("Failed"), value: failed, tone: "error" },
            { label: t("Canceled"), value: canceled, tone: "unknown" },
          ]} />
        </Card>

        <Card className="span-8" title={t("Operations, last 24 h")} description={t("Finished per hour, by outcome.")}>
          {a ? (
            <BarChart
              labels={a.hours.map(hourLabel)}
              everyLabel={3}
              series={[
                { name: t("Succeeded"), tone: "ok", values: a.succeeded },
                { name: t("Failed"), tone: "error", values: a.failed },
                { name: t("Other"), tone: "unknown", values: a.other },
              ]}
            />
          ) : activity.isError ? (
            <p className="fp-blank">{t("The last day could not be counted.")}</p>
          ) : <Empty>{t("Loading…")}</Empty>}
        </Card>

        <Card className="span-4" title={t("By operation")} description={listed}>
          {!loaded ? (
            <Empty>{t("Loading…")}</Empty>
          ) : shownOperations.length === 0 ? (
            <p className="fp-blank">{t("No jobs.")}</p>
          ) : (
            <>
              <Breakdown items={shownOperations.map(([action, n]) => ({ label: <span className="mono">{action}</span>, value: n }))} />
              {byOperation.length > shownOperations.length && (
                <p className="fp-rest">{t("and {n} more operations", { n: byOperation.length - shownOperations.length })}</p>
              )}
            </>
          )}
        </Card>

        <Card className="span-12" flush>
          <Toolbar end={<><span>{t("{n} listed", { n: jobs.length })}</span><ExportButton path="/api/v1/jobs" params={params} /></>}>
            <select value={filters.state} onChange={(e) => setFilter("state", e.target.value)}>
              <option value="">{t("state: any")}</option>
              {JOB_STATES.map((value) => <option key={value} value={value}>{value}</option>)}
            </select>
            <input placeholder={t("operation, e.g. unit.restart")} value={filters.action} onChange={(e) => setFilter("action", e.target.value)} />
            <input placeholder={t("host name")} value={filters.hostname} onChange={(e) => setFilter("hostname", e.target.value)} />
            <input placeholder={t("requested by")} value={filters.actor} onChange={(e) => setFilter("actor", e.target.value)} />
            <input placeholder={t("campaign ID")} value={filters.campaign_id} onChange={(e) => setFilter("campaign_id", e.target.value)} />
            <input placeholder={t("error code")} value={filters.error_code} onChange={(e) => setFilter("error_code", e.target.value)} />
            <label className="toggle">
              {t("Since")}{" "}
              <input type="datetime-local" value={filters.since} onChange={(e) => setFilter("since", e.target.value)} />
            </label>
            <label className="toggle">
              {t("Until")}{" "}
              <input type="datetime-local" value={filters.until} onChange={(e) => setFilter("until", e.target.value)} />
            </label>
            {/* A preset sets the lower bound and lifts the upper one: "the
                last day" reaches now, whatever the until field said. */}
            <span className="segmented">
              <button type="button" onClick={() => setFilters((f) => ({ ...f, since: hoursAgo(1), until: "" }))}>{t("last hour")}</button>
              <button type="button" onClick={() => setFilters((f) => ({ ...f, since: hoursAgo(24), until: "" }))}>{t("last 24 h")}</button>
              <button type="button" onClick={() => setFilters((f) => ({ ...f, since: hoursAgo(24 * 7), until: "" }))}>{t("last 7 days")}</button>
            </span>
            {/* The host and the fan-out come from a link, not from a
                field: they show as chips the operator can take off. */}
            {filters.host_id && (
              <span className="chip">
                {t("host {id}", { id: filters.host_id.slice(0, 8) })}
                <button type="button" className="expander" aria-label={t("Remove the host filter")} onClick={() => setFilter("host_id", "")}>×</button>
              </span>
            )}
            {filters.fanout_id && (
              <span className="chip">
                {t("fan-out {id}", { id: filters.fanout_id.slice(0, 8) })}
                <button type="button" className="expander" aria-label={t("Remove the fan-out filter")} onClick={() => setFilter("fanout_id", "")}>×</button>
              </span>
            )}
            {anyFilter(filters) && (
              <button type="button" className="secondary" onClick={() => setFilters({ ...EMPTY_FILTERS })}>{t("Clear filters")}</button>
            )}
          </Toolbar>

          {/* The batch bar stands only when a job waits: a decision on
              many jobs is one reason for all of them, and each call goes
              to the trail on its own. */}
          {awaitingJobs.length > 0 && (
            <Toolbar>
              <span>{t("{n} of {total} awaiting jobs selected", { n: selectedJobs.length, total: awaitingJobs.length })}</span>
              <input
                placeholder={t("reason for the batch, at least 8 characters")}
                value={batchReason}
                onChange={(e) => setBatchReason(e.target.value)}
              />
              <button
                type="button"
                disabled={selectedJobs.length === 0 || batch.isPending}
                onClick={() => batch.mutate({ operation: "approve", jobs: selectedJobs, reason: batchReason })}
              >
                {t("Approve selected")}
              </button>
              <button
                type="button"
                className="secondary"
                disabled={selectedJobs.length === 0 || !reasonAccepted(batchReason) || batch.isPending}
                title={reasonAccepted(batchReason) ? undefined : t("A cancel needs a reason of at least 8 characters.")}
                onClick={() => batch.mutate({ operation: "cancel", jobs: selectedJobs, reason: batchReason })}
              >
                {t("Cancel selected")}
              </button>
              {batchError && <span className="warning">{batchError}</span>}
            </Toolbar>
          )}

          {list.isLoading ? (
            <Empty>{t("Loading…")}</Empty>
          ) : jobs.length === 0 ? (
            <Empty>{t("No jobs.")}</Empty>
          ) : (
            <table>
              <thead>
                <tr>
                  <th>
                    {awaitingJobs.length > 0 && (
                      <input type="checkbox" checked={allSelected} onChange={toggleAll} aria-label={t("Select every job awaiting approval")} />
                    )}
                  </th>
                  <th>{t("Operation")}</th><th>{t("Host")}</th><th>{t("State")}</th><th>{t("Requested by")}</th><th>{t("Approved by")}</th>
                  <th>{t("Result")}</th><th>{t("Created")}</th><th></th>
                </tr>
              </thead>
              <tbody>
                {jobs.map((job) => (
                  <Fragment key={job.id}>
                    <tr>
                      <td>
                        {job.state === "awaiting_approval" && (
                          <input type="checkbox" checked={selected.has(job.id)} onChange={() => toggle(job.id)} aria-label={t("Select job {id}", { id: job.id.slice(0, 8) })} />
                        )}
                      </td>
                      <td>
                        <button
                          className="expander"
                          aria-expanded={expanded === job.id}
                          onClick={() => setExpanded(expanded === job.id ? "" : job.id)}
                        >
                          {expanded === job.id ? "▾" : "▸"}
                        </button>
                        <Link to={`/jobs/${job.id}`} className="mono">{job.action_type}</Link>
                        {job.campaign_id && (
                          <>
                            {" "}
                            <Link to={`/campaigns/${job.campaign_id}`} className="chip" title={t("Part of a campaign")}>
                              {t("campaign {id}", { id: job.campaign_id.slice(0, 8) })}
                            </Link>
                          </>
                        )}
                      </td>
                      <td>
                        <Link to={`/hosts/${job.host_id}/overview`}>{job.hostname || job.host_id.slice(0, 8)}</Link>
                      </td>
                      <td>
                        <JobState state={job.state} />
                        {/* A queued job the budgets refused says so next to its
                            state: without the key it stands in the queue for no
                            visible reason and looks like a forgotten job. */}
                        {job.state === "queued" && waitedBudget(job.wait_reason) && (
                          <span className="badge warn" title={t("The fleet or the site has no free capacity for this operation; the job starts when a token of this budget is free.")}>
                            {t("waiting for budget {key}", { key: waitedBudget(job.wait_reason) })}
                          </span>
                        )}
                        {/* The bar accompanies the state, it does not replace it:
                            the operator is to see both that the operation runs
                            and how far it got. */}
                        {progress.has(job.id) && (
                          <ProgressBar
                            percent={progress.get(job.id)?.percent}
                            step={progress.get(job.id)?.step}
                            total={progress.get(job.id)?.total}
                            caption={progress.get(job.id)?.message}
                          />
                        )}
                      </td>
                      <td>{job.created_by}</td>
                      {/* For a destructive operation one approval starts nothing:
                          the operator is to see whom we are still waiting for,
                          instead of clicking "Approve" and seeing nothing happen. */}
                      <td>
                        {job.required_approvals > 1 ? (
                          <>
                            {t("{collected} of {required} approvals", { collected: job.collected_approvals, required: job.required_approvals })}
                            {job.approved_by && <span className="source"> · {job.approved_by}</span>}
                          </>
                        ) : (
                          job.approved_by || "—"
                        )}
                      </td>
                      <td>{job.result_error_code ? <ErrorCode code={job.result_error_code} /> : (job.result_status || "—")}</td>
                      <td><Time value={job.created_at} /></td>
                      <td className="actions-cell">
                        {job.state === "awaiting_approval" && (
                          <div className="row-actions">
                            <button
                              onClick={() => { setReviewing(reviewing === job.id ? "" : job.id); setCanceling(""); }}
                              disabled={approve.isPending}
                              aria-expanded={reviewing === job.id}
                            >
                              {t("Approve")}
                            </button>
                            <button
                              className="secondary"
                              onClick={() => { setCanceling(canceling === job.id ? "" : job.id); setReviewing(""); }}
                              aria-expanded={canceling === job.id}
                            >
                              {t("Cancel")}
                            </button>
                          </div>
                        )}
                        {REORDERABLE_STATES.includes(job.state) && (
                          <div className="row-actions">
                            <Link className="button secondary" to={orderAgainAddress(job)} title={t("Opens the Bulk workspace with the same operation, payload and host written in.")}>
                              {t("Order again")}
                            </Link>
                          </div>
                        )}
                      </td>
                    </tr>
                    {/* An approval is given to a payload the operator has
                        read: the row opens with it, and the button that
                        binds the consent to its hash stands under it. */}
                    {reviewing === job.id && job.state === "awaiting_approval" && (
                      <tr className="detail-row">
                        <td colSpan={columns}>
                          <p className="source">
                            {t("You approve exactly this payload for {operation} on {host}; the consent is bound to hash {hash}.", {
                              operation: job.action_type, host: job.hostname || job.host_id.slice(0, 8), hash: job.payload_hash.slice(0, 12),
                            })}
                          </p>
                          <pre>{prettyJSON(job.payload)}</pre>
                          <Actions>
                            <button onClick={() => approve.mutate(job)} disabled={approve.isPending}>{t("Approve this payload")}</button>
                            <button className="secondary" onClick={() => setReviewing("")}>{t("Back")}</button>
                            {approve.error && <span className="page-error">{approve.error instanceof Error ? approve.error.message : String(approve.error)}</span>}
                          </Actions>
                        </td>
                      </tr>
                    )}
                    {canceling === job.id && job.state === "awaiting_approval" && (
                      <tr className="detail-row">
                        <td colSpan={columns}>
                          <Actions>
                            <input
                              autoFocus
                              placeholder={t("reason for the cancel, at least 8 characters")}
                              value={cancelReason}
                              onChange={(e) => setCancelReason(e.target.value)}
                              onKeyDown={(e) => { if (e.key === "Enter" && reasonAccepted(cancelReason)) cancel.mutate({ job, reason: cancelReason }); }}
                            />
                            <button
                              className="danger"
                              disabled={!reasonAccepted(cancelReason) || cancel.isPending}
                              onClick={() => cancel.mutate({ job, reason: cancelReason })}
                            >
                              {t("Cancel this job")}
                            </button>
                            <button className="secondary" onClick={() => { setCanceling(""); setCancelReason(""); }}>{t("Back")}</button>
                            {cancel.error && <span className="page-error">{cancel.error instanceof Error ? cancel.error.message : String(cancel.error)}</span>}
                          </Actions>
                        </td>
                      </tr>
                    )}
                    {expanded === job.id && (
                      <tr className="detail-row">
                        <td colSpan={columns}>
                          <Attempts jobId={job.id} />
                          <p className="source"><Link to={`/jobs/${job.id}`}>{t("Open the job: full payload, plan and output")}</Link></p>
                        </td>
                      </tr>
                    )}
                  </Fragment>
                ))}
              </tbody>
            </table>
          )}
          {/* The next page comes on request; the list has no total, because
              nobody counts the trail of tasks, they browse it. */}
          {list.hasNextPage && (
            <p>
              <button className="secondary" onClick={() => list.fetchNextPage()} disabled={list.isFetchingNextPage}>
                {t("Load more")}
              </button>
            </p>
          )}
        </Card>
      </div>
    </>
  );
}

/** The budget key out of a wait reason; empty when the job waits on no budget. */
export function waitedBudget(reason?: string): string {
  const prefix = "awaiting_budget:";
  return reason?.startsWith(prefix) ? reason.slice(prefix.length) : "";
}

/** The job execution attempts together with the result typed for the given operation. */
function Attempts({ jobId }: { jobId: string }) {
  const t = useT();
  const { data, error } = useQuery({
    queryKey: ["attempts", jobId],
    queryFn: () => api.get<Collection<Attempt>>(`/api/v1/jobs/${jobId}/attempts`),
  });
  if (error) return <ErrorBox error={error} />;
  if (!data?.items.length) return <Empty>{t("No execution attempts.")}</Empty>;

  return (
    <div>
      {data.items.map((attempt) => (
        <div key={attempt.id} className="attempt">
          <AttemptHead attempt={attempt} />
          {attempt.stdout && <pre>{attempt.stdout.slice(0, 4000)}</pre>}
          {attempt.stderr && <pre>{attempt.stderr.slice(0, 2000)}</pre>}
        </div>
      ))}
    </div>
  );
}

/**
 * The head of an attempt: its number, state and exit code, the unit
 * before and after, the message and the typed result. The job page shows
 * the same head over the full output, so the two screens agree.
 */
export function AttemptHead({ attempt }: { attempt: Attempt }) {
  const t = useT();
  return (
    <>
      <div className="attempt-head">
        {t("attempt {n}", { n: attempt.attempt_number })} · <JobState state={attempt.status ?? "—"} /> ·{" "}
        {t("exit code {code}", { code: attempt.exit_code ?? "—" })}
        {attempt.replayed && <> · <span className="badge">{t("replayed from journal")}</span></>}
        {attempt.error_code && <> · <span className="badge error">{attempt.error_code}</span></>}
      </div>
      {attempt.unit_state_before && attempt.unit_state_after && (
        <div className="source">
          {t("unit")}: {attempt.unit_state_before.active_state}/{attempt.unit_state_before.sub_state}
          {" "}pid {attempt.unit_state_before.main_pid} → {attempt.unit_state_after.active_state}/
          {attempt.unit_state_after.sub_state} pid {attempt.unit_state_after.main_pid}
        </div>
      )}
      {attempt.message && <div className="source">{attempt.message}</div>}
      {attempt.detail && <TypedResult detail={attempt.detail} />}
    </>
  );
}

type SpaceFact = {
  path: string; filesystem?: string; available_bytes?: number; needed_bytes?: number;
  purpose?: string; basis?: string;
};

/**
 * Where the bytes of a package change go, file system by file system. A
 * separate /var or /boot can be full while "/" has room; the host refuses
 * such a change before the transaction, and the plan is where the operator
 * sees it coming. A fact whose need was not measured says so - an unknown
 * size is not zero.
 */
function SpaceFacts({ facts }: { facts?: SpaceFact[] }) {
  const t = useT();
  if (!facts || facts.length === 0) return null;
  const purposes: Record<string, string> = {
    download: t("download cache"), install: t("installed files"), boot: t("boot files"),
  };
  return (
    <div>
      {facts.map((fact) => {
        const known = fact.basis && fact.basis !== "unknown";
        const short = known && (fact.needed_bytes ?? 0) > (fact.available_bytes ?? 0);
        return (
          <div key={`${fact.purpose}:${fact.path}`} className={short ? "warning" : undefined}
            title={short ? t("The host will refuse this change: the file system has fewer free bytes than the change needs.") : undefined}>
            {fact.path}
            {fact.filesystem && fact.filesystem !== fact.path && ` (${fact.filesystem})`}
            {": "}
            {purposes[fact.purpose ?? ""] ?? fact.purpose}
            {", "}
            {known
              ? t("needs {needed}, {available} free", {
                  needed: bytes(fact.needed_bytes), available: bytes(fact.available_bytes),
                })
              : t("need unknown, {available} free", { available: bytes(fact.available_bytes) })}
            {fact.basis === "download_only" && ` (${t("estimated from the archives alone")})`}
            {fact.basis === "boot_files" && ` (${t("estimated from the running kernel")})`}
          </div>
        );
      })}
    </div>
  );
}

/** The result dependent on the operation type: a package plan, a transaction report, a preflight. */
export function TypedResult({ detail }: { detail: Record<string, any> }) {
  const t = useT();
  switch (detail.kind) {
    case "package_plan":
      return (
        <div className="source">
          {t("plan {manager}: {changes} changes, download {mb} MB", {
            manager: detail.manager, changes: detail.changes?.length ?? 0,
            mb: Math.round((detail.download_bytes ?? 0) / 1048576),
          })}
          {detail.reboot_predicted && `, ${t("reboot predicted")}`}
          <SpaceFacts facts={detail.space} />
        </div>
      );
    case "package_apply":
      return (
        <div className="source">
          {t("{n} packages applied", { n: detail.applied?.length ?? 0 })}
          {detail.reboot_required && `, ${t("reboot required")}`}
          {detail.package_database_broken && `, ${t("PACKAGE DATABASE NEEDS REPAIR")}`}
          {(detail.packages_needing_attention?.length ?? 0) > 0 &&
            `, ${t("needing attention: {names}", { names: detail.packages_needing_attention.join(", ") })}`}
          {/* rpm keeps a package whose %post failed: the transaction is a
              success with a defect, and the defect is named here. */}
          {(detail.scriptlet_errors?.length ?? 0) > 0 && (
            <span className="warning">
              {", "}{t("maintainer script failed: {names}", { names: detail.scriptlet_errors.join(", ") })}
            </span>
          )}
        </div>
      );
    case "domain_enroll":
      return (
        <div className="source">
          {(detail.checks ?? []).map((check: any) => (
            <div key={check.name}>
              {check.passed === true ? "OK" : check.passed === false ? (check.blocking ? t("BLOCKING") : t("warning")) : t("unknown")}
              {" "}{check.name}: {check.detail}
            </div>
          ))}
        </div>
      );
    case "unit_status":
      return (
        <div className="source">
          {(detail.units ?? []).map((unit: any) => (
            <div key={unit.name}>
              {unit.name}: {unit.active_state}/{unit.sub_state}
            </div>
          ))}
        </div>
      );
    case "file_plan":
    case "firewall_plan":
    case "mount_plan":
    case "network_plan":
    case "dns_plan":
    case "ssh_plan":
    case "kernel_module_plan":
    case "time_plan":
    case "device_plan":
    case "certificate_plan":
    case "backup_plan":
    case "trust_plan":
    case "renewal_plan":
      return (
        <div className="source">
          <PlanSummary plan={(detail.plan ?? {}) as Record<string, any>} />
        </div>
      );
    default:
      return null;
  }
}
