import { useEffect, useRef, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, fetchWithCredentials, loadedItems, type Collection, type Page } from "../../lib/api";
import { exportAddress, exportFileName } from "../../components/ExportButton";
import { useToast } from "../../components/Toast";
import { stateName } from "../../components/ui";
import { useDebounced } from "../../lib/debounce";
import { absoluteTime, relativeTime, toInstant } from "../../lib/format";
import { needsReason } from "../../lib/actions";
import { OPERATIONS_INTERVAL, REFRESH_INTERVAL, useProgress } from "../../lib/stream";
import type { Campaign, FleetActivity, Job } from "../../lib/types";
import { useT } from "../../i18n";
import { Board } from "../Board";
import type { BoardEntry } from "../../components/board";
import {
  Band, Bars, Bones, Card, Chart, Empty, Field, Fields, Meter, Modal, Note, Pill, Presets, Problem, RowsPerPage, Table, Tag, Tags, Toolbar, TwoLine, type Segment, type Tone,
} from "../kit";

/**
 * The operations: one row is one operation on one host.
 *
 * Everything that narrows the list is a question put to the server, and
 * the band over the table counts the rows the server sent back - so the
 * summary and the list are the same answer read twice, never two answers.
 *
 * A decision is taken in a dialog and not in a row that unfolds. An
 * approval is given to a payload somebody has read, and the consent is
 * bound to the hash of exactly that payload; a cancel is recorded with a
 * reason the trail keeps. Both are things that cannot be taken back, so
 * they get the one piece of the kit that stops the screen and asks.
 */

/** The states the filter offers, in the order a job moves through them. */
const STATES = [
  "awaiting_approval", "queued", "dispatched", "running",
  "succeeded", "failed", "timed_out", "canceled", "expired",
];

/** The states after which the same order can be placed again: the job is over and did not do its work. */
const REORDERABLE = ["failed", "timed_out", "canceled", "expired"];

/** The columns the server will order the list by, as it names them. */
const SORTS = ["created_at", "finished_at", "state", "action_type", "hostname"];

/** The shortest reason the control plane records with a decision. */
export const MIN_REASON = 8;

/** Whether a reason is long enough for the trail to be worth keeping. */
export function reasonAccepted(reason: string): boolean {
  return reason.trim().length >= MIN_REASON;
}

/** What narrows the list, as the address carries it. */
export type Filters = {
  state: string; action: string; actor: string; hostname: string; host_id: string;
  fanout_id: string; campaign_id: string; error_code: string; since: string; until: string; sort: string;
};

const KEYS: (keyof Filters)[] = [
  "state", "action", "actor", "hostname", "host_id", "fanout_id", "campaign_id", "error_code", "since", "until", "sort",
];

export const NO_FILTERS: Filters = {
  state: "", action: "", actor: "", hostname: "", host_id: "", fanout_id: "",
  campaign_id: "", error_code: "", since: "", until: "", sort: "",
};

/** The filters read off the address: a tile, a fan-out link or a bookmark sets them. */
export function readFilters(address: URLSearchParams): Filters {
  const out = { ...NO_FILTERS };
  for (const key of KEYS) out[key] = address.get(key) ?? "";
  return out;
}

/** The address the filters make: only the ones that are set, so an unfiltered screen is a plain /next/jobs. */
export function filterAddress(filters: Filters): URLSearchParams {
  const out = new URLSearchParams();
  for (const key of KEYS) if (filters[key]) out.set(key, filters[key]);
  return out;
}

/** Whether anything narrows the list. The order only arranges it and does not count. */
export function anyFilter(filters: Filters): boolean {
  return KEYS.some((key) => key !== "sort" && filters[key] !== "");
}

/** A moment some hours back, written the way a datetime-local field takes it: local time, to the minute. */
export function hoursAgo(hours: number, now: Date = new Date()): string {
  const at = new Date(now.getTime() - hours * 3600 * 1000);
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${at.getFullYear()}-${pad(at.getMonth() + 1)}-${pad(at.getDate())}T${pad(at.getHours())}:${pad(at.getMinutes())}`;
}

/** The payload as the operator reads it, whatever shape it arrived in. */
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

/** The budget key out of a wait reason; empty when nothing holds the job. */
export function waitedBudget(reason?: string): string {
  const prefix = "awaiting_budget:";
  return reason?.startsWith(prefix) ? reason.slice(prefix.length) : "";
}

/**
 * The state of a job as a tone.
 *
 * What waits for a person is not what broke, and what somebody stopped is
 * neither: three different things an operator decides between at a glance,
 * so they may not share a colour.
 */
export function jobTone(state: string): Tone {
  if (["succeeded", "no_change"].includes(state)) return "ok";
  if (["failed", "timed_out", "expired", "lease_expired"].includes(state)) return "error";
  if (["awaiting_approval", "awaiting_budget", "awaiting_lock"].includes(state)) return "warn";
  if (["canceled", "cancelled", "canceling", "cancel_requested", "rejected", "ineligible", "superseded_by_result"].includes(state)) {
    return "unknown";
  }
  if (["queued", "planned", "leased"].includes(state)) return "neutral";
  return "info";
}

/**
 * The address of the Bulk workspace with the same order written into it:
 * the operation, the payload it carried and the one host it ran on.
 */
export function orderAgainAddress(job: Pick<Job, "action_type" | "payload" | "host_id" | "hostname">): string {
  const query = new URLSearchParams({
    action: job.action_type,
    name: `${job.action_type} again on ${job.hostname || job.host_id.slice(0, 8)}`,
    payload: JSON.stringify(job.payload ?? {}, null, 2),
  });
  query.append("host_id", job.host_id);
  return `/bulk?${query}`;
}

/** What a decision is being taken on, and which decision it is. */
type Asking = { verdict: "approve" | "cancel"; jobs: Job[] };

export function Jobs() {
  const t = useT();
  // The address carries the filters, so a tile on the dashboard, a link
  // out of a fan-out and a bookmark all land on the same narrowed list.
  const [address, setAddress] = useSearchParams();
  const [filters, setFilters] = useState<Filters>(() => readFilters(address));
  const set = (key: keyof Filters, value: string) => setFilters((before) => ({ ...before, [key]: value }));
  // The address last written here. It tells a change typed on the screen
  // from a link followed into it, so the two sides follow each other
  // instead of chasing each other round.
  const written = useRef(address.toString());
  useEffect(() => {
    const next = filterAddress(filters).toString();
    if (next !== written.current) {
      written.current = next;
      setAddress(new URLSearchParams(next), { replace: true });
    }
  }, [filters, setAddress]);
  useEffect(() => {
    const now = address.toString();
    if (now !== written.current) {
      written.current = now;
      setFilters(readFilters(address));
    }
  }, [address]);

  const [size, setSize] = useState(50);
  const [picked, setPicked] = useState<Set<string>>(new Set());
  const [asking, setAsking] = useState<Asking | null>(null);
  const [reason, setReason] = useState("");
  const queryClient = useQueryClient();

  // The typed filters reach the server after a pause rather than per
  // keystroke: a list is re-read on every one of them otherwise.
  const action = useDebounced(filters.action.trim());
  const actor = useDebounced(filters.actor.trim());
  const hostname = useDebounced(filters.hostname.trim());
  const campaign = useDebounced(filters.campaign_id.trim());
  const errorCode = useDebounced(filters.error_code.trim());

  // An order naming a column the server has not got is left out rather
  // than sent to be refused; the server's own default is the newest first.
  const sort = SORTS.includes(filters.sort.split(":")[0]) ? filters.sort : "";

  const query = new URLSearchParams({ limit: String(size) });
  if (sort) query.set("sort", sort);
  if (filters.state) query.set("state", filters.state);
  if (action) query.set("action", action);
  if (actor) query.set("actor", actor);
  if (hostname) query.set("hostname", hostname);
  if (filters.host_id) query.set("host_id", filters.host_id);
  if (filters.fanout_id) query.set("fanout_id", filters.fanout_id);
  if (campaign) query.set("campaign_id", campaign);
  if (errorCode) query.set("error_code", errorCode);
  if (toInstant(filters.since)) query.set("since", toInstant(filters.since));
  if (toInstant(filters.until)) query.set("until", toInstant(filters.until));

  const list = useInfiniteQuery({
    queryKey: ["jobs", query.toString()],
    queryFn: ({ pageParam }) => {
      const page = new URLSearchParams(query);
      if (pageParam) page.set("cursor", pageParam);
      return api.get<Page<Job>>(`/api/v1/jobs?${page}`);
    },
    initialPageParam: "",
    getNextPageParam: (last) => last.next_cursor || undefined,
    // The list has no stream of its own, because what is on it also changes
    // through other operators' decisions and through jobs expiring.
    refetchInterval: OPERATIONS_INTERVAL,
  });

  // One stream per tab carries the progress of everything in flight and
  // wakes the list when one of them ends.
  const progress = useProgress("/api/v1/events");

  const jobs = loadedItems(list.data);
  const loaded = list.data !== undefined;

  // The jobs name their campaign by identifier alone; the names are read
  // once, and only once the list is showing a job that has one.
  const campaigns = useQuery({
    queryKey: ["campaigns", "names"],
    queryFn: () => api.get<Collection<Campaign>>("/api/v1/campaigns?limit=200"),
    enabled: jobs.some((job) => job.campaign_id),
    retry: false,
    staleTime: 60 * 1000,
  });
  const campaignName = (id: string) => campaigns.data?.items.find((one) => one.id === id)?.name;

  // The chart is the whole fleet's last day, counted in the database: it
  // answers a different question from the list and so takes no filter.
  const activity = useQuery({
    queryKey: ["fleet-activity"],
    queryFn: () => api.get<FleetActivity>("/api/v1/fleet/activity?hours=24"),
    refetchInterval: REFRESH_INTERVAL,
  });

  /* A batch decision is the single call repeated, so the trail carries one
     record per job, exactly as it would had each been clicked in turn. The
     first refusal stops the run: the rest of the set is still ticked, and
     the reader is told which job refused and why. */
  const decide = useMutation({
    mutationFn: async ({ verdict, jobs: set, reason: why }: Asking & { reason: string }) => {
      for (const job of set) {
        try {
          if (verdict === "approve") {
            await api.post(`/api/v1/jobs/${job.id}/approve`, {
              payload_hash: job.payload_hash,
              reason: why.trim() || undefined,
            });
          } else {
            await api.post(`/api/v1/jobs/${job.id}/cancel`, { reason: why.trim() });
          }
          setPicked((before) => {
            const after = new Set(before);
            after.delete(job.id);
            return after;
          });
        } finally {
          void queryClient.invalidateQueries({ queryKey: ["jobs"] });
        }
      }
    },
    onSuccess: () => { setAsking(null); setReason(""); },
  });

  const ask = (verdict: "approve" | "cancel", set: Job[]) => {
    decide.reset();
    setReason("");
    setAsking({ verdict, jobs: set });
  };

  if (list.error) return <Problem>{String(list.error)}</Problem>;

  // The band counts what the server returned for this filter. Before the
  // answer arrives nothing is counted, and it says so rather than drawing
  // a fleet in which nothing is happening.
  const count = (...states: string[]) =>
    (loaded ? jobs.filter((job) => states.includes(job.state)).length : undefined);
  const band: Segment[] = [
    { label: t("Awaiting approval"), value: count("awaiting_approval"), tone: "warn" },
    { label: t("Queued"), value: count("queued", "leased", "dispatched"), tone: "neutral" },
    { label: t("Running"), value: count("running"), tone: "info" },
    { label: t("Succeeded"), value: count("succeeded"), tone: "ok" },
    { label: t("Failed"), value: count("failed", "timed_out", "expired"), tone: "error" },
    { label: t("Canceled"), value: count("canceled", "cancelled", "rejected"), tone: "unknown" },
  ];
  const listed = t("among the {n} listed", { n: jobs.length });

  // The listed jobs by operation, the busiest first; a long tail is said
  // in words under the bars rather than drawn as a hundred of them.
  const byOperation = Object.entries(
    jobs.reduce<Record<string, number>>((all, job) => {
      all[job.action_type] = (all[job.action_type] ?? 0) + 1;
      return all;
    }, {}),
  ).sort((a, b) => b[1] - a[1]);
  const shownOperations = byOperation.slice(0, 10);

  const hourLabel = (iso: string) => new Date(iso).toLocaleTimeString([], { hour: "2-digit" });
  const day = activity.data;

  // The batch works on the ticked jobs still awaiting approval: one that
  // somebody else decided in the meantime simply drops out of the set.
  const awaiting = jobs.filter((job) => job.state === "awaiting_approval");
  const chosen = awaiting.filter((job) => picked.has(job.id));
  const allPicked = awaiting.length > 0 && chosen.length === awaiting.length;
  const pick = (id: string) => setPicked((before) => {
    const after = new Set(before);
    if (after.has(id)) after.delete(id); else after.add(id);
    return after;
  });

  const wantsReason = asking !== null
    && (asking.verdict === "cancel" || asking.jobs.some((job) => needsReason(job.action_type)));
  const ready = !wantsReason || reasonAccepted(reason);

  return (
    <>
      <Board screen={JOBS_SCREEN} catalogue={JOBS} drawn={{
        state: (
          <Card title={t("State")} note={listed}>
            <Band segments={band} testId="job-states" />
          </Card>
        ),
        activity: (
          <Card title={t("Operations, last 24 h")} note={t("Finished per hour, by outcome, over the whole fleet.")}>
            {day ? (
              <Chart
                labels={day.hours.map(hourLabel)}
                everyLabel={3}
                series={[
                  { name: t("Succeeded"), tone: "ok", values: day.succeeded },
                  { name: t("Failed"), tone: "error", values: day.failed },
                  { name: t("Other"), tone: "unknown", values: day.other },
                ]}
              />
            ) : (
              activity.isError ? <Empty>{t("The last day could not be counted.")}</Empty> : <Bones rows={3} height={28} />
            )}
          </Card>
        ),
        operations: (
          <Card
            title={t("By operation")}
            note={listed}
            foot={byOperation.length > shownOperations.length
              ? t("and {n} more operations", { n: byOperation.length - shownOperations.length })
              : undefined}
          >
            {shownOperations.length === 0
              ? (loaded ? <Empty>{t("No jobs.")}</Empty> : <Bones rows={4} />)
              : <Bars items={shownOperations.map(([one, n]) => ({
                  label: <code title={one}>{one}</code>, value: n,
                }))} />}
          </Card>
        ),
        jobs: (
          <Card
            title={t("Jobs")}
            flush
            tools={<Export params={query} />}
            foot={
              <>
                <span className="fl-note">{t("{n} listed", { n: jobs.length })}</span>
                <RowsPerPage size={size} onSize={setSize} />
                {list.hasNextPage && (
                  <button
                    type="button"
                    className="fl-quiet fl-small"
                    onClick={() => void list.fetchNextPage()}
                    disabled={list.isFetchingNextPage}
                    data-testid="more"
                  >
                    {list.isFetchingNextPage ? t("loading…") : t("Load more")}
                  </button>
                )}
              </>
            }
          >
            <Toolbar
              end={
                <select
                  value={filters.sort}
                  onChange={(event) => set("sort", event.target.value)}
                  aria-label={t("Order")}
                  data-testid="sort"
                >
                  <option value="">{t("newest first")}</option>
                  <option value="created_at:asc">{t("oldest first")}</option>
                  <option value="finished_at:desc">{t("last to finish first")}</option>
                  <option value="state:asc">{t("by state")}</option>
                  <option value="action_type:asc">{t("by operation")}</option>
                  <option value="hostname:asc">{t("by host")}</option>
                </select>
              }
            >
              <select
                value={filters.state}
                onChange={(event) => set("state", event.target.value)}
                aria-label={t("state: any")}
                data-testid="state"
              >
                <option value="">{t("state: any")}</option>
                {STATES.map((one) => <option key={one} value={one}>{t(stateName(one))}</option>)}
              </select>
              <input
                value={filters.action}
                onChange={(event) => set("action", event.target.value)}
                placeholder={t("operation")}
                aria-label={t("operation")}
                title={t("the operation, e.g. unit.restart")}
                data-testid="action"
              />
              <input
                value={filters.hostname}
                onChange={(event) => set("hostname", event.target.value)}
                placeholder={t("host name")}
                aria-label={t("host name")}
                data-testid="hostname"
              />
              <input
                value={filters.actor}
                onChange={(event) => set("actor", event.target.value)}
                placeholder={t("requested by")}
                aria-label={t("requested by")}
                data-testid="actor"
              />
              <input
                value={filters.campaign_id}
                onChange={(event) => set("campaign_id", event.target.value)}
                placeholder={t("campaign ID")}
                aria-label={t("campaign ID")}
                data-testid="campaign"
              />
              <input
                value={filters.error_code}
                onChange={(event) => set("error_code", event.target.value)}
                placeholder={t("error code")}
                aria-label={t("error code")}
                data-testid="error-code"
              />
              <input
                type="datetime-local"
                value={filters.since}
                onChange={(event) => set("since", event.target.value)}
                aria-label={t("Since")}
                data-testid="since"
              />
              <input
                type="datetime-local"
                value={filters.until}
                onChange={(event) => set("until", event.target.value)}
                aria-label={t("Until")}
                data-testid="until"
              />
              {/* A preset sets the lower bound and lifts the upper one:
                  "the last day" reaches now, whatever Until said before. */}
              <Presets
                label={t("Time range")}
                options={([[1, t("last hour")], [24, t("last 24 h")], [24 * 7, t("last 7 days")]] as const).map(([hours, label]) => ({
                  label,
                  onPick: () => setFilters((before) => ({ ...before, since: hoursAgo(hours), until: "" })),
                }))}
              />
              {/* The host and the fan-out arrive from a link rather than from
                  a field, so they stand as chips the reader can take off. */}
              {(filters.host_id || filters.fanout_id) && (
                <Tags>
                  {filters.host_id && (
                    <Tag>
                      {t("host {id}", { id: filters.host_id.slice(0, 8) })}
                      <button type="button" className="fl-word" aria-label={t("Remove the host filter")}
                              onClick={() => set("host_id", "")}>×</button>
                    </Tag>
                  )}
                  {filters.fanout_id && (
                    <Tag>
                      {t("fan-out {id}", { id: filters.fanout_id.slice(0, 8) })}
                      <button type="button" className="fl-word" aria-label={t("Remove the fan-out filter")}
                              onClick={() => set("fanout_id", "")}>×</button>
                    </Tag>
                  )}
                </Tags>
              )}
              {anyFilter(filters) && (
                <button type="button" className="fl-plain" data-testid="clear"
                        onClick={() => setFilters({ ...NO_FILTERS, sort: filters.sort })}>
                  {t("Clear filters")}
                </button>
              )}
            </Toolbar>

            {/* One decision over many jobs is one reason for all of them,
                and every call still goes to the trail on its own. */}
            {awaiting.length > 0 && (
              <Toolbar>
                <span className="fl-note">
                  {t("{n} of {total} awaiting jobs ticked", { n: chosen.length, total: awaiting.length })}
                </span>
                <button type="button" className="fl-small" disabled={chosen.length === 0}
                        onClick={() => ask("approve", chosen)} data-testid="approve-ticked">
                  {t("Approve ticked")}
                </button>
                <button type="button" className="fl-danger fl-small" disabled={chosen.length === 0}
                        onClick={() => ask("cancel", chosen)} data-testid="cancel-ticked">
                  {t("Cancel ticked")}
                </button>
              </Toolbar>
            )}

            <Table
              rows={jobs}
              keyOf={(job) => job.id}
              rowTestId={(job) => `job-${job.id}`}
              testId="jobs"
              loading={list.isLoading} empty={t("No job matches this.")}
              columns={[
                {
                  key: "pick",
                  head: awaiting.length > 0 ? (
                    <input
                      type="checkbox"
                      checked={allPicked}
                      onChange={() => setPicked(allPicked ? new Set() : new Set(awaiting.map((job) => job.id)))}
                      aria-label={t("Tick every job awaiting approval")}
                      data-testid="pick-all"
                    />
                  ) : undefined,
                  cell: (job) => job.state === "awaiting_approval" ? (
                    <input
                      type="checkbox"
                      checked={picked.has(job.id)}
                      onChange={() => pick(job.id)}
                      aria-label={t("Tick job {id}", { id: job.id.slice(0, 8) })}
                    />
                  ) : null,
                },
                {
                  key: "operation",
                  head: t("Operation"),
                  tight: true,
                  cell: (job) => (
                    <TwoLine sub={job.campaign_id
                      ? <Link to={`/campaigns/${job.campaign_id}`} title={t("Part of a campaign")}>
                          {campaignName(job.campaign_id)
                            ? t("campaign {name}", { name: campaignName(job.campaign_id) ?? "" })
                            : t("campaign {id}", { id: job.campaign_id.slice(0, 8) })}
                        </Link>
                      : undefined}>
                      <Link to={`/jobs/${job.id}`}><code title={job.action_type}>{job.action_type}</code></Link>
                    </TwoLine>
                  ),
                },
                {
                  key: "host",
                  head: t("Host"),
                  tight: true,
                  cell: (job) => (
                    <Link to={`/next/hosts/${job.host_id}`} className="fl-nowrap">
                      {job.hostname || job.host_id.slice(0, 8)}
                    </Link>
                  ),
                },
                {
                  key: "state",
                  head: t("State"),
                  cell: (job) => {
                    const budget = job.state === "queued" ? waitedBudget(job.wait_reason) : "";
                    const moving = progress.get(job.id);
                    return (
                      <Tags>
                        <Pill tone={jobTone(job.state)}>{t(stateName(job.state))}</Pill>
                        {/* A queued job the budgets refused says so beside its
                            state: without the key it stands in the queue for no
                            visible reason and reads as a forgotten job. */}
                        {budget && (
                          <Pill tone="warn" title={t("The fleet or the site has no free capacity for this operation; the job starts when a token of this budget is free.")}>
                            {t("waiting for budget {key}", { key: budget })}
                          </Pill>
                        )}
                        {/* The reading accompanies the state and never replaces
                            it: the reader is to see both that it runs and how
                            far it has got. */}
                        {moving && (
                          <Meter
                            share={(moving.percent ?? 0) / 100}
                            tone="info"
                            text={moving.percent !== undefined
                              ? `${Math.round(moving.percent)}%`
                              : t("{step} of {total}", { step: moving.step ?? 0, total: moving.total ?? 0 })}
                          />
                        )}
                      </Tags>
                    );
                  },
                },
                {
                  key: "by",
                  head: t("Requested by"),
                  minor: true,
                  tight: true,
                  cell: (job) => <span title={job.created_by}>{job.created_by}</span>,
                },
                {
                  key: "approved",
                  head: t("Approved by"),
                  minor: true,
                  tight: true,
                  // One approval starts nothing where two are required: the
                  // reader is to see whom we are still waiting for rather than
                  // press Approve and watch nothing happen.
                  cell: (job) => job.required_approvals > 1
                    ? (
                      <span title={job.approved_by}>
                        {t("{collected} of {required} approvals", {
                          collected: job.collected_approvals, required: job.required_approvals,
                        })}
                      </span>
                    )
                    : job.approved_by
                      ? <span title={job.approved_by}>{job.approved_by}</span>
                      : <span className="fl-faint">—</span>,
                },
                {
                  key: "result",
                  head: t("Result"),
                  cell: (job) => job.result_error_code
                    ? <Pill tone="error" title={job.result_message}>{job.result_error_code}</Pill>
                    : job.result_status
                      ? <span title={job.result_message}>{t(stateName(job.result_status))}</span>
                      : <span className="fl-faint">—</span>,
                },
                {
                  key: "created",
                  head: t("Created"),
                  minor: true,
                  cell: (job) => <span title={absoluteTime(job.created_at)}>{relativeTime(job.created_at)}</span>,
                },
                {
                  key: "finished",
                  head: t("Finished"),
                  minor: true,
                  cell: (job) => job.finished_at
                    ? <span title={absoluteTime(job.finished_at)}>{relativeTime(job.finished_at)}</span>
                    : <span className="fl-faint">—</span>,
                },
                {
                  key: "do",
                  actions: true,
                  cell: (job) => job.state === "awaiting_approval" ? (
                    <>
                      <button type="button" className="fl-small" onClick={() => ask("approve", [job])}
                              data-testid={`approve-${job.id}`}>
                        {t("Approve")}
                      </button>
                      <button type="button" className="fl-danger fl-small" onClick={() => ask("cancel", [job])}
                              data-testid={`cancel-${job.id}`}>
                        {t("Cancel")}
                      </button>
                    </>
                  ) : REORDERABLE.includes(job.state) ? (
                    <Link
                      className="fl-btn fl-quiet fl-small"
                      to={orderAgainAddress(job)}
                      title={t("Opens the Bulk workspace with the same operation, payload and host written in.")}
                    >
                      {t("Order again")}
                    </Link>
                  ) : null,
                },
              ]}
            />
          </Card>
        ),
      }} />

      {asking && (
        <Modal
          title={asking.jobs.length === 1
            ? (asking.verdict === "approve" ? t("Approve this job") : t("Cancel this job"))
            : (asking.verdict === "approve"
              ? t("Approve {n} jobs", { n: asking.jobs.length })
              : t("Cancel {n} jobs", { n: asking.jobs.length }))}
          onClose={() => { setAsking(null); setReason(""); }}
          actions={
            <>
              <button type="button" className="fl-quiet" onClick={() => { setAsking(null); setReason(""); }}>
                {t("Back")}
              </button>
              <button
                type="button"
                className={asking.verdict === "cancel" ? "fl-danger" : undefined}
                disabled={!ready || decide.isPending}
                onClick={() => decide.mutate({ ...asking, reason })}
                data-testid="confirm"
                title={ready ? undefined : t("The decision is recorded with a reason of at least 8 characters.")}
              >
                {asking.verdict === "approve"
                  ? t("Approve this payload")
                  : asking.jobs.length === 1 ? t("Cancel this job") : t("Cancel these jobs")}
              </button>
            </>
          }
        >
          {asking.verdict === "approve" && asking.jobs.length === 1 ? (
            <>
              <Note>
                {t("You approve exactly this payload for {operation} on {host}; the consent is bound to hash {hash}.", {
                  operation: asking.jobs[0].action_type,
                  host: asking.jobs[0].hostname || asking.jobs[0].host_id.slice(0, 8),
                  hash: asking.jobs[0].payload_hash.slice(0, 12),
                })}
              </Note>
              <pre className="fl-mono" data-testid="payload">{prettyJSON(asking.jobs[0].payload)}</pre>
            </>
          ) : (
            <Note>
              {asking.verdict === "approve"
                ? t("Each of these jobs is approved against the hash of the payload it already carries; nothing is approved that has changed since.")
                : t("Every one of these jobs is cancelled separately and the reason is recorded next to each.")}
            </Note>
          )}
          <Fields>
            <Field
              label={t("Reason for the trail")}
              wide
              hint={wantsReason
                ? t("At least 8 characters; this operation is one the control plane records a reason for.")
                : t("Optional for this operation.")}
            >
              <input
                autoFocus
                value={reason}
                onChange={(event) => setReason(event.target.value)}
                data-testid="reason"
              />
            </Field>
          </Fields>
          {decide.error && <Problem>{String(decide.error)}</Problem>}
        </Modal>
      )}
    </>
  );
}

/**
 * The list as a file: the same filter the screen is showing, every page of
 * it, counted by the server rather than by what happens to be loaded.
 */
function Export({ params }: { params: URLSearchParams }) {
  const t = useT();
  const toast = useToast();
  const [busy, setBusy] = useState(false);
  const download = async () => {
    setBusy(true);
    try {
      const response = await fetchWithCredentials(exportAddress("/api/v1/jobs", params));
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
      toast.error(t("The export failed: {message}", { message: error instanceof Error ? error.message : String(error) }));
    } finally {
      setBusy(false);
    }
  };
  return (
    <button type="button" className="fl-quiet fl-small" onClick={() => void download()} disabled={busy} data-testid="export">
      {busy ? t("Exporting…") : t("Export CSV")}
    </button>
  );
}

export const JOBS_SCREEN = "next_jobs";

export const JOBS: BoardEntry[] = [
  { key: "state", title: "State", width: 12, height: 2 },
  { key: "activity", title: "Operations, last 24 h", width: 8, height: 3 },
  { key: "operations", title: "By operation", width: 4, height: 2 },
  { key: "jobs", title: "Jobs", width: 12, height: 6 },
];
