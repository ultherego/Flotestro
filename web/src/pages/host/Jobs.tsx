import { Fragment, useState } from "react";
import { Link } from "react-router-dom";
import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, loadedItems, type Collection, type Page } from "../../lib/api";
import { useDebounced } from "../../lib/debounce";
import { toInstant } from "../../lib/format";
import type { Attempt, Job, OperationContract } from "../../lib/types";
import { ErrorBox, ErrorCode, Time, ProgressBar, Empty, JobState } from "../../components/ui";
import { Breakdown } from "../../components/widgets";
import { Foot, ModuleHeader, ModulePage, Section, Summary, Table, Widgets, countWhere, useHost } from "./shared";
import { OPERATIONS_INTERVAL, useProgress } from "../../lib/stream";
import { contractWords, useOperations } from "../Bulk";
import { AttemptHead, hoursAgo, prettyJSON, reasonAccepted } from "../Jobs";
import { useT } from "../../i18n";

/** The states a job passes through before the host has touched anything. */
const BEFORE_START = ["planned", "awaiting_approval", "queued", "leased", "dispatched"];
/** The states in which the host is working on the job. */
const STARTED = ["running"];

/** The states the filter offers, with the words the state badge uses for them; the same list the fleet page offers. */
const JOB_STATES: { value: string; label: string }[] = [
  { value: "awaiting_approval", label: "awaiting approval" },
  { value: "queued", label: "queued" },
  { value: "dispatched", label: "dispatched" },
  { value: "running", label: "running" },
  { value: "succeeded", label: "succeeded" },
  { value: "failed", label: "failed" },
  { value: "timed_out", label: "timed out" },
  { value: "canceled", label: "canceled" },
  { value: "expired", label: "expired" },
];

/**
 * The campaign a job belongs to, as the chip names it: the campaign's name
 * where the job's author carries it ("campaign:<name>"), else the first
 * letters of its identifier.
 */
export function campaignLabel(job: Pick<Job, "campaign_id" | "created_by">): string {
  const author = job.created_by;
  if (author.startsWith("campaign:") && author.length > "campaign:".length) return author.slice("campaign:".length);
  return (job.campaign_id ?? "").slice(0, 8);
}

/** How many jobs one page of the list carries. */
const JOBS_PAGE = 50;

/**
 * Whether a cancel request would stop this job, from the contract of its
 * operation: before the start every operation is cancellable, once the host
 * reported a start only one that stops cleanly.
 */
export function cancellable(job: Job, contract: OperationContract | undefined): boolean {
  if (BEFORE_START.includes(job.state)) return true;
  if (!STARTED.includes(job.state)) return false;
  return contract?.cancel_mode === "safe";
}

/**
 * The jobs of one host. The list is the fleet list narrowed to the host: the
 * same filters, the same pages, the same row that opens on its attempts.
 */
export function HostJobs() {
  const t = useT();
  const host = useHost();
  const queryClient = useQueryClient();
  const progress = useProgress("/api/v1/events");
  const [state, setState] = useState("");
  const [action, setAction] = useState("");
  const [since, setSince] = useState("");
  // The typed prefix reaches the server after a pause, not per keystroke.
  const settledAction = useDebounced(action.trim());
  const [expanded, setExpanded] = useState<string>("");
  // The row whose payload is on screen for approval, and the row whose
  // cancel reason is being typed: one of each at a time.
  const [reviewing, setReviewing] = useState<string>("");
  const [canceling, setCanceling] = useState<string>("");
  const [cancelReason, setCancelReason] = useState("");

  const params = new URLSearchParams({ host_id: host.id, limit: String(JOBS_PAGE) });
  if (state) params.set("state", state);
  if (settledAction) params.set("action_prefix", settledAction);
  if (toInstant(since)) params.set("since", toInstant(since));
  const list = useInfiniteQuery({
    queryKey: ["jobs", host.id, params.toString()],
    queryFn: ({ pageParam }) => {
      const page = new URLSearchParams(params);
      if (pageParam) page.set("cursor", pageParam);
      return api.get<Page<Job>>(`/api/v1/jobs?${page}`);
    },
    initialPageParam: "",
    getNextPageParam: (last) => last.next_cursor || undefined,
    refetchInterval: OPERATIONS_INTERVAL,
  });

  // The cancel button follows the contract of the operation and the
  // operator's permission: a button that leads only to a refusal is an
  // interface defect, and one drawn on a running package transaction would
  const catalogue = useOperations();
  const whoami = useQuery({
    queryKey: ["whoami"],
    queryFn: () => api.get<{ permissions: string[] }>("/api/v1/whoami"),
    staleTime: 5 * 60 * 1000,
  });
  const permissions = whoami.data?.permissions ?? [];
  const mayCancel = permissions.includes("job.cancel");
  const mayApprove = permissions.includes("job.approve");
  const approve = useMutation({
    mutationFn: (job: Job) => api.post(`/api/v1/jobs/${job.id}/approve`, { payload_hash: job.payload_hash }),
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
  const contractOf = (action: string): OperationContract | undefined =>
    catalogue.data?.items.find((item) => item.action === action);
  if (list.error) return <ErrorBox error={list.error} />;

  // The listed jobs by outcome, in the words the state badge uses; the
  // list is unknown until it loads and shows dashes then.
  const jobs = list.data ? loadedItems(list.data) : undefined;
  const succeeded = ["succeeded", "completed"];
  const failed = ["failed", "timed_out", "expired", "partially_applied"];
  const waiting = ["awaiting_approval", "queued", "planned", "planning", "paused", "awaiting_budget"];
  const running = ["dispatched", "running"];
  const operations = Object.entries((jobs ?? []).reduce<Record<string, number>>((acc, job) => {
    const module = job.action_type.split(".")[0];
    acc[module] = (acc[module] ?? 0) + 1;
    return acc;
  }, {})).sort((a, b) => b[1] - a[1]).slice(0, 8);
  // Who ordered the listed jobs: a person by name, every campaign as one
  // requester.
  const requesters = Object.entries((jobs ?? []).reduce<Record<string, number>>((acc, job) => {
    const who = job.created_by.startsWith("campaign:") ? t("campaigns") : job.created_by;
    acc[who] = (acc[who] ?? 0) + 1;
    return acc;
  }, {})).sort((a, b) => b[1] - a[1]).slice(0, 5);
  const filtered = state !== "" || settledAction !== "" || toInstant(since) !== "";
  const columns = 7;

  return (
    <ModulePage>
      <ModuleHeader
        title={t("Jobs")}
        description={t("Every operation requested on this host, newest first.")}
      />
      <Widgets>
      <Summary
        title={t("Outcomes")}
        description={filtered
          ? t("The {n} listed jobs on this host that match the filter, by where they stand.", { n: jobs?.length ?? 0 })
          : t("The last {n} jobs on this host, by where they stand.", { n: jobs?.length ?? JOBS_PAGE })}
        span={8}
        segments={[
          { label: t("succeeded"), value: countWhere(jobs, (job) => succeeded.includes(job.state)), tone: "ok" },
          { label: t("failed"), value: countWhere(jobs, (job) => failed.includes(job.state)), tone: "error" },
          { label: t("running"), value: countWhere(jobs, (job) => running.includes(job.state)), tone: "info" },
          { label: t("waiting"), value: countWhere(jobs, (job) => waiting.includes(job.state)), tone: "warn" },
          { label: t("other"), value: countWhere(jobs, (job) => ![...succeeded, ...failed, ...running, ...waiting].includes(job.state)), tone: "unknown" },
        ]}
      >
        {requesters.length > 0 && (
          <>
            <p className="widget-subhead">{t("Requested by")}</p>
            <Breakdown items={requesters.map(([who, count]) => ({ label: who, value: count }))} />
          </>
        )}
      </Summary>
      <Section title={t("By module")} span={4} description={t("Which modules the operations belong to.")}>
        {!jobs ? (
          <p className="source" style={{ margin: 0 }}>{t("Loading…")}</p>
        ) : !operations.length ? (
          <p className="source" style={{ margin: 0 }}>{t("No jobs for this host.")}</p>
        ) : (
          <Breakdown items={operations.map(([module, count]) => ({ label: <span className="hm-mono">{module}</span>, value: count }))} />
        )}
      </Section>
      <Section
        title={t("Jobs")}
        count={jobs?.length}
        span={12}
        tools={
          <>
            <select value={state} onChange={(e) => setState(e.target.value)}>
              <option value="">{t("state: any")}</option>
              {JOB_STATES.map((item) => <option key={item.value} value={item.value}>{t(item.label)}</option>)}
            </select>
            <input
              placeholder={t("operation prefix, e.g. packages.")}
              value={action}
              onChange={(e) => setAction(e.target.value)}
            />
            <label className="toggle">
              {t("Since")}{" "}
              <input type="datetime-local" value={since} onChange={(e) => setSince(e.target.value)} />
            </label>
            {/* A preset sets the lower bound to the moment of the click:
                "the last day" is what the operator asks after an incident. */}
            <span className="segmented">
              <button type="button" onClick={() => setSince(hoursAgo(1))}>{t("last hour")}</button>
              <button type="button" onClick={() => setSince(hoursAgo(24))}>{t("last 24 h")}</button>
              <button type="button" onClick={() => setSince(hoursAgo(24 * 7))}>{t("last 7 days")}</button>
            </span>
            {filtered && (
              <button type="button" className="secondary" onClick={() => { setState(""); setAction(""); setSince(""); }}>
                {t("Clear filters")}
              </button>
            )}
          </>
        }
        flush
      >
        {cancel.error && <ErrorBox error={cancel.error} />}
        {approve.error && <ErrorBox error={approve.error} />}
        {!jobs ? (
          <Empty>{t("Loading…")}</Empty>
        ) : jobs.length === 0 ? (
          <Empty>{filtered ? t("No job matches the filter.") : t("No jobs for this host.")}</Empty>
        ) : (
          <Table>
            <thead><tr><th>{t("Operation")}</th><th>{t("State")}</th><th>{t("Requested by")}</th><th>{t("Approved by")}</th><th>{t("Result")}</th><th>{t("Created")}</th><th></th></tr></thead>
            <tbody>
              {jobs.map((job) => {
                const contract = contractOf(job.action_type);
                const [, cancelMeaning] = contractWords(t, "cancel", contract?.cancel_mode);
                const open = expanded === job.id;
                return (
                <Fragment key={job.id}>
                <tr>
                  <td>
                    {/* The row opens on its attempts and their typed result;
                        the link opens the job with its full payload, plan
                        and output. */}
                    <button
                      className="expander"
                      aria-expanded={open}
                      aria-label={open ? t("Hide the attempts") : t("Show the attempts")}
                      onClick={() => setExpanded(open ? "" : job.id)}
                    >
                      {open ? "▾" : "▸"}
                    </button>
                    {" "}
                    <Link to={`/jobs/${job.id}`} className="hm-mono" title={job.id}>{job.action_type}</Link>
                    {job.campaign_id && (
                      <>
                        {" "}
                        <Link to={`/campaigns/${job.campaign_id}`} className="chip" title={`${t("Part of a campaign")} · ${job.campaign_id}`}>
                          {t("campaign {id}", { id: campaignLabel(job) })}
                        </Link>
                      </>
                    )}
                  </td>
                  <td>
                    <JobState state={job.state} />
                    {progress.has(job.id) && (
                      <ProgressBar
                        percent={progress.get(job.id)?.percent}
                        step={progress.get(job.id)?.step}
                        total={progress.get(job.id)?.total}
                        caption={progress.get(job.id)?.message}
                      />
                    )}
                  </td>
                  <td>
                    {/* A campaign's job is requested by the campaign; the
                        chip beside the operation already names it. */}
                    {job.created_by.startsWith("campaign:") ? <span className="source">{t("the campaign")}</span> : job.created_by}
                  </td>
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
                  {/* The result is the typed answer of the host: an error
                      code with its guide, or a status other than the one
                      the state badge already shows. */}
                  <td>
                    {job.result_error_code
                      ? <ErrorCode code={job.result_error_code} />
                      : job.result_status && job.result_status !== job.state
                        ? <JobState state={job.result_status} />
                        : <span className="source">—</span>}
                  </td>
                  <td><Time value={job.created_at} /></td>
                  <td>
                    <div className="operations">
                      {mayApprove && job.state === "awaiting_approval" && (
                        <button
                          onClick={() => { setReviewing(reviewing === job.id ? "" : job.id); setCanceling(""); }}
                          disabled={approve.isPending}
                          aria-expanded={reviewing === job.id}
                        >
                          {t("Approve")}
                        </button>
                      )}
                      {mayCancel && cancellable(job, contract) ? (
                        <button
                          className="secondary"
                          title={STARTED.includes(job.state) ? cancelMeaning : t("The host has not started this yet; a cancel stops it before it does.")}
                          aria-expanded={canceling === job.id}
                          onClick={() => { setCanceling(canceling === job.id ? "" : job.id); setReviewing(""); }}
                        >
                          {t("Cancel")}
                        </button>
                      ) : STARTED.includes(job.state) && contract?.cancel_mode ? (
                        <span className="source" title={cancelMeaning}>{t("runs to its end")}</span>
                      ) : null}
                    </div>
                  </td>
                </tr>
                {/* An approval is given to a payload the operator has read:
                    the row opens with it, and the button that binds the
                    consent to its hash stands under it. */}
                {reviewing === job.id && job.state === "awaiting_approval" && (
                  <tr className="detail-row">
                    <td colSpan={columns}>
                      <p className="source" style={{ marginTop: 0 }}>
                        {t("You approve exactly this payload for {operation} on {host}; the consent is bound to hash {hash}.", {
                          operation: job.action_type, host: host.hostname, hash: job.payload_hash.slice(0, 12),
                        })}
                      </p>
                      <pre>{prettyJSON(job.payload)}</pre>
                      <div className="operations">
                        <button onClick={() => approve.mutate(job)} disabled={approve.isPending}>{t("Approve this payload")}</button>
                        <button className="secondary" onClick={() => setReviewing("")}>{t("Back")}</button>
                      </div>
                    </td>
                  </tr>
                )}
                {/* A cancel carries a reason into the trail, so the reason
                    is typed before the button works; the host job list
                    used to send a fixed sentence, which told nobody why. */}
                {canceling === job.id && (
                  <tr className="detail-row">
                    <td colSpan={columns}>
                      <div className="operations">
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
                      </div>
                    </td>
                  </tr>
                )}
                {open && (
                  <tr className="detail-row">
                    <td colSpan={columns}>
                      <Attempts jobId={job.id} />
                      <p className="source" style={{ marginBottom: 0 }}>
                        <Link to={`/jobs/${job.id}`}>{t("Open the job: full payload, plan and output")}</Link>
                        {" · "}
                        <Link to={`/hosts/${host.id}/logs?job=${job.id}`}>{t("Read the journal of this job")}</Link>
                      </p>
                    </td>
                  </tr>
                )}
                </Fragment>
                );
              })}
            </tbody>
          </Table>
        )}
        {/* The next page comes on request; the list has no total, because
            nobody counts the history of a host, they browse it. */}
        {list.hasNextPage && (
          <Foot>
            <span>{t("{n} listed", { n: jobs?.length ?? 0 })}</span>
            <button className="secondary" onClick={() => list.fetchNextPage()} disabled={list.isFetchingNextPage}>
              {list.isFetchingNextPage ? t("Loading…") : t("Load more")}
            </button>
          </Foot>
        )}
      </Section>
      </Widgets>
    </ModulePage>
  );
}

/**
 * The attempts of a job with the result typed for its operation: the same
 * head the fleet list and the job page show, so the three screens agree on
 * what an attempt did.
 */
function Attempts({ jobId }: { jobId: string }) {
  const t = useT();
  const { data, error } = useQuery({
    queryKey: ["attempts", jobId],
    queryFn: () => api.get<Collection<Attempt>>(`/api/v1/jobs/${jobId}/attempts`),
  });
  if (error) return <ErrorBox error={error} />;
  if (!data) return <p className="source" style={{ margin: 0 }}>{t("Loading…")}</p>;
  if (!data.items.length) return <p className="source" style={{ margin: 0 }}>{t("No execution attempts.")}</p>;
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
