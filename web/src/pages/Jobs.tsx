import { Fragment, useState } from "react";
import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useSearchParams } from "react-router-dom";
import { api, loadedItems, LIST_PAGE, type Collection, type Page } from "../lib/api";
import { useDebounced } from "../lib/debounce";
import { toInstant } from "../lib/format";
import { PlanSummary } from "../components/plan";
import type { Attempt, FleetActivity, Job } from "../lib/types";
import { ErrorBox, ErrorCode, Time, ProgressBar, Empty, JobState } from "../components/ui";
import { Card, PageHeader, Toolbar } from "../components/layout";
import { BarChart, Breakdown, StatusBar } from "../components/widgets";
import { OPERATIONS_INTERVAL, REFRESH_INTERVAL, useProgress } from "../lib/stream";
import { useT } from "../i18n";

/** The states the filter offers. */
const JOB_STATES = ["awaiting_approval", "queued", "dispatched", "running", "succeeded", "failed", "timed_out", "canceled", "expired"];

/**
 * The job list with approvals. An approval confirms the plan hash.
 *
 * The filters run on the server and the list grows page by page: the fleet
 * orders thousands of tasks a week, and "the failed ones since Monday" is a
 * question the database answers better than a screen scanning a list.
 */
export function Jobs() {
  const t = useT();
  // A tile on the dashboard links here with a filter already set.
  const [initial] = useSearchParams();
  const [state, setState] = useState(initial.get("state") ?? "");
  const [action, setAction] = useState(initial.get("action") ?? "");
  const [actor, setActor] = useState(initial.get("actor") ?? "");
  const [campaignID, setCampaignID] = useState(initial.get("campaign_id") ?? "");
  const [errorCode, setErrorCode] = useState(initial.get("error_code") ?? "");
  const [since, setSince] = useState(initial.get("since") ?? "");
  const [until, setUntil] = useState(initial.get("until") ?? "");
  const [expanded, setExpanded] = useState<string>("");
  const queryClient = useQueryClient();
  // The typed filters reach the server after a pause, not per keystroke.
  const settledAction = useDebounced(action.trim());
  const settledActor = useDebounced(actor.trim());
  const settledCampaign = useDebounced(campaignID.trim());
  const settledError = useDebounced(errorCode.trim());

  const params = new URLSearchParams({ limit: String(LIST_PAGE) });
  if (state) params.set("state", state);
  if (settledAction) params.set("action", settledAction);
  if (settledActor) params.set("actor", settledActor);
  if (settledCampaign) params.set("campaign_id", settledCampaign);
  if (settledError) params.set("error_code", settledError);
  if (toInstant(since)) params.set("since", toInstant(since));
  if (toInstant(until)) params.set("until", toInstant(until));

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
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["jobs"] }),
  });
  const cancel = useMutation({
    mutationFn: (job: Job) =>
      api.post(`/api/v1/jobs/${job.id}/cancel`, { reason: "canceled from the panel" }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["jobs"] }),
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
          <Toolbar end={<span>{t("{n} listed", { n: jobs.length })}</span>}>
            <select value={state} onChange={(e) => setState(e.target.value)}>
              <option value="">{t("state: any")}</option>
              {JOB_STATES.map((value) => <option key={value} value={value}>{value}</option>)}
            </select>
            <input placeholder={t("operation, e.g. unit.restart")} value={action} onChange={(e) => setAction(e.target.value)} />
            <input placeholder={t("requested by")} value={actor} onChange={(e) => setActor(e.target.value)} />
            <input placeholder={t("campaign ID")} value={campaignID} onChange={(e) => setCampaignID(e.target.value)} />
            <input placeholder={t("error code")} value={errorCode} onChange={(e) => setErrorCode(e.target.value)} />
            <label className="toggle">
              {t("Since")}{" "}
              <input type="datetime-local" value={since} onChange={(e) => setSince(e.target.value)} />
            </label>
            <label className="toggle">
              {t("Until")}{" "}
              <input type="datetime-local" value={until} onChange={(e) => setUntil(e.target.value)} />
            </label>
          </Toolbar>

          {list.isLoading ? (
            <Empty>{t("Loading…")}</Empty>
          ) : jobs.length === 0 ? (
            <Empty>{t("No jobs.")}</Empty>
          ) : (
            <table>
              <thead>
                <tr>
                  <th>{t("Operation")}</th><th>{t("State")}</th><th>{t("Requested by")}</th><th>{t("Approved by")}</th>
                  <th>{t("Result")}</th><th>{t("Created")}</th><th></th>
                </tr>
              </thead>
              <tbody>
                {jobs.map((job) => (
                  <Fragment key={job.id}>
                    <tr>
                      <td>
                        <button
                          className="expander"
                          aria-expanded={expanded === job.id}
                          onClick={() => setExpanded(expanded === job.id ? "" : job.id)}
                        >
                          {expanded === job.id ? "▾" : "▸"}
                        </button>
                        <a href="#" className="mono" onClick={(e) => { e.preventDefault(); setExpanded(expanded === job.id ? "" : job.id); }}>
                          {job.action_type}
                        </a>
                      </td>
                      <td>
                        <JobState state={job.state} />
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
                            <button onClick={() => approve.mutate(job)} disabled={approve.isPending}>
                              {t("Approve")}
                            </button>
                            <button className="secondary" onClick={() => cancel.mutate(job)}>{t("Cancel")}</button>
                          </div>
                        )}
                      </td>
                    </tr>
                    {expanded === job.id && (
                      <tr className="detail-row">
                        <td colSpan={7}><Attempts jobId={job.id} /></td>
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
          {attempt.stdout && <pre>{attempt.stdout.slice(0, 4000)}</pre>}
          {attempt.stderr && <pre>{attempt.stderr.slice(0, 2000)}</pre>}
        </div>
      ))}
    </div>
  );
}

/** The result dependent on the operation type: a package plan, a transaction report, a preflight. */
function TypedResult({ detail }: { detail: Record<string, any> }) {
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
        </div>
      );
    case "package_apply":
      return (
        <div className="source">
          {t("{n} packages applied", { n: detail.applied?.length ?? 0 })}
          {detail.reboot_required && `, ${t("reboot required")}`}
          {detail.package_database_broken && `, ${t("PACKAGE DATABASE NEEDS REPAIR")}`}
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
