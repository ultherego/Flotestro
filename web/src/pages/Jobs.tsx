import { Fragment, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, type Collection } from "../lib/api";
import { PlanSummary } from "../components/plan";
import type { Attempt, Job } from "../lib/types";
import { ErrorBox, ErrorCode, Time, ProgressBar, Empty, JobState } from "../components/ui";
import { Card, PageHeader, Stat, StatGrid, Toolbar } from "../components/layout";
import { OPERATIONS_INTERVAL, useProgress } from "../lib/stream";
import { useT } from "../i18n";

/** The job list with approvals. An approval confirms the plan hash. */
export function Jobs() {
  const t = useT();
  const [state, setState] = useState("");
  const [expanded, setExpanded] = useState<string>("");
  const queryClient = useQueryClient();

  const params = new URLSearchParams({ limit: "100" });
  if (state) params.set("state", state);

  const { data, error } = useQuery({
    queryKey: ["jobs", params.toString()],
    queryFn: () => api.get<Collection<Job>>(`/api/v1/jobs?${params}`),
    // The operation list has no stream of its own, because its content also
    // changes through other operators' operations and through jobs expiring.
    refetchInterval: OPERATIONS_INTERVAL,
  });

  // One stream per tab carries the progress of all the running operations
  // and wakes the list when one of them changes state.
  const progress = useProgress("/api/v1/events");

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

  if (error) return <ErrorBox error={error} />;

  // The tiles count what is on the list, nothing more: the list is one
  // page of the newest jobs, and the hint says so.
  const jobs = data?.items ?? [];
  const count = (states: string[]) => jobs.filter((job) => states.includes(job.state)).length;
  const awaiting = count(["awaiting_approval"]);
  const inProgress = count(["queued", "leased", "dispatched", "running"]);
  const failed = count(["failed", "timed_out", "expired"]);
  const succeeded = count(["succeeded"]);
  const listed = t("among the {n} listed", { n: jobs.length });

  return (
    <>
      <PageHeader
        title={t("Jobs")}
        description={t("Approval confirms the plan hash, so tampering with its content is detectable.")}
      />

      <StatGrid>
        <Stat label={t("Awaiting approval")} value={awaiting} hint={listed} tone={awaiting > 0 ? "warn" : undefined} />
        <Stat label={t("In progress")} value={inProgress} hint={listed} />
        <Stat label={t("Failed")} value={failed} hint={listed} tone={failed > 0 ? "error" : undefined} />
        <Stat label={t("Succeeded")} value={succeeded} hint={listed} />
      </StatGrid>

      <Card flush>
        <Toolbar>
          <select value={state} onChange={(e) => setState(e.target.value)}>
            <option value="">{t("state: any")}</option>
            {["awaiting_approval", "queued", "dispatched", "running", "succeeded", "failed", "canceled", "expired"].map(
              (value) => <option key={value} value={value}>{value}</option>,
            )}
          </select>
        </Toolbar>

        {!data?.items.length ? (
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
              {data.items.map((job) => (
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
      </Card>
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
