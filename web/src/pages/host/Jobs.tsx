import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, type Collection } from "../../lib/api";
import type { Job, OperationContract } from "../../lib/types";
import { ErrorBox, ErrorCode, Time, ProgressBar, Empty, JobState } from "../../components/ui";
import { Breakdown } from "../../components/widgets";
import { ModuleHeader, ModulePage, Section, Summary, Table, Widgets, countWhere, useHost } from "./shared";
import { OPERATIONS_INTERVAL, useProgress } from "../../lib/stream";
import { contractWords, useOperations } from "../Bulk";
import { useT } from "../../i18n";

/** The states a job passes through before the host has touched anything. */
const BEFORE_START = ["planned", "awaiting_approval", "queued", "leased", "dispatched"];
/** The states in which the host is working on the job. */
const STARTED = ["running"];

/**
 * Whether a cancel request would stop this job, from the contract of its
 * operation: before the start every operation is cancellable, once the
 * host reported a start only one that stops cleanly. The server accepts
 * a cancel in more states than that; the button is shown only where it
 * does what its label says.
 */
export function cancellable(job: Job, contract: OperationContract | undefined): boolean {
  if (BEFORE_START.includes(job.state)) return true;
  if (!STARTED.includes(job.state)) return false;
  return contract?.cancel_mode === "safe";
}

export function HostJobs() {
  const t = useT();
  const host = useHost();
  const queryClient = useQueryClient();
  const progress = useProgress("/api/v1/events");
  const { data, error } = useQuery({
    queryKey: ["jobs", host.id],
    queryFn: () => api.get<Collection<Job>>(`/api/v1/jobs?host_id=${host.id}&limit=50`),
    refetchInterval: OPERATIONS_INTERVAL,
  });
  // The cancel button follows the contract of the operation and the
  // operator's permission: a button that leads only to a refusal is an
  // interface defect, and one drawn on a running package transaction
  // would promise a stop the host cannot make.
  const catalogue = useOperations();
  const whoami = useQuery({
    queryKey: ["whoami"],
    queryFn: () => api.get<{ permissions: string[] }>("/api/v1/whoami"),
    staleTime: 5 * 60 * 1000,
  });
  const mayCancel = (whoami.data?.permissions ?? []).includes("job.cancel");
  const cancel = useMutation({
    mutationFn: (jobID: string) => api.post(`/api/v1/jobs/${jobID}/cancel`, { reason: "from the host job list" }),
    onSettled: () => queryClient.invalidateQueries({ queryKey: ["jobs", host.id] }),
  });
  const contractOf = (action: string): OperationContract | undefined =>
    catalogue.data?.items.find((item) => item.action === action);
  if (error) return <ErrorBox error={error} />;

  // The listed jobs by outcome, in the words the state badge uses; the
  // list is unknown until it loads and shows dashes then.
  const jobs = data?.items;
  const succeeded = ["succeeded", "completed"];
  const failed = ["failed", "timed_out", "expired", "partially_applied"];
  const waiting = ["awaiting_approval", "queued", "planned", "planning", "paused", "awaiting_budget"];
  const running = ["dispatched", "running"];
  const operations = Object.entries((jobs ?? []).reduce<Record<string, number>>((acc, job) => {
    const module = job.action_type.split(".")[0];
    acc[module] = (acc[module] ?? 0) + 1;
    return acc;
  }, {})).sort((a, b) => b[1] - a[1]).slice(0, 8);

  return (
    <ModulePage>
      <ModuleHeader
        title={t("Jobs")}
        description={t("Every operation requested on this host, newest first.")}
      />
      <Widgets>
      <Summary
        title={t("Outcomes")}
        description={t("The last {n} jobs on this host, by where they stand.", { n: jobs?.length ?? 50 })}
        span={8}
        segments={[
          { label: t("succeeded"), value: countWhere(jobs, (job) => succeeded.includes(job.state)), tone: "ok" },
          { label: t("failed"), value: countWhere(jobs, (job) => failed.includes(job.state)), tone: "error" },
          { label: t("running"), value: countWhere(jobs, (job) => running.includes(job.state)), tone: "info" },
          { label: t("waiting"), value: countWhere(jobs, (job) => waiting.includes(job.state)), tone: "warn" },
          { label: t("other"), value: countWhere(jobs, (job) => ![...succeeded, ...failed, ...running, ...waiting].includes(job.state)), tone: "unknown" },
        ]}
      />
      <Section title={t("By module")} span={4} description={t("Which modules the operations belong to.")}>
        {!jobs ? (
          <p className="source" style={{ margin: 0 }}>{t("Loading…")}</p>
        ) : !operations.length ? (
          <p className="source" style={{ margin: 0 }}>{t("No jobs for this host.")}</p>
        ) : (
          <Breakdown items={operations.map(([module, count]) => ({ label: <span className="hm-mono">{module}</span>, value: count }))} />
        )}
      </Section>
      <Section title={t("Jobs")} count={data?.items.length} span={12} flush>
        {cancel.error && <ErrorBox error={cancel.error} />}
        {!data?.items.length ? (
          <Empty>{t("No jobs for this host.")}</Empty>
        ) : (
          <Table>
            <thead><tr><th>{t("Operation")}</th><th>{t("State")}</th><th>{t("Requested by")}</th><th>{t("Approved by")}</th><th>{t("Result")}</th><th>{t("Created")}</th><th></th></tr></thead>
            <tbody>
              {data.items.map((job) => {
                const contract = contractOf(job.action_type);
                const [, cancelMeaning] = contractWords(t, "cancel", contract?.cancel_mode);
                return (
                <tr key={job.id}>
                  <td className="hm-mono">{job.action_type}</td>
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
                  <td>{job.created_by}</td>
                  <td>{job.approved_by || "—"}</td>
                  <td>{job.result_error_code ? <ErrorCode code={job.result_error_code} /> : (job.result_status || "—")}</td>
                  <td><Time value={job.created_at} /></td>
                  <td>
                    {mayCancel && cancellable(job, contract) ? (
                      <button
                        className="secondary"
                        title={STARTED.includes(job.state) ? cancelMeaning : t("The host has not started this yet; a cancel stops it before it does.")}
                        disabled={cancel.isPending && cancel.variables === job.id}
                        onClick={() => cancel.mutate(job.id)}
                      >
                        {t("Cancel")}
                      </button>
                    ) : STARTED.includes(job.state) && contract?.cancel_mode ? (
                      <span className="source" title={cancelMeaning}>{t("runs to its end")}</span>
                    ) : null}
                  </td>
                </tr>
                );
              })}
            </tbody>
          </Table>
        )}
      </Section>
      </Widgets>
    </ModulePage>
  );
}
