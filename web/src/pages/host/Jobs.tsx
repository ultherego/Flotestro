import { useQuery } from "@tanstack/react-query";
import { api, type Collection } from "../../lib/api";
import type { Job } from "../../lib/types";
import { ErrorBox, Time, ProgressBar, Empty, JobState } from "../../components/ui";
import { useHost } from "./shared";
import { OPERATIONS_INTERVAL, useProgress } from "../../lib/stream";
import { useT } from "../../i18n";

export function HostJobs() {
  const t = useT();
  const host = useHost();
  const progress = useProgress("/api/v1/events");
  const { data, error } = useQuery({
    queryKey: ["jobs", host.id],
    queryFn: () => api.get<Collection<Job>>(`/api/v1/jobs?host_id=${host.id}&limit=50`),
    refetchInterval: OPERATIONS_INTERVAL,
  });
  if (error) return <ErrorBox error={error} />;
  if (!data?.items.length) return <Empty>{t("No jobs for this host.")}</Empty>;

  return (
    <table>
      <thead><tr><th>{t("Operation")}</th><th>{t("State")}</th><th>{t("Requested by")}</th><th>{t("Approved by")}</th><th>{t("Result")}</th><th>{t("Created")}</th></tr></thead>
      <tbody>
        {data.items.map((job) => (
          <tr key={job.id}>
            <td>{job.action_type}</td>
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
            <td>{job.result_error_code || job.result_status || "—"}</td>
            <td><Time value={job.created_at} /></td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
