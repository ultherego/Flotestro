import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useParams } from "react-router-dom";
import { api, type Collection } from "../lib/api";
import type {
  Campaign as CampaignType, CampaignReport, CampaignTarget, TimelineEntry,
} from "../lib/types";
import { ErrorBox, Time, Pair, Pairs, ProgressBar, Empty, JobState } from "../components/ui";
import { JobPlan } from "../components/plan";
import { OPERATIONS_INTERVAL, useProgress, useProgressStream } from "../lib/stream";
import { useT } from "../i18n";

export function Campaign() {
  const t = useT();
  const { id = "" } = useParams();
  const queryClient = useQueryClient();

  const campaign = useQuery({
    queryKey: ["campaign", id],
    queryFn: () => api.get<CampaignType>(`/api/v1/campaigns/${id}`),
    refetchInterval: OPERATIONS_INTERVAL,
  });
  const targets = useQuery({
    queryKey: ["campaign-targets", id],
    queryFn: () => api.get<Collection<CampaignTarget>>(`/api/v1/campaigns/${id}/targets`),
    refetchInterval: OPERATIONS_INTERVAL,
  });
  const report = useQuery({
    queryKey: ["campaign-report", id],
    queryFn: () => api.get<CampaignReport>(`/api/v1/campaigns/${id}/report`),
    refetchInterval: OPERATIONS_INTERVAL,
  });
  // The timeline comes from the durable trail, not from notifications: an
  // event sent while the panel restarted no longer exists anywhere, and an
  // operator coming back to a campaign is to see how it went, not only how
  // it ended.
  const timeline = useQuery({
    queryKey: ["campaign-timeline", id],
    queryFn: () => api.get<Collection<TimelineEntry>>(`/api/v1/campaigns/${id}/timeline`),
    refetchInterval: OPERATIONS_INTERVAL,
  });

  // The campaign is the screen where progress matters for a decision: the
  // operator watches the canary and decides whether to let further waves go.
  useProgressStream(id ? `/api/v1/campaigns/${id}/events` : null, [
    ["campaign", id],
    ["campaign-targets", id],
    ["campaign-report", id],
  ]);
  // The progress of the campaign's running operations, per host.
  const progress = useProgress(id ? `/api/v1/campaigns/${id}/events` : null);

  const control = useMutation({
    mutationFn: (operation: string) =>
      api.post(`/api/v1/campaigns/${id}/${operation}`, {
        reason: "from the panel",
        // The approval carries the fingerprint of the campaign currently on
        // screen. When the campaign changed since it was loaded, the server
        // refuses instead of transferring the consent onto something else.
        approval_fingerprint: campaign.data?.approval_fingerprint,
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["campaign", id] });
      queryClient.invalidateQueries({ queryKey: ["campaign-targets", id] });
    },
  });

  if (campaign.error) return <ErrorBox error={campaign.error} />;
  if (!campaign.data) return <Empty>{t("Loading…")}</Empty>;
  const data = campaign.data;

  return (
    <>
      <h1>{data.name}</h1>
      <p className="subtitle">
        <JobState state={data.state} /> · {data.action_type} · {t("requested by {who}", { who: data.created_by })}
      </p>

      <div style={{ marginBottom: 20 }}>
        {data.state === "awaiting_approval" && (
          <button onClick={() => control.mutate("approve")}>{t("Approve")}</button>
        )}{" "}
        {["canary", "running", "planned"].includes(data.state) && (
          <button className="secondary" onClick={() => control.mutate("pause")}>{t("Pause")}</button>
        )}{" "}
        {data.state === "paused" && (
          <button onClick={() => control.mutate("resume")}>{t("Resume")}</button>
        )}{" "}
        {!["completed", "failed", "canceled"].includes(data.state) && (
          <button className="secondary" onClick={() => control.mutate("cancel")}>{t("Cancel")}</button>
        )}
      </div>

      <Pairs>
        <Pair label={t("Canary / wave")}>{data.canary_size} / {data.wave_size}</Pair>
        <Pair label={t("Concurrent hosts")}>{data.max_concurrent}</Pair>
        <Pair label={t("Failure threshold")}>{t("{percent}% or {count} hosts", { percent: data.failure_threshold_percent, count: data.failure_threshold_absolute })}</Pair>
        <Pair label={t("Reboot policy")}>{data.reboot_policy}</Pair>
        <Pair label={t("Approved by")}>{data.approved_by || "—"}</Pair>
        <Pair label={t("Approval fingerprint")}>
          <span title={data.approval_fingerprint}>{data.approval_fingerprint.slice(0, 16) || "—"}</span>
        </Pair>
        <Pair label={t("Paused by")}>{data.paused_by || "—"}</Pair>
        <Pair label={t("Pause reason")}>{data.pause_reason || "—"}</Pair>
        <Pair label={t("Created")}><Time value={data.created_at} /></Pair>
      </Pairs>

      {report.data && (
        <>
          <h2>{t("Waves")}</h2>
          <table>
            <thead><tr><th>{t("Wave")}</th><th>{t("Canary")}</th><th>{t("Closed")}</th><th>{t("Summary")}</th></tr></thead>
            <tbody>
              {report.data.waves.map((wave) => (
                <tr key={wave.wave}>
                  <td>{wave.wave}</td>
                  <td>{wave.is_canary ? t("yes") : t("no")}</td>
                  <td>{wave.completed ? t("yes") : t("no")}</td>
                  <td>{Object.entries(wave.totals).map(([state, count]) => `${state}: ${count}`).join(", ")}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}

      <h2>{t("Timeline")}</h2>
      {!timeline.data?.items.length ? (
        <Empty>{t("No recorded events yet.")}</Empty>
      ) : (
        <table>
          <thead><tr><th>{t("When")}</th><th>{t("Event")}</th><th>{t("Host")}</th><th>{t("Detail")}</th></tr></thead>
          <tbody>
            {timeline.data.items.map((entry) => (
              <tr key={entry.id}>
                <td><Time value={entry.occurred_at} /></td>
                <td>{entry.event_type}</td>
                <td>{eventHostName(entry, targets.data?.items ?? [])}</td>
                <td>{eventDescription(entry)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      <h2>{t("Targets")}</h2>
      {!targets.data?.items.length ? (
        <Empty>{t("No targets.")}</Empty>
      ) : (
        <table>
          <thead><tr><th>{t("Host")}</th><th>{t("Wave")}</th><th>{t("Plan")}</th><th>{t("State")}</th><th>{t("Progress")}</th><th>{t("Error code")}</th><th>{t("Message")}</th></tr></thead>
          <tbody>
            {targets.data.items.map((target) => (
              <tr key={target.host_id}>
                <td>{target.hostname || target.host_id.slice(0, 8)}</td>
                <td>{target.wave}{target.wave === 0 && ` (${t("canary")})`}</td>
                {/* The consent covers the differences computed on the host,
                    not the intent. A host without a planning operation has
                    no plan to show. */}
                <td>{target.plan_job_id ? <JobPlan jobId={target.plan_job_id} /> : "—"}</td>
                <td><JobState state={target.state} /></td>
                {/* The progress belongs to the operation currently running
                    on this host. A host waiting for its wave has nothing to
                    show. */}
                <td>
                  {targetProgress(progress, target) ? (
                    <ProgressBar
                      percent={targetProgress(progress, target)?.percent}
                      step={targetProgress(progress, target)?.step}
                      total={targetProgress(progress, target)?.total}
                      caption={targetProgress(progress, target)?.message}
                    />
                  ) : (
                    "—"
                  )}
                </td>
                <td>{target.error_code || "—"}</td>
                <td>{target.message || "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </>
  );
}

/** eventHostName translates a host identifier into a name from the target list. */
function eventHostName(entry: TimelineEntry, targets: CampaignTarget[]): string {
  const hostID = entry.payload?.host_id;
  if (!hostID) return "—";
  const target = targets.find((item) => item.host_id === hostID);
  return target?.hostname || hostID.slice(0, 8);
}

/**
 * eventDescription shows what tells one event from another.
 *
 * The error code and the pause reason matter more here than the event type
 * itself: "host failed" without a reason says nothing beyond something
 * having gone wrong.
 */
function eventDescription(entry: TimelineEntry): string {
  const parts = [
    entry.payload?.error_code,
    entry.payload?.message,
    entry.payload?.pause_reason,
  ].filter((part) => part);
  if (typeof entry.payload?.wave === "number" && entry.aggregate_type === "campaign_target") {
    parts.unshift(`wave ${entry.payload.wave}`);
  }
  return parts.join(" · ") || "—";
}

/**
 * The progress of a campaign target is looked up by the operation that
 * belongs to it. A campaign schedules several operations on a host in turn -
 * the upgrade, the reboot, the health check - so the host identifier alone
 * is not enough.
 */
function targetProgress(
  progress: Map<string, { step?: number; total?: number; percent?: number; message?: string }>,
  target: CampaignTarget,
) {
  for (const jobID of [target.job_id, target.reboot_job_id, target.health_job_id]) {
    if (jobID && progress.has(jobID)) return progress.get(jobID);
  }
  return undefined;
}
