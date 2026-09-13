import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useParams } from "react-router-dom";
import { api, type Collection } from "../lib/api";
import type {
  Campaign as CampaignType, CampaignReport, CampaignTarget, TimelineEntry,
} from "../lib/types";
import { ErrorBox, Time, Pair, Pairs, ProgressBar, Empty, JobState } from "../components/ui";
import { JobPlan } from "../components/plan";
import { OPERATIONS_INTERVAL, useProgress, useProgressStream } from "../lib/stream";
import { loadedTargets, TARGET_STATES, useTargets } from "../lib/targets";
import { moduleForAction } from "./host/modules";
import { useT } from "../i18n";

export function Campaign() {
  const t = useT();
  const { id = "" } = useParams();
  const queryClient = useQueryClient();
  const [stateFilter, setStateFilter] = useState("");
  const [search, setSearch] = useState("");
  // The stop that is being confirmed: pausing and cancelling say what they
  // do to the hosts under way before anything happens.
  const [pendingStop, setPendingStop] = useState<"pause" | "cancel" | null>(null);
  const [stopReason, setStopReason] = useState("");

  const campaign = useQuery({
    queryKey: ["campaign", id],
    queryFn: () => api.get<CampaignType>(`/api/v1/campaigns/${id}`),
    refetchInterval: OPERATIONS_INTERVAL,
  });
  const targets = useTargets(id, { state: stateFilter, search });
  const loaded = loadedTargets(targets.data);
  const total = targets.data?.pages[0]?.total ?? 0;
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
    ["campaign-timeline", id],
  ]);
  // The progress of the campaign's running operations, per host.
  const progress = useProgress(id ? `/api/v1/campaigns/${id}/events` : null);

  const control = useMutation({
    mutationFn: (operation: string) =>
      api.post(`/api/v1/campaigns/${id}/${operation}`, {
        reason: stopReason.trim() || "from the panel",
        // The approval carries the fingerprint of the campaign currently on
        // screen. When the campaign changed since it was loaded, the server
        // refuses instead of transferring the consent onto something else.
        approval_fingerprint: campaign.data?.approval_fingerprint,
      }),
    onSuccess: () => {
      setPendingStop(null);
      setStopReason("");
      queryClient.invalidateQueries({ queryKey: ["campaign", id] });
      queryClient.invalidateQueries({ queryKey: ["campaign-targets", id] });
    },
  });

  if (campaign.error) return <ErrorBox error={campaign.error} />;
  if (!campaign.data) return <Empty>{t("Loading…")}</Empty>;
  const data = campaign.data;

  // What a stop does depends on where the hosts are: a host that has not
  // started will not start, a host mid-operation finishes on its own - no
  // campaign action here interrupts work on a host or rolls it back.
  const totals = report.data?.totals ?? {};
  const notStarted = (totals.pending ?? 0) + (totals.awaiting_budget ?? 0) + (totals.planning ?? 0);
  const underWay = (totals.running ?? 0) + (totals.rebooting ?? 0) + (totals.verifying ?? 0);

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
          <button className="secondary" onClick={() => setPendingStop("pause")}>{t("Pause")}</button>
        )}{" "}
        {data.state === "paused" && (
          <button onClick={() => control.mutate("resume")}>{t("Resume")}</button>
        )}{" "}
        {!["completed", "failed", "canceled"].includes(data.state) && (
          <button className="secondary" onClick={() => setPendingStop("cancel")}>{t("Cancel")}</button>
        )}
      </div>

      {pendingStop && (
        <div className="form" style={{ marginBottom: 20 }}>
          <h2 style={{ marginTop: 0 }}>{pendingStop === "pause" ? t("Pause the campaign?") : t("Cancel the campaign?")}</h2>
          <p className="subtitle" style={{ margin: 0 }}>
            {pendingStop === "pause"
              ? t("No further host starts until the campaign is resumed. {underWay} operations already under way finish on their own — a pause does not interrupt work on a host.", { underWay })
              : t("{notStarted} hosts that have not started are marked canceled and will not start. {underWay} operations already under way finish on their own — cancelling does not interrupt them and does not roll anything back.", { notStarted, underWay })}
          </p>
          <label>
            {t("Reason (kept in the audit trail)")}
            <input value={stopReason} onChange={(e) => setStopReason(e.target.value)} />
          </label>
          <div className="operations">
            <button onClick={() => control.mutate(pendingStop)} disabled={control.isPending}>
              {pendingStop === "pause" ? t("Pause") : t("Cancel the campaign")}
            </button>
            <button className="secondary" onClick={() => setPendingStop(null)}>{t("Back")}</button>
          </div>
        </div>
      )}

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
                <td>{eventHostName(entry, loaded)}</td>
                <td>{eventDescription(entry)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      <h2>{t("Targets")}</h2>
      {/* The filter runs on the server and the rows arrive page by page:
          the screen shows what the operator asked about, not the whole
          fleet at once. */}
      <div className="filters">
        <select value={stateFilter} onChange={(e) => setStateFilter(e.target.value)}>
          <option value="">{t("state: any")}</option>
          {TARGET_STATES.map((value) => <option key={value} value={value}>{value}</option>)}
        </select>
        <input placeholder={t("Filter by hostname")} value={search} onChange={(e) => setSearch(e.target.value)} />
        <span className="source">{t("{shown} of {total} shown", { shown: loaded.length, total })}</span>
      </div>
      {!loaded.length ? (
        <Empty>{t("No targets.")}</Empty>
      ) : (
        <table>
          <thead><tr><th>{t("Host")}</th><th>{t("Wave")}</th><th>{t("Plan")}</th><th>{t("State")}</th><th>{t("Progress")}</th><th>{t("Error code")}</th><th>{t("Message")}</th></tr></thead>
          <tbody>
            {loaded.map((target) => (
              <tr key={target.host_id}>
                {/* The host opens on the module of the change, with the way
                    back to this campaign in the address. */}
                <td>
                  <Link to={`/hosts/${target.host_id}/${moduleForAction(data.action_type)}?campaign=${id}`}>
                    {target.hostname || target.host_id.slice(0, 8)}
                  </Link>
                </td>
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
      {targets.hasNextPage && (
        <p>
          <button className="secondary" onClick={() => targets.fetchNextPage()} disabled={targets.isFetchingNextPage}>
            {t("Load more ({n} left)", { n: total - loaded.length })}
          </button>
        </p>
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
