import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useParams } from "react-router-dom";
import { api, type Collection } from "../lib/api";
import type {
  Campaign as CampaignType, CampaignApproval, CampaignReport, CampaignTarget, TimelineEntry,
} from "../lib/types";
import { ErrorBox, ErrorCode, Time, Pair, Pairs, ProgressBar, Empty, JobState } from "../components/ui";
import { Actions, Card, Columns, Field, FieldGrid, PageHeader, Stat, StatGrid, Toolbar } from "../components/layout";
import { JobPlan } from "../components/plan";
import { VirtualRows } from "../components/virtual";
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
  // The approval is a decision with evidence: the reason and the change
  // ticket go into the approval record next to the fingerprint.
  const [approving, setApproving] = useState(false);
  const [approvalReason, setApprovalReason] = useState("");
  const [changeTicket, setChangeTicket] = useState("");
  // The manual gate: the canary ran, and going on into the waves is a
  // decision somebody signs with a reason, like every other control.
  const [advancing, setAdvancing] = useState(false);
  const [advanceReason, setAdvanceReason] = useState("");
  // The plan the operator opened from the target table. A plan summary is
  // several lines and the windowed table needs rows of one fixed height, so
  // the plan is shown below the table for one host at a time.
  const [selectedPlanJob, setSelectedPlanJob] = useState<{ jobId: string; host: string } | null>(null);

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
  // The approval record is the evidence of the consent; it exists only
  // once somebody approved, so the card appears with it.
  const approvals = useQuery({
    queryKey: ["campaign-approvals", id],
    queryFn: () => api.get<Collection<CampaignApproval>>(`/api/v1/campaigns/${id}/approvals`),
    enabled: campaign.data !== undefined && campaign.data.approved_by !== undefined && campaign.data.approved_by !== "",
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

  // Every control carries a reason. The approval carries the fingerprint of
  // the campaign currently on screen as well: when the campaign changed
  // since it was loaded, the server refuses instead of transferring the
  // consent onto something else.
  const controlBody = (operation: string) => {
    if (operation === "approve") {
      return {
        approval_fingerprint: campaign.data?.approval_fingerprint,
        reason: approvalReason.trim(),
        change_ticket: changeTicket.trim(),
      };
    }
    if (operation === "advance") {
      return { reason: advanceReason.trim() || "from the panel" };
    }
    return { reason: stopReason.trim() || "from the panel" };
  };
  const control = useMutation({
    mutationFn: (operation: string) =>
      api.post(`/api/v1/campaigns/${id}/${operation}`, controlBody(operation)),
    onSuccess: () => {
      setPendingStop(null);
      setStopReason("");
      setApproving(false);
      setApprovalReason("");
      setChangeTicket("");
      setAdvancing(false);
      setAdvanceReason("");
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
  const offlineQueued = totals.queued_offline ?? 0;
  const notStarted = (totals.pending ?? 0) + (totals.awaiting_budget ?? 0) + (totals.planning ?? 0) + offlineQueued;
  const underWay = (totals.running ?? 0) + (totals.rebooting ?? 0) + (totals.verifying ?? 0);

  const succeeded = totals.succeeded ?? 0;
  const failed = (totals.failed ?? 0) + (totals.timed_out ?? 0) + (totals.partially_applied ?? 0);

  return (
    <>
      <PageHeader
        breadcrumb={[{ label: t("Campaigns"), to: "/campaigns" }]}
        title={data.name}
        description={<><JobState state={data.state} /> · {data.action_type} · {t("requested by {who}", { who: data.created_by })}</>}
        actions={
          <>
            {data.state === "awaiting_approval" && (
              <button onClick={() => { setPendingStop(null); setApproving(true); }}>{t("Approve")}</button>
            )}
            {data.state === "manual_gate" && (
              <button onClick={() => { setPendingStop(null); setAdvancing(true); }}>{t("Advance to the waves")}</button>
            )}
            {["canary", "running", "planned", "manual_gate"].includes(data.state) && (
              <button className="secondary" onClick={() => setPendingStop("pause")}>{t("Pause")}</button>
            )}
            {data.state === "paused" && (
              <button onClick={() => control.mutate("resume")}>{t("Resume")}</button>
            )}
            {!["completed", "failed", "canceled"].includes(data.state) && (
              <button className="secondary" onClick={() => setPendingStop("cancel")}>{t("Cancel")}</button>
            )}
          </>
        }
      />

      {approving && data.state === "awaiting_approval" && (
        <Card
          title={t("Approve the campaign?")}
          description={t("The consent covers exactly what is on screen: this operation, this payload, these {count} hosts and this rollout. It is recorded with the fingerprint {fingerprint}, your authentication and the reason.", { count: total, fingerprint: data.approval_fingerprint.slice(0, 12) })}
          footer={
            <Actions>
              <button onClick={() => control.mutate("approve")} disabled={control.isPending}>
                {t("Approve")}
              </button>
              <button className="secondary" onClick={() => setApproving(false)}>{t("Back")}</button>
            </Actions>
          }
        >
          <FieldGrid>
            <Field label={t("Reason (kept in the audit trail)")} hint={t("Required for a critical operation, at least 8 characters.")} wide>
              <input value={approvalReason} onChange={(e) => setApprovalReason(e.target.value)} />
            </Field>
            <Field label={t("Change ticket")} hint={t("Optional: the identifier or address of the change request.")}>
              <input value={changeTicket} onChange={(e) => setChangeTicket(e.target.value)} placeholder="CHG-1234" />
            </Field>
          </FieldGrid>
          {control.error && <p className="warning"><span>{control.error instanceof Error ? control.error.message : String(control.error)}</span></p>}
        </Card>
      )}

      {advancing && data.state === "manual_gate" && (
        <Card
          title={t("Advance to the waves?")}
          description={t("The canary is settled. {succeeded} hosts succeeded and {failed} failed; the remaining {notStarted} hosts start in waves of {wave} once you advance. The decision is recorded with your identity and the reason.", {
            succeeded, failed, notStarted, wave: data.wave_size,
          })}
          footer={
            <Actions>
              <button onClick={() => control.mutate("advance")} disabled={control.isPending}>
                {t("Advance to the waves")}
              </button>
              <button className="secondary" onClick={() => setAdvancing(false)}>{t("Back")}</button>
            </Actions>
          }
        >
          <FieldGrid>
            <Field label={t("Reason (kept in the audit trail)")} wide>
              <input value={advanceReason} onChange={(e) => setAdvanceReason(e.target.value)} />
            </Field>
          </FieldGrid>
          {control.error && <p className="warning"><span>{control.error instanceof Error ? control.error.message : String(control.error)}</span></p>}
        </Card>
      )}

      {pendingStop && (
        <Card
          tone={pendingStop === "pause" ? "warn" : "error"}
          title={pendingStop === "pause" ? t("Pause the campaign?") : t("Cancel the campaign?")}
          description={pendingStop === "pause"
            ? t("No further host starts until the campaign is resumed. {underWay} operations already under way finish on their own — a pause does not interrupt work on a host.", { underWay })
            : t("{notStarted} hosts that have not started are marked canceled and will not start. {underWay} operations already under way finish on their own — cancelling does not interrupt them and does not roll anything back.", { notStarted, underWay })}
          footer={
            <Actions>
              <button
                className={pendingStop === "cancel" ? "danger" : ""}
                onClick={() => control.mutate(pendingStop)}
                disabled={control.isPending}
              >
                {pendingStop === "pause" ? t("Pause") : t("Cancel the campaign")}
              </button>
              <button className="secondary" onClick={() => setPendingStop(null)}>{t("Back")}</button>
            </Actions>
          }
        >
          <FieldGrid>
            <Field label={t("Reason (kept in the audit trail)")} wide>
              <input value={stopReason} onChange={(e) => setStopReason(e.target.value)} />
            </Field>
          </FieldGrid>
        </Card>
      )}

      {report.data && (
        <StatGrid>
          <Stat label={t("Targets")} value={total} />
          <Stat label={t("Not started")} value={notStarted} />
          <Stat label={t("In progress")} value={underWay} />
          <Stat label={t("Succeeded")} value={succeeded} tone={succeeded > 0 ? "ok" : undefined} />
          <Stat label={t("Failed")} value={failed} tone={failed > 0 ? "error" : undefined} />
          {offlineQueued > 0 && (
            <Stat label={t("Waiting for connection")} value={offlineQueued} tone="warn" />
          )}
        </StatGrid>
      )}

      <Columns wide>
      <Card title={t("Details")}>
        <Pairs>
          <Pair label={t("Canary / wave")}>{data.canary_size} / {data.wave_size}</Pair>
          <Pair label={t("Concurrent hosts")}>{data.max_concurrent}</Pair>
          <Pair label={t("Failure threshold")}>{t("{percent}% or {count} hosts", { percent: data.failure_threshold_percent, count: data.failure_threshold_absolute })}</Pair>
          <Pair label={t("Reboot policy")}>{data.reboot_policy}</Pair>
          <Pair label={t("Offline policy")}>{data.offline_policy}</Pair>
          <Pair label={t("Waits for offline hosts until")}>{data.deadline_at ? <Time value={data.deadline_at} /> : "—"}</Pair>
          <Pair label={t("Manual gate after the canary")}>
            {!data.manual_gate ? t("no") : data.gate_advanced_by
              ? t("advanced by {who}", { who: data.gate_advanced_by })
              : t("yes")}
          </Pair>
          <Pair label={t("Connectivity loss threshold")}>
            {data.connectivity_lost_absolute > 0
              ? t("{count} hosts", { count: data.connectivity_lost_absolute })
              : t("off")}
          </Pair>
          <Pair label={t("Approved by")}>{data.approved_by || "—"}</Pair>
          <Pair label={t("Approval fingerprint")}>
            <span className="mono" title={data.approval_fingerprint}>{data.approval_fingerprint.slice(0, 16) || "—"}</span>
          </Pair>
          <Pair label={t("Paused by")}>{data.paused_by || "—"}</Pair>
          <Pair label={t("Pause reason")}>{data.pause_reason || "—"}</Pair>
          <Pair label={t("Created")}><Time value={data.created_at} /></Pair>
        </Pairs>
      </Card>
      <div className="stack">

      {approvals.data && approvals.data.items.length > 0 && (
        <Card title={t("Approval record")} description={t("Who consented to what, on what authentication and why. The record is written once and never changed.")} flush>
          <table>
            <thead><tr><th>{t("Approved by")}</th><th>{t("Requested by")}</th><th>{t("Authentication")}</th><th>{t("Reason")}</th><th>{t("Change ticket")}</th><th>{t("When")}</th></tr></thead>
            <tbody>
              {approvals.data.items.map((record) => (
                <tr key={record.id}>
                  <td>{record.approved_by}</td>
                  <td>{record.requested_by}</td>
                  <td title={record.acr ? `acr ${record.acr}${record.amr?.length ? `, amr ${record.amr.join(" ")}` : ""}` : undefined}>
                    {record.authentication === "api_token" ? t("API token (not re-authenticated)") : t("session")}
                    {record.authenticated_at && <> · <Time value={record.authenticated_at} /></>}
                  </td>
                  <td>{record.reason || "—"}</td>
                  <td className="mono">{record.change_ticket || "—"}</td>
                  <td><Time value={record.created_at} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
      )}

      {/* A host that came back with a different plan ran nothing: the
          consent covered the old plan, and the operator is to see which
          hosts need a new one rather than count them among the skipped. */}
      {report.data?.plan_changed && report.data.plan_changed.length > 0 && (
        <Card
          tone="warn"
          title={t("Plans changed after a reconnect")}
          description={t("These hosts came back with a state that gives a different plan than the one approved. Nothing ran on them; order a new campaign to approve the new plans.")}
        >
          <ul>
            {report.data.plan_changed.map((target) => (
              <li key={target.host_id}>
                <Link to={`/hosts/${target.host_id}/${moduleForAction(data.action_type)}?campaign=${id}`}>
                  {target.hostname || target.host_id.slice(0, 8)}
                </Link>
                {target.message && <> — {target.message}</>}
              </li>
            ))}
          </ul>
        </Card>
      )}

      {report.data && (
        <Card title={t("Waves")} flush>
          <table>
            <thead><tr><th className="num">{t("Wave")}</th><th>{t("Canary")}</th><th>{t("Closed")}</th><th>{t("Summary")}</th></tr></thead>
            <tbody>
              {report.data.waves.map((wave) => (
                <tr key={wave.wave}>
                  <td className="num">{wave.wave}</td>
                  <td>{wave.is_canary ? t("yes") : t("no")}</td>
                  <td>{wave.completed ? t("yes") : t("no")}</td>
                  <td>{Object.entries(wave.totals).map(([state, count]) => `${state}: ${count}`).join(", ")}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
      )}
      </div>
      </Columns>

      <Card title={t("Timeline")} flush>
        {!timeline.data?.items.length ? (
          <Empty>{t("No recorded events yet.")}</Empty>
        ) : (
          <table>
            <thead><tr><th>{t("When")}</th><th>{t("Event")}</th><th>{t("Host")}</th><th>{t("Detail")}</th></tr></thead>
            <tbody>
              {timeline.data.items.map((entry) => (
                <tr key={entry.id}>
                  <td><Time value={entry.occurred_at} /></td>
                  <td className="mono">{entry.event_type}</td>
                  <td>{eventHostName(entry, loaded)}</td>
                  <td>{eventDescription(entry)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>

      {/* The export is a file, not a screen: a report of ten thousand hosts
          goes to a spreadsheet, streamed from the server page by page. */}
      <Card
        title={t("Targets")}
        actions={
          <a className="button" href={`/api/v1/campaigns/${id}/report?format=csv`} download={`campaign-${id}.csv`}>{t("Download the targets as CSV")}</a>
        }
        flush
      >
        {/* The filter runs on the server and the rows arrive page by page:
            the screen shows what the operator asked about, not the whole
            fleet at once. */}
        <Toolbar end={<span>{t("{shown} of {total} shown", { shown: loaded.length, total })}</span>}>
          <select value={stateFilter} onChange={(e) => setStateFilter(e.target.value)}>
            <option value="">{t("state: any")}</option>
            {TARGET_STATES.map((value) => <option key={value} value={value}>{value}</option>)}
          </select>
          <input placeholder={t("Filter by hostname")} value={search} onChange={(e) => setSearch(e.target.value)} />
        </Toolbar>
        {!loaded.length ? (
          <Empty>{t("No targets.")}</Empty>
        ) : (
          // The rows are windowed: a campaign of ten thousand hosts is ten
          // thousand rows on the server and a few dozen in the browser. The
          // next page is fetched as the operator nears the end of the list.
          <VirtualRows
            items={loaded}
            rowHeight={40}
            height={480}
            columns={7}
            rowKey={(target) => target.host_id}
            head={<tr><th>{t("Host")}</th><th className="num">{t("Wave")}</th><th>{t("Plan")}</th><th>{t("State")}</th><th>{t("Progress")}</th><th>{t("Error code")}</th><th>{t("Message")}</th></tr>}
            onNearEnd={targets.hasNextPage && !targets.isFetchingNextPage ? () => targets.fetchNextPage() : undefined}
            loading={targets.isFetchingNextPage}
            render={(target) => {
              const planJob = target.plan_job_id;
              return (
                <>
                  {/* The host opens on the module of the change, with the way
                      back to this campaign in the address. */}
                  <td>
                    <Link to={`/hosts/${target.host_id}/${moduleForAction(data.action_type)}?campaign=${id}`}>
                      {target.hostname || target.host_id.slice(0, 8)}
                    </Link>
                  </td>
                  <td className="num">{target.wave}{target.wave === 0 && ` (${t("canary")})`}</td>
                  {/* The consent covers the differences computed on the host,
                      not the intent. A host without a planning operation has
                      no plan to show; a host with one opens it below the table,
                      because the summary does not fit a row of fixed height. */}
                  <td>
                    {planJob ? (
                      <button
                        className="inline"
                        aria-pressed={selectedPlanJob?.jobId === planJob}
                        onClick={() => setSelectedPlanJob(
                          selectedPlanJob?.jobId === planJob
                            ? null
                            : { jobId: planJob, host: target.hostname || target.host_id.slice(0, 8) },
                        )}
                      >
                        {t("plan")}
                      </button>
                    ) : (
                      "—"
                    )}
                  </td>
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
                  <td><ErrorCode code={target.error_code} /></td>
                  <td title={target.message}>{target.message || "—"}</td>
                </>
              );
            }}
          />
        )}
        {/* The button stays next to the automatic fetch: a page that failed
            to arrive is asked for again by hand, not by scrolling. */}
        {targets.hasNextPage && (
          <p>
            <button className="secondary" onClick={() => targets.fetchNextPage()} disabled={targets.isFetchingNextPage}>
              {t("Load more ({n} left)", { n: total - loaded.length })}
            </button>
          </p>
        )}
      </Card>
      {selectedPlanJob && (
        <Card
          title={t("Plan for {host}", { host: selectedPlanJob.host })}
          footer={
            <Actions>
              <button className="secondary" onClick={() => setSelectedPlanJob(null)}>{t("Close")}</button>
            </Actions>
          }
        >
          <JobPlan jobId={selectedPlanJob.jobId} />
        </Card>
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
