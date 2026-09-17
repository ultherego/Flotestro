import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate, useParams } from "react-router-dom";
import { api, ApiError, type Collection } from "../lib/api";
import type {
  Campaign as CampaignType, CampaignApproval, CampaignReport, CampaignTarget, SelectorExpression, TimelineEntry,
} from "../lib/types";
import { ErrorBox, ErrorCode, Time, Pair, Pairs, ProgressBar, Empty, JobState } from "../components/ui";
import { Actions, Card, Columns, Field, FieldGrid, PageHeader, Toolbar } from "../components/layout";
import { StatusBar } from "../components/widgets";
import { JobPlan, PlanGroupView, STALE_PLAN_CODES, unknownPlanHosts } from "../components/plan";
import { VirtualRows } from "../components/virtual";
import { OPERATIONS_INTERVAL, useProgress, useProgressStream } from "../lib/stream";
import {
  type CampaignStep, type CompensationLinks, loadedTargets, SETTLED_CAMPAIGN_STATES, TARGET_STATES,
  useTargets, useTargetSteps,
} from "../lib/targets";
import { moduleForAction } from "./host/modules";
import {
  bulkPrefill, ContractChips, contractWords, MIN_REASON, type PlanGroups, reasonValid,
  REVERSE_OPERATION, reversePayload, useOperation,
} from "./Bulk";
import { describeExpression } from "./Groups";
import { useConfirm } from "../components/Modal";
import { useToast } from "../components/Toast";
import { useT } from "../i18n";

/**
 * The record as the API returns it. The shared Campaign type names the
 * fields every screen reads; the order itself - the selector as given,
 * the window, the units, the timeouts - and the links to other campaigns
 * are read here through this shape, so the approver reads the whole
 * order off the page rather than the parts the list needs.
 */
type CampaignRecord = CampaignType & CompensationLinks & {
  selector?: {
    site?: string;
    environment?: string;
    os_family?: string;
    host_ids?: string[];
    expression?: SelectorExpression | null;
    exclude?: string[];
    exclude_reason?: string;
  } | null;
  health_check_units?: string[];
  maintenance_start?: string;
  maintenance_end?: string;
  job_timeout_seconds?: number;
  reboot_timeout_seconds?: number;
  approved_at?: string;
  started_at?: string;
  finished_at?: string;
  canceled_by?: string;
  plan_set_hash?: string;
  policy_id?: string;
  policy_version?: number;
  /** The campaign whose failed hosts this one runs again, and the campaigns ordered to retry this one. */
  retries_campaign_id?: string;
  retries_campaign_name?: string;
  retried_by?: { id: string; name: string; state: string }[];
};

/**
 * The cancel protocol as a target row carries it: when the cancel was
 * asked of the host, and what the host answered - the outcome and the
 * phase it was in. Read off the host's task by the server; absent for a
 * host nobody asked.
 */
export type CancelState = {
  cancel_requested_at?: string;
  cancel_outcome?: string;
  cancel_phase?: string;
};

/**
 * One line about the cancel of a host's task, for the row: what the
 * host answered, or that the answer is still awaited. Empty for a host
 * nobody asked. The outcome is the protocol's word; the sentence says
 * what it means for the host, because "not_interruptible" on its own
 * reads as an error to somebody who did not write the protocol.
 */
export function cancelOutcomeLine(target: CancelState, t: (key: string, params?: Record<string, string | number>) => string): string {
  if (!target.cancel_requested_at && !target.cancel_outcome) return "";
  switch (target.cancel_outcome) {
    case "not_started":
      return t("Cancel: the host had not started the task; it will not start.");
    case "interrupted":
      return t("Cancel: the host interrupted the task while it was {phase}.", { phase: target.cancel_phase || "under way" });
    case "not_interruptible":
      return t("Cancel: the host runs the task to its end ({phase}); the result settles it.", { phase: target.cancel_phase || "under way" });
    case "already_done":
      return t("Cancel: the host had already finished the task; its result settles it.");
    default:
      return t("Cancel requested; waiting for the host to answer.");
  }
}

/**
 * Whether the operator may skip the host by name: only a host waiting
 * for its connection in a campaign that has not settled - the offline
 * canary the barrier waits for. The server refuses everything else with
 * skip_not_allowed; the button is not drawn where the answer is known.
 */
export function canSkipTarget(target: { state: string }, campaignState: string): boolean {
  return target.state === "queued_offline" && !SETTLED_CAMPAIGN_STATES.includes(campaignState);
}

export function Campaign() {
  const t = useT();
  const { id = "" } = useParams();
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const confirm = useConfirm();
  const toast = useToast();
  const [stateFilter, setStateFilter] = useState("");
  const [search, setSearch] = useState("");
  // The timeline is read through a filter of its own: one kind of event,
  // or one host, out of the trail of a campaign on thousands.
  const [eventKind, setEventKind] = useState("");
  const [eventHost, setEventHost] = useState("");
  // The control that is being confirmed: pausing and cancelling say what
  // they do to the hosts under way before anything happens, and resuming
  // is recorded with a reason like they are.
  const [pendingStop, setPendingStop] = useState<"pause" | "cancel" | "resume" | null>(null);
  const [stopReason, setStopReason] = useState("");
  // The retry: a new campaign on the hosts that failed, ordered with a
  // reason and, on request, the hosts that ended unknown as well.
  const [retrying, setRetrying] = useState(false);
  const [retryReason, setRetryReason] = useState("");
  const [includeUnknown, setIncludeUnknown] = useState(false);
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
  // The host whose steps are open below the table. The strip of one host
  // is five pills with their tasks and reasons; the windowed table has no
  // room for that in a row of fixed height, and a strip per row would be
  // one request per host on a campaign of thousands.
  const [selectedStepsHost, setSelectedStepsHost] = useState<{ hostId: string; host: string } | null>(null);

  const campaign = useQuery({
    queryKey: ["campaign", id],
    queryFn: () => api.get<CampaignType>(`/api/v1/campaigns/${id}`),
    refetchInterval: OPERATIONS_INTERVAL,
  });
  // The contract of the campaign's operation and of its reverse, from the
  // catalogue: what a stop does to the hosts under way and what way back
  // exists are read from there, never guessed from the operation name.
  const actionType = campaign.data?.action_type ?? "";
  const operation = useOperation(actionType || undefined);
  const reverseAction: string | undefined = REVERSE_OPERATION[actionType];
  const reverseOperation = useOperation(reverseAction);
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
  // The plans grouped by fingerprint: a hundred hosts with an identical
  // change are one row, so the operator reads what the campaign does per
  // shape of the change rather than per host.
  const plans = useQuery({
    queryKey: ["campaign-plans", id],
    queryFn: () => api.get<PlanGroups>(`/api/v1/campaigns/${id}/plans`),
    refetchInterval: OPERATIONS_INTERVAL,
  });

  // The campaign is the screen where progress matters for a decision: the
  // operator watches the canary and decides whether to let further waves go.
  useProgressStream(id ? `/api/v1/campaigns/${id}/events` : null, [
    ["campaign", id],
    ["campaign-targets", id],
    ["campaign-report", id],
    ["campaign-timeline", id],
    ["campaign-steps", id],
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
  const retry = useMutation({
    mutationFn: () => api.post<CampaignRecord>(`/api/v1/campaigns/${id}/retry`, {
      reason: retryReason.trim(), include_unknown: includeUnknown,
    }),
    onSuccess: (created) => {
      setRetrying(false);
      setRetryReason("");
      setIncludeUnknown(false);
      queryClient.invalidateQueries({ queryKey: ["campaigns"] });
      queryClient.invalidateQueries({ queryKey: ["campaign", id] });
      navigate(`/campaigns/${created.id}`);
    },
  });
  // The skip of a host waiting for its connection: the offline canary
  // the barrier waits for, let go by name with a reason the dialog asks
  // for. The row and the totals are read again once the server answered.
  const skip = useMutation({
    mutationFn: ({ hostId, reason }: { hostId: string; reason: string }) =>
      api.post(`/api/v1/campaigns/${id}/targets/${hostId}/skip`, { reason }),
    onSuccess: (_, { hostId }) => {
      toast.success(t("Host {host} skipped; the campaign goes on without it.", { host: hostId.slice(0, 8) }));
      queryClient.invalidateQueries({ queryKey: ["campaign", id] });
      queryClient.invalidateQueries({ queryKey: ["campaign-targets", id] });
    },
    onError: (error) => {
      toast.error(error instanceof Error ? error.message : String(error));
    },
  });
  const askToSkip = async (target: { host_id: string; hostname?: string; wave: number }) => {
    const host = target.hostname || target.host_id.slice(0, 8);
    const { ok, reason } = await confirm({
      title: t("Skip {host}?", { host }),
      body: (
        <p>
          {target.wave === 0
            ? t("The host is a canary waiting for its connection, and the waves do not start until the canary is settled. Skipping it opens the barrier on the word of the canary hosts that ran; the host takes no part and is not a failure.")
            : t("The host waits for its connection. Skipping it leaves it out of the campaign with your reason; it takes no part and is not a failure.")}
        </p>
      ),
      confirmLabel: t("Skip this host"),
      reason: { required: true, label: t("Reason (kept in the audit trail)") },
    });
    if (ok && reason) skip.mutate({ hostId: target.host_id, reason });
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
  const data = campaign.data as CampaignRecord;
  // The links to other campaigns travel on the record; the shared
  // Campaign type does not name them, so they are read through this one.
  const links = data;

  // What a stop does depends on where the hosts are: a host that has not
  // started will not start, a host mid-operation finishes on its own - no
  // campaign action here interrupts work on a host or rolls it back.
  const totals = report.data?.totals ?? {};
  const offlineQueued = totals.queued_offline ?? 0;
  // A host whose task is handed over and not started, or waits for a lock
  // on the host, is waiting like the offline one: it has changed nothing
  // yet, and a cancel would leave its task to finish.
  const waitingToStart = (totals.dispatched ?? 0) + (totals.awaiting_lock ?? 0);
  const notStarted = (totals.pending ?? 0) + (totals.awaiting_budget ?? 0) + (totals.planning ?? 0) + offlineQueued;
  const underWay = (totals.running ?? 0) + (totals.rebooting ?? 0) + (totals.verifying ?? 0) + waitingToStart;

  // No change is a success: the host has the desired state. Unknown is
  // not - and it is not a failure of the change either, so it has a
  // segment of its own rather than a place in the red one.
  const succeeded = totals.succeeded ?? 0;
  const noChange = totals.no_change ?? 0;
  const unknown = totals.unknown ?? 0;
  const failed = (totals.failed ?? 0) + (totals.timed_out ?? 0) + (totals.partially_applied ?? 0);
  // What a retry would run on: the failed hosts, and the unknown ones on
  // request. Offered only once the campaign settled - the server refuses
  // a retry before that, and the counts move until then.
  const settled = SETTLED_CAMPAIGN_STATES.includes(data.state);
  const failedHosts = totals.failed ?? 0;
  const canRetry = settled && report.data !== undefined && failedHosts + unknown > 0;
  const retryable = canRetry ? failedHosts + (includeUnknown ? unknown : 0) : 0;
  // The approval of a critical or destructive operation needs a reason
  // the server accepts: the same rule as the fresh authentication it asks
  // for, checked here so the button says so instead of the refusal.
  const reasonForced = approvalReasonRequired(operation?.risk);
  const approvalReady = !reasonForced || reasonValid(approvalReason);
  // A plan the panel cannot read on any host blocks the consent: nobody can
  // approve what nobody has seen. The host is excluded with a reason, or
  // the campaign is planned again.
  const unknownPlans = unknownPlanHosts(plans.data?.items ?? []);
  const staleHosts = loaded.filter((target) => STALE_PLAN_CODES.has(target.error_code ?? "")).map((target) => target.hostname ?? target.host_id);
  const approvalBlocked = unknownPlans.length > 0;

  // What the hosts under way do when the campaign stops, from the cancel
  // mode of the operation. The campaign stop itself never interrupts a
  // host; the sentence says whether such a host could be stopped at all.
  const underWayFate = (() => {
    switch (operation?.cancel_mode) {
      case "safe":
        return t("{underWay} operations under way stop cleanly when cancelled one by one from the host's job list; the campaign stop itself leaves them to finish.", { underWay });
      case "checkpoint_only":
        return t("{underWay} operations under way finish the step they are on and do not start the next one; none is interrupted mid-step.", { underWay });
      case "local_watchdog_owned":
        return t("{underWay} operations under way are settled by the host's own watchdog: the change is committed or reverted on the host, and the panel cannot stop that.", { underWay });
      case "impossible_after_start":
        return t("{underWay} operations under way finish on their own: once started, this operation cannot be cancelled.", { underWay });
      default:
        return t("{underWay} operations already under way finish on their own — cancelling does not interrupt them.", { underWay });
    }
  })();
  const rollbackHint = (() => {
    switch (operation?.rollback) {
      case "exact_restore":
        return t("Nothing is rolled back by the stop. The previous version is kept on every host that changed; putting it back is a new plan.");
      case "compensating":
        return t("Nothing is rolled back by the stop. A change that landed is undone by a new plan that neutralises it.");
      case "automatic_local":
        return t("Nothing is rolled back by the stop. A host that failed its connectivity check has already reverted itself; a host that committed goes back only with a new plan.");
      case "best_effort":
        return t("Nothing is rolled back by the stop, and there is only a best-effort way back with no guarantee of the previous state.");
      case "none":
        return t("Nothing is rolled back by the stop, and there is no way back for this operation.");
      default:
        return t("Nothing is rolled back by the stop.");
    }
  })();
  const rollbackPlannable = PLANNABLE_ROLLBACK.includes(operation?.rollback ?? "");
  // What the compensation card offers. The catalogue decides the class and
  // whether the reverse runs as a campaign; the record says whether the
  // campaign settled and how many hosts it changed. Until the catalogue is
  // in, nothing is offered rather than something guessed.
  const offer: CompensationOffer = operation
    ? compensationOffer({
      state: data.state,
      rollback: operation.rollback,
      reverseAction,
      reverseReady: reverseOperation?.campaign_ready,
      changedHosts: links.changed_hosts,
    })
    : { kind: "not_settled" };
  const [rollbackWord, rollbackMeaning] = contractWords(t, "rollback", operation?.rollback);
  // The address of the compensation in the Bulk workspace: the whole set
  // the campaign changed, or the hosts named - one row of the table.
  const compensationOf = (hostIDs: string[] = []) =>
    bulkPrefill(reverseAction ?? "", t("Rollback of {name}", { name: data.name }),
      reversePayload(actionType, data.payload), data.id, hostIDs);
  const rowCompensation = offer.kind === "campaign";
  // The timeline through its filter: the kinds are read off the trail
  // itself, so the list offers what happened rather than every kind the
  // engine knows.
  const eventKinds = Array.from(new Set((timeline.data?.items ?? []).map((entry) => entry.event_type))).sort();
  const hostNeedle = eventHost.trim().toLowerCase();
  const events = (timeline.data?.items ?? []).filter((entry) =>
    (!eventKind || entry.event_type === eventKind)
    && (!hostNeedle || eventHostName(entry, loaded).toLowerCase().includes(hostNeedle)
      || (entry.payload?.host_id ?? "").toLowerCase().includes(hostNeedle)));

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
            {(data.state === "paused" || data.state === "pausing") && (
              <button onClick={() => setPendingStop("resume")}>{t("Resume")}</button>
            )}
            {!SETTLED_CAMPAIGN_STATES.includes(data.state) && data.state !== "canceling" && (
              <button className="secondary" onClick={() => setPendingStop("cancel")}>{t("Cancel")}</button>
            )}
            {canRetry && (
              <button onClick={() => { setPendingStop(null); setRetrying(true); }}>{t("Retry on failed hosts")}</button>
            )}
            {/* The same order once more, written into the wizard: the
                operation, the name and the payload; the targets and the
                rollout are decided there again. */}
            <Link className="button" to={bulkPrefill(data.action_type, data.name, data.payload ?? {})} title={t("Opens the Bulk workspace with the same operation, name and payload written in; the targets and the rollout are chosen again.")}>
              {t("Clone")}
            </Link>
          </>
        }
      />

      {/* The order itself, before any decision about it: what runs, with
          what payload, on which hosts as they were named, under which
          rollout. The approver reads this; the fingerprint below binds the
          consent to exactly it. */}
      <OrderCard campaign={data} operation={operation} />

      {retrying && canRetry && (
        <Card
          title={t("Retry on failed hosts?")}
          description={t("A new campaign with the same operation, payload and rollout on exactly the {n} hosts that did not reach the desired state; the hosts that succeeded are not touched. It waits for its own approval and is linked to this one.", { n: retryable })}
          footer={
            <Actions>
              <button onClick={() => retry.mutate()} disabled={retry.isPending || !reasonValid(retryReason) || retryable === 0}>
                {t("Order the retry on {n} hosts", { n: retryable })}
              </button>
              <button className="secondary" onClick={() => setRetrying(false)}>{t("Back")}</button>
            </Actions>
          }
        >
          <FieldGrid>
            <Field label={t("Reason (kept in the audit trail)")} hint={t("Required: at least {n} characters.", { n: MIN_REASON })} wide>
              <input value={retryReason} onChange={(e) => setRetryReason(e.target.value)} />
            </Field>
            {/* An unknown host may hold the change half done; running it
                again blind is the operator's call, made here on purpose. */}
            <label className="toggle">
              <input type="checkbox" checked={includeUnknown} onChange={(e) => setIncludeUnknown(e.target.checked)} />{" "}
              {t("Include the {n} hosts that ended unknown (read what they hold first)", { n: unknown })}
            </label>
          </FieldGrid>
          {retry.error && (
            <p className="warning">
              <span>
                {retry.error instanceof ApiError && <><code>{retry.error.code}</code> · </>}
                {retry.error instanceof Error ? retry.error.message : String(retry.error)}
              </span>
            </p>
          )}
        </Card>
      )}

      {approving && data.state === "awaiting_approval" && (
        <Card
          title={t("Approve the campaign?")}
          description={t("The consent covers exactly what is on screen: this operation, this payload, these {count} hosts and this rollout. It is recorded with the fingerprint {fingerprint}, your authentication and the reason.", { count: total, fingerprint: data.approval_fingerprint.slice(0, 12) })}
          footer={
            <Actions>
              <button onClick={() => control.mutate("approve")} disabled={control.isPending || !approvalReady || approvalBlocked}>
                {t("Approve")}
              </button>
              <button className="secondary" onClick={() => setApproving(false)}>{t("Back")}</button>
            </Actions>
          }
        >
          {approvalBlocked && (
            <p className="warning"><span>{t("Approval is blocked: {n} hosts have a plan the panel cannot read. Exclude them with a reason or plan the campaign again.", { n: unknownPlans.length })} {unknownPlans.slice(0, 12).join(", ")}</span></p>
          )}
          <FieldGrid>
            <Field
              label={t("Reason (kept in the audit trail)")}
              hint={reasonForced
                ? t("Required: this operation is {risk}, and the approval needs a reason of at least {n} characters.", { risk: operation?.risk ?? "critical", n: MIN_REASON })
                : t("Optional here; a critical operation requires at least {n} characters.", { n: MIN_REASON })}
              wide
            >
              <input value={approvalReason} onChange={(e) => setApprovalReason(e.target.value)} />
            </Field>
            <Field label={t("Change ticket")} hint={t("Optional: the identifier or address of the change request.")}>
              <input value={changeTicket} onChange={(e) => setChangeTicket(e.target.value)} placeholder="CHG-1234" />
            </Field>
          </FieldGrid>
          {control.error && <p className="warning"><span>{control.error instanceof Error ? control.error.message : String(control.error)}</span></p>}
          {control.error instanceof ApiError && STALE_PLAN_CODES.has(control.error.code) && (
            <Actions>
              <span className="source">{t("The host no longer computes this plan; plan again and approve the new one.")}</span>
              <Link className="button" to={bulkPrefill(data.action_type, data.name, data.payload ?? {})}>{t("Replan")}</Link>
            </Actions>
          )}
        </Card>
      )}

      {advancing && data.state === "manual_gate" && (
        <Card
          title={t("Advance to the waves?")}
          description={t("The canary is settled. {succeeded} hosts succeeded and {failed} failed; the remaining {notStarted} hosts start in waves of {wave} once you advance. The decision is recorded with your identity and the reason.", {
            succeeded: succeeded + noChange, failed: failed + unknown, notStarted, wave: data.wave_size,
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
          tone={pendingStop === "pause" ? "warn" : pendingStop === "cancel" ? "error" : undefined}
          title={pendingStop === "pause" ? t("Pause the campaign?") : pendingStop === "resume" ? t("Resume the campaign?") : t("Cancel the campaign?")}
          description={pendingStop === "pause"
            ? `${t("No further host starts until the campaign is resumed.")} ${underWayFate}`
            : pendingStop === "resume"
              ? t("The campaign goes back to its queue: {notStarted} hosts that have not started continue in their waves, under the same thresholds. The decision is recorded with your identity and the reason.", { notStarted })
              : `${t("{notStarted} hosts that have not started are marked canceled and will not start.", { notStarted })} ${underWayFate} ${rollbackHint}`}
          footer={
            <Actions>
              <button
                className={pendingStop === "cancel" ? "danger" : ""}
                onClick={() => control.mutate(pendingStop)}
                disabled={control.isPending}
              >
                {pendingStop === "pause" ? t("Pause") : pendingStop === "resume" ? t("Resume") : t("Cancel the campaign")}
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
          {pendingStop === "cancel" && rollbackPlannable && reverseAction && (
            <p className="subtitle">
              {reverseOperation?.campaign_ready ? (
                <Link to={bulkPrefill(reverseAction, t("Rollback of {name}", { name: data.name }), reversePayload(actionType, data.payload), data.id)}>
                  {t("Plan the rollback")}
                </Link>
              ) : (
                t("The reverse operation {action} runs host by host today; a rollback campaign is not offered.", { action: reverseAction })
              )}
              {" · "}
              {t("The rollback is a new campaign with its own plans and its own approval; the version or the rollback identifier is per host.")}
            </p>
          )}
        </Card>
      )}

      {/* The fate of the hosts as one coloured bar: the campaign's state
          read from across the room, each segment leading to its hosts. */}
      <Card
        title={t("Targets")}
        description={data.state === "canceling"
          ? t("{n} hosts in this campaign. The campaign is canceled; {underWay} hosts still carry their tasks and it ends once they settle.", { n: total, underWay })
          : t("{n} hosts in this campaign", { n: total })}
      >
        <StatusBar segments={[
          { label: t("Not started"), value: report.data ? notStarted - offlineQueued : undefined, tone: "neutral" },
          { label: t("Waiting for connection"), value: report.data ? offlineQueued : undefined, tone: "warn" },
          { label: t("Waiting to start"), value: report.data ? waitingToStart : undefined, tone: "warn" },
          { label: t("In progress"), value: report.data ? underWay - waitingToStart : undefined, tone: "info" },
          { label: t("Succeeded"), value: report.data ? succeeded : undefined, tone: "ok" },
          { label: t("No change"), value: report.data ? noChange : undefined, tone: "ok" },
          { label: t("Failed"), value: report.data ? failed : undefined, tone: "error" },
          { label: t("Unknown"), value: report.data ? unknown : undefined, tone: "warn" },
          { label: t("Skipped"), value: report.data ? (totals.skipped ?? 0) + (totals.canceled ?? 0) : undefined, tone: "unknown" },
        ]} />
      </Card>

      {/* The way back, as a decision on a settled campaign: how many hosts
          changed, what class of return the operation declares, and one
          button into a new plan with its own approval. An operation with
          no way back says so here instead of leaving the operator to infer
          it from a missing link. */}
      {offer.kind !== "not_settled" && (
        <Card
          title={t("Compensation")}
          description={`${t("Way back")}: ${rollbackWord} — ${rollbackMeaning}`}
          footer={offer.kind === "campaign" ? (
            <Actions>
              <Link className="button" to={compensationOf()}>{t("Compensate {n} hosts", { n: offer.changed })}</Link>
              <span className="subtitle">
                {t("The compensation is a new campaign with its own plans and its own approval; the version or the rollback identifier is per host.")}
              </span>
            </Actions>
          ) : undefined}
        >
          <p>
            {offer.kind === "no_reverse" && t("There is no reverse operation to plan for this campaign; what it changed stays as the hosts hold it.")}
            {offer.kind === "nothing_changed" && t("No host was changed by this campaign; there is nothing to compensate.")}
            {offer.kind === "host_by_host" && t("{n} hosts changed. The reverse operation {action} runs host by host today; a compensating campaign is not offered.", { n: offer.changed, action: offer.reverse })}
            {offer.kind === "campaign" && t("{n} hosts changed and can be put back by {action} on exactly those hosts; a host the change did not land on is refused.", { n: offer.changed, action: offer.reverse })}
          </p>
          <Pairs>
            {/* What was already ordered to undo this campaign, read from
                the compensating records: a second compensation is still
                the operator's decision, so the list informs and never
                hides the button. */}
            <Pair label={t("Compensated by")}>
              {links.compensated_by && links.compensated_by.length > 0
                ? links.compensated_by.map((other, index) => (
                  <span key={other.id}>
                    {index > 0 && ", "}
                    <Link to={`/campaigns/${other.id}`}>{other.name}</Link> <JobState state={other.state} />
                  </span>
                ))
                : t("no compensation ordered yet")}
            </Pair>
          </Pairs>
        </Card>
      )}

      <Columns wide>
      <Card title={t("Details")}>
        <Pairs>
          <Pair label={t("Requested by")}>{data.created_by}</Pair>
          <Pair label={t("Approved by")}>{data.approved_by || "—"}{data.approved_at && <> · <Time value={data.approved_at} /></>}</Pair>
          <Pair label={t("Approval fingerprint")}>
            <span className="mono" title={data.approval_fingerprint}>{data.approval_fingerprint.slice(0, 16) || "—"}</span>
          </Pair>
          {data.plan_set_hash && (
            <Pair label={t("Plan set fingerprint")}>
              <span className="mono" title={data.plan_set_hash}>{data.plan_set_hash.slice(0, 16)}</span>
            </Pair>
          )}
          <Pair label={t("Manual gate after the canary")}>
            {!data.manual_gate ? t("no") : data.gate_advanced_by
              ? t("advanced by {who}", { who: data.gate_advanced_by })
              : t("yes")}
          </Pair>
          <Pair label={t("Paused by")}>{data.paused_by || "—"}</Pair>
          <Pair label={t("Pause reason")}>{data.pause_reason || "—"}</Pair>
          {data.canceled_by && <Pair label={t("Canceled by")}>{data.canceled_by}</Pair>}
          <Pair label={t("Created")}><Time value={data.created_at} /></Pair>
          <Pair label={t("Started")}>{data.started_at ? <Time value={data.started_at} /> : "—"}</Pair>
          <Pair label={t("Finished")}>{data.finished_at ? <Time value={data.finished_at} /> : "—"}</Pair>
          {/* The retries of this campaign, read from their records: the
              list informs and never hides the button. */}
          {settled && (
            <Pair label={t("Retried by")}>
              {links.retried_by && links.retried_by.length > 0
                ? links.retried_by.map((other, index) => (
                  <span key={other.id}>
                    {index > 0 && ", "}
                    <Link to={`/campaigns/${other.id}`}>{other.name}</Link> <JobState state={other.state} />
                  </span>
                ))
                : canRetry ? t("no retry ordered yet") : t("nothing to retry")}
            </Pair>
          )}
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

      {/* The change as the hosts computed it: one row per shape of the
          plan together with the hosts that get it. A document or a list of
          commands in the plan is shown in full, since that is what lands
          on the host. */}
      <Card
        title={t("Plans")}
        description={t("One group is one shape of the change and the hosts that get it. A host whose plan changed since refuses the change.")}
        flush
      >
        {plans.error ? (
          <ErrorBox error={plans.error} />
        ) : !plans.data ? (
          <Empty>{t("Loading…")}</Empty>
        ) : plans.data.items.length === 0 ? (
          <Empty>{t("No plan yet.")}</Empty>
        ) : (
          <div className="plan-groups">
            {plans.data.items.map((group) => (
              <PlanGroupView key={group.plan_hash} group={group} action={actionType} stale={staleHosts} />
            ))}
            {staleHosts.length > 0 && canRetry && (
              <p className="warning">
                <span>{t("{n} hosts refused the plan as stale; the previous consent does not carry over. Order a retry to plan them again.", { n: staleHosts.length })}</span>
                <button className="secondary" onClick={() => setRetrying(true)}>{t("Replan")}</button>
              </p>
            )}
          </div>
        )}
      </Card>

      {/* The trail is filtered in the browser: it is already loaded whole,
          and one kind of event or one host is what a diagnosis looks for.
          The export is the filtered rows, built here from the same list. */}
      <Card
        title={t("Timeline")}
        actions={events.length > 0 ? (
          <a className="button" href={timelineCSV(events, loaded)} download={`campaign-${id}-timeline.csv`}>{t("Download the timeline as CSV")}</a>
        ) : undefined}
        flush
      >
        <Toolbar end={<span>{t("{shown} of {total} shown", { shown: events.length, total: timeline.data?.items.length ?? 0 })}</span>}>
          <select value={eventKind} onChange={(e) => setEventKind(e.target.value)} aria-label={t("Event kind")}>
            <option value="">{t("event: any")}</option>
            {eventKinds.map((kind) => <option key={kind} value={kind}>{kind}</option>)}
          </select>
          <input placeholder={t("Filter by hostname")} aria-label={t("Filter by hostname")} value={eventHost} onChange={(e) => setEventHost(e.target.value)} />
        </Toolbar>
        {!timeline.data?.items.length ? (
          <Empty>{t("No recorded events yet.")}</Empty>
        ) : events.length === 0 ? (
          <Empty>{t("No event matches the filter.")}</Empty>
        ) : (
          <table>
            <thead><tr><th>{t("When")}</th><th>{t("Event")}</th><th>{t("Host")}</th><th>{t("Detail")}</th></tr></thead>
            <tbody>
              {events.map((entry) => (
                <tr key={entry.id}>
                  <td><Time value={entry.occurred_at} /></td>
                  <td className="mono">{entry.event_type}</td>
                  <td>{eventHostName(entry, loaded)}</td>
                  <td>
                    {eventDescription(entry)}
                    {/* The task behind the event opens on its own page. */}
                    {entry.payload?.job_id && <> · <Link className="mono" to={`/jobs/${entry.payload.job_id}`}>{entry.payload.job_id.slice(0, 8)}</Link></>}
                  </td>
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
          <select value={stateFilter} onChange={(e) => setStateFilter(e.target.value)} aria-label={t("State")}>
            <option value="">{t("state: any")}</option>
            {TARGET_STATES.map((value) => <option key={value} value={value}>{value}</option>)}
          </select>
          <input placeholder={t("Filter by hostname")} aria-label={t("Filter by hostname")} value={search} onChange={(e) => setSearch(e.target.value)} />
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
            columns={rowCompensation ? 9 : 8}
            rowKey={(target) => target.host_id}
            head={<tr><th>{t("Host")}</th><th className="num">{t("Wave")}</th><th>{t("Plan")}</th><th>{t("Steps")}</th><th>{t("State")}</th><th>{t("Progress")}</th><th>{t("Error code")}</th><th>{t("Message")}</th>{rowCompensation && <th>{t("Way back")}</th>}</tr>}
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
                  {/* The steps of the host - plan, change, reboot, verify,
                      compensate - open below the table for the same reason
                      the plan does: a strip does not fit a row. */}
                  <td>
                    <button
                      className="inline"
                      aria-pressed={selectedStepsHost?.hostId === target.host_id}
                      onClick={() => setSelectedStepsHost(
                        selectedStepsHost?.hostId === target.host_id
                          ? null
                          : { hostId: target.host_id, host: target.hostname || target.host_id.slice(0, 8) },
                      )}
                    >
                      {t("steps")}
                    </button>
                  </td>
                  {/* A host that has not started says what it waits on: the
                      lock another task of the host holds, as the agent named
                      it. Without it a running host that does nothing looks
                      like a lost one. */}
                  <td>
                    <JobState state={target.state} />
                    {target.blocker && (
                      <div
                        className="source"
                        title={target.blocker}
                        style={{ maxWidth: "28ch", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis", lineHeight: 1.2 }}
                      >
                        {t("Blocker")}: {target.blocker}
                      </div>
                    )}
                    {/* The cancel protocol on the host: asked, and what the
                        host answered. A cancel written on the panel alone
                        would say "stopped" about a transaction the host ran
                        to its end. */}
                    {cancelOutcomeLine(target as CancelState, t) && (
                      <div
                        className="source"
                        title={cancelOutcomeLine(target as CancelState, t)}
                        style={{ maxWidth: "28ch", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis", lineHeight: 1.2 }}
                      >
                        {cancelOutcomeLine(target as CancelState, t)}
                      </div>
                    )}
                    {/* An offline canary holds the barrier; the operator may
                        let it go by name, with a reason. */}
                    {canSkipTarget(target, data.state) && (
                      <button
                        className="inline"
                        onClick={() => askToSkip(target)}
                        disabled={skip.isPending}
                        title={t("Leave this host out with a reason; a skipped canary opens the waves.")}
                      >
                        {t("Skip")}
                      </button>
                    )}
                  </td>
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
                  {/* The way back for one host. A row knows the target's
                      state and not its steps, so only a host that succeeded
                      gets the link here; a host that failed after its change
                      landed is offered it from its step strip, which knows. */}
                  {rowCompensation && (
                    <td>
                      {target.state === "succeeded" ? (
                        <Link to={compensationOf([target.host_id])}>{t("compensate this host")}</Link>
                      ) : (
                        "—"
                      )}
                    </td>
                  )}
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
      {selectedStepsHost && (
        <Card
          title={t("Steps for {host}", { host: selectedStepsHost.host })}
          description={t("Every executable step of the host with its task, its attempts and the reason it did not run. A step without a record has not been reached.")}
          footer={
            <Actions>
              <button className="secondary" onClick={() => setSelectedStepsHost(null)}>{t("Close")}</button>
            </Actions>
          }
        >
          <TargetSteps
            campaignID={id}
            hostID={selectedStepsHost.hostId}
            compensation={rowCompensation ? compensationOf([selectedStepsHost.hostId]) : undefined}
          />
        </Card>
      )}
    </>
  );
}

/**
 * The order as it was given: the operation with its contract, the payload
 * as the hosts will get it, the targets as they were named, and the whole
 * rollout policy. Every field is the record's - nothing is inferred - and
 * a value the order left to the default shows resolved, the way it will
 * apply. A secret in the payload is a reference by name: the value never
 * travels in the order, and the list says so next to the names.
 */
function OrderCard({ campaign, operation }: {
  campaign: CampaignRecord;
  operation: ReturnType<typeof useOperation>;
}) {
  const t = useT();
  const selector = campaign.selector ?? {};
  const secrets = secretReferences(campaign.payload);
  const units = campaign.health_check_units ?? [];
  const payloadText = JSON.stringify(campaign.payload ?? {}, null, 2);
  const [rollbackWord] = contractWords(t, "rollback", operation?.rollback);
  return (
    <Card
      title={t("The order")}
      description={t("What was ordered, as the approval binds it: this operation, this payload, these targets and this rollout. Read it before deciding; the fingerprint covers exactly this.")}
    >
      <Columns wide>
        <div className="stack">
          <Pairs>
            <Pair label={t("Operation")}><span className="mono">{campaign.action_type}</span></Pair>
            <Pair label={t("Contract")}>{operation ? <ContractChips contract={operation} /> : "—"}</Pair>
            {operation?.risk && <Pair label={t("Risk")}>{operation.risk}</Pair>}
            {operation?.rollback && <Pair label={t("Way back")}>{rollbackWord}</Pair>}
            {/* The targets as the order named them; the snapshot below
                says what they resolved to. */}
            <Pair label={t("Targets as ordered")}>
              {selector.expression
                ? <span className="mono">{describeExpression(selector.expression)}</span>
                : selector.host_ids && selector.host_ids.length > 0
                  ? t("{n} hosts named one by one", { n: selector.host_ids.length })
                  : [selector.site && `${t("site")}: ${selector.site}`, selector.environment && `${t("environment")}: ${selector.environment}`, selector.os_family && `${t("OS family")}: ${selector.os_family}`].filter(Boolean).join(" · ") || t("the whole visible fleet")}
            </Pair>
            {selector.exclude && selector.exclude.length > 0 && (
              <Pair label={t("Excluded by name")}>
                {t("{n} hosts", { n: selector.exclude.length })} — {selector.exclude_reason || "—"}
              </Pair>
            )}
            <Pair label={t("Canary / wave")}>{campaign.canary_size} / {campaign.wave_size}</Pair>
            <Pair label={t("Concurrent hosts")}>{campaign.max_concurrent}</Pair>
            <Pair label={t("Failure threshold")}>{t("{percent}% or {count} hosts", { percent: campaign.failure_threshold_percent, count: campaign.failure_threshold_absolute })}</Pair>
            <Pair label={t("Connectivity loss threshold")}>
              {campaign.connectivity_lost_absolute > 0 ? t("{count} hosts", { count: campaign.connectivity_lost_absolute }) : t("off")}
            </Pair>
            <Pair label={t("Reboot policy")}>
              {campaign.reboot_policy}
              {campaign.reboot_policy !== "never" && campaign.reboot_timeout_seconds ? ` · ${t("waits {n} s for the host to come back", { n: campaign.reboot_timeout_seconds })}` : ""}
            </Pair>
            <Pair label={t("Health-check units")}>{units.length > 0 ? units.map((unit) => <span key={unit} className="chip chip-mono">{unit}</span>) : t("none")}</Pair>
            <Pair label={t("Task timeout")}>{campaign.job_timeout_seconds ? t("{n} s", { n: campaign.job_timeout_seconds }) : t("the operation's default")}</Pair>
            <Pair label={t("Offline policy")}>{campaign.offline_policy}</Pair>
            <Pair label={t("Waits for offline hosts until")}>{campaign.deadline_at ? <Time value={campaign.deadline_at} /> : "—"}</Pair>
            <Pair label={t("Maintenance window")}>
              {campaign.maintenance_start || campaign.maintenance_end
                ? <>{campaign.maintenance_start ? <Time value={campaign.maintenance_start} /> : t("any time")} → {campaign.maintenance_end ? <Time value={campaign.maintenance_end} /> : t("open-ended")}</>
                : t("none: the campaign may start at any time")}
            </Pair>
            <Pair label={t("Manual gate after the canary")}>{campaign.manual_gate ? t("yes") : t("no")}</Pair>
            {/* The links to the campaigns this order stands on: what it
                undoes, what it runs again, which policy ordered it. Each
                is on this record; the other side is read from here too. */}
            {campaign.compensates_campaign_id && (
              <Pair label={t("Compensates")}>
                <Link to={`/campaigns/${campaign.compensates_campaign_id}`}>
                  {campaign.compensates_campaign_name || campaign.compensates_campaign_id.slice(0, 8)}
                </Link>
              </Pair>
            )}
            {campaign.retries_campaign_id && (
              <Pair label={t("Retries")}>
                <Link to={`/campaigns/${campaign.retries_campaign_id}`}>
                  {campaign.retries_campaign_name || campaign.retries_campaign_id.slice(0, 8)}
                </Link>
                {" · "}
                {t("the same order on the hosts that failed there")}
              </Pair>
            )}
            {campaign.policy_id && (
              <Pair label={t("Ordered by policy")}>
                <Link to={`/policies/${campaign.policy_id}`}>{campaign.policy_id.slice(0, 8)}</Link>
                {campaign.policy_version ? ` · v${campaign.policy_version}` : ""}
              </Pair>
            )}
          </Pairs>
        </div>
        <div className="stack">
          <h3>{t("Payload")}</h3>
          <pre data-testid="order-payload">{payloadText}</pre>
          {secrets.length > 0 && (
            <p className="subtitle">
              {t("Secrets referenced by name: {names}. The value never travels in the order; the host fetches it on a short lease when the task runs.", { names: secrets.join(", ") })}
            </p>
          )}
        </div>
      </Columns>
    </Card>
  );
}

/**
 * The secrets a payload refers to, as "name" or "name@version". A
 * reference is an object with a name under a key ending in _secret, or
 * a map of them under a key ending in _secrets, wherever it sits in the
 * payload; the panel never carries the value, so there is nothing to
 * hide - only the names to point out.
 */
export function secretReferences(payload: unknown): string[] {
  const found: string[] = [];
  const nameOf = (value: unknown) => {
    if (value && typeof value === "object" && typeof (value as { name?: unknown }).name === "string") {
      const reference = value as { name: string; version?: number };
      found.push(reference.version ? `${reference.name}@${reference.version}` : reference.name);
    }
  };
  const walk = (node: unknown) => {
    if (!node || typeof node !== "object") return;
    for (const [key, value] of Object.entries(node as Record<string, unknown>)) {
      if (key.endsWith("_secret")) {
        nameOf(value);
      } else if (key.endsWith("_secrets") && value && typeof value === "object") {
        Object.values(value as Record<string, unknown>).forEach(nameOf);
      } else {
        walk(value);
      }
    }
  };
  walk(payload);
  return Array.from(new Set(found));
}

/**
 * timelineCSV renders the filtered trail as a file the browser saves: the
 * same columns as the table, one row per event. A cell that starts like a
 * spreadsheet formula gets a leading apostrophe, the way the server's
 * export guards its cells.
 */
export function timelineCSV(entries: TimelineEntry[], targets: CampaignTarget[]): string {
  const cell = (value: string) => {
    const guarded = /^[=+\-@\t\r]/.test(value) ? `'${value}` : value;
    return `"${guarded.replace(/"/g, '""')}"`;
  };
  const rows = [["occurred_at", "event_type", "host", "host_id", "job_id", "detail"].join(",")];
  for (const entry of entries) {
    rows.push([
      entry.occurred_at, entry.event_type, entry.payload?.host_id ? eventHostName(entry, targets) : "",
      entry.payload?.host_id ?? "",
      entry.payload?.job_id ?? "", eventDescription(entry),
    ].map(cell).join(","));
  }
  return `data:text/csv;charset=utf-8,${encodeURIComponent(rows.join("\n"))}`;
}

/** The step names as the strip shows them; the keys are the server's step kinds. */
const STEP_NAMES: Record<string, string> = {
  plan: "plan", execute: "execute", reboot: "reboot", verify: "verify", compensate: "compensate",
};

/**
 * The strip of one host's steps: plan → execute → reboot → verify →
 * compensate, each with its state, its task and - where it did not run -
 * the reason. The order comes from the server's contract, not from this
 * file. A step the host has not reached has no record and is drawn as
 * unknown rather than as pending: nothing decided about it yet.
 */
function TargetSteps({ campaignID, hostID, compensation }: {
  campaignID: string;
  hostID: string;
  /** The address of this host's compensation, when the campaign offers one. */
  compensation?: string;
}) {
  const t = useT();
  const steps = useTargetSteps(campaignID, hostID);
  if (steps.error) return <ErrorBox error={steps.error} />;
  if (!steps.data) return <Empty>{t("Loading…")}</Empty>;
  const order = steps.data.step_order.length > 0 ? steps.data.step_order : Object.keys(STEP_NAMES);
  const byKey = new Map<string, CampaignStep>(steps.data.items.map((step) => [step.step_key, step]));
  if (byKey.size === 0) return <Empty>{t("No step recorded yet.")}</Empty>;
  const explained = order.map((key) => byKey.get(key)).filter((step): step is CampaignStep => !!step?.reason);
  // The change landed when the execute step succeeded, whatever the reboot
  // or the verification did after it - the same rule the server counts
  // changed hosts by, and the rule the row cannot apply on its own.
  const changed = byKey.get("execute")?.state === "succeeded";
  return (
    <>
      <div style={{ display: "flex", flexWrap: "wrap", alignItems: "center", gap: 6 }} data-testid="step-strip">
        {order.map((key, index) => {
          const step = byKey.get(key);
          const name = t(STEP_NAMES[key] ?? key);
          return (
            <span key={key} style={{ display: "inline-flex", alignItems: "center", gap: 6 }}>
              {index > 0 && <span className="source">→</span>}
              {step ? (
                <span className="chip" title={step.reason || undefined}>
                  {name}
                  <JobState state={step.state} />
                  {/* The task carried the step and opens on its own page.
                      The short identifier is enough to tell it apart; the
                      whole one is on hover. */}
                  {step.job_id && (
                    <Link to={`/jobs/${step.job_id}`} className="mono" title={step.job_id}>
                      {step.job_id.slice(0, 8)}
                    </Link>
                  )}
                  {step.attempts > 1 && <span className="source">{t("attempt {n}", { n: step.attempts })}</span>}
                </span>
              ) : (
                <span className="chip unknown" title={t("The host has not reached this step.")}>{name} —</span>
              )}
            </span>
          );
        })}
      </div>
      {explained.length > 0 && (
        <Pairs>
          {explained.map((step) => (
            <Pair key={step.step_key} label={t(STEP_NAMES[step.step_key] ?? step.step_key)}>{step.reason}</Pair>
          ))}
        </Pairs>
      )}
      {compensation && changed && (
        <p>
          <Link to={compensation}>{t("compensate this host")}</Link>
          {" · "}
          {t("The change landed on this host; the compensation is a new campaign on this host alone, with its own plan and approval.")}
        </p>
      )}
    </>
  );
}

/** The classes of return a compensation can be planned along; the others have no plan to make. */
const PLANNABLE_ROLLBACK = ["exact_restore", "compensating", "automatic_local"];

/**
 * What the compensation card offers on a campaign. Nothing until the
 * campaign settled - the server refuses a compensation of a campaign that
 * may still change hosts, and the count of changed hosts is zero until
 * then. A plain statement for an operation with no reverse the panel could
 * plan. Otherwise the reverse operation with the count of changed hosts:
 * as a campaign where the reverse runs as one, and as a note where it runs
 * host by host today.
 */
export type CompensationOffer =
  | { kind: "not_settled" }
  | { kind: "no_reverse" }
  | { kind: "nothing_changed"; reverse: string }
  | { kind: "host_by_host"; reverse: string; changed: number }
  | { kind: "campaign"; reverse: string; changed: number };

/**
 * compensationOffer decides the variant from the record and the catalogue
 * alone, so the decision reads without a screen. The rollback class and
 * the reverse operation both come from the catalogue: a class that can be
 * planned along without a declared reverse is no offer, and a reverse
 * under a best-effort or absent way back is none either.
 */
export function compensationOffer(input: {
  state: string;
  rollback?: string;
  reverseAction?: string;
  reverseReady?: boolean;
  changedHosts?: number;
}): CompensationOffer {
  if (!SETTLED_CAMPAIGN_STATES.includes(input.state)) return { kind: "not_settled" };
  if (!input.reverseAction || !PLANNABLE_ROLLBACK.includes(input.rollback ?? "")) return { kind: "no_reverse" };
  const changed = input.changedHosts ?? 0;
  if (changed <= 0) return { kind: "nothing_changed", reverse: input.reverseAction };
  if (!input.reverseReady) return { kind: "host_by_host", reverse: input.reverseAction, changed };
  return { kind: "campaign", reverse: input.reverseAction, changed };
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

/**
 * The risk classes whose approval needs a reason the server accepts: an
 * operation that can cut a host off or destroy what it holds is approved
 * with a sentence, not a click.
 */
function approvalReasonRequired(risk: string | undefined): boolean {
  return risk === "critical" || risk === "destructive";
}
