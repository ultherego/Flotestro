import { useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ApiError, type Collection } from "../../lib/api";
import { absoluteTime, relativeTime } from "../../lib/format";
import { moduleForAction } from "../../lib/modules";
import { OPERATIONS_INTERVAL, useProgress, useProgressStream, type Progress } from "../../lib/stream";
import {
  loadedTargets, SETTLED_CAMPAIGN_STATES, TARGET_STATES, useTargets, useTargetSteps,
  type CampaignStep, type CompensationLinks, type TargetRow,
} from "../../lib/targets";
import {
  STALE_PLAN_CODES, planStatus, unknownPlanHosts,
  type HostPlan, type PackagePlanFacts, type PlanGroup,
} from "../../components/plan";
import { stateName } from "../../lib/states";
import {
  bulkPrefill, contractWords, MIN_REASON, reasonValid, REVERSE_OPERATION, reversePayload,
  useOperation, type Operation, type PlanGroups,
} from "../../lib/orders";
import { describeExpression } from "../../lib/selectors";
import type {
  Campaign as CampaignType, CampaignApproval, CampaignReport, CampaignTarget,
  SelectorExpression, TimelineEntry,
} from "../../lib/types";
import type { Attempt } from "../../lib/types";
import { useT } from "../../i18n";
import {
  Band, Banner, Bones, Card, Chart, Check, Empty, Fact, Facts, Feed, FeedRow, Field, Fields, Find,
  Grid, Kpi, Kpis, Meter, Modal, Needs, Note, Pill, Problem, Ring, Screen, Squares, Stack, Table,
  Tabs, Tag, Tags, Toolbar, useTab, type Segment, type Series, type Tone,
} from "../kit";
import { campaignTone } from "./Campaigns";
import { ErrorCode, PlanBody, Save } from "./Job";

/**
 * One rollout across many hosts: its plan, its gates, its waves, its
 * progress, and the decisions it is waiting on.
 *
 * Everything counted here is counted by the server. A host that never
 * answered is not counted as done, and a count that has not arrived is an
 * em dash rather than a nought - a campaign over a fleet nobody has heard
 * from and a campaign over a fleet with nothing wrong are different
 * answers, and the operator decides differently on each.
 */

/** The record as the API returns it, beyond the shared campaign type. */
export type CampaignRecord = CampaignType & CompensationLinks & {
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

/** The cancel protocol as a target row carries it. */
export type CancelState = {
  cancel_requested_at?: string;
  cancel_outcome?: string;
  cancel_phase?: string;
};

/** The classes of return a compensation can be planned along. */
const PLANNABLE_ROLLBACK = ["exact_restore", "compensating", "automatic_local"];

/** The step names as the strip shows them; the keys are the server's step kinds. */
const STEP_NAMES: Record<string, string> = {
  plan: "plan", execute: "execute", reboot: "reboot", verify: "verify", compensate: "compensate",
};

/** Which decision the screen is asking about. */
type Asking =
  | { kind: "approve" | "advance" | "pause" | "resume" | "cancel" | "retry" }
  | { kind: "skip"; target: TargetRow };

/**
 * One line about the cancel of a host's task: what the host answered, or
 * that the answer is still awaited.
 */
export function cancelOutcomeLine(
  target: CancelState,
  t: (key: string, params?: Record<string, string | number>) => string,
): string {
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
 * Whether the operator may skip the host by name: only a host waiting for
 * its connection in a campaign that has not settled - the offline canary
 * the barrier waits for.
 */
export function canSkipTarget(target: { state: string }, campaignState: string): boolean {
  return target.state === "queued_offline" && !SETTLED_CAMPAIGN_STATES.includes(campaignState);
}

/** What the compensation card offers on a campaign. */
export type CompensationOffer =
  | { kind: "not_settled" }
  | { kind: "no_reverse" }
  | { kind: "nothing_changed"; reverse: string }
  | { kind: "host_by_host"; reverse: string; changed: number }
  | { kind: "campaign"; reverse: string; changed: number };

/**
 * compensationOffer decides the variant from the record and the catalogue
 * alone, so the decision reads without a screen.
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

/** The secrets a payload refers to, as "name" or "name@version". */
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

/** eventHostName translates a host identifier into a name from the target list. */
export function eventHostName(entry: TimelineEntry, targets: CampaignTarget[]): string {
  const hostID = entry.payload?.host_id;
  if (!hostID) return "—";
  const target = targets.find((item) => item.host_id === hostID);
  return target?.hostname || hostID.slice(0, 8);
}

/** eventDescription shows what tells one event from another. */
export function eventDescription(entry: TimelineEntry): string {
  const parts = [
    entry.payload?.error_code,
    entry.payload?.message,
    entry.payload?.pause_reason,
  ].filter((part) => part);
  // A host that takes no part carries no wave number; naming one would
  // invent a place in the rollout it never had.
  if (typeof entry.payload?.wave === "number" && entry.payload.wave >= 0
    && entry.aggregate_type === "campaign_target") {
    parts.unshift(`wave ${entry.payload.wave}`);
  }
  return parts.join(" · ") || "—";
}

/**
 * timelineCSV renders the filtered trail as a file the browser saves: the
 * same columns as the feed, one row per event.
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

/**
 * The state of one host in a rollout as a tone.
 *
 * A host nobody heard from is not a host that failed, and a host somebody
 * left out is neither: three decisions, three colours.
 */
export function targetTone(state: string): Tone {
  if (["succeeded", "no_change"].includes(state)) return "ok";
  if (["failed", "timed_out", "partially_applied"].includes(state)) return "error";
  if (["unknown", "queued_offline", "awaiting_budget", "awaiting_lock"].includes(state)) return "warn";
  if (["skipped", "canceled", "excluded", "ineligible"].includes(state)) return "unknown";
  if (["running", "rebooting", "verifying", "planning", "dispatched"].includes(state)) return "info";
  return "neutral";
}

/**
 * The progress of a campaign target, looked up by the operation that
 * belongs to it.
 */
export function targetProgress(progress: Map<string, Progress>, target: CampaignTarget): Progress | undefined {
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
export function approvalReasonRequired(risk: string | undefined): boolean {
  return risk === "critical" || risk === "destructive";
}

/** The sub-tabs of one campaign, in the order a reader wants them. */
const CAMPAIGN_TABS = ["progress", "hosts", "order", "approval", "timeline"] as const;

export function Campaign() {
  const t = useT();
  const [tab, go] = useTab(CAMPAIGN_TABS);
  const { id = "" } = useParams();
  const queryClient = useQueryClient();
  const navigate = useNavigate();

  const [stateFilter, setStateFilter] = useState("");
  const [search, setSearch] = useState("");
  // The timeline is read through a filter of its own: one kind of event,
  // or one host, out of the trail of a campaign on thousands.
  const [eventKind, setEventKind] = useState("");
  const [eventHost, setEventHost] = useState("");
  // The decision being taken, and the evidence that goes into the record
  // with it. Every control carries a reason the trail keeps.
  const [asking, setAsking] = useState<Asking | null>(null);
  const [reason, setReason] = useState("");
  const [changeTicket, setChangeTicket] = useState("");
  const [includeUnknown, setIncludeUnknown] = useState(false);
  // The plan and the steps the operator opened from the target table.
  const [openPlan, setOpenPlan] = useState<{ jobId: string; host: string } | null>(null);
  const [openSteps, setOpenSteps] = useState<{ hostId: string; host: string } | null>(null);

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
  // event sent while the panel was restarting exists nowhere else.
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

  // This is the screen where progress matters for a decision: the operator
  // watches the canary and decides whether to let further waves go.
  useProgressStream(id ? `/api/v1/campaigns/${id}/events` : null, [
    ["campaign", id],
    ["campaign-targets", id],
    ["campaign-report", id],
    ["campaign-timeline", id],
    ["campaign-steps", id],
  ]);
  const progress = useProgress(id ? `/api/v1/campaigns/${id}/events` : null);

  const close = () => { setAsking(null); setReason(""); setChangeTicket(""); setIncludeUnknown(false); };
  const ask = (next: Asking) => { control.reset(); retry.reset(); skip.reset(); setReason(""); setAsking(next); };

  // Every control carries a reason.
  const controlBody = (operation: string) => {
    if (operation === "approve") {
      return {
        approval_fingerprint: campaign.data?.approval_fingerprint,
        reason: reason.trim(),
        change_ticket: changeTicket.trim(),
      };
    }
    return { reason: reason.trim() || "from the panel" };
  };
  const retry = useMutation({
    mutationFn: () => api.post<CampaignRecord>(`/api/v1/campaigns/${id}/retry`, {
      reason: reason.trim(), include_unknown: includeUnknown,
    }),
    onSuccess: (created) => {
      close();
      void queryClient.invalidateQueries({ queryKey: ["campaigns"] });
      void queryClient.invalidateQueries({ queryKey: ["campaign", id] });
      navigate(`/campaigns/${created.id}`);
    },
  });
  // The skip of a host waiting for its connection: the offline canary the
  // barrier waits for, let go by name with a reason the dialog asks for.
  const skip = useMutation({
    mutationFn: ({ hostId, reason: why }: { hostId: string; reason: string }) =>
      api.post(`/api/v1/campaigns/${id}/targets/${hostId}/skip`, { reason: why }),
    onSuccess: () => {
      close();
      void queryClient.invalidateQueries({ queryKey: ["campaign", id] });
      void queryClient.invalidateQueries({ queryKey: ["campaign-targets", id] });
    },
  });
  const control = useMutation({
    mutationFn: (operation: string) => api.post(`/api/v1/campaigns/${id}/${operation}`, controlBody(operation)),
    onSuccess: () => {
      close();
      void queryClient.invalidateQueries({ queryKey: ["campaign", id] });
      void queryClient.invalidateQueries({ queryKey: ["campaign-targets", id] });
    },
  });

  const help = (
    <p>
      {t("What was ordered, as the approval binds it: this operation, this payload, these hosts, this rollout. The hosts are counted by what they reported, so a host that never answered is not counted as done. Every control on this screen - approve, advance, pause, resume, cancel, retry, skip - is recorded with who took the decision and why.")}
    </p>
  );

  if (campaign.error) {
    return (
      <Screen title={t("Campaign")} icon="campaigns" help={help}>
        <Card><Problem>{String(campaign.error)}</Problem></Card>
      </Screen>
    );
  }
  if (!campaign.data) {
    return (
      <Screen title={t("Campaign")} icon="campaigns" help={help}>
        <Card><Bones rows={4} /></Card>
      </Screen>
    );
  }

  const data = campaign.data as CampaignRecord;
  // The links to other campaigns travel on the record; the shared Campaign
  // type does not name them, so they are read through this one.
  const links = data;
  const counted = report.data !== undefined;
  const totals = report.data?.totals ?? {};

  // What a stop does depends on where the hosts are: a host that has not
  // started will not start, a host mid-operation finishes on its own - no
  // campaign action here interrupts work on a host or rolls it back.
  const offlineQueued = totals.queued_offline ?? 0;
  const waitingToStart = (totals.dispatched ?? 0) + (totals.awaiting_lock ?? 0);
  const notStarted = (totals.pending ?? 0) + (totals.awaiting_budget ?? 0) + (totals.planning ?? 0) + offlineQueued;
  const underWay = (totals.running ?? 0) + (totals.rebooting ?? 0) + (totals.verifying ?? 0) + waitingToStart;
  // No change is a success: the host has the desired state.
  const succeeded = totals.succeeded ?? 0;
  const noChange = totals.no_change ?? 0;
  const unknown = totals.unknown ?? 0;
  const failed = (totals.failed ?? 0) + (totals.timed_out ?? 0) + (totals.partially_applied ?? 0);
  const skipped = (totals.skipped ?? 0) + (totals.canceled ?? 0);
  const done = succeeded + noChange;

  const settled = SETTLED_CAMPAIGN_STATES.includes(data.state);
  const failedHosts = totals.failed ?? 0;
  const canRetry = settled && counted && failedHosts + unknown > 0;
  const retryable = canRetry ? failedHosts + (includeUnknown ? unknown : 0) : 0;
  // The approval of a critical or destructive operation needs a reason the
  // server accepts: the same rule as the fresh authentication it asks for,
  // checked here so the button says so instead of the refusal.
  const reasonForced = approvalReasonRequired(operation?.risk);
  const approvalReady = !reasonForced || reasonValid(reason);
  // A plan the panel cannot read on any host blocks the consent: nobody can
  // approve what nobody has seen.
  const unknownPlans = unknownPlanHosts(plans.data?.items ?? []);
  const staleHosts = loaded
    .filter((target) => STALE_PLAN_CODES.has(target.error_code ?? ""))
    .map((target) => target.hostname ?? target.host_id);
  const approvalBlocked = unknownPlans.length > 0;

  // What the hosts under way do when the campaign stops, from the cancel
  // mode of the operation.
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

  // The trail through its filter: the kinds are read off the trail itself,
  // so the list offers what happened rather than every kind the engine knows.
  const eventKinds = Array.from(new Set((timeline.data?.items ?? []).map((entry) => entry.event_type))).sort();
  const hostNeedle = eventHost.trim().toLowerCase();
  const events = (timeline.data?.items ?? []).filter((entry) =>
    (!eventKind || entry.event_type === eventKind)
    && (!hostNeedle || eventHostName(entry, loaded).toLowerCase().includes(hostNeedle)
      || (entry.payload?.host_id ?? "").toLowerCase().includes(hostNeedle)));

  // What the hosts came back with. A count that has not arrived is left
  // out of the band as "not counted" rather than drawn as a nought.
  const band: Segment[] = [
    { label: t("Not started"), value: counted ? notStarted - offlineQueued : undefined, tone: "neutral" },
    { label: t("Waiting for connection"), value: counted ? offlineQueued : undefined, tone: "warn" },
    { label: t("Waiting to start"), value: counted ? waitingToStart : undefined, tone: "warn" },
    { label: t("In progress"), value: counted ? underWay - waitingToStart : undefined, tone: "info" },
    { label: t("Succeeded"), value: counted ? succeeded : undefined, tone: "ok" },
    { label: t("No change"), value: counted ? noChange : undefined, tone: "ok" },
    { label: t("Failed"), value: counted ? failed : undefined, tone: "error" },
    { label: t("Unknown"), value: counted ? unknown : undefined, tone: "warn" },
    { label: t("Skipped"), value: counted ? skipped : undefined, tone: "unknown" },
  ];

  // What waits on a person. A count at zero does not belong on the list at
  // all; a count nobody could take is an em dash and says so.
  const everyNeed: { label: string; value?: number; tone?: Tone; to?: string }[] = [
    { label: t("The campaign waits for an approval"), value: data.state === "awaiting_approval" ? 1 : 0, tone: "warn" },
    { label: t("The canary is settled and the waves wait for a decision"), value: data.state === "manual_gate" ? 1 : 0, tone: "warn" },
    { label: t("Hosts waiting for their connection"), value: counted ? offlineQueued : undefined, tone: "warn" },
    {
      label: t("Hosts that failed"),
      value: counted ? failedHosts : undefined,
      tone: "error",
      to: `/jobs?campaign_id=${id}&state=failed`,
    },
    { label: t("Hosts that ended unknown"), value: counted ? unknown : undefined, tone: "warn" },
    {
      label: t("Hosts whose plan the panel cannot read"),
      value: plans.data ? unknownPlans.length : undefined,
      tone: "error",
    },
  ];
  const needs = everyNeed.filter((one) => one.value !== 0);

  // The rollout as it went, wave by wave: the one measurement of progress
  // over time the server actually keeps for a campaign.
  const waves = report.data?.waves ?? [];
  const waveSeries: Series[] = [
    {
      name: t("Succeeded"),
      tone: "ok",
      values: waves.map((wave) => (wave.totals.succeeded ?? 0) + (wave.totals.no_change ?? 0)),
    },
    {
      name: t("Failed"),
      tone: "error",
      values: waves.map((wave) => (wave.totals.failed ?? 0) + (wave.totals.timed_out ?? 0) + (wave.totals.partially_applied ?? 0)),
    },
    {
      name: t("Other"),
      tone: "neutral",
      values: waves.map((wave) => {
        const all = Object.values(wave.totals).reduce((sum, one) => sum + one, 0);
        const good = (wave.totals.succeeded ?? 0) + (wave.totals.no_change ?? 0);
        const bad = (wave.totals.failed ?? 0) + (wave.totals.timed_out ?? 0) + (wave.totals.partially_applied ?? 0);
        return Math.max(0, all - good - bad);
      }),
    },
  ];

  const headline = !counted
    ? undefined
    : data.state === "canceling"
      ? t("Canceled; {underWay} hosts still carry their tasks", { underWay })
      : failed > 0
        ? t("{done} of {total} hosts done, {failed} failed", { done, total, failed })
        : t("{done} of {total} hosts done", { done, total });

  const actions = (
    <>
      {data.state === "awaiting_approval" && (
        <button type="button" onClick={() => ask({ kind: "approve" })} data-testid="approve">{t("Approve")}</button>
      )}
      {data.state === "manual_gate" && (
        <button type="button" onClick={() => ask({ kind: "advance" })} data-testid="advance">{t("Advance to the waves")}</button>
      )}
      {["canary", "running", "planned", "manual_gate"].includes(data.state) && (
        <button type="button" className="fl-quiet" onClick={() => ask({ kind: "pause" })} data-testid="pause">{t("Pause")}</button>
      )}
      {(data.state === "paused" || data.state === "pausing") && (
        <button type="button" onClick={() => ask({ kind: "resume" })} data-testid="resume">{t("Resume")}</button>
      )}
      {!settled && data.state !== "canceling" && (
        <button type="button" className="fl-danger" onClick={() => ask({ kind: "cancel" })} data-testid="cancel">{t("Cancel")}</button>
      )}
      {canRetry && (
        <button type="button" onClick={() => ask({ kind: "retry" })} data-testid="retry">{t("Retry on failed hosts")}</button>
      )}
      {/* The same order once more, written into the wizard: the operation,
          the name and the payload; the targets and the rollout are decided
          there again. */}
      <Link
        className="fl-btn fl-quiet"
        to={bulkPrefill(data.action_type, data.name, data.payload ?? {})}
        title={t("Opens the Bulk workspace with the same operation, name and payload written in; the targets and the rollout are chosen again.")}
        data-testid="clone"
      >
        {t("Clone")}
      </Link>
    </>
  );

  return (
    <Screen
      title={data.name}
      icon="campaigns"
      help={help}
      actions={actions}
      /* The lead is a paragraph, so what goes in it has to read as a line
         of text: the kit's Tags is a block and cannot stand inside one. */
      lead={
        <>
          <Pill tone={campaignTone(data.state)}>{t(stateName(data.state))}</Pill>{" "}
          <Tag>{data.action_type}</Tag>{" "}
          <Tag>{t("requested by {who}", { who: data.created_by })}</Tag>{" "}
          {data.approved_by && <><Tag>{t("approved by {who}", { who: data.approved_by })}</Tag>{" "}</>}
          {data.started_at && <><Tag>{t("started {when}", { when: relativeTime(data.started_at) })}</Tag>{" "}</>}
          {data.finished_at && <Tag>{t("finished {when}", { when: relativeTime(data.finished_at) })}</Tag>}
        </>
      }
      banner={data.pause_reason && (data.state === "paused" || data.state === "pausing")
        ? <Banner tone="warn">{t("Paused by {who}: {why}", { who: data.paused_by || t("unknown"), why: data.pause_reason })}</Banner>
        : undefined}
    >
      <Kpis>
        <Kpi
          hero
          icon="campaigns"
          label={t("Hosts done")}
          value={counted ? done : null}
          note={headline}
          testId="kpi-done"
        />
        <Kpi label={t("Failed")} value={counted ? failed : null} tone="error" testId="kpi-failed" />
        <Kpi label={t("Under way")} value={counted ? underWay : null} tone="info" testId="kpi-underway" />
        <Kpi label={t("Unknown")} value={counted ? unknown : null} tone="warn" testId="kpi-unknown" />
      </Kpis>

      <Tabs
        value={tab}
        onChange={go}
        tabs={[
          { value: "progress", label: t("Progress") },
          { value: "hosts", label: t("Hosts"), count: total || undefined },
          { value: "order", label: t("Order") },
          { value: "approval", label: t("Approval") },
          { value: "timeline", label: t("Timeline") },
        ]}
      />

      {/* One campaign was thirteen containers on one board until 17.10.
          How far it got, which hosts, what was ordered, who consented and
          what happened are five readings, and the reader wants one. */}
      {tab === "progress" && (
      <>
      <Grid>
        <Card span={4} title={t("How far it has got")}>
          {/* A share nobody could take draws no arc at all: a campaign with
              no targets is not a campaign at nought per cent. */}
          <Ring
            share={counted && total > 0 ? done / total : undefined}
            label={t("of the hosts")}
            tone={failed > 0 ? "warn" : "ok"}
            legend={[
              { label: t("Succeeded"), value: counted ? succeeded : "—", tone: "ok" },
              { label: t("No change"), value: counted ? noChange : "—", tone: "ok" },
              { label: t("Failed"), value: counted ? failed : "—", tone: "error" },
              { label: t("Unknown"), value: counted ? unknown : "—", tone: "warn" },
              { label: t("Still to go"), value: counted ? notStarted + underWay : "—", tone: "neutral" },
            ]}
          />
        </Card>

        <Card span={8} title={t("The hosts")} note={counted ? undefined : t("The report has not arrived; nothing here is counted yet.")}>
          <Band segments={band} testId="target-states" />
        </Card>

        <Card
          span={4}
          title={t("Waiting on a person")}
          note={t("Nothing here moves until somebody decides.")}
        >
          {needs.length === 0
            ? <Empty>{t("Nothing waits on a person.")}</Empty>
            : <Needs items={needs} />}
        </Card>

        <Card
          span={8}
          title={t("The rollout, wave by wave")}
          note={t("Each wave as the report counts it; the canary is the first.")}
        >
          {!report.data ? (
            <Bones rows={4} />
          ) : waves.length === 0 ? (
            <Empty>{t("No wave has been recorded yet.")}</Empty>
          ) : (
            <Chart
              testId="waves-chart"
              everyLabel={1}
              labels={waves.map((wave) => (wave.is_canary ? t("canary") : t("wave {n}", { n: wave.wave })))}
              series={waveSeries}
            />
          )}
        </Card>

        {/* The drawing above groups the states into three bands so the
            shape of the rollout can be read; this is the report itself.
            Whether a wave is closed is on no drawing at all: a wave that
            has run every host and a wave still letting hosts in look the
            same from their counts, and the operator decides differently
            on each. */}
        <Card
          span={12}
          title={t("Waves")}
          note={t("Each wave as the report counts it, state by state.")}
          flush
          foot={report.data ? t("{n} waves", { n: waves.length }) : undefined}
        >
          <Table
            rows={waves}
            keyOf={(one) => String(one.wave)}
            rowTestId={(one) => `wave-${one.wave}`}
            testId="waves"
            loading={!report.data}
            empty={t("No wave has been recorded yet.")}
            columns={[
              { key: "wave", head: t("Wave"), num: true, cell: (one) => one.wave },
              {
                key: "canary",
                head: t("Canary"),
                cell: (one) => one.is_canary
                  ? <Pill tone="info" title={t("The first wave, the one the barrier rests on.")}>{t("yes")}</Pill>
                  : t("no"),
              },
              {
                key: "closed",
                head: t("Closed"),
                cell: (one) => one.completed
                  ? <Pill tone="ok" title={t("Every host of this wave has finished.")}>{t("yes")}</Pill>
                  : <Pill tone="info" title={t("Hosts of this wave are still under way.")}>{t("no")}</Pill>,
              },
              {
                key: "summary",
                head: t("Summary"),
                cell: (one) => {
                  const counted = Object.entries(one.totals).filter(([, n]) => n > 0);
                  // A wave the report put no count against is not a wave of
                  // noughts - nobody counted it - and it says so.
                  if (counted.length === 0) {
                    return <Pill tone="unknown">{t("not counted")}</Pill>;
                  }
                  return (
                    <Tags>
                      {counted.map(([state, n]) => (
                        <Pill key={state} tone={targetTone(state)}>
                          {`${t(stateName(state))}: ${n}`}
                        </Pill>
                      ))}
                    </Tags>
                  );
                },
              },
            ]}
          />
        </Card>

        {/* The whole set in one block: it answers "is anything wrong"
            before a number can be read, and stays readable where a table
            of a thousand rows does not. */}
        <Card
          span={12}
          title={t("Every host the campaign reached")}
          note={t("{shown} of {total} loaded; a square is a host.", { shown: loaded.length, total })}
        >
          {loaded.length === 0 ? (
            targets.isLoading ? <Bones rows={3} /> : <Empty>{t("No targets.")}</Empty>
          ) : (
            <Squares
              testId="target-squares"
              items={loaded.map((target) => ({
                key: target.host_id,
                tone: targetTone(target.state),
                title: `${target.hostname || target.host_id.slice(0, 8)} · ${target.state}`,
                to: `/hosts/${target.host_id}`,
              }))}
              tally={[
                { label: t("succeeded"), value: counted ? succeeded + noChange : "—", tone: "ok" },
                { label: t("failed"), value: counted ? failed : "—", tone: "error" },
                { label: t("unknown"), value: counted ? unknown : "—", tone: "warn" },
                { label: t("still to go"), value: counted ? notStarted + underWay : "—", tone: "neutral" },
              ]}
            />
          )}
        </Card>
      </Grid>

      {/* A host that came back with a different plan ran nothing: the
          consent covered the old plan, and the operator is to see which
          hosts need a new one rather than count them among the skipped. */}
      {report.data?.plan_changed && report.data.plan_changed.length > 0 && (
        <Card
          title={t("Plans changed after a reconnect")}
          note={t("These hosts came back with a state that gives a different plan than the one approved. Nothing ran on them; order a new campaign to approve the new plans.")}
          flush
        >
          <Table
            testId="plan-changed"
            rows={report.data.plan_changed}
            keyOf={(target) => target.host_id}
            columns={[
              {
                key: "host",
                head: t("Host"),
                cell: (target) => (
                  <Link to={`/hosts/${target.host_id}/${moduleForAction(data.action_type)}?campaign=${id}`}>
                    {target.hostname || target.host_id.slice(0, 8)}
                  </Link>
                ),
              },
              { key: "message", head: t("Message"), cell: (target) => target.message || "—" },
            ]}
          />
        </Card>
      )}

      </>
      )}

      {/* The order itself, before any decision about it: what runs, with
          what payload, on which hosts as they were named, under which
          rollout. The approver reads this; the fingerprint binds the
          consent to exactly it. */}
      {tab === "order" && <Order campaign={data} operation={operation} />}

      {tab === "approval" && (
      <>
      <Grid>
        <Card span={6} title={t("The record")}>
          <Facts>
            <Fact label={t("Requested by")}>{data.created_by}</Fact>
            <Fact label={t("Approved by")}>
              {data.approved_by || "—"}
              {data.approved_at && <> · <span title={absoluteTime(data.approved_at)}>{relativeTime(data.approved_at)}</span></>}
            </Fact>
            <Fact label={t("Approval fingerprint")}>
              <span className="fl-mono" title={data.approval_fingerprint}>{data.approval_fingerprint.slice(0, 16) || "—"}</span>
            </Fact>
            {data.plan_set_hash && (
              <Fact label={t("Plan set fingerprint")}>
                <span className="fl-mono" title={data.plan_set_hash}>{data.plan_set_hash.slice(0, 16)}</span>
              </Fact>
            )}
            <Fact label={t("Manual gate after the canary")}>
              {!data.manual_gate
                ? t("no")
                : data.gate_advanced_by
                  ? t("advanced by {who}", { who: data.gate_advanced_by })
                  : t("yes")}
            </Fact>
            <Fact label={t("Paused by")}>{data.paused_by || "—"}</Fact>
            <Fact label={t("Pause reason")}>{data.pause_reason || "—"}</Fact>
            {data.canceled_by && <Fact label={t("Canceled by")}>{data.canceled_by}</Fact>}
            <Fact label={t("Created")}>
              <span title={absoluteTime(data.created_at)}>{relativeTime(data.created_at)}</span>
            </Fact>
            <Fact label={t("Started")}>
              {data.started_at ? <span title={absoluteTime(data.started_at)}>{relativeTime(data.started_at)}</span> : "—"}
            </Fact>
            <Fact label={t("Finished")}>
              {data.finished_at ? <span title={absoluteTime(data.finished_at)}>{relativeTime(data.finished_at)}</span> : "—"}
            </Fact>
            {/* The retries of this campaign, read from their records: the
                list informs and never hides the button. */}
            {settled && (
              <Fact label={t("Retried by")}>
                {links.retried_by && links.retried_by.length > 0
                  ? (
                    <Tags>
                      {links.retried_by.map((other) => (
                        <Tag key={other.id} to={`/campaigns/${other.id}`}>
                          {other.name} · {t(stateName(other.state))}
                        </Tag>
                      ))}
                    </Tags>
                  )
                  : canRetry ? t("no retry ordered yet") : t("nothing to retry")}
              </Fact>
            )}
          </Facts>
        </Card>

        {approvals.data && approvals.data.items.length > 0 && (
          <Card span={6} title={t("Approval record")} note={t("written once, never changed")} flush>
            <Table
              testId="approval-record"
              rows={approvals.data.items}
              keyOf={(record) => record.id}
              columns={[
                { key: "who", head: t("Approved by"), cell: (record) => record.approved_by },
                { key: "asked", head: t("Requested by"), minor: true, cell: (record) => record.requested_by },
                {
                  key: "auth",
                  head: t("Authentication"),
                  cell: (record) => (
                    <span title={record.acr ? `acr ${record.acr}${record.amr?.length ? `, amr ${record.amr.join(" ")}` : ""}` : undefined}>
                      {record.authentication === "api_token" ? t("API token (not re-authenticated)") : t("session")}
                      {record.authenticated_at && ` · ${relativeTime(record.authenticated_at)}`}
                    </span>
                  ),
                },
                { key: "why", head: t("Reason"), cell: (record) => record.reason || "—" },
                { key: "ticket", head: t("Change ticket"), tight: true, minor: true, cell: (record) => record.change_ticket || "—" },
                {
                  key: "when",
                  head: t("When"),
                  cell: (record) => <span title={absoluteTime(record.created_at)}>{relativeTime(record.created_at)}</span>,
                },
              ]}
            />
          </Card>
        )}
      </Grid>

      {/* The way back, as a decision on a settled campaign: how many hosts
          changed, what class of return the operation declares, and one way
          into a new plan with its own approval. An operation with no way
          back says so here rather than leaving it to be inferred. */}
      {offer.kind !== "not_settled" && (
        <Card
          title={t("Compensation")}
          note={`${t("Way back")}: ${rollbackWord} — ${rollbackMeaning}`}
          foot={offer.kind === "campaign" ? (
            <>
              <Link className="fl-btn" to={compensationOf()} data-testid="compensate">
                {t("Compensate {n} hosts", { n: offer.changed })}
              </Link>
              <span className="fl-note">
                {t("The compensation is a new campaign with its own plans and its own approval; the version or the rollback identifier is per host.")}
              </span>
            </>
          ) : undefined}
        >
          <Stack>
            <Note>
              {offer.kind === "no_reverse" && t("There is no reverse operation to plan for this campaign; what it changed stays as the hosts hold it.")}
              {offer.kind === "nothing_changed" && t("No host was changed by this campaign; there is nothing to compensate.")}
              {offer.kind === "host_by_host" && t("{n} hosts changed. The reverse operation {action} runs host by host today; a compensating campaign is not offered.", { n: offer.changed, action: offer.reverse })}
              {offer.kind === "campaign" && t("{n} hosts changed and can be put back by {action} on exactly those hosts; a host the change did not land on is refused.", { n: offer.changed, action: offer.reverse })}
            </Note>
            <Facts>
              {/* What was already ordered to undo this campaign, read from
                  the compensating records: a second compensation is still
                  the operator's decision, so the list informs and never
                  hides the button. */}
              <Fact label={t("Compensated by")}>
                {links.compensated_by && links.compensated_by.length > 0
                  ? (
                    <Tags>
                      {links.compensated_by.map((other) => (
                        <Tag key={other.id} to={`/campaigns/${other.id}`}>
                          {other.name} · {t(stateName(other.state))}
                        </Tag>
                      ))}
                    </Tags>
                  )
                  : t("no compensation ordered yet")}
              </Fact>
            </Facts>
          </Stack>
        </Card>
      )}

      </>
      )}

      {tab === "order" && (
      <Card
        title={t("Plans")}
        note={t("One group is one shape of the change and the hosts that get it.")}
      >
        {plans.error ? (
          <Problem>{String(plans.error)}</Problem>
        ) : !plans.data ? (
          <Bones rows={4} />
        ) : plans.data.items.length === 0 ? (
          <Empty>{t("No plan yet.")}</Empty>
        ) : (
          <Stack wide>
            {plans.data.items.map((group) => (
              <PlanGroupBody key={group.plan_hash} group={group} action={actionType} stale={staleHosts} />
            ))}
            {staleHosts.length > 0 && canRetry && (
              <Banner
                tone="warn"
                actions={
                  <button type="button" className="fl-quiet fl-small" onClick={() => ask({ kind: "retry" })} data-testid="replan">
                    {t("Replan")}
                  </button>
                }
              >
                {t("{n} hosts refused the plan as stale; the previous consent does not carry over. Order a retry to plan them again.", { n: staleHosts.length })}
              </Banner>
            )}
          </Stack>
        )}
      </Card>
      )}

      {/* The trail is filtered in the browser: it is already loaded whole,
          and one kind of event or one host is what a diagnosis looks for.
          The export is the filtered rows, built here from the same list. */}
      {tab === "timeline" && (
      <Card
        title={t("Timeline")}
        flush
        tools={events.length > 0 ? (
          <a
            className="fl-btn fl-quiet fl-small"
            href={timelineCSV(events, loaded)}
            download={`campaign-${id}-timeline.csv`}
            data-testid="timeline-csv"
          >
            {t("Download the timeline as CSV")}
          </a>
        ) : undefined}
      >
        <Toolbar end={<span className="fl-note">{t("{shown} of {total} shown", { shown: events.length, total: timeline.data?.items.length ?? 0 })}</span>}>
          <select value={eventKind} onChange={(event) => setEventKind(event.target.value)} aria-label={t("Event kind")} data-testid="event-kind">
            <option value="">{t("event: any")}</option>
            {eventKinds.map((kind) => <option key={kind} value={kind}>{kind}</option>)}
          </select>
          <Find value={eventHost} onChange={setEventHost} placeholder={t("Filter by hostname")} testId="event-host" />
        </Toolbar>
        {!timeline.data ? (
          <Bones rows={4} />
        ) : timeline.data.items.length === 0 ? (
          <Empty>{t("No recorded events yet.")}</Empty>
        ) : events.length === 0 ? (
          <Empty>{t("No event matches the filter.")}</Empty>
        ) : (
          <Feed>
            {events.map((entry) => (
              <FeedRow
                key={entry.id}
                icon="campaigns"
                tone={entry.payload?.error_code ? "error" : entry.payload?.pause_reason ? "warn" : "neutral"}
                what={<><span className="fl-mono">{entry.event_type}</span>{" "}{eventDescription(entry)}</>}
                who={
                  <>
                    {eventHostName(entry, loaded)}
                    {/* The task behind the event opens on its own screen. */}
                    {entry.payload?.job_id && <> · {entry.payload.job_id.slice(0, 8)}</>}
                  </>
                }
                when={<span title={absoluteTime(entry.occurred_at)}>{relativeTime(entry.occurred_at)}</span>}
                to={entry.payload?.job_id ? `/jobs/${entry.payload.job_id}` : undefined}
              />
            ))}
          </Feed>
        )}
      </Card>
      )}

      {tab === "hosts" && (
      <>
      {/* The export is a file, not a screen: a report of ten thousand hosts
          goes to a spreadsheet, streamed from the server page by page. */}
      <Card
        title={t("Targets")}
        flush
        tools={
          <a
            className="fl-btn fl-quiet fl-small"
            href={`/api/v1/campaigns/${id}/report?format=csv`}
            download={`campaign-${id}.csv`}
            data-testid="targets-csv"
          >
            {t("Download the targets as CSV")}
          </a>
        }
        foot={
          <>
            <span className="fl-note">{t("{shown} of {total} shown", { shown: loaded.length, total })}</span>
            {targets.hasNextPage && (
              <button
                type="button"
                className="fl-quiet fl-small"
                onClick={() => void targets.fetchNextPage()}
                disabled={targets.isFetchingNextPage}
                data-testid="more-targets"
              >
                {t("Load more ({n} left)", { n: total - loaded.length })}
              </button>
            )}
          </>
        }
      >
        {/* The filter runs on the server and the rows arrive page by page:
            the screen shows what the operator asked about, not the whole
            fleet at once. */}
        <Toolbar>
          <select value={stateFilter} onChange={(event) => setStateFilter(event.target.value)} aria-label={t("State")} data-testid="target-state">
            <option value="">{t("state: any")}</option>
            {TARGET_STATES.map((value) => <option key={value} value={value}>{t(stateName(value))}</option>)}
          </select>
          <Find value={search} onChange={setSearch} placeholder={t("Filter by hostname")} testId="target-search" />
        </Toolbar>
        <Table
          testId="targets"
          rows={loaded}
          keyOf={(target) => target.host_id}
          rowTestId={(target) => `target-${target.hostname || target.host_id}`}
          loading={targets.isLoading} empty={t("No targets.")}
          columns={[
            {
              key: "host",
              head: t("Host"),
              tight: true,
              // The host opens on the module of the change, with the way
              // back to this campaign in the address.
              cell: (target) => (
                <Link to={`/hosts/${target.host_id}/${moduleForAction(data.action_type)}?campaign=${id}`}>
                  {target.hostname || target.host_id.slice(0, 8)}
                </Link>
              ),
            },
            {
              key: "wave",
              head: t("Wave"),
              num: true,
              // A host that was settled when the campaign was ordered is in
              // no wave; showing it as wave zero would read as a canary.
              cell: (target) => (
                <span title={target.wave < 0 ? t("The host takes no part in the campaign and is in no wave.") : undefined}>
                  {target.wave < 0 ? "—" : target.wave}{target.wave === 0 ? ` (${t("canary")})` : ""}
                </span>
              ),
            },
            {
              key: "plan",
              head: t("Plan"),
              // The consent covers the differences computed on the host, not
              // the intent. A host with a planning operation opens its plan
              // below the table, because the summary does not fit a row.
              cell: (target) => target.plan_job_id ? (
                <button
                  type="button"
                  className="fl-plain"
                  aria-pressed={openPlan?.jobId === target.plan_job_id}
                  onClick={() => setOpenPlan(openPlan?.jobId === target.plan_job_id
                    ? null
                    : { jobId: target.plan_job_id as string, host: target.hostname || target.host_id.slice(0, 8) })}
                  data-testid={`plan-${target.host_id}`}
                >
                  {t("plan")}
                </button>
              ) : "—",
            },
            {
              key: "steps",
              head: t("Steps"),
              cell: (target) => (
                <button
                  type="button"
                  className="fl-plain"
                  aria-pressed={openSteps?.hostId === target.host_id}
                  onClick={() => setOpenSteps(openSteps?.hostId === target.host_id
                    ? null
                    : { hostId: target.host_id, host: target.hostname || target.host_id.slice(0, 8) })}
                  data-testid={`steps-${target.host_id}`}
                >
                  {t("steps")}
                </button>
              ),
            },
            {
              key: "state",
              head: t("State"),
              cell: (target) => (
                <Tags>
                  <Pill tone={targetTone(target.state)}>{t(stateName(target.state))}</Pill>
                  {/* A host that has not started says what it waits on: the
                      lock another task of the host holds, as the agent named
                      it. Without it a running host that does nothing looks
                      like a lost one. */}
                  {target.blocker && <Pill tone="warn" title={target.blocker}>{t("blocked")}</Pill>}
                  {/* The cancel protocol on the host: asked, and what the
                      host answered. A cancel written on the panel alone
                      would say "stopped" about a transaction the host ran
                      to its end. */}
                  {cancelOutcomeLine(target as CancelState, t) && (
                    <Pill tone="unknown" title={cancelOutcomeLine(target as CancelState, t)}>{t("cancel")}</Pill>
                  )}
                  {/* An offline canary holds the barrier; the operator may
                      let it go by name, with a reason. */}
                  {canSkipTarget(target, data.state) && (
                    <button
                      type="button"
                      className="fl-plain"
                      onClick={() => ask({ kind: "skip", target })}
                      disabled={skip.isPending}
                      title={t("Leave this host out with a reason; a skipped canary opens the waves.")}
                      data-testid={`skip-${target.host_id}`}
                    >
                      {t("Skip")}
                    </button>
                  )}
                </Tags>
              ),
            },
            {
              key: "progress",
              head: t("Progress"),
              // The progress belongs to the operation currently running on
              // this host. A host waiting for its wave has nothing to show.
              cell: (target) => {
                const moving = targetProgress(progress, target);
                if (!moving) return <span className="fl-faint">—</span>;
                return (
                  <Meter
                    share={(moving.percent ?? 0) / 100}
                    tone="info"
                    text={moving.percent !== undefined
                      ? `${Math.round(moving.percent)}%`
                      : t("{step} of {total}", { step: moving.step ?? 0, total: moving.total ?? 0 })}
                  />
                );
              },
            },
            { key: "error", head: t("Error code"), tight: true, cell: (target) => <ErrorCode code={target.error_code} /> },
            { key: "message", head: t("Message"), minor: true, tight: true, cell: (target) => target.message || "—" },
            // The way back for one host. A row knows the target's state and
            // not its steps, so only a host that succeeded gets the link
            // here; a host that failed after its change landed is offered it
            // from its step strip, which knows.
            ...(rowCompensation ? [{
              key: "back",
              head: t("Way back"),
              actions: true,
              cell: (target: TargetRow) => target.state === "succeeded"
                ? <Link to={compensationOf([target.host_id])}>{t("compensate this host")}</Link>
                : "—",
            }] : []),
          ]}
        />
      </Card>

      {openPlan && (
        <Card
          title={t("Plan for {host}", { host: openPlan.host })}
          tools={
            <button type="button" className="fl-quiet fl-small" onClick={() => setOpenPlan(null)}>{t("Close")}</button>
          }
        >
          <HostPlanOf jobId={openPlan.jobId} />
        </Card>
      )}

      {openSteps && (
        <Card
          title={t("Steps for {host}", { host: openSteps.host })}
          note={t("Every executable step of the host with its task, its attempts and the reason it did not run. A step without a record has not been reached.")}
          tools={
            <button type="button" className="fl-quiet fl-small" onClick={() => setOpenSteps(null)}>{t("Close")}</button>
          }
        >
          <TargetSteps
            campaignID={id}
            hostID={openSteps.hostId}
            compensation={rowCompensation ? compensationOf([openSteps.hostId]) : undefined}
          />
        </Card>
      )}
      </>
      )}

      {asking?.kind === "retry" && canRetry && (
        <Modal
          title={t("Retry on failed hosts?")}
          onClose={close}
          actions={
            <>
              <button type="button" className="fl-quiet" onClick={close}>{t("Back")}</button>
              <button
                type="button"
                onClick={() => retry.mutate()}
                disabled={retry.isPending || !reasonValid(reason) || retryable === 0}
                data-testid="confirm-retry"
              >
                {t("Order the retry on {n} hosts", { n: retryable })}
              </button>
            </>
          }
        >
          <Note>
            {t("A new campaign with the same operation, payload and rollout on exactly the {n} hosts that did not reach the desired state; the hosts that succeeded are not touched. It waits for its own approval and is linked to this one.", { n: retryable })}
          </Note>
          <Fields>
            <Field label={t("Reason for the trail")} wide hint={t("Required: at least {n} characters.", { n: MIN_REASON })}>
              <input autoFocus value={reason} onChange={(event) => setReason(event.target.value)} data-testid="reason" />
            </Field>
          </Fields>
          {/* An unknown host may hold the change half done; running it again
              blind is the operator's call, made here on purpose. */}
          <Check checked={includeUnknown} onChange={setIncludeUnknown}>
            {t("Include the {n} hosts that ended unknown (read what they hold first)", { n: unknown })}
          </Check>
          {retry.error && (
            <Problem>
              {retry.error instanceof ApiError ? `${retry.error.code} · ` : ""}
              {retry.error instanceof Error ? retry.error.message : String(retry.error)}
            </Problem>
          )}
        </Modal>
      )}

      {asking?.kind === "approve" && data.state === "awaiting_approval" && (
        <Modal
          title={t("Approve the campaign?")}
          onClose={close}
          actions={
            <>
              <button type="button" className="fl-quiet" onClick={close}>{t("Back")}</button>
              <button
                type="button"
                onClick={() => control.mutate("approve")}
                disabled={control.isPending || !approvalReady || approvalBlocked}
                data-testid="confirm-approve"
              >
                {t("Approve")}
              </button>
            </>
          }
        >
          <Note>
            {t("The consent covers exactly what is on screen: this operation, this payload, these {count} hosts and this rollout. It is recorded with the fingerprint {fingerprint}, your authentication and the reason.", {
              count: total, fingerprint: data.approval_fingerprint.slice(0, 12),
            })}
          </Note>
          {approvalBlocked && (
            <Banner tone="error">
              {t("Approval is blocked: {n} hosts have a plan the panel cannot read. Exclude them with a reason or plan the campaign again.", { n: unknownPlans.length })}
              {" "}
              {unknownPlans.slice(0, 12).join(", ")}
            </Banner>
          )}
          <Fields>
            <Field
              label={t("Reason for the trail")}
              wide
              hint={reasonForced
                ? t("Required: this operation is {risk}, and the approval needs a reason of at least {n} characters.", { risk: operation?.risk ?? "critical", n: MIN_REASON })
                : t("Optional here; a critical operation requires at least {n} characters.", { n: MIN_REASON })}
            >
              <input autoFocus value={reason} onChange={(event) => setReason(event.target.value)} data-testid="reason" />
            </Field>
            <Field label={t("Change ticket")} hint={t("Optional: the identifier or address of the change request.")}>
              <input value={changeTicket} onChange={(event) => setChangeTicket(event.target.value)} placeholder="CHG-1234" data-testid="ticket" />
            </Field>
          </Fields>
          {control.error && <Problem>{String(control.error)}</Problem>}
          {control.error instanceof ApiError && STALE_PLAN_CODES.has(control.error.code) && (
            <Note>
              {t("The host no longer computes this plan; plan again and approve the new one.")}
              {" "}
              <Link to={bulkPrefill(data.action_type, data.name, data.payload ?? {})}>{t("Replan")}</Link>
            </Note>
          )}
        </Modal>
      )}

      {asking?.kind === "advance" && data.state === "manual_gate" && (
        <Modal
          title={t("Advance to the waves?")}
          onClose={close}
          actions={
            <>
              <button type="button" className="fl-quiet" onClick={close}>{t("Back")}</button>
              <button type="button" onClick={() => control.mutate("advance")} disabled={control.isPending} data-testid="confirm-advance">
                {t("Advance to the waves")}
              </button>
            </>
          }
        >
          <Note>
            {t("The canary is settled. {succeeded} hosts succeeded and {failed} failed; the remaining {notStarted} hosts start in waves of {wave} once you advance. The decision is recorded with your identity and the reason.", {
              succeeded: done, failed: failed + unknown, notStarted, wave: data.wave_size,
            })}
          </Note>
          <Fields>
            <Field label={t("Reason for the trail")} wide>
              <input autoFocus value={reason} onChange={(event) => setReason(event.target.value)} data-testid="reason" />
            </Field>
          </Fields>
          {control.error && <Problem>{String(control.error)}</Problem>}
        </Modal>
      )}

      {(asking?.kind === "pause" || asking?.kind === "resume" || asking?.kind === "cancel") && (
        <Modal
          title={asking.kind === "pause"
            ? t("Pause the campaign?")
            : asking.kind === "resume" ? t("Resume the campaign?") : t("Cancel the campaign?")}
          onClose={close}
          actions={
            <>
              <button type="button" className="fl-quiet" onClick={close}>{t("Back")}</button>
              <button
                type="button"
                className={asking.kind === "cancel" ? "fl-danger" : undefined}
                onClick={() => control.mutate(asking.kind)}
                disabled={control.isPending}
                data-testid="confirm-stop"
              >
                {asking.kind === "pause" ? t("Pause") : asking.kind === "resume" ? t("Resume") : t("Cancel the campaign")}
              </button>
            </>
          }
        >
          <Note>
            {asking.kind === "pause"
              ? `${t("No further host starts until the campaign is resumed.")} ${underWayFate}`
              : asking.kind === "resume"
                ? t("The campaign goes back to its queue: {notStarted} hosts that have not started continue in their waves, under the same thresholds. The decision is recorded with your identity and the reason.", { notStarted })
                : `${t("{notStarted} hosts that have not started are marked canceled and will not start.", { notStarted })} ${underWayFate} ${rollbackHint}`}
          </Note>
          <Fields>
            <Field label={t("Reason for the trail")} wide>
              <input autoFocus value={reason} onChange={(event) => setReason(event.target.value)} data-testid="reason" />
            </Field>
          </Fields>
          {asking.kind === "cancel" && rollbackPlannable && reverseAction && (
            <Note>
              {reverseOperation?.campaign_ready ? (
                <Link to={bulkPrefill(reverseAction, t("Rollback of {name}", { name: data.name }), reversePayload(actionType, data.payload), data.id)}>
                  {t("Plan the rollback")}
                </Link>
              ) : (
                t("The reverse operation {action} runs host by host today; a rollback campaign is not offered.", { action: reverseAction })
              )}
              {" · "}
              {t("The rollback is a new campaign with its own plans and its own approval; the version or the rollback identifier is per host.")}
            </Note>
          )}
          {control.error && <Problem>{String(control.error)}</Problem>}
        </Modal>
      )}

      {asking?.kind === "skip" && (
        <Modal
          title={t("Skip {host}?", { host: asking.target.hostname || asking.target.host_id.slice(0, 8) })}
          onClose={close}
          actions={
            <>
              <button type="button" className="fl-quiet" onClick={close}>{t("Back")}</button>
              <button
                type="button"
                className="fl-danger"
                onClick={() => skip.mutate({ hostId: asking.target.host_id, reason: reason.trim() })}
                disabled={skip.isPending || !reasonValid(reason)}
                data-testid="confirm-skip"
              >
                {t("Skip this host")}
              </button>
            </>
          }
        >
          <Note>
            {asking.target.wave === 0
              ? t("The host is a canary waiting for its connection, and the waves do not start until the canary is settled. Skipping it opens the barrier on the word of the canary hosts that ran; the host takes no part and is not a failure.")
              : t("The host waits for its connection. Skipping it leaves it out of the campaign with your reason; it takes no part and is not a failure.")}
          </Note>
          <Fields>
            <Field label={t("Reason for the trail")} wide hint={t("Required: at least {n} characters.", { n: MIN_REASON })}>
              <input autoFocus value={reason} onChange={(event) => setReason(event.target.value)} data-testid="reason" />
            </Field>
          </Fields>
          {skip.error && <Problem>{String(skip.error)}</Problem>}
        </Modal>
      )}
    </Screen>
  );
}

/**
 * The order as it was given: the operation with its contract, the payload
 * as the hosts will get it, the targets as they were named, and the whole
 * rollout policy. The fingerprint covers exactly this.
 */
function Order({ campaign, operation }: { campaign: CampaignRecord; operation: Operation | undefined }) {
  const t = useT();
  const selector = campaign.selector ?? {};
  const secrets = secretReferences(campaign.payload);
  const units = campaign.health_check_units ?? [];
  const [rollbackWord] = contractWords(t, "rollback", operation?.rollback);
  return (
    <Card
      title={t("The order")}
      note={t("What was ordered, as the approval binds it: this operation, this payload, these targets and this rollout. Read it before deciding; the fingerprint covers exactly this.")}
    >
      <Grid>
        <Card span={6} title={t("Operation and rollout")}>
          <Facts>
            <Fact label={t("Operation")}><span className="fl-mono">{campaign.action_type}</span></Fact>
            <Fact label={t("Contract")}>{operation ? <Contract operation={operation} /> : "—"}</Fact>
            {operation?.risk && <Fact label={t("Risk")}>{operation.risk}</Fact>}
            {operation?.rollback && <Fact label={t("Way back")}>{rollbackWord}</Fact>}
            {/* The targets as the order named them. */}
            <Fact label={t("Targets as ordered")}>
              {selector.expression
                ? <span className="fl-mono">{describeExpression(selector.expression)}</span>
                : selector.host_ids && selector.host_ids.length > 0
                  ? t("{n} hosts named one by one", { n: selector.host_ids.length })
                  : [
                    selector.site && `${t("site")}: ${selector.site}`,
                    selector.environment && `${t("environment")}: ${selector.environment}`,
                    selector.os_family && `${t("OS family")}: ${selector.os_family}`,
                  ].filter(Boolean).join(" · ") || t("the whole visible fleet")}
            </Fact>
            {selector.exclude && selector.exclude.length > 0 && (
              <Fact label={t("Excluded by name")}>
                {t("{n} hosts", { n: selector.exclude.length })} — {selector.exclude_reason || "—"}
              </Fact>
            )}
            <Fact label={t("Canary / wave")}>{`${campaign.canary_size} / ${campaign.wave_size}`}</Fact>
            <Fact label={t("Concurrent hosts")}>{campaign.max_concurrent}</Fact>
            <Fact label={t("Failure threshold")}>
              {t("{percent}% or {count} hosts", {
                percent: campaign.failure_threshold_percent, count: campaign.failure_threshold_absolute,
              })}
            </Fact>
            <Fact label={t("Connectivity loss threshold")}>
              {campaign.connectivity_lost_absolute > 0
                ? t("{count} hosts", { count: campaign.connectivity_lost_absolute })
                : t("off")}
            </Fact>
            <Fact label={t("Reboot policy")}>
              {campaign.reboot_policy}
              {campaign.reboot_policy !== "never" && campaign.reboot_timeout_seconds
                ? ` · ${t("waits {n} s for the host to come back", { n: campaign.reboot_timeout_seconds })}`
                : ""}
            </Fact>
            <Fact label={t("Health-check units")}>
              {units.length > 0 ? <Tags>{units.map((unit) => <Tag key={unit}>{unit}</Tag>)}</Tags> : t("none")}
            </Fact>
            <Fact label={t("Task timeout")}>
              {campaign.job_timeout_seconds ? t("{n} s", { n: campaign.job_timeout_seconds }) : t("the operation's default")}
            </Fact>
            <Fact label={t("Offline policy")}>{campaign.offline_policy}</Fact>
            <Fact label={t("Waits for offline hosts until")}>
              {campaign.deadline_at
                ? <span title={absoluteTime(campaign.deadline_at)}>{relativeTime(campaign.deadline_at)}</span>
                : "—"}
            </Fact>
            <Fact label={t("Maintenance window")}>
              {campaign.maintenance_start || campaign.maintenance_end
                ? `${campaign.maintenance_start ? absoluteTime(campaign.maintenance_start) : t("any time")} → ${campaign.maintenance_end ? absoluteTime(campaign.maintenance_end) : t("open-ended")}`
                : t("none: the campaign may start at any time")}
            </Fact>
            <Fact label={t("Manual gate after the canary")}>{campaign.manual_gate ? t("yes") : t("no")}</Fact>
            {/* The links to the campaigns this order stands on: what it
                undoes, what it runs again, which policy ordered it. */}
            {campaign.compensates_campaign_id && (
              <Fact label={t("Compensates")}>
                <Link to={`/campaigns/${campaign.compensates_campaign_id}`}>
                  {campaign.compensates_campaign_name || campaign.compensates_campaign_id.slice(0, 8)}
                </Link>
              </Fact>
            )}
            {campaign.retries_campaign_id && (
              <Fact label={t("Retries")}>
                <Link to={`/campaigns/${campaign.retries_campaign_id}`}>
                  {campaign.retries_campaign_name || campaign.retries_campaign_id.slice(0, 8)}
                </Link>
                {" · "}
                {t("the same order on the hosts that failed there")}
              </Fact>
            )}
            {campaign.policy_id && (
              <Fact label={t("Ordered by policy")}>
                <Link to={`/policies/${campaign.policy_id}`}>{campaign.policy_id.slice(0, 8)}</Link>
                {campaign.policy_version ? ` · v${campaign.policy_version}` : ""}
              </Fact>
            )}
          </Facts>
        </Card>
        <Card
          span={6}
          title={t("Payload")}
          tools={<Save text={JSON.stringify(campaign.payload ?? {}, null, 2)} filename={`campaign-${campaign.id.slice(0, 8)}-payload.json`} />}
        >
          <pre className="fl-mono" data-testid="order-payload">{JSON.stringify(campaign.payload ?? {}, null, 2)}</pre>
          {secrets.length > 0 && (
            <Note>
              {t("Secrets referenced by name: {names}. The value never travels in the order; the host fetches it on a short lease when the task runs.", { names: secrets.join(", ") })}
            </Note>
          )}
        </Card>
      </Grid>
    </Card>
  );
}

/**
 * The contract of an operation: what a cancel does, whether a repeat is
 * safe, what way back exists, what is verified, and which host resources
 * the operation holds while it runs.
 */
function Contract({ operation }: { operation: Operation }) {
  const t = useT();
  const chips: { label: string; meaning: string; tone: Tone }[] = [];
  for (const [field, value, label] of [
    ["cancel", operation.cancel_mode, t("cancel")],
    ["retry", operation.retry_class, t("retry")],
    ["rollback", operation.rollback, t("rollback")],
    ["verification", operation.verification, t("verification")],
  ] as const) {
    if (!value) continue;
    const [word, meaning] = contractWords(t, field, value);
    chips.push({
      label: `${label}: ${word}`,
      meaning,
      tone: field === "rollback" && value === "none" ? "warn" : "neutral",
    });
  }
  const claims = operation.resource_claims ?? [];
  if (claims.length > 0) {
    chips.push({
      label: `${t("claims")}: ${claims.map((claim) => {
        const mode = claim.mode === "exclusive" ? t("exclusive") : t("shared");
        return claim.weight > 1 ? `${claim.class} (${mode} ×${claim.weight})` : `${claim.class} (${mode})`;
      }).join(", ")}`,
      meaning: t("The host resources the operation holds while it runs. An exclusive claim keeps every other change off that resource; shared claims coexist and their weight is what they cost the host."),
      tone: "neutral",
    });
  }
  if (chips.length === 0) return <>—</>;
  return (
    <Tags>
      {chips.map((chip) => <Pill key={chip.label} tone={chip.tone} title={chip.meaning}>{chip.label}</Pill>)}
    </Tags>
  );
}

/**
 * One group of plans: the hosts that get this shape of the change, the
 * fingerprint it is approved under, when it stops being valid, and the
 * plan itself.
 */
function PlanGroupBody({ group, action, stale }: { group: PlanGroup; action?: string; stale: string[] }) {
  const t = useT();
  const plan = (group.plan?.plan ?? group.plan ?? {}) as HostPlan & PackagePlanFacts;
  const status = planStatus(group);
  const planner = group.planner_version ?? plan.planner_version;
  // The hosts of this group the host side has since refused as stale:
  // their consent does not carry over, whatever the digest still says.
  const staleHere = stale.filter((host) => group.hosts.includes(host));
  return (
    <Card
      title={t("{n} hosts", { n: group.count })}
      note={group.hosts.slice(0, 12).join(", ") + (group.hosts.length > 12 ? ` +${group.hosts.length - 12}` : "")}
      tools={
        <Tags>
          <Tag>{t("fingerprint {hash}", { hash: group.plan_hash.slice(0, 16) })}</Tag>
          <Tag>{t("planner {version}", { version: planner || "—" })}</Tag>
          <Tag>{t("valid until {when}", { when: relativeTime(group.expires_at) })}</Tag>
          {status === "expired" && <Pill tone="error">{t("expired")}</Pill>}
          {status === "unknown" && (
            <Pill tone="error" title={t("The panel cannot read this plan as a declaration of its effects; exclude these hosts with a reason or plan again.")}>
              {t("unknown plan")}
            </Pill>
          )}
          {staleHere.length > 0 && (
            <Pill tone="error" title={staleHere.join("\n")}>{t("stale on {n} hosts", { n: staleHere.length })}</Pill>
          )}
        </Tags>
      }
    >
      {status === "unknown" ? (
        <Banner tone="error">
          {t("The host gave a plan the panel cannot read. Nothing here is approved: exclude the hosts with a reason, or plan the campaign again once the agent is upgraded.")}
        </Banner>
      ) : (
        <PlanBody plan={plan} action={action} />
      )}
    </Card>
  );
}

/** The host plan read from the last attempt of the planning operation. */
function HostPlanOf({ jobId }: { jobId: string }) {
  const t = useT();
  const { data, error } = useQuery({
    queryKey: ["attempts", jobId],
    queryFn: () => api.get<Collection<Attempt>>(`/api/v1/jobs/${jobId}/attempts`),
  });
  if (error) return <Empty>{t("The plan of this host could not be read.")}</Empty>;
  if (!data) return <Bones rows={3} />;
  const attempt = [...data.items].reverse()
    .find((item) => item.detail?.kind === "package_plan" || item.detail?.plan !== undefined);
  if (!attempt) return <Empty>{t("No plan.")}</Empty>;
  const plan = (attempt.detail?.kind === "package_plan" ? attempt.detail : attempt.detail?.plan) as (HostPlan & PackagePlanFacts);
  return (
    <Stack>
      <PlanBody plan={plan ?? {}} />
      <Link to={`/jobs/${jobId}`}>{t("Open the planning operation")}</Link>
    </Stack>
  );
}

/**
 * The strip of one host's steps: plan → execute → reboot → verify →
 * compensate, each with its state, its task and - where it did not run -
 * the reason.
 */
function TargetSteps({ campaignID, hostID, compensation }: {
  campaignID: string;
  hostID: string;
  /** The address of this host's compensation, when the campaign offers one. */
  compensation?: string;
}) {
  const t = useT();
  const steps = useTargetSteps(campaignID, hostID);
  if (steps.error) return <Problem>{String(steps.error)}</Problem>;
  if (!steps.data) return <Bones rows={2} />;
  const order = steps.data.step_order.length > 0 ? steps.data.step_order : Object.keys(STEP_NAMES);
  const byKey = new Map<string, CampaignStep>(steps.data.items.map((step) => [step.step_key, step]));
  if (byKey.size === 0) return <Empty>{t("No step recorded yet.")}</Empty>;
  const explained = order.map((key) => byKey.get(key)).filter((step): step is CampaignStep => !!step?.reason);
  // The change landed when the execute step succeeded, whatever the reboot
  // or the verification did after it - the same rule the server counts
  // changed hosts by, and the rule a row cannot apply on its own.
  const changed = byKey.get("execute")?.state === "succeeded";
  return (
    <Stack>
      <Tags>
        {order.map((key) => {
          const step = byKey.get(key);
          const name = t(STEP_NAMES[key] ?? key);
          if (!step) {
            return <Pill key={key} tone="unknown" title={t("The host has not reached this step.")}>{`${name} —`}</Pill>;
          }
          return (
            <Pill key={key} tone={targetTone(step.state)} title={step.reason || undefined}>
              {name}
              {step.attempts > 1 ? ` · ${t("attempt {n}", { n: step.attempts })}` : ""}
            </Pill>
          );
        })}
      </Tags>
      <Tags>
        {order.map((key) => {
          const step = byKey.get(key);
          // The task carried the step and opens on its own screen.
          if (!step?.job_id) return null;
          return (
            <Tag key={key} to={`/jobs/${step.job_id}`} title={step.job_id}>
              {`${t(STEP_NAMES[key] ?? key)} · ${step.job_id.slice(0, 8)}`}
            </Tag>
          );
        })}
      </Tags>
      {explained.length > 0 && (
        <Facts>
          {explained.map((step) => (
            <Fact key={step.step_key} label={t(STEP_NAMES[step.step_key] ?? step.step_key)}>{step.reason}</Fact>
          ))}
        </Facts>
      )}
      {compensation && changed && (
        <Note>
          <Link to={compensation}>{t("compensate this host")}</Link>
          {" · "}
          {t("The change landed on this host; the compensation is a new campaign on this host alone, with its own plan and approval.")}
        </Note>
      )}
    </Stack>
  );
}
