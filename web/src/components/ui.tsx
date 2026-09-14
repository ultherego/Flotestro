import type { ReactNode } from "react";
import { ApiError } from "../lib/api";
import { optional, relativeTime, absoluteTime } from "../lib/format";
import { useErrorGuides } from "../lib/errors";
import { useT } from "../i18n";

/** The connection state badge. The unknown state has a look of its own. */
export function ConnectionState({ state }: { state: string }) {
  const t = useT();
  const kind =
    state === "online" ? "ok" : state === "offline" ? "error" : state === "stale" ? "warn" : "unknown";
  return <span className={`badge ${kind}`}>{t(stateName(state))}</span>;
}

/** The operation result or the job state. */
export function JobState({ state }: { state: string }) {
  const t = useT();
  // No change is a success without a mutation: the host already had the
  // desired state, and green is the colour of the desired state.
  const succeeded = ["succeeded", "completed", "active", "no_change"].includes(state);
  const failed = ["failed", "timed_out", "expired", "partially_applied", "plan_failed"].includes(state);
  // Incapability and a skip are not a failure: the host broke nothing, it
  // simply took no part. Red would call it an error that did not happen.
  // A superseded attempt did no work of its own: the result came in on
  // the attempt before it, and this one was closed to keep the record
  // straight. Neither a failure nor a success of its own.
  const skipped = ["ineligible", "skipped", "superseded_by_result"].includes(state);
  // A campaign that finished with issues, a host that ended unknown, and
  // every wait are drawn as attention rather than as an error: the
  // operator has something to look at, not something that broke. Unknown
  // is not grey: grey is the colour of "took no part", and an unknown host
  // may have changed.
  const waiting = ["awaiting_approval", "queued", "planned", "planning", "paused",
    "awaiting_budget", "queued_offline", "awaiting_lock", "dispatched", "manual_gate",
    "completed_with_issues", "unknown"].includes(state);
  const kind = succeeded ? "ok" : failed ? "error" : skipped ? "unknown" : waiting ? "warn" : "";
  // The legend travels with the badge: every state says what it means for
  // the host and what, if anything, the operator has to do about it.
  const meaning = stateMeaning(state);
  return <span className={`badge ${kind}`} title={meaning ? t(meaning) : undefined}>{t(stateName(state))}</span>;
}

/** One sentence per state, shown on hover. States are not self-explanatory. */
function stateMeaning(state: string): string {
  const meanings: Record<string, string> = {
    queued: "Approved and waiting for delivery to the host.",
    active: "The change is in force; nothing waits.",
    leased: "Taken by a scheduler; delivery to the host is under way.",
    dispatched: "Handed to the agent; the host has not reported a start yet.",
    awaiting_lock: "The agent holds the task and waits for a resource of the host held by another task; the blocker names it.",
    running: "The host is carrying out the operation.",
    lease_expired: "The host did not answer within the lease; the operation was delivered again.",
    superseded_by_result: "The result arrived on an earlier attempt after its lease ran out; this attempt did nothing.",
    awaiting_approval: "Nothing happens until somebody approves; the approval confirms the plan hash.",
    planning: "Every host computes its own plan; nothing is applied yet.",
    planned: "The plans are in; the campaign waits for the consent.",
    awaiting_budget: "The host is ready, but the fleet or the site has no capacity now; it starts when a token frees up.",
    queued_offline: "The host was not connected when its turn came; the campaign waits for it without a slot until its deadline, then leaves it out.",
    manual_gate: "The canary is settled; nothing more starts until somebody advances the campaign into the waves.",
    pending: "In the snapshot, waiting for its wave.",
    rebooting: "The host is rebooting; done only when it comes back with a new boot ID.",
    verifying: "The change is applied; the post-change check is running.",
    ineligible: "This host will not run the operation: it lacks the adapter or does not meet a condition. Not a failure and not counted towards the threshold.",
    excluded: "Left out by name when the campaign was ordered; the message carries who excluded it and why. Not a failure.",
    skipped: "Left out on purpose, e.g. a maintenance window. Not a failure.",
    no_change: "The host already had the desired state; nothing was changed. A success without a mutation.",
    succeeded: "Done and verified on the host.",
    failed: "The host reported a failure; the error code and the message say what.",
    unknown: "The task ended without a result: the session broke or the agent restarted mid-task. Not a success and not counted as unchanged; read the host before ordering again.",
    timed_out: "No result within the allowed time; the state of the host is unknown until it reports.",
    expired: "Not run in time: a task not approved before its expiry, or a campaign whose plans passed their time limit before any host started.",
    canceling: "Canceled with hosts still carrying their tasks; nothing new starts, and the campaign ends canceled once they settle.",
    canceled: "Stopped before it started, or the running work was left to finish.",
    partially_applied: "Some of the change landed and some did not; the result lists both.",
    paused: "No new hosts start until resumed; work under way finishes on its own.",
    completed: "Every host is settled and every host that took part got through.",
    completed_with_issues: "Every host is settled under the threshold, but some failed or ended unknown; the report names them.",
    plan_failed: "Planning left no host to run on: every plan was refused, failed or never computed. Nothing was approved and nothing ran.",
  };
  return meanings[state] ?? "";
}

/**
 * The states come from the database as contract identifiers and looked like
 * that in the interface: "awaiting_approval" or "partially_applied". A name
 * readable for the operator cannot be the only record of the state - the
 * identifier stays in the API and in the audit log - but it is the operator
 * who looks at the screen.
 *
 * A state outside the list is shown as it came. Guessing a translation
 * would hide the fact that the panel saw something it does not know.
 */
function stateName(state: string): string {
  const names: Record<string, string> = {
    online: "online", offline: "offline", stale: "stale", unknown: "unknown",
    queued: "queued", planned: "planned", leased: "assigned",
    dispatched: "dispatched", running: "running",
    awaiting_approval: "awaiting approval",
    // The campaign computes a plan on every host; it changes nothing yet.
    planning: "planning per host",
    // The host is ready, but the fleet or the site has no capacity now.
    awaiting_budget: "waiting for capacity",
    // The host will not carry out this operation: it lacks the adapter or
    // does not meet the condition. That is not an execution failure and
    // does not count towards the failure threshold.
    ineligible: "cannot run this",
    // The agent holds the task and waits for a resource of the host.
    awaiting_lock: "waiting for a lock",
    succeeded: "succeeded", failed: "failed", timed_out: "timed out",
    // A success without a mutation, and an end without a result.
    no_change: "no change",
    canceled: "canceled", cancelled: "canceled", canceling: "canceling", expired: "expired",
    completed_with_issues: "completed with issues", plan_failed: "planning failed",
    lease_expired: "lease expired", superseded_by_result: "superseded",
    rejected: "rejected", replayed: "replayed",
    active: "active", paused: "paused", completed: "completed",
    partially_applied: "partially applied",
    denied: "denied", success: "success", failure: "failure",
  };
  return names[state] ?? state;
}

/**
 * A number that may be undetermined. Zero and missing knowledge are
 * different things, so they look different.
 */
export function OptionalNumber({
  value,
  warnFrom = 1,
}: {
  value: number | null | undefined;
  warnFrom?: number;
}) {
  const t = useT();
  if (value === null || value === undefined) {
    return <span className="badge unknown">{t("unknown")}</span>;
  }
  if (value >= warnFrom) {
    return <span className="badge warn">{value}</span>;
  }
  return <span>{value}</span>;
}

export function OptionalFlag({ value }: { value: boolean | null | undefined }) {
  const t = useT();
  if (value === null || value === undefined) {
    return <span className="badge unknown">{t("unknown")}</span>;
  }
  return value ? <span className="badge warn">{t("yes")}</span> : <span>{t("no")}</span>;
}

/** A time with its observation source: every value has a time when it was true. */
export function Time({ value }: { value?: string | null }) {
  const t = useT();
  if (!value) return <span className="badge unknown">{t("never")}</span>;
  return <span title={absoluteTime(value)}>{relativeTime(value)}</span>;
}

export function Empty({ children }: { children: ReactNode }) {
  return <div className="empty">{children}</div>;
}

/**
 * A refusal is not a panel failure, only the server's answer to the user's
 * permissions. A red error message would suggest a defect where the system
 * works correctly.
 */
export function ErrorBox({ error }: { error: unknown }) {
  const t = useT();
  if (error instanceof ApiError && error.forbidden) {
    return <Empty>{t("You do not have permission to view this.")}</Empty>;
  }
  const message = error instanceof Error ? error.message : String(error);
  return <div className="page-error">{t("Error: {message}", { message })}</div>;
}

export function Pairs({ children }: { children: ReactNode }) {
  return <dl className="pairs">{children}</dl>;
}

export function Pair({ label, children }: { label: string; children: ReactNode }) {
  return (
    <>
      <dt>{label}</dt>
      <dd>{children}</dd>
    </>
  );
}

export { optional };

/**
 * The progress bar of an operation in flight.
 *
 * Undetermined progress is not drawn as zero - a bar at zero looks like
 * work that stands still. Without a percentage and without steps only the
 * description of what is happening right now remains.
 */
export function ProgressBar({
  percent, step, total, caption,
}: { percent?: number; step?: number; total?: number; caption?: string }) {
  const t = useT();
  const fromPercent = typeof percent === "number" ? percent : undefined;
  const fromSteps = step && total ? Math.round((step / total) * 100) : undefined;
  const fill = fromPercent ?? fromSteps;

  return (
    <div className="progress">
      <div className="progress-track">
        {fill === undefined ? (
          <span className="progress-unknown" />
        ) : (
          <span className="progress-fill" style={{ width: `${Math.min(100, fill)}%` }} />
        )}
      </div>
      <span className="progress-caption">
        {step && total ? `${step}/${total}` : fill !== undefined ? `${fill}%` : t("in progress")}
        {caption ? ` · ${caption}` : ""}
      </span>
    </div>
  );
}

/**
 * An error code with its guide on hover: what happened, whether a retry
 * helps and what to do next. The code stays visible as it came - it is
 * the identifier automation and the audit log use.
 */
export function ErrorCode({ code }: { code?: string | null }) {
  const t = useT();
  const guides = useErrorGuides();
  if (!code) return <>—</>;
  const guide = guides.get(code);
  if (!guide) return <code>{code}</code>;
  const retry: Record<string, string> = {
    never: t("a retry will fail the same way"),
    automatic: t("retried automatically"),
    after_change: t("retry after the named change"),
    after_replan: t("compute the plan again first"),
    read_state: t("read the state of the host before repeating"),
  };
  const title = `${t(guide.meaning)}\n${t("Next")}: ${t(guide.action)}\n${t("Retry")}: ${retry[guide.retry] ?? guide.retry}`;
  return <code title={title} className={guide.counts_as_failure ? "" : "source"}>{code}</code>;
}
