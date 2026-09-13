import type { ReactNode } from "react";
import { ApiError } from "../lib/api";
import { optional, relativeTime, absoluteTime } from "../lib/format";
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
  const succeeded = ["succeeded", "completed", "active"].includes(state);
  const failed = ["failed", "timed_out", "expired", "partially_applied"].includes(state);
  // Incapability and a skip are not a failure: the host broke nothing, it
  // simply took no part. Red would call it an error that did not happen.
  const skipped = ["ineligible", "skipped", "no_change"].includes(state);
  const waiting = ["awaiting_approval", "queued", "planned", "planning", "paused",
    "awaiting_budget"].includes(state);
  const kind = succeeded ? "ok" : failed ? "error" : skipped ? "unknown" : waiting ? "warn" : "";
  return <span className={`badge ${kind}`}>{t(stateName(state))}</span>;
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
    succeeded: "succeeded", failed: "failed", timed_out: "timed out",
    canceled: "canceled", cancelled: "canceled", expired: "expired",
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
