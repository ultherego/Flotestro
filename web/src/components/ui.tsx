import { useState, type ReactNode } from "react";
import { ApiError } from "../lib/api";
import { optional, relativeTime, absoluteTime, bytes, duration, goDuration } from "../lib/format";
import { copyToClipboard } from "../lib/clipboard";
import { Icon } from "./icons";
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
  // simply took no part.
  const skipped = ["ineligible", "skipped", "superseded_by_result"].includes(state);
  // A campaign that finished with issues, a host that ended unknown, and
  // every wait are drawn as attention rather than as an error: the operator
  // has something to look at, not something that broke.
  const waiting = ["awaiting_approval", "queued", "planned", "planning", "paused",
    "awaiting_budget", "queued_offline", "awaiting_lock", "dispatched", "manual_gate",
    "cancel_requested", "completed_with_issues", "unknown"].includes(state);
  const kind = succeeded ? "ok" : failed ? "error" : skipped ? "unknown" : waiting ? "warn" : "";
  // The legend travels with the badge: every state says what it means for
  // the host and what, if anything, the operator has to do about it.
  const meaning = stateMeaning(state);
  return <span className={`badge ${kind}`} title={meaning ? t(meaning) : undefined}>{t(stateName(state))}</span>;
}

/** One sentence per state, shown on hover. States are not self-explanatory. */
export function stateMeaning(state: string): string {
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
    cancel_requested: "A cancel was asked of the host holding the task; the job waits for the agent to say what it found - not started, interrupted, not interruptible or already done - or for the operation's timeout, after which the outcome is unknown.",
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
    pausing: "A pause was ordered; the hosts still carrying their tasks finish, then the campaign is paused.",
    completed: "Every host is settled and every host that took part got through.",
    completed_with_issues: "Every host is settled under the threshold, but some failed or ended unknown; the report names them.",
    plan_failed: "Planning left no host to run on: every plan was refused, failed or never computed. Nothing was approved and nothing ran.",
  };
  return meanings[state] ?? "";
}

/**
 * The states come from the database as contract identifiers and looked like
 * that in the interface: "awaiting_approval" or "partially_applied".
 */
export function stateName(state: string): string {
  const names: Record<string, string> = {
    online: "online", offline: "offline", stale: "stale", unknown: "unknown",
    queued: "queued", planned: "planned", leased: "assigned",
    dispatched: "dispatched", running: "running",
    cancel_requested: "cancel requested",
    awaiting_approval: "awaiting approval",
    // The campaign computes a plan on every host; it changes nothing yet.
    planning: "planning per host",
    // The host is ready, but the fleet or the site has no capacity now.
    awaiting_budget: "waiting for capacity",
    // The host will not carry out this operation: it lacks the adapter or
    // does not meet the condition.
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
    active: "active", paused: "paused", pausing: "pausing", completed: "completed",
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
 * permissions.
 */
export function ErrorBox({ error }: { error: unknown }) {
  const t = useT();
  if (error instanceof ApiError && error.forbidden) {
    return <Empty>{t("You do not have permission to view this.")}</Empty>;
  }
  const message = error instanceof Error ? error.message : String(error);
  return <div className="page-error">{t("Error: {message}", { message })}</div>;
}

/**
 * A list of label/value pairs. One grid for the whole panel: the label track
 * is elastic, every value wraps, and inside a narrow card the pairs stack so
 * that a fingerprint or a DSN cannot push past the card's edge.
 */
export function Pairs({ children, stacked = false }: { children: ReactNode; stacked?: boolean }) {
  return <dl className={stacked ? "pairs stacked" : "pairs"}>{children}</dl>;
}

export function Pair({
  label, hint, wide = false, children,
}: {
  label: string;
  /** What the value means, on hover; a sentence does not belong in the list. */
  hint?: string;
  /** A value that needs the whole width: a table, a list, a long identifier. */
  wide?: boolean;
  children: ReactNode;
}) {
  return (
    <>
      <dt className={wide ? "wide" : undefined} title={hint}>{label}</dt>
      <dd className={wide ? "wide" : undefined}>{children}</dd>
    </>
  );
}

/* ---------------------------------------------------------------------- */
/* Values. Every screen that shows a fact of the server draws it through    */
/* here, so a byte count, a duration and an identifier look the same        */
/* wherever they appear - and so no screen has to invent the case it         */
/* forgot.                                                                  */
/* ---------------------------------------------------------------------- */

/** How a value is read. `id` is for an opaque identifier, `duration` for a Go one. */
export type FactKind =
  | "text" | "number" | "bytes" | "seconds" | "ms" | "time" | "flag" | "duration" | "id";

export function FactValue({ value, kind = "text" }: { value: unknown; kind?: FactKind }) {
  const t = useT();
  if (value === null || value === undefined || value === "") return <span className="source">—</span>;
  switch (kind) {
    case "flag":
      return <span className={value ? "badge ok" : "badge error"}>{value ? t("yes") : t("no")}</span>;
    case "bytes":
      return <span className="mono">{bytes(Number(value))}</span>;
    case "seconds":
      return <span className="mono">{duration(Number(value))}</span>;
    case "ms":
      return <span className="mono">{Number(value).toFixed(1)} ms</span>;
    case "time":
      return <Time value={String(value)} />;
    case "number":
      return <span className="mono">{String(value)}</span>;
    case "duration":
      return <span className="mono" title={String(value)}>{goDuration(String(value))}</span>;
    case "id":
      return <Identifier value={String(value)} />;
    default:
      // An object reaching a text row is the one case that used to be drawn
      // as raw JSON on one unbreakable line. It gets its own shape instead.
      if (typeof value === "object") return <Structured value={value} />;
      return <span className="mono">{String(value)}</span>;
  }
}

/**
 * An opaque identifier: a fingerprint, a uuid, a key id. Shown by its ends,
 * because the middle of a hash carries nothing a reader can use, with the
 * whole value on hover and one click to copy it.
 */
export function Identifier({ value, keep = 8 }: { value: string; keep?: number }) {
  const t = useT();
  const [copied, setCopied] = useState(false);
  const short = value.length > keep * 2 + 3
    ? `${value.slice(0, keep)}…${value.slice(-keep)}`
    : value;
  return (
    <button
      type="button"
      className="identifier"
      title={copied ? t("Copied") : value}
      onClick={() => {
        void copyToClipboard(value).then((done) => {
          if (!done) return;
          setCopied(true);
          window.setTimeout(() => setCopied(false), 2000);
        });
      }}
    >
      <span className="mono">{short}</span>
      <Icon name={copied ? "check" : "copy"} />
    </button>
  );
}

/**
 * A value the server sent as a structure. A list of records becomes a table
 * of its own keys, a map becomes a nested list, and a list of words becomes
 * words - never a line of JSON, which is what a card cannot hold and a
 * reader cannot read.
 */
export function Structured({ value }: { value: unknown }) {
  const t = useT();
  if (Array.isArray(value)) {
    if (value.length === 0) return <span className="source">—</span>;
    const records = value.filter((one) => one !== null && typeof one === "object" && !Array.isArray(one));
    if (records.length !== value.length) {
      return <span className="mono wrap">{value.map((one) => String(one)).join(", ")}</span>;
    }
    const columns = Array.from(new Set(records.flatMap((one) => Object.keys(one as object))));
    return (
      <TableScroll>
        <table className="facts-table">
          <thead>
            <tr>{columns.map((column) => <th key={column} scope="col">{t(labelOfKey(column))}</th>)}</tr>
          </thead>
          <tbody>
            {records.map((record, index) => (
              <tr key={index}>
                {columns.map((column) => (
                  <td key={column}>
                    <FactValue value={(record as Record<string, unknown>)[column]} kind={kindOfKey(column)} />
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </TableScroll>
    );
  }
  if (value !== null && typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>);
    if (entries.length === 0) return <span className="source">—</span>;
    return (
      <dl className="pairs stacked nested">
        {entries.map(([key, one]) => (
          <Pair key={key} label={t(labelOfKey(key))}>
            <FactValue value={one} kind={kindOfKey(key)} />
          </Pair>
        ))}
      </dl>
    );
  }
  return <span className="mono wrap">{String(value)}</span>;
}

/**
 * A table that cannot widen its card. Four columns in a card a third of the
 * page wide used to push the last one past the border; now the table scrolls
 * and the card holds its shape.
 */
export function TableScroll({ children }: { children: ReactNode }) {
  return <div className="table-scroll">{children}</div>;
}

/* A key of the server read as words, for a structure no screen has named:
   the fact is visible before any screen learns its label. A key that is not
   one of the server's own names - the id a map is keyed by, say - is left
   exactly as it came, because an identifier with a capital letter is a
   different identifier. */
function labelOfKey(key: string): string {
  if (!/^[a-z][a-z0-9_]*$/.test(key)) return key;
  const words = key.replace(/_/g, " ").trim();
  return words.charAt(0).toUpperCase() + words.slice(1);
}

/* What a key of a structure is, by its name. The server's own naming is
   consistent enough to read: _at is a time, _seconds a duration, _bytes a
   size, _id an identifier. */
function kindOfKey(key: string): FactKind {
  if (/(^|_)(id|uuid|fingerprint|digest|hash)$/.test(key)) return "id";
  if (/_at$/.test(key)) return "time";
  if (/_seconds(_ago)?$/.test(key)) return "seconds";
  if (/_bytes$/.test(key)) return "bytes";
  if (/_ms$/.test(key)) return "ms";
  return "text";
}

export { optional };

/**
 * The progress bar of an operation in flight. Undetermined progress is not
 * drawn as zero - a bar at zero looks like work that stands still.
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
 * helps and what to do next.
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
