import { useT } from "../i18n";
import { toneClass } from "../ui/kit";

/**
 * How many of each severity there are, as one row of blocks.
 *
 * A count of zero keeps its block, greyed: a row that hides its empty
 * severities changes shape as the fleet changes, and the eye then has to
 * read the labels every time instead of recognising a position. "Nothing
 * critical" is also an answer, and it is the one worth seeing at a glance.
 *
 * Unknown stands at the end and is not a severity but the absence of one:
 * alerts whose rule has no data. It is here because leaving it out would
 * let a fleet nobody can see look like a quiet fleet.
 */

export type SeverityCounts = {
  /**
   * How many are firing at each severity. Undefined is not zero: it is the
   * server not having answered yet, and a bar that drew noughts there would
   * say "nothing is on fire" about a fleet nobody has asked.
   */
  critical?: number;
  warning?: number;
  info?: number;
  /** Rules with no data. Undefined means the caller does not track it. */
  unknown?: number;
};

/* A severity is read as a state: critical is an error, warning a warning,
   info the neutral blue, and unknown the colour of every other unknown. */
const SEVERITY_TONE: Record<keyof SeverityCounts, string> = {
  critical: "error", warning: "warn", info: "info", unknown: "unknown",
};

const ORDER: { key: keyof SeverityCounts; label: string }[] = [
  { key: "critical", label: "Critical" },
  { key: "warning", label: "Warning" },
  { key: "info", label: "Info" },
  { key: "unknown", label: "Unknown" },
];

export function SeverityBar({
  counts, onPick,
}: {
  counts: SeverityCounts;
  onPick?: (severity: keyof SeverityCounts) => void;
}) {
  const t = useT();
  return (
    <div className="ui-severity" role="group" aria-label={t("Alerts by severity")}>
      {ORDER.map(({ key, label }) => {
        const count = counts[key];
        if (key === "unknown" && count === undefined) return null;
        // Three states, not two: a count, a nought, and no answer at all.
        const unanswered = count === undefined;
        const empty = !unanswered && !count;
        const content = (
          <>
            <span className="ui-severity-count">{unanswered ? "—" : count}</span>
            <span className="ui-severity-label">{t(label)}</span>
          </>
        );
        const className = [
          "ui-severity-block", toneClass(SEVERITY_TONE[key]),
          empty ? "ui-severity-empty" : "", unanswered ? "ui-severity-unanswered" : "",
        ].join(" ").trim();
        return onPick && !empty && !unanswered ? (
          <button key={key} type="button" className={className}
                  data-testid={`severity-${key}`} onClick={() => onPick(key)}>
            {content}
          </button>
        ) : (
          <div key={key} className={className} data-testid={`severity-${key}`}>{content}</div>
        );
      })}
    </div>
  );
}
