import { useT } from "../i18n";

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
  critical: number;
  warning: number;
  info: number;
  /** Rules with no data. Undefined means the caller does not track it. */
  unknown?: number;
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
    <div className="severity-bar" role="group" aria-label={t("Alerts by severity")}>
      {ORDER.map(({ key, label }) => {
        const count = counts[key];
        if (key === "unknown" && count === undefined) return null;
        const empty = !count;
        const content = (
          <>
            <span className="severity-count">{count ?? 0}</span>
            <span className="severity-label">{t(label)}</span>
          </>
        );
        const className = `severity-block severity-${key}${empty ? " severity-empty" : ""}`;
        return onPick && !empty ? (
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
