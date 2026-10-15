import type { ReactNode } from "react";
import { Icon, type IconName } from "./icons";
import { useT } from "../i18n";

/**
 * One measurement, shown the way a measurement is read: the number first and
 * large, its label small underneath.
 *
 * Two rules are built in rather than left to whoever uses it.
 *
 * A value nobody knows is not a zero. `value={null}` draws an em dash and
 * says "unknown" in words - the panel's first principle, and the one a tile
 * is most tempted to break, because a dash looks untidy and a zero looks
 * tidy and wrong.
 *
 * A state is a thin border and a mark, never a filled background. The filled
 * tile belongs to `hero`, which carries the accent and therefore carries no
 * meaning: it says "look here first", not "this is healthy".
 */

export type MetricState = "ok" | "warn" | "error" | "unknown";

export function MetricTile({
  label, value, unit, state, hero = false, size = "l", footnote, span, icon, delta,
}: {
  label: string;
  /** null or undefined is unknown. A number is shown as given. */
  value: ReactNode | null | undefined;
  unit?: string;
  state?: MetricState;
  hero?: boolean;
  size?: "xl" | "l" | "m";
  footnote?: string;
  /** How many of the twelve columns the tile takes, when it stands in a
      widget grid. Without it the tile is one column wide, which is what a
      grid child with no span class is - and which is never what was meant. */
  span?: number;
  /** The mark above the number, in a quiet round chip. It names the subject
      so the eye can find the right tile in a row of four without reading
      four labels. */
  icon?: IconName;
  /** How it moved, beside the label: the direction decides the colour, and
      the caller says whether up is good - more hosts online is, more hosts
      offline is not. */
  delta?: { text: string; direction: "up" | "down"; good?: boolean };
}) {
  const t = useT();
  const unknown = value === null || value === undefined;
  const shown: MetricState | undefined = unknown ? "unknown" : state;
  const classes = ["metric-tile", `metric-tile-${size}`];
  if (span) classes.push(`span-${span}`);
  if (hero) classes.push("metric-tile-hero");
  if (shown && shown !== "ok") classes.push(`metric-tile-${shown}`);

  return (
    <div className={classes.join(" ")} data-testid={`metric-${label}`} data-state={shown ?? "none"}>
      {icon && (
        <span className="metric-chip" aria-hidden="true">
          <Icon name={icon} />
        </span>
      )}
      <div className="metric-value">
        {unknown ? <span className="metric-unknown" title={t("unknown")}>—</span> : value}
        {!unknown && unit ? <span className="metric-unit">{unit}</span> : null}
      </div>
      <div className="metric-foot">
        <span className="metric-label">{unknown ? t("{label}: unknown", { label }) : label}</span>
        {delta && !unknown && (
          <span className={`metric-delta ${delta.good === false ? "bad" : "good"}`}>
            {delta.text}
            <span aria-hidden="true">{delta.direction === "up" ? " ↑" : " ↓"}</span>
          </span>
        )}
      </div>
      {footnote ? <div className="metric-footnote">{footnote}</div> : null}
    </div>
  );
}
