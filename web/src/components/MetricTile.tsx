import type { ReactNode } from "react";
import type { IconName } from "./icons";
import { useT } from "../i18n";
import { Stat, type Span } from "../ui/kit";

/**
 * One measurement, shown the way a measurement is read: the number first
 * and large, its label small underneath.
 *
 * It is the kit's Stat under the names the fleet screens already use. The
 * two rules it is here for are the kit's own: a value nobody knows is an
 * em dash and the word unknown, never a nought; and a state colours the
 * figure, never the frame - the filled tile belongs to `hero`, which wears
 * the accent and therefore carries no meaning at all.
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
  /** How many of the twelve columns the tile takes on a widget grid. */
  span?: number;
  /** The mark above the number, naming the subject. */
  icon?: IconName;
  /** How it moved, beside the label; the caller says whether up is good. */
  delta?: { text: string; direction: "up" | "down"; good?: boolean };
}) {
  const t = useT();
  const unknown = value === null || value === undefined;
  return (
    <Stat
      label={unknown ? t("{label}: unknown", { label }) : label}
      value={value}
      unit={unit}
      tone={state}
      icon={icon}
      hero={hero}
      size={size}
      note={footnote}
      delta={delta}
      span={span as Span | undefined}
      testId={`metric-${label}`}
    />
  );
}
