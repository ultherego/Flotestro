import { toInstant } from "./format";
import type { StateTone } from "./tone";

/**
 * The management reports: the period they cover, the query they are asked
 * with, and the words and colours they are read in.
 *
 * All of it is a pure function of what the operator picked, which is why it
 * sits beside the screen rather than inside it: the report on screen, the
 * export of the same report and the print of it have to agree on the period
 * and on what a state is called.
 */

/** The periods offered with one click, and the one typed by hand. */
export type Preset = "7d" | "30d" | "this_month" | "previous_month" | "custom";

export const PRESETS: { key: Preset; label: string }[] = [
  { key: "7d", label: "Last 7 days" },
  { key: "30d", label: "Last 30 days" },
  { key: "this_month", label: "This month" },
  { key: "previous_month", label: "Previous month" },
  { key: "custom", label: "Custom" },
];

/**
 * The bounds of a preset as instants: the last days end now; a month runs
 * from its first midnight to the next one in the browser's clock, because
 * "September" is the operator's September, not the server's.
 */
export function presetRange(preset: Preset, now: Date, custom: { from: string; to: string }): { from: string; to: string } {
  const monthStart = (shift: number) => new Date(now.getFullYear(), now.getMonth() + shift, 1);
  switch (preset) {
    case "7d":
      return { from: new Date(now.getTime() - 7 * 24 * 3600 * 1000).toISOString(), to: now.toISOString() };
    case "30d":
      return { from: new Date(now.getTime() - 30 * 24 * 3600 * 1000).toISOString(), to: now.toISOString() };
    case "this_month":
      return { from: monthStart(0).toISOString(), to: monthStart(1).toISOString() };
    case "previous_month":
      return { from: monthStart(-1).toISOString(), to: monthStart(0).toISOString() };
    default:
      return { from: toInstant(custom.from), to: toInstant(custom.to) };
  }
}

/** The filter of the page: the period and the part of the fleet. */
export type ReportFilters = {
  from: string;
  to: string;
  site: string;
  environment: string;
};

/**
 * The query every report and every export is asked with: the bounds and the
 * filter, and nothing when a bound is missing - a half period is refused by
 * the server, and the page does not ask until both ends are set.
 */
export function reportParams(filters: ReportFilters): URLSearchParams {
  const params = new URLSearchParams();
  if (filters.from && filters.to) {
    params.set("from", filters.from);
    params.set("to", filters.to);
  }
  if (filters.site.trim()) params.set("site", filters.site.trim());
  if (filters.environment.trim()) params.set("environment", filters.environment.trim());
  return params;
}

/** A rate as a percentage with one decimal; a dash for no rate. */
export function percent(rate?: number | null): string {
  if (rate === null || rate === undefined) return "—";
  return `${(rate * 100).toFixed(1)}%`;
}

/** A duration in the largest units that read at a glance: 2d 03h, 1h 05m, 45s. */
export function duration(seconds?: number | null): string {
  if (seconds === null || seconds === undefined) return "—";
  const pad = (number: number) => String(number).padStart(2, "0");
  if (seconds >= 86400) return `${Math.floor(seconds / 86400)}d ${pad(Math.floor((seconds % 86400) / 3600))}h`;
  if (seconds >= 3600) return `${Math.floor(seconds / 3600)}h ${pad(Math.floor((seconds % 3600) / 60))}m`;
  if (seconds >= 60) return `${Math.floor(seconds / 60)}m ${pad(seconds % 60)}s`;
  return `${seconds}s`;
}

/** The tone of a campaign's terminal state on the report. */
export function campaignStateTone(state: string): StateTone {
  switch (state) {
    case "completed":
      return "ok";
    case "completed_with_issues":
      return "warn";
    case "failed":
    case "plan_failed":
      return "error";
    case "canceled":
    case "expired":
      return "neutral";
    default:
      return "unknown";
  }
}

/** The states of a closed campaign in the order the summary shows them,
 *  with the words the page uses for them. */
export const CAMPAIGN_STATES: { state: string; label: string }[] = [
  { state: "completed", label: "completed" },
  { state: "completed_with_issues", label: "completed with issues" },
  { state: "failed", label: "failed" },
  { state: "plan_failed", label: "plan failed" },
  { state: "expired", label: "expired" },
  { state: "canceled", label: "canceled" },
];

/** The word for a state, the state itself for one the list does not know. */
export function campaignStateLabel(state: string): string {
  return CAMPAIGN_STATES.find((entry) => entry.state === state)?.label ?? state;
}

/** How many campaigns the table shows on screen before it asks to unfold; on paper it is whole. */
export const FOLDED_ROWS = 25;
