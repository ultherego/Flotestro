// Shared formatting. Every value shown to the operator has an observation
// time, and an undetermined state is never drawn as zero.

import { t } from "../i18n";

export function relativeTime(value?: string | null): string {
  if (!value) return t("never");
  const seconds = Math.floor((Date.now() - new Date(value).getTime()) / 1000);
  if (seconds < 0) return t("in a moment");
  if (seconds < 60) return t("{n}s ago", { n: seconds });
  if (seconds < 3600) return t("{n}m ago", { n: Math.floor(seconds / 60) });
  if (seconds < 86400) return t("{n}h ago", { n: Math.floor(seconds / 3600) });
  return t("{n}d ago", { n: Math.floor(seconds / 86400) });
}

/**
 * The absolute time in ISO form in the browser's local zone.
 *
 * A format dependent on the browser language would diverge between
 * operators looking at the same incident, and the order of day and month is
 * sometimes reversed in it. The operational trail must read the same for
 * everybody.
 */
export function absoluteTime(value?: string | null): string {
  if (!value) return "";
  const date = new Date(value);
  const pad = (number: number) => String(number).padStart(2, "0");
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ` +
    `${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`;
}

/**
 * An undetermined value has its own representation. Drawing it as zero
 * would be a false signal that the host is fine.
 */
export function optional(value: number | boolean | null | undefined): string {
  if (value === null || value === undefined) return t("unknown");
  if (typeof value === "boolean") return value ? t("yes") : t("no");
  return String(value);
}

export function bytes(value?: number): string {
  if (!value) return "0 B";
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let size = value;
  let unit = 0;
  while (size >= 1024 && unit < units.length - 1) {
    size /= 1024;
    unit += 1;
  }
  return `${size.toFixed(size < 10 && unit > 0 ? 1 : 0)} ${units[unit]}`;
}
