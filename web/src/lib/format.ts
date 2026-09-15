// Shared formatting. Every value shown to the operator has an observation
// time, and an undetermined state is never drawn as zero.

import { t } from "../i18n";

// The zone the absolute times are read in, kept outside React like the
// locale: the helpers here are plain functions called from anywhere, and
// the preferences provider tells them the zone once it knows it. Empty
// means the browser's own zone.
let preferredZone = "";

/** The zone the times are formatted in: the preferred one, or empty for the browser's. */
export function preferredTimeZone(): string {
  return preferredZone;
}

/** Sets the zone every absolute time is formatted in from now on; the preferences provider calls it. */
export function setPreferredTimeZone(zone: string): void {
  preferredZone = zone;
}

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
 * The absolute time in ISO form, in the zone the operator prefers or,
 * without a preference, in the browser's local zone.
 *
 * A format dependent on the browser language would diverge between
 * operators looking at the same incident, and the order of day and month is
 * sometimes reversed in it. The operational trail must read the same for
 * everybody. The zone is the one exception: an operator on call for a
 * fleet in another zone reads the trail in the fleet's clock, and says so
 * in their preferences.
 */
export function absoluteTime(value?: string | null): string {
  if (!value) return "";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "";
  const zone = preferredTimeZone();
  if (zone) return inZone(date, zone);
  const pad = (number: number) => String(number).padStart(2, "0");
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ` +
    `${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`;
}

/**
 * The absolute time in the same ISO shape, in a named zone: what the
 * profile screen shows for a zone the operator is still choosing. A zone
 * this browser cannot format in falls back to the browser's own.
 */
export function absoluteTimeIn(value: string, zone: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "";
  try {
    return inZone(date, zone);
  } catch {
    return absoluteTime(value);
  }
}

/**
 * The same ISO shape in a named zone. The parts come from the browser's
 * own zone tables, in the 24-hour clock, and are put together by hand so
 * the text is the one every screen shows rather than a locale's own.
 */
function inZone(date: Date, zone: string): string {
  const parts = new Intl.DateTimeFormat("en-GB", {
    timeZone: zone, hourCycle: "h23",
    year: "numeric", month: "2-digit", day: "2-digit",
    hour: "2-digit", minute: "2-digit", second: "2-digit",
  }).formatToParts(date);
  const part = (type: Intl.DateTimeFormatPartTypes) => parts.find((entry) => entry.type === type)?.value ?? "";
  return `${part("year")}-${part("month")}-${part("day")} ${part("hour")}:${part("minute")}:${part("second")}`;
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

/**
 * Turns the value of a datetime-local input into the RFC 3339 instant the
 * API reads. The input speaks the browser's local time without a zone; the
 * API wants an instant, so the conversion happens here rather than on the
 * server guessing the operator's zone. An empty or unreadable value is no
 * bound.
 */
export function toInstant(local: string): string {
  if (!local) return "";
  const parsed = new Date(local);
  return Number.isNaN(parsed.getTime()) ? "" : parsed.toISOString();
}
