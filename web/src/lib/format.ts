// Shared formatting. Every value shown to the operator has an observation
// time, and an undetermined state is never drawn as zero.

import { t } from "../i18n";

// The zone the absolute times are read in, kept outside React like the
// locale: the helpers here are plain functions called from anywhere, and the
// preferences provider tells them the zone once it knows it.
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
  // A moment ahead reads by the same scale as one behind: a certificate
  // ten years out is not "in a moment".
  if (seconds < 0) {
    const ahead = -seconds;
    if (ahead < 60) return t("in a moment");
    if (ahead < 3600) return t("in {n}m", { n: Math.floor(ahead / 60) });
    if (ahead < 86400) return t("in {n}h", { n: Math.floor(ahead / 3600) });
    return t("in {n}d", { n: Math.floor(ahead / 86400) });
  }
  if (seconds < 60) return t("{n}s ago", { n: seconds });
  if (seconds < 3600) return t("{n}m ago", { n: Math.floor(seconds / 60) });
  if (seconds < 86400) return t("{n}h ago", { n: Math.floor(seconds / 3600) });
  return t("{n}d ago", { n: Math.floor(seconds / 86400) });
}

/**
 * The absolute time in ISO form, in the zone the operator prefers or,
 * without a preference, in the browser's local zone.
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
 * The absolute time in the same ISO shape, in a named zone: what the profile
 * screen shows for a zone the operator is still choosing.
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
 * The same ISO shape in a named zone.
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

export function bytes(value?: number | null): string {
  // Nobody knowing is not nought. A size the host never reported read as
  // "0 B" here, which is a claim the panel has no grounds for - a disk
  // nobody measured and an empty disk are not the same disk.
  if (value === undefined || value === null || Number.isNaN(value)) return "\u2014";
  if (value === 0) return "0 B";
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
 * API reads.
 */
export function toInstant(local: string): string {
  if (!local) return "";
  const parsed = new Date(local);
  return Number.isNaN(parsed.getTime()) ? "" : parsed.toISOString();
}

/**
 * A number of seconds as a short duration. Fractions matter below a minute -
 * a latency of 0.4s is not "0s".
 */
export function duration(value: number): string {
  if (!Number.isFinite(value) || value < 0) return "—";
  if (value < 60) return `${value < 10 ? value.toFixed(1) : Math.round(value)}s`;
  if (value < 3600) return `${Math.floor(value / 60)}m ${Math.round(value % 60)}s`;
  if (value < 86400) return `${Math.floor(value / 3600)}h ${Math.floor((value % 3600) / 60)}m`;
  return `${Math.floor(value / 86400)}d ${Math.floor((value % 86400) / 3600)}h`;
}

/**
 * A Go duration such as 720h0m0s, 4m30s or 29m53s in the units a person
 * reads it in: whole days, hours, minutes and seconds, the zero parts left
 * out. A value that is not one is given back as it came.
 */
export function goDuration(value: string): string {
  const match = /^(?:(\d+)h)?(?:(\d+)m)?(?:(\d+(?:\.\d+)?)s)?$/.exec(value);
  if (!match || value === "") return value;
  const hours = Number(match[1] ?? 0);
  const minutes = Number(match[2] ?? 0);
  const seconds = Number(match[3] ?? 0);
  const parts: string[] = [];
  if (hours >= 24) parts.push(`${Math.floor(hours / 24)} d`);
  if (hours % 24 > 0) parts.push(`${hours % 24} h`);
  if (minutes > 0) parts.push(`${minutes} min`);
  if (seconds > 0) parts.push(`${seconds} s`);
  return parts.length > 0 ? parts.join(" ") : "0 s";
}
