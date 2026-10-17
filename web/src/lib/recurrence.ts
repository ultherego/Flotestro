import type { Translate } from "../i18n";

/**
 * The recurrence of a schedule: the form an operator fills in, the RRULE
 * text the API reads, and the translation both ways.
 *
 * The schedules screen edits one and the bulk wizard keeps one beside an
 * order, so a rule written in one is the rule the other reads back; two
 * copies of this would be two ideas of what "weekly" means.
 */

/** The recurrence as the form holds it; freq "" means one moment. */
export type RecurrenceForm = {
  freq: "" | "MONTHLY" | "WEEKLY";
  monthDay: number;
  weekdays: string[];
  hour: number;
  minute: number;
};

/** The weekday codes of RRULE, Monday first as the calendar reads them. */
export const WEEKDAYS = ["MO", "TU", "WE", "TH", "FR", "SA", "SU"];

export function emptyRecurrence(): RecurrenceForm {
  return { freq: "", monthDay: 1, weekdays: ["MO"], hour: 2, minute: 0 };
}

/**
 * The rule text the API reads, or an empty string for one moment.
 */
export function recurrenceText(form: RecurrenceForm): string {
  if (!form.freq) return "";
  const at = `BYHOUR=${form.hour};BYMINUTE=${form.minute}`;
  if (form.freq === "MONTHLY") return `FREQ=MONTHLY;BYMONTHDAY=${form.monthDay};${at}`;
  const days = WEEKDAYS.filter((day) => form.weekdays.includes(day));
  return `FREQ=WEEKLY;BYDAY=${days.join(",")};${at}`;
}

/**
 * The form of a stored rule, or null when the text is not one the form can
 * hold - the server accepts the same subset, so a stored rule always parses,
 * and null only ever means an empty or foreign text.
 */
export function parseRecurrence(text: string | undefined): RecurrenceForm | null {
  if (!text) return null;
  const form = emptyRecurrence();
  const parts: Record<string, string> = {};
  for (const part of text.split(";")) {
    const [key, value] = part.split("=");
    if (key && value !== undefined) parts[key.trim().toUpperCase()] = value.trim().toUpperCase();
  }
  if (parts.FREQ !== "MONTHLY" && parts.FREQ !== "WEEKLY") return null;
  form.freq = parts.FREQ;
  if (parts.BYHOUR !== undefined) form.hour = Number(parts.BYHOUR);
  if (parts.BYMINUTE !== undefined) form.minute = Number(parts.BYMINUTE);
  if (form.freq === "MONTHLY") {
    const day = Number(parts.BYMONTHDAY);
    if (!Number.isInteger(day) || day < 1 || day > 31) return null;
    form.monthDay = day;
  } else {
    const days = (parts.BYDAY ?? "").split(",").map((day) => day.trim()).filter((day) => WEEKDAYS.includes(day));
    if (days.length === 0) return null;
    form.weekdays = WEEKDAYS.filter((day) => days.includes(day));
  }
  if (!Number.isInteger(form.hour) || form.hour < 0 || form.hour > 23) return null;
  if (!Number.isInteger(form.minute) || form.minute < 0 || form.minute > 59) return null;
  return form;
}

/** What is wrong with a recurrence form, or null when nothing is. */
export function recurrenceProblem(form: RecurrenceForm): "no_weekday" | "bad_day" | "bad_time" | null {
  if (!form.freq) return null;
  if (!Number.isInteger(form.hour) || form.hour < 0 || form.hour > 23) return "bad_time";
  if (!Number.isInteger(form.minute) || form.minute < 0 || form.minute > 59) return "bad_time";
  if (form.freq === "MONTHLY" && (!Number.isInteger(form.monthDay) || form.monthDay < 1 || form.monthDay > 31)) return "bad_day";
  if (form.freq === "WEEKLY" && !form.weekdays.some((day) => WEEKDAYS.includes(day))) return "no_weekday";
  return null;
}

const pad = (value: number) => String(value).padStart(2, "0");

/**
 * The rule in words: "monthly on day 15 at 02:30", "weekly on MO, TH at
 * 22:00", or "once" for a single moment.
 */
export function describeRecurrence(t: Translate, text: string | undefined): string {
  const form = parseRecurrence(text);
  if (!form) return t("once");
  const at = `${pad(form.hour)}:${pad(form.minute)}`;
  if (form.freq === "MONTHLY") return t("monthly on day {day} at {time}", { day: form.monthDay, time: at });
  return t("weekly on {days} at {time}", { days: form.weekdays.join(", "), time: at });
}

/** The browser's zone, the zone an operator writes the schedule's hours in. */
export function browserZone(): string {
  try {
    return Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC";
  } catch {
    return "UTC";
  }
}

