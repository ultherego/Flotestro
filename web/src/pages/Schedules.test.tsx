import { describe, expect, it } from "vitest";
import {
  describeRecurrence, entriesByDay, monthGrid, nextRunWords, parseRecurrence, recurrenceProblem, recurrenceText,
  scheduleBody, type CalendarEntry,
} from "./Schedules";

/* The page draws what these helpers say: the rule text the API reads,
   the words for the next moment, the grid of the month. They are pure,
   so every branch is checked here without a screen. */

const t = (text: string, params?: Record<string, string | number>) =>
  text.replace(/\{(\w+)\}/g, (_, key: string) => String(params?.[key] ?? `{${key}}`));

describe("recurrenceText and parseRecurrence", () => {
  it("writes a monthly rule and reads it back", () => {
    const text = recurrenceText({ freq: "MONTHLY", monthDay: 15, weekdays: [], hour: 2, minute: 30 });
    expect(text).toBe("FREQ=MONTHLY;BYMONTHDAY=15;BYHOUR=2;BYMINUTE=30");
    expect(parseRecurrence(text)).toEqual({ freq: "MONTHLY", monthDay: 15, weekdays: ["MO"], hour: 2, minute: 30 });
  });

  it("writes the weekdays in the calendar's order whatever order they were ticked in", () => {
    const text = recurrenceText({ freq: "WEEKLY", monthDay: 1, weekdays: ["FR", "MO"], hour: 22, minute: 0 });
    expect(text).toBe("FREQ=WEEKLY;BYDAY=MO,FR;BYHOUR=22;BYMINUTE=0");
    expect(parseRecurrence("freq=weekly;byday=fr,mo;byhour=22;byminute=0")?.weekdays).toEqual(["MO", "FR"]);
  });

  it("gives an empty text for one moment and null for a rule outside the subset", () => {
    expect(recurrenceText({ freq: "", monthDay: 1, weekdays: [], hour: 0, minute: 0 })).toBe("");
    expect(parseRecurrence("")).toBeNull();
    expect(parseRecurrence(undefined)).toBeNull();
    expect(parseRecurrence("FREQ=DAILY;BYHOUR=1")).toBeNull();
    expect(parseRecurrence("FREQ=MONTHLY;BYMONTHDAY=32")).toBeNull();
    expect(parseRecurrence("FREQ=WEEKLY;BYDAY=XX")).toBeNull();
  });

  it("names what stops a form from being a rule", () => {
    expect(recurrenceProblem({ freq: "", monthDay: 0, weekdays: [], hour: 99, minute: 0 })).toBeNull();
    expect(recurrenceProblem({ freq: "WEEKLY", monthDay: 1, weekdays: [], hour: 1, minute: 0 })).toBe("no_weekday");
    expect(recurrenceProblem({ freq: "MONTHLY", monthDay: 0, weekdays: [], hour: 1, minute: 0 })).toBe("bad_day");
    expect(recurrenceProblem({ freq: "MONTHLY", monthDay: 1, weekdays: [], hour: 24, minute: 0 })).toBe("bad_time");
    expect(recurrenceProblem({ freq: "MONTHLY", monthDay: 1, weekdays: [], hour: 1, minute: 0 })).toBeNull();
  });
});

describe("describeRecurrence", () => {
  it("puts the rule in words with the time padded", () => {
    expect(describeRecurrence(t, "FREQ=MONTHLY;BYMONTHDAY=3;BYHOUR=1;BYMINUTE=5")).toBe("monthly on day 3 at 01:05");
    expect(describeRecurrence(t, "FREQ=WEEKLY;BYDAY=MO,TH;BYHOUR=22;BYMINUTE=30")).toBe("weekly on MO, TH at 22:30");
    expect(describeRecurrence(t, undefined)).toBe("once");
  });
});

describe("nextRunWords", () => {
  const now = new Date("2026-09-15T12:00:00Z");

  it("says how far ahead the moment is and when exactly", () => {
    const soon = new Date(now.getTime() + 20 * 60 * 1000).toISOString();
    expect(nextRunWords(t, { enabled: true, next_run_at: soon }, now)).toMatch(/^in 20 min \(2026-09-15 /);
    const hours = new Date(now.getTime() + 5 * 3600 * 1000).toISOString();
    expect(nextRunWords(t, { enabled: true, next_run_at: hours }, now)).toMatch(/^in 5 h \(/);
    const days = new Date(now.getTime() + 3 * 86400 * 1000).toISOString();
    expect(nextRunWords(t, { enabled: true, next_run_at: days }, now)).toMatch(/^in 3 days \(2026-09-18 /);
  });

  it("reads a moment the loop is late for as due, never as a time in the past", () => {
    const passed = new Date(now.getTime() - 30 * 1000).toISOString();
    expect(nextRunWords(t, { enabled: true, next_run_at: passed }, now)).toMatch(/^due now \(/);
  });

  it("tells a disabled schedule from one with nothing more to place", () => {
    expect(nextRunWords(t, { enabled: false, next_run_at: now.toISOString() }, now)).toBe("disabled");
    expect(nextRunWords(t, { enabled: true, next_run_at: null }, now)).toBe("nothing more to place");
  });
});

describe("monthGrid", () => {
  it("starts every row on a Monday and covers the whole month", () => {
    // September 2026 starts on a Tuesday and ends on a Wednesday.
    const weeks = monthGrid(2026, 8);
    expect(weeks.length).toBe(5);
    expect(weeks[0][0].getDate()).toBe(31);
    expect(weeks[0][0].getMonth()).toBe(7);
    expect(weeks[0][1].getDate()).toBe(1);
    for (const week of weeks) {
      expect(week.length).toBe(7);
      expect(week[0].getDay()).toBe(1);
    }
    const last = weeks[weeks.length - 1];
    expect(last.some((date) => date.getDate() === 30 && date.getMonth() === 8)).toBe(true);
  });

  it("gives exactly four rows to a month of four whole weeks", () => {
    // February 2021: the 1st is a Monday and the 28th a Sunday.
    expect(monthGrid(2021, 1).length).toBe(4);
  });
});

describe("entriesByDay", () => {
  const from = new Date(2026, 8, 1);
  const to = new Date(2026, 9, 1);
  const entries: CalendarEntry[] = [
    { kind: "schedule", id: "s", name: "patching", start: new Date(2026, 8, 15, 2, 30).toISOString() },
    { kind: "host_window", id: "h", name: "web-1", start: new Date(2026, 8, 20, 8).toISOString(), end: new Date(2026, 8, 22, 18).toISOString() },
    { kind: "campaign_window", id: "c", name: "kernel", end: new Date(2026, 8, 3, 6).toISOString() },
  ];

  it("puts a moment on its day and a window on every day it covers", () => {
    const byDay = entriesByDay(entries, from, to);
    expect(byDay.get("2026-09-15")?.map((entry) => entry.id)).toEqual(["s"]);
    expect(byDay.get("2026-09-20")?.map((entry) => entry.id)).toEqual(["h"]);
    expect(byDay.get("2026-09-21")?.map((entry) => entry.id)).toEqual(["h"]);
    expect(byDay.get("2026-09-22")?.map((entry) => entry.id)).toEqual(["h"]);
    expect(byDay.get("2026-09-23")).toBeUndefined();
  });

  it("draws a window without a start from the first day of the range", () => {
    const byDay = entriesByDay(entries, from, to);
    expect(byDay.get("2026-09-01")?.map((entry) => entry.id)).toEqual(["c"]);
    expect(byDay.get("2026-09-03")?.map((entry) => entry.id)).toEqual(["c"]);
    expect(byDay.get("2026-09-04")).toBeUndefined();
  });
});

describe("scheduleBody", () => {
  const form = {
    name: "monthly patching",
    orderText: JSON.stringify({ name: "patch", action: "packages.upgrade", selector: { site: "lab" } }),
    startAt: "",
    recurrence: { freq: "MONTHLY" as const, monthDay: 1, weekdays: [], hour: 3, minute: 0 },
    timezone: "Europe/Warsaw",
    enabled: true,
    reason: "CHG-42: the monthly window",
  };

  it("builds the body the API takes from a recurring form", () => {
    const { body, problem } = scheduleBody(form);
    expect(problem).toBeUndefined();
    expect(body).toMatchObject({
      name: "monthly patching", recurrence: "FREQ=MONTHLY;BYMONTHDAY=1;BYHOUR=3;BYMINUTE=0",
      timezone: "Europe/Warsaw", enabled: true, reason: "CHG-42: the monthly window",
    });
    expect((body?.order as { action: string }).action).toBe("packages.upgrade");
    expect(body?.start_at).toBeUndefined();
  });

  it("names what stops the form: no moment, a moment behind, a short reason, an order that is not JSON", () => {
    expect(scheduleBody({ ...form, recurrence: { ...form.recurrence, freq: "" } }).problem).toBe("moment");
    expect(scheduleBody({ ...form, recurrence: { ...form.recurrence, freq: "" }, startAt: "2001-01-01T00:00" }).problem).toBe("start_past");
    expect(scheduleBody({ ...form, reason: "short" }).problem).toBe("reason");
    expect(scheduleBody({ ...form, orderText: "{" }).problem).toBe("order_json");
    expect(scheduleBody({ ...form, orderText: "[]" }).problem).toBe("order_json");
    expect(scheduleBody({ ...form, name: " " }).problem).toBe("name");
    expect(scheduleBody({ ...form, recurrence: { ...form.recurrence, freq: "WEEKLY", weekdays: [] } }).problem).toBe("recurrence");
  });
});
