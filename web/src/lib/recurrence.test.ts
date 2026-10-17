import { describe, expect, it } from "vitest";
import {
  describeRecurrence, parseRecurrence, recurrenceProblem, recurrenceText,
} from "./recurrence";

/* The rule text the API reads, read back, and said in words. They are pure,
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
