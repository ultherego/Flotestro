import { describe, expect, it } from "vitest";
import { entryFile, foundUnderName, kindLabel, previewOf, scheduleKinds, type Schedule } from "./Schedules";
import type { Capabilities } from "../../lib/types";

/* Cron and systemd timers are two mechanisms of one thing. Which of them a
   host can carry is the host's answer, not the panel's guess, and an agent
   silent about its features is one from before the timers. */

const t = (text: string) => text;
const schedules = (features?: Record<string, boolean>, available = true): Capabilities => [
  { name: "schedules", version: 1, available, read_only: false, features },
];

describe("scheduleKinds", () => {
  it("offers what the host says it has", () => {
    expect(scheduleKinds(schedules({ cron: true, timers: true, managed_timers: true }))).toEqual(["cron", "timer"]);
    expect(scheduleKinds(schedules({ cron: false, timers: true, managed_timers: true }))).toEqual(["timer"]);
    expect(scheduleKinds(schedules({ cron: true, timers: false }))).toEqual(["cron"]);
  });

  it("offers no timer to an agent that only reads them", () => {
    // The adapter of an older agent names the timers it reads and nothing
    // about writing them: it would ignore the kind and write a cron entry
    // under the name of a timer.
    expect(scheduleKinds(schedules({ cron: true, timers: true }))).toEqual(["cron"]);
  });

  it("reads silence as the cron of every release before the timers", () => {
    expect(scheduleKinds(schedules())).toEqual(["cron"]);
  });

  it("offers nothing where there is no adapter at all", () => {
    expect(scheduleKinds(schedules({ cron: true, timers: true }, false))).toEqual([]);
    expect(scheduleKinds([])).toEqual([]);
    expect(scheduleKinds(undefined)).toEqual([]);
  });
});

describe("kindLabel", () => {
  it("names each mechanism, and leaves an unknown one as it came", () => {
    expect(kindLabel("cron", t)).toBe("a cron entry");
    expect(kindLabel("timer", t)).toBe("a systemd timer");
    expect(kindLabel("any", t)).toBe("whichever the host has");
    expect(kindLabel("anacron", t)).toBe("anacron");
  });
});

/* The preview is typed by the control plane; the plan of a timer comes
   from the document the agent prints where the typed result does not
   carry it yet, so a panel newer than the control plane still shows the
   operator what would be written. */

describe("previewOf", () => {
  const document = JSON.stringify({
    expression: "15 3 * * *",
    timezone: "Europe/Warsaw",
    next_runs: ["2026-09-19T03:15:00+02:00"],
    calendar: "*-*-* 03:15:00",
    units: [{ path: "/etc/systemd/system/flotestro-a.timer", content: "[Timer]\n" }],
  });

  it("takes the typed result and the plan beside it", () => {
    const preview = previewOf({
      status: "succeeded",
      stdout: document,
      detail: {
        kind: "schedule_preview", expression: "15 3 * * *", timezone: "Europe/Warsaw",
        runs: ["2026-09-19T03:15:00+02:00"], error: "",
      },
    });
    expect(preview.expression).toBe("15 3 * * *");
    expect(preview.next_runs).toEqual(["2026-09-19T03:15:00+02:00"]);
    expect(preview.calendar).toBe("*-*-* 03:15:00");
    expect(preview.units?.[0].path).toBe("/etc/systemd/system/flotestro-a.timer");
  });

  it("falls back to the document of an agent whose result is not typed", () => {
    const preview = previewOf({ status: "succeeded", stdout: document });
    expect(preview.timezone).toBe("Europe/Warsaw");
    expect(preview.calendar).toBe("*-*-* 03:15:00");
  });

  it("stays a preview of nothing when there is nothing to read", () => {
    expect(previewOf({ status: "succeeded" })).toEqual({});
    expect(previewOf({ status: "succeeded", stdout: "not a document" })).toEqual({});
  });
});

/* An entry found on the host is named by the file it lives in and the line
   inside it, and one file holds as many entries as it has lines. A name typed
   into the form is therefore compared with the file, not with an identifier. */

describe("foundUnderName", () => {
  const line = (path: string, at: number): Schedule => ({
    id: `${path}:${at}`, kind: "cron", source: "manual", enabled: true,
    expression: "0 1 * * 0", path, line: at,
  });
  const ours: Schedule = {
    id: "raid-check", kind: "cron", source: "managed", enabled: true,
    expression: "0 5 * * *", path: "/etc/cron.d/flotestro-raid-check", line: 2,
  };
  const entries: Schedule[] = [
    ours,
    line("/etc/cron.d/raid-check", 1),
    line("/etc/cron.d/raid-check", 2),
    line("/etc/crontab", 4),
  ];

  it("finds every line of the file the name would take over", () => {
    expect(foundUnderName(entries, "raid-check").map((entry) => entry.line)).toEqual([1, 2]);
    expect(entryFile(entries[1])).toBe("raid-check");
  });

  it("leaves our own entry alone: ordering that name again rewrites it", () => {
    expect(foundUnderName([ours], "raid-check")).toEqual([]);
  });

  it("finds nothing for an empty name or a name nobody uses", () => {
    expect(foundUnderName(entries, "")).toEqual([]);
    expect(foundUnderName(entries, "nightly")).toEqual([]);
  });
});
