import { describe, expect, it } from "vitest";
import {
  enableOrder, ensureOrder, entryFile, entryOrder, foundUnderName, kindLabel, previewOf, scheduleKinds,
  type Schedule,
} from "./Schedules";
import { emptyForm, operationForm, type FormValue } from "../../lib/operations";
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

/* The four changes go through the operation registry, so the host page and
   the Bulk workspace send one payload and refuse one set of values. What
   the host already runs under a name stays this page's own refusal. */

function bulk(action: string, form: FormValue): Record<string, unknown> {
  const entry = operationForm(action);
  if (!entry) throw new Error(`the registry has no form for ${action}`);
  return entry.toPayload({ ...emptyForm(entry), ...form });
}

const nightly = {
  id: "nightly-backup",
  expression: "0 3 * * *",
  command: ["/usr/local/bin/backup", "--quiet"],
  user: "root",
  comment: "the nightly copy",
  kind: "cron",
  adopt: false,
};

describe("ensureOrder", () => {
  it("sends what the Bulk workspace sends", () => {
    expect(ensureOrder(nightly).payload).toEqual(bulk("schedule.ensure", {
      ...nightly, command: nightly.command.join("\n"),
    }));
    expect(ensureOrder(nightly).payload).toEqual({
      schedule: {
        id: "nightly-backup",
        expression: "0 3 * * *",
        command: ["/usr/local/bin/backup", "--quiet"],
        user: "root",
        kind: "cron",
        comment: "the nightly copy",
      },
    });
    expect(ensureOrder(nightly).problems).toEqual([]);
  });

  // The refusals the page did not make before it went through the registry.
  it("refuses on the host page what the Bulk workspace refuses", () => {
    const refuses = (change: Partial<typeof nightly>, sentence: string) => {
      const order = ensureOrder({ ...nightly, ...change });
      expect(order.problems, JSON.stringify(change)).not.toEqual([]);
      expect(order.problems[0].message).toContain(sentence);
      expect(order.problems).toEqual(
        operationForm("schedule.ensure")?.validate({
          ...emptyForm(operationForm("schedule.ensure")!),
          ...nightly, ...change,
          command: (change.command ?? nightly.command).join("\n"),
        }),
      );
    };

    refuses({ id: "nightly backup" }, "An identifier is letters");
    refuses({ expression: "every night" }, "five fields");
    refuses({ command: ["backup"] }, "absolute path");
    refuses({ command: ["/usr/local/bin/backup", "> /dev/null"] }, "shell character");
    refuses({ user: "" }, "root is not a default");
    refuses({ user: "Jane" }, "lower-case letters");
    // Cron runs when either day field matches, a timer only when both do.
    refuses({ kind: "timer", expression: "0 3 1 * 1" }, "both match");
  });
});

describe("entryOrder and enableOrder", () => {
  it("send what the Bulk workspace sends", () => {
    for (const action of ["schedule.run_now", "schedule.remove"]) {
      expect(entryOrder(action, "nightly-backup").payload)
        .toEqual(bulk(action, { id: "nightly-backup" }));
      expect(entryOrder(action, "nightly-backup").payload).toEqual({ schedule: { id: "nightly-backup" } });
    }
    expect(enableOrder("nightly-backup", true).payload)
      .toEqual(bulk("schedule.disable", { id: "nightly-backup", enabled: true }));
    // Switching it off carries no flag: the registry leaves out what is
    // false, and the host reads an absent flag as off.
    expect(enableOrder("nightly-backup", false).payload).toEqual({ schedule: { id: "nightly-backup" } });
  });

  it("refuses an identifier the panel never gave", () => {
    expect(entryOrder("schedule.remove", "").problems).not.toEqual([]);
    expect(entryOrder("schedule.run_now", "an entry with spaces").problems).not.toEqual([]);
  });
});
