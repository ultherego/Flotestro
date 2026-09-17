import { describe, expect, it } from "vitest";
import { bootFilterSupport, bootParam, findMatches, jobWindow, logFileName, splitMatches, utcStamp } from "./Logs";
import type { Attempt, Capabilities, Job } from "../../lib/types";

/* The window of a job is what the journal read is bounded to; it is
   computed from the record and the attempts, so it is tested on its own. */

const job = (extra: Partial<Job> = {}): Job => ({
  id: "j1", host_id: "h1", action_type: "unit.restart", state: "succeeded",
  payload: { unit: { unit: "cron.service" } }, payload_hash: "x", requires_approval: true,
  required_approvals: 1, collected_approvals: 1, created_by: "op",
  expires_at: "2026-09-15T11:00:00Z", created_at: "2026-09-15T10:00:00Z",
  finished_at: "2026-09-15T10:02:00Z", ...extra,
});

const attempt = (extra: Partial<Attempt> = {}): Attempt => ({
  id: "a1", attempt_number: 1, replayed: false, created_at: "2026-09-15T10:00:30Z",
  dispatched_at: "2026-09-15T10:01:00Z", finished_at: "2026-09-15T10:02:00Z", ...extra,
});

describe("utcStamp", () => {
  it("writes the moment the way journalctl takes it, in UTC", () => {
    expect(utcStamp(Date.UTC(2026, 8, 15, 10, 1, 0))).toBe("2026-09-15 10:01:00 UTC");
    expect(utcStamp(Date.UTC(2026, 0, 2, 3, 4, 5))).toBe("2026-01-02 03:04:05 UTC");
  });
});

describe("jobWindow", () => {
  it("runs from the delivery of the last attempt to the end of the job plus the margin", () => {
    const window = jobWindow(job(), [attempt({ id: "a0", dispatched_at: "2026-09-15T09:00:00Z" }), attempt()]);
    expect(window).toEqual({
      since: "2026-09-15 10:01:00 UTC", until: "2026-09-15 10:02:30 UTC", unit: "cron.service",
    });
  });

  it("has no window before the delivery, and none without a job", () => {
    expect(jobWindow(job(), [])).toBeNull();
    expect(jobWindow(job(), undefined)).toBeNull();
    expect(jobWindow(undefined, [attempt()])).toBeNull();
  });

  it("bounds a running job by now", () => {
    const now = Date.UTC(2026, 8, 15, 10, 5, 0);
    const window = jobWindow(job({ state: "running", finished_at: undefined }), [attempt({ finished_at: undefined })], now);
    expect(window?.until).toBe("2026-09-15 10:05:30 UTC");
  });

  it("names no unit for a payload without one", () => {
    const window = jobWindow(job({ action_type: "packages.upgrade", payload: { package_upgrade: {} } }), [attempt()]);
    expect(window?.unit).toBeUndefined();
    const read = jobWindow(job({ action_type: "journal.read", payload: { journal: { unit: "sshd.service", lines: 10 } } }), [attempt()]);
    expect(read?.unit).toBe("sshd.service");
  });
});

/* The search runs over the lines on screen; the helpers decide which
   lines match and how a line is cut for the marks, so they are tested
   without a screen. */

describe("findMatches", () => {
  const lines = ["Sep 15 10:00:01 web01 sshd[12]: Accepted publickey", "Sep 15 10:00:02 web01 cron[13]: (root) CMD", "sshd: error"];

  it("lists the matching lines by index, case-insensitively", () => {
    expect(findMatches(lines, "SSHD")).toEqual([0, 2]);
    expect(findMatches(lines, "cron")).toEqual([1]);
    expect(findMatches(lines, "nothing")).toEqual([]);
  });

  it("matches nothing for a blank search and for no lines", () => {
    expect(findMatches(lines, "")).toEqual([]);
    expect(findMatches(lines, "   ")).toEqual([]);
    expect(findMatches(undefined, "sshd")).toEqual([]);
  });
});

describe("splitMatches", () => {
  it("cuts a line into the pieces to mark and the pieces to leave, keeping the line's case", () => {
    expect(splitMatches("Error: disk error", "error")).toEqual([
      { text: "Error", hit: true }, { text: ": disk ", hit: false }, { text: "error", hit: true },
    ]);
    expect(splitMatches("abcabc", "bc")).toEqual([
      { text: "a", hit: false }, { text: "bc", hit: true }, { text: "a", hit: false }, { text: "bc", hit: true },
    ]);
  });

  it("leaves a line without a match, and a blank search, as one piece", () => {
    expect(splitMatches("nothing here", "sshd")).toEqual([{ text: "nothing here", hit: false }]);
    expect(splitMatches("nothing here", "")).toEqual([{ text: "nothing here", hit: false }]);
    expect(splitMatches("", "x")).toEqual([{ text: "", hit: false }]);
  });
});

describe("logFileName", () => {
  const at = Date.UTC(2026, 8, 15, 10, 1, 0);

  it("names the file by the host, the unit and the moment", () => {
    expect(logFileName("web01", "cron.service", at)).toBe("web01-cron.service-20260915100100.log");
  });

  it("turns a path into one file name and names an unbounded journal read", () => {
    expect(logFileName("web01", "/var/log/syslog", at)).toBe("web01-var-log-syslog-20260915100100.log");
    expect(logFileName("web01", "", at)).toBe("web01-all-20260915100100.log");
  });
});

/* A read by boot is offered only where the agent applies the filter: an
   older agent is silent about the feature and would answer with every
   boot, so silence reads as "cannot", with the reason spelled out. */

const t = (text: string) => text;
const journald = (features?: Record<string, boolean>, available = true): Capabilities => [
  { name: "journald", version: 1, available, read_only: false, features },
];

describe("bootFilterSupport", () => {
  it("is supported only when the journald adapter names the feature", () => {
    expect(bootFilterSupport(journald({ boot_filter: true }), t)).toEqual({ supported: true });
  });

  it("names the reason for an old agent, an adapter without the feature and a host without journald", () => {
    const silent = bootFilterSupport(journald(), t);
    expect(silent.supported).toBe(false);
    expect(silent.reason).toContain("cannot filter the journal by boot");
    expect(bootFilterSupport(journald({ boot_filter: false }), t).supported).toBe(false);
    expect(bootFilterSupport(journald({ boot_filter: true }, false), t).reason).toContain("no journald adapter");
    expect(bootFilterSupport([], t).supported).toBe(false);
    expect(bootFilterSupport(undefined, t).supported).toBe(false);
  });
});

describe("bootParam", () => {
  it("takes the kernel's dashed form and the journal's bare one, and nothing else", () => {
    expect(bootParam("2cd11312-4365-4fe6-b49e-e4d704ea2c5a")).toBe("2cd1131243654fe6b49ee4d704ea2c5a");
    expect(bootParam("2CD1131243654FE6B49EE4D704EA2C5A")).toBe("2cd1131243654fe6b49ee4d704ea2c5a");
    expect(bootParam("yesterday")).toBe("");
    expect(bootParam("")).toBe("");
    expect(bootParam(null)).toBe("");
  });
});
