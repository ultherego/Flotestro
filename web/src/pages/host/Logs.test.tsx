import { describe, expect, it } from "vitest";
import { jobWindow, utcStamp } from "./Logs";
import type { Attempt, Job } from "../../lib/types";

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
