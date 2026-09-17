import { describe, expect, it } from "vitest";
import { cancelOutcomeLine, canSkipTarget, compensationOffer, secretReferences, timelineCSV } from "./Campaign";
import { bulkPrefill } from "./Bulk";

/* The compensation card is a decision read off the record and the
   catalogue: settled or not, a reverse or none, how many hosts changed,
   and whether the reverse runs as a campaign. The decision is a pure
   function so every branch is checked here without a screen. */

const settled = {
  state: "completed",
  rollback: "exact_restore",
  reverseAction: "file.rollback",
  reverseReady: true,
  changedHosts: 3,
};

describe("compensationOffer", () => {
  it("offers nothing while the campaign may still change hosts", () => {
    for (const state of ["planning", "awaiting_approval", "canary", "running", "paused", "manual_gate"]) {
      expect(compensationOffer({ ...settled, state })).toEqual({ kind: "not_settled" });
    }
  });

  it("offers a campaign on the changed hosts once the campaign settled, however it ended", () => {
    for (const state of ["completed", "failed", "canceled"]) {
      expect(compensationOffer({ ...settled, state })).toEqual({ kind: "campaign", reverse: "file.rollback", changed: 3 });
    }
  });

  it("states plainly that there is no way back for an operation without a reverse", () => {
    expect(compensationOffer({ ...settled, reverseAction: undefined, rollback: "none" })).toEqual({ kind: "no_reverse" });
    expect(compensationOffer({ ...settled, reverseAction: undefined, rollback: "best_effort" })).toEqual({ kind: "no_reverse" });
    // A reverse under a way back that cannot be planned along is no
    // offer either: the class says there is no guarantee of the state.
    expect(compensationOffer({ ...settled, rollback: "best_effort" })).toEqual({ kind: "no_reverse" });
    expect(compensationOffer({ ...settled, rollback: undefined })).toEqual({ kind: "no_reverse" });
  });

  it("accepts every class a compensation can be planned along", () => {
    for (const rollback of ["exact_restore", "compensating", "automatic_local"]) {
      expect(compensationOffer({ ...settled, rollback }).kind).toBe("campaign");
    }
  });

  it("says there is nothing to compensate when no host changed", () => {
    expect(compensationOffer({ ...settled, changedHosts: 0 })).toEqual({ kind: "nothing_changed", reverse: "file.rollback" });
    // A record from before the count existed carries no number; that is
    // not a changed fleet.
    expect(compensationOffer({ ...settled, changedHosts: undefined })).toEqual({ kind: "nothing_changed", reverse: "file.rollback" });
  });

  it("names the reverse that runs host by host instead of offering a campaign", () => {
    expect(compensationOffer({ ...settled, reverseReady: false })).toEqual({ kind: "host_by_host", reverse: "file.rollback", changed: 3 });
    expect(compensationOffer({ ...settled, reverseReady: undefined })).toEqual({ kind: "host_by_host", reverse: "file.rollback", changed: 3 });
  });
});

describe("bulkPrefill", () => {
  it("names the compensated campaign and the hosts of a single-host compensation in the address", () => {
    const address = bulkPrefill("file.rollback", "Rollback of x", { file: { path: "/etc/x" } }, "camp-1", ["host-a", "host-b"]);
    const params = new URLSearchParams(address.slice(address.indexOf("?") + 1));
    expect(address.startsWith("/bulk?")).toBe(true);
    expect(params.get("action")).toBe("file.rollback");
    expect(params.get("name")).toBe("Rollback of x");
    expect(params.get("compensates")).toBe("camp-1");
    expect(params.getAll("host_id")).toEqual(["host-a", "host-b"]);
    expect(JSON.parse(params.get("payload") ?? "")).toEqual({ file: { path: "/etc/x" } });
  });

  it("names no host when the compensation covers the whole campaign", () => {
    const address = bulkPrefill("file.rollback", "Rollback of x", {}, "camp-1");
    expect(address).not.toContain("host_id");
    expect(bulkPrefill("file.rollback", "x", {})).not.toContain("compensates");
  });
});

/* The order card points out the secrets a payload refers to by name; the
   value never travels, so the names are all there is to show. */
describe("secretReferences", () => {
  it("names every reference wherever it sits in the payload, with its pinned version", () => {
    const payload = {
      file: { path: "/etc/app.conf", content_secret: { name: "app-conf", version: 3 } },
      container: {
        env_secrets: { DB_PASSWORD: { name: "db-password" }, API_KEY: { name: "api-key", version: 0 } },
        registry: { password_secret: { name: "registry" } },
      },
    };
    expect(secretReferences(payload)).toEqual(["app-conf@3", "db-password", "api-key", "registry"]);
  });

  it("names nothing for a payload without a secret, and never a value", () => {
    expect(secretReferences({ unit: { unit: "cron.service" } })).toEqual([]);
    expect(secretReferences(undefined)).toEqual([]);
    expect(secretReferences({ file: { content: "plain text" } })).toEqual([]);
  });
});

/* The timeline export is built from the rows on screen: the same columns
   for every event, the host named where the target list knows it, and a
   cell that starts like a formula guarded the way the server guards its
   own export. */
describe("timelineCSV", () => {
  const targets = [{ campaign_id: "c", host_id: "host-a", hostname: "alpha", wave: 0, state: "failed" }];
  const entries = [
    { id: 1, aggregate_type: "campaign", event_type: "campaign.approved", occurred_at: "2026-09-15T10:00:00Z" },
    {
      id: 2, aggregate_type: "campaign_target", event_type: "target.failed", occurred_at: "2026-09-15T10:01:00Z",
      payload: { host_id: "host-a", wave: 0, error_code: "unit_not_found", message: "=SUM(1) \"quoted\"", job_id: "job-1" },
    },
  ];

  it("writes one row per event with the host name and a guarded detail", () => {
    const address = timelineCSV(entries, targets);
    expect(address.startsWith("data:text/csv;charset=utf-8,")).toBe(true);
    const lines = decodeURIComponent(address.slice(address.indexOf(",") + 1)).split("\n");
    expect(lines[0]).toBe("occurred_at,event_type,host,host_id,job_id,detail");
    expect(lines[1]).toBe('"2026-09-15T10:00:00Z","campaign.approved","","","","—"');
    expect(lines[2]).toBe('"2026-09-15T10:01:00Z","target.failed","alpha","host-a","job-1","wave 0 · unit_not_found · =SUM(1) ""quoted"""');
  });
});

/* The cancel protocol on a row: the host's answer in a sentence, or the
   wait for it, and nothing for a host nobody asked. The sentence carries
   the phase the host named, because the outcome alone does not say what
   the host was doing. */
describe("cancelOutcomeLine", () => {
  const t = (key: string, params?: Record<string, string | number>) =>
    key.replace(/\{(\w+)\}/g, (_, name: string) => String(params?.[name] ?? ""));

  it("says nothing for a host nobody asked to stop", () => {
    expect(cancelOutcomeLine({}, t)).toBe("");
    expect(cancelOutcomeLine({ cancel_phase: "started" }, t)).toBe("");
  });

  it("says the answer is awaited once the cancel was asked", () => {
    expect(cancelOutcomeLine({ cancel_requested_at: "2026-09-17T10:00:00Z" }, t)).toContain("waiting for the host");
  });

  it("names every outcome of the protocol with the phase the host was in", () => {
    const asked = { cancel_requested_at: "2026-09-17T10:00:00Z" };
    expect(cancelOutcomeLine({ ...asked, cancel_outcome: "not_started", cancel_phase: "awaiting_lock" }, t)).toContain("had not started");
    expect(cancelOutcomeLine({ ...asked, cancel_outcome: "interrupted", cancel_phase: "started" }, t)).toContain("interrupted the task while it was started");
    expect(cancelOutcomeLine({ ...asked, cancel_outcome: "not_interruptible", cancel_phase: "mutating" }, t)).toContain("runs the task to its end (mutating)");
    expect(cancelOutcomeLine({ ...asked, cancel_outcome: "already_done" }, t)).toContain("already finished");
  });
});

/* The skip is offered where the server allows it: a host waiting for its
   connection in a campaign that may still change hosts. */
describe("canSkipTarget", () => {
  it("offers the skip for a host waiting for its connection while the campaign runs", () => {
    for (const state of ["canary", "running", "paused", "manual_gate", "planned"]) {
      expect(canSkipTarget({ state: "queued_offline" }, state)).toBe(true);
    }
  });

  it("offers nothing for a host that is not waiting offline, or once the campaign settled", () => {
    for (const state of ["pending", "running", "dispatched", "skipped", "succeeded", "canceled"]) {
      expect(canSkipTarget({ state }, "running")).toBe(false);
    }
    for (const state of ["completed", "failed", "canceled", "expired"]) {
      expect(canSkipTarget({ state: "queued_offline" }, state)).toBe(false);
    }
  });
});
