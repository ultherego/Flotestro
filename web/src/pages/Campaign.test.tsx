import { describe, expect, it } from "vitest";
import { compensationOffer } from "./Campaign";
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
