import { describe, expect, it } from "vitest";
import { budgetTone, classTotals, describeBudgetKey, fairShare, holderLink, saturated, waiting } from "./Budgets";

/* The helpers read the keys and the numbers the way the store writes
   them; the page only draws what they say, so they are tested on their
   own, without a screen. */

describe("describeBudgetKey", () => {
  it("reads a fleet-wide key as global with its resource", () => {
    expect(describeBudgetKey("global:mutations")).toEqual({ kind: "global", scope: "", resource: "mutations", pattern: false });
    expect(describeBudgetKey("global:reads")).toEqual({ kind: "global", scope: "", resource: "reads", pattern: false });
  });

  it("reads a site key as the site and the family of resource", () => {
    expect(describeBudgetKey("site:warsaw:packages")).toEqual({ kind: "site", scope: "warsaw", resource: "packages", pattern: false });
    expect(describeBudgetKey("site:warsaw:reboot")).toEqual({ kind: "site", scope: "warsaw", resource: "reboot", pattern: false });
  });

  it("marks an asterisk in the scope as the default policy of the family", () => {
    expect(describeBudgetKey("site:*:packages")).toEqual({ kind: "site", scope: "*", resource: "packages", pattern: true });
    expect(describeBudgetKey("backend:*:backup")).toEqual({ kind: "backend", scope: "*", resource: "backup", pattern: true });
  });

  it("reads a backend key with the repository the store flattened into it", () => {
    expect(describeBudgetKey("backend:s3_https_//bucket/repo:backup")).toEqual({
      kind: "backend", scope: "s3_https_//bucket/repo", resource: "backup", pattern: false,
    });
  });

  it("keeps a key of an unknown shape whole rather than dropping it", () => {
    expect(describeBudgetKey("gateway:eu:west:uplink")).toEqual({ kind: "other", scope: "", resource: "gateway:eu:west:uplink", pattern: false });
    expect(describeBudgetKey("odd")).toEqual({ kind: "other", scope: "", resource: "odd", pattern: false });
    expect(describeBudgetKey("global:")).toEqual({ kind: "global", scope: "", resource: "", pattern: false });
  });
});

describe("fairShare", () => {
  it("splits the capacity between the claimants the way the store does", () => {
    expect(fairShare(10, 3)).toBe(3);
    expect(fairShare(10, 1)).toBe(10);
    expect(fairShare(10, 10)).toBe(1);
  });

  it("never goes below one token, and nobody asking means one claimant", () => {
    expect(fairShare(3, 7)).toBe(1);
    expect(fairShare(10, 0)).toBe(10);
  });
});

describe("saturated", () => {
  it("is full at the capacity, not one below it", () => {
    expect(saturated({ used: 5, capacity: 5 })).toBe(true);
    expect(saturated({ used: 4, capacity: 5 })).toBe(false);
  });

  it("is never full without a capacity to fill", () => {
    expect(saturated({ used: 0, capacity: 0 })).toBe(false);
  });
});

describe("budgetTone", () => {
  it("is an error when nothing is free", () => {
    expect(budgetTone({ used: 8, capacity: 8, waiting_jobs: 0 })).toBe("error");
  });

  it("warns when jobs wait or the budget is nearly full", () => {
    expect(budgetTone({ used: 2, capacity: 8, waiting_jobs: 1 })).toBe("warn");
    expect(budgetTone({ used: 6, capacity: 8, waiting_jobs: 0 })).toBe("warn");
  });

  it("is fine with room and nobody waiting", () => {
    expect(budgetTone({ used: 5, capacity: 8, waiting_jobs: 0 })).toBe("ok");
    expect(budgetTone({ used: 0, capacity: 8, waiting_jobs: 0 })).toBe("ok");
  });

  it("warns for campaign hosts waiting the way it does for jobs", () => {
    expect(budgetTone({ used: 2, capacity: 8, waiting_jobs: 0, waiting_targets: 3 })).toBe("warn");
    expect(budgetTone({ used: 2, capacity: 8, waiting_jobs: 0, waiting_targets: 0 })).toBe("ok");
  });
});

describe("waiting", () => {
  it("adds the queued jobs and the campaign hosts", () => {
    expect(waiting({ waiting_jobs: 2, waiting_targets: 3 })).toBe(5);
    expect(waiting({ waiting_jobs: 0, waiting_targets: 0 })).toBe(0);
  });
});

describe("classTotals", () => {
  it("adds the tokens of every budget per class, the known classes always and in order", () => {
    const totals = classTotals([
      { by_class: { maintenance: 3, interactive: 1 } },
      { by_class: { maintenance: 2 } },
      { by_class: {} },
    ]);
    expect(totals).toEqual([
      { name: "incident", tokens: 0 },
      { name: "interactive", tokens: 1 },
      { name: "maintenance", tokens: 5 },
      { name: "background", tokens: 0 },
    ]);
  });

  it("shows a class the API named on its own only when it holds something", () => {
    expect(classTotals([{ by_class: { unknown: 2, zeta: 1, alpha: 1 } }]).slice(4)).toEqual([
      { name: "alpha", tokens: 1 },
      { name: "unknown", tokens: 2 },
      { name: "zeta", tokens: 1 },
    ]);
    expect(classTotals([{ by_class: { unknown: 0 } }])).toHaveLength(4);
  });

  it("reads a row of the first shape, without the classes, as holding nothing", () => {
    expect(classTotals([{} as { by_class: Record<string, number> }])).toEqual([
      { name: "incident", tokens: 0 },
      { name: "interactive", tokens: 0 },
      { name: "maintenance", tokens: 0 },
      { name: "background", tokens: 0 },
    ]);
  });
});

describe("holderLink", () => {
  it("leads a campaign host to its campaign", () => {
    expect(holderLink({ owner: "5a1c3e2f-0000-0000-0000-000000000000", claimant: "campaign:c1" }))
      .toEqual({ to: "/campaigns/c1", label: "campaign" });
  });

  it("leads a job to the jobs of the author who ordered it", () => {
    expect(holderLink({ owner: "job:j1", claimant: "jobs:alice@example.org" }))
      .toEqual({ to: "/jobs?actor=alice%40example.org", label: "job" });
    // A job whose claimant has another shape still leads to the list.
    expect(holderLink({ owner: "job:j1", claimant: "somebody" })).toEqual({ to: "/jobs", label: "job" });
  });

  it("leads a fan-out to its read", () => {
    expect(holderLink({ owner: "fanout:f1", claimant: "reads:alice" })).toEqual({ to: "/reads/f1", label: "read" });
  });

  it("leads a holder of an unknown shape nowhere rather than somewhere wrong", () => {
    expect(holderLink({ owner: "integration-test:job-budget", claimant: "integration-test" })).toBeNull();
  });
});
