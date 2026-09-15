import { describe, expect, it } from "vitest";
import { buildExpression, bulkAddress, filterGroups, readsAddress, rulesOf, sortGroups, usageSentence } from "./Groups";

/* The list's search and order, the addresses the group page hands to the
   wizard and the read form, and the way a saved selector is taken apart
   into the builder's rows are all pure functions, so every branch is
   checked here without a screen. */

const groups = [
  { name: "databases", description: "the primaries", member_count: 4 },
  { name: "caches", description: "", member_count: 12 },
  { name: "edge", description: "public entry points", member_count: undefined },
  { name: "archive", description: "old databases", member_count: 0 },
];

describe("filterGroups", () => {
  it("keeps everything for an empty search", () => {
    expect(filterGroups(groups, "  ")).toHaveLength(4);
  });

  it("finds a group by name or description, case aside", () => {
    expect(filterGroups(groups, "DATA").map((group) => group.name)).toEqual(["databases", "archive"]);
    expect(filterGroups(groups, "entry").map((group) => group.name)).toEqual(["edge"]);
    expect(filterGroups(groups, "nobody")).toEqual([]);
  });
});

describe("sortGroups", () => {
  it("orders by name", () => {
    expect(sortGroups(groups, "name").map((group) => group.name)).toEqual(["archive", "caches", "databases", "edge"]);
  });

  it("orders by size with the biggest first and an unknown size last, not as zero", () => {
    expect(sortGroups(groups, "size").map((group) => group.name)).toEqual(["caches", "databases", "archive", "edge"]);
  });

  it("leaves the given list alone", () => {
    const before = groups.map((group) => group.name);
    sortGroups(groups, "size");
    expect(groups.map((group) => group.name)).toEqual(before);
  });
});

describe("bulkAddress", () => {
  it("names the group as the target of an order named after it", () => {
    const address = bulkAddress("databases-gold");
    const params = new URLSearchParams(address.slice(address.indexOf("?") + 1));
    expect(address.startsWith("/bulk?")).toBe(true);
    expect(params.get("group")).toBe("databases-gold");
    expect(params.get("name")).toBe("databases-gold");
    expect(params.getAll("host_id")).toEqual([]);
  });

  it("names the ticked hosts alone, because an expression would outvote them", () => {
    const address = bulkAddress("databases-gold", ["host-a", "host-b"]);
    const params = new URLSearchParams(address.slice(address.indexOf("?") + 1));
    expect(params.get("group")).toBeNull();
    expect(params.getAll("host_id")).toEqual(["host-a", "host-b"]);
    expect(params.get("name")).toBe("databases-gold");
  });
});

describe("readsAddress", () => {
  it("opens the read form with the group as the selector", () => {
    const params = new URLSearchParams(readsAddress("edge").slice("/reads?".length));
    expect(params.get("action")).toBe("journal.read");
    expect(params.get("group")).toBe("edge");
  });
});

describe("rulesOf", () => {
  it("takes a flat selector apart into the rows that built it", () => {
    const rules = [
      { field: "tag" as const, value: "role=db", negated: false },
      { field: "site" as const, value: "lab", negated: true },
    ];
    for (const combine of ["all", "any"] as const) {
      const expression = buildExpression(rules, combine);
      expect(rulesOf(expression)).toEqual({ rules, combine, exact: true });
    }
  });

  it("reads a single leaf as one row joined by all", () => {
    expect(rulesOf({ group: "databases" })).toEqual({
      rules: [{ field: "group", value: "databases", negated: false }], combine: "all", exact: true,
    });
    expect(rulesOf({ not: { os_family: "debian" } })).toEqual({
      rules: [{ field: "os_family", value: "debian", negated: true }], combine: "all", exact: true,
    });
  });

  it("says when the selector is deeper than rows can say", () => {
    const nested = rulesOf({ all: [{ tag: "role=db" }, { any: [{ site: "a" }, { site: "b" }] }] });
    expect(nested.exact).toBe(false);
    expect(nested.rules).toEqual([{ field: "tag", value: "role=db", negated: false }]);
    // A fact the builder does not offer is not a row either.
    expect(rulesOf({ machine_id: "x" } as unknown as Parameters<typeof rulesOf>[0]).exact).toBe(false);
    // A group with no selector starts from one empty row.
    expect(rulesOf(undefined)).toEqual({ rules: [{ field: "tag", value: "", negated: false }], combine: "all", exact: true });
  });
});

describe("usageSentence", () => {
  const t = (key: string, vars?: Record<string, string | number>) =>
    key.replace(/\{(\w+)\}/g, (_, name: string) => String(vars?.[name] ?? ""));

  it("says nothing when nothing names the group", () => {
    expect(usageSentence(undefined, t)).toBe("");
    expect(usageSentence({ campaigns: [], policies: [] }, t)).toBe("");
  });

  it("names every campaign and policy in one sentence", () => {
    const sentence = usageSentence({
      campaigns: [{ id: "c1", name: "kernel wave", state: "completed" }],
      policies: [{ id: "p1", name: "ssh baseline", state: "enabled" }],
    }, t);
    expect(sentence).toBe("Its selector is named by: campaign kernel wave, policy ssh baseline. They will stop resolving.");
  });
});
