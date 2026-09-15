import { describe, expect, it } from "vitest";
import { complianceShares, policyStanding, ruleSummary, verdictTone } from "./Policies";
import { emptyRule, intervalMinutes, pruneRule, rulesFromExpression, rulesFromText, selectorOf } from "./Policy";
import { countVerdicts, groupByPolicy } from "./host/Policies";
import type { PolicyResult } from "../lib/types";

/* The helpers read the verdicts and the documents the way the server
   writes them; the pages only draw what they say, so they are tested on
   their own, without a screen. */

describe("verdictTone", () => {
  it("colours a drift as a warning and an error as red: unknown is not compliant", () => {
    expect(verdictTone("compliant")).toBe("ok");
    expect(verdictTone("drift")).toBe("warn");
    expect(verdictTone("error")).toBe("error");
    expect(verdictTone("not_applicable")).toBe("unknown");
  });
});

describe("complianceShares", () => {
  it("gives one segment per verdict with a count, in the fixed order", () => {
    const shares = complianceShares({ compliant: 3, drift: 1, error: 0, not_applicable: 0 });
    expect(shares.map((segment) => segment.verdict)).toEqual(["compliant", "drift"]);
    expect(shares[0].share).toBeCloseTo(0.75);
    expect(shares[1].share).toBeCloseTo(0.25);
  });

  it("draws nothing for a policy nobody evaluated - an empty bar is not a green one", () => {
    expect(complianceShares(undefined)).toEqual([]);
    expect(complianceShares({ compliant: 0, drift: 0, error: 0, not_applicable: 0 })).toEqual([]);
  });
});

describe("ruleSummary", () => {
  it("puts every kind in the server's words", () => {
    expect(ruleSummary({ kind: "package_installed", name: "cron" })).toBe("package cron installed");
    expect(ruleSummary({ kind: "package_absent", name: "telnetd" })).toBe("package telnetd absent");
    expect(ruleSummary({ kind: "unit_state", unit: "cron.service", enabled: true, active: true })).toBe("unit cron.service enabled and active");
    expect(ruleSummary({ kind: "unit_state", unit: "cron.service", active: false })).toBe("unit cron.service inactive");
    expect(ruleSummary({ kind: "file_content", path: "/etc/motd", sha256: "abcdef0123456789" })).toBe("file /etc/motd at abcdef012345");
    expect(ruleSummary({ kind: "sysctl", key: "net.ipv4.ip_forward", value: "0" })).toBe("sysctl net.ipv4.ip_forward = 0");
    expect(ruleSummary({ kind: "ssh_key_present", user: "deploy", fingerprint: "SHA256:x" })).toBe("key SHA256:x on deploy");
  });

  it("keeps an unknown kind by its name rather than dropping it", () => {
    expect(ruleSummary({ kind: "timer_present" })).toBe("timer_present");
  });
});

describe("policyStanding", () => {
  it("tells a never-published draft from a draft on top of a version", () => {
    expect(policyStanding({ version: 0, draft: false, enabled: true })).toBe("unpublished");
    expect(policyStanding({ version: 2, draft: true, enabled: true })).toBe("draft");
    expect(policyStanding({ version: 2, draft: false, enabled: true })).toBe("published");
    expect(policyStanding({ version: 2, draft: true, enabled: false })).toBe("disabled");
  });
});

describe("the rule editor", () => {
  it("starts a rule with the fields of its kind only", () => {
    expect(emptyRule("sysctl")).toEqual({ kind: "sysctl", key: "", value: "" });
    expect(emptyRule("unit_state")).toEqual({ kind: "unit_state", unit: "", enabled: true, active: true });
  });

  it("prunes the fields of another kind when the kind changes", () => {
    expect(pruneRule({ kind: "sysctl", key: "k", value: "1", name: "left over" })).toEqual({ kind: "sysctl", key: "k", value: "1" });
    expect(pruneRule({ kind: "unit_state", unit: "cron.service", enabled: true })).toEqual({ kind: "unit_state", unit: "cron.service", enabled: true });
    expect(pruneRule({ kind: "ssh_key_present", user: "u", fingerprint: "SHA256:f", public_key: "ssh-ed25519 AAAA" }))
      .toEqual({ kind: "ssh_key_present", user: "u", fingerprint: "SHA256:f", public_key: "ssh-ed25519 AAAA" });
  });

  it("reads the JSON fallback and refuses what is not a list of rules", () => {
    expect(rulesFromText('[{"kind":"sysctl","key":"k","value":"1"}]').rules).toEqual([{ kind: "sysctl", key: "k", value: "1" }]);
    expect(rulesFromText('{"kind":"sysctl"}').error).toBeTruthy();
    expect(rulesFromText('[{"key":"k"}]').error).toBeTruthy();
    expect(rulesFromText("not json").error).toBeTruthy();
  });

  it("shows the interval in minutes, never below one", () => {
    expect(intervalMinutes(900)).toBe(15);
    expect(intervalMinutes(10)).toBe(1);
  });
});

describe("rulesFromExpression", () => {
  it("takes a flat expression apart into the rows of the builder", () => {
    expect(rulesFromExpression({ all: [{ tag: "role=web" }, { not: { site: "lab" } }] })).toEqual({
      rules: [{ field: "tag", value: "role=web", negated: false }, { field: "site", value: "lab", negated: true }],
      combine: "all",
    });
    expect(rulesFromExpression({ os_family: "debian" })).toEqual({ rules: [{ field: "os_family", value: "debian", negated: false }], combine: "all" });
    expect(rulesFromExpression(null)?.rules).toHaveLength(1);
  });

  it("refuses a nested expression, which the builder would flatten", () => {
    expect(rulesFromExpression({ all: [{ any: [{ tag: "a" }, { tag: "b" }] }, { site: "lab" }] })).toBeNull();
  });
});

describe("selectorOf", () => {
  it("sends the flat fields, the built expression or the JSON as typed", () => {
    expect(selectorOf({ targetMode: "filters", site: " lab ", environment: "", osFamily: "debian", selectorRules: [], combine: "all", expressionText: "" }).selector)
      .toEqual({ site: "lab", environment: undefined, os_family: "debian" });
    expect(selectorOf({ targetMode: "expression", site: "", environment: "", osFamily: "", selectorRules: [{ field: "tag", value: "role=web", negated: false }], combine: "all", expressionText: "" }).selector)
      .toEqual({ expression: { tag: "role=web" } });
    expect(selectorOf({ targetMode: "json", site: "", environment: "", osFamily: "", selectorRules: [], combine: "all", expressionText: '{"group":"web"}' }).selector)
      .toEqual({ expression: { group: "web" } });
    expect(selectorOf({ targetMode: "json", site: "", environment: "", osFamily: "", selectorRules: [], combine: "all", expressionText: "{" }).error).toBeTruthy();
  });
});

describe("the host page", () => {
  const result = (policy: string, index: number, verdict: PolicyResult["verdict"]): PolicyResult => ({
    policy_id: policy, policy_name: policy.toUpperCase(), host_id: "h", rule_index: index, version: 1, verdict, evaluated_at: "2026-09-15T12:00:00Z",
  });

  it("groups the verdicts by policy in the order given", () => {
    const groups = groupByPolicy([result("a", 0, "compliant"), result("a", 1, "drift"), result("b", 0, "error")]);
    expect(groups.map((group) => [group.policyID, group.name, group.results.length])).toEqual([["a", "A", 2], ["b", "B", 1]]);
  });

  it("counts every verdict, zero included", () => {
    expect(countVerdicts([result("a", 0, "compliant"), result("a", 1, "drift")])).toEqual({ compliant: 1, drift: 1, error: 0, not_applicable: 0 });
    expect(countVerdicts([])).toEqual({ compliant: 0, drift: 0, error: 0, not_applicable: 0 });
  });
});
