import { describe, expect, it } from "vitest";
import {
  approvalForced, campaignBody, clearDraft, DRAFT_KEY, emptyOrder, jobTimeoutValid, loadDraft, MIN_REASON,
  orderTargets, parseUnits, prefilledOrder, reasonValid, REVERSE_OPERATION, reversePayload, saveDraft,
  windowInstant, windowProblem,
} from "./Bulk";

/* The wizard's decisions - what counts as a reason, whether the window
   holds, what the order sends, what a reload gets back - are pure
   functions of the order, so every branch is checked here without a
   screen. */

/** A storage in memory with the shape the wizard reads and writes. */
function memoryStorage(initial: Record<string, string> = {}): Storage {
  const items = new Map(Object.entries(initial));
  return {
    get length() { return items.size; },
    clear: () => items.clear(),
    getItem: (key) => items.get(key) ?? null,
    key: (index) => [...items.keys()][index] ?? null,
    removeItem: (key) => { items.delete(key); },
    setItem: (key, value) => { items.set(key, String(value)); },
  };
}

/** A storage that refuses every access, as a private window may. */
function brokenStorage(): Storage {
  const refuse = () => { throw new Error("storage is blocked"); };
  return { length: 0, clear: refuse, getItem: refuse, key: refuse, removeItem: refuse, setItem: refuse };
}

describe("reasonValid", () => {
  it("counts the characters after trimming", () => {
    expect(reasonValid("CHG-1234 kernel")).toBe(true);
    expect(reasonValid("short")).toBe(false);
    expect(reasonValid("       a      ")).toBe(false);
    expect(reasonValid("x".repeat(MIN_REASON))).toBe(true);
    expect(reasonValid("x".repeat(MIN_REASON - 1))).toBe(false);
  });
});

describe("windowProblem", () => {
  const now = new Date("2026-09-15T12:00:00");

  it("accepts an empty window and one that lies ahead", () => {
    expect(windowProblem("", "", now)).toBeNull();
    expect(windowProblem("2026-09-15T22:00", "2026-09-16T02:00", now)).toBeNull();
    expect(windowProblem("", "2026-09-16T02:00", now)).toBeNull();
    expect(windowProblem("2026-09-15T22:00", "", now)).toBeNull();
  });

  it("refuses a window that starts or ends in the past", () => {
    expect(windowProblem("2026-09-15T11:00", "2026-09-16T02:00", now)).toBe("start_past");
    expect(windowProblem("", "2026-09-15T11:00", now)).toBe("end_past");
    // The very moment is not ahead either.
    expect(windowProblem("2026-09-15T12:00", "", now)).toBe("start_past");
  });

  it("refuses an end before the start, and one equal to it", () => {
    expect(windowProblem("2026-09-16T02:00", "2026-09-15T22:00", now)).toBe("end_before_start");
    expect(windowProblem("2026-09-16T02:00", "2026-09-16T02:00", now)).toBe("end_before_start");
  });

  it("names a value that is not a date", () => {
    expect(windowProblem("soon", "", now)).toBe("start_invalid");
    expect(windowProblem("", "later", now)).toBe("end_invalid");
  });
});

describe("windowInstant", () => {
  it("turns a local value into an RFC 3339 instant and leaves an empty one out", () => {
    expect(windowInstant("")).toBeUndefined();
    expect(windowInstant("not a date")).toBeUndefined();
    const instant = windowInstant("2026-09-15T22:30");
    expect(instant).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/);
    expect(new Date(instant ?? "").getTime()).toBe(new Date("2026-09-15T22:30").getTime());
  });
});

describe("parseUnits", () => {
  it("reads one unit per line or comma, trimmed, without repeats", () => {
    expect(parseUnits("nginx.service\n php-fpm.service ,nginx.service;cron.service\n\n")).toEqual([
      "nginx.service", "php-fpm.service", "cron.service",
    ]);
    expect(parseUnits("")).toEqual([]);
    expect(parseUnits(" , \n")).toEqual([]);
  });
});

describe("jobTimeoutValid", () => {
  it("takes zero as the default and bounds everything else", () => {
    expect(jobTimeoutValid(0)).toBe(true);
    expect(jobTimeoutValid(30)).toBe(true);
    expect(jobTimeoutValid(86400)).toBe(true);
    expect(jobTimeoutValid(29)).toBe(false);
    expect(jobTimeoutValid(86401)).toBe(false);
    expect(jobTimeoutValid(-5)).toBe(false);
    expect(jobTimeoutValid(90.5)).toBe(false);
  });
});

describe("orderTargets", () => {
  it("counts the hosts the address named before anything the preview says", () => {
    expect(orderTargets({ hostIDs: ["a", "b"] }, { count: 40, eligible: 30 })).toBe(2);
    expect(orderTargets({ hostIDs: ["a"] }, undefined)).toBe(1);
  });

  it("falls back to the eligible count, then the matched count, then zero", () => {
    expect(orderTargets({ hostIDs: [] }, { count: 40, eligible: 30 })).toBe(30);
    expect(orderTargets({ hostIDs: [] }, { count: 40 })).toBe(40);
    expect(orderTargets({ hostIDs: [] }, undefined)).toBe(0);
  });
});

describe("approvalForced", () => {
  it("forces the gate for the classes that can cut a host off or destroy it", () => {
    expect(approvalForced("critical")).toBe(true);
    expect(approvalForced("destructive")).toBe(true);
    expect(approvalForced("high")).toBe(false);
    expect(approvalForced("low")).toBe(false);
    expect(approvalForced(undefined)).toBe(false);
  });
});

describe("campaignBody", () => {
  const order = {
    ...emptyOrder(),
    name: "Restart cron",
    action: "unit.restart",
    unit: "cron.service",
    reason: "  CHG-1234: cron leaks memory  ",
  };

  it("sends the operator's reason, trimmed, instead of the operation name", () => {
    const body = campaignBody(order, "high");
    expect(body.reason).toBe("CHG-1234: cron leaks memory");
    expect(body.name).toBe("Restart cron");
    expect(body.payload).toEqual({ unit: { unit: "cron.service" } });
  });

  it("leaves the window, the units and the timeout out when the order says nothing about them", () => {
    const body = campaignBody(order, "high");
    expect(body.maintenance_start).toBeUndefined();
    expect(body.maintenance_end).toBeUndefined();
    expect(body.health_check_units).toBeUndefined();
    expect(body.job_timeout_seconds).toBeUndefined();
    expect(body.reboot_timeout_seconds).toBeUndefined();
    expect(body.requires_approval).toBe(true);
  });

  it("sends the window as instants, the units as a list and the timeout as given", () => {
    const body = campaignBody({
      ...order,
      maintenanceStart: "2026-09-15T22:00",
      maintenanceEnd: "2026-09-16T02:00",
      healthCheckUnits: "cron.service\nnginx.service",
      jobTimeoutSeconds: 600,
    }, "high");
    expect(body.maintenance_start).toBe(new Date("2026-09-15T22:00").toISOString());
    expect(body.maintenance_end).toBe(new Date("2026-09-16T02:00").toISOString());
    expect(body.health_check_units).toEqual(["cron.service", "nginx.service"]);
    expect(body.job_timeout_seconds).toBe(600);
  });

  it("keeps the approval gate on a critical operation whatever the box says", () => {
    expect(campaignBody({ ...order, requiresApproval: false }, "critical").requires_approval).toBe(true);
    expect(campaignBody({ ...order, requiresApproval: false }, "destructive").requires_approval).toBe(true);
    expect(campaignBody({ ...order, requiresApproval: false }, "high").requires_approval).toBe(false);
  });

  it("sends the named hosts instead of the filters and the expression", () => {
    const body = campaignBody({ ...order, hostIDs: ["host-a"], site: "warsaw" }, "high");
    const selector = body.selector as Record<string, unknown>;
    expect(selector.host_ids).toEqual(["host-a"]);
    expect(selector.expression).toBeUndefined();
    expect(selector.site).toBe("warsaw");
  });

  it("does not gate on a canary of zero", () => {
    expect(campaignBody({ ...order, manualGate: true, canary: 0 }, "high").manual_gate).toBe(false);
    expect(campaignBody({ ...order, manualGate: true, canary: 2 }, "high").manual_gate).toBe(true);
  });
});

describe("the draft in the browser", () => {
  it("comes back as it was saved, on the step it was on", () => {
    const storage = memoryStorage();
    const order = { ...emptyOrder(), name: "Restart cron", action: "unit.restart", reason: "CHG-1 cron" };
    saveDraft(storage, { order, step: 3 });
    expect(loadDraft(storage)).toEqual({ order, step: 3 });
  });

  it("is gone once cleared, and absent where nothing was saved", () => {
    const storage = memoryStorage();
    saveDraft(storage, { order: emptyOrder(), step: 1 });
    clearDraft(storage);
    expect(storage.getItem(DRAFT_KEY)).toBeNull();
    expect(loadDraft(storage)).toBeNull();
    expect(loadDraft(memoryStorage())).toBeNull();
    expect(loadDraft(null)).toBeNull();
  });

  it("never reopens past the step where the campaign came into being", () => {
    const storage = memoryStorage();
    saveDraft(storage, { order: emptyOrder(), step: 7 });
    expect(loadDraft(storage)?.step).toBe(5);
    saveDraft(storage, { order: emptyOrder(), step: -2 });
    expect(loadDraft(storage)?.step).toBe(0);
  });

  it("lays an older draft over the defaults, so a field it does not know starts from its default", () => {
    const storage = memoryStorage({
      [DRAFT_KEY]: JSON.stringify({ order: { name: "Old draft", canary: 3 }, step: 2 }),
    });
    const draft = loadDraft(storage);
    expect(draft?.order.name).toBe("Old draft");
    expect(draft?.order.canary).toBe(3);
    expect(draft?.order.reason).toBe("");
    expect(draft?.order.requiresApproval).toBe(true);
    expect(draft?.order.rules).toEqual(emptyOrder().rules);
  });

  it("ignores a draft that is not an order", () => {
    expect(loadDraft(memoryStorage({ [DRAFT_KEY]: "not json" }))).toBeNull();
    expect(loadDraft(memoryStorage({ [DRAFT_KEY]: JSON.stringify({ step: 2 }) }))).toBeNull();
    expect(loadDraft(memoryStorage({ [DRAFT_KEY]: JSON.stringify("order") }))).toBeNull();
  });

  it("keeps working where the storage refuses", () => {
    const storage = brokenStorage();
    expect(() => saveDraft(storage, { order: emptyOrder(), step: 1 })).not.toThrow();
    expect(() => clearDraft(storage)).not.toThrow();
    expect(loadDraft(storage)).toBeNull();
  });
});

describe("prefilledOrder", () => {
  it("reads the order another screen handed over, the reason included", () => {
    const params = new URLSearchParams(
      "action=file.rollback&name=Rollback+of+x&payload=%7B%7D&compensates=camp-1&host_id=a&host_id=b&reason=CHG-9+undo+the+bad+config",
    );
    const draft = prefilledOrder(params);
    expect(draft?.step).toBe(0);
    expect(draft?.order.action).toBe("file.rollback");
    expect(draft?.order.name).toBe("Rollback of x");
    expect(draft?.order.compensates).toBe("camp-1");
    expect(draft?.order.hostIDs).toEqual(["a", "b"]);
    expect(draft?.order.reason).toBe("CHG-9 undo the bad config");
  });

  it("is nothing for an address without an order, so the draft may reopen", () => {
    expect(prefilledOrder(new URLSearchParams(""))).toBeNull();
    expect(prefilledOrder(new URLSearchParams("tab=x"))).toBeNull();
    expect(prefilledOrder(new URLSearchParams("reason=CHG-1+because"))?.order.reason).toBe("CHG-1 because");
  });
});

describe("REVERSE_OPERATION", () => {
  it("offers a rollback campaign only where one payload can name the reverse on every host", () => {
    expect(REVERSE_OPERATION["file.ensure"]).toBe("file.rollback");
    // The network and firewall rollbacks name a plan the host minted
    // under its own identifier; one payload cannot name them all.
    expect(REVERSE_OPERATION["network.profile.apply"]).toBeUndefined();
    expect(REVERSE_OPERATION["firewall.rule.ensure"]).toBeUndefined();
    expect(reversePayload("network.profile.apply", { network: { interface: "eth0" } })).toEqual({});
    expect(reversePayload("file.ensure", { file: { path: "/etc/x" } })).toEqual({ file: { path: "/etc/x", version_sha256: "" } });
  });
});
