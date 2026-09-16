import { describe, expect, it } from "vitest";
import { firstUndone, mayAct, pageName, readableDetail, stepTone } from "./Setup";

/* The first-run page decides a few things without the server: which step
   is highlighted, what colour a state gets, who may press a test button
   and what the button beside a step is called. All of it is pure and is
   checked here without a screen. */

describe("firstUndone", () => {
  it("highlights the first step that is undone, past the done, warning and optional ones", () => {
    expect(firstUndone([
      { key: "identity_provider", state: "done" },
      { key: "group_mapping", state: "warning" },
      { key: "bootstrap_token", state: "optional" },
      { key: "hosts", state: "undone" },
      { key: "policy", state: "undone" },
    ])).toBe("hosts");
  });

  it("highlights nothing when every required step is done", () => {
    expect(firstUndone([
      { key: "identity_provider", state: "done" },
      { key: "relay", state: "optional" },
      { key: "fleet_ca", state: "warning" },
    ])).toBeUndefined();
    expect(firstUndone([])).toBeUndefined();
  });
});

describe("stepTone", () => {
  it("shows done as fine, undone as a fault, a warning as a warning and optional as unknown", () => {
    expect(stepTone("done")).toBe("ok");
    expect(stepTone("undone")).toBe("error");
    expect(stepTone("warning")).toBe("warn");
    expect(stepTone("optional")).toBe("unknown");
  });
});

describe("mayAct", () => {
  it("lets the settings reader or the access manager test the provider", () => {
    expect(mayAct(new Set(["settings.read"]), "identity_provider")).toBe(true);
    expect(mayAct(new Set(["principal.manage"]), "identity_provider")).toBe(true);
    expect(mayAct(new Set(["host.read"]), "identity_provider")).toBe(false);
  });

  it("lets the identity reader test the directory and only the access manager add a mapping", () => {
    expect(mayAct(new Set(["identity.read"]), "directory")).toBe(true);
    expect(mayAct(new Set(["identity.read"]), "group_mapping")).toBe(false);
    expect(mayAct(new Set(["principal.manage"]), "group_mapping")).toBe(true);
  });

  it("offers no action on the steps that have no form here", () => {
    const everything = new Set(["settings.read", "principal.manage", "identity.read"]);
    for (const key of ["hosts", "relay", "policy", "alert_rule", "notification_channel", "fleet_ca", "bootstrap_token"]) {
      expect(mayAct(everything, key)).toBe(false);
    }
  });
});

describe("pageName", () => {
  it("names the page a path leads to, the query aside", () => {
    expect(pageName("/access?tab=mappings")).toBe("Access");
    expect(pageName("/access?tab=ca")).toBe("Access");
    expect(pageName("/hosts/new")).toBe("Add host");
    expect(pageName("/hosts")).toBe("Hosts");
    expect(pageName("/monitoring")).toBe("Monitoring");
    expect(pageName("/settings")).toBe("Settings");
  });

  it("falls back to a plain verb for a path it does not know", () => {
    expect(pageName("/somewhere/else")).toBe("Open");
  });
});

describe("readableDetail", () => {
  it("rewrites a moment in the server's RFC 3339 shape as the panel's absolute time", () => {
    const detail = readableDetail("flotestro/panel@EXAMPLE answered at 2026-09-16T15:35:25Z");
    expect(detail).not.toContain("T15:35:25Z");
    expect(detail).toMatch(/answered at \d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/);
  });

  it("leaves a sentence without a moment as it came", () => {
    expect(readableDetail("6 hosts enrolled")).toBe("6 hosts enrolled");
  });
});
