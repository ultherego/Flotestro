import { describe, expect, it } from "vitest";
import type { Host } from "../lib/types";
import { hostMeta, matchesHost, moduleSegment, remember, selectRows, step, toggled } from "./HostSelect";

/* The selector is a list built from the starred hosts, the ones opened
   last and the fleet by pure functions; every decision about order, the
   headings, the query and the keyboard is checked here without a screen
   or a server. */

function host(id: string, hostname: string, extra: Partial<Host> = {}): Host {
  return { id, hostname, site: "lab", environment: "prod", connection_state: "online", tags: [], ...extra } as Host;
}

describe("hostMeta", () => {
  it("joins the site and the environment, and leaves out what is not known", () => {
    expect(hostMeta({ site: "lab", environment: "prod" })).toBe("lab / prod");
    expect(hostMeta({ site: "", environment: "prod" })).toBe("prod");
    expect(hostMeta({ site: "", environment: "" })).toBe("");
  });
});

describe("matchesHost", () => {
  it("answers by the name or the address, whatever the case, and to nothing with everything", () => {
    const web = { hostname: "Web-01", management_address: "10.0.0.5" };
    expect(matchesHost(web, "web")).toBe(true);
    expect(matchesHost(web, "0.0.5")).toBe(true);
    expect(matchesHost(web, "  ")).toBe(true);
    expect(matchesHost(web, "db")).toBe(false);
    expect(matchesHost({ hostname: "db-01" }, "10.")).toBe(false);
  });
});

describe("selectRows", () => {
  const byID = new Map<string, Host>([
    ["f1", host("f1", "files-01")],
    ["r1", host("r1", "redis-01", { management_address: "10.0.0.9" })],
    ["r2", host("r2", "web-02")],
  ]);
  const fleet = [host("a", "app-01"), host("f1", "files-01"), host("r2", "web-02"), host("z", "zabbix-01")];

  it("stands the favourites, then the recent, then the fleet, each host once under its first heading", () => {
    const rows = selectRows(["f1"], ["r1", "r2", "f1"], byID, fleet, "");
    expect(rows.map((row) => row.key)).toEqual(["Favourites:f1", "Recent:r1", "Recent:r2", "Hosts:a", "Hosts:z"]);
    expect(rows.map((row) => row.group)).toEqual(["Favourites", "Recent", "Recent", "Hosts", "Hosts"]);
  });

  it("narrows the remembered hosts by the query and takes the fleet as the server answered", () => {
    const rows = selectRows(["f1"], ["r1", "r2"], byID, [host("z", "zabbix-01")], "web");
    expect(rows.map((row) => row.key)).toEqual(["Recent:r2", "Hosts:z"]);
  });

  it("leaves out a remembered host whose record is not at hand", () => {
    const rows = selectRows(["gone"], ["missing", "r1"], byID, [], "");
    expect(rows.map((row) => row.key)).toEqual(["Recent:r1"]);
  });

  it("is empty for nothing remembered and an empty fleet", () => {
    expect(selectRows([], [], new Map(), [], "")).toEqual([]);
  });
});

describe("remember", () => {
  it("puts the host first, once, and keeps the list short", () => {
    expect(remember(["a", "b", "c"], "b")).toEqual(["b", "a", "c"]);
    expect(remember(["a", "b"], "c", 2)).toEqual(["c", "a"]);
    expect(remember([], "a")).toEqual(["a"]);
  });
});

describe("toggled", () => {
  it("stars a host that was not starred and unstars one that was", () => {
    expect(toggled([], "a")).toEqual(["a"]);
    expect(toggled(["a", "b"], "a")).toEqual(["b"]);
  });
});

describe("step", () => {
  it("moves one row at a time, clamped to the ends, and jumps to either end", () => {
    expect(step("ArrowDown", 0, 3)).toBe(1);
    expect(step("ArrowDown", 2, 3)).toBe(2);
    expect(step("ArrowUp", 0, 3)).toBe(0);
    expect(step("ArrowUp", 2, 3)).toBe(1);
    expect(step("Home", 2, 3)).toBe(0);
    expect(step("End", 0, 3)).toBe(2);
  });

  it("leaves the highlight alone for any other key and for an empty list", () => {
    expect(step("a", 1, 3)).toBeUndefined();
    expect(step("ArrowDown", 0, 0)).toBeUndefined();
  });
});

describe("moduleSegment", () => {
  it("is the first segment after the host, or nothing on the overview", () => {
    expect(moduleSegment("packages")).toBe("packages");
    expect(moduleSegment("jobs/j1")).toBe("jobs");
    expect(moduleSegment("")).toBe("");
    expect(moduleSegment(undefined)).toBe("");
  });
});
