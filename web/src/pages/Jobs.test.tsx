import { describe, expect, it } from "vitest";
import {
  anyFilter, EMPTY_FILTERS, filterParams, hoursAgo, localInput, orderAgainAddress, prettyJSON, readFilters, reasonAccepted,
} from "./Jobs";
import { hasContent, outputFilename } from "./Job";

/* The filters of the job list live in the address bar: a tile, a read
   fan-out and a bookmark set them, and every change goes back. The
   round trip is a pair of pure functions, checked here without a screen. */

describe("job filters in the address", () => {
  it("reads every filter a link may carry and leaves the rest empty", () => {
    const filters = readFilters(new URLSearchParams("fanout_id=f-1&host_id=h-1&state=failed&since=2026-09-15T10:00"));
    expect(filters).toEqual({ ...EMPTY_FILTERS, fanout_id: "f-1", host_id: "h-1", state: "failed", since: "2026-09-15T10:00" });
    expect(anyFilter(filters)).toBe(true);
    expect(anyFilter(readFilters(new URLSearchParams()))).toBe(false);
  });

  it("writes only the set filters, so a cleared screen is a plain address", () => {
    expect(filterParams({ ...EMPTY_FILTERS }).toString()).toBe("");
    const params = filterParams({ ...EMPTY_FILTERS, hostname: "web-", error_code: "E_TIMEOUT" });
    expect(params.get("hostname")).toBe("web-");
    expect(params.get("error_code")).toBe("E_TIMEOUT");
    expect([...params.keys()]).toEqual(["hostname", "error_code"]);
  });

  it("survives the round trip through the address", () => {
    const filters = { ...EMPTY_FILTERS, action: "unit.restart", actor: "ops", campaign_id: "c-1", until: "2026-09-15T12:30" };
    expect(readFilters(filterParams(filters))).toEqual(filters);
  });
});

describe("since presets", () => {
  it("speak the local form of the datetime input, to the minute", () => {
    const now = new Date(2026, 8, 15, 14, 45, 30);
    expect(localInput(now)).toBe("2026-09-15T14:45");
    expect(hoursAgo(1, now)).toBe("2026-09-15T13:45");
    expect(hoursAgo(24, now)).toBe("2026-09-14T14:45");
    expect(hoursAgo(24 * 7, now)).toBe("2026-09-08T14:45");
  });
});

describe("ordering a job again", () => {
  it("opens the Bulk workspace with the operation, the payload and the one host written in", () => {
    const address = orderAgainAddress({
      action_type: "unit.restart", payload: { unit: { name: "cron.service" } }, host_id: "host-a", hostname: "web-1",
    });
    const params = new URLSearchParams(address.slice(address.indexOf("?") + 1));
    expect(address.startsWith("/bulk?")).toBe(true);
    expect(params.get("action")).toBe("unit.restart");
    expect(params.get("name")).toBe("unit.restart again on web-1");
    expect(params.getAll("host_id")).toEqual(["host-a"]);
    expect(JSON.parse(params.get("payload") ?? "")).toEqual({ unit: { name: "cron.service" } });
    expect(address).not.toContain("compensates");
  });

  it("names the host by the start of its identifier when it has no name", () => {
    const address = orderAgainAddress({ action_type: "system.reboot", payload: {}, host_id: "0123456789abcdef" });
    expect(new URLSearchParams(address.slice(address.indexOf("?") + 1)).get("name")).toBe("system.reboot again on 01234567");
  });
});

describe("the reason of a cancel", () => {
  it("is accepted from eight characters on, blanks not counted", () => {
    expect(reasonAccepted("")).toBe(false);
    expect(reasonAccepted("   too short   ")).toBe(true);
    expect(reasonAccepted("short  ")).toBe(false);
    expect(reasonAccepted("wrong host")).toBe(true);
  });
});

describe("the payload on screen", () => {
  it("is indented whether it came as an object or as a JSON text", () => {
    expect(prettyJSON({ a: 1 })).toBe("{\n  \"a\": 1\n}");
    expect(prettyJSON("{\"a\":1}")).toBe("{\n  \"a\": 1\n}");
    expect(prettyJSON("not json")).toBe("not json");
    expect(prettyJSON(null)).toBe("");
  });

  it("says when preconditions carry nothing", () => {
    expect(hasContent({})).toBe(false);
    expect(hasContent(undefined)).toBe(false);
    expect(hasContent("null")).toBe(false);
    expect(hasContent({ unit_active: true })).toBe(true);
  });
});

describe("output files", () => {
  it("are named after the job, the attempt and the stream", () => {
    expect(outputFilename("0123456789abcdef", 2, "stderr")).toBe("job-01234567-attempt-2-stderr.txt");
  });
});
