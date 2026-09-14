import { describe, expect, it } from "vitest";
import { factReason, layoutText, uptimeText } from "./System";

/* The helpers read the platform picture the way the agent writes it; the
   page only draws what they say, so they are tested on their own. */

describe("factReason", () => {
  it("returns the reason of a fact that was not read", () => {
    expect(factReason({ "dmi.serial": "permission denied" }, "dmi.serial")).toBe("permission denied");
  });

  it("lets a fact inherit the reason of its parent", () => {
    const missing = { dmi: "the host has no DMI tables" };
    expect(factReason(missing, "dmi.serial")).toBe("the host has no DMI tables");
    expect(factReason(missing, "dmi.uuid")).toBe("the host has no DMI tables");
  });

  it("says nothing about a fact that was read", () => {
    expect(factReason({ dmi: "absent" }, "cpu")).toBeUndefined();
    expect(factReason(undefined, "cpu")).toBeUndefined();
  });
});

describe("uptimeText", () => {
  it("counts days, hours and minutes", () => {
    expect(uptimeText(3 * 86400 + 4 * 3600 + 5 * 60 + 9)).toBe("3 d 4 h 5 min");
  });

  it("drops the days when there are none and keeps the hours when there are days", () => {
    expect(uptimeText(2 * 3600 + 30 * 60)).toBe("2 h 30 min");
    expect(uptimeText(86400 + 7)).toBe("1 d 0 h 0 min");
    expect(uptimeText(59)).toBe("0 min");
  });
});

describe("layoutText", () => {
  it("names the sockets, the cores per socket and the threads", () => {
    expect(layoutText({ sockets: 2, cores: 4, threads: 8 })).toBe("2 sockets × 2 cores, 8 threads");
    expect(layoutText({ sockets: 1, cores: 1, threads: 2 })).toBe("1 socket × 1 core, 2 threads");
  });

  it("gives the threads alone when the host described no layout", () => {
    expect(layoutText({ threads: 4 })).toBe("4 threads");
    expect(layoutText({ cores: 2 })).toBe("2 cores");
    expect(layoutText(undefined)).toBe("");
    expect(layoutText({})).toBe("");
  });
});
