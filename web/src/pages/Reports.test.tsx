import { describe, expect, it } from "vitest";
import { campaignStateLabel, campaignStateTone, duration, percent, presetRange, reportParams } from "./Reports";

/* The period picker and the address of a report are pure functions of
   the operator's choice; every branch is checked here without a screen. */

describe("presetRange", () => {
  const now = new Date(2026, 8, 15, 10, 30);
  const custom = { from: "", to: "" };

  it("ends the last days now and starts them the given days back", () => {
    const week = presetRange("7d", now, custom);
    expect(week.to).toBe(now.toISOString());
    expect(new Date(week.from).getTime()).toBe(now.getTime() - 7 * 24 * 3600 * 1000);
    const month = presetRange("30d", now, custom);
    expect(new Date(month.from).getTime()).toBe(now.getTime() - 30 * 24 * 3600 * 1000);
  });

  it("runs a month from its first midnight to the next one in the browser's clock", () => {
    const current = presetRange("this_month", now, custom);
    expect(new Date(current.from).getTime()).toBe(new Date(2026, 8, 1).getTime());
    expect(new Date(current.to).getTime()).toBe(new Date(2026, 9, 1).getTime());
    const previous = presetRange("previous_month", now, custom);
    expect(new Date(previous.from).getTime()).toBe(new Date(2026, 7, 1).getTime());
    expect(new Date(previous.to).getTime()).toBe(new Date(2026, 8, 1).getTime());
  });

  it("keeps what the operator typed for a custom period, and nothing for a blank", () => {
    const typed = presetRange("custom", now, { from: "2026-09-01T00:00", to: "2026-09-10T00:00" });
    expect(typed.from).toBe(new Date("2026-09-01T00:00").toISOString());
    expect(typed.to).toBe(new Date("2026-09-10T00:00").toISOString());
    expect(presetRange("custom", now, { from: "2026-09-01T00:00", to: "" })).toEqual({ from: new Date("2026-09-01T00:00").toISOString(), to: "" });
  });
});

describe("reportParams", () => {
  it("asks with both bounds and the trimmed filter", () => {
    const params = reportParams({ from: "2026-09-01T00:00:00.000Z", to: "2026-09-10T00:00:00.000Z", site: " warsaw ", environment: "" });
    expect(params.get("from")).toBe("2026-09-01T00:00:00.000Z");
    expect(params.get("to")).toBe("2026-09-10T00:00:00.000Z");
    expect(params.get("site")).toBe("warsaw");
    expect(params.has("environment")).toBe(false);
  });

  it("asks without a period when one end is missing, so the server is not sent a half period", () => {
    const params = reportParams({ from: "2026-09-01T00:00:00.000Z", to: "", site: "", environment: "prod" });
    expect(params.has("from")).toBe(false);
    expect(params.has("to")).toBe(false);
    expect(params.get("environment")).toBe("prod");
  });
});

describe("the words of the report", () => {
  it("renders a rate as a percentage and a missing rate as a dash", () => {
    expect(percent(0.5)).toBe("50.0%");
    expect(percent(1)).toBe("100.0%");
    expect(percent(0.123456)).toBe("12.3%");
    expect(percent(null)).toBe("—");
    expect(percent(undefined)).toBe("—");
  });

  it("renders a duration in the largest units that read at a glance", () => {
    expect(duration(45)).toBe("45s");
    expect(duration(65)).toBe("1m 05s");
    expect(duration(3900)).toBe("1h 05m");
    expect(duration(2 * 86400 + 3 * 3600)).toBe("2d 03h");
    expect(duration(null)).toBe("—");
  });

  it("colours the terminal states of a campaign and names them in words", () => {
    expect(campaignStateTone("completed")).toBe("ok");
    expect(campaignStateTone("completed_with_issues")).toBe("warn");
    expect(campaignStateTone("failed")).toBe("error");
    expect(campaignStateTone("plan_failed")).toBe("error");
    expect(campaignStateTone("canceled")).toBe("neutral");
    expect(campaignStateTone("expired")).toBe("neutral");
    expect(campaignStateTone("running")).toBe("unknown");
    expect(campaignStateLabel("completed_with_issues")).toBe("completed with issues");
    expect(campaignStateLabel("something_else")).toBe("something_else");
  });
});
