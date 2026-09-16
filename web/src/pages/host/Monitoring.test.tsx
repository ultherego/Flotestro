import { afterEach, describe, expect, it } from "vitest";
import { axisLabel } from "./Monitoring";
import { setPreferredTimeZone } from "../../lib/format";

/* The time axis of a chart reads in the clock the rest of the panel uses:
   the 24-hour clock in the zone the operator prefers. */

describe("axisLabel", () => {
  afterEach(() => setPreferredTimeZone(""));

  it("writes the hour of a short window in the 24-hour clock of the preferred zone", () => {
    setPreferredTimeZone("UTC");
    expect(axisLabel("3h")("2026-09-15T19:03:00Z")).toBe("19:03");
    expect(axisLabel("24h")("2026-09-15T07:46:00Z")).toBe("07:46");
  });

  it("adds the day in a week and keeps only the day in a month", () => {
    setPreferredTimeZone("UTC");
    expect(axisLabel("7d")("2026-09-15T19:03:00Z")).toBe("09-15 19:03");
    expect(axisLabel("30d")("2026-09-15T19:03:00Z")).toBe("09-15");
  });

  it("follows the preferred zone", () => {
    setPreferredTimeZone("Europe/Warsaw");
    expect(axisLabel("3h")("2026-09-15T19:03:00Z")).toBe("21:03");
  });
});
